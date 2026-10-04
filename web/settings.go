package web

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/CaffeinatedTech/caffeinated-clients/internal/auth"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/crm"
)

// --- settings page ------------------------------------------------------

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	s.settingsPage(w, r, sess, http.StatusOK, func(d *pageData) {
		if r.URL.Query().Get("notice") == "password" {
			d.Notice = "Password changed."
		}
	})
}

// settingsPage builds the settings view model and renders it. fn may adjust the
// page (inline error, pending secret, one-time codes) before rendering.
func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request, sess *auth.Session, status int, fn func(*pageData)) {
	data, err := s.settingsData(r, sess)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if fn != nil {
		fn(&data)
	}
	s.render(w, status, "settings.html", data)
}

func (s *Server) settingsData(r *http.Request, sess *auth.Session) (pageData, error) {
	audit, err := s.svc.ListAudit(r.Context(), 100)
	if err != nil {
		return pageData{}, err
	}
	remaining, err := s.svc.UnusedRecoveryCodeCount(r.Context(), sess.User.ID)
	if err != nil {
		return pageData{}, err
	}
	return pageData{
		Title:             "Settings",
		CSRFToken:         sess.CSRFToken,
		User:              sess.User,
		Authed:            true,
		Active:            "settings",
		Audit:             audit,
		RecoveryRemaining: remaining,
	}, nil
}

// reauth re-verifies the current password and, unless 2FA is disabled, a
// current TOTP code or single-use recovery code before a security-sensitive
// settings change. It returns a user-facing error on failure.
func (s *Server) reauth(r *http.Request, sess *auth.Session, password, code string) (bool, string) {
	_, ok, err := s.svc.Authenticate(r.Context(), sess.User.Username, password)
	if err != nil {
		return false, "Could not verify your password. Try again."
	}
	if !ok {
		return false, "That password did not match."
	}
	if s.cfg.Disable2FA || !sess.User.TOTPEnabled {
		return true, ""
	}
	if auth.ValidateTOTP(sess.User.TOTPSecret, code, time.Now()) {
		return true, ""
	}
	if used, err := s.svc.ConsumeRecoveryCode(r.Context(), sess.User.ID, code); err == nil && used {
		return true, ""
	}
	return false, "That code did not match."
}

// --- password -----------------------------------------------------------

func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	current := r.FormValue("current_password")
	next := r.FormValue("new_password")
	confirm := r.FormValue("new_password_confirm")
	fail := func(msg string) {
		s.settingsPage(w, r, sess, http.StatusBadRequest, func(d *pageData) { d.Error = msg })
	}
	if _, ok, err := s.svc.Authenticate(r.Context(), sess.User.Username, current); err != nil {
		s.serverError(w, err)
		return
	} else if !ok {
		fail("Current password did not match.")
		return
	}
	if len(next) < 8 {
		fail("New password must be at least 8 characters.")
		return
	}
	if next != confirm {
		fail("New passwords do not match.")
		return
	}
	if err := s.svc.SetPassword(r.Context(), sess.User.ID, next); err != nil {
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "password_change", Entity: "user", EntityID: &sess.User.ID, IP: s.clientIP(r),
	})
	http.Redirect(w, r, "/settings?notice=password", http.StatusSeeOther)
}

// --- two-factor re-enrollment -------------------------------------------

func (s *Server) handleTOTPReenrollStart(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	if ok, msg := s.reauth(r, sess, r.FormValue("password"), r.FormValue("code")); !ok {
		s.settingsPage(w, r, sess, http.StatusBadRequest, func(d *pageData) { d.Error = msg })
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.svc.SetPendingTOTPSecret(r.Context(), sess.User.ID, secret); err != nil {
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "totp_reenroll_start", Entity: "user", EntityID: &sess.User.ID, IP: s.clientIP(r),
	})
	s.settingsPage(w, r, sess, http.StatusOK, func(d *pageData) {
		d.Secret = secret
		d.OTPAuthURL = auth.OTPAuthURL(s.svc.Issuer(), sess.User.Username, secret)
		d.Notice = "Add the new key to your authenticator, then confirm the code it shows."
	})
}

func (s *Server) handleTOTPReenrollConfirm(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	pending, err := s.svc.PendingTOTPSecret(r.Context(), sess.User.ID)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if pending == "" {
		s.settingsPage(w, r, sess, http.StatusBadRequest, func(d *pageData) {
			d.Error = "No authenticator re-enrollment is in progress."
		})
		return
	}
	if !auth.ValidateTOTP(pending, r.FormValue("code"), time.Now()) {
		s.settingsPage(w, r, sess, http.StatusBadRequest, func(d *pageData) {
			d.Error = "That code did not match."
			d.Secret = pending
			d.OTPAuthURL = auth.OTPAuthURL(s.svc.Issuer(), sess.User.Username, pending)
		})
		return
	}
	if err := s.svc.EnablePendingTOTP(r.Context(), sess.User.ID); err != nil {
		s.serverError(w, err)
		return
	}
	sess.User.TOTPEnabled = true
	codes, err := auth.NewRecoveryCodes()
	if err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.svc.StoreRecoveryCodes(r.Context(), sess.User.ID, codes); err != nil {
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "totp_reenrolled", Entity: "user", EntityID: &sess.User.ID, IP: s.clientIP(r),
	})
	s.settingsPage(w, r, sess, http.StatusOK, func(d *pageData) {
		d.Codes = codes
		d.RecoveryRemaining = len(codes)
		d.Notice = "Two-factor re-enrolled. Save these recovery codes now; they are shown only once."
	})
}

// --- recovery codes -----------------------------------------------------

func (s *Server) handleRecoveryRegenerate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	if ok, msg := s.reauth(r, sess, r.FormValue("password"), r.FormValue("code")); !ok {
		s.settingsPage(w, r, sess, http.StatusBadRequest, func(d *pageData) { d.Error = msg })
		return
	}
	codes, err := auth.NewRecoveryCodes()
	if err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.svc.StoreRecoveryCodes(r.Context(), sess.User.ID, codes); err != nil {
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "recovery_codes_regenerated", Entity: "user", EntityID: &sess.User.ID, IP: s.clientIP(r),
	})
	s.settingsPage(w, r, sess, http.StatusOK, func(d *pageData) {
		d.Codes = codes
		d.RecoveryRemaining = len(codes)
		d.Notice = "New recovery codes generated. Save them now; they are shown only once."
	})
}

// --- JSON export --------------------------------------------------------

// exportPayload flattens crm.ExportData and appends the audit log.
type exportPayload struct {
	crm.ExportData
	AuditLog []auth.AuditRecord `json:"audit_log"`
}

// handleExport streams the plaintext JSON export. GET excludes secret notes;
// POST is the explicit opt-in that includes them (F12.3), behind a confirmation
// and CSRF. Both are audited (F13.1).
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	includeSecrets := false
	event := "data_export"
	if r.Method == http.MethodPost {
		if r.FormValue("include_secrets") != "1" || r.FormValue("confirm") != "1" {
			sess := sessionFrom(r.Context())
			s.settingsPage(w, r, sess, http.StatusBadRequest, func(d *pageData) {
				d.Error = "Tick the confirmation to export secret notes."
			})
			return
		}
		includeSecrets = true
		event = "data_export_secrets"
	}
	data, err := s.crm.Export(r.Context(), includeSecrets)
	if err != nil {
		s.serverError(w, err)
		return
	}
	audit, err := s.svc.AllAudit(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: event, Entity: "export", IP: s.clientIP(r),
		Detail: map[string]any{"includes_secret_notes": includeSecrets},
	})
	blob, err := json.MarshalIndent(exportPayload{ExportData: data, AuditLog: audit}, "", "  ")
	if err != nil {
		s.serverError(w, err)
		return
	}
	name := "caffeinated-clients-export-" + time.Now().UTC().Format("20060102")
	if includeSecrets {
		name += "-with-secrets"
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.json"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(blob)
}
