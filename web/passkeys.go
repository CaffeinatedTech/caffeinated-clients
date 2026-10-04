package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/CaffeinatedTech/caffeinated-clients/internal/auth"
)

// --- WebAuthn adapter ----------------------------------------------------

// waUser adapts the single account (plus its stored passkeys) to the
// webauthn.User interface. The user handle is derived deterministically from
// the row id so it is stable across restarts without another column.
type waUser struct {
	user  auth.User
	creds []auth.Passkey
}

func (u waUser) WebAuthnID() []byte { return webAuthnUserID(u.user.ID) }
func (u waUser) WebAuthnName() string {
	if u.user.Username != "" {
		return u.user.Username
	}
	return "operator"
}
func (u waUser) WebAuthnDisplayName() string { return u.WebAuthnName() }

func (u waUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(u.creds))
	for _, p := range u.creds {
		out = append(out, toWebAuthnCredential(p))
	}
	return out
}

func webAuthnUserID(id int64) []byte {
	sum := sha256.Sum256([]byte("caffeinated-clients:user:" + strconv.FormatInt(id, 10)))
	return sum[:]
}

func toWebAuthnCredential(p auth.Passkey) webauthn.Credential {
	ts := make([]protocol.AuthenticatorTransport, 0, len(p.Transports))
	for _, t := range p.Transports {
		ts = append(ts, protocol.AuthenticatorTransport(t))
	}
	return webauthn.Credential{
		ID:              p.CredentialID,
		PublicKey:       p.PublicKey,
		AttestationType: p.AttestationType,
		Transport:       ts,
		Flags: webauthn.CredentialFlags{
			BackupEligible: p.BackupEligible,
			BackupState:    p.BackupState,
		},
		Authenticator: webauthn.Authenticator{AAGUID: p.AAGUID, SignCount: p.SignCount},
	}
}

func transportsFromCredential(ts []protocol.AuthenticatorTransport) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, string(t))
	}
	return out
}

func sessionJSON(s *webauthn.SessionData) (string, error) {
	b, err := json.Marshal(s)
	return string(b), err
}

// waFor loads the passkeys for the single account and wraps it.
func (s *Server) waFor(ctx context.Context, u auth.User) (waUser, error) {
	creds, err := s.svc.ListPasskeys(ctx, u.ID)
	if err != nil {
		return waUser{}, err
	}
	return waUser{user: u, creds: creds}, nil
}

// --- challenge cookie and JSON helpers ----------------------------------

func (s *Server) setChallengeCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     challengeCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(challengeTTL.Seconds()),
	})
}

func (s *Server) clearChallengeCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     challengeCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func challengeToken(r *http.Request) string {
	c, err := r.Cookie(challengeCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

// --- registration state -------------------------------------------------

// accountComplete reports whether the single account has at least one usable
// credential. An account with a name but no password and no passkey is an
// abandoned registration and can be resumed at /register.
func (s *Server) accountComplete(ctx context.Context) (bool, error) {
	u, err := s.svc.GetUser(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if u.PasswordHash != "" {
		return true, nil
	}
	n, err := s.svc.PasskeyCount(ctx, u.ID)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// registrationUser returns the incomplete single user, creating it if none
// exists. The caller must have confirmed that registration is not complete.
func (s *Server) registrationUser(ctx context.Context, name string) (auth.User, error) {
	u, err := s.svc.GetUser(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return s.svc.CreateUserNoPassword(ctx, name)
	}
	if err != nil {
		return auth.User{}, err
	}
	return u, nil
}

// --- first-run registration ---------------------------------------------

func (s *Server) handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	complete, err := s.accountComplete(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	if complete {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	errMsg := ""
	if r.URL.Query().Get("error") == "passkey" {
		errMsg = "That passkey could not be registered. Try again."
	}
	s.render(w, http.StatusOK, "register.html", pageData{
		Title:     "Create your account",
		Error:     errMsg,
		CSRFToken: s.ensureCSRFCookie(w, r),
	})
}

func (s *Server) handleRegisterPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	complete, err := s.accountComplete(ctx)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if complete {
		writeJSONError(w, http.StatusConflict, "An account already exists.")
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Could not read the request.")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeJSONError(w, http.StatusBadRequest, "Enter your name.")
		return
	}
	u, err := s.registrationUser(ctx, name)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Could not start registration.")
		return
	}
	if err := s.svc.SetUsername(ctx, u.ID, name); err != nil {
		s.serverError(w, err)
		return
	}
	u.Username = name
	user, err := s.waFor(ctx, u)
	if err != nil {
		s.serverError(w, err)
		return
	}
	creation, session, err := s.wa.BeginRegistration(user)
	if err != nil {
		s.serverError(w, err)
		return
	}
	data, err := sessionJSON(session)
	if err != nil {
		s.serverError(w, err)
		return
	}
	token, err := s.svc.StoreChallenge(ctx, &u.ID, "register", data, challengeTTL)
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.setChallengeCookie(w, token)
	writeJSON(w, http.StatusOK, creation)
}

func (s *Server) handleRegisterPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fail := func() { http.Redirect(w, r, "/register?error=passkey", http.StatusSeeOther) }

	token := challengeToken(r)
	s.clearChallengeCookie(w)
	data, err := s.svc.TakeChallenge(ctx, token, "register")
	if err != nil {
		fail()
		return
	}
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		fail()
		return
	}
	u, err := s.svc.GetUser(ctx)
	if err != nil {
		fail()
		return
	}
	user, err := s.waFor(ctx, u)
	if err != nil {
		s.serverError(w, err)
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes([]byte(r.FormValue("credential")))
	if err != nil {
		fail()
		return
	}
	cred, err := s.wa.CreateCredential(user, session, parsed)
	if err != nil {
		s.log.Warn("passkey registration failed", "err", err)
		fail()
		return
	}
	if _, err := s.svc.AddPasskey(ctx, passkeyFromCredential(u.ID, cred, "Passkey")); err != nil {
		s.serverError(w, err)
		return
	}
	codes, err := auth.NewRecoveryCodes()
	if err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.svc.StoreRecoveryCodes(ctx, u.ID, codes); err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.newFullSession(w, r, u, s.clientIP(r)); err != nil {
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(ctx, auth.AuditEntry{Event: "user_registered", Entity: "user", EntityID: &u.ID, IP: s.clientIP(r),
		Detail: map[string]any{"method": "passkey"}})
	_ = s.svc.Audit(ctx, auth.AuditEntry{Event: "passkey_registered", Entity: "user", EntityID: &u.ID, IP: s.clientIP(r)})
	_ = s.svc.Audit(ctx, auth.AuditEntry{Event: "login_success", Entity: "user", EntityID: &u.ID, IP: s.clientIP(r)})
	s.render(w, http.StatusOK, "recovery.html", pageData{Title: "Recovery codes", Codes: codes})
}

func (s *Server) handleRegisterPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	complete, err := s.accountComplete(ctx)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if complete {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	password := r.FormValue("password")
	confirm := r.FormValue("password_confirm")
	fail := func(msg string) {
		s.render(w, http.StatusBadRequest, "register.html", pageData{
			Title:        "Create your account",
			Error:        msg,
			CSRFToken:    s.ensureCSRFCookie(w, r),
			RegisterName: name,
		})
	}
	if name == "" {
		fail("Enter your name.")
		return
	}
	if len(password) < 8 {
		fail("Password must be at least 8 characters.")
		return
	}
	if password != confirm {
		fail("Passwords do not match.")
		return
	}
	u, err := s.registrationUser(ctx, name)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.svc.SetUsername(ctx, u.ID, name); err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.svc.SetPassword(ctx, u.ID, password); err != nil {
		s.serverError(w, err)
		return
	}
	u.Username = name
	u.PasswordHash = "set"
	_, token, err := s.svc.CreateSession(ctx, u, auth.StagePending, pendingTTL, r.UserAgent(), s.clientIP(r))
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.setSessionCookie(w, token, pendingTTL)
	_ = s.svc.Audit(ctx, auth.AuditEntry{Event: "user_registered", Entity: "user", EntityID: &u.ID, IP: s.clientIP(r),
		Detail: map[string]any{"method": "password"}})
	http.Redirect(w, r, "/setup", http.StatusSeeOther)
}

// --- passkey login ------------------------------------------------------

func (s *Server) handleLoginPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, err := s.svc.GetUser(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSONError(w, http.StatusNotFound, "No account exists.")
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	user, err := s.waFor(ctx, u)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if len(user.creds) == 0 {
		writeJSONError(w, http.StatusConflict, "No passkeys are registered.")
		return
	}
	assertion, session, err := s.wa.BeginLogin(user)
	if err != nil {
		s.serverError(w, err)
		return
	}
	data, err := sessionJSON(session)
	if err != nil {
		s.serverError(w, err)
		return
	}
	token, err := s.svc.StoreChallenge(ctx, &u.ID, "login", data, challengeTTL)
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.setChallengeCookie(w, token)
	writeJSON(w, http.StatusOK, assertion)
}

func (s *Server) handleLoginPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := s.clientIP(r)
	fail := func() { http.Redirect(w, r, "/login?error=passkey", http.StatusSeeOther) }

	token := challengeToken(r)
	s.clearChallengeCookie(w)
	data, err := s.svc.TakeChallenge(ctx, token, "login")
	if err != nil {
		fail()
		return
	}
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		fail()
		return
	}
	u, err := s.svc.GetUser(ctx)
	if err != nil {
		fail()
		return
	}
	user, err := s.waFor(ctx, u)
	if err != nil {
		s.serverError(w, err)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes([]byte(r.FormValue("credential")))
	if err != nil {
		fail()
		return
	}
	cred, err := s.wa.ValidateLogin(user, session, parsed)
	if err != nil {
		s.log.Warn("passkey login failed", "err", err)
		_ = s.svc.Audit(ctx, auth.AuditEntry{Event: "login_failure", Entity: "user", EntityID: &u.ID, IP: ip,
			Detail: map[string]any{"method": "passkey"}})
		fail()
		return
	}
	for _, p := range user.creds {
		if bytes.Equal(p.CredentialID, cred.ID) {
			_ = s.svc.UpdatePasskeyUse(ctx, p.ID, cred.Authenticator.SignCount)
			break
		}
	}
	if err := s.newFullSession(w, r, u, ip); err != nil {
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(ctx, auth.AuditEntry{Event: "passkey_login", Entity: "user", EntityID: &u.ID, IP: ip})
	_ = s.svc.Audit(ctx, auth.AuditEntry{Event: "login_success", Entity: "user", EntityID: &u.ID, IP: ip})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- recovery-code login (passkey-only accounts) ------------------------

// handleRecoveryLoginPage offers a standalone recovery-code login only when no
// password exists. With a password, recovery codes remain a second factor and
// are entered on the TOTP page, never in place of the password.
func (s *Server) handleRecoveryLoginPage(w http.ResponseWriter, r *http.Request) {
	enabled, err := s.svc.PasswordLoginEnabled(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	if enabled {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "login_recovery.html", pageData{
		Title:     "Recovery code",
		CSRFToken: s.ensureCSRFCookie(w, r),
	})
}

func (s *Server) handleRecoveryLoginPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := s.clientIP(r)
	enabled, err := s.svc.PasswordLoginEnabled(ctx)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if enabled {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	u, err := s.svc.GetUser(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	now := time.Now()
	keys := []string{"ip:" + ip, "user:" + strings.ToLower(u.Username)}
	for _, k := range keys {
		if ok, retry := s.limiter.Allow(k, now); !ok {
			s.renderRateLimited(w, "login_recovery.html", s.ensureCSRFCookie(w, r), retry)
			return
		}
	}
	used, err := s.svc.ConsumeRecoveryCode(ctx, u.ID, r.FormValue("code"))
	if err != nil {
		s.serverError(w, err)
		return
	}
	if !used {
		for _, k := range keys {
			s.limiter.Fail(k, now)
		}
		_ = s.svc.Audit(ctx, auth.AuditEntry{Event: "login_failure", Entity: "user", EntityID: &u.ID, IP: ip,
			Detail: map[string]any{"method": "recovery_code"}})
		s.render(w, http.StatusUnauthorized, "login_recovery.html", pageData{
			Title:     "Recovery code",
			Error:     "That code did not match. Try again.",
			CSRFToken: s.ensureCSRFCookie(w, r),
		})
		return
	}
	for _, k := range keys {
		s.limiter.Reset(k)
	}
	if err := s.newFullSession(w, r, u, ip); err != nil {
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(ctx, auth.AuditEntry{Event: "recovery_code_used", Entity: "user", EntityID: &u.ID, IP: ip})
	_ = s.svc.Audit(ctx, auth.AuditEntry{Event: "login_success", Entity: "user", EntityID: &u.ID, IP: ip})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- settings: manage passkeys ------------------------------------------

func (s *Server) reauthManagePasskeys(r *http.Request, sess *auth.Session) (bool, string) {
	enabled, err := s.svc.PasswordLoginEnabled(r.Context())
	if err != nil {
		return false, "Could not verify your session. Try again."
	}
	if !enabled {
		// Passkey-only: the full session was itself created by a passkey.
		// ponytail: no step-up assertion here — the ceiling is that a stolen
		// full session can manage passkeys; upgrade by adding a session
		// reauth_at set from a fresh assertion and requiring it here.
		return true, ""
	}
	return s.reauth(r, sess, r.FormValue("password"), r.FormValue("code"))
}

func (s *Server) handlePasskeyAddBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := sessionFrom(ctx)
	enabled, err := s.svc.PasswordLoginEnabled(ctx)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if enabled {
		var body struct {
			Password string `json:"password"`
			Code     string `json:"code"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSONError(w, http.StatusBadRequest, "Could not read the request.")
			return
		}
		if ok, msg := s.reauth(r, sess, body.Password, body.Code); !ok {
			writeJSONError(w, http.StatusForbidden, msg)
			return
		}
	}
	user, err := s.waFor(ctx, sess.User)
	if err != nil {
		s.serverError(w, err)
		return
	}
	var exclusions []protocol.CredentialDescriptor
	for _, c := range user.WebAuthnCredentials() {
		exclusions = append(exclusions, c.Descriptor())
	}
	creation, session, err := s.wa.BeginRegistration(user, webauthn.WithExclusions(exclusions))
	if err != nil {
		s.serverError(w, err)
		return
	}
	data, err := sessionJSON(session)
	if err != nil {
		s.serverError(w, err)
		return
	}
	token, err := s.svc.StoreChallenge(ctx, &sess.User.ID, "register", data, challengeTTL)
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.setChallengeCookie(w, token)
	writeJSON(w, http.StatusOK, creation)
}

func (s *Server) handlePasskeyAddFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := sessionFrom(ctx)
	fail := func(msg string) {
		s.settingsPage(w, r, sess, http.StatusBadRequest, func(d *pageData) { d.Error = msg })
	}
	token := challengeToken(r)
	s.clearChallengeCookie(w)
	data, err := s.svc.TakeChallenge(ctx, token, "register")
	if err != nil {
		fail("That passkey request expired. Try again.")
		return
	}
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		fail("That passkey request was invalid. Try again.")
		return
	}
	user, err := s.waFor(ctx, sess.User)
	if err != nil {
		s.serverError(w, err)
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes([]byte(r.FormValue("credential")))
	if err != nil {
		fail("The passkey could not be read. Try again.")
		return
	}
	cred, err := s.wa.CreateCredential(user, session, parsed)
	if err != nil {
		s.log.Warn("passkey registration failed", "err", err)
		fail("That passkey could not be registered. Try again.")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = "Passkey"
	}
	if _, err := s.svc.AddPasskey(ctx, passkeyFromCredential(sess.User.ID, cred, name)); err != nil {
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(ctx, auth.AuditEntry{Event: "passkey_registered", Entity: "user", EntityID: &sess.User.ID, IP: s.clientIP(r)})
	http.Redirect(w, r, "/settings?notice=passkey", http.StatusSeeOther)
}

func (s *Server) handlePasskeyRename(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := sessionFrom(ctx)
	if ok, msg := s.reauthManagePasskeys(r, sess); !ok {
		s.settingsPage(w, r, sess, http.StatusBadRequest, func(d *pageData) { d.Error = msg })
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.settingsPage(w, r, sess, http.StatusBadRequest, func(d *pageData) { d.Error = "Unknown passkey." })
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		s.settingsPage(w, r, sess, http.StatusBadRequest, func(d *pageData) { d.Error = "Give the passkey a name." })
		return
	}
	if err := s.svc.RenamePasskey(ctx, sess.User.ID, id, name); err != nil {
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(ctx, auth.AuditEntry{Event: "passkey_renamed", Entity: "user", EntityID: &sess.User.ID, IP: s.clientIP(r)})
	http.Redirect(w, r, "/settings?notice=passkey", http.StatusSeeOther)
}

func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := sessionFrom(ctx)
	if ok, msg := s.reauthManagePasskeys(r, sess); !ok {
		s.settingsPage(w, r, sess, http.StatusBadRequest, func(d *pageData) { d.Error = msg })
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.settingsPage(w, r, sess, http.StatusBadRequest, func(d *pageData) { d.Error = "Unknown passkey." })
		return
	}
	count, err := s.svc.PasskeyCount(ctx, sess.User.ID)
	if err != nil {
		s.serverError(w, err)
		return
	}
	enabled, err := s.svc.PasswordLoginEnabled(ctx)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if count <= 1 && !enabled {
		s.settingsPage(w, r, sess, http.StatusBadRequest, func(d *pageData) {
			d.Error = "This is your only sign-in method. Add another passkey or a password first."
		})
		return
	}
	if err := s.svc.DeletePasskey(ctx, sess.User.ID, id); err != nil {
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(ctx, auth.AuditEntry{Event: "passkey_removed", Entity: "user", EntityID: &sess.User.ID, IP: s.clientIP(r)})
	http.Redirect(w, r, "/settings?notice=passkey", http.StatusSeeOther)
}

func (s *Server) handlePasswordRemove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := sessionFrom(ctx)
	if ok, msg := s.reauth(r, sess, r.FormValue("password"), r.FormValue("code")); !ok {
		s.settingsPage(w, r, sess, http.StatusBadRequest, func(d *pageData) { d.Error = msg })
		return
	}
	count, err := s.svc.PasskeyCount(ctx, sess.User.ID)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if count == 0 {
		s.settingsPage(w, r, sess, http.StatusBadRequest, func(d *pageData) {
			d.Error = "Add a passkey before removing your password."
		})
		return
	}
	if err := s.svc.RemovePassword(ctx, sess.User.ID); err != nil {
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(ctx, auth.AuditEntry{Event: "password_removed", Entity: "user", EntityID: &sess.User.ID, IP: s.clientIP(r)})
	http.Redirect(w, r, "/settings?notice=password-removed", http.StatusSeeOther)
}

func passkeyFromCredential(userID int64, cred *webauthn.Credential, name string) auth.Passkey {
	return auth.Passkey{
		UserID:          userID,
		CredentialID:    cred.ID,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		AAGUID:          cred.Authenticator.AAGUID,
		SignCount:       cred.Authenticator.SignCount,
		BackupEligible:  cred.Flags.BackupEligible,
		BackupState:     cred.Flags.BackupState,
		Transports:      transportsFromCredential(cred.Transport),
		Name:            name,
	}
}
