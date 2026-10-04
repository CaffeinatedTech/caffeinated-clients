package web

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/CaffeinatedTech/caffeinated-clients/internal/auth"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/config"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/crm"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/store"
)

const (
	sessionCookieName = "cc_session"
	csrfCookieName    = "cc_csrf"
	pendingTTL        = 10 * time.Minute
)

var csrfCookieMaxAge = int((time.Hour).Seconds())

type ctxKey int

const sessionCtxKey ctxKey = iota

// Server serves the HTTP application.
type Server struct {
	svc      *auth.Service
	cfg      *config.Config
	log      *slog.Logger
	db       *sql.DB
	crm      *crm.Store
	tmpl     pageTemplates
	partials *template.Template
	static   fs.FS
	limiter  *auth.Limiter
}

// New builds a Server and parses the embedded templates.
func New(svc *auth.Service, cfg *config.Config, log *slog.Logger, db *sql.DB) (*Server, error) {
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	partials, err := parsePartials()
	if err != nil {
		return nil, err
	}
	static, err := staticSub()
	if err != nil {
		return nil, err
	}
	return &Server{svc: svc, cfg: cfg, log: log, db: db, crm: crm.New(db), tmpl: tmpl, partials: partials, static: static, limiter: auth.NewLimiter()}, nil
}

// Handler returns the routed, middleware-wrapped http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.Handle("GET /static/", s.assetHandler())
	mux.HandleFunc("GET /manifest.webmanifest", s.handleManifest)
	mux.HandleFunc("GET /sw.js", s.handleServiceWorker)
	mux.HandleFunc("GET /offline", s.handleOffline)
	mux.HandleFunc("GET /login", s.requireAnonymous(s.handleLoginPage))
	mux.HandleFunc("POST /login", s.requireCSRF(s.handleLoginPost))
	mux.HandleFunc("GET /login/totp", s.requirePending(s.handleTOTPPage))
	mux.HandleFunc("POST /login/totp", s.requirePending(s.requireCSRF(s.handleTOTPPost)))
	mux.HandleFunc("GET /setup", s.requirePending(s.handleSetupPage))
	mux.HandleFunc("POST /setup", s.requirePending(s.requireCSRF(s.handleSetupPost)))
	mux.HandleFunc("POST /logout", s.requireFull(s.requireCSRF(s.handleLogout)))
	mux.HandleFunc("GET /", s.requireFull(s.handleHome))
	mux.HandleFunc("GET /search", s.requireFull(s.handleSearch))
	mux.HandleFunc("GET /clients", s.requireFull(s.handleClients))
	mux.HandleFunc("GET /clients/new", s.requireFull(s.handleClientNew))
	mux.HandleFunc("POST /clients", s.requireFull(s.requireCSRF(s.handleClientCreate)))
	mux.HandleFunc("GET /clients/{id}", s.requireFull(s.handleClientShow))
	mux.HandleFunc("POST /clients/{id}", s.requireFull(s.requireCSRF(s.handleClientUpdate)))
	mux.HandleFunc("POST /clients/{id}/archive", s.requireFull(s.requireCSRF(s.handleClientArchive)))
	mux.HandleFunc("POST /clients/{id}/delete", s.requireFull(s.requireCSRF(s.handleClientDelete)))
	mux.HandleFunc("POST /clients/{id}/contacts", s.requireFull(s.requireCSRF(s.handleContactCreate)))
	mux.HandleFunc("POST /clients/{id}/contacts/{cid}", s.requireFull(s.requireCSRF(s.handleContactUpdate)))
	mux.HandleFunc("POST /clients/{id}/contacts/{cid}/primary", s.requireFull(s.requireCSRF(s.handleContactPrimary)))
	mux.HandleFunc("POST /clients/{id}/contacts/{cid}/delete", s.requireFull(s.requireCSRF(s.handleContactDelete)))
	mux.HandleFunc("POST /clients/{id}/notes", s.requireFull(s.requireCSRF(s.handleNoteCreate)))
	mux.HandleFunc("POST /clients/{id}/notes/{nid}", s.requireFull(s.requireCSRF(s.handleNoteUpdate)))
	mux.HandleFunc("POST /clients/{id}/notes/{nid}/pin", s.requireFull(s.requireCSRF(s.handleNotePin)))
	mux.HandleFunc("POST /clients/{id}/notes/{nid}/secret", s.requireFull(s.requireCSRF(s.handleNoteSecret)))
	mux.HandleFunc("POST /clients/{id}/notes/{nid}/delete", s.requireFull(s.requireCSRF(s.handleNoteDelete)))
	mux.HandleFunc("POST /notes/{nid}/reveal", s.requireFull(s.requireCSRF(s.handleNoteReveal)))
	mux.HandleFunc("POST /clients/{id}/projects", s.requireFull(s.requireCSRF(s.handleClientProjectCreate)))
	mux.HandleFunc("POST /clients/{id}/jobs", s.requireFull(s.requireCSRF(s.handleClientJobCreate)))

	// Projects. A project always belongs to a client (F6.4).
	mux.HandleFunc("GET /projects", s.requireFull(s.handleProjects))
	mux.HandleFunc("POST /projects", s.requireFull(s.requireCSRF(s.handleProjectCreate)))
	mux.HandleFunc("GET /projects/{id}", s.requireFull(s.handleProjectShow))
	mux.HandleFunc("POST /projects/{id}", s.requireFull(s.requireCSRF(s.handleProjectUpdate)))
	mux.HandleFunc("POST /projects/{id}/delete", s.requireFull(s.requireCSRF(s.handleProjectDelete)))
	mux.HandleFunc("POST /projects/{id}/jobs", s.requireFull(s.requireCSRF(s.handleProjectJobCreate)))

	// Jobs. A job belongs to a client and optionally to one of its projects
	// (F7.1); creation is available from the client page, project page, and
	// the global jobs view (F7.3).
	mux.HandleFunc("GET /jobs", s.requireFull(s.handleJobs))
	mux.HandleFunc("POST /jobs", s.requireFull(s.requireCSRF(s.handleJobCreate)))
	mux.HandleFunc("GET /jobs/{id}", s.requireFull(s.handleJobShow))
	mux.HandleFunc("POST /jobs/{id}", s.requireFull(s.requireCSRF(s.handleJobUpdate)))
	mux.HandleFunc("POST /jobs/{id}/delete", s.requireFull(s.requireCSRF(s.handleJobDelete)))

	mux.HandleFunc("GET /settings", s.requireFull(s.handleSettings))
	return securityHeaders(mux)
}

// securityHeaders applies the F11.7/S7 headers to every response. The theme
// bootstrap is an external script and no inline styles are used, so the CSP
// needs no unsafe-inline.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; manifest-src 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// --- middleware ---------------------------------------------------------

func (s *Server) requireFull(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.loadSession(r)
		if err != nil {
			s.serverError(w, err)
			return
		}
		if sess == nil {
			s.redirectLogin(w, r)
			return
		}
		if sess.Stage != auth.StageFull {
			s.redirectPending(w, r, sess)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessionCtxKey, sess)))
	}
}

func (s *Server) requirePending(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.loadSession(r)
		if err != nil {
			s.serverError(w, err)
			return
		}
		if sess == nil {
			s.redirectLogin(w, r)
			return
		}
		if sess.Stage == auth.StageFull {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessionCtxKey, sess)))
	}
}

// requireAnonymous allows only requests without a session; an existing pending
// or full session is sent on to the right place.
func (s *Server) requireAnonymous(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.loadSession(r)
		if err != nil {
			s.serverError(w, err)
			return
		}
		if sess != nil {
			s.redirectPending(w, r, sess)
			return
		}
		next(w, r)
	}
}

// requireCSRF rejects any non-GET request without a token matching the session
// (or, for pre-auth login, the double-submit cookie).
func (s *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		want := ""
		if sess := sessionFrom(r.Context()); sess != nil {
			want = sess.CSRFToken
		} else if c, err := r.Cookie(csrfCookieName); err == nil {
			want = c.Value
		}
		got := r.FormValue("csrf_token")
		if got == "" {
			got = r.Header.Get("X-CSRF-Token")
		}
		if want == "" || subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// --- session helpers ----------------------------------------------------

func (s *Server) loadSession(r *http.Request) (*auth.Session, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	sess, err := s.svc.GetSession(r.Context(), c.Value, s.idleTTL())
	if errors.Is(err, auth.ErrNoSession) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *Server) idleTTL() time.Duration { return s.cfg.SessionTTL / 8 }

func sessionFrom(ctx context.Context) *auth.Session {
	sess, _ := ctx.Value(sessionCtxKey).(*auth.Session)
	return sess
}

func (s *Server) redirectLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) redirectPending(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	if sess.Stage == auth.StageFull {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if sess.User.TOTPEnabled {
		http.Redirect(w, r, "/login/totp", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/setup", http.StatusSeeOther)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// ensureCSRFCookie returns the pre-auth CSRF token, setting a cookie if needed.
func (s *Server) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	token, err := auth.NewCSRFToken()
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   csrfCookieMaxAge,
	})
	return token
}

func (s *Server) secureCookies() bool {
	return strings.HasPrefix(s.cfg.BaseURL, "https://")
}

// clientIP honors X-Forwarded-For only when proxy trust is enabled (S9).
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// --- rendering and health ----------------------------------------------

type pageData struct {
	Title        string
	Error        string
	CSRFToken    string
	Username     string
	Secret       string
	OTPAuthURL   string
	Codes        []string
	User         auth.User
	Authed       bool
	Active       string
	AssetVersion string

	// Phase 4 CRM view model.
	Clients        []crm.Client
	Client         crm.Client
	Contacts       []crm.Contact
	PrimaryContact *crm.Contact
	Counts         crm.CascadeCounts
	Results        crm.Results
	Query          string
	Filter         string
	Status         string
	Sort           string
	Tab            string
	ContactForm    crm.ContactInput
	ContactFormID  int64

	// Phase 5 notes and audit view model.
	Notes []crm.Note
	Note  crm.Note
	Audit []auth.AuditRecord

	// Phase 6 projects and jobs view model.
	Projects        []crm.Project
	Project         crm.Project
	OngoingProjects []crm.Project
	Jobs            []crm.Job
	Job             crm.Job
	UpcomingJobs    []crm.Job
	OverdueJobs     []crm.Job
	ProjectForm     crm.ProjectInput
	JobForm         crm.JobInput
	FormClientID    int64
	ClientFilter    string
	ProjectFilter   string
	Due             string
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data pageData) {
	t, ok := s.tmpl[name]
	if !ok {
		s.log.Error("unknown template", "template", name)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if data.AssetVersion == "" {
		data.AssetVersion = BuildVersion
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		s.log.Error("template render failed", "template", name, "err", err)
	}
}

// renderFragment executes a single named partial (an HTMX swap target) without
// the surrounding layout.
func (s *Server) renderFragment(w http.ResponseWriter, status int, name string, data pageData) {
	if data.AssetVersion == "" {
		data.AssetVersion = BuildVersion
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := s.partials.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("template render failed", "template", name, "err", err)
	}
}

// --- static assets and PWA ----------------------------------------------

// assetHandler serves embedded static files. Assets are versioned by query
// string and safe to cache immutably; the service worker versions its cache by
// BuildVersion and drops old caches on activate.
func (s *Server) assetHandler() http.Handler {
	files := http.StripPrefix("/static/", http.FileServerFS(s.static))
	// Real builds set BuildVersion (e.g. a git sha) so the ?v= URL changes and
	// immutable caching is safe. The dev build keeps a stable URL, so it must
	// revalidate or local edits would be pinned in the browser cache.
	cache := "public, max-age=31536000, immutable"
	if BuildVersion == "dev" {
		cache = "no-cache"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", cache)
		files.ServeHTTP(w, r)
	})
}

func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	body, err := fs.ReadFile(s.static, "manifest.webmanifest")
	if err != nil {
		s.serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/manifest+json")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(body)
}

// handleServiceWorker serves sw.js with the build version substituted so a new
// deploy produces a byte-different worker that browsers pick up.
func (s *Server) handleServiceWorker(w http.ResponseWriter, r *http.Request) {
	s.serveVersioned(w, "sw.js", "text/javascript; charset=utf-8", true)
}

func (s *Server) handleOffline(w http.ResponseWriter, r *http.Request) {
	s.serveVersioned(w, "offline.html", "text/html; charset=utf-8", false)
}

func (s *Server) serveVersioned(w http.ResponseWriter, name, contentType string, sw bool) {
	body, err := fs.ReadFile(s.static, name)
	if err != nil {
		s.serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")
	if sw {
		w.Header().Set("Service-Worker-Allowed", "/")
	}
	io.WriteString(w, strings.ReplaceAll(string(body), "__BUILD_VERSION__", BuildVersion))
}

func (s *Server) serverError(w http.ResponseWriter, err error) {
	s.log.Error("request failed", "err", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

func (s *Server) renderRateLimited(w http.ResponseWriter, name, csrf string, retry time.Duration) {
	if retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
	}
	s.render(w, http.StatusTooManyRequests, name, pageData{
		Title:     "Sign in",
		Error:     "Too many attempts. Try again later.",
		CSRFToken: csrf,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := store.Health(r.Context(), s.db); err != nil {
		s.log.Error("healthz: database ping failed", "err", err)
		http.Error(w, "unhealthy", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, "ok\n")
}

// --- handlers -----------------------------------------------------------

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "login.html", pageData{
		Title:     "Sign in",
		CSRFToken: s.ensureCSRFCookie(w, r),
	})
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	now := time.Now()
	keys := []string{"ip:" + ip, "user:" + strings.ToLower(username)}
	for _, k := range keys {
		if ok, retry := s.limiter.Allow(k, now); !ok {
			s.renderRateLimited(w, "login.html", s.ensureCSRFCookie(w, r), retry)
			return
		}
	}

	user, ok, err := s.svc.Authenticate(r.Context(), username, password)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if !ok {
		for _, k := range keys {
			s.limiter.Fail(k, now)
		}
		_ = s.svc.Audit(r.Context(), auth.AuditEntry{
			Event: "login_failure", Entity: "user", IP: ip,
			Detail: map[string]any{"username": username},
		})
		s.render(w, http.StatusUnauthorized, "login.html", pageData{
			Title:     "Sign in",
			Error:     "Invalid username or password.",
			CSRFToken: s.ensureCSRFCookie(w, r),
			Username:  username,
		})
		return
	}
	for _, k := range keys {
		s.limiter.Reset(k)
	}

	// Break-glass: password verified, second factor deliberately skipped.
	if s.cfg.Disable2FA {
		if err := s.newFullSession(w, r, user, ip); err != nil {
			s.serverError(w, err)
			return
		}
		_ = s.svc.Audit(r.Context(), auth.AuditEntry{Event: "login_success", Entity: "user", EntityID: &user.ID, IP: ip,
			Detail: map[string]any{"2fa_disabled": true}})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	_, token, err := s.svc.CreateSession(r.Context(), user, auth.StagePending, pendingTTL, r.UserAgent(), ip)
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.setSessionCookie(w, token, pendingTTL)
	if user.TOTPEnabled {
		http.Redirect(w, r, "/login/totp", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/setup", http.StatusSeeOther)
}

func (s *Server) handleTOTPPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	if !sess.User.TOTPEnabled {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "totp.html", pageData{
		Title:     "Two-factor authentication",
		CSRFToken: sess.CSRFToken,
	})
}

func (s *Server) handleTOTPPost(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	ip := s.clientIP(r)
	now := time.Now()
	keys := []string{"ip:" + ip, "user:" + strings.ToLower(sess.User.Username)}
	for _, k := range keys {
		if ok, retry := s.limiter.Allow(k, now); !ok {
			s.renderRateLimited(w, "totp.html", sess.CSRFToken, retry)
			return
		}
	}

	code := strings.TrimSpace(r.FormValue("code"))
	ok := auth.ValidateTOTP(sess.User.TOTPSecret, code, now)
	recoveryUsed := false
	if !ok {
		used, err := s.svc.ConsumeRecoveryCode(r.Context(), sess.User.ID, code)
		if err != nil {
			s.serverError(w, err)
			return
		}
		if used {
			ok, recoveryUsed = true, true
		}
	}
	if !ok {
		for _, k := range keys {
			s.limiter.Fail(k, now)
		}
		_ = s.svc.Audit(r.Context(), auth.AuditEntry{
			Event: "login_failure", Entity: "user", EntityID: &sess.User.ID, IP: ip,
		})
		s.render(w, http.StatusUnauthorized, "totp.html", pageData{
			Title:     "Two-factor authentication",
			Error:     "That code did not match. Try again.",
			CSRFToken: sess.CSRFToken,
		})
		return
	}
	for _, k := range keys {
		s.limiter.Reset(k)
	}
	if err := s.svc.DeleteSession(r.Context(), sess.Token); err != nil {
		s.serverError(w, err)
		return
	}
	if recoveryUsed {
		_ = s.svc.Audit(r.Context(), auth.AuditEntry{
			Event: "recovery_code_used", Entity: "user", EntityID: &sess.User.ID, IP: ip,
		})
	}
	if err := s.newFullSession(w, r, sess.User, ip); err != nil {
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{Event: "login_success", Entity: "user", EntityID: &sess.User.ID, IP: ip})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	if sess.User.TOTPEnabled {
		http.Redirect(w, r, "/login/totp", http.StatusSeeOther)
		return
	}
	secret := sess.User.TOTPSecret
	if secret == "" {
		var err error
		secret, err = auth.NewTOTPSecret()
		if err != nil {
			s.serverError(w, err)
			return
		}
		if err := s.svc.SetTOTPSecret(r.Context(), sess.User.ID, secret); err != nil {
			s.serverError(w, err)
			return
		}
	}
	s.render(w, http.StatusOK, "setup.html", pageData{
		Title:      "Set up two-factor authentication",
		CSRFToken:  sess.CSRFToken,
		Username:   sess.User.Username,
		Secret:     secret,
		OTPAuthURL: auth.OTPAuthURL(s.svc.Issuer(), sess.User.Username, secret),
	})
}

func (s *Server) handleSetupPost(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	if sess.User.TOTPEnabled {
		http.Redirect(w, r, "/login/totp", http.StatusSeeOther)
		return
	}
	secret := sess.User.TOTPSecret
	otpURL := auth.OTPAuthURL(s.svc.Issuer(), sess.User.Username, secret)
	code := strings.TrimSpace(r.FormValue("code"))
	if !auth.ValidateTOTP(secret, code, time.Now()) {
		s.render(w, http.StatusBadRequest, "setup.html", pageData{
			Title:      "Set up two-factor authentication",
			Error:      "That code did not match. Try again.",
			CSRFToken:  sess.CSRFToken,
			Username:   sess.User.Username,
			Secret:     secret,
			OTPAuthURL: otpURL,
		})
		return
	}
	if err := s.svc.EnableTOTP(r.Context(), sess.User.ID); err != nil {
		s.serverError(w, err)
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
	if err := s.svc.DeleteSession(r.Context(), sess.Token); err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.newFullSession(w, r, sess.User, s.clientIP(r)); err != nil {
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{Event: "totp_enrolled", Entity: "user", EntityID: &sess.User.ID, IP: s.clientIP(r)})
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{Event: "login_success", Entity: "user", EntityID: &sess.User.ID, IP: s.clientIP(r)})
	s.render(w, http.StatusOK, "recovery.html", pageData{
		Title: "Recovery codes",
		Codes: codes,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	if err := s.svc.DeleteSession(r.Context(), sess.Token); err != nil {
		s.serverError(w, err)
		return
	}
	s.clearSessionCookie(w)
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{Event: "logout", Entity: "user", EntityID: &sess.User.ID, IP: s.clientIP(r)})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	recent, err := s.crm.RecentClients(r.Context(), 6)
	if err != nil {
		s.serverError(w, err)
		return
	}
	ongoing, err := s.crm.OngoingProjects(r.Context(), 5)
	if err != nil {
		s.serverError(w, err)
		return
	}
	overdue, err := s.crm.OverdueJobs(r.Context(), 5)
	if err != nil {
		s.serverError(w, err)
		return
	}
	upcoming, err := s.crm.UpcomingJobs(r.Context(), 5)
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, http.StatusOK, "home.html", pageData{
		Title:           "Dashboard",
		CSRFToken:       sess.CSRFToken,
		User:            sess.User,
		Authed:          true,
		Active:          "home",
		Clients:         recent,
		OngoingProjects: ongoing,
		OverdueJobs:     overdue,
		UpcomingJobs:    upcoming,
	})
}

// handleSettings renders the global audit view (F13.3). The rest of the
// Settings page lands in Phase 7.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	audit, err := s.svc.ListAudit(r.Context(), 100)
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, http.StatusOK, "settings.html", pageData{
		Title:     "Settings",
		CSRFToken: sess.CSRFToken,
		User:      sess.User,
		Authed:    true,
		Active:    "settings",
		Audit:     audit,
	})
}

// newFullSession issues a completed session and sets its cookie.
func (s *Server) newFullSession(w http.ResponseWriter, r *http.Request, user auth.User, ip string) error {
	_, token, err := s.svc.CreateSession(r.Context(), user, auth.StageFull, s.cfg.SessionTTL, r.UserAgent(), ip)
	if err != nil {
		return err
	}
	s.setSessionCookie(w, token, s.cfg.SessionTTL)
	return nil
}
