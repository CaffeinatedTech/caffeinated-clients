package web

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/CaffeinatedTech/caffeinated-clients/internal/auth"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/config"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/store"
)

const testPassword = "correct horse battery staple"

func newTestServer(t *testing.T, mutate func(*config.Config)) (*httptest.Server, *sql.DB, *auth.Service, *config.Config) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 11)
	}
	db, err := store.Open(t.TempDir()+"/clients.db", key)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := store.Migrate(context.Background(), db); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	params := auth.Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}
	svc := auth.NewService(db, params, "caffeinated-clients")
	if _, err := svc.Bootstrap(context.Background(), "admin", testPassword); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	cfg := &config.Config{BaseURL: "http://localhost:8080", SessionTTL: time.Hour, LogLevel: slog.LevelError}
	if mutate != nil {
		mutate(cfg)
	}
	srv, err := New(svc, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), db)
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, db, svc, cfg
}

func newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func get(t *testing.T, c *http.Client, u string) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func postForm(t *testing.T, c *http.Client, u string, form url.Values) (*http.Response, string) {
	t.Helper()
	resp, err := c.PostForm(u, form)
	if err != nil {
		t.Fatalf("POST %s: %v", u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

var csrfRe = regexp.MustCompile(`name="csrf_token" value="([^"]*)"`)

func extractCSRF(t *testing.T, body string) string {
	t.Helper()
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf token in body: %s", body)
	}
	return m[1]
}

func csrfFromDB(t *testing.T, db *sql.DB, stage string) string {
	t.Helper()
	var tok string
	if err := db.QueryRow(`SELECT csrf_token FROM sessions WHERE stage = ? ORDER BY id DESC LIMIT 1`, stage).Scan(&tok); err != nil {
		t.Fatalf("read %s session csrf: %v", stage, err)
	}
	return tok
}

func loginPassword(t *testing.T, c *http.Client, ts *httptest.Server) {
	t.Helper()
	_, body := get(t, c, ts.URL+"/login")
	resp, _ := postForm(t, c, ts.URL+"/login", url.Values{
		"csrf_token": {extractCSRF(t, body)},
		"username":   {"admin"},
		"password":   {testPassword},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST /login status = %d, want 303", resp.StatusCode)
	}
}

func TestPasswordThenTOTPEnrollmentThenHome(t *testing.T) {
	ts, db, _, _ := newTestServer(t, nil)
	c := newClient(t)

	_, body := get(t, c, ts.URL+"/login")
	resp, _ := postForm(t, c, ts.URL+"/login", url.Values{
		"csrf_token": {extractCSRF(t, body)},
		"username":   {"admin"},
		"password":   {testPassword},
	})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/setup" {
		t.Fatalf("login: status=%d location=%q, want 303 /setup", resp.StatusCode, resp.Header.Get("Location"))
	}

	resp, body = get(t, c, ts.URL+"/setup")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /setup = %d", resp.StatusCode)
	}
	if !strings.Contains(body, "data:image/png;base64,") {
		t.Fatal("GET /setup does not render a QR code")
	}
	var secret string
	if err := db.QueryRow(`SELECT totp_secret FROM users`).Scan(&secret); err != nil {
		t.Fatalf("read secret: %v", err)
	}
	if secret == "" {
		t.Fatal("setup did not generate a TOTP secret")
	}
	code, err := auth.TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	resp, body = postForm(t, c, ts.URL+"/setup", url.Values{
		"csrf_token": {csrfFromDB(t, db, auth.StagePending)},
		"code":       {code},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /setup = %d", resp.StatusCode)
	}
	if n := strings.Count(body, "<code>"); n < auth.RecoveryCodeCount {
		t.Fatalf("recovery page shows %d codes, want %d", n, auth.RecoveryCodeCount)
	}

	resp, body = get(t, c, ts.URL+"/")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Signed in as") {
		t.Fatalf("GET / = %d, body=%q", resp.StatusCode, body)
	}
}

func TestWrongPasswordAndCSRF(t *testing.T) {
	ts, _, _, _ := newTestServer(t, nil)
	c := newClient(t)

	if resp, _ := get(t, c, ts.URL+"/"); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("unauthenticated GET / = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	_, body := get(t, c, ts.URL+"/login")
	resp, _ := postForm(t, c, ts.URL+"/login", url.Values{
		"username": {"admin"}, "password": {testPassword},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("login without CSRF = %d, want 403", resp.StatusCode)
	}

	resp, _ = postForm(t, c, ts.URL+"/login", url.Values{
		"csrf_token": {extractCSRF(t, body)},
		"username":   {"admin"},
		"password":   {"wrong password"},
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password = %d, want 401", resp.StatusCode)
	}
}

func TestRecoveryCodeLoginSingleUse(t *testing.T) {
	ts, db, svc, _ := newTestServer(t, nil)
	ctx := context.Background()
	user, err := svc.GetUser(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetTOTPSecret(ctx, user.ID, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"); err != nil {
		t.Fatal(err)
	}
	if err := svc.EnableTOTP(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	codes, err := auth.NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.StoreRecoveryCodes(ctx, user.ID, codes); err != nil {
		t.Fatal(err)
	}

	c := newClient(t)
	loginPassword(t, c, ts)

	resp, _ := postForm(t, c, ts.URL+"/login/totp", url.Values{
		"csrf_token": {csrfFromDB(t, db, auth.StagePending)},
		"code":       {codes[0]},
	})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("recovery login = %d %q, want 303 /", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Log out, then try the same recovery code again.
	resp, _ = postForm(t, c, ts.URL+"/logout", url.Values{
		"csrf_token": {csrfFromDB(t, db, auth.StageFull)},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout = %d, want 303", resp.StatusCode)
	}

	loginPassword(t, c, ts)
	resp, _ = postForm(t, c, ts.URL+"/login/totp", url.Values{
		"csrf_token": {csrfFromDB(t, db, auth.StagePending)},
		"code":       {codes[0]},
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reused recovery code = %d, want 401", resp.StatusCode)
	}
}

func TestBreakGlassDisablesTOTP(t *testing.T) {
	ts, _, _, _ := newTestServer(t, func(c *config.Config) { c.Disable2FA = true })
	c := newClient(t)

	_, body := get(t, c, ts.URL+"/login")
	resp, _ := postForm(t, c, ts.URL+"/login", url.Values{
		"csrf_token": {extractCSRF(t, body)},
		"username":   {"admin"},
		"password":   {testPassword},
	})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("break-glass login = %d %q, want 303 /", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, body := get(t, c, ts.URL+"/"); resp.StatusCode != http.StatusOK || !strings.Contains(body, "Signed in") {
		t.Fatalf("GET / after break-glass = %d", resp.StatusCode)
	}
}
