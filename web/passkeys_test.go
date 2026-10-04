package web

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/CaffeinatedTech/caffeinated-clients/internal/auth"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/config"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/store"
)

// newEmptyServer builds a server with no account yet, for first-run tests.
func newEmptyServer(t *testing.T) (*httptest.Server, *auth.Service, *sql.DB) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 41)
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
	cfg := &config.Config{BaseURL: "http://localhost:8080", SessionTTL: time.Hour, LogLevel: slog.LevelError}
	srv, err := New(svc, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), db)
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, svc, db
}

func addFakePasskey(t *testing.T, svc *auth.Service, userID int64) {
	t.Helper()
	_, err := svc.AddPasskey(context.Background(), auth.Passkey{
		UserID: userID, CredentialID: []byte("fake-credential"), PublicKey: []byte("fake-public-key"),
		AttestationType: "none", Name: "Test passkey",
	})
	if err != nil {
		t.Fatalf("AddPasskey: %v", err)
	}
}

func makePasskeyOnly(t *testing.T, svc *auth.Service) auth.User {
	t.Helper()
	ctx := context.Background()
	u, err := svc.GetUser(ctx)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if err := svc.RemovePassword(ctx, u.ID); err != nil {
		t.Fatalf("RemovePassword: %v", err)
	}
	addFakePasskey(t, svc, u.ID)
	return u
}

func TestPasskeyOnlyHidesPasswordAndRejectsPost(t *testing.T) {
	ts, _, svc, _ := newTestServer(t, nil)
	makePasskeyOnly(t, svc)

	c := newClient(t)
	resp, body := get(t, c, ts.URL+"/login")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /login = %d", resp.StatusCode)
	}
	if !strings.Contains(body, "Sign in with a passkey") {
		t.Fatal("login page does not offer a passkey button")
	}
	if strings.Contains(body, `name="password"`) {
		t.Fatal("passkey-only account rendered the password form")
	}
	if !strings.Contains(body, "/login/recovery") {
		t.Fatal("passkey-only account does not offer a recovery-code link")
	}

	// A POST with a valid CSRF token still must be refused before any Argon2.
	resp, _ = postForm(t, c, ts.URL+"/login", url.Values{
		"csrf_token": {extractCSRF(t, body)},
		"username":   {"admin"},
		"password":   {testPassword},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /login on passkey-only account = %d, want 403", resp.StatusCode)
	}
}

func TestPasswordAccountShowsBothMethods(t *testing.T) {
	ts, _, svc, _ := newTestServer(t, nil)
	u, err := svc.GetUser(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	addFakePasskey(t, svc, u.ID)

	c := newClient(t)
	_, body := get(t, c, ts.URL+"/login")
	if !strings.Contains(body, "Sign in with a passkey") || !strings.Contains(body, `name="password"`) {
		t.Fatal("password account with a passkey should show both sign-in methods")
	}
}

func TestSettingsRendersPasskeyList(t *testing.T) {
	ts, _, svc, _ := newTestServer(t, nil)
	ctx := context.Background()
	u, err := svc.GetUser(ctx)
	if err != nil {
		t.Fatal(err)
	}
	addFakePasskey(t, svc, u.ID)

	_, token, err := svc.CreateSession(ctx, u, auth.StageFull, time.Hour, "test", "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	c := newClient(t)
	u0, _ := url.Parse(ts.URL)
	c.Jar.SetCookies(u0, []*http.Cookie{{Name: sessionCookieName, Value: token, Path: "/"}})

	resp, body := get(t, c, ts.URL+"/settings")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /settings = %d", resp.StatusCode)
	}
	for _, want := range []string{"Passkeys", "Test passkey", "Remove passkey", "Remove password"} {
		if !strings.Contains(body, want) {
			t.Fatalf("settings page missing %q", want)
		}
	}
}

func TestLoginPasskeyBeginReturnsOptions(t *testing.T) {
	ts, _, svc, _ := newTestServer(t, nil)
	u, err := svc.GetUser(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	addFakePasskey(t, svc, u.ID)

	c := newClient(t)
	_, body := get(t, c, ts.URL+"/login")
	resp, out := postForm(t, c, ts.URL+"/login/passkey/begin", url.Values{
		"csrf_token": {extractCSRF(t, body)},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("passkey begin = %d, body=%s", resp.StatusCode, out)
	}
	if !strings.Contains(out, `"publicKey"`) || !strings.Contains(out, `"challenge"`) {
		t.Fatalf("begin response is not assertion options: %s", out)
	}
	found := false
	for _, ck := range resp.Cookies() {
		if ck.Name == challengeCookieName {
			found = true
		}
	}
	if !found {
		t.Fatal("passkey begin did not set a challenge cookie")
	}
}

func TestRecoveryLoginStandaloneForPasskeyOnly(t *testing.T) {
	ts, _, svc, _ := newTestServer(t, nil)
	u := makePasskeyOnly(t, svc)
	codes, err := auth.NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.StoreRecoveryCodes(context.Background(), u.ID, codes); err != nil {
		t.Fatal(err)
	}

	c := newClient(t)
	resp, body := get(t, c, ts.URL+"/login/recovery")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /login/recovery = %d", resp.StatusCode)
	}
	resp, _ = postForm(t, c, ts.URL+"/login/recovery", url.Values{
		"csrf_token": {extractCSRF(t, body)},
		"code":       {codes[0]},
	})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("recovery login = %d %q, want 303 /", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, body := get(t, c, ts.URL+"/"); resp.StatusCode != http.StatusOK || !strings.Contains(body, "Signed in") {
		t.Fatalf("GET / after recovery login = %d", resp.StatusCode)
	}
	// The code is single-use.
	c2 := newClient(t)
	_, b2 := get(t, c2, ts.URL+"/login/recovery")
	resp, _ = postForm(t, c2, ts.URL+"/login/recovery", url.Values{
		"csrf_token": {extractCSRF(t, b2)},
		"code":       {codes[0]},
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reused recovery code = %d, want 401", resp.StatusCode)
	}
}

func TestRegisterOnlyWhenNoAccount(t *testing.T) {
	ts, _, _ := newEmptyServer(t)

	c := newClient(t)
	resp, body := get(t, c, ts.URL+"/register")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Create with a passkey") {
		t.Fatalf("GET /register = %d, body=%s", resp.StatusCode, body)
	}

	// Create a password account through the first-run form.
	resp, _ = postForm(t, c, ts.URL+"/register/password", url.Values{
		"csrf_token":       {extractCSRF(t, body)},
		"name":             {"Adam"},
		"password":         {testPassword},
		"password_confirm": {testPassword},
	})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/setup" {
		t.Fatalf("register password = %d %q, want 303 /setup", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Once an account exists, registration is closed.
	c2 := newClient(t)
	resp, _ = get(t, c2, ts.URL+"/register")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("GET /register with account = %d %q, want 303 /login", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestSettingsRendersPasskeyOnly(t *testing.T) {
	ts, _, svc, _ := newTestServer(t, nil)
	u := makePasskeyOnly(t, svc)

	_, token, err := svc.CreateSession(context.Background(), u, auth.StageFull, time.Hour, "test", "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	c := newClient(t)
	u0, _ := url.Parse(ts.URL)
	c.Jar.SetCookies(u0, []*http.Cookie{{Name: sessionCookieName, Value: token, Path: "/"}})

	resp, body := get(t, c, ts.URL+"/settings")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /settings = %d", resp.StatusCode)
	}
	if !strings.Contains(body, "signs in with passkeys only") {
		t.Fatal("passkey-only settings page missing the passkey-only note")
	}
	for _, absent := range []string{"Change password", "Two-factor authentication"} {
		if strings.Contains(body, absent) {
			t.Fatalf("passkey-only settings page unexpectedly shows %q", absent)
		}
	}
	if !strings.Contains(body, "Regenerate recovery codes") {
		t.Fatal("passkey-only settings page must allow regenerating recovery codes")
	}
}
