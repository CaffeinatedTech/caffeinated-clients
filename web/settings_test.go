package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/CaffeinatedTech/caffeinated-clients/internal/auth"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/config"
)

// TestSettingsPasswordChange covers the password re-auth path: a wrong current
// password is rejected, a good one is stored, and only the new password works.
func TestSettingsPasswordChange(t *testing.T) {
	ts, db, svc, _ := newTestServer(t, func(c *config.Config) { c.Disable2FA = true })
	c := newClient(t)
	loginPassword(t, c, ts)
	csrf := csrfFromDB(t, db, auth.StageFull)

	resp, body := postForm(t, c, ts.URL+"/settings/password", url.Values{
		"csrf_token": {csrf}, "current_password": {"wrong"}, "new_password": {"new-passphrase"}, "new_password_confirm": {"new-passphrase"},
	})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Current password did not match") {
		t.Fatalf("wrong current password = %d, body=%q", resp.StatusCode, body)
	}

	resp, _ = postForm(t, c, ts.URL+"/settings/password", url.Values{
		"csrf_token": {csrf}, "current_password": {testPassword}, "new_password": {"new-passphrase"}, "new_password_confirm": {"new-passphrase"},
	})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings?notice=password" {
		t.Fatalf("change password = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	user, err := svc.GetUser(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := svc.Authenticate(t.Context(), user.Username, testPassword); ok {
		t.Fatal("old password still authenticates")
	}
	if _, ok, _ := svc.Authenticate(t.Context(), user.Username, "new-passphrase"); !ok {
		t.Fatal("new password does not authenticate")
	}
}

// TestSettingsExport covers F12.3: the default export excludes secret notes,
// the opt-in POST includes them only with both confirmations, and both are
// audited.
func TestSettingsExport(t *testing.T) {
	ts, db, _, _ := newTestServer(t, func(c *config.Config) { c.Disable2FA = true })
	c := newClient(t)
	loginPassword(t, c, ts)
	csrf := csrfFromDB(t, db, auth.StageFull)

	resp, _ := postForm(t, c, ts.URL+"/clients", url.Values{"csrf_token": {csrf}, "name": {"Acme Co"}})
	clientLoc := resp.Header.Get("Location")
	if clientLoc == "" {
		t.Fatalf("create client = %d, no Location", resp.StatusCode)
	}
	postForm(t, c, ts.URL+clientLoc+"/notes", url.Values{
		"csrf_token": {csrf}, "title": {"Public"}, "body": {"PublicBody"},
	})
	postForm(t, c, ts.URL+clientLoc+"/notes", url.Values{
		"csrf_token": {csrf}, "title": {"Hidden"}, "body": {"SecretBody"}, "is_secret": {"1"},
	})

	resp, body := get(t, c, ts.URL+"/settings/export")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET export = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("export Content-Type = %q", ct)
	}
	if !strings.Contains(resp.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("export missing attachment disposition: %q", resp.Header.Get("Content-Disposition"))
	}
	if !strings.Contains(body, "PublicBody") {
		t.Fatal("export missing public note")
	}
	if strings.Contains(body, "SecretBody") {
		t.Fatal("default export leaked a secret note body")
	}

	// Including secrets needs both boxes ticked.
	resp, _ = postForm(t, c, ts.URL+"/settings/export", url.Values{
		"csrf_token": {csrf}, "include_secrets": {"1"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unconfirmed secret export = %d, want 400", resp.StatusCode)
	}
	resp, body = postForm(t, c, ts.URL+"/settings/export", url.Values{
		"csrf_token": {csrf}, "include_secrets": {"1"}, "confirm": {"1"},
	})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "SecretBody") {
		t.Fatalf("secret export = %d, missing body", resp.StatusCode)
	}

	var exports int
	if err := db.QueryRow(`SELECT count(*) FROM audit_log WHERE event IN ('data_export', 'data_export_secrets')`).Scan(&exports); err != nil {
		t.Fatal(err)
	}
	if exports != 2 {
		t.Fatalf("export audit entries = %d, want 2", exports)
	}
}

// TestSettingsRecoveryAndReenroll covers regenerating recovery codes and
// re-enrolling the authenticator, using break-glass so only the password is
// needed to re-authenticate.
func TestSettingsRecoveryAndReenroll(t *testing.T) {
	ts, db, _, _ := newTestServer(t, func(c *config.Config) { c.Disable2FA = true })
	c := newClient(t)
	loginPassword(t, c, ts)
	csrf := csrfFromDB(t, db, auth.StageFull)

	resp, body := postForm(t, c, ts.URL+"/settings/recovery-codes", url.Values{
		"csrf_token": {csrf}, "password": {testPassword},
	})
	if resp.StatusCode != http.StatusOK || strings.Count(body, "<code>") != auth.RecoveryCodeCount {
		t.Fatalf("regenerate codes = %d, codes=%d", resp.StatusCode, strings.Count(body, "<code>"))
	}
	var unused int
	if err := db.QueryRow(`SELECT count(*) FROM recovery_codes WHERE used_at IS NULL`).Scan(&unused); err != nil {
		t.Fatal(err)
	}
	if unused != auth.RecoveryCodeCount {
		t.Fatalf("stored unused codes = %d, want %d", unused, auth.RecoveryCodeCount)
	}

	// Start a re-enrollment, then confirm with a code from the pending secret.
	resp, _ = postForm(t, c, ts.URL+"/settings/2fa/start", url.Values{
		"csrf_token": {csrf}, "password": {testPassword},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("2fa start = %d", resp.StatusCode)
	}
	var pending string
	if err := db.QueryRow(`SELECT totp_pending_secret FROM users`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending == "" {
		t.Fatal("re-enrollment did not store a pending secret")
	}
	code, err := auth.TOTPCode(pending, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp, body = postForm(t, c, ts.URL+"/settings/2fa/confirm", url.Values{
		"csrf_token": {csrf}, "code": {code},
	})
	if resp.StatusCode != http.StatusOK || strings.Count(body, "<code>") != auth.RecoveryCodeCount {
		t.Fatalf("2fa confirm = %d, codes=%d", resp.StatusCode, strings.Count(body, "<code>"))
	}
	var secret, after string
	var enabled int
	if err := db.QueryRow(`SELECT totp_secret, totp_pending_secret, totp_enabled FROM users`).Scan(&secret, &after, &enabled); err != nil {
		t.Fatal(err)
	}
	if secret != pending || after != "" || enabled != 1 {
		t.Fatalf("after re-enroll: secret=%q pending=%q enabled=%d", secret, after, enabled)
	}
}
