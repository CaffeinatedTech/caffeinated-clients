package web

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/CaffeinatedTech/caffeinated-clients/internal/auth"
)

func TestSecurityHeaders(t *testing.T) {
	ts, _, _, _ := newTestServer(t, nil)
	resp, _ := get(t, newClient(t), ts.URL+"/login")

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "same-origin",
		"X-Frame-Options":        "DENY",
	}
	for header, value := range want {
		if got := resp.Header.Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q missing %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP should not allow unsafe-inline/unsafe-eval: %q", csp)
	}
}

func TestStaticAndPWARoutes(t *testing.T) {
	ts, _, _, _ := newTestServer(t, nil)
	c := newClient(t)

	cases := []struct {
		path      string
		content   string
		substring string
	}{
		{"/static/app.css", "text/css", "tailwind"},
		{"/static/theme.js", "javascript", "cc-theme"},
		{"/static/htmx.min.js", "javascript", "htmx"},
		{"/manifest.webmanifest", "application/manifest+json", `"start_url"`},
		{"/sw.js", "javascript", "cc-static-"},
		{"/offline", "text/html", "You're offline"},
	}
	for _, tc := range cases {
		resp, body := get(t, c, ts.URL+tc.path)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", tc.path, resp.StatusCode)
			continue
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, tc.content) {
			t.Errorf("GET %s Content-Type = %q, want substring %q", tc.path, ct, tc.content)
		}
		if !strings.Contains(body, tc.substring) {
			t.Errorf("GET %s body missing %q", tc.path, tc.substring)
		}
		if strings.Contains(body, "__BUILD_VERSION__") {
			t.Errorf("GET %s still contains the build-version placeholder", tc.path)
		}
	}
}

func TestTemplateSmoke(t *testing.T) {
	tmpls, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	if len(tmpls) == 0 {
		t.Fatal("no page templates parsed")
	}
	data := pageData{
		Title:        "Test",
		CSRFToken:    "csrf-token",
		Username:     "admin",
		Secret:       "SECRETKEY",
		OTPAuthURL:   "otpauth://totp/x",
		Codes:        []string{"AAAA-BBBB"},
		User:         auth.User{ID: 1, Username: "admin"},
		Authed:       true,
		Active:       "home",
		AssetVersion: "test",
	}
	for name := range tmpls {
		var buf bytes.Buffer
		if err := tmpls[name].ExecuteTemplate(&buf, "layout", data); err != nil {
			t.Errorf("render %s: %v", name, err)
			continue
		}
		if buf.Len() == 0 {
			t.Errorf("render %s produced no output", name)
		}
	}
}
