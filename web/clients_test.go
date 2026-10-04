package web

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/CaffeinatedTech/caffeinated-clients/internal/auth"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/config"
)

// TestClientContactSearchFlow exercises the Phase 4 HTTP paths end to end with
// the break-glass login (no TOTP) so the test stays offline and fast.
func TestClientContactSearchFlow(t *testing.T) {
	ts, db, _, _ := newTestServer(t, func(c *config.Config) { c.Disable2FA = true })
	c := newClient(t)
	loginPassword(t, c, ts)
	csrf := csrfFromDB(t, db, auth.StageFull)

	// Create a client; it must be reachable with only a name.
	resp, _ := postForm(t, c, ts.URL+"/clients", url.Values{
		"csrf_token": {csrf},
		"name":       {"Acme Co"},
		"phone":      {"+1 555 0100"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create client = %d, want 303", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/clients/") {
		t.Fatalf("create client Location = %q", loc)
	}

	// The client page renders.
	if resp, body := get(t, c, ts.URL+loc); resp.StatusCode != http.StatusOK || !strings.Contains(body, "Acme Co") {
		t.Fatalf("client page = %d, body=%q", resp.StatusCode, body)
	}

	// Add a primary contact.
	resp, _ = postForm(t, c, ts.URL+loc+"/contacts", url.Values{
		"csrf_token": {csrf},
		"name":       {"Ada Lovelace"},
		"phone":      {"555-0100"},
		"is_primary": {"1"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create contact = %d, want 303", resp.StatusCode)
	}

	// Search hits the live fragment for HTMX. A name query finds the client;
	// any phone formatting finds both the client and its contact.
	cases := []struct {
		query       string
		wantClient  bool
		wantContact bool
	}{
		{"Acme", true, false},
		{"555-0100", true, true},
		{"+15550100", true, true},
	}
	for _, tc := range cases {
		req, err := http.NewRequest("GET", ts.URL+"/search?q="+url.QueryEscape(tc.query), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("HX-Request", "true")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("search %q: %v", tc.query, err)
		}
		body := readBody(t, resp)
		if strings.Contains(body, "<html") {
			t.Errorf("search %q returned a full page, want a fragment", tc.query)
		}
		if got := strings.Contains(body, "Acme Co"); got != tc.wantClient {
			t.Errorf("search %q client present = %v, want %v", tc.query, got, tc.wantClient)
		}
		if got := strings.Contains(body, "Ada Lovelace"); got != tc.wantContact {
			t.Errorf("search %q contact present = %v, want %v", tc.query, got, tc.wantContact)
		}
	}

	// A secret note must never surface in search (F5.5/F8.5).
	res, err := db.Exec(`INSERT INTO notes (client_id, title, is_secret) VALUES ((SELECT id FROM clients LIMIT 1), 'Router admin', 1)`)
	if err != nil {
		t.Fatalf("insert secret note: %v", err)
	}
	if _, err := res.RowsAffected(); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/search?q=Router", nil)
	req.Header.Set("HX-Request", "true")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if body := readBody(t, resp); strings.Contains(body, "Router admin") {
		t.Fatalf("secret note leaked into search: %s", body)
	}
}

// TestClientCascadeDeleteHTTP deletes a client through the route and confirms
// the dependent rows are gone.
func TestClientCascadeDeleteHTTP(t *testing.T) {
	ts, db, _, _ := newTestServer(t, func(c *config.Config) { c.Disable2FA = true })
	c := newClient(t)
	loginPassword(t, c, ts)
	csrf := csrfFromDB(t, db, auth.StageFull)

	resp, _ := postForm(t, c, ts.URL+"/clients", url.Values{"csrf_token": {csrf}, "name": {"Acme Co"}})
	loc := resp.Header.Get("Location")
	if _, err := db.Exec(`INSERT INTO notes (client_id, title) VALUES ((SELECT id FROM clients LIMIT 1), 'Note')`); err != nil {
		t.Fatal(err)
	}

	resp, _ = postForm(t, c, ts.URL+loc+"/delete", url.Values{"csrf_token": {csrf}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete = %d, want 303", resp.StatusCode)
	}
	var clients, notes int
	if err := db.QueryRow(`SELECT (SELECT count(*) FROM clients), (SELECT count(*) FROM notes)`).Scan(&clients, &notes); err != nil {
		t.Fatal(err)
	}
	if clients != 0 || notes != 0 {
		t.Fatalf("after cascade delete: clients=%d notes=%d, want 0/0", clients, notes)
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}
