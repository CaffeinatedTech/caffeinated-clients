package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/CaffeinatedTech/caffeinated-clients/internal/auth"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/config"
)

// TestNoteSecretRevealFlow covers the Phase 5 HTTP paths: secret masking,
// no-store reveal, audit recording, search exclusion, and flag preservation on
// edit, using the break-glass login so the test stays offline and fast.
func TestNoteSecretRevealFlow(t *testing.T) {
	ts, db, _, _ := newTestServer(t, func(c *config.Config) { c.Disable2FA = true })
	c := newClient(t)
	loginPassword(t, c, ts)
	csrf := csrfFromDB(t, db, auth.StageFull)

	resp, _ := postForm(t, c, ts.URL+"/clients", url.Values{"csrf_token": {csrf}, "name": {"Acme Co"}})
	clientLoc := resp.Header.Get("Location")
	if clientLoc == "" {
		t.Fatalf("create client = %d, no Location", resp.StatusCode)
	}
	var clientID int64
	if err := db.QueryRow(`SELECT id FROM clients LIMIT 1`).Scan(&clientID); err != nil {
		t.Fatal(err)
	}

	// Create one public and one secret note.
	if resp, _ := postForm(t, c, ts.URL+clientLoc+"/notes", url.Values{
		"csrf_token": {csrf}, "title": {"Public note"}, "body": {"PublicBody"},
	}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("public create = %d, want 303", resp.StatusCode)
	}
	if resp, _ := postForm(t, c, ts.URL+clientLoc+"/notes", url.Values{
		"csrf_token": {csrf}, "title": {"Router admin"}, "body": {"SecretBody"}, "is_secret": {"1"},
	}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("secret create = %d, want 303", resp.StatusCode)
	}

	// The ordinary notes tab renders the public body but never the secret body.
	body := ""
	if resp, b := get(t, c, ts.URL+clientLoc+"?tab=notes"); resp.StatusCode != http.StatusOK {
		t.Fatalf("notes tab = %d", resp.StatusCode)
	} else {
		body = b
	}
	if !strings.Contains(body, "PublicBody") {
		t.Errorf("notes tab missing public body")
	}
	if strings.Contains(body, "SecretBody") {
		t.Errorf("secret body leaked into ordinary render")
	}

	// A secret note is never searchable, by title or body (F5.5).
	req, _ := http.NewRequest("GET", ts.URL+"/search?q="+url.QueryEscape("Router"), nil)
	req.Header.Set("HX-Request", "true")
	sresp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if got := readBody(t, sresp); strings.Contains(got, "Router admin") {
		t.Fatalf("secret note title leaked into search: %s", got)
	}

	var secretID int64
	if err := db.QueryRow(`SELECT id FROM notes WHERE is_secret = 1`).Scan(&secretID); err != nil {
		t.Fatal(err)
	}

	// Reveal returns the body for this request only, no-store, and is audited.
	req, _ = http.NewRequest("POST", ts.URL+"/notes/"+itoa(secretID)+"/reveal", strings.NewReader("csrf_token="+url.QueryEscape(csrf)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	rresp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if rresp.StatusCode != http.StatusOK {
		t.Fatalf("reveal = %d, want 200", rresp.StatusCode)
	}
	if cc := rresp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("reveal Cache-Control = %q, want no-store", cc)
	}
	if rb := readBody(t, rresp); !strings.Contains(rb, "SecretBody") {
		t.Fatalf("reveal did not return the body: %s", rb)
	}
	var reveals int
	if err := db.QueryRow(`SELECT count(*) FROM audit_log WHERE event = 'secret_note_reveal' AND entity_id = ?`, secretID).Scan(&reveals); err != nil {
		t.Fatal(err)
	}
	if reveals != 1 {
		t.Fatalf("reveal audit entries = %d, want 1", reveals)
	}

	// Reveal refuses non-secret notes.
	var publicID int64
	if err := db.QueryRow(`SELECT id FROM notes WHERE is_secret = 0`).Scan(&publicID); err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest("POST", ts.URL+"/notes/"+itoa(publicID)+"/reveal", strings.NewReader("csrf_token="+url.QueryEscape(csrf)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	presp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if presp.StatusCode != http.StatusNotFound {
		t.Fatalf("reveal non-secret = %d, want 404", presp.StatusCode)
	}
	presp.Body.Close()

	// Editing a secret note keeps it secret (F4.6).
	if resp, _ := postForm(t, c, ts.URL+clientLoc+"/notes/"+itoa(secretID), url.Values{
		"csrf_token": {csrf}, "title": {"Router admin v2"}, "body": {"SecretBody2"},
	}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("edit secret = %d, want 303", resp.StatusCode)
	}
	var stillSecret int
	if err := db.QueryRow(`SELECT is_secret FROM notes WHERE id = ?`, secretID).Scan(&stillSecret); err != nil {
		t.Fatal(err)
	}
	if stillSecret != 1 {
		t.Fatalf("edit cleared the secret flag")
	}

	// The global audit view in Settings lists the reveal.
	if resp, b := get(t, c, ts.URL+"/settings"); resp.StatusCode != http.StatusOK || !strings.Contains(b, "secret note reveal") {
		t.Errorf("settings audit view = %d, missing reveal entry", resp.StatusCode)
	}
}

// TestJobNotesHTTP covers F7.6 over HTTP: job notes render on the job page,
// a secret body never leaks, the reveal fragment posts back to the job scope,
// job notes stay out of the client notes tab, and deleting the job removes them.
func TestJobNotesHTTP(t *testing.T) {
	ts, db, _, _ := newTestServer(t, func(c *config.Config) { c.Disable2FA = true })
	c := newClient(t)
	loginPassword(t, c, ts)
	csrf := csrfFromDB(t, db, auth.StageFull)

	if resp, _ := postForm(t, c, ts.URL+"/clients", url.Values{"csrf_token": {csrf}, "name": {"Acme Co"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create client = %d", resp.StatusCode)
	}
	var clientID int64
	if err := db.QueryRow(`SELECT id FROM clients LIMIT 1`).Scan(&clientID); err != nil {
		t.Fatal(err)
	}
	if resp, _ := postForm(t, c, ts.URL+"/jobs", url.Values{
		"csrf_token": {csrf}, "client_id": {itoa(clientID)}, "title": {"Fix DNS"},
	}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create job = %d, want 303", resp.StatusCode)
	}
	var jobID int64
	if err := db.QueryRow(`SELECT id FROM jobs LIMIT 1`).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	jobLoc := "/jobs/" + itoa(jobID)

	// One untitled note and one secret note.
	if resp, _ := postForm(t, c, ts.URL+jobLoc+"/notes", url.Values{
		"csrf_token": {csrf}, "body": {"ping gateway"},
	}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("job note create = %d, want 303", resp.StatusCode)
	}
	if resp, _ := postForm(t, c, ts.URL+jobLoc+"/notes", url.Values{
		"csrf_token": {csrf}, "title": {"Router"}, "body": {"SecretBody"}, "is_secret": {"1"},
	}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("secret job note create = %d, want 303", resp.StatusCode)
	}

	// The job page shows the public body and never the secret body.
	resp, body := get(t, c, ts.URL+jobLoc)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "ping gateway") {
		t.Fatalf("job page = %d, missing job note body", resp.StatusCode)
	}
	if strings.Contains(body, "SecretBody") {
		t.Fatalf("secret job note body leaked into the job page")
	}

	// Job notes stay off the client's own notes tab (F7.6).
	if _, cbody := get(t, c, ts.URL+"/clients/"+itoa(clientID)+"?tab=notes"); strings.Contains(cbody, "ping gateway") {
		t.Fatalf("job note leaked into the client notes tab")
	}

	// Reveal returns the body and its editor targets the job scope.
	var secretID int64
	if err := db.QueryRow(`SELECT id FROM notes WHERE is_secret = 1`).Scan(&secretID); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/notes/"+itoa(secretID)+"/reveal", strings.NewReader("csrf_token="+url.QueryEscape(csrf)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	rresp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	rb := readBody(t, rresp)
	if rresp.StatusCode != http.StatusOK || !strings.Contains(rb, "SecretBody") {
		t.Fatalf("job secret reveal = %d, body=%q", rresp.StatusCode, rb)
	}
	if !strings.Contains(rb, jobLoc+"/notes/"+itoa(secretID)) {
		t.Fatalf("reveal editor does not post back to the job scope: %q", rb)
	}

	// Deleting the job cascades to its notes.
	if resp, _ := postForm(t, c, ts.URL+jobLoc+"/delete", url.Values{"csrf_token": {csrf}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete job = %d, want 303", resp.StatusCode)
	}
	var remaining int
	if err := db.QueryRow(`SELECT count(*) FROM notes WHERE job_id = ?`, jobID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("job notes after job delete = %d, want 0", remaining)
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
