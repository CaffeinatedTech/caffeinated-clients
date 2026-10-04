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

func webDate(offsetDays int) string {
	return time.Now().AddDate(0, 0, offsetDays).Format("2006-01-02")
}

// TestProjectJobHTTPFlow covers the Phase 6 HTTP paths: creating projects and
// jobs from the client page, progress on the project page, the dashboard
// widgets, and the same-client project/job constraint.
func TestProjectJobHTTPFlow(t *testing.T) {
	ts, db, _, _ := newTestServer(t, func(c *config.Config) { c.Disable2FA = true })
	c := newClient(t)
	loginPassword(t, c, ts)
	csrf := csrfFromDB(t, db, auth.StageFull)

	mkClient := func(name string) int64 {
		t.Helper()
		resp, _ := postForm(t, c, ts.URL+"/clients", url.Values{"csrf_token": {csrf}, "name": {name}})
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("create client %s = %d, want 303", name, resp.StatusCode)
		}
		var id int64
		if err := db.QueryRow(`SELECT id FROM clients WHERE name = ?`, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	acmeID := mkClient("Acme Co")
	globexID := mkClient("Globex")
	acmeLoc := "/clients/" + itoa(acmeID)

	// Create a project (with an overdue due date) from the client page.
	resp, _ := postForm(t, c, ts.URL+acmeLoc+"/projects", url.Values{
		"csrf_token": {csrf}, "name": {"Website"}, "status": {"active"}, "due_date": {webDate(-1)},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create project = %d, want 303", resp.StatusCode)
	}
	var projectID int64
	if err := db.QueryRow(`SELECT id FROM projects WHERE client_id = ?`, acmeID).Scan(&projectID); err != nil {
		t.Fatal(err)
	}

	// Create a job under it from the client page.
	resp, _ = postForm(t, c, ts.URL+acmeLoc+"/jobs", url.Values{
		"csrf_token": {csrf}, "title": {"Fix DNS"}, "project_id": {itoa(projectID)},
		"status": {"open"}, "due_date": {webDate(-2)},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create job = %d, want 303", resp.StatusCode)
	}

	// The project page shows the job and its progress.
	if resp, body := get(t, c, ts.URL+"/projects/"+itoa(projectID)); resp.StatusCode != http.StatusOK || !strings.Contains(body, "Fix DNS") {
		t.Fatalf("project page = %d, missing job; body=%q", resp.StatusCode, body)
	}

	// The global jobs view lists it and honours the overdue filter.
	if resp, body := get(t, c, ts.URL+"/jobs?due=overdue"); resp.StatusCode != http.StatusOK || !strings.Contains(body, "Fix DNS") {
		t.Fatalf("jobs overdue filter = %d, missing job", resp.StatusCode)
	}

	// The dashboard shows the ongoing project and the overdue job.
	if resp, body := get(t, c, ts.URL+"/"); resp.StatusCode != http.StatusOK ||
		!strings.Contains(body, "Ongoing projects") || !strings.Contains(body, "Overdue") {
		t.Fatalf("dashboard = %d, missing widgets; body=%q", resp.StatusCode, body)
	}

	// A job cannot reference another client's project (F7.1).
	resp, body := postForm(t, c, ts.URL+"/jobs", url.Values{
		"csrf_token": {csrf}, "client_id": {itoa(globexID)}, "title": {"Bad"}, "project_id": {itoa(projectID)},
	})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "same client") {
		t.Fatalf("cross-client job = %d, want 400 with message; body=%q", resp.StatusCode, body)
	}

	// The same link from the global form is accepted.
	resp, _ = postForm(t, c, ts.URL+"/jobs", url.Values{
		"csrf_token": {csrf}, "client_id": {itoa(acmeID)}, "title": {"Global job"}, "project_id": {itoa(projectID)},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("same-client global job = %d, want 303", resp.StatusCode)
	}

	// Deleting the project detaches (but keeps) its jobs.
	resp, _ = postForm(t, c, ts.URL+"/projects/"+itoa(projectID)+"/delete", url.Values{"csrf_token": {csrf}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete project = %d, want 303", resp.StatusCode)
	}
	var jobs, orphaned int
	if err := db.QueryRow(`SELECT count(*), count(*) FILTER (WHERE project_id IS NULL) FROM jobs`).Scan(&jobs, &orphaned); err != nil {
		t.Fatal(err)
	}
	if jobs == 0 || orphaned != jobs {
		t.Fatalf("after project delete: jobs=%d orphaned=%d, want all detached", jobs, orphaned)
	}
}
