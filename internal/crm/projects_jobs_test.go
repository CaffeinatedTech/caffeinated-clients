package crm

import (
	"context"
	"errors"
	"testing"
	"time"
)

func dateStr(offsetDays int) string {
	return time.Now().AddDate(0, 0, offsetDays).Format(dateLayout)
}

func TestProjectLifecycleAndProgress(t *testing.T) {
	s, _ := openCRM(t)
	ctx := context.Background()
	clientID, _ := s.CreateClient(ctx, ClientInput{Name: "Acme Co"})

	id, err := s.CreateProject(ctx, clientID, ProjectInput{Name: "Website", Status: "active", DueDate: dateStr(7)})
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	p, err := s.GetProject(ctx, id)
	if err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	if p.Name != "Website" || p.Status != "active" || p.ClientName != "Acme Co" {
		t.Fatalf("unexpected project: %+v", p)
	}
	if p.StartedAt.IsZero() {
		t.Fatalf("active project has no started_at")
	}

	// Progress aggregates the project's jobs (F6.3).
	for i, status := range []string{"done", "done", "open"} {
		if _, err := s.CreateJob(ctx, clientID, JobInput{Title: "Job", Status: status, ProjectID: id}); err != nil {
			t.Fatalf("CreateJob %d: %v", i, err)
		}
	}
	p, _ = s.GetProject(ctx, id)
	if p.Jobs != 3 || p.DoneJobs != 2 || p.Progress() != 66 {
		t.Fatalf("progress = %d/%d (%d%%), want 2/3 (66%%)", p.DoneJobs, p.Jobs, p.Progress())
	}

	// Completing the project records a timestamp; reopening clears it.
	if err := s.UpdateProject(ctx, clientID, id, ProjectInput{Name: "Website", Status: "done"}); err != nil {
		t.Fatalf("UpdateProject done: %v", err)
	}
	p, _ = s.GetProject(ctx, id)
	if p.CompletedAt.IsZero() {
		t.Fatalf("done project has no completed_at")
	}
	if err := s.UpdateProject(ctx, clientID, id, ProjectInput{Name: "Website", Status: "active"}); err != nil {
		t.Fatalf("UpdateProject active: %v", err)
	}
	p, _ = s.GetProject(ctx, id)
	if !p.CompletedAt.IsZero() {
		t.Fatalf("reopened project kept completed_at")
	}

	if err := s.UpdateProject(ctx, clientID, id, ProjectInput{Name: "  "}); !errors.Is(err, ErrNameRequired) {
		t.Fatalf("blank name = %v, want ErrNameRequired", err)
	}
	if err := s.UpdateProject(ctx, clientID, id, ProjectInput{Name: "Website", DueDate: "not-a-date"}); !errors.Is(err, ErrInvalidDate) {
		t.Fatalf("bad date = %v, want ErrInvalidDate", err)
	}
}

func TestProjectOngoingSet(t *testing.T) {
	s, _ := openCRM(t)
	ctx := context.Background()
	clientID, _ := s.CreateClient(ctx, ClientInput{Name: "Acme Co"})
	for _, status := range []string{"planning", "active", "waiting", "done", "archived"} {
		if _, err := s.CreateProject(ctx, clientID, ProjectInput{Name: status, Status: status}); err != nil {
			t.Fatalf("CreateProject %s: %v", status, err)
		}
	}
	ongoing, err := s.OngoingProjects(ctx, 10)
	if err != nil {
		t.Fatalf("OngoingProjects: %v", err)
	}
	got := map[string]bool{}
	for _, p := range ongoing {
		got[p.Status] = true
	}
	if len(ongoing) != 3 || !got["planning"] || !got["active"] || !got["waiting"] {
		t.Fatalf("ongoing = %+v, want planning/active/waiting only", ongoing)
	}

	all, _ := s.ListProjects(ctx, ProjectOptions{Status: "all"})
	if len(all) != 5 {
		t.Fatalf("all projects = %d, want 5", len(all))
	}
}

func TestJobSameClientConstraint(t *testing.T) {
	s, _ := openCRM(t)
	ctx := context.Background()
	acme, _ := s.CreateClient(ctx, ClientInput{Name: "Acme Co"})
	globex, _ := s.CreateClient(ctx, ClientInput{Name: "Globex"})
	project, err := s.CreateProject(ctx, acme, ProjectInput{Name: "Website"})
	if err != nil {
		t.Fatal(err)
	}

	// A job cannot reference another client's project (enforced in the store).
	if _, err := s.CreateJob(ctx, globex, JobInput{Title: "Job", ProjectID: project}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("cross-client create = %v, want ErrInvalidInput", err)
	}

	globexJob, err := s.CreateJob(ctx, globex, JobInput{Title: "Job"})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := s.UpdateJob(ctx, globex, globexJob, JobInput{Title: "Job", ProjectID: project}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("cross-client update = %v, want ErrInvalidInput", err)
	}

	// A valid same-client link works, and the project name is returned.
	acmeJob, err := s.CreateJob(ctx, acme, JobInput{Title: "Job", ProjectID: project})
	if err != nil {
		t.Fatalf("same-client create: %v", err)
	}
	j, _ := s.GetJob(ctx, acmeJob)
	if j.ProjectID != project || j.ProjectName != "Website" || j.ClientName != "Acme Co" {
		t.Fatalf("job = %+v", j)
	}
}

func TestJobOverdueAndUpcoming(t *testing.T) {
	s, _ := openCRM(t)
	ctx := context.Background()
	clientID, _ := s.CreateClient(ctx, ClientInput{Name: "Acme Co"})

	mk := func(title, status, due string) {
		t.Helper()
		if _, err := s.CreateJob(ctx, clientID, JobInput{Title: title, Status: status, DueDate: due}); err != nil {
			t.Fatalf("CreateJob %s: %v", title, err)
		}
	}
	mk("Past", "open", dateStr(-1))
	mk("Today", "open", dateStr(0))
	mk("Future", "open", dateStr(3))
	mk("DonePast", "done", dateStr(-2))
	mk("NoDue", "open", "")

	overdue, err := s.OverdueJobs(ctx, 10)
	if err != nil {
		t.Fatalf("OverdueJobs: %v", err)
	}
	if len(overdue) != 1 || overdue[0].Title != "Past" {
		t.Fatalf("overdue = %+v, want [Past]", overdue)
	}
	upcoming, err := s.UpcomingJobs(ctx, 10)
	if err != nil {
		t.Fatalf("UpcomingJobs: %v", err)
	}
	if len(upcoming) != 2 || upcoming[0].Title != "Today" || upcoming[1].Title != "Future" {
		t.Fatalf("upcoming = %+v, want [Today Future]", upcoming)
	}

	// The default list hides done jobs; "all" includes them.
	open, _ := s.ListJobs(ctx, JobOptions{})
	if len(open) != 4 {
		t.Fatalf("default jobs = %d, want 4", len(open))
	}
	all, _ := s.ListJobs(ctx, JobOptions{Status: "all"})
	if len(all) != 5 {
		t.Fatalf("all jobs = %d, want 5", len(all))
	}
}

func TestJobCompletionTimestamp(t *testing.T) {
	s, _ := openCRM(t)
	ctx := context.Background()
	clientID, _ := s.CreateClient(ctx, ClientInput{Name: "Acme Co"})
	id, err := s.CreateJob(ctx, clientID, JobInput{Title: "Job", Status: "done"})
	if err != nil {
		t.Fatal(err)
	}
	j, _ := s.GetJob(ctx, id)
	if j.CompletedAt.IsZero() {
		t.Fatalf("done job has no completed_at")
	}
	if err := s.UpdateJob(ctx, clientID, id, JobInput{Title: "Job", Status: "open"}); err != nil {
		t.Fatal(err)
	}
	j, _ = s.GetJob(ctx, id)
	if !j.CompletedAt.IsZero() {
		t.Fatalf("reopened job kept completed_at")
	}
}
