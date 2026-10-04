package crm

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Job is a discrete unit of work for one client, optionally under one of that
// client's projects (F7.1). ProjectID is 0 when the job stands alone.
type Job struct {
	ID          int64
	ClientID    int64
	ClientName  string
	ProjectID   int64
	ProjectName string
	Title       string
	Description string
	Status      string
	Priority    string
	DueDate     time.Time
	CompletedAt time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Open reports whether the job is not done (F7.4).
func (j Job) Open() bool { return j.Status != "done" }

// JobInput is the editable set of job fields.
type JobInput struct {
	Title       string
	Description string
	Status      string
	Priority    string
	DueDate     string
	ProjectID   int64
}

// JobOptions filters and sorts the job list (F7.4).
type JobOptions struct {
	Status        string // "", "open", "all", or a specific status
	ClientID      int64  // 0 = any client
	ClientFilter  string // client name filter
	ProjectID     int64  // 0 = any project
	ProjectFilter string // project name filter
	Due           string // "", "overdue", "upcoming", "today", "none"
	Sort          string // "" (due first), "updated"
	Limit         int
}

var jobStatuses = map[string]bool{"open": true, "in_progress": true, "waiting": true, "done": true}
var jobPriorities = map[string]bool{"low": true, "normal": true, "high": true}

const jobColumns = `j.id, j.client_id, cl.name, COALESCE(j.project_id, 0), COALESCE(p.name, ''),
	j.title, j.description, j.status, j.priority, COALESCE(j.due_date, ''), COALESCE(j.completed_at, ''),
	j.created_at, j.updated_at`

func normalizeJobStatus(status string) (string, error) {
	status = strings.TrimSpace(status)
	if status == "" {
		return "open", nil
	}
	if !jobStatuses[status] {
		return "", ErrInvalidInput
	}
	return status, nil
}

func normalizePriority(priority string) (string, error) {
	priority = strings.TrimSpace(priority)
	if priority == "" {
		return "normal", nil
	}
	if !jobPriorities[priority] {
		return "", ErrInvalidInput
	}
	return priority, nil
}

// checkProjectSameClient verifies that projectID (when non-zero) exists and
// belongs to clientID (F7.1). This is enforced in the store, not just the UI.
func (s *Store) checkProjectSameClient(ctx context.Context, clientID, projectID int64) error {
	if projectID == 0 {
		return nil
	}
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM projects WHERE id = ? AND client_id = ?`, projectID, clientID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrInvalidInput
	}
	return nil
}

// CreateJob inserts a job for a client; the title is required and any project
// must belong to the same client (F7.1/F7.3).
func (s *Store) CreateJob(ctx context.Context, clientID int64, in JobInput) (int64, error) {
	title := strings.TrimSpace(in.Title)
	if title == "" {
		return 0, ErrTitleRequired
	}
	if _, err := s.GetClient(ctx, clientID); err != nil {
		return 0, err
	}
	status, err := normalizeJobStatus(in.Status)
	if err != nil {
		return 0, err
	}
	priority, err := normalizePriority(in.Priority)
	if err != nil {
		return 0, err
	}
	due, err := parseDate(in.DueDate)
	if err != nil {
		return 0, err
	}
	if err := s.checkProjectSameClient(ctx, clientID, in.ProjectID); err != nil {
		return 0, err
	}
	now := time.Now()
	var completed any
	if status == "done" {
		completed = formatTS(now)
	}
	var projectID any
	if in.ProjectID != 0 {
		projectID = in.ProjectID
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO jobs (client_id, project_id, title, description, status, priority, due_date, completed_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		clientID, projectID, title, in.Description, status, priority, nullIfEmpty(due), completed, formatTS(now), formatTS(now))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateJob edits a job that must belong to clientID, re-validates the
// same-client project rule, and tracks the completion timestamp (F7.5).
func (s *Store) UpdateJob(ctx context.Context, clientID, jobID int64, in JobInput) error {
	title := strings.TrimSpace(in.Title)
	if title == "" {
		return ErrTitleRequired
	}
	status, err := normalizeJobStatus(in.Status)
	if err != nil {
		return err
	}
	priority, err := normalizePriority(in.Priority)
	if err != nil {
		return err
	}
	due, err := parseDate(in.DueDate)
	if err != nil {
		return err
	}
	if err := s.checkProjectSameClient(ctx, clientID, in.ProjectID); err != nil {
		return err
	}
	now := formatTS(time.Now())
	var projectID any
	if in.ProjectID != 0 {
		projectID = in.ProjectID
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE jobs
		 SET project_id = ?, title = ?, description = ?, status = ?, priority = ?, due_date = ?, updated_at = ?,
		     completed_at = CASE WHEN ? = 'done' THEN COALESCE(completed_at, ?) ELSE NULL END
		 WHERE id = ? AND client_id = ?`,
		projectID, title, in.Description, status, priority, nullIfEmpty(due), now, status, now, jobID, clientID)
	if err != nil {
		return err
	}
	return affected(res)
}

// DeleteJob removes a job that must belong to clientID.
func (s *Store) DeleteJob(ctx context.Context, clientID, jobID int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM jobs WHERE id = ? AND client_id = ?`, jobID, clientID)
	if err != nil {
		return err
	}
	return affected(res)
}

// GetJob returns one job with its client and project names.
func (s *Store) GetJob(ctx context.Context, id int64) (Job, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+jobColumns+` FROM jobs j JOIN clients cl ON cl.id = j.client_id
		 LEFT JOIN projects p ON p.id = j.project_id WHERE j.id = ?`, id)
	j, err := scanJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	return j, err
}

// ListJobs returns jobs filtered and sorted per opt. By default it hides done
// jobs; pass Status "all" to include them.
func (s *Store) ListJobs(ctx context.Context, opt JobOptions) ([]Job, error) {
	var where []string
	var args []any
	switch opt.Status {
	case "", "open":
		where = append(where, "j.status <> 'done'")
	case "all":
	default:
		if !jobStatuses[opt.Status] {
			return nil, ErrInvalidInput
		}
		where = append(where, "j.status = ?")
		args = append(args, opt.Status)
	}
	if opt.ClientID > 0 {
		where = append(where, "j.client_id = ?")
		args = append(args, opt.ClientID)
	}
	if f := strings.TrimSpace(opt.ClientFilter); f != "" {
		where = append(where, "cl.name LIKE ?")
		args = append(args, "%"+f+"%")
	}
	if opt.ProjectID > 0 {
		where = append(where, "j.project_id = ?")
		args = append(args, opt.ProjectID)
	}
	if f := strings.TrimSpace(opt.ProjectFilter); f != "" {
		where = append(where, "p.name LIKE ?")
		args = append(args, "%"+f+"%")
	}
	today := time.Now().Format(dateLayout)
	open := "j.status <> 'done' AND j.due_date IS NOT NULL AND j.due_date <> ''"
	switch opt.Due {
	case "overdue":
		where = append(where, open+" AND j.due_date < ?")
		args = append(args, today)
	case "upcoming":
		where = append(where, open+" AND j.due_date >= ?")
		args = append(args, today)
	case "today":
		where = append(where, open+" AND j.due_date = ?")
		args = append(args, today)
	case "none":
		where = append(where, "j.due_date IS NULL")
	case "":
	default:
		return nil, ErrInvalidInput
	}
	order := "(j.due_date IS NULL OR j.due_date = ''), j.due_date ASC, j.updated_at DESC"
	if opt.Sort == "updated" {
		order = "j.updated_at DESC"
	}
	limit := maxListLimit
	if opt.Limit > 0 {
		limit = opt.Limit
	}
	q := `SELECT ` + jobColumns + ` FROM jobs j JOIN clients cl ON cl.id = j.client_id
	      LEFT JOIN projects p ON p.id = j.project_id`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY " + order + " LIMIT " + fmt.Sprint(limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// OverdueJobs returns open jobs past their due date for the dashboard (F7.4).
func (s *Store) OverdueJobs(ctx context.Context, limit int) ([]Job, error) {
	return s.ListJobs(ctx, JobOptions{Status: "open", Due: "overdue", Limit: limit})
}

// UpcomingJobs returns open jobs due today or later for the dashboard (F7.4).
func (s *Store) UpcomingJobs(ctx context.Context, limit int) ([]Job, error) {
	return s.ListJobs(ctx, JobOptions{Status: "open", Due: "upcoming", Limit: limit})
}

func scanJob(sc scanner) (Job, error) {
	var (
		j                Job
		due, completed   string
		created, updated string
	)
	if err := sc.Scan(&j.ID, &j.ClientID, &j.ClientName, &j.ProjectID, &j.ProjectName,
		&j.Title, &j.Description, &j.Status, &j.Priority, &due, &completed, &created, &updated); err != nil {
		return Job{}, err
	}
	j.DueDate = parseDateValue(due)
	j.CompletedAt = parseTS(completed)
	j.CreatedAt = parseTS(created)
	j.UpdatedAt = parseTS(updated)
	return j, nil
}
