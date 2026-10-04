package crm

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Project is a body of work for one client (F6.1). Jobs and DoneJobs are the
// aggregate the client and project pages use for progress (F6.3).
type Project struct {
	ID          int64
	ClientID    int64
	ClientName  string
	Name        string
	Description string
	Status      string
	DueDate     time.Time
	StartedAt   time.Time
	CompletedAt time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Jobs        int
	DoneJobs    int
}

// Ongoing reports whether the project counts as ongoing (F6.2).
func (p Project) Ongoing() bool { return ongoingProjectStatuses[p.Status] }

// Progress is the percentage of a project's jobs that are done, or 0 when it
// has no jobs.
func (p Project) Progress() int {
	if p.Jobs == 0 {
		return 0
	}
	return p.DoneJobs * 100 / p.Jobs
}

// ProjectInput is the editable set of project fields.
type ProjectInput struct {
	Name        string
	Description string
	Status      string
	DueDate     string
}

// ProjectOptions filters and sorts the project list (F6).
type ProjectOptions struct {
	Status   string // "", "ongoing", "all", or a specific status
	ClientID int64  // 0 = any client
	Filter   string // name filter
	Sort     string // "status" (default), "name", "updated", "due"
	Limit    int
}

var projectStatuses = map[string]bool{
	"planning": true, "active": true, "waiting": true, "done": true, "archived": true,
}

var ongoingProjectStatuses = map[string]bool{"planning": true, "active": true, "waiting": true}

const projectColumns = `p.id, p.client_id, cl.name, p.name, p.description, p.status,
	COALESCE(p.due_date, ''), COALESCE(p.started_at, ''), COALESCE(p.completed_at, ''),
	p.created_at, p.updated_at,
	(SELECT count(*) FROM jobs j WHERE j.project_id = p.id),
	(SELECT count(*) FROM jobs j WHERE j.project_id = p.id AND j.status = 'done')`

func normalizeProjectStatus(status string) (string, error) {
	status = strings.TrimSpace(status)
	if status == "" {
		return "planning", nil
	}
	if !projectStatuses[status] {
		return "", ErrInvalidInput
	}
	return status, nil
}

// CreateProject inserts a project for a client; the client must exist and the
// name is required (F6.1/F6.4).
func (s *Store) CreateProject(ctx context.Context, clientID int64, in ProjectInput) (int64, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return 0, ErrNameRequired
	}
	if _, err := s.GetClient(ctx, clientID); err != nil {
		return 0, err
	}
	status, err := normalizeProjectStatus(in.Status)
	if err != nil {
		return 0, err
	}
	due, err := parseDate(in.DueDate)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	var started, completed any
	if status == "active" || status == "done" {
		started = formatTS(now)
	}
	if status == "done" {
		completed = formatTS(now)
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO projects (client_id, name, description, status, due_date, started_at, completed_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		clientID, name, in.Description, status, nullIfEmpty(due), started, completed, formatTS(now), formatTS(now))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateProject edits a project that must belong to clientID and advances its
// lifecycle timestamps: started_at is set on the first move to active/done and
// completed_at tracks the done status (F6.1).
func (s *Store) UpdateProject(ctx context.Context, clientID, projectID int64, in ProjectInput) error {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return ErrNameRequired
	}
	status, err := normalizeProjectStatus(in.Status)
	if err != nil {
		return err
	}
	due, err := parseDate(in.DueDate)
	if err != nil {
		return err
	}
	now := formatTS(time.Now())
	res, err := s.db.ExecContext(ctx,
		`UPDATE projects
		 SET name = ?, description = ?, status = ?, due_date = ?, updated_at = ?,
		     started_at = CASE WHEN ? IN ('active', 'done') THEN COALESCE(started_at, ?) ELSE started_at END,
		     completed_at = CASE WHEN ? = 'done' THEN COALESCE(completed_at, ?) ELSE NULL END
		 WHERE id = ? AND client_id = ?`,
		name, in.Description, status, nullIfEmpty(due), now, status, now, status, now, projectID, clientID)
	if err != nil {
		return err
	}
	return affected(res)
}

// DeleteProject removes a project that must belong to clientID. Its jobs are
// kept and detached (project_id becomes NULL) by the schema's foreign key.
func (s *Store) DeleteProject(ctx context.Context, clientID, projectID int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM projects WHERE id = ? AND client_id = ?`, projectID, clientID)
	if err != nil {
		return err
	}
	return affected(res)
}

// GetProject returns one project with its client name and job progress.
func (s *Store) GetProject(ctx context.Context, id int64) (Project, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+projectColumns+` FROM projects p JOIN clients cl ON cl.id = p.client_id WHERE p.id = ?`, id)
	p, err := scanProject(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	return p, err
}

// ListProjects returns projects filtered and sorted per opt. Archived projects
// are hidden by default.
func (s *Store) ListProjects(ctx context.Context, opt ProjectOptions) ([]Project, error) {
	var where []string
	var args []any
	switch opt.Status {
	case "":
		where = append(where, "p.status <> 'archived'")
	case "all":
	case "ongoing":
		where = append(where, "p.status IN ('planning', 'active', 'waiting')")
	default:
		if !projectStatuses[opt.Status] {
			return nil, ErrInvalidInput
		}
		where = append(where, "p.status = ?")
		args = append(args, opt.Status)
	}
	if opt.ClientID > 0 {
		where = append(where, "p.client_id = ?")
		args = append(args, opt.ClientID)
	}
	if f := strings.TrimSpace(opt.Filter); f != "" {
		where = append(where, "p.name LIKE ?")
		args = append(args, "%"+f+"%")
	}
	order := "CASE p.status WHEN 'active' THEN 0 WHEN 'planning' THEN 1 WHEN 'waiting' THEN 2 WHEN 'done' THEN 3 ELSE 4 END, p.name COLLATE NOCASE"
	switch opt.Sort {
	case "name":
		order = "p.name COLLATE NOCASE"
	case "updated":
		order = "p.updated_at DESC"
	case "due":
		order = "(p.due_date IS NULL OR p.due_date = ''), p.due_date ASC, p.name COLLATE NOCASE"
	}
	limit := maxListLimit
	if opt.Limit > 0 {
		limit = opt.Limit
	}
	q := `SELECT ` + projectColumns + ` FROM projects p JOIN clients cl ON cl.id = p.client_id`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY " + order + " LIMIT " + fmt.Sprint(limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// OngoingProjects returns ongoing projects for the dashboard (F6.2/F8.1),
// soonest due first.
func (s *Store) OngoingProjects(ctx context.Context, limit int) ([]Project, error) {
	return s.ListProjects(ctx, ProjectOptions{Status: "ongoing", Sort: "due", Limit: limit})
}

func scanProject(sc scanner) (Project, error) {
	var (
		p                       Project
		due, started, completed string
		created, updated        string
	)
	if err := sc.Scan(&p.ID, &p.ClientID, &p.ClientName, &p.Name, &p.Description, &p.Status,
		&due, &started, &completed, &created, &updated, &p.Jobs, &p.DoneJobs); err != nil {
		return Project{}, err
	}
	p.DueDate = parseDateValue(due)
	p.StartedAt = parseTS(started)
	p.CompletedAt = parseTS(completed)
	p.CreatedAt = parseTS(created)
	p.UpdatedAt = parseTS(updated)
	return p, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
