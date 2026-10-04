package crm

import (
	"context"
	"time"
)

// ExportData is the plaintext JSON export shape (F12.3). It deliberately
// excludes users, sessions, and recovery codes: those hold password hashes,
// TOTP secrets, and token hashes, which must never leave the encrypted database
// in a plaintext file. Secret notes are excluded unless IncludeSecretNotes.
type ExportData struct {
	GeneratedAt         string    `json:"generated_at"`
	IncludesSecretNotes bool      `json:"includes_secret_notes"`
	Clients             []Client  `json:"clients"`
	Contacts            []Contact `json:"contacts"`
	Notes               []Note    `json:"notes"`
	Projects            []Project `json:"projects"`
	Jobs                []Job     `json:"jobs"`
}

// Export reads every CRM row into ExportData. When includeSecrets is false,
// secret notes are omitted entirely (F12.3).
func (s *Store) Export(ctx context.Context, includeSecrets bool) (ExportData, error) {
	out := ExportData{
		GeneratedAt:         formatTS(time.Now()),
		IncludesSecretNotes: includeSecrets,
	}
	var err error
	if out.Clients, err = s.exportClients(ctx); err != nil {
		return out, err
	}
	if out.Contacts, err = s.exportContacts(ctx); err != nil {
		return out, err
	}
	if out.Notes, err = s.exportNotes(ctx, includeSecrets); err != nil {
		return out, err
	}
	if out.Projects, err = s.exportProjects(ctx); err != nil {
		return out, err
	}
	if out.Jobs, err = s.exportJobs(ctx); err != nil {
		return out, err
	}
	return out, nil
}

func (s *Store) exportClients(ctx context.Context) ([]Client, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+clientColumns+` FROM clients ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) exportContacts(ctx context.Context) ([]Contact, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+contactColumns+` FROM contacts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Contact
	for rows.Next() {
		c, err := scanContact(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) exportNotes(ctx context.Context, includeSecrets bool) ([]Note, error) {
	q := `SELECT ` + noteColumns + ` FROM notes`
	if !includeSecrets {
		q += ` WHERE is_secret = 0`
	}
	q += ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Note
	for rows.Next() {
		n, err := scanNote(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) exportProjects(ctx context.Context) ([]Project, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+projectColumns+` FROM projects p JOIN clients cl ON cl.id = p.client_id ORDER BY p.id`)
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

func (s *Store) exportJobs(ctx context.Context) ([]Job, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+jobColumns+` FROM jobs j JOIN clients cl ON cl.id = j.client_id
		 LEFT JOIN projects p ON p.id = j.project_id ORDER BY j.id`)
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
