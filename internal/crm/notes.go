package crm

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Note is one note attached to a client. A secret note (IsSecret) is masked in
// every ordinary render and revealable only through the audited endpoint; the
// stored body is identical whether or not the flag is set (F4.1, F5.1).
type Note struct {
	ID        int64
	ClientID  int64
	Title     string
	Body      string
	Pinned    bool
	IsSecret  bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NoteInput is the editable set of note fields for creation. Edits update only
// the title and body: pinning and the secret flag are toggled by their own
// actions, so editing a note can never clear the secret treatment (F4.6).
type NoteInput struct {
	Title    string
	Body     string
	IsSecret bool
}

const noteColumns = `id, client_id, title, body, pinned, is_secret, created_at, updated_at`

// ListNotes returns a client's notes, pinned first then most recently updated.
func (s *Store) ListNotes(ctx context.Context, clientID int64) ([]Note, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+noteColumns+` FROM notes WHERE client_id = ?
		 ORDER BY pinned DESC, updated_at DESC`, clientID)
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

// GetNote returns one note or ErrNotFound.
func (s *Store) GetNote(ctx context.Context, id int64) (Note, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+noteColumns+` FROM notes WHERE id = ?`, id)
	n, err := scanNote(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Note{}, ErrNotFound
	}
	return n, err
}

// CreateNote inserts a note for a client. Only the title and body are editable;
// the optional secret flag is set at creation (F4.1/F5.1).
func (s *Store) CreateNote(ctx context.Context, clientID int64, in NoteInput) (int64, error) {
	now := formatTS(time.Now())
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO notes (client_id, title, body, is_secret, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		clientID, strings.TrimSpace(in.Title), in.Body, boolInt(in.IsSecret), now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateNote edits a note's title and body. It deliberately does not touch the
// pinned or secret flags, so an edit preserves them (F4.6).
func (s *Store) UpdateNote(ctx context.Context, clientID, noteID int64, in NoteInput) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE notes SET title = ?, body = ?, updated_at = ?
		 WHERE id = ? AND client_id = ?`,
		strings.TrimSpace(in.Title), in.Body, formatTS(time.Now()), noteID, clientID)
	if err != nil {
		return err
	}
	return affected(res)
}

// DeleteNote removes a note that must belong to clientID.
func (s *Store) DeleteNote(ctx context.Context, clientID, noteID int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM notes WHERE id = ? AND client_id = ?`, noteID, clientID)
	if err != nil {
		return err
	}
	return affected(res)
}

// SetNotePinned pins or unpins a note (F4.2).
func (s *Store) SetNotePinned(ctx context.Context, clientID, noteID int64, pinned bool) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE notes SET pinned = ?, updated_at = ? WHERE id = ? AND client_id = ?`,
		boolInt(pinned), formatTS(time.Now()), noteID, clientID)
	if err != nil {
		return err
	}
	return affected(res)
}

// SetNoteSecret toggles the secret flag. It changes only the UI treatment and
// search exclusion; the stored body is untouched (F4.6/F5.1).
func (s *Store) SetNoteSecret(ctx context.Context, clientID, noteID int64, secret bool) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE notes SET is_secret = ?, updated_at = ? WHERE id = ? AND client_id = ?`,
		boolInt(secret), formatTS(time.Now()), noteID, clientID)
	if err != nil {
		return err
	}
	return affected(res)
}

func scanNote(sc scanner) (Note, error) {
	var (
		n                Note
		pinned, secret   int
		created, updated string
	)
	if err := sc.Scan(&n.ID, &n.ClientID, &n.Title, &n.Body, &pinned, &secret, &created, &updated); err != nil {
		return Note{}, err
	}
	n.Pinned = pinned == 1
	n.IsSecret = secret == 1
	n.CreatedAt = parseTS(created)
	n.UpdatedAt = parseTS(updated)
	return n, nil
}
