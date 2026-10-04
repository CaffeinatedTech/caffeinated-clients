// Package crm owns client and contact data plus the search that spans clients,
// contacts, projects, and non-secret note titles. All queries use bound
// parameters; the single-primary-contact rule is enforced here, not only in
// the UI. Everything is reached through the same encrypted *sql.DB as auth.
package crm

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Sentinel errors. Handlers map these to 404s and inline form messages.
var (
	ErrNotFound      = errors.New("crm: not found")
	ErrNameRequired  = errors.New("crm: name is required")
	ErrTitleRequired = errors.New("crm: title is required")
	ErrInvalidInput  = errors.New("crm: invalid input")
	ErrInvalidDate   = errors.New("crm: invalid date")
)

const (
	defaultSearchLimit = 20
	maxListLimit       = 500
)

// tsLayout matches the strftime('%Y-%m-%dT%H:%M:%fZ') schema default so Go- and
// SQLite-written timestamps sort together.
const tsLayout = "2006-01-02T15:04:05.000Z"

func formatTS(t time.Time) string { return t.UTC().Format(tsLayout) }

func parseTS(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(tsLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// dateLayout is the date-only format stored for project and job due dates. ISO
// date strings sort lexicographically, so range filters stay simple.
const dateLayout = "2006-01-02"

func parseDate(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	t, err := time.Parse(dateLayout, s)
	if err != nil {
		return "", ErrInvalidDate
	}
	return t.Format(dateLayout), nil
}

func parseDateValue(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(dateLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// Store is the CRM data layer over the encrypted database.
type Store struct{ db *sql.DB }

// New returns a Store backed by db.
func New(db *sql.DB) *Store { return &Store{db: db} }

// Client is one client (business or person).
type Client struct {
	ID          int64
	Name        string
	Status      string
	Website     string
	Address     string
	Phone       string
	PhoneDigits string
	Summary     string
	Tags        string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ArchivedAt  time.Time
}

// Archived reports whether the client is archived.
func (c Client) Archived() bool { return c.Status == "archived" }

// ClientInput is the editable set of client fields.
type ClientInput struct {
	Name    string
	Status  string
	Website string
	Address string
	Phone   string
	Summary string
	Tags    string
}

// Contact is one person at a client.
type Contact struct {
	ID          int64
	ClientID    int64
	Name        string
	Role        string
	Phone       string
	PhoneDigits string
	Email       string
	Notes       string
	IsPrimary   bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ContactInput is the editable set of contact fields.
type ContactInput struct {
	Name      string
	Role      string
	Phone     string
	Email     string
	Notes     string
	IsPrimary bool
}

// ListOptions filters and sorts the client list (F2.5).
type ListOptions struct {
	Filter string // text filter on name/phone
	Status string // "", "all", or a specific status
	Sort   string // "name" (default), "updated", "created"
}

// CascadeCounts is what a client delete would remove (F12.5).
type CascadeCounts struct {
	Contacts int
	Notes    int
	Projects int
	Jobs     int
}

// Total is the number of dependent rows across all kinds.
func (c CascadeCounts) Total() int { return c.Contacts + c.Notes + c.Projects + c.Jobs }

// Hit is one search result.
type Hit struct {
	Kind       string
	ID         int64
	Title      string
	Subtitle   string
	ClientID   int64
	ClientName string
	Href       string
}

// Results are search hits grouped by kind (F8.3).
type Results struct {
	Query    string
	Clients  []Hit
	Contacts []Hit
	Projects []Hit
	Notes    []Hit
}

// Total is the number of hits across all groups.
func (r Results) Total() int {
	return len(r.Clients) + len(r.Contacts) + len(r.Projects) + len(r.Notes)
}

// Empty reports whether the search produced no hits.
func (r Results) Empty() bool { return r.Total() == 0 }

// NormalizePhone reduces a phone number to digits for storage and search.
func NormalizePhone(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// looksLikePhone reports whether a query is phone-shaped (only digits and the
// punctuation people put in phone numbers, with at least one digit), so a
// name search is not polluted by coincidental digits.
func looksLikePhone(s string) bool {
	hasDigit := false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '+' || r == '-' || r == '(' || r == ')' || r == ' ' || r == '.' || r == '/':
		default:
			return false
		}
	}
	return hasDigit
}

var clientStatuses = map[string]bool{"active": true, "inactive": true, "archived": true}

// --- clients ------------------------------------------------------------

// CreateClient inserts a client. Only a name is required (F2.1).
func (s *Store) CreateClient(ctx context.Context, in ClientInput) (int64, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return 0, ErrNameRequired
	}
	status, err := normalizeStatus(in.Status)
	if err != nil {
		return 0, err
	}
	now := formatTS(time.Now())
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO clients (name, status, website, address, phone, phone_digits, summary, tags, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		name, status, strings.TrimSpace(in.Website), strings.TrimSpace(in.Address),
		strings.TrimSpace(in.Phone), NormalizePhone(in.Phone), in.Summary, strings.TrimSpace(in.Tags), now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateClient edits a client and clears or preserves archived_at in step with
// the status.
func (s *Store) UpdateClient(ctx context.Context, id int64, in ClientInput) error {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return ErrNameRequired
	}
	status, err := normalizeStatus(in.Status)
	if err != nil {
		return err
	}
	now := formatTS(time.Now())
	res, err := s.db.ExecContext(ctx,
		`UPDATE clients
		 SET name = ?, status = ?, website = ?, address = ?, phone = ?, phone_digits = ?,
		     summary = ?, tags = ?, updated_at = ?,
		     archived_at = CASE WHEN ? = 'archived' THEN COALESCE(archived_at, ?) ELSE NULL END
		 WHERE id = ?`,
		name, status, strings.TrimSpace(in.Website), strings.TrimSpace(in.Address),
		strings.TrimSpace(in.Phone), NormalizePhone(in.Phone), in.Summary, strings.TrimSpace(in.Tags),
		now, status, now, id)
	if err != nil {
		return err
	}
	return affected(res)
}

// SetArchived archives or restores a client (F2.4).
func (s *Store) SetArchived(ctx context.Context, id int64, archived bool) error {
	now := formatTS(time.Now())
	var res sql.Result
	var err error
	if archived {
		res, err = s.db.ExecContext(ctx,
			`UPDATE clients SET status = 'archived', archived_at = COALESCE(archived_at, ?), updated_at = ? WHERE id = ?`,
			now, now, id)
	} else {
		res, err = s.db.ExecContext(ctx,
			`UPDATE clients SET status = 'active', archived_at = NULL, updated_at = ? WHERE id = ?`,
			now, id)
	}
	if err != nil {
		return err
	}
	return affected(res)
}

// DeleteClient removes a client; contacts, notes, projects, and jobs cascade
// via foreign keys (F12.5).
func (s *Store) DeleteClient(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM clients WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return affected(res)
}

// ClientCascadeCounts returns the rows a delete would remove.
func (s *Store) ClientCascadeCounts(ctx context.Context, id int64) (CascadeCounts, error) {
	var c CascadeCounts
	err := s.db.QueryRowContext(ctx,
		`SELECT
		   (SELECT count(*) FROM contacts WHERE client_id = ?),
		   (SELECT count(*) FROM notes    WHERE client_id = ?),
		   (SELECT count(*) FROM projects WHERE client_id = ?),
		   (SELECT count(*) FROM jobs     WHERE client_id = ?)`,
		id, id, id, id).Scan(&c.Contacts, &c.Notes, &c.Projects, &c.Jobs)
	return c, err
}

const clientColumns = `id, name, status, website, address, phone, phone_digits, summary, tags, created_at, updated_at, COALESCE(archived_at, '')`

// GetClient returns one client or ErrNotFound.
func (s *Store) GetClient(ctx context.Context, id int64) (Client, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+clientColumns+` FROM clients WHERE id = ?`, id)
	c, err := scanClient(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, ErrNotFound
	}
	return c, err
}

// ListClients returns clients filtered and sorted per opt. Archived clients are
// hidden unless explicitly requested.
func (s *Store) ListClients(ctx context.Context, opt ListOptions) ([]Client, error) {
	var where []string
	var args []any
	switch opt.Status {
	case "":
		where = append(where, "status <> 'archived'")
	case "all":
	default:
		where = append(where, "status = ?")
		args = append(args, opt.Status)
	}
	if f := strings.TrimSpace(opt.Filter); f != "" {
		cond := "name LIKE ?"
		args = append(args, "%"+f+"%")
		if digits := NormalizePhone(f); digits != "" && looksLikePhone(f) {
			cond += " OR (phone_digits <> '' AND (phone_digits LIKE ? OR ? LIKE '%' || phone_digits || '%'))"
			args = append(args, "%"+digits+"%", digits)
		}
		where = append(where, "("+cond+")")
	}
	order := "name COLLATE NOCASE ASC"
	switch opt.Sort {
	case "updated":
		order = "updated_at DESC"
	case "created":
		order = "created_at DESC"
	}
	q := `SELECT ` + clientColumns + ` FROM clients`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY " + order + " LIMIT " + fmt.Sprint(maxListLimit)

	rows, err := s.db.QueryContext(ctx, q, args...)
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

// RecentClients returns the most recently updated non-archived clients for the
// dashboard (F8.1).
func (s *Store) RecentClients(ctx context.Context, limit int) ([]Client, error) {
	if limit <= 0 {
		limit = 5
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+clientColumns+` FROM clients WHERE status <> 'archived' ORDER BY updated_at DESC LIMIT ?`, limit)
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

func normalizeStatus(status string) (string, error) {
	status = strings.TrimSpace(status)
	if status == "" {
		return "active", nil
	}
	if !clientStatuses[status] {
		return "", fmt.Errorf("crm: invalid client status %q", status)
	}
	return status, nil
}

func affected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- contacts -----------------------------------------------------------

const contactColumns = `id, client_id, name, role, phone, phone_digits, email, notes, is_primary, created_at, updated_at`

// ListContacts returns a client's contacts, primary first.
func (s *Store) ListContacts(ctx context.Context, clientID int64) ([]Contact, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+contactColumns+` FROM contacts WHERE client_id = ? ORDER BY is_primary DESC, name COLLATE NOCASE ASC`, clientID)
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

// CreateContact inserts a contact, clearing any existing primary (F3.3).
func (s *Store) CreateContact(ctx context.Context, clientID int64, in ContactInput) (int64, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return 0, ErrNameRequired
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := formatTS(time.Now())
	if in.IsPrimary {
		if _, err := tx.ExecContext(ctx, `UPDATE contacts SET is_primary = 0, updated_at = ? WHERE client_id = ?`, now, clientID); err != nil {
			return 0, err
		}
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO contacts (client_id, name, role, phone, phone_digits, email, notes, is_primary, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		clientID, name, strings.TrimSpace(in.Role), strings.TrimSpace(in.Phone), NormalizePhone(in.Phone),
		strings.TrimSpace(in.Email), in.Notes, boolInt(in.IsPrimary), now, now)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// UpdateContact edits a contact that must belong to clientID, applying the
// single-primary rule.
func (s *Store) UpdateContact(ctx context.Context, clientID, contactID int64, in ContactInput) error {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return ErrNameRequired
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := formatTS(time.Now())
	if in.IsPrimary {
		if _, err := tx.ExecContext(ctx,
			`UPDATE contacts SET is_primary = 0, updated_at = ? WHERE client_id = ? AND id <> ?`,
			now, clientID, contactID); err != nil {
			return err
		}
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE contacts
		 SET name = ?, role = ?, phone = ?, phone_digits = ?, email = ?, notes = ?, is_primary = ?, updated_at = ?
		 WHERE id = ? AND client_id = ?`,
		name, strings.TrimSpace(in.Role), strings.TrimSpace(in.Phone), NormalizePhone(in.Phone),
		strings.TrimSpace(in.Email), in.Notes, boolInt(in.IsPrimary), now, contactID, clientID)
	if err != nil {
		return err
	}
	if err := affected(res); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteContact removes a contact that must belong to clientID.
func (s *Store) DeleteContact(ctx context.Context, clientID, contactID int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM contacts WHERE id = ? AND client_id = ?`, contactID, clientID)
	if err != nil {
		return err
	}
	return affected(res)
}

// SetPrimaryContact makes contactID the only primary contact for clientID.
func (s *Store) SetPrimaryContact(ctx context.Context, clientID, contactID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM contacts WHERE id = ? AND client_id = ?`, contactID, clientID).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return ErrNotFound
	}
	now := formatTS(time.Now())
	if _, err := tx.ExecContext(ctx,
		`UPDATE contacts SET is_primary = 0, updated_at = ? WHERE client_id = ? AND is_primary = 1`, now, clientID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE contacts SET is_primary = 1, updated_at = ? WHERE id = ? AND client_id = ?`, now, contactID, clientID); err != nil {
		return err
	}
	return tx.Commit()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// --- search -------------------------------------------------------------

// Search finds clients, contacts, projects, and non-secret note titles
// matching query (F8.2). Secret notes and note bodies are never searched
// (F5.5/F8.5).
func (s *Store) Search(ctx context.Context, query string, limit int) (Results, error) {
	query = strings.TrimSpace(query)
	res := Results{Query: query}
	if query == "" {
		return res, nil
	}
	if limit <= 0 {
		limit = defaultSearchLimit
	}
	text := "%" + query + "%"
	digits := NormalizePhone(query)
	phoneLike := looksLikePhone(query) && digits != ""

	var (
		hits []Hit
		err  error
	)
	if hits, err = s.searchClients(ctx, text, digits, phoneLike, limit); err != nil {
		return res, err
	}
	res.Clients = hits
	if hits, err = s.searchContacts(ctx, text, digits, phoneLike, limit); err != nil {
		return res, err
	}
	res.Contacts = hits
	if hits, err = s.searchProjects(ctx, text, limit); err != nil {
		return res, err
	}
	res.Projects = hits
	if hits, err = s.searchNotes(ctx, text, limit); err != nil {
		return res, err
	}
	res.Notes = hits
	return res, nil
}

func (s *Store) searchClients(ctx context.Context, text, digits string, phone bool, limit int) ([]Hit, error) {
	q := `SELECT id, name, phone, status FROM clients WHERE name LIKE ?`
	args := []any{text}
	if phone {
		q += ` OR (phone_digits <> '' AND (phone_digits LIKE ? OR ? LIKE '%' || phone_digits || '%'))`
		args = append(args, "%"+digits+"%", digits)
	}
	q += ` ORDER BY name COLLATE NOCASE ASC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Hit
	for rows.Next() {
		var h Hit
		var phoneText, status string
		if err := rows.Scan(&h.ID, &h.Title, &phoneText, &status); err != nil {
			return nil, err
		}
		h.Kind = "client"
		h.ClientID = h.ID
		h.ClientName = h.Title
		h.Subtitle = firstNonEmpty(phoneText, status)
		h.Href = fmt.Sprintf("/clients/%d", h.ID)
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) searchContacts(ctx context.Context, text, digits string, phone bool, limit int) ([]Hit, error) {
	q := `SELECT ct.id, ct.name, ct.role, ct.phone, ct.email, cl.id, cl.name
	      FROM contacts ct JOIN clients cl ON cl.id = ct.client_id
	      WHERE ct.name LIKE ? OR ct.email LIKE ?`
	args := []any{text, text}
	if phone {
		q += ` OR (ct.phone_digits <> '' AND (ct.phone_digits LIKE ? OR ? LIKE '%' || ct.phone_digits || '%'))`
		args = append(args, "%"+digits+"%", digits)
	}
	q += ` ORDER BY ct.name COLLATE NOCASE ASC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Hit
	for rows.Next() {
		var h Hit
		var role, phoneText, email string
		if err := rows.Scan(&h.ID, &h.Title, &role, &phoneText, &email, &h.ClientID, &h.ClientName); err != nil {
			return nil, err
		}
		h.Kind = "contact"
		h.Subtitle = strings.Join(nonEmpty(role, "at "+h.ClientName), " · ")
		if phoneText != "" {
			h.Subtitle = phoneText + " · " + h.Subtitle
		}
		h.Href = fmt.Sprintf("/clients/%d?tab=contacts", h.ClientID)
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) searchProjects(ctx context.Context, text string, limit int) ([]Hit, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT p.id, p.name, p.status, cl.id, cl.name
		 FROM projects p JOIN clients cl ON cl.id = p.client_id
		 WHERE p.name LIKE ? ORDER BY p.name COLLATE NOCASE ASC LIMIT ?`, text, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Hit
	for rows.Next() {
		var h Hit
		var status string
		if err := rows.Scan(&h.ID, &h.Title, &status, &h.ClientID, &h.ClientName); err != nil {
			return nil, err
		}
		h.Kind = "project"
		h.Subtitle = status + " · " + h.ClientName
		h.Href = fmt.Sprintf("/projects/%d", h.ID)
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) searchNotes(ctx context.Context, text string, limit int) ([]Hit, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT n.id, n.title, cl.id, cl.name, COALESCE(n.job_id, 0)
		 FROM notes n JOIN clients cl ON cl.id = n.client_id
		 WHERE n.is_secret = 0 AND n.title <> '' AND n.title LIKE ?
		 ORDER BY n.title COLLATE NOCASE ASC LIMIT ?`, text, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Hit
	for rows.Next() {
		var h Hit
		var jobID int64
		if err := rows.Scan(&h.ID, &h.Title, &h.ClientID, &h.ClientName, &jobID); err != nil {
			return nil, err
		}
		h.Kind = "note"
		h.Subtitle = "note · " + h.ClientName
		h.Href = fmt.Sprintf("/clients/%d", h.ClientID)
		if jobID != 0 {
			h.Href = fmt.Sprintf("/jobs/%d", jobID)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// --- scanning -----------------------------------------------------------

type scanner interface{ Scan(dest ...any) error }

func scanClient(sc scanner) (Client, error) {
	var (
		c                      Client
		created, updated, arch string
	)
	if err := sc.Scan(&c.ID, &c.Name, &c.Status, &c.Website, &c.Address, &c.Phone, &c.PhoneDigits,
		&c.Summary, &c.Tags, &created, &updated, &arch); err != nil {
		return Client{}, err
	}
	c.CreatedAt = parseTS(created)
	c.UpdatedAt = parseTS(updated)
	c.ArchivedAt = parseTS(arch)
	return c, nil
}

func scanContact(sc scanner) (Contact, error) {
	var (
		c                Contact
		primary          int
		created, updated string
	)
	if err := sc.Scan(&c.ID, &c.ClientID, &c.Name, &c.Role, &c.Phone, &c.PhoneDigits, &c.Email,
		&c.Notes, &primary, &created, &updated); err != nil {
		return Contact{}, err
	}
	c.IsPrimary = primary == 1
	c.CreatedAt = parseTS(created)
	c.UpdatedAt = parseTS(updated)
	return c, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func nonEmpty(values ...string) []string {
	var out []string
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
