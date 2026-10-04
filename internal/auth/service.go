package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Session stages.
const (
	StagePending = "pending" // password accepted, second factor outstanding
	StageFull    = "full"    // fully authenticated
)

// ErrUserExists means the single-user bootstrap ran when a user already exists.
var ErrUserExists = errors.New("auth: user already exists")

// ErrNoSession means the session token is unknown, expired, or idle-timeout.
var ErrNoSession = errors.New("auth: no valid session")

// tsLayout matches the strftime('%Y-%m-%dT%H:%M:%fZ') default used in the
// schema, so Go-written timestamps sort and compare consistently.
const tsLayout = "2006-01-02T15:04:05.000Z"

func formatTS(t time.Time) string { return t.UTC().Format(tsLayout) }

func parseTS(s string) time.Time {
	t, err := time.Parse(tsLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// User is the single account.
type User struct {
	ID             int64
	Username       string
	PasswordHash   string
	TOTPSecret     string
	TOTPEnabled    bool
	TOTPEnrolledAt string
}

// Session is a server-side session joined with its user. Token is the raw
// cookie value and is never persisted; only its hash is.
type Session struct {
	ID         int64
	UserID     int64
	Token      string
	Stage      string
	CSRFToken  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	User       User
}

// AuditEntry is one append-only audit row (F13). Detail is JSON and must never
// contain secrets.
type AuditEntry struct {
	Event    string
	Entity   string
	EntityID *int64
	ClientID *int64
	IP       string
	Detail   map[string]any
}

// Service owns authentication state in the encrypted database.
type Service struct {
	db     *sql.DB
	params Params
	issuer string

	dummyOnce sync.Once
	dummy     string
}

// NewService returns a Service using params for all new password and
// recovery-code hashes. issuer labels the TOTP entry in authenticator apps.
func NewService(db *sql.DB, params Params, issuer string) *Service {
	return &Service{db: db, params: params, issuer: issuer}
}

// Issuer is the TOTP issuer label.
func (s *Service) Issuer() string { return s.issuer }

// Params returns the hashing parameters (for tests).
func (s *Service) Params() Params { return s.params }

// UserCount returns the number of users (0 before bootstrap, 1 after).
func (s *Service) UserCount(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// GetUser returns the single user, or sql.ErrNoRows if none exists.
func (s *Service) GetUser(ctx context.Context) (User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, totp_secret, totp_enabled, COALESCE(totp_enrolled_at, '')
		 FROM users ORDER BY id LIMIT 1`)
	return scanUser(row)
}

func (s *Service) getUserByUsername(ctx context.Context, username string) (User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, totp_secret, totp_enabled, COALESCE(totp_enrolled_at, '')
		 FROM users WHERE username = ? LIMIT 1`, username)
	return scanUser(row)
}

func scanUser(row *sql.Row) (User, error) {
	var u User
	var enabled int
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.TOTPSecret, &enabled, &u.TOTPEnrolledAt)
	if err != nil {
		return User{}, err
	}
	u.TOTPEnabled = enabled == 1
	return u, nil
}

// Bootstrap creates the single user. It refuses (ErrUserExists) if any user
// already exists, keeping the "exactly one user" invariant (F1.1/F1.2).
func (s *Service) Bootstrap(ctx context.Context, username, password string) (bool, error) {
	username = trimSpace(username)
	if username == "" {
		return false, errors.New("auth: bootstrap username is required")
	}
	if len(password) < 8 {
		return false, errors.New("auth: bootstrap password must be at least 8 characters")
	}
	n, err := s.UserCount(ctx)
	if err != nil {
		return false, err
	}
	if n > 0 {
		return false, ErrUserExists
	}
	hash, err := HashPassword(s.params, password)
	if err != nil {
		return false, err
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash) VALUES (?, ?)`, username, hash)
	if err != nil {
		return false, err
	}
	id, _ := res.LastInsertId()
	_ = s.Audit(ctx, AuditEntry{Event: "user_bootstrapped", Entity: "user", EntityID: &id})
	return true, nil
}

// Authenticate verifies username/password. It always performs an Argon2id
// verification, even for an unknown user, so timing does not reveal account
// existence. It returns the user and whether the password matched.
func (s *Service) Authenticate(ctx context.Context, username, password string) (User, bool, error) {
	u, err := s.getUserByUsername(ctx, trimSpace(username))
	if errors.Is(err, sql.ErrNoRows) {
		s.dummyVerify(password) // equalize timing
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	if !VerifyPassword(u.PasswordHash, password) {
		return User{}, false, nil
	}
	return u, true, nil
}

// dummyVerify performs a throwaway Argon2id verification when no user matched,
// so a missing account takes about as long as a wrong password. The dummy hash
// is built once, with this service's parameters.
func (s *Service) dummyVerify(password string) {
	s.dummyOnce.Do(func() {
		h, err := HashPassword(s.params, "not-a-real-password")
		if err == nil {
			s.dummy = h
		}
	})
	VerifyPassword(s.dummy, password)
}

// SetTOTPSecret stores a provisional secret without enabling TOTP. It is a
// no-op if TOTP is already enabled, so an in-progress enrollment cannot be
// hijacked.
func (s *Service) SetTOTPSecret(ctx context.Context, userID int64, secret string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_secret = ?, totp_enabled = 0, updated_at = ? WHERE id = ? AND totp_enabled = 0`,
		secret, formatTS(time.Now()), userID)
	return err
}

// EnableTOTP marks the user's TOTP secret as confirmed.
func (s *Service) EnableTOTP(ctx context.Context, userID int64) error {
	now := formatTS(time.Now())
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_enabled = 1, totp_enrolled_at = ?, updated_at = ? WHERE id = ?`,
		now, now, userID)
	return err
}

// SetPassword hashes and stores a new password for the user.
func (s *Service) SetPassword(ctx context.Context, userID int64, password string) error {
	hash, err := HashPassword(s.params, password)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`,
		hash, formatTS(time.Now()), userID)
	return err
}

// SetPendingTOTPSecret stores a replacement secret without touching the active
// one, so re-enrollment can be confirmed before it takes effect.
func (s *Service) SetPendingTOTPSecret(ctx context.Context, userID int64, secret string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_pending_secret = ?, updated_at = ? WHERE id = ?`,
		secret, formatTS(time.Now()), userID)
	return err
}

// PendingTOTPSecret returns the unconfirmed re-enrollment secret, or "" if
// none is in progress.
func (s *Service) PendingTOTPSecret(ctx context.Context, userID int64) (string, error) {
	var secret string
	err := s.db.QueryRowContext(ctx,
		`SELECT totp_pending_secret FROM users WHERE id = ?`, userID).Scan(&secret)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return secret, err
}

// EnablePendingTOTP promotes a confirmed pending secret to the active secret
// and enables TOTP. It is a no-op when no re-enrollment is pending.
func (s *Service) EnablePendingTOTP(ctx context.Context, userID int64) error {
	now := formatTS(time.Now())
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_secret = totp_pending_secret, totp_pending_secret = '',
		     totp_enabled = 1, totp_enrolled_at = ?, updated_at = ?
		 WHERE id = ? AND totp_pending_secret <> ''`,
		now, now, userID)
	return err
}

// UnusedRecoveryCodeCount returns how many single-use codes remain.
func (s *Service) UnusedRecoveryCodeCount(ctx context.Context, userID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL`, userID).Scan(&n)
	return n, err
}

// StoreRecoveryCodes replaces the user's unused recovery codes with hashes of
// the supplied plaintext codes.
func (s *Service) StoreRecoveryCodes(ctx context.Context, userID int64, codes []string) error {
	hashes := make([]string, len(codes))
	for i, c := range codes {
		h, err := HashRecoveryCode(s.params, c)
		if err != nil {
			return err
		}
		hashes[i] = h
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)`, userID, h); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ConsumeRecoveryCode tries each unused code and, on a match, marks it used
// and returns true. A code can never be used twice (F1.5).
func (s *Service) ConsumeRecoveryCode(ctx context.Context, userID int64, code string) (bool, error) {
	if NormalizeRecoveryCode(code) == "" {
		return false, nil
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, code_hash FROM recovery_codes WHERE user_id = ? AND used_at IS NULL`, userID)
	if err != nil {
		return false, err
	}
	type candidate struct {
		id   int64
		hash string
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.hash); err != nil {
			rows.Close()
			return false, err
		}
		candidates = append(candidates, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	for _, c := range candidates {
		if VerifyRecoveryCode(c.hash, code) {
			res, err := s.db.ExecContext(ctx,
				`UPDATE recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL`,
				formatTS(time.Now()), c.id)
			if err != nil {
				return false, err
			}
			n, _ := res.RowsAffected()
			return n == 1, nil
		}
	}
	return false, nil
}

// CreateSession issues a new session for user at the given stage and lifetime.
// It returns the raw token to set as a cookie; only the hash is stored.
func (s *Service) CreateSession(ctx context.Context, user User, stage string, ttl time.Duration, userAgent, ip string) (Session, string, error) {
	token, err := NewToken()
	if err != nil {
		return Session{}, "", err
	}
	csrf, err := NewCSRFToken()
	if err != nil {
		return Session{}, "", err
	}
	now := time.Now()
	sess := Session{
		UserID:     user.ID,
		Token:      token,
		Stage:      stage,
		CSRFToken:  csrf,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(ttl),
		User:       user,
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at, user_agent, ip, stage, csrf_token)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		HashToken(token), user.ID, formatTS(now), formatTS(now), formatTS(sess.ExpiresAt),
		truncate(userAgent, 300), truncate(ip, 100), stage, csrf)
	if err != nil {
		return Session{}, "", err
	}
	sess.ID, _ = res.LastInsertId()
	return sess, token, nil
}

// GetSession resolves a raw token to a valid session. An unknown, expired, or
// idle session is deleted and reported as ErrNoSession.
func (s *Service) GetSession(ctx context.Context, token string, idleTTL time.Duration) (Session, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT s.id, s.user_id, s.stage, s.csrf_token, s.created_at, s.last_seen_at, s.expires_at,
		        u.id, u.username, u.password_hash, u.totp_secret, u.totp_enabled, COALESCE(u.totp_enrolled_at, '')
		 FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.token_hash = ?`, HashToken(token))
	var (
		sess                   Session
		created, seen, expires string
		enabled                int
	)
	err := row.Scan(&sess.ID, &sess.UserID, &sess.Stage, &sess.CSRFToken, &created, &seen, &expires,
		&sess.User.ID, &sess.User.Username, &sess.User.PasswordHash, &sess.User.TOTPSecret, &enabled, &sess.User.TOTPEnrolledAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNoSession
	}
	if err != nil {
		return Session{}, err
	}
	sess.User.TOTPEnabled = enabled == 1
	sess.Token = token
	sess.CreatedAt = parseTS(created)
	sess.LastSeenAt = parseTS(seen)
	sess.ExpiresAt = parseTS(expires)

	now := time.Now()
	if now.After(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) > idleTTL {
		s.DeleteSession(ctx, token)
		return Session{}, ErrNoSession
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at = ? WHERE id = ?`, formatTS(now), sess.ID); err != nil {
		return Session{}, err
	}
	sess.LastSeenAt = now
	return sess, nil
}

// DeleteSession removes a session by raw token. It is idempotent.
func (s *Service) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, HashToken(token))
	return err
}

// DeleteExpiredSessions removes sessions past absolute expiry; called at
// startup so the table does not grow unbounded.
func (s *Service) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, formatTS(time.Now()))
	return err
}

// Audit appends an audit row. detail is marshalled to JSON and must never
// contain secret note bodies, passwords, tokens, or recovery codes (F13.2).
func (s *Service) Audit(ctx context.Context, e AuditEntry) error {
	detail := "{}"
	if len(e.Detail) > 0 {
		b, err := json.Marshal(e.Detail)
		if err != nil {
			return err
		}
		detail = string(b)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (event, entity, entity_id, client_id, ip, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		e.Event, e.Entity, e.EntityID, e.ClientID, e.IP, detail)
	if err != nil {
		slog.Debug("audit write failed", "event", e.Event, "err", err)
	}
	return err
}

func trimSpace(s string) string {
	return strings.TrimSpace(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
