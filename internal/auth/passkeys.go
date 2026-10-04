package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ErrChallenge means a WebAuthn ceremony challenge is unknown, expired, or
// already used. Challenges are single-use.
var ErrChallenge = errors.New("auth: unknown or expired challenge")

// Passkey is one stored WebAuthn credential. Only public material is kept: the
// credential ID, the public key, and the authenticator's flags/counter. It is
// deliberately decoupled from the webauthn library so this package stays a
// plain database layer; the HTTP layer adapts it to webauthn.Credential.
type Passkey struct {
	ID              int64
	UserID          int64
	CredentialID    []byte
	PublicKey       []byte
	AttestationType string
	AAGUID          []byte
	SignCount       uint32
	BackupEligible  bool
	BackupState     bool
	Transports      []string
	Name            string
	CreatedAt       string
	LastUsedAt      string
}

// PasswordLoginEnabled reports whether any account has a password. When false
// the login form is not rendered and POST /login is refused before any Argon2
// work, so a passkey-only account has no password attack surface.
func (s *Service) PasswordLoginEnabled(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM users WHERE password_hash <> ''`).Scan(&n)
	return n > 0, err
}

// CreateUserNoPassword creates the single user with no password (passkey-only).
// It refuses (ErrUserExists) if a user already exists.
func (s *Service) CreateUserNoPassword(ctx context.Context, username string) (User, error) {
	username = trimSpace(username)
	if username == "" {
		return User{}, errors.New("auth: a name is required")
	}
	n, err := s.UserCount(ctx)
	if err != nil {
		return User{}, err
	}
	if n > 0 {
		return User{}, ErrUserExists
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash) VALUES (?, '')`, username)
	if err != nil {
		return User{}, err
	}
	return s.GetUser(ctx)
}

// SetUsername renames the single user (used when an abandoned passkey
// registration is resumed with a password under a different name).
func (s *Service) SetUsername(ctx context.Context, userID int64, username string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET username = ?, updated_at = ? WHERE id = ?`,
		truncate(trimSpace(username), 200), formatTS(time.Now()), userID)
	return err
}

// RemovePassword clears the password and disables TOTP, leaving any passkeys as
// the account's credentials. The caller must guarantee another credential
// exists first; the database cannot express that invariant.
func (s *Service) RemovePassword(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET password_hash = '', totp_secret = '', totp_enabled = 0,
		     totp_pending_secret = '', totp_enrolled_at = NULL, updated_at = ?
		 WHERE id = ?`, formatTS(time.Now()), userID)
	return err
}

// --- passkey credentials -------------------------------------------------

func (s *Service) ListPasskeys(ctx context.Context, userID int64) ([]Passkey, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, credential_id, public_key, attestation_type, aaguid,
		        sign_count, backup_eligible, backup_state, transports, name,
		        created_at, COALESCE(last_used_at, '')
		 FROM webauthn_credentials WHERE user_id = ? ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Passkey
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Service) PasskeyCount(ctx context.Context, userID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM webauthn_credentials WHERE user_id = ?`, userID).Scan(&n)
	return n, err
}

// AddPasskey stores a verified credential. credential_id is unique across the
// table, so a replayed registration cannot shadow another passkey.
func (s *Service) AddPasskey(ctx context.Context, p Passkey) (int64, error) {
	be, bs := 0, 0
	if p.BackupEligible {
		be = 1
	}
	if p.BackupState {
		bs = 1
	}
	aaguid := p.AAGUID
	if aaguid == nil {
		aaguid = []byte{}
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO webauthn_credentials
		   (user_id, credential_id, public_key, attestation_type, aaguid,
		    sign_count, backup_eligible, backup_state, transports, name)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.UserID, p.CredentialID, p.PublicKey, p.AttestationType, aaguid,
		p.SignCount, be, bs, strings.Join(p.Transports, ","), truncate(p.Name, 100))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Service) RenamePasskey(ctx context.Context, userID, id int64, name string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE webauthn_credentials SET name = ? WHERE id = ? AND user_id = ?`,
		truncate(trimSpace(name), 100), id, userID)
	return err
}

func (s *Service) DeletePasskey(ctx context.Context, userID, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?`, id, userID)
	return err
}

// UpdatePasskeyUse records a successful assertion: the authenticator's new
// signature counter and the time.
func (s *Service) UpdatePasskeyUse(ctx context.Context, id int64, signCount uint32) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE webauthn_credentials SET sign_count = ?, last_used_at = ? WHERE id = ?`,
		signCount, formatTS(time.Now()), id)
	return err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanPasskey(row rowScanner) (Passkey, error) {
	var (
		p      Passkey
		be, bs int
		tx     string
	)
	err := row.Scan(&p.ID, &p.UserID, &p.CredentialID, &p.PublicKey, &p.AttestationType,
		&p.AAGUID, &p.SignCount, &be, &bs, &tx, &p.Name, &p.CreatedAt, &p.LastUsedAt)
	if err != nil {
		return Passkey{}, err
	}
	p.BackupEligible = be == 1
	p.BackupState = bs == 1
	if tx != "" {
		p.Transports = strings.Split(tx, ",")
	}
	return p, nil
}

// --- in-flight ceremony challenges --------------------------------------

// StoreChallenge persists a WebAuthn ceremony's SessionData under a fresh
// random token, returning the raw token to set as a cookie. Only its hash is
// stored.
func (s *Service) StoreChallenge(ctx context.Context, userID *int64, kind, sessionData string, ttl time.Duration) (string, error) {
	token, err := NewToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO webauthn_challenges (token_hash, user_id, kind, session_data, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		HashToken(token), userID, kind, sessionData, formatTS(now), formatTS(now.Add(ttl)))
	if err != nil {
		return "", err
	}
	return token, nil
}

// TakeChallenge consumes a challenge by raw token and kind, returning its
// SessionData. It is deleted whether or not it is expired or the kind mismatches
// (single-use). ErrChallenge is returned for anything other than a fresh match.
func (s *Service) TakeChallenge(ctx context.Context, token, kind string) (string, error) {
	if token == "" {
		return "", ErrChallenge
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var (
		id        int64
		data      string
		expiresAt string
		gotKind   string
	)
	err = tx.QueryRowContext(ctx,
		`SELECT id, kind, session_data, expires_at FROM webauthn_challenges WHERE token_hash = ?`,
		HashToken(token)).Scan(&id, &gotKind, &data, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrChallenge
	}
	if err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM webauthn_challenges WHERE id = ?`, id); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	if gotKind != kind || !time.Now().Before(parseTS(expiresAt)) {
		return "", ErrChallenge
	}
	return data, nil
}

// DeleteExpiredChallenges removes stale challenges at startup so the table does
// not grow unbounded.
func (s *Service) DeleteExpiredChallenges(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM webauthn_challenges WHERE expires_at <= ?`, formatTS(time.Now()))
	return err
}
