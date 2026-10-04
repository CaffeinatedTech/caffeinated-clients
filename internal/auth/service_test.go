package auth

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/CaffeinatedTech/caffeinated-clients/internal/store"
)

func openTestService(t *testing.T) (*Service, *sql.DB) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "clients.db"), key)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := store.Migrate(context.Background(), db); err != nil {
		db.Close()
		t.Fatalf("store.Migrate: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewService(db, testParams(), "caffeinated-clients"), db
}

func TestBootstrapExactlyOneUser(t *testing.T) {
	svc, _ := openTestService(t)
	ctx := context.Background()

	if n, err := svc.UserCount(ctx); err != nil || n != 0 {
		t.Fatalf("UserCount = %d, %v; want 0", n, err)
	}
	created, err := svc.Bootstrap(ctx, "admin", "correct horse battery")
	if err != nil || !created {
		t.Fatalf("Bootstrap = %v, %v; want true, nil", created, err)
	}
	created, err = svc.Bootstrap(ctx, "other", "another password")
	if !errors.Is(err, ErrUserExists) || created {
		t.Fatalf("second Bootstrap = %v, %v; want ErrUserExists", created, err)
	}

	if _, err := svc.Bootstrap(ctx, "admin", "short"); err == nil {
		t.Fatal("expected short password to be rejected")
	}
}

func TestAuthenticate(t *testing.T) {
	svc, _ := openTestService(t)
	ctx := context.Background()
	if _, err := svc.Bootstrap(ctx, "admin", "correct horse battery"); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	if u, ok, err := svc.Authenticate(ctx, "admin", "correct horse battery"); err != nil || !ok || u.Username != "admin" {
		t.Fatalf("valid login = %v, %v, %v", u.Username, ok, err)
	}
	if _, ok, err := svc.Authenticate(ctx, "admin", "wrong"); err != nil || ok {
		t.Fatalf("invalid login accepted: ok=%v err=%v", ok, err)
	}
	if _, ok, err := svc.Authenticate(ctx, "nobody", "wrong"); err != nil || ok {
		t.Fatalf("unknown user accepted: ok=%v err=%v", ok, err)
	}
}

func TestSessionLifecycleAndExpiry(t *testing.T) {
	svc, db := openTestService(t)
	ctx := context.Background()
	if _, err := svc.Bootstrap(ctx, "admin", "correct horse battery"); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	user, err := svc.GetUser(ctx)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}

	const ttl = time.Hour
	sess, token, err := svc.CreateSession(ctx, user, StageFull, ttl, "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sess.CSRFToken == "" {
		t.Fatal("session has no CSRF token")
	}

	got, err := svc.GetSession(ctx, token, ttl/8)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.User.Username != "admin" || got.Stage != StageFull || got.CSRFToken != sess.CSRFToken {
		t.Fatalf("GetSession returned %+v", got)
	}

	if err := svc.DeleteSession(ctx, token); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := svc.GetSession(ctx, token, ttl/8); !errors.Is(err, ErrNoSession) {
		t.Fatalf("deleted session = %v, want ErrNoSession", err)
	}

	// Absolute expiry: push expires_at into the past.
	_, token2, _ := svc.CreateSession(ctx, user, StageFull, ttl, "", "")
	if _, err := db.Exec(`UPDATE sessions SET expires_at = ? WHERE token_hash = ?`,
		formatTS(time.Now().Add(-time.Minute)), HashToken(token2)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetSession(ctx, token2, ttl/8); !errors.Is(err, ErrNoSession) {
		t.Fatalf("expired session = %v, want ErrNoSession", err)
	}
	if n := countSessions(t, db); n != 0 {
		t.Fatalf("expired sessions remain: %d", n)
	}

	// Idle expiry: last_seen_at older than idleTTL while still within TTL.
	_, token3, _ := svc.CreateSession(ctx, user, StageFull, ttl, "", "")
	if _, err := db.Exec(`UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?`,
		formatTS(time.Now().Add(-time.Hour)), HashToken(token3)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetSession(ctx, token3, 10*time.Minute); !errors.Is(err, ErrNoSession) {
		t.Fatalf("idle session = %v, want ErrNoSession", err)
	}
}

func TestRecoveryCodeSingleUse(t *testing.T) {
	svc, _ := openTestService(t)
	ctx := context.Background()
	if _, err := svc.Bootstrap(ctx, "admin", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	user, err := svc.GetUser(ctx)
	if err != nil {
		t.Fatal(err)
	}
	codes, err := NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.StoreRecoveryCodes(ctx, user.ID, codes); err != nil {
		t.Fatalf("StoreRecoveryCodes: %v", err)
	}

	used, err := svc.ConsumeRecoveryCode(ctx, user.ID, codes[0])
	if err != nil || !used {
		t.Fatalf("first use = %v, %v; want true", used, err)
	}
	used, err = svc.ConsumeRecoveryCode(ctx, user.ID, codes[0])
	if err != nil || used {
		t.Fatalf("second use = %v, %v; want false", used, err)
	}
	if used, err := svc.ConsumeRecoveryCode(ctx, user.ID, "ZZZZ-ZZZZ-ZZZZ-ZZZZ"); err != nil || used {
		t.Fatalf("unknown code = %v, %v; want false", used, err)
	}
	if used, err := svc.ConsumeRecoveryCode(ctx, user.ID, codes[1]); err != nil || !used {
		t.Fatalf("other code = %v, %v; want true", used, err)
	}
}

func TestAuditAppendOnly(t *testing.T) {
	svc, db := openTestService(t)
	ctx := context.Background()
	if err := svc.Audit(ctx, AuditEntry{Event: "login_failure", Entity: "user", IP: "127.0.0.1",
		Detail: map[string]any{"username": "admin"}}); err != nil {
		t.Fatalf("Audit: %v", err)
	}
	var event, detail string
	if err := db.QueryRow(`SELECT event, detail FROM audit_log`).Scan(&event, &detail); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if event != "login_failure" || detail == "" {
		t.Fatalf("unexpected audit row: %q %q", event, detail)
	}
}

func countSessions(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sessions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
