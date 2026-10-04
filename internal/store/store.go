// Package store owns the encrypted SQLCipher database: opening it with the
// raw key, applying embedded migrations, and pinging it. It never opens a
// database without a key; a wrong key fails closed.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/sjzar/go-sqlcipher" // SQLCipher-backed database/sql driver
)

// driver is the database/sql driver name registered by go-sqlcipher.
const driver = "sqlcipher"

//go:embed migrations/*.sql
var migrationsFS embed.FS

// timeouts bound connection setup and health queries so a wedged database
// cannot hang the process.
const (
	openTimeout = 10 * time.Second
	pingTimeout = 2 * time.Second
)

// Open opens the encrypted database at path with the raw 32-byte key. It
// creates the file on first run and validates the key with a decrypting read;
// on any failure it closes the handle and returns an error, leaving the file
// untouched.
func Open(path string, key []byte) (*sql.DB, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("database key must be 32 bytes, got %d", len(key))
	}

	// PRAGMAs passed in the DSN are applied to every pooled connection, with
	// the key always applied first by the driver. cipher_page_size is pinned
	// at creation time because changing it later requires a migration.
	q := url.Values{}
	q.Set("_pragma_key", "x'"+hex.EncodeToString(key)+"'")
	q.Set("_pragma_cipher_page_size", "4096")
	q.Set("_pragma_cipher_memory_security", "ON")
	q.Set("_pragma_foreign_keys", "ON")
	q.Set("_pragma_journal_mode", "WAL")
	q.Set("_pragma_busy_timeout", "5000")
	dsn := "file:" + path + "?" + q.Encode()

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	// One writer, one connection: serialises access and avoids SQLITE_BUSY
	// entirely for this single-user app.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), openTimeout)
	defer cancel()
	if err := ping(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("open encrypted database: %w", err)
	}
	return db, nil
}

// Ping performs a decrypting read: it forces page 1 to be decrypted and its
// HMAC verified. Call it through Health for the standard timeout.
func Ping(ctx context.Context, db *sql.DB) error {
	return ping(ctx, db)
}

func ping(ctx context.Context, db *sql.DB) error {
	var n int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master").Scan(&n); err != nil {
		return err
	}
	return nil
}

// Health reports whether the database is reachable and decryptable within the
// ping timeout. It is what GET /healthz calls.
func Health(ctx context.Context, db *sql.DB) error {
	ctx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	return ping(ctx, db)
}

// Migrate applies every embedded migration newer than PRAGMA user_version, in
// filename order, each in its own transaction. It is idempotent.
func Migrate(ctx context.Context, db *sql.DB) error {
	var version int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}

	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		v, err := migrationVersion(e.Name())
		if err != nil {
			return err
		}
		if v <= version {
			continue
		}
		if err := applyMigration(ctx, db, e.Name(), v); err != nil {
			return err
		}
	}
	return nil
}

func applyMigration(ctx context.Context, db *sql.DB, name string, version int) error {
	body, err := migrationsFS.ReadFile(path.Join("migrations", name))
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, string(body)); err != nil {
		return fmt.Errorf("migration %s: %w", name, err)
	}
	// user_version cannot be a bound parameter; version is an int from a
	// filename, never user input.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
		return fmt.Errorf("migration %s: set user_version: %w", name, err)
	}
	return tx.Commit()
}

// migrationVersion extracts the leading integer of a migration filename, e.g.
// "0001_init.sql" -> 1.
func migrationVersion(name string) (int, error) {
	digits, _, _ := strings.Cut(name, "_")
	v, err := strconv.Atoi(digits)
	if err != nil {
		return 0, fmt.Errorf("migration %q: name must start with a number", name)
	}
	return v, nil
}
