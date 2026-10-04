package store

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i * 7)
	}
	return k
}

func openMigrated(t *testing.T, path string, key []byte) *sql.DB {
	t.Helper()
	db, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := Migrate(context.Background(), db); err != nil {
		db.Close()
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

// The database file must not contain a known plaintext marker, and data must
// survive a close/reopen with the correct key.
func TestOpenEncryptsAndReopens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clients.db")
	key := testKey()
	const marker = "MARKER-Acme-9f3c1b7e"

	db := openMigrated(t, path, key)
	if _, err := db.Exec(`INSERT INTO clients (name) VALUES (?)`, marker); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read db: %v", err)
	}
	if bytes.Contains(raw, []byte(marker)) {
		t.Fatal("plaintext marker found in encrypted database file")
	}
	if bytes.HasPrefix(raw, []byte("SQLite format 3\x00")) {
		t.Fatal("database header is not encrypted")
	}

	db2 := openMigrated(t, path, key)
	defer db2.Close()
	var name string
	if err := db2.QueryRow(`SELECT name FROM clients WHERE name = ?`, marker).Scan(&name); err != nil {
		t.Fatalf("select after reopen: %v", err)
	}
	if name != marker {
		t.Fatalf("got %q, want %q", name, marker)
	}
}

// A wrong key must fail closed: Open errors, the file is not recreated or
// mutated, and the correct key still works afterwards.
func TestWrongKeyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clients.db")
	key := testKey()

	db := openMigrated(t, path, key)
	if _, err := db.Exec(`INSERT INTO clients (name) VALUES ('Acme Co')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read db: %v", err)
	}

	wrong := make([]byte, 32)
	for i := range wrong {
		wrong[i] = 0xFF
	}
	if _, err := Open(path, wrong); err == nil {
		t.Fatal("expected wrong key to fail")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read db after wrong key: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("wrong key mutated the database file")
	}

	db2 := openMigrated(t, path, key)
	defer db2.Close()
	var count int
	if err := db2.QueryRow(`SELECT count(*) FROM clients`).Scan(&count); err != nil {
		t.Fatalf("correct key after wrong-key attempt: %v", err)
	}
	if count != 1 {
		t.Fatalf("got %d clients, want 1", count)
	}
}

func TestOpenRejectsBadKeyLength(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "x.db"), make([]byte, 31)); err == nil {
		t.Fatal("expected short key to be rejected")
	}
}

// Open must create a missing data directory so a fresh local checkout works.
func TestOpenCreatesDataDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "data", "clients.db")
	db := openMigrated(t, path, testKey())
	defer db.Close()
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("data dir not created: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("data dir mode = %o, want 700", info.Mode().Perm())
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clients.db")
	db := openMigrated(t, path, testKey())
	defer db.Close()

	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if version != 4 {
		t.Fatalf("user_version = %d, want 4", version)
	}
}

func TestMigrateCreatesSchemaAndConstraints(t *testing.T) {
	db := openMigrated(t, filepath.Join(t.TempDir(), "clients.db"), testKey())
	defer db.Close()

	want := []string{
		"audit_log", "clients", "contacts", "jobs", "notes",
		"projects", "recovery_codes", "sessions", "users",
	}
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	got := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		got[name] = true
	}
	rows.Close()
	for _, name := range want {
		if !got[name] {
			t.Errorf("missing table %q", name)
		}
	}

	// foreign_keys=ON must be active: an orphan contact is rejected.
	if _, err := db.Exec(`INSERT INTO contacts (client_id, name) VALUES (999, 'Ghost')`); err == nil {
		t.Error("expected foreign-key violation for orphan contact")
	}

	res, err := db.Exec(`INSERT INTO clients (name) VALUES ('Acme Co')`)
	if err != nil {
		t.Fatalf("insert client: %v", err)
	}
	clientID, _ := res.LastInsertId()
	if _, err := db.Exec(`INSERT INTO contacts (client_id, name, is_primary) VALUES (?, 'A', 1)`, clientID); err != nil {
		t.Fatalf("insert primary contact: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO contacts (client_id, name, is_primary) VALUES (?, 'B', 1)`, clientID); err == nil {
		t.Error("expected unique-primary-contact violation")
	}
}
