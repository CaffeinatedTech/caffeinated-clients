package crm

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/CaffeinatedTech/caffeinated-clients/internal/store"
)

func openCRM(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 5)
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
	return New(db), db
}

func TestNormalizePhone(t *testing.T) {
	cases := map[string]string{
		"+1 (555) 010-0": "15550100",
		"555-0100":       "5550100",
		"(555) 0100":     "5550100",
		"+15550100":      "15550100",
		"":               "",
		"no digits":      "",
	}
	for in, want := range cases {
		if got := NormalizePhone(in); got != want {
			t.Errorf("NormalizePhone(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClientLifecycle(t *testing.T) {
	s, _ := openCRM(t)
	ctx := context.Background()

	id, err := s.CreateClient(ctx, ClientInput{Name: "  Acme Co  ", Phone: "+1 555 0100"})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	c, err := s.GetClient(ctx, id)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if c.Name != "Acme Co" || c.Status != "active" || c.PhoneDigits != "15550100" {
		t.Fatalf("unexpected client: %+v", c)
	}

	if err := s.UpdateClient(ctx, id, ClientInput{Name: "Acme Ltd", Status: "inactive", Phone: "555-0100"}); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	c, _ = s.GetClient(ctx, id)
	if c.Name != "Acme Ltd" || c.Status != "inactive" || c.PhoneDigits != "5550100" {
		t.Fatalf("after update: %+v", c)
	}

	// Archived clients are hidden from the default list but returned for the
	// archived filter.
	if err := s.SetArchived(ctx, id, true); err != nil {
		t.Fatalf("archive: %v", err)
	}
	defaultList, _ := s.ListClients(ctx, ListOptions{})
	if len(defaultList) != 0 {
		t.Fatalf("default list has %d archived clients, want 0", len(defaultList))
	}
	archived, _ := s.ListClients(ctx, ListOptions{Status: "archived"})
	if len(archived) != 1 || !archived[0].Archived() {
		t.Fatalf("archived list = %+v", archived)
	}

	if err := s.SetArchived(ctx, id, false); err != nil {
		t.Fatalf("restore: %v", err)
	}
	c, _ = s.GetClient(ctx, id)
	if c.Status != "active" || !c.ArchivedAt.IsZero() {
		t.Fatalf("restore left %+v", c)
	}

	if err := s.DeleteClient(ctx, id); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if _, err := s.GetClient(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetClient after delete = %v, want ErrNotFound", err)
	}
}

func TestCreateClientRequiresName(t *testing.T) {
	s, _ := openCRM(t)
	if _, err := s.CreateClient(context.Background(), ClientInput{Name: "   "}); !errors.Is(err, ErrNameRequired) {
		t.Fatalf("blank name = %v, want ErrNameRequired", err)
	}
}

func TestPrimaryContactInvariant(t *testing.T) {
	s, _ := openCRM(t)
	ctx := context.Background()
	clientID, err := s.CreateClient(ctx, ClientInput{Name: "Acme Co"})
	if err != nil {
		t.Fatal(err)
	}

	first, err := s.CreateContact(ctx, clientID, ContactInput{Name: "Ada", IsPrimary: true})
	if err != nil {
		t.Fatalf("CreateContact: %v", err)
	}
	second, err := s.CreateContact(ctx, clientID, ContactInput{Name: "Grace", IsPrimary: true})
	if err != nil {
		t.Fatalf("CreateContact: %v", err)
	}
	assertSinglePrimary(t, s, ctx, clientID, second)

	// Promoting the first clears the second.
	if err := s.UpdateContact(ctx, clientID, first, ContactInput{Name: "Ada", IsPrimary: true}); err != nil {
		t.Fatalf("UpdateContact: %v", err)
	}
	assertSinglePrimary(t, s, ctx, clientID, first)

	// Deleting the primary leaves the rest non-primary (zero is allowed).
	if err := s.DeleteContact(ctx, clientID, first); err != nil {
		t.Fatalf("DeleteContact: %v", err)
	}
	contacts, _ := s.ListContacts(ctx, clientID)
	for _, c := range contacts {
		if c.IsPrimary {
			t.Fatalf("contact %d still primary after delete", c.ID)
		}
	}
}

func assertSinglePrimary(t *testing.T, s *Store, ctx context.Context, clientID, wantPrimary int64) {
	t.Helper()
	contacts, err := s.ListContacts(ctx, clientID)
	if err != nil {
		t.Fatalf("ListContacts: %v", err)
	}
	var primaries []int64
	for _, c := range contacts {
		if c.IsPrimary {
			primaries = append(primaries, c.ID)
		}
	}
	if len(primaries) != 1 || primaries[0] != wantPrimary {
		t.Fatalf("primary contacts = %v, want [%d]", primaries, wantPrimary)
	}
}

func TestSearchGroupingAndPhoneMatching(t *testing.T) {
	s, db := openCRM(t)
	ctx := context.Background()

	clientID, _ := s.CreateClient(ctx, ClientInput{Name: "Acme Co", Phone: "+1 (555) 0100"})
	if _, err := s.CreateContact(ctx, clientID, ContactInput{Name: "Ada Lovelace", Phone: "555-0100"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO projects (client_id, name) VALUES (?, 'Acme Website')`, clientID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO notes (client_id, title) VALUES (?, 'Acme onboarding')`, clientID); err != nil {
		t.Fatal(err)
	}

	res, err := s.Search(ctx, "Acme", 20)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res.Clients) != 1 || len(res.Projects) != 1 || len(res.Notes) != 1 {
		t.Fatalf("grouping wrong: %+v", res)
	}

	// Phone formatting must not matter, in either direction.
	for _, q := range []string{"555-0100", "(555) 0100", "+15550100"} {
		res, err := s.Search(ctx, q, 20)
		if err != nil {
			t.Fatalf("Search(%q): %v", q, err)
		}
		if len(res.Clients) != 1 || len(res.Contacts) != 1 {
			t.Fatalf("Search(%q) clients=%d contacts=%d, want 1/1", q, len(res.Clients), len(res.Contacts))
		}
	}
}

func TestSearchExcludesSecretNotes(t *testing.T) {
	s, db := openCRM(t)
	ctx := context.Background()
	clientID, _ := s.CreateClient(ctx, ClientInput{Name: "Acme Co"})
	if _, err := db.Exec(`INSERT INTO notes (client_id, title, is_secret) VALUES (?, 'Router admin', 1)`, clientID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO notes (client_id, title, is_secret) VALUES (?, 'Router public', 0)`, clientID); err != nil {
		t.Fatal(err)
	}

	res, err := s.Search(ctx, "Router", 20)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res.Notes) != 1 || res.Notes[0].Title != "Router public" {
		t.Fatalf("secret note leaked into search: %+v", res.Notes)
	}

	// Note bodies are not searched at all (F4.5/F8.5).
	if _, err := db.Exec(`INSERT INTO notes (client_id, title, body) VALUES (?, 'Unrelated', 'router secret body')`, clientID); err != nil {
		t.Fatal(err)
	}
	res, _ = s.Search(ctx, "secret body", 20)
	if len(res.Notes) != 0 {
		t.Fatalf("note body leaked into search: %+v", res.Notes)
	}
}

func TestCascadeDelete(t *testing.T) {
	s, db := openCRM(t)
	ctx := context.Background()
	clientID, _ := s.CreateClient(ctx, ClientInput{Name: "Acme Co"})
	if _, err := s.CreateContact(ctx, clientID, ContactInput{Name: "Ada"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO notes (client_id, title) VALUES (?, 'Note')`, clientID); err != nil {
		t.Fatal(err)
	}
	res, err := db.Exec(`INSERT INTO projects (client_id, name) VALUES (?, 'Project')`, clientID)
	if err != nil {
		t.Fatal(err)
	}
	projectID, _ := res.LastInsertId()
	if _, err := db.Exec(`INSERT INTO jobs (client_id, project_id, title) VALUES (?, ?, 'Job')`, clientID, projectID); err != nil {
		t.Fatal(err)
	}

	counts, err := s.ClientCascadeCounts(ctx, clientID)
	if err != nil {
		t.Fatalf("ClientCascadeCounts: %v", err)
	}
	if counts != (CascadeCounts{Contacts: 1, Notes: 1, Projects: 1, Jobs: 1}) {
		t.Fatalf("counts = %+v", counts)
	}

	if err := s.DeleteClient(ctx, clientID); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	for _, table := range []string{"contacts", "notes", "projects", "jobs"} {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s has %d rows after cascade delete, want 0", table, n)
		}
	}
}
