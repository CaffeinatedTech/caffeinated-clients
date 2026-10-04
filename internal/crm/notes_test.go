package crm

import (
	"context"
	"errors"
	"testing"
)

func TestNoteLifecycleAndSecretPreserved(t *testing.T) {
	s, _ := openCRM(t)
	ctx := context.Background()
	clientID, err := s.CreateClient(ctx, ClientInput{Name: "Acme Co"})
	if err != nil {
		t.Fatal(err)
	}

	publicID, err := s.CreateNote(ctx, clientID, NoteInput{Title: "Public", Body: "hello"})
	if err != nil {
		t.Fatalf("CreateNote: %v", err)
	}
	secretID, err := s.CreateNote(ctx, clientID, NoteInput{Title: "Creds", Body: "hunter2", IsSecret: true})
	if err != nil {
		t.Fatalf("CreateNote secret: %v", err)
	}

	notes, err := s.ListNotes(ctx, clientID)
	if err != nil {
		t.Fatalf("ListNotes: %v", err)
	}
	if len(notes) != 2 {
		t.Fatalf("notes = %d, want 2", len(notes))
	}

	// Pinned notes sort first (F4.2).
	if err := s.SetNotePinned(ctx, clientID, publicID, true); err != nil {
		t.Fatalf("SetNotePinned: %v", err)
	}
	notes, _ = s.ListNotes(ctx, clientID)
	if notes[0].ID != publicID || !notes[0].Pinned {
		t.Fatalf("pinned note did not sort first: %+v", notes)
	}

	// Editing title/body must preserve the secret flag (F4.6).
	if err := s.UpdateNote(ctx, clientID, secretID, NoteInput{Title: "Creds v2", Body: "hunter3"}); err != nil {
		t.Fatalf("UpdateNote: %v", err)
	}
	n, err := s.GetNote(ctx, secretID)
	if err != nil {
		t.Fatalf("GetNote: %v", err)
	}
	if !n.IsSecret || n.Title != "Creds v2" || n.Body != "hunter3" {
		t.Fatalf("edit changed more than title/body: %+v", n)
	}

	// Toggling the secret flag changes only the flag, not the body (F4.6).
	if err := s.SetNoteSecret(ctx, clientID, secretID, false); err != nil {
		t.Fatalf("SetNoteSecret: %v", err)
	}
	n, _ = s.GetNote(ctx, secretID)
	if n.IsSecret || n.Body != "hunter3" {
		t.Fatalf("secret toggle altered body or flag: %+v", n)
	}

	// A note can only be edited by its own client.
	if err := s.UpdateNote(ctx, clientID+1, secretID, NoteInput{Title: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-client UpdateNote = %v, want ErrNotFound", err)
	}

	if err := s.DeleteNote(ctx, clientID, secretID); err != nil {
		t.Fatalf("DeleteNote: %v", err)
	}
	if _, err := s.GetNote(ctx, secretID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetNote after delete = %v, want ErrNotFound", err)
	}
}
