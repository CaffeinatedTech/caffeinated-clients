package web

import (
	"errors"
	"net/http"

	"github.com/CaffeinatedTech/caffeinated-clients/internal/auth"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/crm"
)

// --- notes --------------------------------------------------------------

func (s *Server) handleNoteCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	clientID, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	if _, err := s.crm.GetClient(r.Context(), clientID); err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	in := crm.NoteInput{
		Title:    r.FormValue("title"),
		Body:     r.FormValue("body"),
		IsSecret: r.FormValue("is_secret") != "",
	}
	noteID, err := s.crm.CreateNote(r.Context(), clientID, in)
	if err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	if in.IsSecret {
		// A secret note's creation is audited separately like its reveal (F5.6).
		_ = s.svc.Audit(r.Context(), auth.AuditEntry{
			Event: "secret_note_create", Entity: "note", EntityID: &noteID, ClientID: &clientID, IP: s.clientIP(r),
		})
	} else {
		_ = s.svc.Audit(r.Context(), auth.AuditEntry{
			Event: "note_create", Entity: "note", EntityID: &noteID, ClientID: &clientID, IP: s.clientIP(r),
		})
	}
	s.respondNotes(w, r, sess, clientID)
}

func (s *Server) handleNoteUpdate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	clientID, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	noteID, ok := idParam(r, "nid")
	if !ok {
		s.notFound(w)
		return
	}
	// A missing body field means "leave the body unchanged". This lets a secret
	// note's title be edited without ever rendering its body in ordinary HTML:
	// the body is only edited after an audited reveal.
	_ = r.ParseForm()
	in := crm.NoteInput{Title: r.FormValue("title"), Body: r.FormValue("body")}
	if !r.PostForm.Has("body") {
		existing, err := s.crm.GetNote(r.Context(), noteID)
		if err != nil {
			if errors.Is(err, crm.ErrNotFound) {
				s.notFound(w)
				return
			}
			s.serverError(w, err)
			return
		}
		in.Body = existing.Body
	}
	if err := s.crm.UpdateNote(r.Context(), clientID, noteID, in); err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "note_update", Entity: "note", EntityID: &noteID, ClientID: &clientID, IP: s.clientIP(r),
	})
	s.respondNotes(w, r, sess, clientID)
}

func (s *Server) handleNotePin(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	clientID, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	noteID, ok := idParam(r, "nid")
	if !ok {
		s.notFound(w)
		return
	}
	if err := s.crm.SetNotePinned(r.Context(), clientID, noteID, r.FormValue("pinned") == "1"); err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "note_pin", Entity: "note", EntityID: &noteID, ClientID: &clientID, IP: s.clientIP(r),
		Detail: map[string]any{"pinned": r.FormValue("pinned") == "1"},
	})
	s.respondNotes(w, r, sess, clientID)
}

func (s *Server) handleNoteSecret(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	clientID, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	noteID, ok := idParam(r, "nid")
	if !ok {
		s.notFound(w)
		return
	}
	secret := r.FormValue("secret") == "1"
	if err := s.crm.SetNoteSecret(r.Context(), clientID, noteID, secret); err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "secret_flag_toggle", Entity: "note", EntityID: &noteID, ClientID: &clientID, IP: s.clientIP(r),
		Detail: map[string]any{"is_secret": secret},
	})
	s.respondNotes(w, r, sess, clientID)
}

func (s *Server) handleNoteDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	clientID, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	noteID, ok := idParam(r, "nid")
	if !ok {
		s.notFound(w)
		return
	}
	// Read the flag before deleting so the correct audit event is recorded.
	note, err := s.crm.GetNote(r.Context(), noteID)
	if err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	if err := s.crm.DeleteNote(r.Context(), clientID, noteID); err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	event := "note_delete"
	if note.IsSecret {
		event = "secret_note_delete"
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: event, Entity: "note", EntityID: &noteID, ClientID: &clientID, IP: s.clientIP(r),
	})
	s.respondNotes(w, r, sess, clientID)
}

// handleNoteReveal returns a secret note's body for exactly this request, with
// Cache-Control: no-store, and audits the reveal. Non-secret notes are already
// visible, so the endpoint refuses them (F5.3/F5.4/F5.6).
func (s *Server) handleNoteReveal(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	noteID, ok := idParam(r, "nid")
	if !ok {
		s.notFound(w)
		return
	}
	note, err := s.crm.GetNote(r.Context(), noteID)
	if err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	if !note.IsSecret {
		s.notFound(w)
		return
	}
	clientID := note.ClientID
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "secret_note_reveal", Entity: "note", EntityID: &noteID, ClientID: &clientID, IP: s.clientIP(r),
	})
	// Both responses carry Cache-Control: no-store (render/renderFragment set
	// it) so the revealed body is never cached (F5.4).
	if isHTMX(r) {
		s.renderFragment(w, http.StatusOK, "note_reveal", pageData{
			CSRFToken: sess.CSRFToken,
			Note:      note,
		})
		return
	}
	s.render(w, http.StatusOK, "note_revealed.html", pageData{
		Title:     note.Title,
		CSRFToken: sess.CSRFToken,
		User:      sess.User,
		Authed:    true,
		Active:    "clients",
		Note:      note,
	})
}

// respondNotes returns the notes panel for an HTMX swap, or a redirect /
// full-page render otherwise, so note mutations work with and without JS (Q5).
func (s *Server) respondNotes(w http.ResponseWriter, r *http.Request, sess *auth.Session, clientID int64) {
	data, err := s.notePanelData(r, sess, clientID)
	if errors.Is(err, crm.ErrNotFound) {
		s.notFound(w)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	if isHTMX(r) {
		s.renderFragment(w, http.StatusOK, "notes_panel", data)
		return
	}
	http.Redirect(w, r, clientTabURL(clientID, "notes"), http.StatusSeeOther)
}
