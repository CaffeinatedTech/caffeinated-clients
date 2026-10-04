package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/CaffeinatedTech/caffeinated-clients/internal/auth"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/crm"
)

// noteScope says where a note mutation was issued: a client page or a job page.
// A job note carries its job's client_id, so ownership checks and the audit
// client are identical; only the panel returned and the action URLs differ
// (F7.6).
type noteScope struct {
	clientID int64
	base     string // "/clients/5" or "/jobs/9"
	jobID    int64  // 0 for a client note
}

// resolveNoteScope reads the {id} path value as a client id, or as a job id
// when the matched route is job-scoped, and returns the owning client.
func (s *Server) resolveNoteScope(w http.ResponseWriter, r *http.Request) (noteScope, bool) {
	id, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return noteScope{}, false
	}
	if strings.Contains(r.Pattern, "/jobs/") {
		j, err := s.crm.GetJob(r.Context(), id)
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return noteScope{}, false
		}
		if err != nil {
			s.serverError(w, err)
			return noteScope{}, false
		}
		return noteScope{clientID: j.ClientID, base: fmt.Sprintf("/jobs/%d", id), jobID: id}, true
	}
	return noteScope{clientID: id, base: fmt.Sprintf("/clients/%d", id)}, true
}

func (s *Server) handleNoteCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	sc, ok := s.resolveNoteScope(w, r)
	if !ok {
		return
	}
	if _, err := s.crm.GetClient(r.Context(), sc.clientID); err != nil {
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
		JobID:    sc.jobID,
	}
	noteID, err := s.crm.CreateNote(r.Context(), sc.clientID, in)
	if err != nil {
		if errors.Is(err, crm.ErrNotFound) || errors.Is(err, crm.ErrInvalidInput) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	if in.IsSecret {
		// A secret note's creation is audited separately like its reveal (F5.6).
		_ = s.svc.Audit(r.Context(), auth.AuditEntry{
			Event: "secret_note_create", Entity: "note", EntityID: &noteID, ClientID: &sc.clientID, IP: s.clientIP(r),
		})
	} else {
		_ = s.svc.Audit(r.Context(), auth.AuditEntry{
			Event: "note_create", Entity: "note", EntityID: &noteID, ClientID: &sc.clientID, IP: s.clientIP(r),
		})
	}
	s.respondNotes(w, r, sess, sc)
}

func (s *Server) handleNoteUpdate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	sc, ok := s.resolveNoteScope(w, r)
	if !ok {
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
	if err := s.crm.UpdateNote(r.Context(), sc.clientID, noteID, in); err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "note_update", Entity: "note", EntityID: &noteID, ClientID: &sc.clientID, IP: s.clientIP(r),
	})
	s.respondNotes(w, r, sess, sc)
}

func (s *Server) handleNotePin(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	sc, ok := s.resolveNoteScope(w, r)
	if !ok {
		return
	}
	noteID, ok := idParam(r, "nid")
	if !ok {
		s.notFound(w)
		return
	}
	if err := s.crm.SetNotePinned(r.Context(), sc.clientID, noteID, r.FormValue("pinned") == "1"); err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "note_pin", Entity: "note", EntityID: &noteID, ClientID: &sc.clientID, IP: s.clientIP(r),
		Detail: map[string]any{"pinned": r.FormValue("pinned") == "1"},
	})
	s.respondNotes(w, r, sess, sc)
}

func (s *Server) handleNoteSecret(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	sc, ok := s.resolveNoteScope(w, r)
	if !ok {
		return
	}
	noteID, ok := idParam(r, "nid")
	if !ok {
		s.notFound(w)
		return
	}
	secret := r.FormValue("secret") == "1"
	if err := s.crm.SetNoteSecret(r.Context(), sc.clientID, noteID, secret); err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "secret_flag_toggle", Entity: "note", EntityID: &noteID, ClientID: &sc.clientID, IP: s.clientIP(r),
		Detail: map[string]any{"is_secret": secret},
	})
	s.respondNotes(w, r, sess, sc)
}

func (s *Server) handleNoteDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	sc, ok := s.resolveNoteScope(w, r)
	if !ok {
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
	if err := s.crm.DeleteNote(r.Context(), sc.clientID, noteID); err != nil {
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
		Event: event, Entity: "note", EntityID: &noteID, ClientID: &sc.clientID, IP: s.clientIP(r),
	})
	s.respondNotes(w, r, sess, sc)
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
	// The reveal fragment's inline editor must post back to the same scope the
	// note came from (F7.6).
	base := fmt.Sprintf("/clients/%d", note.ClientID)
	if note.JobID != 0 {
		base = fmt.Sprintf("/jobs/%d", note.JobID)
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "secret_note_reveal", Entity: "note", EntityID: &noteID, ClientID: &clientID, IP: s.clientIP(r),
	})
	// Both responses carry Cache-Control: no-store (render/renderFragment set
	// it) so the revealed body is never cached (F5.4).
	if isHTMX(r) {
		s.renderFragment(w, http.StatusOK, "note_reveal", pageData{
			CSRFToken: sess.CSRFToken,
			Note:      note,
			NotesBase: base,
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
		NotesBase: base,
	})
}

// respondNotes returns the notes panel for an HTMX swap, or a redirect /
// full-page render otherwise, so note mutations work with and without JS (Q5).
// It serves both client and job notes.
func (s *Server) respondNotes(w http.ResponseWriter, r *http.Request, sess *auth.Session, sc noteScope) {
	data, err := s.notePanelData(r, sess, sc)
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
	if sc.jobID != 0 {
		http.Redirect(w, r, fmt.Sprintf("/jobs/%d", sc.jobID), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, clientTabURL(sc.clientID, "notes"), http.StatusSeeOther)
}

// notePanelData builds the notes panel view model for either scope, so the same
// partial renders on the client page, the job page, and as an HTMX fragment.
func (s *Server) notePanelData(r *http.Request, sess *auth.Session, sc noteScope) (pageData, error) {
	if sc.jobID != 0 {
		j, err := s.crm.GetJob(r.Context(), sc.jobID)
		if err != nil {
			return pageData{}, err
		}
		notes, err := s.crm.ListJobNotes(r.Context(), sc.jobID)
		if err != nil {
			return pageData{}, err
		}
		return pageData{
			Title:     j.Title,
			CSRFToken: sess.CSRFToken,
			User:      sess.User,
			Authed:    true,
			Active:    "jobs",
			Job:       j,
			Notes:     notes,
			NotesBase: sc.base,
		}, nil
	}
	client, err := s.crm.GetClient(r.Context(), sc.clientID)
	if err != nil {
		return pageData{}, err
	}
	data, err := s.clientPageData(r, sess, client, "notes", "")
	if err != nil {
		return pageData{}, err
	}
	data.NotesBase = sc.base
	return data, nil
}
