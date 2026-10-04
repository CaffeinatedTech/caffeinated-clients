package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/CaffeinatedTech/caffeinated-clients/internal/auth"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/crm"
)

var clientTabs = map[string]bool{
	"overview": true, "contacts": true, "notes": true,
	"projects": true, "jobs": true, "activity": true,
}

// --- client list and creation -------------------------------------------

func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	opt := crm.ListOptions{
		Filter: strings.TrimSpace(r.URL.Query().Get("q")),
		Status: r.URL.Query().Get("status"),
		Sort:   r.URL.Query().Get("sort"),
	}
	clients, err := s.crm.ListClients(r.Context(), opt)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if opt.Sort == "" {
		opt.Sort = "name"
	}
	s.render(w, http.StatusOK, "clients.html", pageData{
		Title:     "Clients",
		CSRFToken: sess.CSRFToken,
		User:      sess.User,
		Authed:    true,
		Active:    "clients",
		Clients:   clients,
		Filter:    opt.Filter,
		Status:    opt.Status,
		Sort:      opt.Sort,
	})
}

func (s *Server) handleClientNew(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	s.render(w, http.StatusOK, "client_new.html", pageData{
		Title:     "New client",
		CSRFToken: sess.CSRFToken,
		User:      sess.User,
		Authed:    true,
		Active:    "clients",
		Client:    crm.Client{Status: "active"},
	})
}

func (s *Server) handleClientCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	in := clientInputFromForm(r)
	id, err := s.crm.CreateClient(r.Context(), in)
	if errors.Is(err, crm.ErrNameRequired) {
		s.render(w, http.StatusBadRequest, "client_new.html", pageData{
			Title:     "New client",
			Error:     "A client name is required.",
			CSRFToken: sess.CSRFToken,
			User:      sess.User,
			Authed:    true,
			Active:    "clients",
			Client:    clientFromInput(in),
		})
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "client_create", Entity: "client", EntityID: &id, ClientID: &id,
		IP: s.clientIP(r), Detail: map[string]any{"name": strings.TrimSpace(in.Name)},
	})
	http.Redirect(w, r, fmt.Sprintf("/clients/%d", id), http.StatusSeeOther)
}

// --- client detail ------------------------------------------------------

func (s *Server) handleClientShow(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	id, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	client, err := s.crm.GetClient(r.Context(), id)
	if errors.Is(err, crm.ErrNotFound) {
		s.notFound(w)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	tab := r.URL.Query().Get("tab")
	if !clientTabs[tab] {
		tab = "overview"
	}
	data, err := s.clientPageData(r, sess, client, tab, "")
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, http.StatusOK, "client.html", data)
}

func (s *Server) handleClientUpdate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	id, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	in := clientInputFromForm(r)
	tab := r.URL.Query().Get("tab")
	if !clientTabs[tab] {
		tab = "overview"
	}
	if err := s.crm.UpdateClient(r.Context(), id, in); err != nil {
		switch {
		case errors.Is(err, crm.ErrNotFound):
			s.notFound(w)
		case errors.Is(err, crm.ErrNameRequired):
			data, derr := s.clientPageData(r, sess, clientFromInput(in), tab, "A client name is required.")
			if derr != nil {
				s.serverError(w, derr)
				return
			}
			s.render(w, http.StatusBadRequest, "client.html", data)
		default:
			s.serverError(w, err)
		}
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "client_update", Entity: "client", EntityID: &id, ClientID: &id, IP: s.clientIP(r),
	})
	http.Redirect(w, r, fmt.Sprintf("/clients/%d", id), http.StatusSeeOther)
}

func (s *Server) handleClientArchive(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	archived := r.FormValue("archived") == "1"
	if err := s.crm.SetArchived(r.Context(), id, archived); err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	event := "client_restore"
	if archived {
		event = "client_archive"
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: event, Entity: "client", EntityID: &id, ClientID: &id, IP: s.clientIP(r),
	})
	http.Redirect(w, r, fmt.Sprintf("/clients/%d", id), http.StatusSeeOther)
}

func (s *Server) handleClientDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	counts, err := s.crm.ClientCascadeCounts(r.Context(), id)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.crm.DeleteClient(r.Context(), id); err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "client_delete", Entity: "client", EntityID: &id, ClientID: &id, IP: s.clientIP(r),
		Detail: map[string]any{
			"contacts": counts.Contacts, "notes": counts.Notes,
			"projects": counts.Projects, "jobs": counts.Jobs,
		},
	})
	http.Redirect(w, r, "/clients", http.StatusSeeOther)
}

// --- contacts -----------------------------------------------------------

func (s *Server) handleContactCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	clientID, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	form := contactInputFromForm(r)
	_, err := s.crm.CreateContact(r.Context(), clientID, form)
	if errors.Is(err, crm.ErrNameRequired) {
		s.respondContacts(w, r, sess, clientID, form, 0, "A contact name is required.")
		return
	}
	if err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	s.respondContacts(w, r, sess, clientID, crm.ContactInput{}, 0, "")
}

func (s *Server) handleContactUpdate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	clientID, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	contactID, ok := idParam(r, "cid")
	if !ok {
		s.notFound(w)
		return
	}
	form := contactInputFromForm(r)
	err := s.crm.UpdateContact(r.Context(), clientID, contactID, form)
	if errors.Is(err, crm.ErrNameRequired) {
		s.respondContacts(w, r, sess, clientID, form, contactID, "A contact name is required.")
		return
	}
	if err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	s.respondContacts(w, r, sess, clientID, crm.ContactInput{}, 0, "")
}

func (s *Server) handleContactPrimary(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	clientID, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	contactID, ok := idParam(r, "cid")
	if !ok {
		s.notFound(w)
		return
	}
	if err := s.crm.SetPrimaryContact(r.Context(), clientID, contactID); err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	s.respondContacts(w, r, sess, clientID, crm.ContactInput{}, 0, "")
}

func (s *Server) handleContactDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	clientID, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	contactID, ok := idParam(r, "cid")
	if !ok {
		s.notFound(w)
		return
	}
	if err := s.crm.DeleteContact(r.Context(), clientID, contactID); err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	s.respondContacts(w, r, sess, clientID, crm.ContactInput{}, 0, "")
}

// respondContacts returns the contacts panel for an HTMX swap, or a redirect /
// full client page otherwise, so the mutation works with and without JS.
func (s *Server) respondContacts(w http.ResponseWriter, r *http.Request, sess *auth.Session, clientID int64, form crm.ContactInput, editID int64, errMsg string) {
	data, err := s.contactPanelData(r, sess, clientID, form, editID, errMsg)
	if errors.Is(err, crm.ErrNotFound) {
		s.notFound(w)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	if isHTMX(r) {
		status := http.StatusOK
		if errMsg != "" {
			status = http.StatusBadRequest
		}
		s.renderFragment(w, status, "contacts_panel", data)
		return
	}
	if errMsg != "" {
		s.render(w, http.StatusBadRequest, "client.html", data)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/clients/%d?tab=contacts", clientID), http.StatusSeeOther)
}

// --- view helpers -------------------------------------------------------

func (s *Server) clientPageData(r *http.Request, sess *auth.Session, client crm.Client, tab, errMsg string) (pageData, error) {
	contacts, err := s.crm.ListContacts(r.Context(), client.ID)
	if err != nil {
		return pageData{}, err
	}
	counts, err := s.crm.ClientCascadeCounts(r.Context(), client.ID)
	if err != nil {
		return pageData{}, err
	}
	data := pageData{
		Title:     client.Name,
		Error:     errMsg,
		CSRFToken: sess.CSRFToken,
		User:      sess.User,
		Authed:    true,
		Active:    "clients",
		Client:    client,
		Contacts:  contacts,
		Counts:    counts,
		Tab:       tab,
		NotesBase: fmt.Sprintf("/clients/%d", client.ID),
	}
	for i := range contacts {
		if contacts[i].IsPrimary {
			data.PrimaryContact = &contacts[i]
			break
		}
	}
	switch tab {
	case "notes":
		notes, err := s.crm.ListNotes(r.Context(), client.ID)
		if err != nil {
			return pageData{}, err
		}
		data.Notes = notes
	case "projects":
		projects, err := s.crm.ListProjects(r.Context(), crm.ProjectOptions{ClientID: client.ID, Status: "all"})
		if err != nil {
			return pageData{}, err
		}
		data.Projects = projects
		data.ProjectForm = projectFormView(crm.ProjectInput{})
	case "jobs":
		jobs, err := s.crm.ListJobs(r.Context(), crm.JobOptions{ClientID: client.ID, Status: "all"})
		if err != nil {
			return pageData{}, err
		}
		projects, err := s.crm.ListProjects(r.Context(), crm.ProjectOptions{ClientID: client.ID, Status: "all"})
		if err != nil {
			return pageData{}, err
		}
		data.Jobs = jobs
		data.Projects = projects
		data.JobForm = jobFormView(crm.JobInput{})
	case "activity":
		audit, err := s.svc.ListClientAudit(r.Context(), client.ID, 100)
		if err != nil {
			return pageData{}, err
		}
		data.Audit = audit
	}
	return data, nil
}

func clientTabURL(clientID int64, tab string) string {
	return fmt.Sprintf("/clients/%d?tab=%s", clientID, tab)
}

func (s *Server) contactPanelData(r *http.Request, sess *auth.Session, clientID int64, form crm.ContactInput, editID int64, errMsg string) (pageData, error) {
	client, err := s.crm.GetClient(r.Context(), clientID)
	if err != nil {
		return pageData{}, err
	}
	data, err := s.clientPageData(r, sess, client, "contacts", errMsg)
	if err != nil {
		return pageData{}, err
	}
	data.ContactForm = form
	data.ContactFormID = editID
	return data, nil
}

func clientInputFromForm(r *http.Request) crm.ClientInput {
	return crm.ClientInput{
		Name:    r.FormValue("name"),
		Status:  r.FormValue("status"),
		Website: r.FormValue("website"),
		Address: r.FormValue("address"),
		Phone:   r.FormValue("phone"),
		Summary: r.FormValue("summary"),
		Tags:    r.FormValue("tags"),
	}
}

func clientFromInput(in crm.ClientInput) crm.Client {
	status := strings.TrimSpace(in.Status)
	if status == "" {
		status = "active"
	}
	return crm.Client{
		Name:    strings.TrimSpace(in.Name),
		Status:  status,
		Website: strings.TrimSpace(in.Website),
		Address: strings.TrimSpace(in.Address),
		Phone:   strings.TrimSpace(in.Phone),
		Summary: in.Summary,
		Tags:    strings.TrimSpace(in.Tags),
	}
}

func contactInputFromForm(r *http.Request) crm.ContactInput {
	return crm.ContactInput{
		Name:      r.FormValue("name"),
		Role:      r.FormValue("role"),
		Phone:     r.FormValue("phone"),
		Email:     r.FormValue("email"),
		Notes:     r.FormValue("notes"),
		IsPrimary: r.FormValue("is_primary") != "",
	}
}

func idParam(r *http.Request, name string) (int64, bool) {
	v, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

func isHTMX(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

func (s *Server) notFound(w http.ResponseWriter) {
	http.Error(w, "not found", http.StatusNotFound)
}
