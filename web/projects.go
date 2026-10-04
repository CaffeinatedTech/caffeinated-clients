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

// --- global projects ----------------------------------------------------

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	opt := crm.ProjectOptions{
		Filter: strings.TrimSpace(r.URL.Query().Get("q")),
		Status: r.URL.Query().Get("status"),
		Sort:   r.URL.Query().Get("sort"),
	}
	if opt.Sort == "" {
		opt.Sort = "status"
	}
	data, err := s.projectsPageData(r, sess, opt, crm.ProjectInput{}, 0, "")
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, http.StatusOK, "projects.html", data)
}

func (s *Server) projectsPageData(r *http.Request, sess *auth.Session, opt crm.ProjectOptions, form crm.ProjectInput, clientID int64, errMsg string) (pageData, error) {
	projects, err := s.crm.ListProjects(r.Context(), opt)
	if err != nil {
		return pageData{}, err
	}
	clients, err := s.crm.ListClients(r.Context(), crm.ListOptions{})
	if err != nil {
		return pageData{}, err
	}
	return pageData{
		Title:        "Projects",
		Error:        errMsg,
		CSRFToken:    sess.CSRFToken,
		User:         sess.User,
		Authed:       true,
		Active:       "projects",
		Projects:     projects,
		Clients:      clients,
		Filter:       opt.Filter,
		Status:       opt.Status,
		Sort:         opt.Sort,
		ProjectForm:  projectFormView(form),
		FormClientID: clientID,
	}, nil
}

func (s *Server) handleProjectCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	clientID, _ := strconv.ParseInt(r.FormValue("client_id"), 10, 64)
	in := projectInputFromForm(r)
	fail := func(msg string) {
		data, err := s.projectsPageData(r, sess, crm.ProjectOptions{Sort: "status"}, in, clientID, msg)
		if err != nil {
			s.serverError(w, err)
			return
		}
		s.render(w, http.StatusBadRequest, "projects.html", data)
	}
	if clientID <= 0 {
		fail("Choose a client.")
		return
	}
	id, err := s.crm.CreateProject(r.Context(), clientID, in)
	if err != nil {
		if msg := projectErrorMessage(err); msg != "" {
			fail(msg)
			return
		}
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "project_create", Entity: "project", EntityID: &id, ClientID: &clientID, IP: s.clientIP(r),
	})
	http.Redirect(w, r, fmt.Sprintf("/projects/%d", id), http.StatusSeeOther)
}

// --- project detail -----------------------------------------------------

func (s *Server) handleProjectShow(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	id, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	p, err := s.crm.GetProject(r.Context(), id)
	if errors.Is(err, crm.ErrNotFound) {
		s.notFound(w)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	data, err := s.projectPageData(r, sess, p, projectFormFromProject(p), crm.JobInput{ProjectID: p.ID}, "")
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, http.StatusOK, "project.html", data)
}

func (s *Server) handleProjectUpdate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	id, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	p, err := s.crm.GetProject(r.Context(), id)
	if errors.Is(err, crm.ErrNotFound) {
		s.notFound(w)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	in := projectInputFromForm(r)
	if err := s.crm.UpdateProject(r.Context(), p.ClientID, id, in); err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		if msg := projectErrorMessage(err); msg != "" {
			data, derr := s.projectPageData(r, sess, p, in, crm.JobInput{ProjectID: p.ID}, msg)
			if derr != nil {
				s.serverError(w, derr)
				return
			}
			s.render(w, http.StatusBadRequest, "project.html", data)
			return
		}
		s.serverError(w, err)
		return
	}
	clientID := p.ClientID
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "project_update", Entity: "project", EntityID: &id, ClientID: &clientID, IP: s.clientIP(r),
	})
	http.Redirect(w, r, fmt.Sprintf("/projects/%d", id), http.StatusSeeOther)
}

func (s *Server) handleProjectDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	p, err := s.crm.GetProject(r.Context(), id)
	if errors.Is(err, crm.ErrNotFound) {
		s.notFound(w)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.crm.DeleteProject(r.Context(), p.ClientID, id); err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	clientID := p.ClientID
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "project_delete", Entity: "project", EntityID: &id, ClientID: &clientID, IP: s.clientIP(r),
	})
	http.Redirect(w, r, "/projects", http.StatusSeeOther)
}

// handleProjectJobCreate adds a job to the project from the project page
// (F7.3); the client and project are fixed by the URL.
func (s *Server) handleProjectJobCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	id, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	p, err := s.crm.GetProject(r.Context(), id)
	if errors.Is(err, crm.ErrNotFound) {
		s.notFound(w)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	in := jobInputFromForm(r)
	in.ProjectID = id
	jobID, err := s.crm.CreateJob(r.Context(), p.ClientID, in)
	if err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		if msg := jobErrorMessage(err); msg != "" {
			data, derr := s.projectPageData(r, sess, p, projectFormFromProject(p), in, msg)
			if derr != nil {
				s.serverError(w, derr)
				return
			}
			s.render(w, http.StatusBadRequest, "project.html", data)
			return
		}
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "job_create", Entity: "job", EntityID: &jobID, ClientID: &p.ClientID, IP: s.clientIP(r),
	})
	http.Redirect(w, r, fmt.Sprintf("/projects/%d", id), http.StatusSeeOther)
}

// --- client-page projects panel -----------------------------------------

func (s *Server) handleClientProjectCreate(w http.ResponseWriter, r *http.Request) {
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
	in := projectInputFromForm(r)
	id, err := s.crm.CreateProject(r.Context(), clientID, in)
	if err == nil {
		_ = s.svc.Audit(r.Context(), auth.AuditEntry{
			Event: "project_create", Entity: "project", EntityID: &id, ClientID: &clientID, IP: s.clientIP(r),
		})
		s.respondProjects(w, r, sess, clientID, crm.ProjectInput{}, nil)
		return
	}
	if errors.Is(err, crm.ErrNotFound) {
		s.notFound(w)
		return
	}
	s.respondProjects(w, r, sess, clientID, in, err)
}

func (s *Server) respondProjects(w http.ResponseWriter, r *http.Request, sess *auth.Session, clientID int64, form crm.ProjectInput, cause error) {
	errMsg := ""
	if cause != nil {
		errMsg = projectErrorMessage(cause)
		if errMsg == "" {
			s.serverError(w, cause)
			return
		}
	}
	data, err := s.projectPanelData(r, sess, clientID, form, errMsg)
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
		s.renderFragment(w, status, "projects_panel", data)
		return
	}
	if errMsg != "" {
		s.render(w, http.StatusBadRequest, "client.html", data)
		return
	}
	http.Redirect(w, r, clientTabURL(clientID, "projects"), http.StatusSeeOther)
}

func (s *Server) projectPanelData(r *http.Request, sess *auth.Session, clientID int64, form crm.ProjectInput, errMsg string) (pageData, error) {
	client, err := s.crm.GetClient(r.Context(), clientID)
	if err != nil {
		return pageData{}, err
	}
	data, err := s.clientPageData(r, sess, client, "projects", errMsg)
	if err != nil {
		return pageData{}, err
	}
	data.ProjectForm = projectFormView(form)
	return data, nil
}

// projectPageData builds the project detail view model. jobForm pre-fills the
// add-job form so a validation error preserves entered values (Q4).
func (s *Server) projectPageData(r *http.Request, sess *auth.Session, p crm.Project, projectForm crm.ProjectInput, jobForm crm.JobInput, errMsg string) (pageData, error) {
	jobs, err := s.crm.ListJobs(r.Context(), crm.JobOptions{ProjectID: p.ID, Status: "all"})
	if err != nil {
		return pageData{}, err
	}
	if jobForm.ProjectID == 0 {
		jobForm.ProjectID = p.ID
	}
	return pageData{
		Title:       p.Name,
		Error:       errMsg,
		CSRFToken:   sess.CSRFToken,
		User:        sess.User,
		Authed:      true,
		Active:      "projects",
		Project:     p,
		ProjectForm: projectFormView(projectForm),
		Jobs:        jobs,
		JobForm:     jobFormView(jobForm),
	}, nil
}

// --- input and view helpers ---------------------------------------------

func projectInputFromForm(r *http.Request) crm.ProjectInput {
	return crm.ProjectInput{
		Name:        r.FormValue("name"),
		Description: r.FormValue("description"),
		Status:      r.FormValue("status"),
		DueDate:     r.FormValue("due_date"),
	}
}

func projectFormView(in crm.ProjectInput) crm.ProjectInput {
	if strings.TrimSpace(in.Status) == "" {
		in.Status = "planning"
	}
	return in
}

func projectFormFromProject(p crm.Project) crm.ProjectInput {
	due := ""
	if !p.DueDate.IsZero() {
		due = p.DueDate.Format("2006-01-02")
	}
	return crm.ProjectInput{Name: p.Name, Description: p.Description, Status: p.Status, DueDate: due}
}

// projectErrorMessage maps a store error to an inline message, or "" when the
// error is not a user-fixable validation failure.
func projectErrorMessage(err error) string {
	switch {
	case errors.Is(err, crm.ErrNameRequired):
		return "A project name is required."
	case errors.Is(err, crm.ErrInvalidDate):
		return "Enter a valid due date (YYYY-MM-DD)."
	case errors.Is(err, crm.ErrInvalidInput):
		return "Check the project fields and try again."
	case errors.Is(err, crm.ErrNotFound):
		return "Choose a valid client."
	default:
		return ""
	}
}
