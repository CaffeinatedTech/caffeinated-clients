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

// --- global jobs --------------------------------------------------------

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	q := r.URL.Query()
	opt := crm.JobOptions{
		Status:        q.Get("status"),
		ClientFilter:  strings.TrimSpace(q.Get("client")),
		ProjectFilter: strings.TrimSpace(q.Get("project")),
		Due:           q.Get("due"),
		Sort:          q.Get("sort"),
	}
	data, err := s.jobsPageData(r, sess, opt, crm.JobInput{}, 0, "")
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, http.StatusOK, "jobs.html", data)
}

func (s *Server) jobsPageData(r *http.Request, sess *auth.Session, opt crm.JobOptions, form crm.JobInput, clientID int64, errMsg string) (pageData, error) {
	jobs, err := s.crm.ListJobs(r.Context(), opt)
	if err != nil {
		return pageData{}, err
	}
	clients, err := s.crm.ListClients(r.Context(), crm.ListOptions{})
	if err != nil {
		return pageData{}, err
	}
	projects, err := s.crm.ListProjects(r.Context(), crm.ProjectOptions{Status: "all"})
	if err != nil {
		return pageData{}, err
	}
	return pageData{
		Title:         "Jobs",
		Error:         errMsg,
		CSRFToken:     sess.CSRFToken,
		User:          sess.User,
		Authed:        true,
		Active:        "jobs",
		Jobs:          jobs,
		Clients:       clients,
		Projects:      projects,
		Status:        opt.Status,
		ClientFilter:  opt.ClientFilter,
		ProjectFilter: opt.ProjectFilter,
		Due:           opt.Due,
		Sort:          opt.Sort,
		JobForm:       jobFormView(form),
		FormClientID:  clientID,
	}, nil
}

func (s *Server) handleJobCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	clientID, _ := strconv.ParseInt(r.FormValue("client_id"), 10, 64)
	in := jobInputFromForm(r)
	fail := func(msg string) {
		data, err := s.jobsPageData(r, sess, crm.JobOptions{}, in, clientID, msg)
		if err != nil {
			s.serverError(w, err)
			return
		}
		s.render(w, http.StatusBadRequest, "jobs.html", data)
	}
	if clientID <= 0 {
		fail("Choose a client.")
		return
	}
	id, err := s.crm.CreateJob(r.Context(), clientID, in)
	if err != nil {
		if msg := jobErrorMessage(err); msg != "" {
			fail(msg)
			return
		}
		s.serverError(w, err)
		return
	}
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "job_create", Entity: "job", EntityID: &id, ClientID: &clientID, IP: s.clientIP(r),
	})
	http.Redirect(w, r, fmt.Sprintf("/jobs/%d", id), http.StatusSeeOther)
}

// --- job detail ---------------------------------------------------------

func (s *Server) handleJobShow(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	id, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	j, err := s.crm.GetJob(r.Context(), id)
	if errors.Is(err, crm.ErrNotFound) {
		s.notFound(w)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	data, err := s.jobPageData(r, sess, j, jobFormFromJob(j), "")
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, http.StatusOK, "job.html", data)
}

func (s *Server) handleJobUpdate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	id, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	j, err := s.crm.GetJob(r.Context(), id)
	if errors.Is(err, crm.ErrNotFound) {
		s.notFound(w)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	in := jobInputFromForm(r)
	if err := s.crm.UpdateJob(r.Context(), j.ClientID, id, in); err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		if msg := jobErrorMessage(err); msg != "" {
			data, derr := s.jobPageData(r, sess, j, in, msg)
			if derr != nil {
				s.serverError(w, derr)
				return
			}
			s.render(w, http.StatusBadRequest, "job.html", data)
			return
		}
		s.serverError(w, err)
		return
	}
	clientID := j.ClientID
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "job_update", Entity: "job", EntityID: &id, ClientID: &clientID, IP: s.clientIP(r),
	})
	http.Redirect(w, r, fmt.Sprintf("/jobs/%d", id), http.StatusSeeOther)
}

func (s *Server) handleJobDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r, "id")
	if !ok {
		s.notFound(w)
		return
	}
	j, err := s.crm.GetJob(r.Context(), id)
	if errors.Is(err, crm.ErrNotFound) {
		s.notFound(w)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.crm.DeleteJob(r.Context(), j.ClientID, id); err != nil {
		if errors.Is(err, crm.ErrNotFound) {
			s.notFound(w)
			return
		}
		s.serverError(w, err)
		return
	}
	clientID := j.ClientID
	_ = s.svc.Audit(r.Context(), auth.AuditEntry{
		Event: "job_delete", Entity: "job", EntityID: &id, ClientID: &clientID, IP: s.clientIP(r),
	})
	http.Redirect(w, r, "/jobs", http.StatusSeeOther)
}

// --- client-page jobs panel ---------------------------------------------

func (s *Server) handleClientJobCreate(w http.ResponseWriter, r *http.Request) {
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
	in := jobInputFromForm(r)
	id, err := s.crm.CreateJob(r.Context(), clientID, in)
	if err == nil {
		_ = s.svc.Audit(r.Context(), auth.AuditEntry{
			Event: "job_create", Entity: "job", EntityID: &id, ClientID: &clientID, IP: s.clientIP(r),
		})
		s.respondJobs(w, r, sess, clientID, crm.JobInput{}, nil)
		return
	}
	if errors.Is(err, crm.ErrNotFound) {
		s.notFound(w)
		return
	}
	s.respondJobs(w, r, sess, clientID, in, err)
}

func (s *Server) respondJobs(w http.ResponseWriter, r *http.Request, sess *auth.Session, clientID int64, form crm.JobInput, cause error) {
	errMsg := ""
	if cause != nil {
		errMsg = jobErrorMessage(cause)
		if errMsg == "" {
			s.serverError(w, cause)
			return
		}
	}
	data, err := s.jobPanelData(r, sess, clientID, form, errMsg)
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
		s.renderFragment(w, status, "jobs_panel", data)
		return
	}
	if errMsg != "" {
		s.render(w, http.StatusBadRequest, "client.html", data)
		return
	}
	http.Redirect(w, r, clientTabURL(clientID, "jobs"), http.StatusSeeOther)
}

func (s *Server) jobPanelData(r *http.Request, sess *auth.Session, clientID int64, form crm.JobInput, errMsg string) (pageData, error) {
	client, err := s.crm.GetClient(r.Context(), clientID)
	if err != nil {
		return pageData{}, err
	}
	data, err := s.clientPageData(r, sess, client, "jobs", errMsg)
	if err != nil {
		return pageData{}, err
	}
	data.JobForm = jobFormView(form)
	return data, nil
}

// jobPageData builds the job detail view model with the client's projects for
// the project picker.
func (s *Server) jobPageData(r *http.Request, sess *auth.Session, j crm.Job, form crm.JobInput, errMsg string) (pageData, error) {
	projects, err := s.crm.ListProjects(r.Context(), crm.ProjectOptions{ClientID: j.ClientID, Status: "all"})
	if err != nil {
		return pageData{}, err
	}
	return pageData{
		Title:     j.Title,
		Error:     errMsg,
		CSRFToken: sess.CSRFToken,
		User:      sess.User,
		Authed:    true,
		Active:    "jobs",
		Job:       j,
		Projects:  projects,
		JobForm:   jobFormView(form),
	}, nil
}

// --- input and view helpers ---------------------------------------------

func jobInputFromForm(r *http.Request) crm.JobInput {
	projectID, _ := strconv.ParseInt(r.FormValue("project_id"), 10, 64)
	return crm.JobInput{
		Title:       r.FormValue("title"),
		Description: r.FormValue("description"),
		Status:      r.FormValue("status"),
		Priority:    r.FormValue("priority"),
		DueDate:     r.FormValue("due_date"),
		ProjectID:   projectID,
	}
}

func jobFormView(in crm.JobInput) crm.JobInput {
	if strings.TrimSpace(in.Status) == "" {
		in.Status = "open"
	}
	if strings.TrimSpace(in.Priority) == "" {
		in.Priority = "normal"
	}
	return in
}

func jobFormFromJob(j crm.Job) crm.JobInput {
	due := ""
	if !j.DueDate.IsZero() {
		due = j.DueDate.Format("2006-01-02")
	}
	return crm.JobInput{
		Title:       j.Title,
		Description: j.Description,
		Status:      j.Status,
		Priority:    j.Priority,
		DueDate:     due,
		ProjectID:   j.ProjectID,
	}
}

// jobErrorMessage maps a store error to an inline message, or "" when the
// error is not a user-fixable validation failure.
func jobErrorMessage(err error) string {
	switch {
	case errors.Is(err, crm.ErrTitleRequired):
		return "A job title is required."
	case errors.Is(err, crm.ErrInvalidDate):
		return "Enter a valid due date (YYYY-MM-DD)."
	case errors.Is(err, crm.ErrInvalidInput):
		return "Check the job fields; a project must belong to the same client."
	case errors.Is(err, crm.ErrNotFound):
		return "Choose a valid client."
	default:
		return ""
	}
}
