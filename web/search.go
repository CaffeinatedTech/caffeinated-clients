package web

import (
	"net/http"
	"strings"

	"github.com/CaffeinatedTech/caffeinated-clients/internal/crm"
)

// handleSearch serves search results as an HTMX fragment for the live search
// box, or as a full page when visited directly (F8.4, Q5).
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	results := crm.Results{Query: query}
	if query != "" {
		got, err := s.crm.Search(r.Context(), query, 20)
		if err != nil {
			s.serverError(w, err)
			return
		}
		results = got
	}
	data := pageData{
		Title:     "Search",
		CSRFToken: sess.CSRFToken,
		User:      sess.User,
		Authed:    true,
		Results:   results,
		Query:     query,
	}
	if isHTMX(r) {
		s.renderFragment(w, http.StatusOK, "search_results", data)
		return
	}
	s.render(w, http.StatusOK, "search.html", data)
}
