// Package web is the HTTP layer: routing, middleware, handlers, and the
// embedded HTML templates. It serves the auth flow in Phase 2; the app shell,
// theming, and PWA land in Phase 3.
package web

import (
	"embed"
	"html/template"
)

//go:embed templates/*.html
var templatesFS embed.FS

// parseTemplates parses every embedded template file once. Templates are named
// by base filename (e.g. "login.html").
func parseTemplates() (*template.Template, error) {
	return template.ParseFS(templatesFS, "templates/*.html")
}
