// Package web is the HTTP layer: routing, middleware, handlers, and the
// embedded HTML templates and static assets.
package web

import (
	"embed"
	"html/template"
	"io/fs"
	"path"
)

//go:embed templates/layout.html templates/partials/*.html templates/pages/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// BuildVersion identifies the running build and versions the static-asset and
// service-worker caches. Override at link time with
// -ldflags "-X github.com/CaffeinatedTech/caffeinated-clients/web.BuildVersion=<value>".
var BuildVersion = "dev"

// pageTemplates maps a page filename (e.g. "home.html") to a template set that
// has the layout and partials plus that page's "content" definition. Each page
// gets its own clone so the shared "content" name does not collide.
type pageTemplates map[string]*template.Template

func parseTemplates() (pageTemplates, error) {
	base, err := template.New("").ParseFS(templatesFS, "templates/layout.html", "templates/partials/*.html")
	if err != nil {
		return nil, err
	}
	names, err := fs.Glob(templatesFS, "templates/pages/*.html")
	if err != nil {
		return nil, err
	}
	out := make(pageTemplates, len(names))
	for _, p := range names {
		clone, err := base.Clone()
		if err != nil {
			return nil, err
		}
		if _, err := clone.ParseFS(templatesFS, p); err != nil {
			return nil, err
		}
		out[path.Base(p)] = clone
	}
	return out, nil
}

// staticSub returns the embedded static assets rooted at static/, so a request
// for /static/app.css maps to app.css.
func staticSub() (fs.FS, error) { return fs.Sub(staticFS, "static") }
