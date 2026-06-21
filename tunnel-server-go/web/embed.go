// Package web embeds the management SPA static assets (copied verbatim from the Java/C#
// server's static resources).
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var staticFS embed.FS

// StaticFS returns the embedded SPA file system rooted at the static directory.
func StaticFS() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic("web: embedded static assets missing: " + err.Error())
	}
	return sub
}
