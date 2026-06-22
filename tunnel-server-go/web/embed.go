// Package web embeds the management SPA static assets.
package web

import (
	"embed"
	"io/fs"
)

//go:generate npm --prefix ../../tunnel-server-web run deploy:go

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
