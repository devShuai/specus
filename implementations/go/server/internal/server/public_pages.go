package server

import "net/http"

// Public tools use clean URLs in invitations and browser history. Only these
// document entrypoints may map to the SPA; missing APIs/assets are never a fallback.
func registerPublicPageEntries(mux *http.ServeMux, files http.Handler) {
	for _, page := range []string{"/nat-detect", "/transfer", "/diagram", "/diagram-embed", "/download"} {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != page && r.URL.Path != page+"/" {
				http.NotFound(w, r)
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			// Clone the server-side lookup only: do not redirect the browser or
			// mutate its document URL/query, which may carry invitation state.
			lookup := r.Clone(r.Context())
			lookupURL := *r.URL
			lookupURL.Path, lookupURL.RawPath = "/", ""
			lookup.URL = &lookupURL
			w.Header().Set("Cache-Control", "no-cache")
			files.ServeHTTP(w, lookup)
		})
		mux.Handle(page, handler)
		mux.Handle(page+"/", handler)
	}
}
