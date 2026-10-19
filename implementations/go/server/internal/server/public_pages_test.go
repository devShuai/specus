package server

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

var publicPageEntries = []string{"/nat-detect", "/transfer", "/diagram", "/diagram-embed", "/download"}

func TestPublicPageEntriesPreserveURLAndPortalSecurity(t *testing.T) {
	_, server := newAPIServer(t)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	index, err := client.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	want, err := io.ReadAll(index.Body)
	index.Body.Close()
	if err != nil || index.StatusCode != http.StatusOK || !strings.Contains(string(want), "<html") {
		t.Fatalf("index: status=%d error=%v", index.StatusCode, err)
	}
	for _, entry := range publicPageEntries {
		for _, suffix := range []string{"", "/", "?roomId=fixture&view=file", "/?roomId=fixture&view=file"} {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				t.Run(method+entry+suffix, func(t *testing.T) {
					request, _ := http.NewRequest(method, server.URL+entry+suffix, nil)
					response, err := client.Do(request)
					if err != nil {
						t.Fatal(err)
					}
					defer response.Body.Close()
					body, err := io.ReadAll(response.Body)
					if err != nil || response.StatusCode != http.StatusOK {
						t.Fatalf("status=%d error=%v body=%q", response.StatusCode, err, body)
					}
					if response.Request.URL.RequestURI() != entry+suffix || response.Header.Get("Location") != "" {
						t.Fatal("public entry must not redirect or lose query state")
					}
					if method == http.MethodGet && string(body) != string(want) {
						t.Fatal("public entry did not serve the actual SPA index")
					}
					if method == http.MethodHead && len(body) != 0 {
						t.Fatal("HEAD returned a response body")
					}
					if !strings.HasPrefix(response.Header.Get("Content-Type"), "text/html") || response.Header.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(response.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
						t.Fatalf("portal headers missing: %v", response.Header)
					}
					if strings.Contains(response.Header.Get("Cache-Control"), "immutable") {
						t.Fatal("mutable HTML must not inherit immutable bundle caching")
					}
				})
			}
		}
	}
}

func TestPublicPageRoutingNeverMasksMissingResourcesOrProxyPaths(t *testing.T) {
	_, server := newAPIServer(t)
	for _, path := range []string{"/transfer/unknown", "/transfer.js", "/transfer-other", "/assets/missing.js", "/api/public/missing", "/api/admin/missing", "/http/missing-client/missing-route/", "/http-share/missing/"} {
		response, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode < 400 || strings.Contains(string(body), "<html") {
			t.Fatalf("%s unexpectedly became SPA HTML: %d", path, response.StatusCode)
		}
	}
}

func TestPublicPageEntriesRejectWriteMethods(t *testing.T) {
	_, server := newAPIServer(t)
	for _, entry := range publicPageEntries {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			request, _ := http.NewRequest(method, server.URL+entry, nil)
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusMethodNotAllowed {
				t.Fatalf("%s %s: got %d, want405", method, entry, response.StatusCode)
			}
		}
	}
}
