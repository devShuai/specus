package directhttp

import (
	"strings"
	"testing"
)

func TestResponseRewriterRewritesHTMLPaths(t *testing.T) {
	rewrite := newResponseRewriter(1024 * 1024)
	body := []byte(`<html><head></head><body><img src="/img/logo.png"><a href='//cdn.example/a'>cdn</a><source srcset="/a.png 1x, /b.png 2x"></body></html>`)
	rewritten, ok := rewrite.rewrite(body, "Demo client", "web", []string{"Content-Type:text/html;charset=UTF-8"})
	if !ok {
		t.Fatal("expected rewrite")
	}
	text := string(rewritten)
	if !strings.Contains(text, `src="/http/Demo%20client/web/img/logo.png"`) {
		t.Fatalf("img src was not rewritten: %s", text)
	}
	if !strings.Contains(text, `href='//cdn.example/a'`) {
		t.Fatalf("protocol-relative URL should not be rewritten: %s", text)
	}
	if !strings.Contains(text, `/http/Demo%20client/web/a.png 1x`) ||
		!strings.Contains(text, `/http/Demo%20client/web/b.png 2x`) {
		t.Fatalf("srcset was not rewritten: %s", text)
	}
	if !strings.Contains(text, "<script>(function(){try{") {
		t.Fatalf("runtime polyfill missing: %s", text)
	}
	for _, expected := range []string{
		"wrapHistory('pushState')",
		"wrapHistory('replaceState')",
		"window.EventSource=function",
		"window.WebSocket=function",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("runtime polyfill missing %q: %s", expected, text)
		}
	}
}

func TestResponseRewriterRewritesCSSPaths(t *testing.T) {
	rewrite := newResponseRewriter(1024 * 1024)
	body := []byte(`@import "/theme.css"; .logo{background:url('/img/logo.png')}`)
	rewritten, ok := rewrite.rewrite(body, "client", "assets", []string{"Content-Type:text/css"})
	if !ok {
		t.Fatal("expected rewrite")
	}
	text := string(rewritten)
	if !strings.Contains(text, `@import "/http/client/assets/theme.css"`) ||
		!strings.Contains(text, `url('/http/client/assets/img/logo.png')`) {
		t.Fatalf("css was not rewritten: %s", text)
	}
}
