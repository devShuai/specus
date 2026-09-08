package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func uiFixture(t *testing.T) (*localUI, *httptest.Server, string) {
	t.Helper()
	// The real core must never load the developer's machine identity or peer key.
	identity := t.TempDir()
	t.Setenv("HOME", identity)
	t.Setenv("USERPROFILE", identity)
	t.Setenv("SPECUS_CLI_STATE_DIR", filepath.Join(t.TempDir(), "private-state"))
	path := filepath.Join(t.TempDir(), "client with spaces.jsonc")
	u := &localUI{ctx: context.Background(), path: path, sessions: map[string]time.Time{}, requests: make(chan struct{}, 16), runtime: &uiRuntime{path: path, loginTimeout: 1}}
	s := httptest.NewServer(u)
	u.origin = s.URL
	t.Cleanup(func() { _ = u.runtime.stop(); s.Close() })
	return u, s, path
}
func uiRequest(t *testing.T, s *httptest.Server, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	encoded, _ := json.Marshal(body)
	r, err := http.NewRequest(method, s.URL+path, strings.NewReader(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Origin", s.URL)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Specus-UI", "1")
	r.Header.Set("Authorization", "Bearer "+token)
	response, err := s.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("sensitive response can be cached")
	}
	var data map[string]any
	if err = json.NewDecoder(response.Body).Decode(&data); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, data
}
func uiSession(t *testing.T, u *localUI, s *httptest.Server) string {
	t.Helper()
	code, data := uiRequest(t, s, "POST", "/api/session", "", map[string]string{"code": u.newCode()})
	if code != 200 {
		t.Fatal(code, data)
	}
	return data["token"].(string)
}

func TestUIArguments(t *testing.T) {
	o, err := parseCLI([]string{"ui", "--config", "x y.jsonc", "--no-open", "--port", "0"})
	if err != nil || !o.noOpen || o.command != "ui" {
		t.Fatal(o, err)
	}
	for _, args := range [][]string{{"--no-open"}, {"run", "--port=0"}, {"ui", "--port=-1"}, {"ui", "--port=65536"}, {"ui", "--json"}, {"ui", "--auto-update"}, {"ui", "--probe"}} {
		if _, err := parseCLI(args); err == nil {
			t.Fatal("accepted", args)
		}
	}
}
func TestUIAuthenticationAndCrossSiteProtection(t *testing.T) {
	u, s, _ := uiFixture(t)
	if code, _ := uiRequest(t, s, "GET", "/api/config", "", nil); code != 401 {
		t.Fatal(code)
	}
	code := u.newCode()
	status, data := uiRequest(t, s, "POST", "/api/session", "", map[string]string{"code": code})
	if status != 200 {
		t.Fatal(status, data)
	}
	token := data["token"].(string)
	if status, _ = uiRequest(t, s, "POST", "/api/session", "", map[string]string{"code": code}); status != 401 {
		t.Fatal("bootstrap replay accepted")
	}
	for _, test := range []struct {
		path, method, origin, host, content string
		expected                            int
	}{
		{"/api/config", "GET", "https://evil.invalid", "", "", 403},
		{"/api/config", "GET", "", "attacker.invalid", "", 403},
		{"/api/config/save", "POST", "", "", "application/json", 403},
		{"/api/config/save", "POST", s.URL, "", "text/plain", 415},
		{"/api/connection", "GET", s.URL, "", "", 405},
		{"/api/config?token=oops", "GET", s.URL, "", "", 400},
		{"/../../client.jsonc", "GET", s.URL, "", "", 404},
		{"/api/config", "OPTIONS", s.URL, "", "", 405},
	} {
		r, _ := http.NewRequest(test.method, s.URL+test.path, strings.NewReader("{}"))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Origin", test.origin)
		r.Header.Set("X-Specus-UI", "1")
		r.Header.Set("Content-Type", test.content)
		if test.host != "" {
			r.Host = test.host
		}
		response, err := s.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != test.expected {
			t.Fatalf("%+v got %d", test, response.StatusCode)
		}
		if response.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("CORS enabled")
		}
	}
	u.authMu.Lock()
	u.sessions[token] = time.Now().Add(-time.Second)
	u.authMu.Unlock()
	if status, _ := uiRequest(t, s, "GET", "/api/config", token, nil); status != 401 {
		t.Fatal("expired session accepted")
	}
}
func TestUIJSONCPreservationAndConflicts(t *testing.T) {
	u, s, path := uiFixture(t)
	token := uiSession(t, u, s)
	original := `// { preserved header
{
  "serverBaseUrl": "http://127.0.0.1:1", // stay
  "apiKey": "PRIVATE-KEY",
  "secret": "env:SPECUS_UI_FIXTURE_SECRET",
  "unknown": {"braces": "} [", "array": [1, /* keep */ 2,],},
}`
	t.Setenv("SPECUS_UI_FIXTURE_SECRET", "DO-NOT-RETURN")
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	status, view := uiRequest(t, s, "GET", "/api/config", token, nil)
	encoded, _ := json.Marshal(view)
	if status != 200 || strings.Contains(string(encoded), "PRIVATE-KEY") || strings.Contains(string(encoded), "SPECUS_UI_FIXTURE_SECRET") || strings.Contains(string(encoded), "DO-NOT-RETURN") {
		t.Fatal(status, string(encoded))
	}
	edit := uiConfigEdit{Revision: view["revision"].(string), Changes: map[string]string{"serverBaseUrl": "http://127.0.0.1:2", "secret": "", "peerMeshDevice": "noop"}}
	if status, data := uiRequest(t, s, "POST", "/api/config/validate", token, edit); status != 200 {
		t.Fatal(status, data)
	}
	unchanged, _ := os.ReadFile(path)
	if string(unchanged) != original {
		t.Fatal("validation wrote configuration")
	}
	if status, data := uiRequest(t, s, "POST", "/api/config/save", token, edit); status != 200 {
		t.Fatal(status, data)
	}
	saved, _ := os.ReadFile(path)
	for _, expected := range []string{"// { preserved header", "// stay", `"secret": "env:SPECUS_UI_FIXTURE_SECRET"`, `"unknown": {"braces": "} [", "array": [1, /* keep */ 2,],}`, `http://127.0.0.1:2`} {
		if !strings.Contains(string(saved), expected) {
			t.Fatal("lost content", expected)
		}
	}
	if err := checkPrivate(path, false); err != nil {
		t.Fatal("saved config is not private", err)
	}
	if status, _ := uiRequest(t, s, "POST", "/api/config/save", token, edit); status != 409 {
		t.Fatal("stale overwrite accepted")
	}
	current, _ := os.ReadFile(path)
	if string(current) != string(saved) {
		t.Fatal("conflict changed config")
	}
}
func TestUIConfigInvalidAndPathBoundaries(t *testing.T) {
	for _, input := range []string{`{"secret":"a","secret":"b"}`, `{"secret":"a", "\u0073ecret":"b"}`, `{"secret":"a", "Secret":"b"}`, `{/* unterminated`, `{"a": [}`, `{} trailing`} {
		_, err := uiConfigSpans([]byte(input))
		if err == nil {
			t.Fatal("invalid document", input)
		}
	}
	_, _, path := uiFixture(t)
	if _, err := uiPatchConfig([]byte(`{}`), map[string]string{"path": "/etc/passwd"}); err == nil {
		t.Fatal("accepted arbitrary field")
	}
	if _, err := uiPatchConfig([]byte(`{}`), map[string]string{"serverBaseUrl": "http://user:pass@localhost"}); err == nil {
		t.Fatal("accepted URL credentials")
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := uiReadConfig(path); err == nil {
		t.Fatal("accepted directory")
	}
	link := filepath.Join(filepath.Dir(path), "link.jsonc")
	if os.Symlink(path, link) == nil {
		if _, _, err := uiReadConfig(link); err == nil {
			t.Fatal("accepted symlink")
		}
	}
}
func TestUIConnectionUsesRealCoreAndDoesNotAutoLogin(t *testing.T) {
	u, s, path := uiFixture(t)
	token := uiSession(t, u, s)
	var requests atomic.Int32
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(403)
		_, _ = io.WriteString(w, "BODY-SECRET")
	}))
	defer auth.Close()
	_, data := uiRequest(t, s, "GET", "/api/config", token, nil)
	edit := uiConfigEdit{Revision: data["revision"].(string), Changes: map[string]string{"serverBaseUrl": auth.URL, "apiKey": "test", "secret": "PRIVATE"}}
	if code, data := uiRequest(t, s, "POST", "/api/config/save", token, edit); code != 200 {
		t.Fatal(code, data)
	}
	for i := 0; i < 2; i++ {
		uiRequest(t, s, "GET", "/api/status", token, nil)
	}
	if requests.Load() != 0 {
		t.Fatal("page read caused authentication")
	}
	_, revision, _ := uiReadConfig(path)
	if code, data := uiRequest(t, s, "POST", "/api/connection", token, map[string]string{"action": "start", "revision": revision}); code != 200 {
		t.Fatal(code, data)
	}
	deadline := time.Now().Add(8 * time.Second)
	for u.runtime.snapshot()["processRunning"] == true && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	snapshot := u.runtime.snapshot()
	raw, _ := json.Marshal(snapshot)
	if requests.Load() != 1 || snapshot["processRunning"] != false || strings.Contains(string(raw), "BODY-SECRET") || strings.Contains(string(raw), "PRIVATE") {
		t.Fatal(requests.Load(), string(raw))
	}
	if status, _ := uiRequest(t, s, "GET", "/api/config", token, nil); status != 200 {
		t.Fatal("management died with tunnel")
	}
}
func TestUIExclusiveManagerLock(t *testing.T) {
	_, _, path := uiFixture(t)
	release, err := uiAcquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, err := uiAcquireLock(path); err == nil {
		duplicate()
		t.Fatal("duplicate manager accepted")
	}
	release()
	release, err = uiAcquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestUIStopCancelsInflightLoginAndRejectsDuplicateStart(t *testing.T) {
	u, s, path := uiFixture(t)
	token := uiSession(t, u, s)
	entered, release := make(chan struct{}), make(chan struct{})
	var requests atomic.Int32
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer auth.Close()
	defer close(release)
	config, _ := json.Marshal(map[string]string{"serverBaseUrl": auth.URL, "apiKey": "test", "secret": "test"})
	if err := os.WriteFile(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	_, revision, _ := uiReadConfig(path)
	u.runtime.loginTimeout = 30
	if code, data := uiRequest(t, s, "POST", "/api/connection", token, map[string]string{"action": "start", "revision": revision}); code != 200 {
		t.Fatal(code, data)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("login not started")
	}
	if code, _ := uiRequest(t, s, "POST", "/api/connection", token, map[string]string{"action": "start", "revision": revision}); code != 409 {
		t.Fatal("duplicate connection accepted")
	}
	started := time.Now()
	if code, data := uiRequest(t, s, "POST", "/api/connection", token, map[string]string{"action": "stop"}); code != 200 {
		t.Fatal(code, data)
	}
	if time.Since(started) > 3*time.Second || u.runtime.snapshot()["processRunning"] != false || requests.Load() != 1 {
		t.Fatal("stop did not cancel one owned login promptly")
	}
}

func TestUIRejectsOversizedAndReadOnlyConfigWithoutWriting(t *testing.T) {
	u, s, path := uiFixture(t)
	token := uiSession(t, u, s)
	code := u.newCode()
	u.authMu.Lock()
	u.bootstrapExpiry = time.Now().Add(-time.Second)
	u.authMu.Unlock()
	if status, _ := uiRequest(t, s, "POST", "/api/session", "", map[string]string{"code": code}); status != 401 {
		t.Fatal("expired bootstrap accepted")
	}
	if status, _ := uiRequest(t, s, "POST", "/api/config/save", token, uiConfigEdit{Revision: "missing", Changes: map[string]string{"secret": strings.Repeat("x", 70000)}}); status != 400 {
		t.Fatal("oversized body accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("rejected request created config")
	}
	data := []byte(`{"serverBaseUrl":"http://127.0.0.1:1","apiKey":"test","secret":"test"}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	_, revision, _ := uiReadConfig(path)
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0600)
	if status, _ := uiRequest(t, s, "POST", "/api/config/save", token, uiConfigEdit{Revision: revision, Changes: map[string]string{"apiKey": "replacement"}}); status != 422 {
		t.Fatal("read-only file overwritten")
	}
	actual, _ := os.ReadFile(path)
	if string(actual) != string(data) {
		t.Fatal("read-only config changed")
	}
}
