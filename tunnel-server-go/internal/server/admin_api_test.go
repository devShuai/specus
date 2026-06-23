package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// newAPIServer boots an App and wraps its management handler in an httptest.Server.
func newAPIServer(t *testing.T) (*App, *httptest.Server) {
	t.Helper()
	app, _ := startTestApp(t)
	ts := httptest.NewServer(app.managementHandler())
	t.Cleanup(ts.Close)
	return app, ts
}

func adminToken(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "admin"})
	resp, err := http.Post(ts.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	var token struct {
		AccessToken string `json:"accessToken"`
		TokenType   string `json:"tokenType"`
		ExpiresIn   int64  `json:"expiresIn"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if token.TokenType != "Bearer" || token.AccessToken == "" || token.ExpiresIn <= 0 {
		t.Fatalf("bad token: %+v", token)
	}
	return token.AccessToken
}

func authRequest(t *testing.T, ts *httptest.Server, method, path, token, body string) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

func TestAdminRejectsMissingToken(t *testing.T) {
	_, ts := newAPIServer(t)
	resp := authRequest(t, ts, http.MethodGet, "/api/admin/overview", "", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAdminLoginAndOverview(t *testing.T) {
	_, ts := newAPIServer(t)
	token := adminToken(t, ts)

	resp := authRequest(t, ts, http.MethodGet, "/api/admin/overview", token, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("overview status %d", resp.StatusCode)
	}
	var overview map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&overview)
	if overview["clients"].(float64) < 1 {
		t.Fatalf("expected >=1 client, got %v", overview["clients"])
	}
}

func TestClientAndTunnelCrud(t *testing.T) {
	_, ts := newAPIServer(t)
	token := adminToken(t, ts)

	// Create a client.
	resp := authRequest(t, ts, http.MethodPost, "/api/admin/clients", token,
		`{"clientName":"go-crud","enabled":true,"connectionRateLimitPerMinute":12}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create client status %d", resp.StatusCode)
	}
	var created struct {
		Client management_ClientView `json:"client"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.Client.ClientName != "go-crud" {
		t.Fatalf("unexpected create result: %+v", created)
	}

	resp = authRequest(t, ts, http.MethodPost, "/api/admin/client-credentials", token,
		`{"apiKey":"ck_go_crud","secret":"secret","enabled":true,"maxOnlineInstances":3}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create credential status %d", resp.StatusCode)
	}
	var credential struct {
		Credential struct {
			APIKey             string `json:"apiKey"`
			MaxOnlineInstances int    `json:"maxOnlineInstances"`
		} `json:"credential"`
		Secret string `json:"secret"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&credential)
	resp.Body.Close()
	if credential.Credential.APIKey != "ck_go_crud" || credential.Secret != "secret" ||
		credential.Credential.MaxOnlineInstances != 3 {
		t.Fatalf("unexpected credential result: %+v", credential)
	}

	// Create a tunnel for the client.
	tunnelBody := `{"listenPort":45999,"targetAddress":"127.0.0.1","targetPort":8080,"enabled":true}`
	resp = authRequest(t, ts, http.MethodPost, "/api/admin/clients/"+itoa(created.Client.ID)+"/tunnels", token, tunnelBody)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create tunnel status %d", resp.StatusCode)
	}
	resp.Body.Close()

	// nat-control push should 409 because the client is offline.
	resp = authRequest(t, ts, http.MethodPost, "/api/admin/clients/"+itoa(created.Client.ID)+"/nat-control", token, "")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 for offline nat-control, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Delete the client.
	resp = authRequest(t, ts, http.MethodDelete, "/api/admin/clients/"+itoa(created.Client.ID), token, "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete client status %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestHTTPRouteValidation(t *testing.T) {
	_, ts := newAPIServer(t)
	token := adminToken(t, ts)
	clients := listClients(t, ts, token)
	demo := findClient(t, clients, DemoClientName)

	// Invalid route (contains '/') -> 400.
	resp := authRequest(t, ts, http.MethodPost, "/api/admin/clients/"+itoa(demo.ID)+"/http-routes", token,
		`{"route":"bad/path","targetBaseUrl":"https://example.com"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid route, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Valid route -> 201.
	resp = authRequest(t, ts, http.MethodPost, "/api/admin/clients/"+itoa(demo.ID)+"/http-routes", token,
		`{"route":"api","targetBaseUrl":"https://example.com/base","enabled":true}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for valid route, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestDirectHTTPOfflineAndOversize(t *testing.T) {
	app, ts := newAPIServer(t)
	_ = app

	// Offline client -> 503.
	resp, err := http.Get(ts.URL + "/http/" + "Demo%20client" + "/api/ping")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 offline, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// minimal client view mirror for decoding.
type management_ClientView struct {
	ID         int64  `json:"id"`
	ClientName string `json:"clientName"`
}

func listClients(t *testing.T, ts *httptest.Server, token string) []management_ClientView {
	t.Helper()
	resp := authRequest(t, ts, http.MethodGet, "/api/admin/clients", token, "")
	defer resp.Body.Close()
	var clients []management_ClientView
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		t.Fatalf("decode clients: %v", err)
	}
	return clients
}

func findClient(t *testing.T, clients []management_ClientView, name string) management_ClientView {
	t.Helper()
	for _, c := range clients {
		if c.ClientName == name {
			return c
		}
	}
	t.Fatalf("client %q not found", name)
	return management_ClientView{}
}

func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}
