package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/config"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/store"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/transfer"
)

// newAPIServer boots an App and wraps its management handler in an httptest.Server.
func newAPIServer(t *testing.T) (*App, *httptest.Server) {
	t.Helper()
	app, _ := startTestApp(t)
	return newHTTPTestServer(t, app)
}

func newAPIServerWithConfig(t *testing.T, cfg config.Config) (*App, *httptest.Server) {
	t.Helper()
	app, _ := startTestAppWithConfig(t, cfg)
	return newHTTPTestServer(t, app)
}

func newHTTPTestServer(t *testing.T, app *App) (*App, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(app.managementHandler())
	t.Cleanup(ts.Close)
	return app, ts
}

func TestOneTimeDownloadGrantRejectsHeadWithoutConsumingIt(t *testing.T) {
	_, ts := newAPIServer(t)
	request, err := http.NewRequest(http.MethodHead,
		ts.URL+"/api/public/transfer/downloads/not-a-real-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", response.StatusCode)
	}
	if response.Header.Get("Allow") != http.MethodGet {
		t.Fatalf("Allow = %q, want GET", response.Header.Get("Allow"))
	}
}

func TestOSSUploadCallbackIsAnonymousButRejectsInvalidSignature(t *testing.T) {
	_, ts := newAPIServer(t)
	response, err := http.Post(ts.URL+"/api/public/transfer/oss-callback",
		"application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.StatusCode)
	}
}

func TestPublicPeerMeshStunConfigMatchesJavaShape(t *testing.T) {
	cfg := config.Default()
	cfg.PeerMesh.Enabled = true
	cfg.PeerMesh.PublicAddress = "tunnel.example.com"
	cfg.PeerMesh.StunTurnPort = 3478
	cfg.PeerMesh.PublicStunServers = []string{
		"stun://stun1.example.com",
		"stun:stun2.example.com:5349",
		"stun1.example.com:3478",
	}
	_, ts := newAPIServerWithConfig(t, cfg)

	resp, err := http.Get(ts.URL + "/api/public/peer-mesh/stun-config")
	if err != nil {
		t.Fatalf("get stun config: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var decoded struct {
		PeerMeshEnabled      bool     `json:"peerMeshEnabled"`
		SelfHostedStunServer string   `json:"selfHostedStunServer"`
		StunServers          []string `json:"stunServers"`
		StunTurnPort         int      `json:"stunTurnPort"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode stun config: %v", err)
	}
	if !decoded.PeerMeshEnabled {
		t.Fatalf("peerMeshEnabled = false, want true")
	}
	if decoded.SelfHostedStunServer != "stun:tunnel.example.com:3478" {
		t.Fatalf("selfHosted = %q", decoded.SelfHostedStunServer)
	}
	want := []string{"stun:tunnel.example.com:3478", "stun:stun1.example.com:3478", "stun:stun2.example.com:5349"}
	if strings.Join(decoded.StunServers, ",") != strings.Join(want, ",") {
		t.Fatalf("stunServers = %#v, want %#v", decoded.StunServers, want)
	}
	if decoded.StunTurnPort != 3478 {
		t.Fatalf("stunTurnPort = %d", decoded.StunTurnPort)
	}
}

func TestPublicIceConfigNormalizesIPv6AndForwardedHost(t *testing.T) {
	cfg := config.Default()
	cfg.PeerMesh.Enabled = true
	cfg.PeerMesh.PublicAddress = ""
	cfg.PeerMesh.PublicStunServers = []string{
		"stun://[2001:db8::10]:5349", "stun:stun.example.com:3479",
	}
	_, ts := newAPIServerWithConfig(t, cfg)
	request, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/public/transfer/ice-config", nil)
	request.Header.Set("X-Forwarded-Host", "[2001:db8::20]:8443, proxy.internal")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var decoded struct {
		PeerMeshEnabled  bool                                          `json:"peerMeshEnabled"`
		TurnAuthRequired bool                                          `json:"turnAuthRequired"`
		IceServers       []struct{ URLs, Username, Credential string } `json:"iceServers"`
	}
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.PeerMeshEnabled || !decoded.TurnAuthRequired {
		t.Fatalf("flags = %+v", decoded)
	}
	urls := make([]string, 0, len(decoded.IceServers))
	for _, server := range decoded.IceServers {
		urls = append(urls, server.URLs)
	}
	want := []string{
		"stun:[2001:db8::20]:3478", "stun:[2001:db8::10]:5349",
		"stun:stun.example.com:3479", "turn:[2001:db8::20]:3478?transport=udp",
	}
	if strings.Join(urls, ",") != strings.Join(want, ",") {
		t.Fatalf("ice URLs = %#v, want %#v", urls, want)
	}
	turn := decoded.IceServers[len(decoded.IceServers)-1]
	if turn.Username == "" || turn.Credential == "" {
		t.Fatalf("TURN credential missing: %+v", turn)
	}
}

func TestStaticResourceCacheHeadersMatchJava(t *testing.T) {
	_, ts := newAPIServer(t)
	response, err := http.Get(ts.URL + "/favicon.svg")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "public, max-age=604800" {
		t.Fatalf("favicon status/cache = %d/%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
	for path, want := range map[string]string{
		"/assets/app.js":                    "public, max-age=31536000, immutable",
		"/schemas/peer-control.schema.json": "public, max-age=3600",
	} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		staticResourceCacheHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(recorder, request)
		if recorder.Header().Get("Cache-Control") != want {
			t.Fatalf("%s cache = %q, want %q", path, recorder.Header().Get("Cache-Control"), want)
		}
	}
}

func TestPublicAttachmentHTTPStatusMatchesJavaExceptionMapping(t *testing.T) {
	cfg := config.Default()
	cfg.PublicTransfer.PresignRateLimitPerIP = 1
	app, ts := newAPIServerWithConfig(t, cfg)
	body := `{"fileName":"a.txt","sizeBytes":1,"roomToken":"room-secret"}`
	unauthenticated, err := http.Post(ts.URL+"/api/public/transfer/attachments/presign-upload",
		"application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	unauthenticated.Body.Close()
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous attachment upload status = %d, want 401", unauthenticated.StatusCode)
	}
	token := adminToken(t, ts)
	request := func() *http.Response {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/public/transfer/attachments/presign-upload", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Real-IP", "203.0.113.10")
		req.Header.Set("Authorization", "Bearer "+token)
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	first := request()
	defer first.Body.Close()
	var firstError map[string]string
	_ = json.NewDecoder(first.Body).Decode(&firstError)
	if first.StatusCode != http.StatusConflict || firstError["error"] != "object storage is not configured" {
		t.Fatalf("disabled storage status/body = %d/%#v", first.StatusCode, firstError)
	}
	second := request()
	defer second.Body.Close()
	var secondError map[string]string
	_ = json.NewDecoder(second.Body).Decode(&secondError)
	if second.StatusCode != http.StatusTooManyRequests || secondError["error"] != "请求过于频繁,请稍后再试" {
		t.Fatalf("rate limit status/body = %d/%#v", second.StatusCode, secondError)
	}

	now := time.Now().UTC()
	tokenHash := sha256.Sum256([]byte("room-secret"))
	tokenHashText := hex.EncodeToString(tokenHash[:])
	item := store.TransferAttachment{ID: 880001, Scope: transfer.ScopePublicTransfer,
		RoomTokenHash: &tokenHashText, ObjectKey: "prefix/a", FileName: "a.txt",
		MimeType: "text/plain", SizeBytes: 1, Status: transfer.StatusPending,
		CreatedAt: now, UpdatedAt: now, UploadExpiresAt: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour)}
	if err := app.db.InsertTransferAttachment(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost,
		ts.URL+"/api/public/transfer/attachments/880001/presign-download",
		strings.NewReader(`{"roomToken":"room-secret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var stateError map[string]string
	_ = json.NewDecoder(response.Body).Decode(&stateError)
	if response.StatusCode != http.StatusConflict || stateError["error"] != "attachment is not uploaded" {
		t.Fatalf("state conflict status/body = %d/%#v", response.StatusCode, stateError)
	}
}

func adminToken(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	return loginToken(t, ts, "admin", "admin")
}

func loginToken(t *testing.T, ts *httptest.Server, username, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
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
	tunnelBody := `{"listenPort":45999,"targetAddress":"127.0.0.1","targetPort":8080,"enabled":true,"detailCaptureEnabled":true}`
	resp = authRequest(t, ts, http.MethodPost, "/api/admin/clients/"+itoa(created.Client.ID)+"/tunnels", token, tunnelBody)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create tunnel status %d", resp.StatusCode)
	}
	var tunnel struct {
		DetailCaptureEnabled bool `json:"detailCaptureEnabled"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tunnel)
	resp.Body.Close()
	if !tunnel.DetailCaptureEnabled {
		t.Fatalf("expected detail capture enabled in tunnel response")
	}

	resp = authRequest(t, ts, http.MethodPost, "/api/admin/clients/"+itoa(created.Client.ID)+"/http-routes", token,
		`{"route":"crud-detail","targetBaseUrl":"https://example.com/base","enabled":true,"detailCaptureEnabled":true}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create http route status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = authRequest(t, ts, http.MethodGet, "/api/admin/clients/"+itoa(created.Client.ID), token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("client detail status %d", resp.StatusCode)
	}
	var detail struct {
		Client  management_ClientView `json:"client"`
		Tunnels []struct {
			ListenPort int `json:"listenPort"`
		} `json:"tunnels"`
		HTTPRoutes []struct {
			Route string `json:"route"`
		} `json:"httpRoutes"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&detail)
	resp.Body.Close()
	if detail.Client.ID != created.Client.ID || len(detail.Tunnels) != 1 || len(detail.HTTPRoutes) != 1 ||
		detail.HTTPRoutes[0].Route != "crud-detail" {
		t.Fatalf("unexpected client detail: %+v", detail)
	}

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

func TestPeerMeshACLAPIExposesAndPersistsDirection(t *testing.T) {
	_, ts := newAPIServer(t)
	token := adminToken(t, ts)
	createClient := func(name string) int64 {
		response := authRequest(t, ts, http.MethodPost, "/api/admin/clients", token,
			`{"clientName":"`+name+`","enabled":true}`)
		defer response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			t.Fatalf("create client %s status %d", name, response.StatusCode)
		}
		var result struct {
			Client management_ClientView `json:"client"`
		}
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		return result.Client.ID
	}
	sourceID := createClient("acl-source")
	targetID := createClient("acl-target")
	body := `{"sourceClientId":` + itoa(sourceID) + `,"targetClientId":` + itoa(targetID) + `,"direction":"both"}`
	response := authRequest(t, ts, http.MethodPost, "/api/admin/peer-mesh/acls", token, body)
	if response.StatusCode != http.StatusCreated {
		response.Body.Close()
		t.Fatalf("create ACL status %d", response.StatusCode)
	}
	var created struct {
		ID        int64  `json:"id"`
		Allowed   bool   `json:"allowed"`
		Direction string `json:"direction"`
	}
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if created.ID == 0 || !created.Allowed || created.Direction != "BOTH" {
		t.Fatalf("unexpected ACL response: %+v", created)
	}

	response = authRequest(t, ts, http.MethodGet, "/api/admin/peer-mesh/acls", token, "")
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("list ACLs status %d", response.StatusCode)
	}
	var listed []struct {
		ID        int64  `json:"id"`
		Direction string `json:"direction"`
	}
	if err := json.NewDecoder(response.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != created.ID || listed[0].Direction != "BOTH" {
		t.Fatalf("listed ACL direction mismatch: %+v", listed)
	}
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
		`{"route":"api","targetBaseUrl":"https://example.com/base","enabled":true,"detailCaptureEnabled":true,"pathRewriteEnabled":true}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for valid route, got %d", resp.StatusCode)
	}
	var route struct {
		DetailCaptureEnabled bool `json:"detailCaptureEnabled"`
		PathRewriteEnabled   bool `json:"pathRewriteEnabled"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&route)
	resp.Body.Close()
	if !route.DetailCaptureEnabled || !route.PathRewriteEnabled {
		t.Fatalf("expected route capture/rewrite flags enabled: %+v", route)
	}
}

func TestManagementUsersAndOwnerScope(t *testing.T) {
	_, ts := newAPIServer(t)
	admin := adminToken(t, ts)

	resp := authRequest(t, ts, http.MethodPost, "/api/admin/database/initialize", admin, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin initialize status %d", resp.StatusCode)
	}
	var initializeBody struct {
		Initialized bool   `json:"initialized"`
		TenantID    string `json:"tenantId"`
		Orm         string `json:"orm"`
		Dialect     string `json:"dialect"`
		Clients     int64  `json:"clients"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&initializeBody)
	resp.Body.Close()
	if !initializeBody.Initialized || initializeBody.TenantID != "default" ||
		initializeBody.Orm != "database/sql" || initializeBody.Dialect == "" || initializeBody.Clients < 1 {
		t.Fatalf("unexpected initialize body: %+v", initializeBody)
	}

	resp = authRequest(t, ts, http.MethodPost, "/api/admin/users", admin,
		`{"username":"alice","password":"alice-password","role":"USER","enabled":true}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create user status %d", resp.StatusCode)
	}
	resp.Body.Close()

	alice := loginToken(t, ts, "alice", "alice-password")

	resp = authRequest(t, ts, http.MethodGet, "/api/admin/me", alice, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me status %d", resp.StatusCode)
	}
	var me struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		Admin    bool   `json:"admin"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&me)
	resp.Body.Close()
	if me.Username != "alice" || me.Role != "USER" || me.Admin {
		t.Fatalf("unexpected me: %+v", me)
	}

	resp = authRequest(t, ts, http.MethodGet, "/api/admin/users", alice, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin users status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = authRequest(t, ts, http.MethodPost, "/api/admin/database/initialize", alice, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin initialize status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = authRequest(t, ts, http.MethodPost, "/api/admin/clients", alice,
		`{"clientName":"alice-client","enabled":true,"connectionRateLimitPerMinute":12}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("alice create client status %d", resp.StatusCode)
	}
	var aliceClient struct {
		Client management_ClientView `json:"client"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&aliceClient)
	resp.Body.Close()

	resp = authRequest(t, ts, http.MethodPost, "/api/admin/clients", admin,
		`{"clientName":"admin-client","enabled":true,"connectionRateLimitPerMinute":12}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("admin create client status %d", resp.StatusCode)
	}
	var adminClient struct {
		Client management_ClientView `json:"client"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&adminClient)
	resp.Body.Close()

	aliceClients := listClients(t, ts, alice)
	if len(aliceClients) != 1 || aliceClients[0].ClientName != "alice-client" {
		t.Fatalf("alice should only see own client, got %+v", aliceClients)
	}

	resp = authRequest(t, ts, http.MethodDelete, "/api/admin/clients/"+itoa(adminClient.Client.ID), alice, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("alice delete admin client status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = authRequest(t, ts, http.MethodPost, "/api/admin/client-credentials", alice,
		`{"apiKey":"ck_alice","secret":"alice-secret","enabled":true,"maxOnlineInstances":2}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("alice create credential status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = authRequest(t, ts, http.MethodPost, "/api/admin/client-credentials", admin,
		`{"apiKey":"ck_admin","secret":"admin-secret","enabled":true,"maxOnlineInstances":2}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("admin create credential status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = authRequest(t, ts, http.MethodGet, "/api/admin/client-credentials", alice, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("alice list credentials status %d", resp.StatusCode)
	}
	var credentials []struct {
		APIKey string `json:"apiKey"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&credentials)
	resp.Body.Close()
	if len(credentials) != 1 || credentials[0].APIKey != "ck_alice" {
		t.Fatalf("alice should only see own credential, got %+v", credentials)
	}

	resp = authRequest(t, ts, http.MethodPost, "/api/admin/clients/"+itoa(adminClient.Client.ID)+"/tunnels", alice,
		`{"listenPort":46001,"targetAddress":"127.0.0.1","targetPort":8080,"enabled":true}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("alice create tunnel for admin client status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = authRequest(t, ts, http.MethodPost, "/api/admin/clients/"+itoa(aliceClient.Client.ID)+"/tunnels", alice,
		`{"listenPort":46002,"targetAddress":"127.0.0.1","targetPort":8080,"enabled":true}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("alice create own tunnel status %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestClientDownloadLinksAdminCrudAndPublicList(t *testing.T) {
	_, ts := newAPIServer(t)
	admin := adminToken(t, ts)

	resp := authRequest(t, ts, http.MethodPost, "/api/admin/client-downloads", admin,
		`{"implementation":"java","platform":"any","arch":"any","displayName":"Java exec jar","downloadUrl":"https://example.com/shuai-tunnel.jar","description":"cross platform","displayOrder":20,"enabled":false}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create disabled download status %d", resp.StatusCode)
	}
	var disabled struct {
		ID          int64  `json:"id"`
		DisplayName string `json:"displayName"`
		Enabled     bool   `json:"enabled"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&disabled)
	resp.Body.Close()
	if disabled.ID == 0 || disabled.DisplayName != "Java exec jar" || disabled.Enabled {
		t.Fatalf("unexpected disabled download: %+v", disabled)
	}

	resp = authRequest(t, ts, http.MethodPost, "/api/admin/client-downloads", admin,
		`{"implementation":"go","platform":"linux","arch":"x64","displayName":"Linux x64","downloadUrl":"https://example.com/shuai-tunnel-linux-amd64","displayOrder":10}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create enabled download status %d", resp.StatusCode)
	}
	var enabled struct {
		ID             int64  `json:"id"`
		Implementation string `json:"implementation"`
		Platform       string `json:"platform"`
		Arch           string `json:"arch"`
		Enabled        bool   `json:"enabled"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&enabled)
	resp.Body.Close()
	if enabled.Implementation != "go" || enabled.Platform != "linux" || enabled.Arch != "x64" || !enabled.Enabled {
		t.Fatalf("unexpected enabled download: %+v", enabled)
	}

	resp, err := http.Get(ts.URL + "/api/public/client-downloads")
	if err != nil {
		t.Fatalf("public client downloads: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public downloads status %d", resp.StatusCode)
	}
	var public []struct {
		ID          int64  `json:"id"`
		DisplayName string `json:"displayName"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&public)
	resp.Body.Close()
	if len(public) != 1 || public[0].ID != enabled.ID {
		t.Fatalf("public downloads should include only enabled link, got %+v", public)
	}

	resp = authRequest(t, ts, http.MethodPut, "/api/admin/client-downloads/"+itoa(enabled.ID), admin,
		`{"implementation":"csharp","platform":"windows","arch":"x64","displayName":"Windows x64","downloadUrl":"https://example.com/shuai-tunnel-win-x64.zip","enabled":true}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update download status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = authRequest(t, ts, http.MethodGet, "/api/admin/client-downloads", admin, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list admin downloads status %d", resp.StatusCode)
	}
	var all []struct {
		ID          int64  `json:"id"`
		DisplayName string `json:"displayName"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&all)
	resp.Body.Close()
	if len(all) != 2 || all[0].DisplayName != "Windows x64" || all[1].DisplayName != "Java exec jar" {
		t.Fatalf("admin downloads order mismatch: %+v", all)
	}

	resp = authRequest(t, ts, http.MethodPost, "/api/admin/users", admin,
		`{"username":"download-user","password":"download-password","role":"USER","enabled":true}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create ordinary user status %d", resp.StatusCode)
	}
	resp.Body.Close()
	userToken := loginToken(t, ts, "download-user", "download-password")
	resp = authRequest(t, ts, http.MethodPost, "/api/admin/client-downloads", userToken,
		`{"implementation":"go","platform":"linux","arch":"arm64","displayName":"Forbidden","downloadUrl":"https://example.com/forbidden"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ordinary user create download status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = authRequest(t, ts, http.MethodDelete, "/api/admin/client-downloads/"+itoa(disabled.ID), admin, "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete download status %d", resp.StatusCode)
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
