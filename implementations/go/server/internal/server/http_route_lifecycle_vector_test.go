package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
)

// httpRouteLifecycleVector is the server half of protocol/test-vectors/http-route-lifecycle-v1.json.
// Its notes array defines every op and expectation replayed here.
type httpRouteLifecycleVector struct {
	BasicCredentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"basicCredentials"`
	TargetBaseURL      string `json:"targetBaseUrl"`
	FakeClientResponse struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	} `json:"fakeClientResponse"`
	Server struct {
		Scenarios []struct {
			ID    string                   `json:"id"`
			Steps []httpRouteLifecycleStep `json:"steps"`
		} `json:"scenarios"`
	} `json:"server"`
}

type httpRouteLifecycleStep struct {
	Op                  string    `json:"op"`
	Route               *string   `json:"route"`
	Auth                bool      `json:"auth"`
	Enabled             *bool     `json:"enabled"`
	Suffix              string    `json:"suffix"`
	Routes              []string  `json:"routes"`
	ExpectPush          *[]string `json:"expectPush"`
	ExpectLoginPush     *[]string `json:"expectLoginPush"`
	ExpectSessionClosed bool      `json:"expectSessionClosed"`
	ExpectRefused       *bool     `json:"expectRefused"`
	Path                string    `json:"path"`
	Credentials         string    `json:"credentials"`
	WebSocket           bool      `json:"websocket"`
	Client              string    `json:"client"`
	Expect              *struct {
		Status         int     `json:"status"`
		StatusAnyOf    []int   `json:"statusAnyOf"`
		NoStore        bool    `json:"noStore"`
		BasicChallenge bool    `json:"basicChallenge"`
		Body           *string `json:"body"`
		Forwarded      *bool   `json:"forwarded"`
	} `json:"expect"`
}

const (
	routeLifecycleAPIKey     = "ck_route_lifecycle"
	routeLifecycleSecret     = "route-lifecycle-secret"
	routeLifecycleMachine    = "route-lifecycle-machine"
	routeLifecycleOSUser     = "route-lifecycle-user"
	routeLifecycleClientName = "Route lifecycle"
)

func TestHTTPRouteLifecycleVectorServerScenarios(t *testing.T) {
	var vector httpRouteLifecycleVector
	contents, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "protocol",
		"test-vectors", "http-route-lifecycle-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(contents, &vector); err != nil {
		t.Fatal(err)
	}
	if len(vector.Server.Scenarios) == 0 {
		t.Fatal("http-route-lifecycle-v1.json has no server scenarios")
	}
	// serveFakeForwardingClient always answers 200 "forwarded"; keep it in step with the vector.
	if response := vector.FakeClientResponse; response.Status != http.StatusOK || response.Body != "forwarded" {
		t.Fatalf("vector fake client response = %+v, the fake client answers 200 forwarded", response)
	}
	for _, scenario := range vector.Server.Scenarios {
		t.Run(scenario.ID, func(t *testing.T) {
			run := newHTTPRouteLifecycleRun(t, &vector)
			for index, step := range scenario.Steps {
				run.step, run.op = index, step.Op
				run.apply(step)
			}
		})
	}
}

// httpRouteLifecycleRun replays one scenario on a fresh server. The scenario client is a machine
// account created by a real HTTP login, so every connect logs in again as that same account.
type httpRouteLifecycleRun struct {
	t          *testing.T
	vector     *httpRouteLifecycleVector
	app        *App
	port       int
	ts         *httptest.Server
	token      string
	httpClient *http.Client

	clientID    int64
	clientName  string
	formerName  string
	deletedName string
	routeIDs    map[string]int64

	// lastLogin is the login of the most recent connect, which reconnect presents again.
	lastLogin *protocol.LoginRequest

	// opened counts HTTP OPENs across every fake client connection of the scenario.
	opened atomic.Int32
	online *httpRouteLifecycleSession

	step int
	op   string
}

// httpRouteLifecycleSession is one logged-in fake client: a control connection whose NAT_CONTROL
// pushes are collected and a data connection that forwards every HTTP OPEN.
type httpRouteLifecycleSession struct {
	control       net.Conn
	data          net.Conn
	natControls   chan string
	controlClosed <-chan struct{}
	dataClosed    <-chan struct{}
}

func newHTTPRouteLifecycleRun(t *testing.T, vector *httpRouteLifecycleVector) *httpRouteLifecycleRun {
	t.Helper()
	cfg := config.Default()
	cfg.HTTP.RouteCacheTTLms = 0
	app, port := startTestAppWithConfig(t, cfg)
	_, ts := newHTTPTestServer(t, app)
	run := &httpRouteLifecycleRun{
		t: t, vector: vector, app: app, port: port, ts: ts, token: adminToken(t, ts),
		httpClient: &http.Client{Timeout: 10 * time.Second},
		routeIDs:   map[string]int64{},
		step:       -1, op: "setup",
	}
	t.Cleanup(run.dropSession)

	run.admin(http.MethodPost, "/api/admin/client-credentials", map[string]any{
		"apiKey": routeLifecycleAPIKey, "secret": routeLifecycleSecret, "maxOnlineInstances": 1,
	}, http.StatusCreated, nil)
	runtime := clientAuthLoginForTest(t, ts.URL, routeLifecycleAPIKey, routeLifecycleSecret,
		routeLifecycleMachine, routeLifecycleOSUser)
	run.clientID = findClient(t, listClients(t, ts, run.token), runtime.ClientName).ID
	// A name with a space makes every public entry URL depend on percent-encoding.
	run.admin(http.MethodPut, "/api/admin/clients/"+itoa(run.clientID),
		map[string]any{"clientName": routeLifecycleClientName}, http.StatusOK, nil)
	run.clientName = routeLifecycleClientName
	return run
}

func (r *httpRouteLifecycleRun) fatalf(format string, args ...any) {
	r.t.Helper()
	r.t.Fatalf("step %d (%s): %s", r.step, r.op, fmt.Sprintf(format, args...))
}

func (r *httpRouteLifecycleRun) apply(step httpRouteLifecycleStep) {
	r.t.Helper()
	switch step.Op {
	case "createRoute":
		name := r.routeName(step)
		body := map[string]any{"route": name, "targetBaseUrl": r.vector.TargetBaseURL, "enabled": true}
		if step.Auth {
			body["authEnabled"] = true
			body["authUsername"] = r.vector.BasicCredentials.Username
			body["authPassword"] = r.vector.BasicCredentials.Password
		}
		var created struct {
			ID int64 `json:"id"`
		}
		r.admin(http.MethodPost, "/api/admin/clients/"+itoa(r.clientID)+"/http-routes", body,
			http.StatusCreated, &created)
		r.routeIDs[name] = created.ID
	case "setRouteEnabled":
		name := r.routeName(step)
		r.admin(http.MethodPut, "/api/admin/http-routes/"+itoa(r.routeID(name)), map[string]any{
			"route": name, "targetBaseUrl": r.vector.TargetBaseURL, "enabled": r.enabled(step),
		}, http.StatusOK, nil)
	case "deleteRoute":
		name := r.routeName(step)
		r.admin(http.MethodDelete, "/api/admin/http-routes/"+itoa(r.routeID(name)), nil, http.StatusNoContent, nil)
		delete(r.routeIDs, name)
	case "setClientEnabled":
		r.admin(http.MethodPut, "/api/admin/clients/"+itoa(r.clientID),
			map[string]any{"enabled": r.enabled(step)}, http.StatusOK, nil)
	case "renameClient":
		renamed := r.clientName + step.Suffix
		r.admin(http.MethodPut, "/api/admin/clients/"+itoa(r.clientID),
			map[string]any{"clientName": renamed}, http.StatusOK, nil)
		r.formerName, r.clientName = r.clientName, renamed
	case "deleteClient":
		r.admin(http.MethodDelete, "/api/admin/clients/"+itoa(r.clientID), nil, http.StatusNoContent, nil)
		r.deletedName = r.clientName
		r.routeIDs = map[string]int64{}
	case "createClient":
		if r.deletedName == "" {
			r.fatalf("createClient needs a deleted client name to reuse")
		}
		var created struct {
			Client struct {
				ID         int64  `json:"id"`
				ClientName string `json:"clientName"`
			} `json:"client"`
		}
		r.admin(http.MethodPost, "/api/admin/clients", map[string]any{"clientName": r.deletedName},
			http.StatusCreated, &created)
		r.clientID, r.clientName = created.Client.ID, created.Client.ClientName
		r.routeIDs = map[string]int64{}
	case "createFormerNameClient":
		if r.formerName == "" {
			r.fatalf("createFormerNameClient needs an earlier renameClient")
		}
		var created struct {
			Client struct {
				ID int64 `json:"id"`
			} `json:"client"`
		}
		r.admin(http.MethodPost, "/api/admin/clients", map[string]any{"clientName": r.formerName},
			http.StatusCreated, &created)
		for _, route := range step.Routes {
			r.admin(http.MethodPost, "/api/admin/clients/"+itoa(created.Client.ID)+"/http-routes", map[string]any{
				"route": route, "targetBaseUrl": r.vector.TargetBaseURL, "enabled": true,
			}, http.StatusCreated, nil)
		}
	case "connect":
		r.connect(step)
		return
	case "reconnect":
		r.reconnect(step)
		return
	case "disconnect":
		r.disconnect()
		return
	case "request":
		r.request(step)
		return
	default:
		r.fatalf("unknown op %q", step.Op)
	}
	if step.ExpectPush != nil {
		r.expectNatControl(*step.ExpectPush, "push")
	}
	if step.ExpectSessionClosed {
		r.expectSessionClosed()
	}
}

func (r *httpRouteLifecycleRun) routeName(step httpRouteLifecycleStep) string {
	r.t.Helper()
	if step.Route == nil {
		r.fatalf("route is required")
	}
	return *step.Route
}

func (r *httpRouteLifecycleRun) routeID(name string) int64 {
	r.t.Helper()
	id, ok := r.routeIDs[name]
	if !ok {
		r.fatalf("route %q was not created for client %q", name, r.clientName)
	}
	return id
}

func (r *httpRouteLifecycleRun) enabled(step httpRouteLifecycleStep) bool {
	r.t.Helper()
	if step.Enabled == nil {
		r.fatalf("enabled is required")
	}
	return *step.Enabled
}

// admin calls the management API as the admin and decodes the response into out when given.
func (r *httpRouteLifecycleRun) admin(method, path string, body any, wantStatus int, out any) {
	r.t.Helper()
	payload := ""
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			r.fatalf("encode %s %s body: %v", method, path, err)
		}
		payload = string(encoded)
	}
	resp := authRequest(r.t, r.ts, method, path, r.token, payload)
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		r.fatalf("%s %s = %d %s, want %d", method, path, resp.StatusCode, data, wantStatus)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			r.fatalf("decode %s %s response %s: %v", method, path, data, err)
		}
	}
}

// connect logs the scenario client in for real: HTTP login with its startup credential, then
// the control and data connections with the issued token.
func (r *httpRouteLifecycleRun) connect(step httpRouteLifecycleStep) {
	r.t.Helper()
	if r.online != nil {
		r.fatalf("connect while the client is already connected")
	}
	if step.ExpectLoginPush == nil {
		r.fatalf("connect needs expectLoginPush")
	}
	runtime := clientAuthLoginForTest(r.t, r.ts.URL, routeLifecycleAPIKey, routeLifecycleSecret,
		routeLifecycleMachine, routeLifecycleOSUser)
	if runtime.ClientName != r.clientName {
		r.fatalf("HTTP login signed in as %q, want %q", runtime.ClientName, r.clientName)
	}
	r.lastLogin = &protocol.LoginRequest{
		ClientName:      runtime.ClientName,
		ClientSessionID: runtime.ClientSessionID,
		AccessToken:     runtime.AccessToken,
	}
	if answer := r.login(*r.lastLogin); !answer.Success {
		r.fatalf("control login refused: %#v", answer)
	}
	r.expectNatControl(*step.ExpectLoginPush, "login push")
}

// reconnect logs in again with the token of the last connect and no new HTTP login, still naming
// the account as it was called then.
func (r *httpRouteLifecycleRun) reconnect(step httpRouteLifecycleStep) {
	r.t.Helper()
	if r.online != nil {
		r.fatalf("reconnect while the client is already connected")
	}
	if r.lastLogin == nil || step.ExpectRefused == nil {
		r.fatalf("reconnect needs an earlier connect and expectRefused")
	}
	answer := r.login(*r.lastLogin)
	if *step.ExpectRefused {
		if answer.Success {
			r.dropSession()
			r.fatalf("the token of %q logged in again as %q, want it refused", r.lastLogin.ClientName, answer.ClientName)
		}
		return
	}
	if !answer.Success {
		r.fatalf("control login refused: %#v", answer)
	}
	if answer.ClientName != r.clientName {
		r.fatalf("control login answered as %q, want the account's current name %q", answer.ClientName, r.clientName)
	}
	if step.ExpectLoginPush == nil {
		r.fatalf("an accepted reconnect needs expectLoginPush")
	}
	r.expectNatControl(*step.ExpectLoginPush, "login push")
}

// login logs the fake client in: the control connection, and when the server accepts it, the data
// connection, which must be accepted too. It returns the control connection's answer. A refused
// control connection must then be closed by the server.
func (r *httpRouteLifecycleRun) login(request protocol.LoginRequest) protocol.LoginResponse {
	r.t.Helper()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(r.port))
	dial := func(role string) (net.Conn, *bufio.Reader, protocol.LoginResponse) {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			r.fatalf("dial %s connection: %v", role, err)
		}
		request.ConnectionRole = role
		if err := protocol.WritePacket(conn, request); err != nil {
			_ = conn.Close()
			r.fatalf("write %s login: %v", role, err)
		}
		reader := bufio.NewReader(conn)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		packet, err := readProtocolPacket(reader)
		_ = conn.SetReadDeadline(time.Time{})
		answer, ok := packet.(protocol.LoginResponse)
		if err != nil || !ok {
			_ = conn.Close()
			r.fatalf("%s login answered %#v (%v), want LOGIN_RESPONSE", role, packet, err)
		}
		return conn, reader, answer
	}
	control, controlReader, answer := dial(protocol.ConnectionRoleControl)
	if !answer.Success {
		defer control.Close()
		_ = control.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.Copy(io.Discard, controlReader); err != nil {
			r.fatalf("the server kept the refused control connection open: %v", err)
		}
		return answer
	}
	session := &httpRouteLifecycleSession{control: control, natControls: make(chan string, 64)}
	session.controlClosed = collectNatControlPushes(controlReader, session.natControls)
	r.online = session
	data, dataReader, dataAnswer := dial(protocol.ConnectionRoleData)
	session.data = data
	session.dataClosed = serveFakeForwardingClient(data, dataReader, &r.opened)
	if !dataAnswer.Success {
		r.fatalf("data login refused after an accepted control login: %#v", dataAnswer)
	}
	return answer
}

// collectNatControlPushes forwards every NAT_CONTROL payload read from the control connection.
// The returned channel closes once the control connection can no longer be read.
func collectNatControlPushes(reader *bufio.Reader, pushes chan<- string) <-chan struct{} {
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			packet, err := readProtocolPacket(reader)
			if err != nil {
				return
			}
			if message, ok := packet.(protocol.MessageResponse); ok &&
				message.MessageType == protocol.MessageTypeNatControl {
				pushes <- message.Message
			}
		}
	}()
	return closed
}

func (r *httpRouteLifecycleRun) disconnect() {
	r.t.Helper()
	session := r.online
	if session == nil {
		r.fatalf("disconnect while the client is offline")
	}
	r.dropSession()
	r.awaitClosed(session, "client")
	deadline := time.Now().Add(5 * time.Second)
	for {
		var detail struct {
			Client struct {
				Online bool `json:"online"`
			} `json:"client"`
		}
		r.admin(http.MethodGet, "/api/admin/clients/"+itoa(r.clientID), nil, http.StatusOK, &detail)
		_, dataBound := r.app.sessions.FindData(r.clientName)
		if !detail.Client.Online && !dataBound {
			return
		}
		if time.Now().After(deadline) {
			r.fatalf("server still shows %q online 5 s after both connections closed", r.clientName)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// dropSession closes the fake client's connections from the client side.
func (r *httpRouteLifecycleRun) dropSession() {
	if r.online == nil {
		return
	}
	_ = r.online.control.Close()
	if r.online.data != nil {
		_ = r.online.data.Close()
	}
	r.online = nil
}

func (r *httpRouteLifecycleRun) expectSessionClosed() {
	r.t.Helper()
	session := r.online
	if session == nil {
		r.fatalf("expectSessionClosed while the client is offline")
	}
	r.awaitClosed(session, "server")
	r.dropSession()
}

// awaitClosed waits up to 5 s for both connections of session to stop being readable.
func (r *httpRouteLifecycleRun) awaitClosed(session *httpRouteLifecycleSession, closer string) {
	r.t.Helper()
	deadline := time.After(5 * time.Second)
	for _, connection := range []struct {
		role   string
		closed <-chan struct{}
	}{{"control", session.controlClosed}, {"data", session.dataClosed}} {
		select {
		case <-connection.closed:
		case <-deadline:
			r.fatalf("%s connection still open 5 s after the %s closed the session", connection.role, closer)
		}
	}
}

// expectNatControl reads the next NAT_CONTROL and compares its HTTP route names as a set.
func (r *httpRouteLifecycleRun) expectNatControl(want []string, what string) {
	r.t.Helper()
	if r.online == nil {
		r.fatalf("expects a NAT_CONTROL %s but the client is offline", what)
	}
	var message string
	select {
	case message = <-r.online.natControls:
	case <-time.After(5 * time.Second):
		r.fatalf("no NAT_CONTROL %s within 5 s", what)
	}
	var bean map[string]json.RawMessage
	if err := json.Unmarshal([]byte(message), &bean); err != nil {
		r.fatalf("decode NAT_CONTROL %s %s: %v", what, message, err)
	}
	raw, present := bean["httpSpecusConfigList"]
	if !present || !strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
		r.fatalf("NAT_CONTROL %s must carry httpSpecusConfigList as an array: %s", what, message)
	}
	var routes []struct {
		Route string `json:"route"`
	}
	if err := json.Unmarshal(raw, &routes); err != nil {
		r.fatalf("decode httpSpecusConfigList of %s %s: %v", what, message, err)
	}
	got := make([]string, 0, len(routes))
	for _, route := range routes {
		got = append(got, route.Route)
	}
	slices.Sort(got)
	wantSorted := slices.Sorted(slices.Values(want))
	if !slices.Equal(got, wantSorted) {
		r.fatalf("NAT_CONTROL %s routes = %v, want %v: %s", what, got, wantSorted, message)
	}
}

func (r *httpRouteLifecycleRun) request(step httpRouteLifecycleStep) {
	r.t.Helper()
	expect := step.Expect
	if expect == nil {
		r.fatalf("request without expect")
	}
	clientName := r.clientName
	switch step.Client {
	case "", "current":
	case "former":
		if r.formerName == "" {
			r.fatalf("client former needs an earlier renameClient")
		}
		clientName = r.formerName
	default:
		r.fatalf("unknown client %q", step.Client)
	}
	target := r.ts.URL + "/http/" + url.PathEscape(clientName) + "/"
	if step.Route != nil {
		target += url.PathEscape(*step.Route) + step.Path
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		r.fatalf("build request %s: %v", target, err)
	}
	switch step.Credentials {
	case "none":
	case "valid":
		req.SetBasicAuth(r.vector.BasicCredentials.Username, r.vector.BasicCredentials.Password)
	case "wrong":
		req.SetBasicAuth(r.vector.BasicCredentials.Username, "wrong")
	default:
		r.fatalf("unknown credentials %q", step.Credentials)
	}
	if step.WebSocket {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		req.Header.Set("Sec-WebSocket-Version", "13")
	}

	before := r.opened.Load()
	resp, err := r.httpClient.Do(req)
	if err != nil {
		r.fatalf("GET %s: %v", target, err)
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		resp.Body.Close()
		r.fatalf("GET %s upgraded to WebSocket (101)", target)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	opens := r.opened.Load() - before

	describe := fmt.Sprintf("GET %s (credentials %s, websocket %v) = %d %q, OPENs %d",
		target, step.Credentials, step.WebSocket, resp.StatusCode, body, opens)
	switch {
	case expect.Status != 0:
		if resp.StatusCode != expect.Status {
			r.fatalf("%s, want status %d", describe, expect.Status)
		}
	case len(expect.StatusAnyOf) > 0:
		if !slices.Contains(expect.StatusAnyOf, resp.StatusCode) {
			r.fatalf("%s, want status in %v", describe, expect.StatusAnyOf)
		}
	default:
		r.fatalf("request expect has neither status nor statusAnyOf")
	}
	if expect.NoStore && !strings.Contains(strings.Join(resp.Header.Values("Cache-Control"), ","), "no-store") {
		r.fatalf("%s, Cache-Control %q lacks no-store", describe, resp.Header.Values("Cache-Control"))
	}
	if expect.BasicChallenge && !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic") {
		r.fatalf("%s, WWW-Authenticate %q is not a Basic challenge", describe, resp.Header.Get("WWW-Authenticate"))
	}
	if expect.Body != nil && string(body) != *expect.Body {
		r.fatalf("%s, want body %q", describe, *expect.Body)
	}
	if expect.Forwarded != nil {
		wantOpens := int32(0)
		if *expect.Forwarded {
			wantOpens = 1
		}
		if opens != wantOpens {
			r.fatalf("%s, want %d OPEN(s) at the fake client", describe, wantOpens)
		}
	}
}
