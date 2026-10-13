package server

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
)

// A runtime token belongs to the account it was issued for, not to the account's name
// (protocol/spec/client-auth.md). These tests reconnect a machine with the clientSessionId and
// accessToken of an earlier HTTP login after an admin deleted or renamed its account and created a
// new account under the old name: the token must never log in as that new account, nor receive its
// public /http traffic.

const (
	tokenAccountAPIKey  = "ck_token_account"
	tokenAccountSecret  = "token-account-secret"
	tokenAccountMachine = "token-account-machine"
	tokenAccountOSUser  = "token-account-user"
)

type tokenAccountFixture struct {
	t          *testing.T
	app        *App
	port       int
	ts         *httptest.Server
	token      string
	httpClient *http.Client
	opened     atomic.Int32

	runtime    clientAuthLoginForTestResponse
	clientID   int64
	clientName string
}

func newTokenAccountFixture(t *testing.T) *tokenAccountFixture {
	t.Helper()
	cfg := config.Default()
	cfg.HTTP.RouteCacheTTLms = 0
	app, port := startTestAppWithConfig(t, cfg)
	_, ts := newHTTPTestServer(t, app)
	f := &tokenAccountFixture{t: t, app: app, port: port, ts: ts, token: adminToken(t, ts),
		httpClient: &http.Client{Timeout: 10 * time.Second}}
	f.admin(http.MethodPost, "/api/admin/client-credentials", map[string]any{
		"apiKey": tokenAccountAPIKey, "secret": tokenAccountSecret, "maxOnlineInstances": 2,
	}, http.StatusCreated, nil)
	f.runtime = clientAuthLoginForTest(t, ts.URL, tokenAccountAPIKey, tokenAccountSecret,
		tokenAccountMachine, tokenAccountOSUser)
	f.clientID = findClient(t, listClients(t, ts, f.token), f.runtime.ClientName).ID
	f.clientName = f.runtime.ClientName
	return f
}

func (f *tokenAccountFixture) admin(method, path string, body any, wantStatus int, out any) {
	f.t.Helper()
	payload := ""
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			f.t.Fatal(err)
		}
		payload = string(encoded)
	}
	resp := authRequest(f.t, f.ts, method, path, f.token, payload)
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		f.t.Fatalf("%s %s = %d %s, want %d", method, path, resp.StatusCode, data, wantStatus)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			f.t.Fatalf("decode %s %s: %v", method, path, err)
		}
	}
}

func (f *tokenAccountFixture) createRoute(clientID int64, route string) {
	f.t.Helper()
	f.admin(http.MethodPost, "/api/admin/clients/"+itoa(clientID)+"/http-routes", map[string]any{
		"route": route, "targetBaseUrl": "http://127.0.0.1:18080", "enabled": true,
	}, http.StatusCreated, nil)
}

// createClient creates an admin-managed account of that name and returns its id.
func (f *tokenAccountFixture) createClient(name string) int64 {
	f.t.Helper()
	var created struct {
		Client struct {
			ID         int64  `json:"id"`
			ClientName string `json:"clientName"`
		} `json:"client"`
	}
	f.admin(http.MethodPost, "/api/admin/clients", map[string]any{"clientName": name}, http.StatusCreated, &created)
	if created.Client.ClientName != name || created.Client.ID == f.clientID {
		f.t.Fatalf("created client = %+v, want a new account named %q", created.Client, name)
	}
	return created.Client.ID
}

// tokenAccountConnection is one reconnect of the machine: the control login's answer and, when
// it was accepted, the control connection's NAT_CONTROL pushes and channels that close with each
// connection.
type tokenAccountConnection struct {
	answer        protocol.LoginResponse
	pushes        chan string
	controlClosed <-chan struct{}
	dataClosed    <-chan struct{}
}

// connect reconnects the machine with the clientSessionId and accessToken of its HTTP login,
// sending loginName as the LOGIN_REQUEST clientName. The data connection logs in only when the
// control login was accepted, and must then be accepted too.
func (f *tokenAccountFixture) connect(loginName string) tokenAccountConnection {
	f.t.Helper()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(f.port))
	request := protocol.LoginRequest{
		ClientName:      loginName,
		ClientSessionID: f.runtime.ClientSessionID,
		AccessToken:     f.runtime.AccessToken,
		ConnectionRole:  protocol.ConnectionRoleControl,
	}
	login := func(role string) (net.Conn, *bufio.Reader, protocol.LoginResponse) {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			f.t.Fatal(err)
		}
		f.t.Cleanup(func() { _ = conn.Close() })
		request.ConnectionRole = role
		if err := protocol.WritePacket(conn, request); err != nil {
			f.t.Fatal(err)
		}
		reader := bufio.NewReader(conn)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		packet, err := readProtocolPacket(reader)
		if err != nil {
			f.t.Fatalf("read %s login answer: %v", role, err)
		}
		_ = conn.SetReadDeadline(time.Time{})
		answer, ok := packet.(protocol.LoginResponse)
		if !ok {
			f.t.Fatalf("%s login answered %#v, want LOGIN_RESPONSE", role, packet)
		}
		return conn, reader, answer
	}
	control, controlReader, answer := login(protocol.ConnectionRoleControl)
	connection := tokenAccountConnection{answer: answer}
	if !answer.Success {
		_ = control.Close()
		return connection
	}
	connection.pushes = make(chan string, 16)
	connection.controlClosed = collectNatControlPushes(controlReader, connection.pushes)
	data, dataReader, dataAnswer := login(protocol.ConnectionRoleData)
	if !dataAnswer.Success {
		f.t.Fatalf("data login after an accepted control login = %#v", dataAnswer)
	}
	connection.dataClosed = serveFakeForwardingClient(data, dataReader, &f.opened)
	return connection
}

func (f *tokenAccountFixture) awaitClosed(what string, closed ...<-chan struct{}) {
	f.t.Helper()
	deadline := time.After(5 * time.Second)
	for _, channel := range closed {
		select {
		case <-channel:
		case <-deadline:
			f.t.Fatalf("%s: connections still open 5 s later", what)
		}
	}
}

func (f *tokenAccountFixture) awaitPush(pushes <-chan string) map[string]json.RawMessage {
	f.t.Helper()
	select {
	case message := <-pushes:
		var bean map[string]json.RawMessage
		if err := json.Unmarshal([]byte(message), &bean); err != nil {
			f.t.Fatalf("decode NAT_CONTROL %s: %v", message, err)
		}
		return bean
	case <-time.After(5 * time.Second):
		f.t.Fatal("no NAT_CONTROL within 5 s")
		return nil
	}
}

// get requests /http/{client}/{route}/ and returns the status and how many OPENs reached the fake client.
func (f *tokenAccountFixture) get(client, route string) (int, int32) {
	f.t.Helper()
	before := f.opened.Load()
	resp, err := f.httpClient.Get(f.ts.URL + "/http/" + url.PathEscape(client) + "/" + url.PathEscape(route) + "/")
	if err != nil {
		f.t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, f.opened.Load() - before
}

func TestDeletedClientTokenCannotLogInAsNewAccountOfTheSameName(t *testing.T) {
	f := newTokenAccountFixture(t)
	f.createRoute(f.clientID, "web")
	first := f.connect(f.clientName)
	if !first.answer.Success {
		t.Fatalf("first login = %#v", first.answer)
	}
	f.awaitPush(first.pushes)

	f.admin(http.MethodDelete, "/api/admin/clients/"+itoa(f.clientID), nil, http.StatusNoContent, nil)
	f.awaitClosed("delete", first.controlClosed, first.dataClosed)
	replacement := f.createClient(f.clientName)
	f.createRoute(replacement, "web")

	// The machine reconnects as it would after any network drop: same session id, same token.
	again := f.connect(f.clientName)
	if again.answer.Success {
		t.Fatalf("token of the deleted account logged in again as %q: %#v", again.answer.ClientName, again.answer)
	}
	if _, bound := f.app.sessions.Find(f.clientName); bound {
		t.Fatalf("a connection is bound under %q after the refused login", f.clientName)
	}
	status, opens := f.get(f.clientName, "web")
	if (status != http.StatusBadGateway && status != http.StatusServiceUnavailable) || opens != 0 {
		t.Fatalf("route of the new %q = %d with %d OPEN(s) at the old machine, want 502/503 and none",
			f.clientName, status, opens)
	}
}

func TestRenamedClientTokenFollowsItsAccountNotTheOldName(t *testing.T) {
	f := newTokenAccountFixture(t)
	f.createRoute(f.clientID, "web")
	first := f.connect(f.clientName)
	if !first.answer.Success {
		t.Fatalf("first login = %#v", first.answer)
	}
	f.awaitPush(first.pushes)

	former := f.clientName
	renamed := former + "-renamed"
	f.admin(http.MethodPut, "/api/admin/clients/"+itoa(f.clientID), map[string]any{"clientName": renamed},
		http.StatusOK, nil)
	f.awaitClosed("rename", first.controlClosed, first.dataClosed)
	bystander := f.createClient(former)
	f.createRoute(bystander, "web")

	// The machine does not know about the rename and still sends its old name: the server binds
	// the connection under the account's current name, as Java and .NET do.
	again := f.connect(former)
	if !again.answer.Success || again.answer.ClientName != renamed {
		t.Fatalf("control login with the renamed account's token = %#v, want success as %q", again.answer, renamed)
	}
	push := f.awaitPush(again.pushes)
	var pushedName string
	_ = json.Unmarshal(push["clientName"], &pushedName)
	if pushedName != renamed {
		t.Fatalf("login NAT_CONTROL clientName = %q, want %q", pushedName, renamed)
	}
	if _, bound := f.app.sessions.Find(former); bound {
		t.Fatalf("the renamed account's machine is bound under its former name %q", former)
	}

	if status, opens := f.get(renamed, "web"); status != http.StatusOK || opens != 1 {
		t.Fatalf("route of the renamed account = %d with %d OPEN(s), want 200 forwarded once", status, opens)
	}
	if status, opens := f.get(former, "web"); (status != http.StatusBadGateway &&
		status != http.StatusServiceUnavailable) || opens != 0 {
		t.Fatalf("route of the new %q = %d with %d OPEN(s) at the renamed machine, want 502/503 and none",
			former, status, opens)
	}
}
