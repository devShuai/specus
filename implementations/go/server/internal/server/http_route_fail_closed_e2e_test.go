package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
)

// fakeForwardingClient answers every HTTP OPEN on the data channel with 200, the way a client
// that still holds a stale route list keeps forwarding a route name to its local target. It
// counts the OPENs so a test can prove the server never handed a request to the client.
func fakeForwardingClient(t *testing.T, dataConn net.Conn, dataReader *bufio.Reader) *atomic.Int32 {
	t.Helper()
	var opened atomic.Int32
	go func() {
		for {
			packet, err := readProtocolPacket(dataReader)
			if err != nil {
				return
			}
			message, ok := packet.(protocol.NatMessage)
			if !ok || message.Type != protocol.NatOpen || fmt.Sprint(message.Metadata["source"]) != "http" {
				continue
			}
			opened.Add(1)
			_ = protocol.WritePacket(dataConn, protocol.NatMessage{
				Type: protocol.NatOpen, StreamID: message.StreamID,
				Metadata: map[string]any{"source": "http", "phase": "response", "statusCode": 200,
					"headers": []string{"Content-Type:text/plain"}},
			})
			_ = protocol.WritePacket(dataConn, protocol.NatMessage{
				Type: protocol.NatData, StreamID: message.StreamID, Data: []byte("forwarded"),
			})
			_ = protocol.WritePacket(dataConn, protocol.NatMessage{Type: protocol.NatFin, StreamID: message.StreamID})
		}
	}()
	return &opened
}

// awaitHTTPRouteListPush reads NAT_CONTROL pushes until one no longer lists the given route and
// returns its httpSpecusConfigList, or fails when the push omits the field altogether.
func awaitHTTPRouteListPush(t *testing.T, controlConn net.Conn, controlReader *bufio.Reader,
	goneRoute string) []map[string]any {
	t.Helper()
	_ = controlConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer controlConn.SetReadDeadline(time.Time{})
	for {
		packet, err := readProtocolPacket(controlReader)
		if err != nil {
			t.Fatalf("read NAT_CONTROL push: %v", err)
		}
		message, ok := packet.(protocol.MessageResponse)
		if !ok || message.MessageType != protocol.MessageTypeNatControl {
			continue
		}
		var bean map[string]json.RawMessage
		if err := json.Unmarshal([]byte(message.Message), &bean); err != nil {
			t.Fatalf("decode NAT_CONTROL: %v", err)
		}
		raw, present := bean["httpSpecusConfigList"]
		if !present {
			t.Fatalf("NAT_CONTROL omitted httpSpecusConfigList, so the client keeps its stale routes: %s",
				message.Message)
		}
		var routes []map[string]any
		if err := json.Unmarshal(raw, &routes); err != nil {
			t.Fatalf("decode httpSpecusConfigList: %v", err)
		}
		stillListed := false
		for _, route := range routes {
			stillListed = stillListed || route["route"] == goneRoute
		}
		if !stillListed {
			return routes
		}
	}
}

func TestDeletedProtectedRouteFailsClosedWhileClientStillForwards(t *testing.T) {
	cfg := config.Default()
	cfg.HTTP.RouteCacheTTLms = 0
	app, port := startTestAppWithConfig(t, cfg)
	_, ts := newHTTPTestServer(t, app)
	token := adminToken(t, ts)
	demo := findClient(t, listClients(t, ts, token), DemoClientName)

	resp := authRequest(t, ts, http.MethodPost, "/api/admin/clients/"+itoa(demo.ID)+"/http-routes", token,
		`{"route":"web","targetBaseUrl":"http://127.0.0.1:8080","enabled":true,`+
			`"authEnabled":true,"authUsername":"route-user","authPassword":"route-password"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create protected route status = %d", resp.StatusCode)
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	controlConn, controlReader, dataConn, dataReader := loginHTTPTestChannelsWithControlReader(t, app, port)
	defer controlConn.Close()
	defer dataConn.Close()
	opened := fakeForwardingClient(t, dataConn, dataReader)
	httpClient := &http.Client{Timeout: 10 * time.Second}

	anonymous, err := httpClient.Get(ts.URL + "/http/Demo%20client/web/secret")
	if err != nil {
		t.Fatal(err)
	}
	anonymous.Body.Close()
	if anonymous.StatusCode != http.StatusUnauthorized || opened.Load() != 0 {
		t.Fatalf("protected route before delete = %d (opens %d), want 401 and no stream",
			anonymous.StatusCode, opened.Load())
	}

	resp = authRequest(t, ts, http.MethodDelete, "/api/admin/http-routes/"+itoa(created.ID), token, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete route status = %d", resp.StatusCode)
	}
	// Deleting the client's last route must still push an explicit, empty route list.
	if routes := awaitHTTPRouteListPush(t, controlConn, controlReader, "web"); len(routes) != 0 {
		t.Fatalf("httpSpecusConfigList after deleting the last route = %v, want []", routes)
	}

	// The fake client still forwards "web", like a client that missed or ignored the push.
	afterDelete, err := httpClient.Get(ts.URL + "/http/Demo%20client/web/secret")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(afterDelete.Body)
	afterDelete.Body.Close()
	if afterDelete.StatusCode != http.StatusNotFound || opened.Load() != 0 {
		t.Fatalf("deleted protected route = %d %q (opens %d), want 404 and nothing forwarded",
			afterDelete.StatusCode, body, opened.Load())
	}
}

func TestPublicRouteOfDisabledClientIsRefused(t *testing.T) {
	cfg := config.Default()
	cfg.HTTP.RouteCacheTTLms = 0
	app, port := startTestAppWithConfig(t, cfg)
	_, ts := newHTTPTestServer(t, app)
	token := adminToken(t, ts)
	demo := findClient(t, listClients(t, ts, token), DemoClientName)
	resp := authRequest(t, ts, http.MethodPost, "/api/admin/clients/"+itoa(demo.ID)+"/http-routes", token,
		`{"route":"open","targetBaseUrl":"http://127.0.0.1:8080","enabled":true}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create public route status = %d", resp.StatusCode)
	}

	controlConn, dataConn, dataReader := loginHTTPTestChannels(t, app, port)
	defer controlConn.Close()
	defer dataConn.Close()
	opened := fakeForwardingClient(t, dataConn, dataReader)
	httpClient := &http.Client{Timeout: 10 * time.Second}

	enabled, err := httpClient.Get(ts.URL + "/http/Demo%20client/open/")
	if err != nil {
		t.Fatal(err)
	}
	enabled.Body.Close()
	if enabled.StatusCode != http.StatusOK || opened.Load() != 1 {
		t.Fatalf("public route of an enabled client = %d (opens %d), want 200 and one stream",
			enabled.StatusCode, opened.Load())
	}

	// Disable the account behind the API's back so the data channel stays bound, as it can
	// while a kick races a request.
	account, err := app.db.FindClientByName(context.Background(), DemoClientName)
	if err != nil || account == nil {
		t.Fatalf("load demo client: %+v %v", account, err)
	}
	account.Enabled = false
	if err := app.db.UpdateClientAndRenameReferences(context.Background(), *account, account.ClientName); err != nil {
		t.Fatal(err)
	}
	disabled, err := httpClient.Get(ts.URL + "/http/Demo%20client/open/")
	if err != nil {
		t.Fatal(err)
	}
	disabled.Body.Close()
	if disabled.StatusCode != http.StatusNotFound || opened.Load() != 1 {
		t.Fatalf("public route of a disabled client = %d (opens %d), want 404 and nothing forwarded",
			disabled.StatusCode, opened.Load())
	}
}
