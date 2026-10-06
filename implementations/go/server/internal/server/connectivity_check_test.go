package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func connectivityCheckPath(routeID string) string {
	return "/api/admin/http-routes/" + routeID + "/connectivity-check"
}

func readConnectivityBody(t *testing.T, response *http.Response) (map[string]any, string) {
	t.Helper()
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode %q: %v", raw, err)
	}
	return body, string(raw)
}

// Unknown, foreign and not-owned routes answer one identical 404; the body and path are validated
// first; every answer is private and uncacheable.
func TestConnectivityCheckEndpointAuthAndVisibility(t *testing.T) {
	_, ts := newAPIServer(t)
	admin := adminToken(t, ts)
	demo := findClient(t, listClients(t, ts, admin), DemoClientName)
	created := authRequest(t, ts, http.MethodPost, "/api/admin/clients/"+itoa(demo.ID)+"/http-routes", admin,
		`{"route":"check","targetBaseUrl":"http://10.20.30.40:8080/base","enabled":true}`)
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("create route status %d", created.StatusCode)
	}
	var route struct {
		ID int64 `json:"id"`
	}
	_ = json.NewDecoder(created.Body).Decode(&route)
	created.Body.Close()
	routeID := itoa(route.ID)

	anonymous, err := http.Post(ts.URL+connectivityCheckPath(routeID), "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	anonymous.Body.Close()
	if anonymous.StatusCode != http.StatusUnauthorized || anonymous.Header.Get("Cache-Control") != "private, no-store" {
		t.Fatalf("anonymous: %d %v", anonymous.StatusCode, anonymous.Header)
	}

	invalid := authRequest(t, ts, http.MethodPost, connectivityCheckPath(routeID), admin, `{"path":"/../etc"}`)
	if body, _ := readConnectivityBody(t, invalid); invalid.StatusCode != http.StatusBadRequest ||
		body["code"] != "CHECK_REQUEST_INVALID" {
		t.Fatalf("invalid path: %d %v", invalid.StatusCode, body)
	}
	unknownField := authRequest(t, ts, http.MethodPost, connectivityCheckPath(routeID), admin, `{"tenantId":"x"}`)
	unknownField.Body.Close()
	if unknownField.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", unknownField.StatusCode)
	}

	unknown := authRequest(t, ts, http.MethodPost, connectivityCheckPath("987654321"), admin, "")
	_, unknownRaw := readConnectivityBody(t, unknown)
	if unknown.StatusCode != http.StatusNotFound || strings.TrimSpace(unknownRaw) != `{"code":"CHECK_TARGET_NOT_FOUND"}` {
		t.Fatalf("unknown route: %d %s", unknown.StatusCode, unknownRaw)
	}
	notNumeric := authRequest(t, ts, http.MethodPost, connectivityCheckPath("abc"), admin, "")
	notNumeric.Body.Close()
	if notNumeric.StatusCode != http.StatusNotFound {
		t.Fatalf("non-numeric route id: %d", notNumeric.StatusCode)
	}

	created = authRequest(t, ts, http.MethodPost, "/api/admin/users", admin,
		`{"username":"alice","password":"alice-password","role":"USER","enabled":true}`)
	created.Body.Close()
	alice := loginToken(t, ts, "alice", "alice-password")
	foreign := authRequest(t, ts, http.MethodPost, connectivityCheckPath(routeID), alice, "{}")
	_, foreignRaw := readConnectivityBody(t, foreign)
	if foreign.StatusCode != http.StatusNotFound || foreignRaw != unknownRaw {
		t.Fatalf("not-owned route: %d %s, want the unknown-route answer %s", foreign.StatusCode, foreignRaw, unknownRaw)
	}

	// The demo client is not connected: the check runs and stops at the device stage.
	offline := authRequest(t, ts, http.MethodPost, connectivityCheckPath(routeID), admin, `{"path":"/healthz"}`)
	body, raw := readConnectivityBody(t, offline)
	if offline.StatusCode != http.StatusOK || offline.Header.Get("Cache-Control") != "private, no-store" ||
		body["outcome"] != "failed" || body["stoppedAt"] != "device-online" || body["code"] != "DEVICE_OFFLINE" ||
		body["routeId"] != float64(route.ID) || !reflect.DeepEqual(body["requests"], []any{}) {
		t.Fatalf("offline check: %d %s", offline.StatusCode, raw)
	}
	if strings.Contains(raw, "10.20.30.40") || strings.Contains(raw, "healthz") {
		t.Fatalf("check result echoes the target or path: %s", raw)
	}

	// The per-route key is shared by every caller: an immediate second check waits ten seconds.
	again := authRequest(t, ts, http.MethodPost, connectivityCheckPath(routeID), admin, "")
	body, raw = readConnectivityBody(t, again)
	if again.StatusCode != http.StatusTooManyRequests || body["code"] != "CHECK_RATE_LIMITED" ||
		again.Header.Get("Retry-After") != "10" || again.Header.Get("Cache-Control") != "private, no-store" {
		t.Fatalf("rate limited: %d %s %v", again.StatusCode, raw, again.Header)
	}
}

// A probe through a real data connection: the server opens HEAD with the fixed metadata and ends
// the request; the capable client's RST classification decides the target stage and its reason never
// leaves the server; a 401 head is unverified and the server resets the stream instead of reading on.
func TestConnectivityCheckThroughDataChannel(t *testing.T) {
	app, port := startTestApp(t)
	account, err := app.db.FindClientByName(context.Background(), DemoClientName)
	if err != nil || account == nil {
		t.Fatalf("load demo client: account=%+v err=%v", account, err)
	}
	now := time.Now().UTC()
	refusedID, protectedID := auth.NewClientID(), auth.NewClientID()
	for _, route := range []store.HTTPRouteMapping{
		{ID: refusedID, Route: "refused", TargetBaseURL: "http://127.0.0.1:9"},
		{ID: protectedID, Route: "protected", TargetBaseURL: "http://127.0.0.1:8080"},
	} {
		route.TenantID, route.ClientID, route.ClientName = account.TenantID, account.ID, account.ClientName
		route.Enabled, route.CreatedAt, route.UpdatedAt = true, now, now
		if err := app.db.InsertHTTPRoute(context.Background(), route); err != nil {
			t.Fatalf("insert route: %v", err)
		}
	}
	controlConn, dataConn, dataReader := loginHTTPTestChannelsWithCapability(t, app, port, 1)
	defer controlConn.Close()
	defer dataConn.Close()

	const secretReason = "dial tcp 127.0.0.1:9?token=s3cret: connection refused"
	frames := make(chan protocol.NatMessage, 16)
	go func() {
		defer close(frames)
		for {
			packet, err := readProtocolPacket(dataReader)
			if err != nil {
				return
			}
			if message, ok := packet.(protocol.NatMessage); ok {
				frames <- message
			}
		}
	}()
	nextFrame := func() protocol.NatMessage {
		t.Helper()
		select {
		case frame, ok := <-frames:
			if !ok {
				t.Fatal("data connection closed")
			}
			return frame
		case <-time.After(5 * time.Second):
			t.Fatal("no NAT frame from the server")
		}
		return protocol.NatMessage{}
	}
	expectProbe := func(method string) uint32 {
		t.Helper()
		open := nextFrame()
		want := map[string]any{"source": "http", "phase": "request", "method": method,
			"relativePath": "/", "rawQuery": "", "headers": []any{"Accept:*/*", "User-Agent:specus-connectivity-check/1"}}
		for key, value := range want {
			if fmt.Sprint(open.Metadata[key]) != fmt.Sprint(value) {
				t.Fatalf("probe OPEN %s = %v, want %v (%#v)", key, open.Metadata[key], value, open.Metadata)
			}
		}
		if open.Type != protocol.NatOpen || open.Metadata["requestId"] == nil || open.Metadata["contentLength"] != nil {
			t.Fatalf("probe OPEN %#v", open)
		}
		if fin := nextFrame(); fin.Type != protocol.NatFin || fin.StreamID != open.StreamID {
			t.Fatalf("probe request FIN %#v", fin)
		}
		return open.StreamID
	}

	_, management := newHTTPTestServer(t, app)
	admin := adminToken(t, management)
	run := func(routeID int64, device func()) (map[string]any, string) {
		t.Helper()
		done := make(chan *http.Response, 1)
		go func() {
			request, _ := http.NewRequest(http.MethodPost, management.URL+connectivityCheckPath(itoa(routeID)),
				bytes.NewReader(nil))
			request.Header.Set("Authorization", "Bearer "+admin)
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				close(done)
				return
			}
			done <- response
		}()
		device()
		response, ok := <-done
		if !ok {
			t.Fatal("connectivity check request failed")
		}
		return readConnectivityBody(t, response)
	}

	body, raw := run(refusedID, func() {
		streamID := expectProbe("HEAD")
		if err := protocol.WritePacket(dataConn, protocol.NatMessage{Type: protocol.NatRST, StreamID: streamID,
			Value: 26, Metadata: map[string]any{"reason": secretReason, "failure": "connect-refused"}}); err != nil {
			t.Fatal(err)
		}
	})
	if body["outcome"] != "failed" || body["stoppedAt"] != "target-reachable" || body["code"] != "TARGET_CONNECT_REFUSED" ||
		!reflect.DeepEqual(body["requests"], []any{"HEAD"}) {
		t.Fatalf("refused target: %s", raw)
	}
	if strings.Contains(raw, "s3cret") || strings.Contains(raw, "127.0.0.1") {
		t.Fatalf("result leaks the reset reason or target: %s", raw)
	}

	body, raw = run(protectedID, func() {
		streamID := expectProbe("HEAD")
		if err := protocol.WritePacket(dataConn, protocol.NatMessage{Type: protocol.NatOpen, StreamID: streamID,
			Metadata: map[string]any{"source": "http", "phase": "response", "statusCode": 401,
				"headers": []string{"WWW-Authenticate:Basic realm=\"app\""}}}); err != nil {
			t.Fatal(err)
		}
		// The head ends the exchange: the server resets the stream rather than read the body.
		if reset := nextFrame(); reset.Type != protocol.NatRST || reset.StreamID != streamID {
			t.Fatalf("after the head: %#v, want RST", reset)
		}
	})
	if body["outcome"] != "unverified" || body["stoppedAt"] != "access-succeeded" ||
		body["code"] != "ACCESS_AUTH_REQUIRED" || body["statusClass"] != "4xx" {
		t.Fatalf("protected target: %s", raw)
	}
}
