package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
	"github.com/devShuai/specus/implementations/go/server/internal/wsevents"
)

type messageTestSession struct {
	name    string
	sent    chan protocol.Packet
	started chan struct{}
	release <-chan struct{}
	sendErr error
}

func (s *messageTestSession) ClientName() string { return s.name }
func (s *messageTestSession) LoginTimeMs() int64 { return time.Now().UnixMilli() }
func (s *messageTestSession) Send(packet protocol.Packet) error {
	if s.started != nil {
		s.started <- struct{}{}
	}
	if s.release != nil {
		<-s.release
	}
	if s.sent != nil {
		s.sent <- packet
	}
	return s.sendErr
}
func (s *messageTestSession) Close(string) {}

func TestClientMessagesWebSocketUsesCapabilitiesAndRoutesBothDirections(t *testing.T) {
	app, ts := newAPIServer(t)
	account, err := app.db.FindClientByName(context.Background(), DemoClientName)
	if err != nil || account == nil {
		t.Fatalf("find demo client: %v", err)
	}
	now := time.Now().UTC()
	if err := app.db.InsertClientSession(context.Background(), store.ClientSession{
		ID: 990001, TenantID: account.TenantID, CredentialID: 1, IdentityID: 1,
		ClientID: account.ID, ClientName: account.ClientName, TokenHash: "message-session-token",
		Status: auth.StatusNettyOnline, MachineFingerprint: "machine", OSUser: "user",
		MessageSendCapable: true, MessageReceiveCapable: true,
		MessageAttachmentsCapable: true, MessageMediaPreviewCapable: true,
		MessageMaxAttachmentBytes: 512 * 1024 * 1024,
		HTTPLoginAt:               now, NettyConnectedAt: &now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("insert client session: %v", err)
	}
	later := now.Add(time.Second)
	if err := app.db.InsertClientSession(context.Background(), store.ClientSession{
		ID: 990002, TenantID: account.TenantID, CredentialID: 2, IdentityID: 2,
		ClientID: account.ID, ClientName: account.ClientName, TokenHash: "newer-incapable-message-session",
		Status: auth.StatusNettyOnline, MachineFingerprint: "machine-2", OSUser: "user",
		MessageReceiveCapable: false, HTTPLoginAt: later, NettyConnectedAt: &later,
		ExpiresAt: later.Add(time.Hour),
	}); err != nil {
		t.Fatalf("insert newer incapable client session: %v", err)
	}
	fake := &messageTestSession{name: account.ClientName, sent: make(chan protocol.Packet, 1)}
	app.sessions.Replace(fake)

	wsURL := adminWebSocketURL(t, ts, "client-messages")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial client messages: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "bye")
	hello := readClientMessageJSON(t, conn)
	if hello["type"] != "hello" || hello["channel"] != "client-messages" {
		t.Fatalf("hello = %#v", hello)
	}

	command := map[string]any{"type": "message", "messageId": "m1", "toClientName": account.ClientName, "message": "hello client"}
	payload, _ := json.Marshal(command)
	if err := conn.Write(context.Background(), websocket.MessageText, payload); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-fake.sent:
		message, ok := packet.(protocol.MessageResponse)
		if !ok || message.ClientName != "admin:admin" || message.Message != "hello client" ||
			message.MessageType != protocol.MessageTypeClientToClient {
			t.Fatalf("unexpected fallback packet: %#v", packet)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("admin message was not routed to the client")
	}
	written := readClientMessageJSON(t, conn)
	if written["type"] != "written" || written["messageId"] != "m1" {
		t.Fatalf("written = %#v", written)
	}

	if !app.clientMessages.deliverFromClient(*account, "admin:admin", "hello admin") {
		t.Fatal("client-to-admin websocket delivery reported false")
	}
	inbound := readClientMessageJSON(t, conn)
	if inbound["type"] != "message" || inbound["fromClientName"] != account.ClientName || inbound["message"] != "hello admin" {
		t.Fatalf("inbound = %#v", inbound)
	}
}

func TestClientMessagesTargetAccessUsesCaseSensitiveTenantAndOwner(t *testing.T) {
	access := wsevents.Access{Username: "Alice", TenantID: "tenant-a"}
	target := store.ClientAccount{OwnerUsername: "Alice", TenantID: "tenant-a"}
	if !canAccessClient(access, target) {
		t.Fatal("exact tenant/owner identity was rejected")
	}
	target.OwnerUsername = "alice"
	if canAccessClient(access, target) {
		t.Fatal("case-distinct owner was accepted")
	}
	target.OwnerUsername = "Alice"
	target.TenantID = "TENANT-A"
	if canAccessClient(access, target) {
		t.Fatal("case-distinct tenant was accepted")
	}
	access.Admin = true
	if canAccessClient(access, target) {
		t.Fatal("admin crossed a case-distinct tenant boundary")
	}
}

func TestClientMessagesWebSocketRejectsLegacyTokenQueryWithReason(t *testing.T) {
	_, ts := newAPIServer(t)
	response, err := http.Get(ts.URL + "/ws/client-messages?token=invalid")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden || response.Header.Get("X-Auth-Reason") != "missing ticket" {
		t.Fatalf("status/header = %d/%q", response.StatusCode, response.Header.Get("X-Auth-Reason"))
	}
}

func TestClientMessagesReportsWriteFailureWithoutBlockingWebSocket(t *testing.T) {
	app, ts := newAPIServer(t)
	account, err := app.db.FindClientByName(context.Background(), DemoClientName)
	if err != nil || account == nil {
		t.Fatalf("find demo client: %v", err)
	}
	now := time.Now().UTC()
	if err := app.db.InsertClientSession(context.Background(), store.ClientSession{
		ID: 990011, TenantID: account.TenantID, CredentialID: 11, IdentityID: 11,
		ClientID: account.ID, ClientName: account.ClientName, TokenHash: "async-message-session",
		Status: auth.StatusNettyOnline, MachineFingerprint: "async-machine", OSUser: "user",
		MessageReceiveCapable: true, HTTPLoginAt: now, NettyConnectedAt: &now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("insert client session: %v", err)
	}
	release := make(chan struct{}, 1)
	defer close(release)
	started := make(chan struct{}, 1)
	app.sessions.Replace(&messageTestSession{
		name: account.ClientName, started: started, release: release,
		sendErr: errors.New("simulated asynchronous write failure"),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	wsURL := adminWebSocketURL(t, ts, "client-messages")
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	_ = readClientMessageJSON(t, conn)
	payload := []byte(`{"type":"message","messageId":"async-1","toClientName":"` + account.ClientName + `","message":"hello"}`)
	if err := conn.Write(ctx, websocket.MessageText, payload); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("asynchronous control write did not start")
	}
	if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"noop"}`)); err != nil {
		t.Fatal(err)
	}
	next := readClientMessageJSON(t, conn)
	if next["type"] != "error" || next["error"] != "unsupported-type" {
		t.Fatalf("next command response = %#v", next)
	}
	release <- struct{}{}
	failed := readClientMessageJSON(t, conn)
	if failed["type"] != "failed" || failed["messageId"] != "async-1" || failed["error"] != "target-write-failed" {
		t.Fatalf("failed status = %#v", failed)
	}
}

func TestClientMessagesWebSocketRejectsMissingTicketWithReason(t *testing.T) {
	_, ts := newAPIServer(t)
	response, err := http.Get(ts.URL + "/ws/client-messages")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden || response.Header.Get("X-Auth-Reason") != "missing ticket" {
		t.Fatalf("status/header = %d/%q", response.StatusCode, response.Header.Get("X-Auth-Reason"))
	}
}

func TestClientMessagesWebSocketUsesTicketAndJavaUTF16Limit(t *testing.T) {
	_, ts := newAPIServer(t)
	wsURL := adminWebSocketURL(t, ts, "client-messages")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial with bearer header: %v", err)
	}
	defer conn.CloseNow()
	_ = readClientMessageJSON(t, conn)
	// More than 64 KiB in UTF-8, but well below Java's 64K UTF-16-char limit.
	payload := []byte(`{"type":"unsupported","padding":"` + strings.Repeat("中", 22_000) + `"}`)
	if len(payload) <= 64*1024 {
		t.Fatalf("test payload is only %d UTF-8 bytes", len(payload))
	}
	if err := conn.Write(ctx, websocket.MessageText, payload); err != nil {
		t.Fatalf("write UTF-8 payload: %v", err)
	}
	response := readClientMessageJSON(t, conn)
	if response["type"] != "error" || response["error"] != "unsupported-type" {
		t.Fatalf("response = %#v", response)
	}
}

func TestClientMessagesWebSocketClosesOnBinaryMessageLikeJava(t *testing.T) {
	_, ts := newAPIServer(t)
	wsURL := adminWebSocketURL(t, ts, "client-messages")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial client messages: %v", err)
	}
	defer conn.CloseNow()
	_ = readClientMessageJSON(t, conn)
	if err := conn.Write(ctx, websocket.MessageBinary, []byte(`{"type":"message"}`)); err != nil {
		t.Fatalf("write binary message: %v", err)
	}
	_, _, err = conn.Read(ctx)
	if status := websocket.CloseStatus(err); status != websocket.StatusUnsupportedData {
		t.Fatalf("binary close status = %d err=%v, want %d", status, err, websocket.StatusUnsupportedData)
	}
}

func readClientMessageJSON(t *testing.T, conn *websocket.Conn) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, payload, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(payload, &value); err != nil {
		t.Fatal(err)
	}
	return value
}
