package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/transfer"
)

// issuePublicTicket posts a public-transfer ws-ticket request and returns the HTTP response.
func issuePublicTicket(t *testing.T, ts *httptest.Server, body map[string]string) *http.Response {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return postPublicTicket(t, ts, payload)
}

// issuePublicTicketJSON posts a public-transfer ws-ticket request with a raw JSON body
// (for non-string fields such as discoverable) and returns the HTTP response.
func issuePublicTicketJSON(t *testing.T, ts *httptest.Server, body map[string]any) *http.Response {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return postPublicTicket(t, ts, payload)
}

func postPublicTicket(t *testing.T, ts *httptest.Server, payload []byte) *http.Response {
	t.Helper()
	response, err := http.Post(ts.URL+"/api/public/transfer/ws-tickets", "application/json",
		bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("issue public ticket: %v", err)
	}
	return response
}

// consumePublicTicket decodes the issued ticket and consumes it against the loopback address,
// returning the stored claims (mirroring the discovery hub handshake).
func consumePublicTicket(t *testing.T, app *App, response *http.Response) security.WebSocketTicketClaims {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("status = %d, want 200; body=%s", response.StatusCode, payload)
	}
	var issued struct {
		Ticket string `json:"ticket"`
	}
	if err := json.NewDecoder(response.Body).Decode(&issued); err != nil || issued.Ticket == "" {
		t.Fatalf("decode ticket: %v", err)
	}
	claims, err := app.webSocketTickets.Consume(context.Background(), issued.Ticket,
		security.WebSocketScopePublicTransfer, "127.0.0.1")
	if err != nil || claims == nil {
		t.Fatalf("consume ticket: claims=%v err=%v", claims, err)
	}
	return *claims
}

func TestPublicWebSocketTicketResolvesSharedRoomThroughRoomService(t *testing.T) {
	app, ts := newAPIServer(t)

	owner := consumePublicTicket(t, app, issuePublicTicket(t, ts,
		map[string]string{"roomId": "room-x", "roomToken": "owner-secret", "peerId": "peer-1"}))
	if !owner.SharedRoom || !strings.HasPrefix(owner.RoomKey, "room:") {
		t.Fatalf("owner claims: %+v", owner)
	}
	if owner.PublicAddress == "" {
		t.Fatalf("shared-room ticket must carry the issuer public address: %+v", owner)
	}
	if owner.RoomRole != string(transfer.RoleOwner) {
		t.Fatalf("owner roomRole = %q, want OWNER", owner.RoomRole)
	}

	again := consumePublicTicket(t, app, issuePublicTicket(t, ts,
		map[string]string{"roomId": "room-x", "roomToken": "owner-secret", "peerId": "peer-2"}))
	if again.RoomKey != owner.RoomKey {
		t.Fatalf("same credential must resolve to the same room: %q != %q", again.RoomKey, owner.RoomKey)
	}

	other := consumePublicTicket(t, app, issuePublicTicket(t, ts,
		map[string]string{"roomId": "room-x", "roomToken": "different-secret", "peerId": "peer-3"}))
	if other.RoomKey == owner.RoomKey {
		t.Fatal("distinct owner tokens must not share a room key")
	}

	// An invite access token resolves to the owner room with the invite role.
	ctx := context.Background()
	invitee, err := app.rooms.CreateAccessToken(ctx, transfer.CreateAccessTokenRequest{
		RoomID: "room-x", RoomToken: "owner-secret", PeerID: "peer-1", Role: "viewer",
	})
	if err != nil {
		t.Fatalf("create invite token: %v", err)
	}
	invited := consumePublicTicket(t, app, issuePublicTicket(t, ts,
		map[string]string{"roomId": "room-x", "roomToken": invitee.Token, "peerId": "peer-4"}))
	if invited.RoomKey != owner.RoomKey || invited.RoomRole != string(transfer.RoleViewer) {
		t.Fatalf("invited claims: %+v, want room %q role VIEWER", invited, owner.RoomKey)
	}
}

func TestPublicWebSocketTicketRejectsInvalidRoomCredential(t *testing.T) {
	_, ts := newAPIServer(t)
	response := issuePublicTicket(t, ts,
		map[string]string{"roomId": "room-x", "roomToken": "st-editor-unknown", "peerId": "peer-1"})
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("status = %d, want 403; body=%s", response.StatusCode, payload)
	}
}

func TestPublicWebSocketTicketWithoutTokenStaysAddressScoped(t *testing.T) {
	app, ts := newAPIServer(t)
	claims := consumePublicTicket(t, app, issuePublicTicket(t, ts,
		map[string]string{"roomId": "nearby", "peerId": "peer-1"}))
	if claims.SharedRoom {
		t.Fatalf("unexpected shared-room claims: %+v", claims)
	}
	// 恒写 publicAddress 与派生 roomKey：跨端共库时 Java 节点消费 Go 票据能得到
	// 与本地重算一致的 netId/groupId（对齐 Java WebSocketTicketResource）。
	if claims.PublicAddress != "127.0.0.1" || claims.RoomKey != "public:127.0.0.1" {
		t.Fatalf("public ticket claims = %+v, want address-scoped room key", claims)
	}
	if claims.RoomRole != string(transfer.RoleEditor) {
		t.Fatalf("roomRole = %q, want EDITOR", claims.RoomRole)
	}
}

func TestPublicWebSocketTicketParsesDiscoverable(t *testing.T) {
	app, ts := newAPIServer(t)

	// Absent discoverable keeps the legacy always-visible default.
	visible := consumePublicTicket(t, app, issuePublicTicket(t, ts,
		map[string]string{"roomId": "nearby", "peerId": "peer-1"}))
	if !visible.Discoverable {
		t.Fatalf("absent discoverable must default to true: %+v", visible)
	}

	explicit := consumePublicTicket(t, app, issuePublicTicketJSON(t, ts,
		map[string]any{"roomId": "nearby", "peerId": "peer-2", "discoverable": true}))
	if !explicit.Discoverable {
		t.Fatalf("explicit discoverable=true was lost: %+v", explicit)
	}

	hidden := consumePublicTicket(t, app, issuePublicTicketJSON(t, ts,
		map[string]any{"roomId": "nearby", "peerId": "peer-3", "discoverable": false}))
	if hidden.Discoverable {
		t.Fatalf("explicit discoverable=false was lost: %+v", hidden)
	}
}
