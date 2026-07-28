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
	if claims.SharedRoom || claims.RoomKey != "" {
		t.Fatalf("unexpected shared-room claims: %+v", claims)
	}
	if claims.RoomRole != string(transfer.RoleEditor) {
		t.Fatalf("roomRole = %q, want EDITOR", claims.RoomRole)
	}
}
