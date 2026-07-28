package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
)

func TestConnectionEventsWebSocketAuthAndLifecycleBroadcast(t *testing.T) {
	app, ts := newAPIServer(t)
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws/connections"

	rejectCtx, rejectCancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, rejectResp, err := websocket.Dial(rejectCtx, wsURL, nil)
	rejectCancel()
	if err == nil {
		t.Fatal("expected websocket upgrade without token to fail")
	}
	if rejectResp == nil || rejectResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected websocket 403 without token, got response=%v err=%v", rejectResp, err)
	}
	if got := rejectResp.Header.Get("X-Auth-Reason"); got != "missing ticket" {
		t.Fatalf("unexpected auth reason: %q", got)
	}

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 2*time.Second)
	conn, resp, err := websocket.Dial(connectCtx, adminWebSocketURL(t, ts, "connections"), nil)
	connectCancel()
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("websocket upgrade with token failed status=%d err=%v", status, err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "done")

	controlConn, reader := dialAndLogin(t, app, app.ControlPort(), DemoClientName)
	login, ok := readPacket(t, reader).(protocol.LoginResponse)
	if !ok || !login.Success {
		t.Fatalf("expected successful login response, got %#v", login)
	}
	created := readConnectionEvent(t, conn)
	if created.TenantID != "default" {
		t.Fatalf("created tenantId = %q, want default", created.TenantID)
	}
	if created.Type != "created" || created.Connection.ClientName != DemoClientName || !created.Connection.Success {
		t.Fatalf("unexpected created event: %+v", created)
	}
	if created.Connection.ID == 0 || created.Connection.ChannelID == nil || created.Connection.ClientID == nil {
		t.Fatalf("created event missing identity fields: %+v", created)
	}

	if err := controlConn.Close(); err != nil {
		t.Fatalf("close control connection: %v", err)
	}
	updated := readConnectionEvent(t, conn)
	if updated.TenantID != "default" {
		t.Fatalf("updated tenantId = %q, want default", updated.TenantID)
	}
	if updated.Type != "updated" || updated.Connection.ID != created.Connection.ID {
		t.Fatalf("unexpected updated event: created=%+v updated=%+v", created, updated)
	}
	if updated.Connection.DisconnectedAt == nil || updated.Connection.DisconnectReason == nil {
		t.Fatalf("updated event missing disconnect fields: %+v", updated)
	}
}

func readConnectionEvent(t *testing.T, conn *websocket.Conn) connectionEventPayload {
	t.Helper()
	readCtx, readCancel := context.WithTimeout(context.Background(), 3*time.Second)
	messageType, payload, err := conn.Read(readCtx)
	readCancel()
	if err != nil {
		t.Fatalf("read websocket event: %v", err)
	}
	if messageType != websocket.MessageText {
		t.Fatalf("expected text websocket message, got %v", messageType)
	}
	var event connectionEventPayload
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatalf("decode websocket event: %v", err)
	}
	return event
}

type connectionEventPayload struct {
	TenantID   string `json:"tenantId"`
	Type       string `json:"type"`
	Connection struct {
		ID               int64   `json:"id"`
		ClientID         *int64  `json:"clientId"`
		ClientName       string  `json:"clientName"`
		ChannelID        *string `json:"channelId"`
		ConnectedAt      string  `json:"connectedAt"`
		DisconnectedAt   *string `json:"disconnectedAt"`
		Success          bool    `json:"success"`
		DisconnectReason *string `json:"disconnectReason"`
	} `json:"connection"`
}
