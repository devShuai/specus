// Package wsevents implements the /ws/connections WebSocket hub that broadcasts connection
// lifecycle events to authenticated admin clients. Mirrors the C# ConnectionEventsHub.
package wsevents

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// ConnectionView is the JSON shape broadcast for a connection event.
type ConnectionView struct {
	ID                   int64   `json:"id"`
	ClientID             *int64  `json:"clientId"`
	ClientName           string  `json:"clientName"`
	ChannelID            *string `json:"channelId"`
	RemoteAddress        *string `json:"remoteAddress"`
	ConnectedAt          string  `json:"connectedAt"`
	DisconnectedAt       *string `json:"disconnectedAt"`
	Success              bool    `json:"success"`
	FailureReason        *string `json:"failureReason"`
	DisconnectReason     *string `json:"disconnectReason"`
	DisconnectReasonText *string `json:"disconnectReasonText"`
}

// Access is the authenticated management principal associated with one websocket.
type Access struct {
	Username string
	TenantID string
	Admin    bool
}

// Event is a typed connection event ("created" | "updated").
type Event struct {
	TenantID   string         `json:"tenantId,omitempty"`
	Type       string         `json:"type"`
	Connection ConnectionView `json:"connection"`
}

// TokenValidator validates the ?token= query parameter and returns the management principal.
type TokenValidator func(token string) (Access, bool)

// ReceiverAuthorizer optionally applies owner-level filtering inside a tenant.
type ReceiverAuthorizer func(access Access, event Event) bool

// Hub tracks open admin WebSocket connections and broadcasts events to them.
type Hub struct {
	validate  TokenValidator
	authorize ReceiverAuthorizer
	mu        sync.Mutex
	sockets   map[*websocket.Conn]Access
}

// NewHub builds a hub that authorizes upgrades with validate.
func NewHub(validate TokenValidator, authorize ReceiverAuthorizer) *Hub {
	return &Hub{validate: validate, authorize: authorize, sockets: make(map[*websocket.Conn]Access)}
}

// ServeHTTP handles the /ws/connections upgrade.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	access, ok := h.validate(r.URL.Query().Get("token"))
	if !ok {
		w.Header().Set("X-Auth-Reason", "invalid token")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	h.mu.Lock()
	h.sockets[conn] = access
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.sockets, conn)
		h.mu.Unlock()
		conn.Close(websocket.StatusNormalClosure, "bye")
	}()

	// Drain client messages until it disconnects (the SPA only listens).
	for {
		if _, _, err := conn.Read(r.Context()); err != nil {
			return
		}
	}
}

// Broadcast sends an event to all connected admins as a JSON text frame.
func (h *Hub) Broadcast(event Event) {
	payload, err := json.Marshal(event)
	if err != nil {
		return
	}
	h.mu.Lock()
	sockets := make(map[*websocket.Conn]Access, len(h.sockets))
	for socket, access := range h.sockets {
		sockets[socket] = access
	}
	h.mu.Unlock()

	for socket, access := range sockets {
		if event.TenantID != "" && access.TenantID != "" && event.TenantID != access.TenantID {
			continue
		}
		if h.authorize != nil && !h.authorize(access, event) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := socket.Write(ctx, websocket.MessageText, payload); err != nil {
			h.mu.Lock()
			delete(h.sockets, socket)
			h.mu.Unlock()
			socket.Close(websocket.StatusInternalError, "write failed")
		}
		cancel()
	}
}
