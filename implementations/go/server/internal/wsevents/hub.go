// Package wsevents implements the /ws/connections WebSocket hub that broadcasts connection
// lifecycle events to authenticated admin clients. Mirrors the C# ConnectionEventsHub.
package wsevents

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/security"
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

// ReceiverAuthorizer optionally applies owner-level filtering inside a tenant.
type ReceiverAuthorizer func(access Access, event Event) bool

// ClusterTransport carries management events between server instances.
type ClusterTransport struct {
	Publish   func(context.Context, string, []byte) error
	Subscribe func(func([]byte))
	Report    func(error)
}

// Hub tracks open admin WebSocket connections and broadcasts events to them.
type Hub struct {
	tickets   *security.WebSocketTicketService
	authorize ReceiverAuthorizer
	mu        sync.Mutex
	sockets   map[*websocket.Conn]Access
	cluster   *ClusterTransport
}

// NewHub builds a hub that authorizes upgrades with validate.
func NewHub(tickets *security.WebSocketTicketService, authorize ReceiverAuthorizer) *Hub {
	return &Hub{tickets: tickets, authorize: authorize, sockets: make(map[*websocket.Conn]Access)}
}

// ConfigureCluster enables shared delivery through a bounded inbound queue.
func (h *Hub) ConfigureCluster(transport ClusterTransport) {
	if transport.Publish == nil || transport.Subscribe == nil {
		return
	}
	h.mu.Lock()
	h.cluster = &transport
	h.mu.Unlock()

	inbound := make(chan []byte, 4096)
	go func() {
		for payload := range inbound {
			h.handleClusterPayload(payload)
		}
	}()
	transport.Subscribe(func(payload []byte) {
		copyOfPayload := append([]byte(nil), payload...)
		select {
		case inbound <- copyOfPayload:
		default:
			if transport.Report != nil {
				transport.Report(errors.New("management cluster event queue is full"))
			}
		}
	})
}

// ServeHTTP handles the /ws/connections upgrade.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ticket, ok := security.ExtractWebSocketTicket(r)
	if !ok {
		w.Header().Set("X-Auth-Reason", "missing ticket")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	claims, err := h.tickets.Consume(r.Context(), ticket, security.WebSocketScopeConnections,
		security.WebSocketRequestAddress(r))
	if err != nil || claims == nil || claims.Username == "" || claims.TenantID == "" {
		w.Header().Set("X-Auth-Reason", "invalid ticket")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	access := Access{Username: claims.Username, TenantID: claims.TenantID, Admin: claims.Admin}
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
	cluster := h.cluster
	h.mu.Unlock()
	if cluster != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = cluster.Publish(ctx, event.TenantID, payload)
		cancel()
		if err == nil {
			return
		}
		if cluster.Report != nil {
			cluster.Report(err)
		}
	}
	h.broadcastLocal(event, payload)
}

func (h *Hub) handleClusterPayload(payload []byte) {
	var event Event
	if err := json.Unmarshal(payload, &event); err != nil || strings.TrimSpace(event.TenantID) == "" ||
		(event.Type != "created" && event.Type != "updated") {
		h.mu.Lock()
		cluster := h.cluster
		h.mu.Unlock()
		if cluster != nil && cluster.Report != nil {
			cluster.Report(errors.New("invalid management cluster event payload"))
		}
		return
	}
	h.broadcastLocal(event, payload)
}

func (h *Hub) broadcastLocal(event Event, payload []byte) {
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
