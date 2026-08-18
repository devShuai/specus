package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/coder/websocket"
	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/control"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
	"github.com/devShuai/specus/implementations/go/server/internal/wsevents"
)

const (
	maxClientMessageChars     = 64 * 1024
	maxClientMessageUTF8Bytes = maxClientMessageChars * 3
)

type clientMessageSocket struct {
	conn   *websocket.Conn
	access wsevents.Access
	mu     sync.Mutex
}

type clientMessagesHub struct {
	db              *store.DB
	sessions        *session.Registry
	tickets         *security.WebSocketTicketService
	addressResolver *security.ClientAddressResolver
	logger          *slog.Logger
	mu              sync.Mutex
	sockets         map[string]map[*clientMessageSocket]struct{}
}

func newClientMessagesHub(db *store.DB, sessions *session.Registry, tickets *security.WebSocketTicketService,
	addressResolver *security.ClientAddressResolver, logger *slog.Logger) *clientMessagesHub {
	if logger == nil {
		logger = slog.Default()
	}
	return &clientMessagesHub{
		db: db, sessions: sessions, tickets: tickets, addressResolver: addressResolver, logger: logger,
		sockets: make(map[string]map[*clientMessageSocket]struct{}),
	}
}

func (h *clientMessagesHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ticket, present := security.ExtractWebSocketTicket(r)
	if !present {
		w.Header().Set("X-Auth-Reason", "missing ticket")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	claims, err := h.tickets.Consume(r.Context(), ticket, security.WebSocketScopeClientMessages,
		security.WebSocketRequestAddress(h.addressResolver, r))
	if err != nil || claims == nil || claims.Username == "" || claims.TenantID == "" {
		w.Header().Set("X-Auth-Reason", "invalid ticket")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	access := wsevents.Access{Username: claims.Username, TenantID: claims.TenantID, Admin: claims.Admin}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	// Java's TextMessage limit is String.length() (UTF-16 code units). Allow the
	// maximum possible UTF-8 representation through the transport, then enforce
	// the exact UTF-16 limit below.
	conn.SetReadLimit(maxClientMessageUTF8Bytes)
	socket := &clientMessageSocket{conn: conn, access: access}
	key := adminSocketKey(access.TenantID, access.Username)
	h.mu.Lock()
	if h.sockets[key] == nil {
		h.sockets[key] = make(map[*clientMessageSocket]struct{})
	}
	h.sockets[key][socket] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.unregister(key, socket)
		_ = conn.Close(websocket.StatusNormalClosure, "bye")
	}()
	_ = socket.write(map[string]any{
		"type": "hello", "channel": "client-messages",
		"username": access.Username, "tenantId": access.TenantID,
	})
	for {
		messageType, payload, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		if messageType != websocket.MessageText {
			_ = conn.Close(websocket.StatusUnsupportedData, "text messages only")
			return
		}
		if len(utf16.Encode([]rune(string(payload)))) > maxClientMessageChars {
			_ = conn.Close(websocket.StatusMessageTooBig, "message too large")
			return
		}
		h.handleCommand(r.Context(), socket, payload)
	}
}

func (h *clientMessagesHub) handleCommand(ctx context.Context, socket *clientMessageSocket, payload []byte) {
	var command struct {
		Type         string `json:"type"`
		MessageID    string `json:"messageId"`
		ToClientName string `json:"toClientName"`
		Message      string `json:"message"`
	}
	if json.Unmarshal(payload, &command) != nil {
		_ = socket.write(map[string]any{"type": "error", "error": "invalid-json"})
		return
	}
	fail := func(reason string) {
		_ = socket.write(map[string]any{"type": "error", "error": reason, "messageId": command.MessageID})
	}
	if command.Type != "message" {
		fail("unsupported-type")
		return
	}
	targetName := strings.TrimSpace(command.ToClientName)
	body := strings.TrimSpace(command.Message)
	if targetName == "" || body == "" {
		fail("target-and-message-required")
		return
	}
	target, err := h.db.FindClientByName(ctx, targetName)
	if err != nil || target == nil || !target.Enabled || !canAccessClient(socket.access, *target) {
		fail("target-not-found")
		return
	}
	capable, err := h.db.ClientHasOnlineMessageReceiveCapability(ctx, target.TenantID, target.ID, auth.StatusNettyOnline)
	if err != nil || !capable {
		fail("target-cannot-receive-message")
		return
	}
	bound, online := h.sessions.Find(target.ClientName)
	if !online {
		fail("target-offline")
		return
	}
	response := protocol.MessageResponse{
		ClientName:   "admin:" + socket.access.Username,
		ToClientName: target.ClientName,
		MessageType:  protocol.MessageTypeClientToClient,
		Message:      body,
	}
	go func() {
		if err := bound.Send(response); err != nil {
			h.logger.Warn("admin client-message delivery failed",
				"target", target.ClientName, "err", err)
			_ = socket.write(map[string]any{
				"type": "failed", "messageId": command.MessageID, "error": "target-write-failed",
			})
			return
		}
		_ = socket.write(map[string]any{
			"type": "written", "messageId": command.MessageID,
			"toClientName": target.ClientName, "message": body,
		})
	}()
}

func (h *clientMessagesHub) deliverFromClient(source store.ClientAccount, targetAdminName, body string) bool {
	username := normalizeAdminTarget(targetAdminName)
	if username == "" || strings.TrimSpace(body) == "" {
		return false
	}
	key := adminSocketKey(source.TenantID, username)
	h.mu.Lock()
	sockets := make([]*clientMessageSocket, 0, len(h.sockets[key]))
	for socket := range h.sockets[key] {
		sockets = append(sockets, socket)
	}
	h.mu.Unlock()
	payload := map[string]any{
		"type": "message", "direction": "in",
		"fromClientName": source.ClientName, "toClientName": "admin:" + username,
		"message": body, "createdAt": time.Now().UTC().Format(time.RFC3339Nano),
	}
	delivered := false
	for _, socket := range sockets {
		if socket.write(payload) == nil {
			delivered = true
		}
	}
	return delivered
}

func (h *clientMessagesHub) unregister(key string, socket *clientMessageSocket) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.sockets[key], socket)
	if len(h.sockets[key]) == 0 {
		delete(h.sockets, key)
	}
}

func (s *clientMessageSocket) write(value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.Write(ctx, websocket.MessageText, payload)
}

func adminSocketKey(tenantID, username string) string {
	return strings.TrimSpace(tenantID) + "\n" + strings.TrimSpace(username)
}

func normalizeAdminTarget(value string) string {
	value = strings.TrimSpace(value)
	if len(value) < len("admin:") || !strings.EqualFold(value[:len("admin:")], "admin:") {
		return ""
	}
	return strings.TrimSpace(value[len("admin:"):])
}

func canAccessClient(access wsevents.Access, target store.ClientAccount) bool {
	return access.TenantID == target.TenantID && (access.Admin || access.Username == target.OwnerUsername)
}

func (a *App) handleClientMessage(conn *control.Conn, request protocol.MessageRequest) error {
	switch request.MessageType {
	case protocol.MessageTypeClientToServer, protocol.MessageTypeServerToClient:
		a.logger.Info("client message received", "type", request.MessageType, "client", conn.ClientName())
		return nil
	case protocol.MessageTypeClientToClient:
	default:
		return nil
	}
	if strings.TrimSpace(request.ToClientName) == "" || strings.TrimSpace(request.Message) == "" {
		return nil
	}
	source, err := a.db.FindClientByName(conn.Context(), conn.ClientName())
	if err != nil || source == nil || !source.Enabled {
		return err
	}
	if username := normalizeAdminTarget(request.ToClientName); username != "" {
		a.clientMessages.deliverFromClient(*source, "admin:"+username, request.Message)
		return nil
	}
	target, err := a.db.FindClientByName(conn.Context(), strings.TrimSpace(request.ToClientName))
	if err != nil || target == nil || !target.Enabled {
		return err
	}
	allowed, err := a.peerMesh.CanPeer(conn.Context(), *source, *target)
	if err != nil || !allowed {
		return err
	}
	session, online := a.sessions.Find(target.ClientName)
	if !online {
		return nil
	}
	return session.Send(protocol.MessageResponse{
		ClientName:   source.ClientName,
		ToClientName: target.ClientName,
		MessageType:  protocol.MessageTypeClientToClient,
		Message:      request.Message,
	})
}
