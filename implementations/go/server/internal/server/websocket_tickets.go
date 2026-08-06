package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/transfer"
)

type adminWebSocketTicketRequest struct {
	Endpoint string `json:"endpoint"`
}

type publicWebSocketTicketRequest struct {
	RoomID      string `json:"roomId"`
	RoomToken   string `json:"roomToken"`
	PeerID      string `json:"peerId"`
	DisplayName string `json:"displayName"`
	// Discoverable mirrors the Java ticket resource: absent means visible. It must be
	// declared here because decodeTicketRequest rejects unknown fields.
	Discoverable *bool `json:"discoverable"`
}

func (a *App) handleAdminWebSocketTicket(w http.ResponseWriter, r *http.Request) {
	access, ok := a.api.ValidateConnectionWebSocketToken(requestBearerToken(r))
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var request adminWebSocketTicketRequest
	if !decodeTicketRequest(w, r, &request) {
		return
	}
	var scope string
	switch strings.TrimSpace(request.Endpoint) {
	case security.WebSocketScopeConnections:
		scope = security.WebSocketScopeConnections
	case security.WebSocketScopeClientMessages:
		scope = security.WebSocketScopeClientMessages
	default:
		http.Error(w, "unsupported websocket endpoint", http.StatusBadRequest)
		return
	}
	issued, err := a.webSocketTickets.Issue(r.Context(), scope, security.WebSocketRequestAddress(r),
		security.WebSocketTicketClaims{Username: access.Username, TenantID: access.TenantID, Admin: access.Admin})
	if err != nil {
		a.logger.Error("issue admin websocket ticket failed", "scope", scope, "err", err)
		http.Error(w, "could not issue websocket ticket", http.StatusInternalServerError)
		return
	}
	writeWebSocketTicket(w, issued)
}

func (a *App) handlePublicWebSocketTicket(w http.ResponseWriter, r *http.Request) {
	var request publicWebSocketTicketRequest
	if !decodeTicketRequest(w, r, &request) {
		return
	}
	roomID := truncateUTF16(strings.TrimSpace(request.RoomID), 120)
	peerID := truncateUTF16(strings.TrimSpace(request.PeerID), 120)
	displayName := truncateUTF16(strings.TrimSpace(request.DisplayName), 120)
	roomToken := truncateUTF16(strings.TrimSpace(request.RoomToken), 512)
	if roomID == "" {
		roomID = "nearby"
	}
	if peerID == "" {
		peerID = "web-" + randomDiscoveryID()
	}
	if displayName == "" {
		displayName = "web"
	}
	claims := security.WebSocketTicketClaims{RoomID: roomID, PeerID: peerID, DisplayName: displayName}
	// 缺省可被发现：老客户端不带该字段时保持既有行为（对齐 Java WebSocketTicketResource）。
	claims.Discoverable = request.Discoverable == nil || *request.Discoverable
	// 恒写 publicAddress：取值链与 upgrade 时 trustedClientIP 的重算一致（ticket 已绑定
	// remote-address，两处必然同值），使跨端共库时 Java 节点消费 Go 票据得到相同的
	// netId/groupId（对齐 Java WebSocketTicketResource）。
	claims.PublicAddress = trustedClientIP(r)
	if roomToken != "" {
		// Aligned with Java WebSocketTicketResource: resolve the room credential through the
		// room service (creating the owner room on first use) instead of hashing the token.
		access, err := a.rooms.Resolve(r.Context(), roomID, roomToken, peerID)
		if err != nil {
			a.failRoomResolve(w, err)
			return
		}
		claims.SharedRoom = true
		claims.RoomKey = "room:" + strconv.FormatInt(access.RoomID, 10)
		claims.RoomRole = string(access.Role)
	} else {
		// public 房间恒写 "public:"+publicAddress，与 upgrade 时 public_transfer_ws.go
		// 的重算结果逐字节一致；upgrade 的重算逻辑保留以兼容旧票据。
		claims.RoomKey = "public:" + claims.PublicAddress
		claims.RoomRole = string(transfer.RoleEditor)
	}
	issued, err := a.webSocketTickets.Issue(r.Context(), security.WebSocketScopePublicTransfer,
		security.WebSocketRequestAddress(r), claims)
	if err != nil {
		a.logger.Error("issue public websocket ticket failed", "sharedRoom", claims.SharedRoom, "err", err)
		http.Error(w, "could not issue websocket ticket", http.StatusInternalServerError)
		return
	}
	writeWebSocketTicket(w, issued)
}

func decodeTicketRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return false
	}
	return true
}

func requestBearerToken(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

func writeWebSocketTicket(w http.ResponseWriter, ticket security.IssuedWebSocketTicket) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ticket)
}

// failRoomResolve maps room-service credential errors to the Java status codes
// (ResponseStatusException / GlobalExceptionHandler).
func (a *App) failRoomResolve(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, transfer.ErrForbidden):
		status = http.StatusForbidden
	case errors.Is(err, transfer.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, transfer.ErrConflict):
		status = http.StatusConflict
	case errors.Is(err, transfer.ErrRateLimited):
		status = http.StatusTooManyRequests
	case errors.Is(err, transfer.ErrInternal):
		status = http.StatusInternalServerError
		a.logger.Error("public websocket room resolution failed", "err", err)
	}
	http.Error(w, err.Error(), status)
}
