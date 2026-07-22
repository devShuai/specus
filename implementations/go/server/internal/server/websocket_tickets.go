package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/security"
)

type adminWebSocketTicketRequest struct {
	Endpoint string `json:"endpoint"`
}

type publicWebSocketTicketRequest struct {
	RoomID      string `json:"roomId"`
	RoomToken   string `json:"roomToken"`
	PeerID      string `json:"peerId"`
	DisplayName string `json:"displayName"`
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
	roomToken := strings.TrimSpace(request.RoomToken)
	if roomID == "" {
		roomID = "nearby"
	}
	if peerID == "" {
		peerID = "web-" + randomDiscoveryID()
	}
	if displayName == "" {
		displayName = "web"
	}
	if len(roomToken) > 512 {
		http.Error(w, "room token is too long", http.StatusBadRequest)
		return
	}
	claims := security.WebSocketTicketClaims{RoomID: roomID, PeerID: peerID, DisplayName: displayName}
	if roomToken != "" {
		digest := sha256.Sum256([]byte(roomToken))
		claims.SharedRoom = true
		claims.RoomKey = "token:" + hex.EncodeToString(digest[:])
	}
	issued, err := a.webSocketTickets.Issue(r.Context(), security.WebSocketScopePublicTransfer,
		security.WebSocketRequestAddress(r), claims)
	if err != nil {
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
