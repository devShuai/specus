package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/coder/websocket"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/config"
)

const (
	maxDiscoveryMessageChars     = 64 * 1024
	maxDiscoveryMessageUTF8Bytes = maxDiscoveryMessageChars * 3
	duplicateDiscoveryPeerError  = "peer id is already connected"
)

type discoveryParticipant struct {
	socket        *discoverySocket
	peerID        string
	displayName   string
	roomID        string
	publicAddress string
	roomKey       string
	sharedRoom    bool
	connectedAt   time.Time
}

func (p discoveryParticipant) sameGroup(other discoveryParticipant) bool {
	return p.roomID == other.roomID && p.roomKey == other.roomKey
}

type discoverySocket struct {
	conn        *websocket.Conn
	mu          sync.Mutex
	rateMu      sync.Mutex
	rateStarted time.Time
	rateCount   int
}

type publicTransferDiscoveryHub struct {
	cfg          config.PublicTransferConfig
	mu           sync.Mutex
	participants map[*discoverySocket]discoveryParticipant
}

func newPublicTransferDiscoveryHub(cfg config.PublicTransferConfig) *publicTransferDiscoveryHub {
	return &publicTransferDiscoveryHub{cfg: cfg, participants: make(map[*discoverySocket]discoveryParticipant)}
}

func (h *publicTransferDiscoveryHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	conn.SetReadLimit(maxDiscoveryMessageUTF8Bytes)
	socket := &discoverySocket{conn: conn, rateStarted: time.Now()}
	participant := discoveryParticipant{
		socket:        socket,
		peerID:        queryValue(r, "peerId", "web-"+randomDiscoveryID(), 120),
		displayName:   queryValue(r, "displayName", "web", 120),
		roomID:        queryValue(r, "roomId", "nearby", 120),
		publicAddress: trustedClientIP(r),
		connectedAt:   time.Now().UTC(),
	}
	roomToken := queryValue(r, "roomToken", "", 512)
	participant.sharedRoom = roomToken != ""
	if participant.sharedRoom {
		digest := sha256.Sum256([]byte(roomToken))
		participant.roomKey = "token:" + hex.EncodeToString(digest[:])
	} else {
		participant.roomKey = "public:" + participant.publicAddress
	}
	if registrationError := h.register(participant); registrationError != "" {
		_ = socket.write(map[string]any{"type": "error", "error": registrationError})
		_ = conn.Close(websocket.StatusPolicyViolation, registrationError)
		return
	}
	defer func() {
		h.unregister(socket)
		_ = conn.Close(websocket.StatusNormalClosure, "bye")
	}()
	_ = socket.write(map[string]any{
		"type": "hello", "peerId": participant.peerID, "roomId": participant.roomID,
		"publicAddress": participant.publicAddress, "sharedRoom": participant.sharedRoom,
		"connectedAt": participant.connectedAt.Format(time.RFC3339Nano),
	})
	h.broadcastRoster(participant)

	for {
		messageType, payload, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		if messageType != websocket.MessageText {
			_ = conn.Close(websocket.StatusUnsupportedData, "text messages only")
			return
		}
		if len(utf16.Encode([]rune(string(payload)))) > maxDiscoveryMessageChars {
			_ = conn.Close(websocket.StatusMessageTooBig, "message too large")
			return
		}
		if !socket.allow(h.cfg) {
			_ = socket.write(map[string]any{"type": "error", "error": "rate limited"})
			_ = conn.Close(websocket.StatusPolicyViolation, "rate limited")
			return
		}
		if !h.handleMessage(socket, participant, payload) {
			_ = socket.write(map[string]any{"type": "error", "error": "invalid message"})
		}
	}
}

func (h *publicTransferDiscoveryHub) register(participant discoveryParticipant) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	limit := h.cfg.MaxDiscoveryPeersPerRoom
	if limit < 1 {
		limit = 1
	}
	count := 0
	for _, existing := range h.participants {
		if existing.sameGroup(participant) {
			if existing.peerID == participant.peerID {
				return duplicateDiscoveryPeerError
			}
			count++
		}
	}
	if count >= limit {
		return "room is full"
	}
	h.participants[participant.socket] = participant
	return ""
}

func (h *publicTransferDiscoveryHub) unregister(socket *discoverySocket) {
	h.mu.Lock()
	participant, ok := h.participants[socket]
	delete(h.participants, socket)
	h.mu.Unlock()
	if ok {
		h.broadcastRoster(participant)
	}
}

func (h *publicTransferDiscoveryHub) handleMessage(socket *discoverySocket, source discoveryParticipant, payload []byte) bool {
	if !json.Valid(payload) {
		return false
	}
	var fields map[string]json.RawMessage
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		if json.Unmarshal(trimmed, &fields) != nil {
			return false
		}
	}
	messageType := discoveryJSONText(fields, "type", "signal")
	if messageType == "ping" {
		_ = socket.write(map[string]any{"type": "pong", "ts": time.Now().UTC().Format(time.RFC3339Nano)})
		return true
	}
	targetPeerID := discoveryJSONText(fields, "targetPeerId", "")
	envelope := map[string]any{
		"type": messageType, "sourcePeerId": source.peerID,
		"targetPeerId": nil,
		"roomId":       source.roomID, "publicAddress": source.publicAddress,
		"payload": nil,
	}
	if strings.TrimSpace(targetPeerID) != "" {
		envelope["targetPeerId"] = targetPeerID
	}
	if raw, ok := fields["payload"]; ok {
		envelope["payload"] = raw
	}
	if target, ok := envelope["targetPeerId"].(string); ok {
		h.sendToPeer(source, target, envelope)
	} else {
		h.broadcast(source, envelope, true)
	}
	return true
}

func discoveryJSONText(fields map[string]json.RawMessage, name, fallback string) string {
	raw, ok := fields[name]
	if !ok {
		return fallback
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return fallback
	}
	if raw[0] == '"' {
		var value string
		if json.Unmarshal(raw, &value) == nil {
			return value
		}
		return fallback
	}
	if raw[0] == '{' || raw[0] == '[' {
		return ""
	}
	return string(raw)
}

func (h *publicTransferDiscoveryHub) sendToPeer(source discoveryParticipant, targetPeerID string, payload any) {
	for _, participant := range h.snapshot() {
		if participant.sameGroup(source) && participant.peerID == targetPeerID {
			_ = participant.socket.write(payload)
			return
		}
	}
}

func (h *publicTransferDiscoveryHub) broadcastRoster(group discoveryParticipant) {
	peers := make([]map[string]any, 0)
	for _, participant := range h.snapshot() {
		if !participant.sameGroup(group) {
			continue
		}
		peers = append(peers, map[string]any{
			"peerId": participant.peerID, "displayName": participant.displayName,
			"roomId": participant.roomID, "publicAddress": participant.publicAddress,
			"sharedRoom":  participant.sharedRoom,
			"connectedAt": participant.connectedAt.Format(time.RFC3339Nano),
		})
	}
	h.broadcast(group, map[string]any{
		"type": "roster", "roomId": group.roomID, "publicAddress": group.publicAddress,
		"sharedRoom": group.sharedRoom, "peers": peers,
	}, false)
}

func (h *publicTransferDiscoveryHub) broadcast(group discoveryParticipant, payload any, excludeSource bool) {
	for _, participant := range h.snapshot() {
		if !participant.sameGroup(group) || excludeSource && participant.socket == group.socket {
			continue
		}
		_ = participant.socket.write(payload)
	}
}

func (h *publicTransferDiscoveryHub) snapshot() []discoveryParticipant {
	h.mu.Lock()
	defer h.mu.Unlock()
	result := make([]discoveryParticipant, 0, len(h.participants))
	for _, participant := range h.participants {
		result = append(result, participant)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].connectedAt.Before(result[j].connectedAt) })
	return result
}

func (s *discoverySocket) allow(cfg config.PublicTransferConfig) bool {
	limit := cfg.DiscoveryMessageRateLimitPerConnection
	if limit < 1 {
		limit = 1
	}
	window := time.Duration(cfg.DiscoveryMessageRateLimitWindowSeconds) * time.Second
	if window <= 0 {
		window = time.Second
	}
	now := time.Now()
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	if now.Sub(s.rateStarted) >= window {
		s.rateStarted = now
		s.rateCount = 0
	}
	s.rateCount++
	return s.rateCount <= limit
}

func (s *discoverySocket) write(value any) error {
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

func queryValue(r *http.Request, name, fallback string, maxLength int) string {
	value := strings.TrimSpace(r.URL.Query().Get(name))
	if value == "" {
		value = fallback
	}
	if len(utf16.Encode([]rune(value))) > maxLength {
		units := 0
		var builder strings.Builder
		for _, char := range value {
			charUnits := len(utf16.Encode([]rune{char}))
			if units+charUnits > maxLength {
				break
			}
			builder.WriteRune(char)
			units += charUnits
		}
		value = builder.String()
	}
	return value
}

func trustedClientIP(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-Real-IP")); value != "" {
		return value
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); strings.TrimSpace(forwarded) != "" {
		parts := strings.Split(forwarded, ",")
		if value := strings.TrimSpace(parts[len(parts)-1]); value != "" {
			return value
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if value := strings.TrimSpace(r.RemoteAddr); value != "" {
		return value
	}
	return "unknown"
}

func randomDiscoveryID() string {
	value := make([]byte, 4)
	_, _ = rand.Read(value)
	return hex.EncodeToString(value)
}
