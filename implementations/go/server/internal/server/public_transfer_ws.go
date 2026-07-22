package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"github.com/coder/websocket"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/config"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/security"
)

const (
	maxDiscoveryMessageChars     = 64 * 1024
	maxDiscoveryMessageUTF8Bytes = maxDiscoveryMessageChars * 3
	duplicateDiscoveryPeerError  = "peer id is already connected"
)

type discoveryParticipant struct {
	socket        *discoverySocket
	leaseID       string
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

func (p discoveryParticipant) groupID() string { return publicTransferGroupID(p.roomID, p.roomKey) }

func (p discoveryParticipant) clusterParticipant() clusterParticipant {
	return clusterParticipant{
		LeaseID: p.leaseID, PeerID: p.peerID, DisplayName: p.displayName,
		RoomID: p.roomID, PublicAddress: p.publicAddress, RoomKey: p.roomKey,
		RoomRole: "EDITOR", SharedRoom: p.sharedRoom,
		ConnectedAt: p.connectedAt.Format(time.RFC3339Nano),
	}
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
	tickets      *security.WebSocketTicketService
	mu           sync.Mutex
	participants map[*discoverySocket]discoveryParticipant
	coordination *publicTransferCoordination
	startupErr   error
	refreshStop  chan struct{}
	closeOnce    sync.Once
	revisions    map[string]*atomic.Uint64
}

type publicTransferClientNameAvailability struct {
	ClientName string `json:"clientName"`
	Available  bool   `json:"available"`
}

func newPublicTransferDiscoveryHub(cfg config.PublicTransferConfig, tickets *security.WebSocketTicketService) *publicTransferDiscoveryHub {
	return newPublicTransferDiscoveryHubWithLogger(cfg, tickets, slog.Default())
}

func newPublicTransferDiscoveryHubWithLogger(cfg config.PublicTransferConfig, tickets *security.WebSocketTicketService, logger *slog.Logger) *publicTransferDiscoveryHub {
	coordination, err := newPublicTransferCoordination(cfg, logger)
	hub := &publicTransferDiscoveryHub{
		cfg: cfg, tickets: tickets, participants: make(map[*discoverySocket]discoveryParticipant),
		coordination: coordination, startupErr: err, refreshStop: make(chan struct{}),
		revisions: make(map[string]*atomic.Uint64),
	}
	if err == nil && coordination.enabled() {
		coordination.setListener(hub.handleClusterEvent)
		go hub.refreshClusterPresence()
	}
	return hub
}

func (h *publicTransferDiscoveryHub) checkClientNameAvailability(ctx context.Context,
	requestedClientName, excludePeerID string) (publicTransferClientNameAvailability, error) {
	clientName := strings.TrimSpace(requestedClientName)
	if clientName == "" {
		return publicTransferClientNameAvailability{}, errors.New("client name is required")
	}
	if len(utf16.Encode([]rune(clientName))) > 120 || strings.IndexFunc(clientName, func(r rune) bool {
		return r < 0x20 || r >= 0x7f && r <= 0x9f
	}) >= 0 {
		return publicTransferClientNameAvailability{}, errors.New("client name is invalid")
	}
	excludePeerID = strings.TrimSpace(excludePeerID)
	if h.coordination.enabled() {
		available, err := h.coordination.isClientNameAvailable(ctx, clientName, excludePeerID)
		return publicTransferClientNameAvailability{ClientName: clientName, Available: available}, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, participant := range h.participants {
		if (excludePeerID == "" || participant.peerID != excludePeerID) &&
			strings.EqualFold(participant.displayName, clientName) {
			return publicTransferClientNameAvailability{ClientName: clientName, Available: false}, nil
		}
	}
	return publicTransferClientNameAvailability{ClientName: clientName, Available: true}, nil
}

func (h *publicTransferDiscoveryHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.startupErr != nil {
		http.Error(w, "public transfer coordination unavailable", http.StatusServiceUnavailable)
		return
	}
	ticket, ok := security.ExtractWebSocketTicket(r)
	if !ok {
		w.Header().Set("X-Auth-Reason", "missing ticket")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	claims, err := h.tickets.Consume(r.Context(), ticket, security.WebSocketScopePublicTransfer,
		security.WebSocketRequestAddress(r))
	if err != nil || claims == nil || claims.PeerID == "" || claims.RoomID == "" {
		w.Header().Set("X-Auth-Reason", "invalid ticket")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	conn.SetReadLimit(maxDiscoveryMessageUTF8Bytes)
	socket := &discoverySocket{conn: conn, rateStarted: time.Now()}
	participant := discoveryParticipant{
		socket:        socket,
		leaseID:       randomDiscoveryLeaseID(),
		peerID:        claims.PeerID,
		displayName:   claims.DisplayName,
		roomID:        claims.RoomID,
		publicAddress: trustedClientIP(r),
		roomKey:       claims.RoomKey,
		sharedRoom:    claims.SharedRoom,
		connectedAt:   time.Now().UTC(),
	}
	if !participant.sharedRoom {
		participant.roomKey = "public:" + participant.publicAddress
	}
	registrationError, rosterRevision := h.register(r.Context(), participant)
	if registrationError != "" {
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
		"rosterRevision": rosterRevision,
		"connectedAt":    participant.connectedAt.Format(time.RFC3339Nano),
	})
	h.broadcastRoster(r.Context(), participant, rosterRevision)

	for {
		messageType, payload, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		if !h.allowMessage(r.Context(), socket, participant) {
			_ = socket.write(map[string]any{"type": "error", "error": "rate limited"})
			_ = conn.Close(websocket.StatusPolicyViolation, "rate limited")
			return
		}
		switch messageType {
		case websocket.MessageText:
			if len(utf16.Encode([]rune(string(payload)))) > maxDiscoveryMessageChars {
				_ = conn.Close(websocket.StatusMessageTooBig, "message too large")
				return
			}
			if !h.handleMessage(socket, participant, payload) {
				_ = socket.write(map[string]any{"type": "error", "error": "invalid message"})
			}
		case websocket.MessageBinary:
			frame, decodeErr := decodePublicRelayClientFrame(payload)
			if decodeErr != nil {
				_ = socket.write(map[string]any{"type": "error", "error": "invalid binary relay frame"})
				_ = conn.Close(websocket.StatusPolicyViolation, "invalid binary relay frame")
				return
			}
			h.sendBinaryToPeer(participant, frame)
		default:
			_ = conn.Close(websocket.StatusUnsupportedData, "unsupported message type")
			return
		}
	}
}

func (h *publicTransferDiscoveryHub) register(ctx context.Context, participant discoveryParticipant) (string, uint64) {
	if h.coordination.enabled() {
		registration, err := h.coordination.register(ctx, participant.clusterParticipant(), h.cfg.MaxDiscoveryPeersPerRoom)
		if err != nil {
			return "coordination unavailable", 0
		}
		if registration.err != "" {
			return registration.err, 0
		}
		h.mu.Lock()
		h.participants[participant.socket] = participant
		h.mu.Unlock()
		return "", registration.revision
	}
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
				return duplicateDiscoveryPeerError, 0
			}
			count++
		}
		if strings.EqualFold(existing.displayName, participant.displayName) {
			return "client name is already in use", 0
		}
	}
	if count >= limit {
		return "room is full", 0
	}
	h.participants[participant.socket] = participant
	return "", h.nextLocalRevisionLocked(participant.groupID())
}

func (h *publicTransferDiscoveryHub) unregister(socket *discoverySocket) {
	h.mu.Lock()
	participant, ok := h.participants[socket]
	delete(h.participants, socket)
	h.mu.Unlock()
	if ok {
		ctx, cancel := context.WithTimeout(context.Background(), h.commandTimeout())
		defer cancel()
		if h.coordination.enabled() {
			revision, err := h.coordination.unregister(ctx, participant.clusterParticipant())
			if err == nil && revision > 0 {
				_ = h.coordination.publishRoster(ctx, participant.groupID(), revision)
			}
		} else {
			h.broadcastRoster(ctx, participant, h.nextLocalRevision(participant.groupID()))
		}
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
	if h.coordination.enabled() {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), h.commandTimeout())
		defer cancel()
		_ = h.coordination.publishText(ctx, source.groupID(), targetPeerID, source.leaseID, false, encoded)
		return
	}
	for _, participant := range h.snapshot() {
		if participant.sameGroup(source) && participant.peerID == targetPeerID {
			_ = participant.socket.write(payload)
			return
		}
	}
}

func (h *publicTransferDiscoveryHub) sendBinaryToPeer(source discoveryParticipant, frame publicRelayClientFrame) {
	payload, err := encodePublicRelayServerFrame(frame.targetPeerID, source.peerID, frame.appFrame)
	if err != nil {
		return
	}
	if h.coordination.enabled() {
		ctx, cancel := context.WithTimeout(context.Background(), h.commandTimeout())
		defer cancel()
		_ = h.coordination.publishBinary(ctx, source.groupID(), frame.targetPeerID, payload)
		return
	}
	for _, participant := range h.snapshot() {
		if participant.sameGroup(source) && participant.peerID == frame.targetPeerID {
			_ = participant.socket.writeBinary(payload)
			return
		}
	}
}

func (h *publicTransferDiscoveryHub) broadcastRoster(ctx context.Context, group discoveryParticipant, revision uint64) {
	if h.coordination.enabled() {
		_ = h.coordination.publishRoster(ctx, group.groupID(), revision)
		return
	}
	h.emitRoster(ctx, group, revision)
}

func (h *publicTransferDiscoveryHub) broadcast(group discoveryParticipant, payload any, excludeSource bool) {
	if h.coordination.enabled() {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), h.commandTimeout())
		defer cancel()
		_ = h.coordination.publishText(ctx, group.groupID(), "", group.leaseID, excludeSource, encoded)
		return
	}
	h.broadcastLocal(group, payload, excludeSource, group.leaseID)
}

func (h *publicTransferDiscoveryHub) broadcastLocal(group discoveryParticipant, payload any, excludeSource bool, sourceLeaseID string) {
	for _, participant := range h.snapshot() {
		if !participant.sameGroup(group) || excludeSource && participant.leaseID == sourceLeaseID {
			continue
		}
		_ = participant.socket.write(payload)
	}
}

func (h *publicTransferDiscoveryHub) emitRoster(ctx context.Context, group discoveryParticipant, eventRevision uint64) {
	peers := make([]map[string]any, 0)
	revision := eventRevision
	if h.coordination.enabled() {
		roster, err := h.coordination.roster(ctx, group.groupID())
		if err != nil {
			return
		}
		revision = roster.revision
		for _, participant := range roster.participants {
			peers = append(peers, clusterParticipantView(participant))
		}
	} else {
		for _, participant := range h.snapshot() {
			if participant.sameGroup(group) {
				peers = append(peers, discoveryParticipantView(participant))
			}
		}
	}
	h.broadcastLocal(group, map[string]any{
		"type": "roster", "roomId": group.roomID, "publicAddress": group.publicAddress,
		"sharedRoom": group.sharedRoom, "rosterRevision": revision, "peers": peers,
	}, false, "")
}

func discoveryParticipantView(participant discoveryParticipant) map[string]any {
	return map[string]any{
		"peerId": participant.peerID, "displayName": participant.displayName,
		"roomId": participant.roomID, "publicAddress": participant.publicAddress,
		"sharedRoom": participant.sharedRoom, "roomRole": "EDITOR",
		"connectedAt": participant.connectedAt.Format(time.RFC3339Nano),
	}
}

func clusterParticipantView(participant clusterParticipant) map[string]any {
	return map[string]any{
		"peerId": participant.PeerID, "displayName": participant.DisplayName,
		"roomId": participant.RoomID, "publicAddress": participant.PublicAddress,
		"sharedRoom": participant.SharedRoom, "roomRole": participant.RoomRole,
		"connectedAt": participant.ConnectedAt,
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

func (h *publicTransferDiscoveryHub) allowMessage(ctx context.Context, socket *discoverySocket, participant discoveryParticipant) bool {
	if !h.coordination.enabled() {
		return socket.allow(h.cfg)
	}
	allowed, err := h.coordination.allowRate(ctx, "discovery-message",
		participant.groupID()+"\n"+participant.peerID,
		maxInt(1, h.cfg.DiscoveryMessageRateLimitPerConnection),
		time.Duration(maxInt64(1, h.cfg.DiscoveryMessageRateLimitWindowSeconds))*time.Second)
	return err == nil && allowed
}

func (h *publicTransferDiscoveryHub) handleClusterEvent(event publicTransferClusterEvent) {
	var group discoveryParticipant
	found := false
	for _, participant := range h.snapshot() {
		if participant.groupID() == event.groupID {
			group = participant
			found = true
			break
		}
	}
	if !found {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), h.commandTimeout())
	defer cancel()
	switch event.kind {
	case clusterEventKindRoster:
		h.emitRoster(ctx, group, event.revision)
	case clusterEventKindText:
		if !json.Valid(event.payload) {
			return
		}
		for _, participant := range h.snapshot() {
			if participant.groupID() != event.groupID ||
				event.targetPeerID != "" && participant.peerID != event.targetPeerID ||
				event.excludeSource && participant.leaseID == event.sourceLeaseID {
				continue
			}
			_ = participant.socket.writeRaw(websocket.MessageText, event.payload)
		}
	case clusterEventKindBinary:
		for _, participant := range h.snapshot() {
			if participant.groupID() == event.groupID && participant.peerID == event.targetPeerID {
				_ = participant.socket.writeBinary(event.payload)
				return
			}
		}
	}
}

func (h *publicTransferDiscoveryHub) refreshClusterPresence() {
	interval := time.Duration(maxInt64(1, h.cfg.PresenceRefreshIntervalMs)) * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-h.refreshStop:
			return
		case <-ticker.C:
			participants := h.snapshot()
			if len(participants) == 0 {
				continue
			}
			groups := make(map[string]struct{})
			failed := false
			for _, participant := range participants {
				ctx, cancel := context.WithTimeout(context.Background(), h.commandTimeout())
				refreshed, err := h.coordination.refresh(ctx, participant.clusterParticipant())
				cancel()
				if err != nil {
					failed = true
					break
				}
				groups[participant.groupID()] = struct{}{}
				if !refreshed {
					h.removeLocal(participant.socket)
					_ = participant.socket.conn.Close(websocket.StatusInternalError, "presence lease lost")
				}
			}
			if failed {
				for _, participant := range h.snapshot() {
					h.removeLocal(participant.socket)
					_ = participant.socket.conn.Close(websocket.StatusInternalError, "coordination unavailable")
				}
				continue
			}
			for groupID := range groups {
				ctx, cancel := context.WithTimeout(context.Background(), h.commandTimeout())
				_ = h.coordination.sweep(ctx, groupID)
				cancel()
			}
		}
	}
}

func (h *publicTransferDiscoveryHub) removeLocal(socket *discoverySocket) {
	h.mu.Lock()
	delete(h.participants, socket)
	h.mu.Unlock()
}

func (h *publicTransferDiscoveryHub) nextLocalRevision(groupID string) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.nextLocalRevisionLocked(groupID)
}

func (h *publicTransferDiscoveryHub) nextLocalRevisionLocked(groupID string) uint64 {
	counter := h.revisions[groupID]
	if counter == nil {
		counter = &atomic.Uint64{}
		h.revisions[groupID] = counter
	}
	return counter.Add(1)
}

func (h *publicTransferDiscoveryHub) commandTimeout() time.Duration {
	return time.Duration(maxInt64(100, h.cfg.RedisCommandTimeoutMs)) * time.Millisecond
}

func (h *publicTransferDiscoveryHub) Close() error {
	var err error
	h.closeOnce.Do(func() {
		close(h.refreshStop)
		if h.coordination != nil {
			err = h.coordination.Close()
		}
	})
	return err
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

func (s *discoverySocket) writeRaw(messageType websocket.MessageType, payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.Write(ctx, messageType, payload)
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

func (s *discoverySocket) writeBinary(payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.Write(ctx, websocket.MessageBinary, payload)
}

func queryValue(r *http.Request, name, fallback string, maxLength int) string {
	value := strings.TrimSpace(r.URL.Query().Get(name))
	if value == "" {
		value = fallback
	}
	return truncateUTF16(value, maxLength)
}

func truncateUTF16(value string, maxLength int) string {
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

func randomDiscoveryLeaseID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return fmt.Sprintf("lease-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(value)
}
