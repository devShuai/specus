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
	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
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
	roomRole      string
	sharedRoom    bool
	discoverable  bool
	connectedAt   time.Time
}

func (p discoveryParticipant) sameGroup(other discoveryParticipant) bool {
	return p.roomID == other.roomID && p.roomKey == other.roomKey
}

// sameNet reports the LAN arm of merged visibility: participants behind the same public
// egress address see each other regardless of roomID or roomKey. The empty/"unknown"
// fallback address never forms a net, so clients without a usable address are not
// grouped together.
func (p discoveryParticipant) sameNet(other discoveryParticipant) bool {
	return publicAddressKnown(p.publicAddress) && p.publicAddress == other.publicAddress
}

// sameScope is the merged visibility/reachability predicate: visible across rooms and
// token rooms on the same net, and across nets inside the same token room.
func (p discoveryParticipant) sameScope(other discoveryParticipant) bool {
	return p.sameGroup(other) || p.sameNet(other)
}

func (p discoveryParticipant) groupID() string { return publicTransferGroupID(p.roomID, p.roomKey) }

func (p discoveryParticipant) netID() string { return publicTransferNetID(p.publicAddress) }

func (p discoveryParticipant) effectiveRoomRole() string {
	if p.roomRole == "" {
		return "EDITOR"
	}
	return p.roomRole
}

func (p discoveryParticipant) clusterParticipant() clusterParticipant {
	return clusterParticipant{
		LeaseID: p.leaseID, PeerID: p.peerID, DisplayName: p.displayName,
		RoomID: p.roomID, PublicAddress: p.publicAddress, RoomKey: p.roomKey,
		RoomRole: p.effectiveRoomRole(), SharedRoom: p.sharedRoom,
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
	// revisions keys local roster counters by netID: every roster push to a recipient
	// carries a fresh tick of that recipient's own net counter, so a recipient never
	// sees a regressing revision (aligned with the Java handler).
	revisions map[string]*atomic.Uint64
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
		roomRole:      claims.RoomRole,
		sharedRoom:    claims.SharedRoom,
		discoverable:  claims.Discoverable,
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
		"type": "hello", "peerId": participant.peerID, "displayName": participant.displayName,
		"roomId": participant.roomID, "roomRole": participant.effectiveRoomRole(),
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
	if !participant.discoverable {
		// Hidden peers never register presence and skip the duplicate/name/capacity
		// checks (aligned with the Java handler): they still join the local session
		// table, receive rosters and may initiate signaling.
		h.mu.Lock()
		h.participants[participant.socket] = participant
		h.mu.Unlock()
		return "", 0
	}
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
		if existing.sameScope(participant) && existing.peerID == participant.peerID {
			return duplicateDiscoveryPeerError, 0
		}
		if strings.EqualFold(existing.displayName, participant.displayName) {
			return "client name is already in use", 0
		}
		// Room capacity stays scoped to the token room (sameGroup), matching the Java
		// handler's roomPeerCount.
		if existing.sameGroup(participant) {
			count++
		}
	}
	if count >= limit {
		return "room is full", 0
	}
	h.participants[participant.socket] = participant
	return "", h.nextLocalRevisionLocked(participant.netID())
}

func (h *publicTransferDiscoveryHub) unregister(socket *discoverySocket) {
	h.mu.Lock()
	participant, ok := h.participants[socket]
	delete(h.participants, socket)
	h.mu.Unlock()
	if !ok || !participant.discoverable {
		// Hidden peers never registered presence nor appeared in rosters, so their
		// departure cannot change anyone's roster.
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), h.commandTimeout())
	defer cancel()
	if h.coordination.enabled() {
		revision, err := h.coordination.unregister(ctx, participant.clusterParticipant())
		if err == nil && revision > 0 {
			h.publishRosterPair(ctx, participant, revision)
		}
	} else {
		h.broadcastRoster(ctx, participant, 0)
	}
}

// publishRosterPair pushes a roster event to both audiences of a merged-scope change:
// the participant's token room (groupID) and the participant's network (netID). The
// event revision is only a hint; receivers re-read a consistent snapshot anyway.
func (h *publicTransferDiscoveryHub) publishRosterPair(ctx context.Context, participant discoveryParticipant, revision uint64) {
	_ = h.coordination.publishRoster(ctx, participant.groupID(), revision)
	_ = h.coordination.publishRoster(ctx, participant.netID(), revision)
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
		// Directed routing resolves the target inside the source's merged visibility
		// domain and delivers to the target's group, exactly once (Java parity).
		target, err := h.coordination.findPeer(ctx, source.clusterParticipant(), targetPeerID)
		if err != nil {
			return
		}
		// Hidden peers never register shared presence, so fall back to the source's
		// group when the target does not resolve (keeps legacy same-group reachability).
		route := source.groupID()
		if target != nil {
			route = target.groupID()
		}
		_ = h.coordination.publishText(ctx, route, targetPeerID, source.leaseID, false, encoded)
		return
	}
	for _, participant := range h.snapshot() {
		if participant.sameScope(source) && participant.peerID == targetPeerID {
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
		target, err := h.coordination.findPeer(ctx, source.clusterParticipant(), frame.targetPeerID)
		if err != nil {
			return
		}
		// Same fallback as sendToPeer: unresolved (hidden) targets go to the source group.
		route := source.groupID()
		if target != nil {
			route = target.groupID()
		}
		_ = h.coordination.publishBinary(ctx, route, frame.targetPeerID, payload)
		return
	}
	for _, participant := range h.snapshot() {
		if participant.sameScope(source) && participant.peerID == frame.targetPeerID {
			_ = participant.socket.writeBinary(payload)
			return
		}
	}
}

func (h *publicTransferDiscoveryHub) broadcastRoster(ctx context.Context, group discoveryParticipant, revision uint64) {
	if h.coordination.enabled() {
		h.publishRosterPair(ctx, group, revision)
		return
	}
	h.emitRoster(ctx, group)
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

// emitRoster builds the roster payload per recipient: sameRoom is relative to the
// recipient and must never leak the peer's roomKey itself. Recipients are the merged
// scope (same token room or same net) of the participant whose change triggered the
// broadcast. Cluster roster reads are cached per recipient identity (groupID + netID).
func (h *publicTransferDiscoveryHub) emitRoster(ctx context.Context, scope discoveryParticipant) {
	snapshot := h.snapshot()
	clusterRosters := make(map[string]clusterRoster)
	for _, recipient := range snapshot {
		if !recipient.sameScope(scope) {
			continue
		}
		peers := make([]map[string]any, 0)
		var revision uint64
		if h.coordination.enabled() {
			identity := recipient.groupID() + "\n" + recipient.netID()
			roster, ok := clusterRosters[identity]
			if !ok {
				var err error
				roster, err = h.coordination.roster(ctx, recipient.clusterParticipant())
				if err != nil {
					return
				}
				clusterRosters[identity] = roster
			}
			revision = roster.revision
			for _, peer := range roster.participants {
				peers = append(peers, clusterParticipantView(peer, recipient))
			}
		} else {
			for _, peer := range snapshot {
				if peer.discoverable && peer.sameScope(recipient) {
					peers = append(peers, discoveryParticipantView(peer, recipient))
				}
			}
			revision = h.nextLocalRevision(recipient.netID())
		}
		_ = recipient.socket.write(map[string]any{
			"type": "roster", "roomId": recipient.roomID, "publicAddress": recipient.publicAddress,
			"sharedRoom": recipient.sharedRoom, "rosterRevision": revision, "peers": peers,
		})
	}
}

func discoveryParticipantView(participant, recipient discoveryParticipant) map[string]any {
	return map[string]any{
		"peerId": participant.peerID, "displayName": participant.displayName,
		"roomId": participant.roomID, "publicAddress": participant.publicAddress,
		"sharedRoom": participant.sharedRoom, "roomRole": participant.effectiveRoomRole(),
		"sameRoom":    participant.roomKey == recipient.roomKey,
		"connectedAt": participant.connectedAt.Format(time.RFC3339Nano),
	}
}

func clusterParticipantView(participant clusterParticipant, recipient discoveryParticipant) map[string]any {
	return map[string]any{
		"peerId": participant.PeerID, "displayName": participant.DisplayName,
		"roomId": participant.RoomID, "publicAddress": participant.PublicAddress,
		"sharedRoom": participant.SharedRoom, "roomRole": participant.RoomRole,
		"sameRoom":    participant.RoomKey == recipient.roomKey,
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

// handleClusterEvent matches events by net or by group: roster events are published to
// both audiences of a change, targeted events are keyed by the resolved target's group,
// and untargeted broadcasts stay group-keyed so net strangers never see room traffic.
// The two hash namespaces cannot collide, so one dual check serves all kinds.
func (h *publicTransferDiscoveryHub) handleClusterEvent(event publicTransferClusterEvent) {
	matched := make([]discoveryParticipant, 0)
	for _, participant := range h.snapshot() {
		if participant.netID() == event.groupID || participant.groupID() == event.groupID {
			matched = append(matched, participant)
		}
	}
	if len(matched) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), h.commandTimeout())
	defer cancel()
	switch event.kind {
	case clusterEventKindRoster:
		h.emitRoster(ctx, matched[0])
	case clusterEventKindText:
		if !json.Valid(event.payload) {
			return
		}
		for _, participant := range matched {
			if event.targetPeerID != "" && participant.peerID != event.targetPeerID ||
				event.excludeSource && participant.leaseID == event.sourceLeaseID {
				continue
			}
			_ = participant.socket.writeRaw(websocket.MessageText, event.payload)
		}
	case clusterEventKindBinary:
		for _, participant := range matched {
			if participant.peerID == event.targetPeerID {
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
			groupNets := make(map[string]discoveryParticipant)
			nets := make(map[string]struct{})
			failed := false
			for _, participant := range participants {
				nets[participant.netID()] = struct{}{}
				if !participant.discoverable {
					// Hidden peers never registered presence and have nothing to refresh.
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), h.commandTimeout())
				refreshed, err := h.coordination.refresh(ctx, participant.clusterParticipant())
				cancel()
				if err != nil {
					failed = true
					break
				}
				groupNets[participant.groupID()+"\n"+participant.netID()] = participant
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
			for _, participant := range groupNets {
				ctx, cancel := context.WithTimeout(context.Background(), h.commandTimeout())
				_ = h.coordination.sweep(ctx, participant.groupID(), participant.netID())
				cancel()
			}
			// Expired members' same-net cross-room audiences are outside the swept group's
			// push scope, so top up with one roster publish per local net; the placeholder
			// revision is fine because receivers re-read a consistent snapshot (Java parity).
			for netID := range nets {
				ctx, cancel := context.WithTimeout(context.Background(), h.commandTimeout())
				_ = h.coordination.publishRoster(ctx, netID, 0)
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

func (h *publicTransferDiscoveryHub) nextLocalRevision(netID string) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.nextLocalRevisionLocked(netID)
}

func (h *publicTransferDiscoveryHub) nextLocalRevisionLocked(netID string) uint64 {
	counter := h.revisions[netID]
	if counter == nil {
		counter = &atomic.Uint64{}
		h.revisions[netID] = counter
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

// unknownPublicAddress is trustedClientIP's fallback when no usable client address exists.
const unknownPublicAddress = "unknown"

// publicAddressKnown reports whether a public egress address can anchor net identity:
// the empty string and trustedClientIP's "unknown" fallback must never group clients.
func publicAddressKnown(publicAddress string) bool {
	return publicAddress != "" && publicAddress != unknownPublicAddress
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
	return unknownPublicAddress
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
