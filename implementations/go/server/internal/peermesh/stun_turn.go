package peermesh

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/stunserver"
)

const (
	stunTurnSoftware            = "shuai-tunnel-standard-stun-turn"
	stunMaxPaddingResponseBytes = 1472
	turnPermissionTTL           = 300 * time.Second
	turnChannelTTL              = 600 * time.Second
	maxRelayBindAttempt         = 128
	peerProbeMagic              = "shuai-peer-mesh"
	peerProbeTypeCheck          = "check"
	peerProbeTypeCheckResponse  = "check-response"
	peerProbeMaxBytes           = 2048
)

type relayProbe struct {
	Magic        string `json:"magic"`
	Type         string `json:"type"`
	SessionID    int64  `json:"sessionId"`
	FromClientID int64  `json:"fromClientId"`
	ToClientID   int64  `json:"toClientId"`
	Token        string `json:"token"`
}

type turnChannelBinding struct {
	Channel   uint16
	Peer      *net.UDPAddr
	ExpiresAt time.Time
}

type relayAllocation struct {
	ID        string
	Client    *net.UDPAddr
	Relay     *net.UDPConn
	RelayAddr *net.UDPAddr
	ClientID  int64
	// GeneralRelay marks allocations that forward arbitrary payloads with standard TURN
	// semantics (public transfer / browser WebRTC) instead of the Peer Mesh specific checks.
	GeneralRelay     bool
	RelayedBytes     atomic.Int64
	QuotaLogged      atomic.Bool
	ExpiresAt        time.Time
	Closed           bool
	Permission       map[string]time.Time
	ChannelsByNumber map[uint16]turnChannelBinding
	ChannelsByPeer   map[string]turnChannelBinding
}

type stunTurnServer struct {
	service              *Service
	logger               *slog.Logger
	mu                   sync.Mutex
	allocations          map[string]*relayAllocation
	allocationByEndpoint map[string]string
	allocationByRelay    map[string]string
	primary              *net.UDPConn
	sockets              map[stunserver.EndpointID]*net.UDPConn
	binding              *stunserver.BindingService
	relayTasks           chan func()
}

type turnAuth struct {
	allowed      bool
	key          []byte
	clientID     int64
	generalRelay bool
}

func (s *Service) RunStunTurn(ctx context.Context) {
	if s == nil || !s.cfg.Enabled {
		return
	}
	server := &stunTurnServer{
		service:              s,
		logger:               s.logger,
		allocations:          make(map[string]*relayAllocation),
		allocationByEndpoint: make(map[string]string),
		allocationByRelay:    make(map[string]string),
	}
	server.run(ctx)
}

func (s *stunTurnServer) run(ctx context.Context) {
	topology, err := s.configureStunTopology()
	if err != nil {
		s.logger.Warn("[peer-mesh] standard STUN/TURN UDP server failed to start",
			"port", s.service.cfg.StunTurnPort, "err", err)
		return
	}
	sockets := make(map[stunserver.EndpointID]*net.UDPConn, len(topology.Endpoints()))
	for _, endpoint := range topology.Endpoints() {
		conn, err := net.ListenUDP("udp", endpoint.Bind)
		if err != nil {
			for _, opened := range sockets {
				_ = opened.Close()
			}
			s.logger.Warn("[peer-mesh] standard STUN/TURN UDP server failed to start",
				"endpoint", endpoint.ID, "bind", endpoint.Bind, "err", err)
			return
		}
		sockets[endpoint.ID] = conn
	}
	s.sockets = sockets
	s.primary = sockets[stunserver.Primary]
	s.binding = stunserver.NewBindingService(
		topology, stunTurnSoftware, !topology.SupportsRFC5780(), stunMaxPaddingResponseBytes)
	s.startRelayWorkers(ctx)

	var wg sync.WaitGroup
	for _, endpoint := range topology.Endpoints() {
		conn := sockets[endpoint.ID]
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.receiveLoop(ctx, conn, endpoint.ID)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.cleanupLoop(ctx)
	}()

	s.logger.Info("[peer-mesh] standard STUN/TURN UDP server listening",
		"endpoints", topology.Describe(), "rfc5780", topology.SupportsRFC5780())
	<-ctx.Done()
	for _, conn := range sockets {
		_ = conn.Close()
	}
	s.closeAllAllocations()
	wg.Wait()
}

// configureStunTopology builds the STUN endpoint topology. 对齐 Java
// StunTurnServer.configureStunSockets：仅当主/备 bind 地址、两个 public 地址与两个端口全部
// 配置时启用 RFC 5780 四端点，否则回退到单 IP 的 basic（primary + alternate port）拓扑。
func (s *stunTurnServer) configureStunTopology() (stunserver.Topology, error) {
	cfg := s.service.cfg
	primaryPort := cfg.StunTurnPort
	alternatePort := s.natProbeAlternatePort()
	primaryBind := net.IPv4zero
	if text := strings.TrimSpace(cfg.StunPrimaryBindAddress); text != "" {
		ip, err := resolveStunIP(text)
		if err != nil {
			return stunserver.Topology{}, fmt.Errorf("stun primary bind address: %w", err)
		}
		primaryBind = ip
	}
	primaryPublic := s.resolvePrimaryAdvertisedIP(primaryBind)
	alternateBindText := strings.TrimSpace(cfg.StunAlternateBindAddress)
	alternatePublicText := strings.TrimSpace(cfg.StunAlternatePublicAddress)
	alternateRequested := alternateBindText != "" || alternatePublicText != ""
	fullConfiguration := strings.TrimSpace(cfg.StunPrimaryBindAddress) != "" &&
		alternateBindText != "" && alternatePublicText != "" &&
		strings.TrimSpace(cfg.PublicAddress) != "" &&
		alternatePort > 0 && alternatePort != primaryPort
	if cfg.StunBehaviorStrict && !fullConfiguration {
		return stunserver.Topology{}, fmt.Errorf(
			"strict RFC 5780 mode requires primary/alternate bind addresses, two public addresses and two ports")
	}
	if alternateRequested && !fullConfiguration {
		s.logger.Warn("[peer-mesh] incomplete RFC 5780 endpoint configuration; falling back to single-IP compatibility mode")
	}
	if fullConfiguration {
		alternateBind, err := resolveStunIP(alternateBindText)
		if err != nil {
			return stunserver.Topology{}, fmt.Errorf("stun alternate bind address: %w", err)
		}
		alternatePublic, err := resolveStunIP(alternatePublicText)
		if err != nil {
			return stunserver.Topology{}, fmt.Errorf("stun alternate public address: %w", err)
		}
		return stunserver.NewRFC5780Topology(
			stunEndpoint(stunserver.Primary, primaryBind, primaryPublic, primaryPort),
			stunEndpoint(stunserver.PrimaryAlternatePort, primaryBind, primaryPublic, alternatePort),
			stunEndpoint(stunserver.AlternatePrimaryPort, alternateBind, alternatePublic, primaryPort),
			stunEndpoint(stunserver.Alternate, alternateBind, alternatePublic, alternatePort))
	}
	var alternate *stunserver.Endpoint
	if alternatePort > 0 && alternatePort != primaryPort {
		value := stunEndpoint(stunserver.PrimaryAlternatePort, primaryBind, primaryPublic, alternatePort)
		alternate = &value
	}
	return stunserver.NewBasicTopology(
		stunEndpoint(stunserver.Primary, primaryBind, primaryPublic, primaryPort), alternate)
}

func stunEndpoint(id stunserver.EndpointID, bindIP, publicIP net.IP, port int) stunserver.Endpoint {
	return stunserver.Endpoint{
		ID:         id,
		Bind:       &net.UDPAddr{IP: append(net.IP(nil), bindIP...), Port: port},
		Advertised: &net.UDPAddr{IP: append(net.IP(nil), publicIP...), Port: port},
	}
}

func resolveStunIP(value string) (net.IP, error) {
	if parsed := net.ParseIP(value); parsed != nil {
		return parsed, nil
	}
	addresses, err := net.LookupIP(value)
	if err != nil || len(addresses) == 0 {
		return nil, fmt.Errorf("cannot resolve %q", value)
	}
	return addresses[0], nil
}

func (s *stunTurnServer) resolvePrimaryAdvertisedIP(bind net.IP) net.IP {
	if text := strings.TrimSpace(s.service.cfg.PublicAddress); text != "" {
		if ip, err := resolveStunIP(text); err == nil {
			return ip
		}
	}
	if bind != nil && !bind.IsUnspecified() {
		return bind
	}
	return s.advertisedIP(&net.UDPAddr{IP: bind})
}

func (s *stunTurnServer) receiveLoop(ctx context.Context, conn *net.UDPConn, incoming stunserver.EndpointID) {
	buf := make([]byte, 65507)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() == nil {
				s.logger.Debug("[peer-mesh] STUN/TURN receive failed", "err", err)
			}
			return
		}
		payload := append([]byte(nil), buf[:n]...)
		if err := s.handle(ctx, conn, incoming, payload, remote); err != nil {
			s.logger.Debug("[peer-mesh] STUN/TURN packet handling failed", "err", err)
		}
	}
}

func (s *stunTurnServer) handle(ctx context.Context, conn *net.UDPConn, incoming stunserver.EndpointID, payload []byte, remote *net.UDPAddr) error {
	if incoming == stunserver.Primary && looksLikeTurnChannelData(payload) {
		return s.handleChannelData(ctx, payload, remote)
	}
	message, err := parseStunMessage(payload)
	if err != nil {
		return nil
	}
	if message.Type == stunBindingRequest {
		return s.bindingRequest(incoming, payload, remote)
	}
	if incoming != stunserver.Primary {
		return s.sendError(conn, remote, *message, errorType(message.Type), 400, "unsupported-endpoint")
	}
	switch message.Type {
	case stunAllocateRequest:
		return s.allocateRequest(ctx, *message, remote)
	case stunRefreshRequest:
		return s.refresh(*message, remote)
	case stunCreatePermissionRequest:
		return s.createPermission(*message, remote)
	case stunChannelBindRequest:
		return s.channelBind(*message, remote)
	case stunSendIndication:
		return s.sendIndication(ctx, *message, remote)
	default:
		return s.sendError(conn, remote, *message, errorType(message.Type), 400, "unsupported-method")
	}
}

// bindingRequest 委托共享 stunserver.BindingService 处理 RFC 5780 的
// CHANGE-REQUEST/RESPONSE-PORT/PADDING，并从 result 指定的端点 socket 回包。
// 对齐 Java StunTurnServer.handle 的 binding 分支。
func (s *stunTurnServer) bindingRequest(incoming stunserver.EndpointID, payload []byte, remote *net.UDPAddr) error {
	if s.binding == nil {
		return nil
	}
	request, err := stunserver.ParseMessage(payload)
	if err != nil {
		return nil
	}
	result, err := s.binding.Process(request, remote, incoming, len(payload))
	if err != nil {
		return err
	}
	packet, err := result.Response.Bytes()
	if err != nil {
		return err
	}
	conn := s.sockets[result.ResponseEndpoint]
	if conn == nil {
		return nil
	}
	s.logger.Debug("[peer-mesh] STUN binding",
		"incoming", incoming, "outgoing", result.ResponseEndpoint, "remote", remote)
	_, err = conn.WriteToUDP(packet, result.ResponseTarget)
	return err
}

func (s *stunTurnServer) allocateRequest(ctx context.Context, request stunMessage, remote *net.UDPAddr) error {
	auth := s.authenticate(request, remote, stunAllocateError)
	if !auth.allowed {
		return nil
	}
	if !request.requestedUDPTransport() {
		return s.sendError(s.primary, remote, request, stunAllocateError, 442, "unsupported-transport")
	}
	if auth.generalRelay {
		if reason := s.generalRelayQuotaRejection(remote); reason != "" {
			// Audit: general relay is driven by a public ICE config, quota rejections must be traceable.
			s.logger.Warn("[peer-mesh][audit] general TURN allocation rejected",
				"client", remote.String(), "reason", reason)
			return s.sendError(s.primary, remote, request, stunAllocateError, 486, reason)
		}
	}
	allocation, err := s.allocateForClient(ctx, remote, auth.clientID, auth.generalRelay)
	if err != nil {
		return s.sendError(s.primary, remote, request, stunAllocateError, 508, "insufficient-capacity")
	}
	response := newStunMessage(stunAllocateSuccess, request.TransactionID,
		newStunAttrXorRelayedAddress(allocation.RelayAddr, request.TransactionID),
		newStunAttrXorMappedAddress(remote, request.TransactionID),
		stunAttrLifetimeValue(s.service.cfg.AllocationTTLSeconds),
		stunAttrSoftwareValue(stunTurnSoftware))
	return s.sendStunWithIntegrity(s.primary, remote, response, auth.key)
}

func (s *stunTurnServer) allocate(ctx context.Context, remote *net.UDPAddr) (*relayAllocation, error) {
	return s.allocateForClient(ctx, remote, 0, false)
}

func (s *stunTurnServer) allocateForClient(ctx context.Context, remote *net.UDPAddr, clientID int64, generalRelay bool) (*relayAllocation, error) {
	var stale *relayAllocation
	s.mu.Lock()
	if id, ok := s.allocationByEndpoint[endpointKey(remote)]; ok {
		if existing := s.allocations[id]; existing != nil && !existing.Closed {
			if time.Now().Before(existing.ExpiresAt) && existing.ClientID == clientID &&
				existing.GeneralRelay == generalRelay {
				existing.Client = cloneUDPAddr(remote)
				existing.ExpiresAt = time.Now().Add(time.Duration(s.service.cfg.AllocationTTLSeconds) * time.Second)
				s.mu.Unlock()
				return existing, nil
			}
			stale = existing
			existing.Closed = true
			delete(s.allocations, existing.ID)
			delete(s.allocationByEndpoint, endpointKey(existing.Client))
			delete(s.allocationByRelay, endpointKey(existing.RelayAddr))
		}
	}
	s.mu.Unlock()
	if stale != nil && stale.Relay != nil {
		_ = stale.Relay.Close()
	}

	relay, err := s.bindRelaySocket()
	if err != nil {
		return nil, err
	}
	allocation := &relayAllocation{
		ID:               randomSuffix(),
		Client:           cloneUDPAddr(remote),
		Relay:            relay,
		RelayAddr:        s.advertisedSocketAddress(relay),
		ClientID:         clientID,
		GeneralRelay:     generalRelay,
		ExpiresAt:        time.Now().Add(time.Duration(s.service.cfg.AllocationTTLSeconds) * time.Second),
		Permission:       make(map[string]time.Time),
		ChannelsByNumber: make(map[uint16]turnChannelBinding),
		ChannelsByPeer:   make(map[string]turnChannelBinding),
	}
	s.mu.Lock()
	s.allocations[allocation.ID] = allocation
	s.allocationByEndpoint[endpointKey(remote)] = allocation.ID
	if s.allocationByRelay == nil {
		s.allocationByRelay = make(map[string]string)
	}
	s.allocationByRelay[endpointKey(allocation.RelayAddr)] = allocation.ID
	s.mu.Unlock()

	go s.relayReceiveLoop(ctx, allocation)
	s.logger.Info("[peer-mesh] TURN allocation created", "client", remote, "relay", allocation.RelayAddr)
	return allocation, nil
}

func (s *stunTurnServer) bindRelaySocket() (*net.UDPConn, error) {
	minPort, maxPort := relayPortRange(s.service.cfg.RelayMinPort, s.service.cfg.RelayMaxPort)
	capacity := maxPort - minPort + 1
	attempts := capacity
	if attempts > maxRelayBindAttempt {
		attempts = maxRelayBindAttempt
	}
	start := relayBindStart(capacity)
	for i := 0; i < attempts; i++ {
		port := minPort + ((start + i) % capacity)
		conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
		if err == nil {
			return conn, nil
		}
	}
	return net.ListenUDP("udp", &net.UDPAddr{Port: 0})
}

func (s *stunTurnServer) refresh(request stunMessage, remote *net.UDPAddr) error {
	auth := s.authenticate(request, remote, stunRefreshError)
	if !auth.allowed {
		return nil
	}
	allocation := s.allocationForRemote(remote)
	if allocation == nil || allocation.ClientID != auth.clientID {
		return s.sendError(s.primary, remote, request, stunRefreshError, 437, "allocation-mismatch")
	}
	lifetime := request.lifetimeSeconds(s.service.cfg.AllocationTTLSeconds)
	if lifetime <= 0 {
		s.closeAllocation(allocation)
	} else {
		allocation.ExpiresAt = time.Now().Add(time.Duration(minInt64(lifetime, s.service.cfg.AllocationTTLSeconds)) * time.Second)
	}
	grantedLifetime := int64(0)
	if lifetime > 0 {
		grantedLifetime = s.service.cfg.AllocationTTLSeconds
	}
	response := newStunMessage(stunRefreshSuccess, request.TransactionID,
		stunAttrLifetimeValue(grantedLifetime),
		stunAttrSoftwareValue(stunTurnSoftware))
	return s.sendStunWithIntegrity(s.primary, remote, response, auth.key)
}

func (s *stunTurnServer) createPermission(request stunMessage, remote *net.UDPAddr) error {
	auth := s.authenticate(request, remote, stunCreatePermissionError)
	if !auth.allowed {
		return nil
	}
	allocation := s.allocationForRemote(remote)
	if allocation == nil || allocation.ClientID != auth.clientID {
		return s.sendError(s.primary, remote, request, stunCreatePermissionError, 437, "allocation-mismatch")
	}
	expires := time.Now().Add(turnPermissionTTL)
	peers := make([]*net.UDPAddr, 0, 4)
	for _, attr := range request.all(stunAttrXorPeerAddress) {
		peer, ok := decodeStunXorAddress(attr.Value, request.TransactionID)
		if !ok {
			continue
		}
		if auth.generalRelay && !isRelayableDestination(peer) {
			s.logger.Warn("[peer-mesh][audit] general TURN permission refused",
				"client", remote.String(), "peer", peer.String())
			return s.sendError(s.primary, remote, request, stunCreatePermissionError, 403, "forbidden-peer-address")
		}
		peers = append(peers, peer)
	}
	s.mu.Lock()
	for _, peer := range peers {
		allocation.Permission[permissionKey(peer)] = expires
	}
	s.mu.Unlock()
	response := newStunMessage(stunCreatePermissionSuccess, request.TransactionID, stunAttrSoftwareValue(stunTurnSoftware))
	return s.sendStunWithIntegrity(s.primary, remote, response, auth.key)
}

func (s *stunTurnServer) channelBind(request stunMessage, remote *net.UDPAddr) error {
	auth := s.authenticate(request, remote, stunChannelBindError)
	if !auth.allowed {
		return nil
	}
	allocation := s.allocationForRemote(remote)
	if allocation == nil || allocation.ClientID != auth.clientID {
		return s.sendError(s.primary, remote, request, stunChannelBindError, 437, "allocation-mismatch")
	}
	channel, okChannel := request.channelNumber()
	peer, okPeer := request.xorPeerAddress()
	if !okChannel || !okPeer {
		return s.sendError(s.primary, remote, request, stunChannelBindError, 400, "invalid-channel-bind")
	}
	if auth.generalRelay && !isRelayableDestination(peer) {
		// ChannelBind implicitly creates a permission, so it needs the same destination policy.
		s.logger.Warn("[peer-mesh][audit] general TURN channel bind refused",
			"client", remote.String(), "peer", peer.String())
		return s.sendError(s.primary, remote, request, stunChannelBindError, 403, "forbidden-peer-address")
	}
	now := time.Now()
	binding := turnChannelBinding{Channel: channel, Peer: cloneUDPAddr(peer), ExpiresAt: now.Add(turnChannelTTL)}
	s.mu.Lock()
	if occupied, ok := allocation.ChannelsByNumber[channel]; ok && occupied.ExpiresAt.After(now) &&
		!sameUDPEndpoint(occupied.Peer, peer) {
		s.mu.Unlock()
		return s.sendError(s.primary, remote, request, stunChannelBindError, 400, "channel-in-use")
	}
	peerKey := endpointKey(peer)
	if previous, ok := allocation.ChannelsByPeer[peerKey]; ok && previous.Channel != channel {
		delete(allocation.ChannelsByNumber, previous.Channel)
	}
	allocation.ChannelsByNumber[channel] = binding
	allocation.ChannelsByPeer[peerKey] = binding
	allocation.Permission[permissionKey(peer)] = now.Add(turnPermissionTTL)
	s.mu.Unlock()
	response := newStunMessage(stunChannelBindSuccess, request.TransactionID, stunAttrSoftwareValue(stunTurnSoftware))
	return s.sendStunWithIntegrity(s.primary, remote, response, auth.key)
}

func (s *stunTurnServer) authenticate(request stunMessage, remote *net.UDPAddr, responseType uint16) turnAuth {
	credentials := s.service.turnCredentials
	if credentials == nil || !credentials.authRequired() {
		return turnAuth{allowed: true}
	}
	username := strings.TrimSpace(request.text(stunAttrUsername))
	realm := strings.TrimSpace(request.text(stunAttrRealm))
	nonce := strings.TrimSpace(request.text(stunAttrNonce))
	if username == "" || nonce == "" || realm != credentials.realm() {
		_ = s.sendTurnAuthError(remote, request, responseType, 401, "unauthorized")
		return turnAuth{}
	}
	if nonce != credentials.nonce {
		_ = s.sendTurnAuthError(remote, request, responseType, 438, "stale-nonce")
		return turnAuth{}
	}
	credential := credentials.credentialForUsername(username)
	if !credentials.usernameCredentialValid(username, credential) {
		_ = s.sendTurnAuthError(remote, request, responseType, 401, "unauthorized")
		return turnAuth{}
	}
	key := credentials.longTermKey(username, credential)
	if !request.verifyMessageIntegrity(key) {
		_ = s.sendTurnAuthError(remote, request, responseType, 401, "bad-message-integrity")
		return turnAuth{}
	}
	return turnAuth{
		allowed:      true,
		key:          key,
		clientID:     credentials.peerMeshClientID(username),
		generalRelay: credentials.isGeneralRelaySubject(username),
	}
}

func (s *stunTurnServer) sendTurnAuthError(remote *net.UDPAddr, request stunMessage, typ uint16, code int, reason string) error {
	credentials := s.service.turnCredentials
	return s.sendStun(s.primary, remote, newStunMessage(typ, request.TransactionID,
		stunAttrErrorCodeValue(code, reason),
		stunAttrSoftwareValue(stunTurnSoftware),
		stunAttrRealmValue(credentials.realm()),
		stunAttrNonceValue(credentials.nonce)))
}

func (s *stunTurnServer) sendIndication(ctx context.Context, indication stunMessage, remote *net.UDPAddr) error {
	allocation := s.allocationForRemote(remote)
	if allocation == nil {
		return nil
	}
	peer, ok := indication.xorPeerAddress()
	if !ok || !s.hasPermission(allocation, peer) {
		return nil
	}
	payload, ok := indication.data()
	if !ok {
		return nil
	}
	target := s.allocationForRelayEndpoint(peer)
	if !s.allowGeneralRelayTraffic(allocation, len(payload)) {
		return nil
	}
	if !s.authorizeRelayPayload(ctx, payload, allocation, target, true) {
		return nil
	}
	_, err := allocation.Relay.WriteToUDP(payload, peer)
	return err
}

func (s *stunTurnServer) handleChannelData(ctx context.Context, packet []byte, remote *net.UDPAddr) error {
	frame, err := parseTurnChannelData(packet)
	if err != nil {
		return nil
	}
	allocation := s.allocationForRemote(remote)
	if allocation == nil {
		return nil
	}
	now := time.Now()
	s.mu.Lock()
	binding, ok := allocation.ChannelsByNumber[frame.Channel]
	s.mu.Unlock()
	target := s.allocationForRelayEndpoint(binding.Peer)
	if !ok || !binding.ExpiresAt.After(now) || !s.hasPermission(allocation, binding.Peer) ||
		!s.allowGeneralRelayTraffic(allocation, len(frame.Payload)) ||
		!s.authorizeRelayPayload(ctx, frame.Payload, allocation, target, true) {
		return nil
	}
	_, err = allocation.Relay.WriteToUDP(frame.Payload, binding.Peer)
	return err
}

// generalRelayQuotaRejection returns a non-empty reason when the general relay admission quota
// is exhausted. Callers hold no lock; the counters are read under s.mu.
func (s *stunTurnServer) generalRelayQuotaRejection(remote *net.UDPAddr) string {
	cfg := s.service.cfg
	if cfg.GeneralRelayMaxAllocations <= 0 {
		return "general-relay-disabled"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	sameAddress := 0
	existingID := s.allocationByEndpoint[endpointKey(remote)]
	for id, item := range s.allocations {
		if item == nil || item.Closed || !item.GeneralRelay || id == existingID {
			continue
		}
		total++
		if remote != nil && item.Client != nil && item.Client.IP.Equal(remote.IP) {
			sameAddress++
		}
	}
	if total >= cfg.GeneralRelayMaxAllocations {
		return "general-relay-allocation-quota"
	}
	if cfg.GeneralRelayMaxAllocationsPerAddr > 0 && sameAddress >= cfg.GeneralRelayMaxAllocationsPerAddr {
		return "general-relay-address-quota"
	}
	return ""
}

// allowGeneralRelayTraffic enforces the per-allocation lifetime byte cap. Peer Mesh allocations
// are unaffected.
//
// There is deliberately no packet-level rate limiting. TURN carries the browser's SCTP-over-DTLS
// (reliable transport); dropping packets to shape the rate wrecks SCTP congestion control and
// retransmission, which was the root cause of "web transfer relay file send fails". Abuse is
// bounded by admission (allocation count / per-address) and total volume: once an allocation
// exceeds max-bytes it is closed so SCTP fails cleanly instead of being dragged into loss.
func (s *stunTurnServer) allowGeneralRelayTraffic(allocation *relayAllocation, bytes int) bool {
	if allocation == nil || !allocation.GeneralRelay {
		return true
	}
	maxBytes := s.service.cfg.GeneralRelayMaxBytes
	total := allocation.RelayedBytes.Add(int64(bytes))
	if maxBytes > 0 && total > maxBytes {
		if allocation.QuotaLogged.CompareAndSwap(false, true) {
			s.logger.Warn("[peer-mesh][audit] general TURN byte quota exhausted, closing allocation",
				"client", allocation.Client.String(), "bytes", total)
			s.closeAllocation(allocation)
		}
		return false
	}
	return true
}

// isRelayableDestination restricts general relay destinations to public unicast addresses so
// the relay cannot be used as a jump host into the server's private network. Peer Mesh mode is
// exempt: local/private deployments legitimately use loopback and site-local relay addresses.
func isRelayableDestination(addr *net.UDPAddr) bool {
	if addr == nil || addr.IP == nil || addr.Port <= 0 {
		return false
	}
	ip := addr.IP
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsPrivate() {
		return false
	}
	// Note: 100.64.0.0/10 is deliberately allowed. It is RFC 6598 carrier-grade NAT; many home
	// and mobile users' public srflx addresses fall in it, and rejecting the whole block would
	// 403 those peers. General relay peers are the browser's real public address, never a mesh
	// virtual IP (which only exists inside the overlay).
	if ip.To4() != nil {
		return true
	}
	// IPv6 ULA fc00::/7
	return len(ip) == net.IPv6len && ip[0]&0xFE != 0xFC
}

func (s *stunTurnServer) authorizeRelayPayload(ctx context.Context, payload []byte,
	source, target *relayAllocation, account bool) bool {
	// General TURN mode (public transfer): the payload is DTLS/SRTP/SCTP or a STUN
	// connectivity check, none of which can pass the Peer Mesh specific checks. Identity was
	// verified at Allocate and the destination at CreatePermission/ChannelBind, and the caller
	// already confirmed the permission, so forward with standard TURN semantics. Outbound the
	// local allocation is source, inbound it is target.
	if (source != nil && source.GeneralRelay) || (target != nil && target.GeneralRelay) {
		return true
	}
	if source == nil || target == nil {
		return false
	}
	identified := s.service.turnCredentials != nil && s.service.turnCredentials.authRequired()
	if identified && (source.ClientID <= 0 || target.ClientID <= 0) {
		return false
	}
	sourceClientID, targetClientID := int64(0), int64(0)
	if identified {
		sourceClientID, targetClientID = source.ClientID, target.ClientID
	}
	if header, ok := ParseDataFrameHeader(payload); ok {
		if account {
			return s.service.AuthorizeRelayFrame(
				ctx, header, sourceClientID, targetClientID, int64(len(payload)))
		}
		return s.service.ValidateRelayFrame(ctx, header, sourceClientID, targetClientID)
	}
	if len(payload) < 2 || len(payload) > peerProbeMaxBytes || payload[0] != '{' || payload[len(payload)-1] != '}' {
		return false
	}
	var probe relayProbe
	if err := json.Unmarshal(payload, &probe); err != nil || probe.Magic != peerProbeMagic {
		return false
	}
	if identified && (probe.FromClientID != sourceClientID || probe.ToClientID != targetClientID) {
		return false
	}
	return s.service.AuthorizeRelayProbe(ctx, probe)
}

func (s *stunTurnServer) relayReceiveLoop(ctx context.Context, allocation *relayAllocation) {
	buf := make([]byte, 65507)
	for {
		n, peer, err := allocation.Relay.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() == nil && !allocation.Closed {
				s.logger.Debug("[peer-mesh] TURN relay receive failed", "err", err)
			}
			return
		}
		if !s.hasPermission(allocation, peer) {
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		source := s.allocationForRelayEndpoint(peer)
		if !s.allowGeneralRelayTraffic(allocation, len(payload)) {
			continue
		}
		if !s.authorizeRelayPayload(ctx, payload, source, allocation, false) {
			continue
		}
		_ = s.dispatchRelayPayload(allocation, peer, payload)
	}
}

func (s *stunTurnServer) dispatchRelayPayload(allocation *relayAllocation, peer *net.UDPAddr, payload []byte) error {
	task := func() {
		now := time.Now()
		s.mu.Lock()
		binding, ok := allocation.ChannelsByPeer[endpointKey(peer)]
		s.mu.Unlock()
		if ok && binding.ExpiresAt.After(now) {
			packet, err := encodeTurnChannelData(binding.Channel, payload)
			if err == nil {
				_, err = s.primary.WriteToUDP(packet, allocation.Client)
			}
			if err != nil {
				s.logger.Debug("[peer-mesh] TURN ChannelData failed", "err", err)
			}
			return
		}
		tx := newStunTransactionID()
		message := newStunMessage(stunDataIndication, tx,
			newStunAttrXorPeerAddress(peer, tx),
			stunAttrDataValue(payload))
		if err := s.sendStun(s.primary, allocation.Client, message); err != nil {
			s.logger.Debug("[peer-mesh] TURN data indication failed", "err", err)
		}
	}
	if s.relayTasks == nil {
		task()
		return nil
	}
	select {
	case s.relayTasks <- task:
	default:
		s.logger.Debug("[peer-mesh] TURN data indication dropped")
	}
	return nil
}

func (s *stunTurnServer) allocationForRemote(remote *net.UDPAddr) *relayAllocation {
	s.mu.Lock()
	id := s.allocationByEndpoint[endpointKey(remote)]
	allocation := s.allocations[id]
	if allocation == nil || allocation.Closed {
		s.mu.Unlock()
		return nil
	}
	if time.Now().After(allocation.ExpiresAt) {
		allocation.Closed = true
		delete(s.allocations, allocation.ID)
		delete(s.allocationByEndpoint, endpointKey(allocation.Client))
		delete(s.allocationByRelay, endpointKey(allocation.RelayAddr))
		s.mu.Unlock()
		if allocation.Relay != nil {
			_ = allocation.Relay.Close()
		}
		return nil
	}
	allocation.Client = cloneUDPAddr(remote)
	s.mu.Unlock()
	return allocation
}

func (s *stunTurnServer) allocationForRelayEndpoint(remote *net.UDPAddr) *relayAllocation {
	if remote == nil {
		return nil
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if id := s.allocationByRelay[endpointKey(remote)]; id != "" {
		if allocation := s.allocations[id]; allocation != nil && !allocation.Closed && now.Before(allocation.ExpiresAt) {
			return allocation
		}
	}
	for _, allocation := range s.allocations {
		if allocation != nil && allocation.RelayAddr != nil && allocation.RelayAddr.Port == remote.Port &&
			!allocation.Closed && now.Before(allocation.ExpiresAt) {
			return allocation
		}
	}
	return nil
}

func (s *stunTurnServer) hasPermission(allocation *relayAllocation, peer *net.UDPAddr) bool {
	if allocation == nil || peer == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	expires := allocation.Permission[permissionKey(peer)]
	return !expires.IsZero() && time.Now().Before(expires)
}

func (s *stunTurnServer) sendStun(conn *net.UDPConn, remote *net.UDPAddr, message stunMessage) error {
	if conn == nil || remote == nil {
		return nil
	}
	_, err := conn.WriteToUDP(message.bytes(), remote)
	return err
}

func (s *stunTurnServer) sendStunWithIntegrity(conn *net.UDPConn, remote *net.UDPAddr, message stunMessage, key []byte) error {
	if conn == nil || remote == nil {
		return nil
	}
	_, err := conn.WriteToUDP(message.bytesWithIntegrity(key), remote)
	return err
}

func (s *stunTurnServer) sendError(conn *net.UDPConn, remote *net.UDPAddr, request stunMessage, typ uint16, code int, reason string) error {
	return s.sendStun(conn, remote, newStunMessage(typ, request.TransactionID,
		stunAttrErrorCodeValue(code, reason),
		stunAttrSoftwareValue(stunTurnSoftware)))
}

func errorType(requestType uint16) uint16 {
	switch requestType {
	case stunBindingRequest:
		return stunBindingError
	case stunAllocateRequest:
		return stunAllocateError
	case stunRefreshRequest:
		return stunRefreshError
	case stunCreatePermissionRequest:
		return stunCreatePermissionError
	case stunChannelBindRequest:
		return stunChannelBindError
	default:
		return stunBindingError
	}
}

func (s *stunTurnServer) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanupExpired()
		}
	}
}

func (s *stunTurnServer) cleanupExpired() {
	now := time.Now()
	var expired []*relayAllocation
	s.mu.Lock()
	for _, allocation := range s.allocations {
		for key, expires := range allocation.Permission {
			if now.After(expires) {
				delete(allocation.Permission, key)
			}
		}
		for channel, binding := range allocation.ChannelsByNumber {
			if now.After(binding.ExpiresAt) {
				delete(allocation.ChannelsByNumber, channel)
				delete(allocation.ChannelsByPeer, endpointKey(binding.Peer))
			}
		}
		if now.After(allocation.ExpiresAt) {
			expired = append(expired, allocation)
		}
	}
	s.mu.Unlock()
	for _, allocation := range expired {
		s.closeAllocation(allocation)
	}
}

func (s *stunTurnServer) closeAllAllocations() {
	s.mu.Lock()
	allocations := make([]*relayAllocation, 0, len(s.allocations))
	for _, allocation := range s.allocations {
		allocations = append(allocations, allocation)
	}
	s.mu.Unlock()
	for _, allocation := range allocations {
		s.closeAllocation(allocation)
	}
}

func (s *stunTurnServer) closeAllocation(allocation *relayAllocation) {
	if allocation == nil {
		return
	}
	s.mu.Lock()
	if allocation.Closed {
		s.mu.Unlock()
		return
	}
	allocation.Closed = true
	delete(s.allocations, allocation.ID)
	delete(s.allocationByEndpoint, endpointKey(allocation.Client))
	delete(s.allocationByRelay, endpointKey(allocation.RelayAddr))
	s.mu.Unlock()
	if allocation.Relay != nil {
		_ = allocation.Relay.Close()
	}
}

func (s *stunTurnServer) startRelayWorkers(ctx context.Context) {
	workers := relayWorkerCount(s.service.cfg.RelayWorkerThreads)
	capacity := s.service.cfg.RelayWorkerQueueCapacity
	if capacity <= 0 {
		capacity = 10000
	}
	s.relayTasks = make(chan func(), capacity)
	for i := 0; i < workers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case task := <-s.relayTasks:
					if task != nil {
						task()
					}
				}
			}
		}()
	}
}

func relayWorkerCount(configured int) int {
	if configured > 0 {
		return configured
	}
	workers := runtime.NumCPU()
	if workers < 2 {
		return 2
	}
	if workers > 8 {
		return 8
	}
	return workers
}

func (s *stunTurnServer) natProbeAlternatePort() int {
	if s.service.cfg.NatProbeAlternatePort > 0 {
		return s.service.cfg.NatProbeAlternatePort
	}
	next := s.service.cfg.StunTurnPort + 1
	if next > 0 && next <= 65535 {
		return next
	}
	return 0
}

func (s *stunTurnServer) advertisedSocketAddress(conn *net.UDPConn) *net.UDPAddr {
	if conn == nil || conn.LocalAddr() == nil {
		return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}
	local := conn.LocalAddr().(*net.UDPAddr)
	return &net.UDPAddr{IP: s.advertisedIP(local), Port: local.Port}
}

func (s *stunTurnServer) advertisedIP(local *net.UDPAddr) net.IP {
	if strings.TrimSpace(s.service.cfg.PublicAddress) != "" {
		if ips, err := net.LookupIP(strings.TrimSpace(s.service.cfg.PublicAddress)); err == nil && len(ips) > 0 {
			return ips[0]
		}
		if ip := net.ParseIP(strings.TrimSpace(s.service.cfg.PublicAddress)); ip != nil {
			return ip
		}
	}
	if local != nil && local.IP != nil && !local.IP.IsUnspecified() {
		return local.IP
	}
	if outbound, err := net.Dial("udp", "8.8.8.8:80"); err == nil {
		defer outbound.Close()
		if addr, ok := outbound.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
			return addr.IP
		}
	}
	return net.IPv4(127, 0, 0, 1)
}

func endpointKey(remote *net.UDPAddr) string {
	if remote == nil {
		return ""
	}
	return net.JoinHostPort(remote.IP.String(), fmt.Sprintf("%d", remote.Port))
}

func permissionKey(remote *net.UDPAddr) string {
	if remote == nil {
		return ""
	}
	return remote.IP.String()
}

func sameUDPEndpoint(left, right *net.UDPAddr) bool {
	return left != nil && right != nil && left.Port == right.Port && left.IP.Equal(right.IP)
}

func cloneUDPAddr(remote *net.UDPAddr) *net.UDPAddr {
	if remote == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), remote.IP...), Port: remote.Port, Zone: remote.Zone}
}

func relayBindStart(capacity int) int {
	if capacity <= 1 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(capacity)))
	if err == nil {
		return int(n.Int64())
	}
	return int(time.Now().UnixNano() % int64(capacity))
}

func relayPortRange(minPort, maxPort int) (int, int) {
	if minPort <= 0 {
		minPort = 49152
	}
	if maxPort <= 0 {
		maxPort = 65535
	}
	if minPort < 1 {
		minPort = 1
	}
	if maxPort > 65535 {
		maxPort = 65535
	}
	if minPort > maxPort {
		minPort, maxPort = maxPort, minPort
	}
	return minPort, maxPort
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
