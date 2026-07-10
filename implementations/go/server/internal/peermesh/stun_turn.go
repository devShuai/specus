package peermesh

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	stunTurnSoftware    = "shuai-tunnel-standard-stun-turn"
	turnPermissionTTL   = 300 * time.Second
	maxRelayBindAttempt = 128
)

type relayAllocation struct {
	ID         string
	Client     *net.UDPAddr
	Relay      *net.UDPConn
	RelayAddr  *net.UDPAddr
	ExpiresAt  time.Time
	Closed     bool
	Permission map[string]time.Time
}

type stunTurnServer struct {
	service              *Service
	logger               *slog.Logger
	mu                   sync.Mutex
	allocations          map[string]*relayAllocation
	allocationByEndpoint map[string]string
	primary              *net.UDPConn
	alternate            *net.UDPConn
	relayTasks           chan func()
}

type turnAuth struct {
	allowed bool
	key     []byte
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
	}
	server.run(ctx)
}

func (s *stunTurnServer) run(ctx context.Context) {
	primary, err := net.ListenUDP("udp", &net.UDPAddr{Port: s.service.cfg.StunTurnPort})
	if err != nil {
		s.logger.Warn("[peer-mesh] standard STUN/TURN UDP server failed to start",
			"port", s.service.cfg.StunTurnPort, "err", err)
		return
	}
	s.primary = primary
	s.startRelayWorkers(ctx)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.receiveLoop(ctx, primary, "primary")
	}()

	if alternatePort := s.natProbeAlternatePort(); alternatePort > 0 && alternatePort != s.service.cfg.StunTurnPort {
		alternate, err := net.ListenUDP("udp", &net.UDPAddr{Port: alternatePort})
		if err != nil {
			s.logger.Warn("[peer-mesh] standard STUN alternate UDP port unavailable", "port", alternatePort, "err", err)
		} else {
			s.alternate = alternate
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.receiveLoop(ctx, alternate, "alternate")
			}()
			s.logger.Info("[peer-mesh] standard STUN alternate UDP port listening", "port", alternatePort)
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.cleanupLoop(ctx)
	}()

	s.logger.Info("[peer-mesh] standard STUN/TURN UDP server listening", "port", s.service.cfg.StunTurnPort)
	<-ctx.Done()
	_ = primary.Close()
	if s.alternate != nil {
		_ = s.alternate.Close()
	}
	s.closeAllAllocations()
	wg.Wait()
}

func (s *stunTurnServer) receiveLoop(ctx context.Context, conn *net.UDPConn, probeRole string) {
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
		if err := s.handle(ctx, conn, probeRole, payload, remote); err != nil {
			s.logger.Debug("[peer-mesh] STUN/TURN packet handling failed", "err", err)
		}
	}
}

func (s *stunTurnServer) handle(ctx context.Context, conn *net.UDPConn, probeRole string, payload []byte, remote *net.UDPAddr) error {
	message, err := parseStunMessage(payload)
	if err != nil {
		return nil
	}
	switch message.Type {
	case stunBindingRequest:
		return s.binding(conn, probeRole, *message, remote)
	case stunAllocateRequest:
		return s.allocateRequest(ctx, *message, remote)
	case stunRefreshRequest:
		return s.refresh(*message, remote)
	case stunCreatePermissionRequest:
		return s.createPermission(*message, remote)
	case stunSendIndication:
		return s.sendIndication(ctx, *message, remote)
	default:
		return s.sendError(conn, remote, *message, errorType(message.Type), 400, "unsupported-method")
	}
}

func (s *stunTurnServer) binding(conn *net.UDPConn, probeRole string, request stunMessage, remote *net.UDPAddr) error {
	attrs := []stunAttribute{
		newStunAttrXorMappedAddress(remote, request.TransactionID),
		stunAttrSoftwareValue(stunTurnSoftware),
		newStunAttrResponseOrigin(s.advertisedSocketAddress(conn), request.TransactionID),
	}
	if s.alternate != nil {
		attrs = append(attrs, newStunAttrOtherAddress(s.advertisedSocketAddress(s.alternate), request.TransactionID))
	}
	response := newStunMessage(stunBindingSuccess, request.TransactionID, attrs...)
	s.logger.Debug("[peer-mesh] STUN binding", "role", probeRole, "remote", remote)
	return s.sendStun(conn, remote, response)
}

func (s *stunTurnServer) allocateRequest(ctx context.Context, request stunMessage, remote *net.UDPAddr) error {
	auth := s.authenticate(request, remote, stunAllocateError)
	if !auth.allowed {
		return nil
	}
	if !request.requestedUDPTransport() {
		return s.sendError(s.primary, remote, request, stunAllocateError, 442, "unsupported-transport")
	}
	allocation, err := s.allocate(ctx, remote)
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
	var stale *relayAllocation
	s.mu.Lock()
	if id, ok := s.allocationByEndpoint[endpointKey(remote)]; ok {
		if existing := s.allocations[id]; existing != nil && !existing.Closed {
			if time.Now().Before(existing.ExpiresAt) {
				existing.Client = cloneUDPAddr(remote)
				existing.ExpiresAt = time.Now().Add(time.Duration(s.service.cfg.AllocationTTLSeconds) * time.Second)
				s.mu.Unlock()
				return existing, nil
			}
			stale = existing
			existing.Closed = true
			delete(s.allocations, existing.ID)
			delete(s.allocationByEndpoint, endpointKey(existing.Client))
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
		ID:         randomSuffix(),
		Client:     cloneUDPAddr(remote),
		Relay:      relay,
		RelayAddr:  s.advertisedSocketAddress(relay),
		ExpiresAt:  time.Now().Add(time.Duration(s.service.cfg.AllocationTTLSeconds) * time.Second),
		Permission: make(map[string]time.Time),
	}
	s.mu.Lock()
	s.allocations[allocation.ID] = allocation
	s.allocationByEndpoint[endpointKey(remote)] = allocation.ID
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
	if allocation == nil {
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
	if allocation == nil {
		return s.sendError(s.primary, remote, request, stunCreatePermissionError, 437, "allocation-mismatch")
	}
	expires := time.Now().Add(turnPermissionTTL)
	s.mu.Lock()
	for _, attr := range request.all(stunAttrXorPeerAddress) {
		peer, ok := decodeStunXorAddress(attr.Value, request.TransactionID)
		if ok {
			allocation.Permission[permissionKey(peer)] = expires
		}
	}
	s.mu.Unlock()
	response := newStunMessage(stunCreatePermissionSuccess, request.TransactionID, stunAttrSoftwareValue(stunTurnSoftware))
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
	return turnAuth{allowed: true, key: key}
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
	if header, ok := ParseDataFrameHeader(payload); ok && !s.service.AuthorizeRelayFrame(ctx, header, int64(len(payload))) {
		return nil
	}
	_, err := allocation.Relay.WriteToUDP(payload, peer)
	return err
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
		_ = s.dispatchDataIndication(allocation, peer, payload)
	}
}

func (s *stunTurnServer) dispatchDataIndication(allocation *relayAllocation, peer *net.UDPAddr, payload []byte) error {
	task := func() {
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
