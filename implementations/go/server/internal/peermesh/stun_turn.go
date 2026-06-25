package peermesh

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	relayMagic           = "shuai-peer-relay"
	relayTypeBinding     = "binding"
	relayTypeBindingResp = "binding-response"
	relayTypeAllocate    = "allocate"
	relayTypeAllocated   = "allocated"
	relayTypeRefresh     = "refresh"
	relayTypeSend        = "send"
	relayTypeData        = "data"
	relayTypeError       = "error"
	relayProbePrimary    = "primary"
	relayProbeAlternate  = "alternate"
	relayProbeChanged    = "changed-port"
)

type relayMessage struct {
	Magic             string `json:"magic,omitempty"`
	Type              string `json:"type,omitempty"`
	TransactionID     string `json:"transactionId,omitempty"`
	ProbeRole         string `json:"probeRole,omitempty"`
	AllocationID      string `json:"allocationId,omitempty"`
	FromAllocationID  string `json:"fromAllocationId,omitempty"`
	ToAllocationID    string `json:"toAllocationId,omitempty"`
	MappedAddress     string `json:"mappedAddress,omitempty"`
	MappedPort        int    `json:"mappedPort,omitempty"`
	AlternateAddress  string `json:"alternateAddress,omitempty"`
	AlternatePort     int    `json:"alternatePort,omitempty"`
	ObservedByAddress string `json:"observedByAddress,omitempty"`
	ObservedByPort    int    `json:"observedByPort,omitempty"`
	TTLSeconds        int64  `json:"ttlSeconds,omitempty"`
	PayloadBase64     string `json:"payloadBase64,omitempty"`
	Error             string `json:"error,omitempty"`
}

type relayAllocation struct {
	ID        string
	Remote    *net.UDPAddr
	ExpiresAt time.Time
}

type stunTurnServer struct {
	service              *Service
	logger               *slog.Logger
	mu                   sync.Mutex
	allocations          map[string]relayAllocation
	allocationByEndpoint map[string]string
	primary              *net.UDPConn
	alternate            *net.UDPConn
}

func (s *Service) RunStunTurn(ctx context.Context) {
	if s == nil || !s.cfg.Enabled {
		return
	}
	server := &stunTurnServer{
		service:              s,
		logger:               s.logger,
		allocations:          make(map[string]relayAllocation),
		allocationByEndpoint: make(map[string]string),
	}
	server.run(ctx)
}

func (s *stunTurnServer) run(ctx context.Context) {
	primary, err := net.ListenUDP("udp", &net.UDPAddr{Port: s.service.cfg.StunTurnPort})
	if err != nil {
		s.logger.Warn("[peer-mesh] STUN/TURN-lite UDP server failed to start",
			"port", s.service.cfg.StunTurnPort, "err", err)
		return
	}
	s.primary = primary
	defer primary.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.receiveLoop(ctx, primary, relayProbePrimary)
	}()

	if alternatePort := s.natProbeAlternatePort(); alternatePort > 0 && alternatePort != s.service.cfg.StunTurnPort {
		alternate, err := net.ListenUDP("udp", &net.UDPAddr{Port: alternatePort})
		if err != nil {
			s.logger.Warn("[peer-mesh] NAT probe alternate UDP port unavailable", "port", alternatePort, "err", err)
		} else {
			s.alternate = alternate
			defer alternate.Close()
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.receiveLoop(ctx, alternate, relayProbeAlternate)
			}()
			s.logger.Info("[peer-mesh] NAT probe alternate UDP port listening", "port", alternatePort)
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.cleanupLoop(ctx)
	}()

	s.logger.Info("[peer-mesh] STUN/TURN-lite UDP server listening", "port", s.service.cfg.StunTurnPort)
	<-ctx.Done()
	primary.Close()
	if s.alternate != nil {
		s.alternate.Close()
	}
	wg.Wait()
}

func (s *stunTurnServer) receiveLoop(ctx context.Context, conn *net.UDPConn, probeRole string) {
	buf := make([]byte, 65507)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() == nil {
				s.logger.Debug("[peer-mesh] STUN/TURN-lite receive failed", "err", err)
			}
			return
		}
		payload := append([]byte(nil), buf[:n]...)
		if err := s.handle(ctx, conn, probeRole, payload, remote); err != nil {
			s.logger.Debug("[peer-mesh] STUN/TURN-lite packet handling failed", "err", err)
		}
	}
}

func (s *stunTurnServer) handle(ctx context.Context, conn *net.UDPConn, probeRole string, payload []byte, remote *net.UDPAddr) error {
	message := strings.TrimSpace(string(payload))
	if strings.HasPrefix(message, "{") {
		var relay relayMessage
		if err := json.Unmarshal(payload, &relay); err == nil && relay.Magic == relayMagic {
			return s.handleRelay(ctx, conn, probeRole, relay, remote)
		}
	}
	switch {
	case strings.HasPrefix(strings.ToUpper(message), "BINDING"):
		return s.sendText(conn, remote, fmt.Sprintf("MAPPED %s %d", remote.IP.String(), remote.Port))
	case strings.HasPrefix(strings.ToUpper(message), "ALLOCATE"):
		allocation := s.allocate(remote)
		return s.sendText(conn, remote, fmt.Sprintf("ALLOCATED %s %d", allocation.ID, s.service.cfg.AllocationTTLSeconds))
	case strings.HasPrefix(strings.ToUpper(message), "REFRESH "):
		id := strings.TrimSpace(message[len("REFRESH "):])
		return s.sendText(conn, remote, s.refreshText(id, remote))
	default:
		return s.sendText(conn, remote, "ERROR unsupported-command")
	}
}

func (s *stunTurnServer) handleRelay(ctx context.Context, conn *net.UDPConn, probeRole string, msg relayMessage, remote *net.UDPAddr) error {
	switch msg.Type {
	case relayTypeBinding:
		if err := s.sendRelay(conn, remote, s.bindingResponse(msg, remote, conn, probeRole)); err != nil {
			return err
		}
		if probeRole == relayProbePrimary && s.alternate != nil {
			return s.sendRelay(s.alternate, remote, s.bindingResponse(msg, remote, s.alternate, relayProbeChanged))
		}
		return nil
	case relayTypeAllocate:
		allocation := s.allocate(remote)
		return s.sendRelay(s.primary, remote, s.allocatedResponse(msg, allocation.ID))
	case relayTypeRefresh:
		return s.refresh(msg, remote)
	case relayTypeSend:
		return s.relayData(ctx, msg, remote)
	default:
		return s.sendRelay(s.primary, remote, s.errorResponse(msg, "unsupported-command"))
	}
}

func (s *stunTurnServer) refresh(msg relayMessage, remote *net.UDPAddr) error {
	s.mu.Lock()
	allocation, ok := s.allocations[msg.AllocationID]
	if !ok || endpointKey(allocation.Remote) != endpointKey(remote) {
		s.mu.Unlock()
		return s.sendRelay(s.primary, remote, s.errorResponse(msg, "allocation-not-found"))
	}
	allocation.Remote = cloneUDPAddr(remote)
	allocation.ExpiresAt = time.Now().Add(time.Duration(s.service.cfg.AllocationTTLSeconds) * time.Second)
	s.allocations[allocation.ID] = allocation
	s.allocationByEndpoint[endpointKey(remote)] = allocation.ID
	s.mu.Unlock()
	return s.sendRelay(s.primary, remote, s.allocatedResponse(msg, allocation.ID))
}

func (s *stunTurnServer) relayData(ctx context.Context, msg relayMessage, remote *net.UDPAddr) error {
	source := s.sourceAllocation(msg, remote)
	if source == nil {
		return s.sendRelay(s.primary, remote, s.errorResponse(msg, "allocation-not-found"))
	}
	target := s.findAllocation(msg.ToAllocationID)
	if target == nil {
		return s.sendRelay(s.primary, remote, s.errorResponse(msg, "target-allocation-not-found"))
	}
	payload, err := base64.StdEncoding.DecodeString(msg.PayloadBase64)
	if err != nil {
		return s.sendRelay(s.primary, remote, s.errorResponse(msg, "invalid-payload"))
	}
	if header, ok := ParseDataFrameHeader(payload); ok {
		if !s.service.AuthorizeRelayFrame(ctx, header, int64(len(payload))) {
			return s.sendRelay(s.primary, remote, s.errorResponse(msg, "relay-session-denied"))
		}
	}
	return s.sendRelay(s.primary, target.Remote, relayMessage{
		Magic:            relayMagic,
		Type:             relayTypeData,
		TransactionID:    msg.TransactionID,
		FromAllocationID: source.ID,
		ToAllocationID:   target.ID,
		PayloadBase64:    msg.PayloadBase64,
	})
}

func (s *stunTurnServer) allocate(remote *net.UDPAddr) relayAllocation {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := endpointKey(remote)
	if id, ok := s.allocationByEndpoint[key]; ok {
		if existing, ok := s.allocations[id]; ok {
			existing.Remote = cloneUDPAddr(remote)
			existing.ExpiresAt = time.Now().Add(time.Duration(s.service.cfg.AllocationTTLSeconds) * time.Second)
			s.allocations[id] = existing
			return existing
		}
	}
	allocation := relayAllocation{
		ID:        randomSuffix(),
		Remote:    cloneUDPAddr(remote),
		ExpiresAt: time.Now().Add(time.Duration(s.service.cfg.AllocationTTLSeconds) * time.Second),
	}
	s.allocations[allocation.ID] = allocation
	s.allocationByEndpoint[key] = allocation.ID
	return allocation
}

func (s *stunTurnServer) sourceAllocation(msg relayMessage, remote *net.UDPAddr) *relayAllocation {
	if msg.AllocationID != "" {
		if allocation := s.findAllocation(msg.AllocationID); allocation != nil && endpointKey(allocation.Remote) == endpointKey(remote) {
			return allocation
		}
	}
	s.mu.Lock()
	id := s.allocationByEndpoint[endpointKey(remote)]
	s.mu.Unlock()
	return s.findAllocation(id)
}

func (s *stunTurnServer) findAllocation(id string) *relayAllocation {
	if id == "" {
		return nil
	}
	s.mu.Lock()
	allocation, ok := s.allocations[id]
	s.mu.Unlock()
	if !ok {
		return nil
	}
	return &allocation
}

func (s *stunTurnServer) refreshText(id string, remote *net.UDPAddr) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	allocation, ok := s.allocations[id]
	if !ok || endpointKey(allocation.Remote) != endpointKey(remote) {
		return "ERROR allocation-not-found"
	}
	allocation.Remote = cloneUDPAddr(remote)
	allocation.ExpiresAt = time.Now().Add(time.Duration(s.service.cfg.AllocationTTLSeconds) * time.Second)
	s.allocations[id] = allocation
	s.allocationByEndpoint[endpointKey(remote)] = id
	return fmt.Sprintf("REFRESHED %s %d", id, s.service.cfg.AllocationTTLSeconds)
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
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, allocation := range s.allocations {
		if now.Before(allocation.ExpiresAt) {
			continue
		}
		delete(s.allocations, id)
		delete(s.allocationByEndpoint, endpointKey(allocation.Remote))
	}
}

func (s *stunTurnServer) bindingResponse(request relayMessage, remote *net.UDPAddr, conn *net.UDPConn, probeRole string) relayMessage {
	response := s.baseResponse(request, relayTypeBindingResp)
	response.ProbeRole = probeRole
	response.MappedAddress = remote.IP.String()
	response.MappedPort = remote.Port
	response.ObservedByAddress = s.advertisedAddress(conn)
	response.ObservedByPort = conn.LocalAddr().(*net.UDPAddr).Port
	if s.alternate != nil {
		response.AlternateAddress = s.advertisedAddress(s.alternate)
		response.AlternatePort = s.alternate.LocalAddr().(*net.UDPAddr).Port
	}
	return response
}

func (s *stunTurnServer) allocatedResponse(request relayMessage, id string) relayMessage {
	response := s.baseResponse(request, relayTypeAllocated)
	response.AllocationID = id
	response.TTLSeconds = s.service.cfg.AllocationTTLSeconds
	return response
}

func (s *stunTurnServer) baseResponse(request relayMessage, typ string) relayMessage {
	return relayMessage{Magic: relayMagic, Type: typ, TransactionID: request.TransactionID}
}

func (s *stunTurnServer) errorResponse(request relayMessage, reason string) relayMessage {
	response := s.baseResponse(request, relayTypeError)
	response.Error = reason
	return response
}

func (s *stunTurnServer) sendRelay(conn *net.UDPConn, remote *net.UDPAddr, msg relayMessage) error {
	if conn == nil {
		return nil
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = conn.WriteToUDP(payload, remote)
	return err
}

func (s *stunTurnServer) sendText(conn *net.UDPConn, remote *net.UDPAddr, msg string) error {
	_, err := conn.WriteToUDP([]byte(msg), remote)
	return err
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

func (s *stunTurnServer) advertisedAddress(conn *net.UDPConn) string {
	if strings.TrimSpace(s.service.cfg.PublicAddress) != "" {
		return strings.TrimSpace(s.service.cfg.PublicAddress)
	}
	if conn == nil || conn.LocalAddr() == nil {
		return ""
	}
	addr := conn.LocalAddr().(*net.UDPAddr)
	if addr.IP == nil || addr.IP.IsUnspecified() {
		return ""
	}
	return addr.IP.String()
}

func endpointKey(remote *net.UDPAddr) string {
	if remote == nil {
		return ""
	}
	return net.JoinHostPort(remote.IP.String(), fmt.Sprintf("%d", remote.Port))
}

func cloneUDPAddr(remote *net.UDPAddr) *net.UDPAddr {
	if remote == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), remote.IP...), Port: remote.Port, Zone: remote.Zone}
}
