package client

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"testing"
	"time"
)

func TestPeerMeshAnnounceCandidatesIncludesServerReflexive(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udp.Close()

	var sent peerControlMessage
	var toClientName string
	mesh := &peerMeshClient{
		config: Config{PeerMeshDevice: "noop", PeerMeshTunName: "shuai0"},
		logger: log.New(io.Discard, "", 0),
		runtime: RuntimeConfig{PeerMesh: PeerMeshConfig{
			Enabled:         true,
			ClientID:        1,
			ClientName:      "go-a",
			VirtualIP:       "100.96.0.1",
			CIDR:            "100.96.0.0/11",
			ClientPublicKey: "local-key",
		}},
		udp: udp,
		peers: map[int64]*peerMeshPeer{
			2: {ClientID: 2, ClientName: "java-b", VirtualIP: "100.96.0.2", PublicKey: "peer-key", Online: true},
		},
		srflx: &peerCandidate{
			Type:       "srflx",
			Transport:  "udp",
			Address:    "203.0.113.10",
			Port:       34567,
			Priority:   800,
			Foundation: "server-reflexive",
		},
		sender: func(_ net.Conn, to string, message any) error {
			toClientName = to
			cast, ok := message.(peerControlMessage)
			if !ok {
				t.Fatalf("unexpected message type %T", message)
			}
			sent = cast
			return nil
		},
	}

	mesh.announceCandidates()

	if toClientName != "java-b" {
		t.Fatalf("toClientName = %q", toClientName)
	}
	if sent.Type != peerControlTypeCandidates {
		t.Fatalf("message type = %q", sent.Type)
	}
	if sent.SourceClientID != 1 || sent.TargetClientID != 2 {
		t.Fatalf("source/target mismatch: %+v", sent)
	}
	foundSrflx := false
	for _, candidate := range sent.Candidates {
		if candidate.Type == "srflx" && candidate.Address == "203.0.113.10" && candidate.Port == 34567 {
			foundSrflx = true
		}
	}
	if !foundSrflx {
		t.Fatalf("server-reflexive candidate missing: %+v", sent.Candidates)
	}
}

func TestPeerMeshNatTypeUsesJavaEnumNames(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udp.Close()

	port := udp.LocalAddr().(*net.UDPAddr).Port
	tests := []struct {
		name     string
		roles    map[string]string
		expected string
	}{
		{
			name: "symmetric",
			roles: map[string]string{
				peerRelayProbePrimary:   "198.51.100.1:41000",
				peerRelayProbeAlternate: "198.51.100.1:42000",
			},
			expected: peerNatTypeSymmetric,
		},
		{
			name: "port restricted",
			roles: map[string]string{
				peerRelayProbePrimary:   "198.51.100.1:41000",
				peerRelayProbeAlternate: "198.51.100.1:41000",
			},
			expected: peerNatTypePortRestricted,
		},
		{
			name: "full cone or restricted",
			roles: map[string]string{
				peerRelayProbePrimary: "198.51.100.1:41000",
				peerRelayProbeChanged: "198.51.100.1:41000",
			},
			expected: peerNatTypeFullConeOrRestricted,
		},
		{
			name: "port preserved",
			roles: map[string]string{
				peerRelayProbePrimary: fmt.Sprintf("198.51.100.1:%d", port),
			},
			expected: peerNatTypePortPreserved,
		},
		{
			name: "nat",
			roles: map[string]string{
				peerRelayProbePrimary: "198.51.100.1:41000",
			},
			expected: peerNatTypeNat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mesh := &peerMeshClient{udp: udp, natByRole: tt.roles}
			if got := mesh.natTypeLocked(); got != tt.expected {
				t.Fatalf("natTypeLocked() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestPeerMeshGatherCandidatesStillTriesDirectForSymmetricNatLikeJava(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udp.Close()

	mesh := &peerMeshClient{
		udp: udp,
		runtime: RuntimeConfig{PeerMesh: PeerMeshConfig{
			CIDR: "100.96.0.0/11",
		}},
		natByRole: map[string]string{
			peerRelayProbePrimary:   "198.51.100.1:41000",
			peerRelayProbeAlternate: "198.51.100.1:42000",
		},
		srflx: &peerCandidate{
			Type:      "srflx",
			Transport: "udp",
			Address:   "198.51.100.1",
			Port:      41000,
		},
		relay: &peerCandidate{
			Type:      "relay",
			Transport: "udp",
			Address:   "203.0.113.10",
			Port:      7011,
			RelayID:   "alloc-a",
		},
	}

	candidates := mesh.gatherCandidates()

	foundSrflx := false
	foundRelay := false
	for _, candidate := range candidates {
		if candidate.Type == "srflx" && candidate.Address == "198.51.100.1" && candidate.Port == 41000 {
			foundSrflx = true
		}
		if candidate.Type == "relay" && candidate.RelayID == "alloc-a" {
			foundRelay = true
		}
	}
	if !foundSrflx || !foundRelay {
		t.Fatalf("candidates = %+v, want direct srflx and relay", candidates)
	}
}

func TestPeerMeshGatherCandidatesIncludesPortMapCandidateEvenWhenNatIsSymmetric(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udp.Close()

	mesh := &peerMeshClient{
		udp: udp,
		runtime: RuntimeConfig{PeerMesh: PeerMeshConfig{
			CIDR: "100.96.0.0/11",
		}},
		natByRole: map[string]string{
			peerRelayProbePrimary:   "198.51.100.1:41000",
			peerRelayProbeAlternate: "198.51.100.1:42000",
		},
		portMap: &peerCandidate{
			Type:       "srflx",
			Transport:  "udp",
			Address:    "203.0.113.20",
			Port:       52000,
			Priority:   900,
			Foundation: "port-map-upnp",
		},
		relay: &peerCandidate{
			Type:      "relay",
			Transport: "udp",
			Address:   "203.0.113.10",
			Port:      7011,
			RelayID:   "alloc-a",
		},
	}

	candidates := mesh.gatherCandidates()

	foundPortMap := false
	for _, candidate := range candidates {
		if candidate.Foundation == "port-map-upnp" && candidate.Address == "203.0.113.20" && candidate.Port == 52000 {
			foundPortMap = true
		}
	}
	if !foundPortMap {
		t.Fatalf("port-map candidate missing: %+v", candidates)
	}
}

func TestPeerMeshPendingPacketQueueCapsAndExpires(t *testing.T) {
	mesh := &peerMeshClient{
		packets: make(map[int64][]pendingPeerPacket),
		logger:  log.New(io.Discard, "", 0),
	}

	for i := 0; i < peerMaxPendingPackets+3; i++ {
		mesh.queuePendingPacket(42, []byte{byte(i)})
	}

	if got := len(mesh.packets[42]); got != peerMaxPendingPackets {
		t.Fatalf("pending packet count = %d, want %d", got, peerMaxPendingPackets)
	}
	if got := mesh.packets[42][0].Packet[0]; got != 3 {
		t.Fatalf("oldest pending packet = %d, want 3 after cap trimming", got)
	}

	mesh.packets[42][0].SentAt = time.Now().Add(-peerPendingPacketTTL - time.Second)
	mesh.cleanupPendingPackets()

	if got := len(mesh.packets[42]); got != peerMaxPendingPackets-1 {
		t.Fatalf("pending packet count after cleanup = %d, want %d", got, peerMaxPendingPackets-1)
	}
}

func TestPeerMeshRequestRelayCandidatesIsThrottledLikeJava(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	defer udp.Close()
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen relay udp: %v", err)
	}
	defer relay.Close()

	mesh := &peerMeshClient{
		udp:    udp,
		logger: log.New(io.Discard, "", 0),
		runtime: RuntimeConfig{PeerMesh: PeerMeshConfig{
			TurnHost: "127.0.0.1",
			TurnPort: relay.LocalAddr().(*net.UDPAddr).Port,
		}},
	}

	mesh.requestRelayCandidates()
	first := readStunMessages(t, relay, 2)
	if first[0].Type != stunBindingRequest || first[1].Type != stunAllocateRequest {
		t.Fatalf("first relay request messages = %+v, want binding+allocate", first)
	}
	mesh.requestRelayCandidates()
	if messages := readStunMessages(t, relay, 1); len(messages) != 0 {
		t.Fatalf("second relay request was not throttled: %+v", messages)
	}
}

func TestPeerMeshRequestRelayRefreshIsThrottledLikeJava(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	defer udp.Close()
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen relay udp: %v", err)
	}
	defer relay.Close()

	mesh := &peerMeshClient{
		udp:      udp,
		logger:   log.New(io.Discard, "", 0),
		relayID:  "alloc-a",
		relayTTL: time.Now().Add(2 * time.Minute),
		runtime: RuntimeConfig{PeerMesh: PeerMeshConfig{
			TurnHost: "127.0.0.1",
			TurnPort: relay.LocalAddr().(*net.UDPAddr).Port,
		}},
	}

	mesh.requestRelayCandidates()
	first := readStunMessages(t, relay, 2)
	if first[0].Type != stunBindingRequest || first[1].Type != stunRefreshRequest {
		t.Fatalf("first relay refresh messages = %+v, want binding+refresh", first)
	}
	mesh.requestRelayCandidates()
	if messages := readStunMessages(t, relay, 1); len(messages) != 0 {
		t.Fatalf("fresh relay refresh was not throttled: %+v", messages)
	}
}

func TestPeerMeshRequestAlternateProbeIsThrottledLikeJava(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	defer udp.Close()
	alternate, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen alternate udp: %v", err)
	}
	defer alternate.Close()

	mesh := &peerMeshClient{
		udp:     udp,
		logger:  log.New(io.Discard, "", 0),
		runtime: RuntimeConfig{PeerMesh: PeerMeshConfig{CIDR: "100.96.0.0/11"}},
	}
	observed := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3478}
	alternateAddr := alternate.LocalAddr().(*net.UDPAddr)

	mesh.requestAlternateProbe(peerRelayProbePrimary, alternateAddr, observed)
	first := readStunMessages(t, alternate, 1)
	if first[0].Type != stunBindingRequest {
		t.Fatalf("alternate probe message = %+v, want alternate binding", first[0])
	}
	mesh.mu.Lock()
	role := mesh.pendingStun[stunTransactionHex(first[0].TransactionID)]
	mesh.mu.Unlock()
	if role != peerRelayProbeAlternate {
		t.Fatalf("alternate probe role = %q", role)
	}
	mesh.requestAlternateProbe(peerRelayProbePrimary, alternateAddr, observed)
	if messages := readStunMessages(t, alternate, 1); len(messages) != 0 {
		t.Fatalf("second alternate probe was not throttled: %+v", messages)
	}
}

func TestPeerMeshSendUsesRelayAllocationLikeJava(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	defer udp.Close()
	direct, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen direct udp: %v", err)
	}
	defer direct.Close()
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen relay udp: %v", err)
	}
	defer relay.Close()

	session := &peerMeshSession{
		ID:                      1001,
		PeerID:                  2,
		Token:                   "token",
		ExpiresAt:               time.Now().Add(time.Minute),
		RemoteEndpoint:          direct.LocalAddr().(*net.UDPAddr),
		RelayTargetAllocationID: endpointKeyUDP(direct.LocalAddr().(*net.UDPAddr)),
		PathType:                "DIRECT",
		LastDirectSuccess:       time.Now(),
		AESKey:                  []byte("0123456789abcdef0123456789abcdef"),
	}
	mesh := &peerMeshClient{
		udp:      udp,
		relayID:  "alloc-local",
		relayTTL: time.Now().Add(time.Minute),
		logger:   log.New(io.Discard, "", 0),
		runtime: RuntimeConfig{PeerMesh: PeerMeshConfig{
			ClientID: 1,
			TurnHost: "127.0.0.1",
			TurnPort: relay.LocalAddr().(*net.UDPAddr).Port,
			CIDR:     "100.96.0.0/11",
		}},
		sessions: map[int64]*peerMeshSession{2: session},
	}

	if err := mesh.sendEncryptedPayload(session, []byte("payload")); err != nil {
		t.Fatalf("send encrypted payload: %v", err)
	}
	relayMessages := readStunMessages(t, relay, 2)
	if len(relayMessages) != 2 || relayMessages[0].Type != stunCreatePermissionRequest || relayMessages[1].Type != stunSendIndication {
		t.Fatalf("relay messages = %+v, want permission+send indication", relayMessages)
	}
	peer, ok := relayMessages[1].xorPeerAddress()
	if !ok || peer.Port != direct.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("relay peer address = %+v", peer)
	}
	if messages := readUDPPackets(t, direct, 1); len(messages) != 0 {
		t.Fatalf("direct endpoint received packets while relay allocation exists: %d", len(messages))
	}
}

func TestPeerMeshRelayProbeDoesNotOverrideHealthyDirectLikeJava(t *testing.T) {
	session := &peerMeshSession{
		ID:                1001,
		PeerID:            2,
		Token:             "token",
		ExpiresAt:         time.Now().Add(time.Minute),
		RemoteEndpoint:    &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 51000},
		PathType:          "DIRECT",
		LastDirectSuccess: time.Now(),
		AESKey:            []byte("0123456789abcdef0123456789abcdef"),
	}
	mesh := &peerMeshClient{
		logger:   log.New(io.Discard, "", 0),
		runtime:  RuntimeConfig{PeerMesh: PeerMeshConfig{CIDR: "100.96.0.0/11"}},
		sessions: map[int64]*peerMeshSession{2: session},
		pending: map[string]pendingPeerProbe{
			"nonce-a": {
				SessionID: 1001,
				PeerID:    2,
				SentAt:    time.Now().Add(-10 * time.Millisecond),
				Relay:     true,
				RelayID:   "alloc-peer",
			},
		},
	}

	mesh.completeProbe(peerUDPProbe{
		Magic:     peerProbeMagic,
		Type:      peerProbeTypeCheckResponse,
		SessionID: 1001,
		Nonce:     "nonce-a",
		Token:     "token",
	}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7011}, "alloc-peer")

	if session.PathType != "DIRECT" || session.RelayTargetAllocationID != "" {
		t.Fatalf("session path = %s relay=%q, want healthy direct unchanged", session.PathType, session.RelayTargetAllocationID)
	}
}

func TestPeerMeshDirectKeepaliveUsesNominatedEndpointLikeJava(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	defer udp.Close()
	direct, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen direct udp: %v", err)
	}
	defer direct.Close()

	session := &peerMeshSession{
		ID:                1001,
		PeerID:            2,
		Token:             "token",
		ExpiresAt:         time.Now().Add(time.Minute),
		RemoteEndpoint:    direct.LocalAddr().(*net.UDPAddr),
		PathType:          "DIRECT",
		LastDirectSuccess: time.Now(),
		AESKey:            []byte("0123456789abcdef0123456789abcdef"),
	}
	mesh := &peerMeshClient{
		udp:      udp,
		stopCh:   make(chan struct{}),
		logger:   log.New(io.Discard, "", 0),
		runtime:  RuntimeConfig{PeerMesh: PeerMeshConfig{ClientID: 1, CIDR: "100.96.0.0/11"}},
		sessions: map[int64]*peerMeshSession{2: session},
		pending:  map[string]pendingPeerProbe{},
	}
	defer close(mesh.stopCh)

	mesh.keepaliveDirectPaths()

	packets := readUDPPackets(t, direct, 1)
	if len(packets) != 1 {
		t.Fatalf("direct keepalive packets = %d, want 1", len(packets))
	}
	var probe peerUDPProbe
	if err := json.Unmarshal(packets[0], &probe); err != nil {
		t.Fatalf("decode keepalive probe: %v", err)
	}
	if probe.Magic != peerProbeMagic || probe.Type != peerProbeTypeCheck || probe.SessionID != session.ID || probe.Token != session.Token {
		t.Fatalf("probe = %+v, want direct keepalive check", probe)
	}
	if len(mesh.pending) != 1 {
		t.Fatalf("pending probes = %d, want 1", len(mesh.pending))
	}

	mesh.keepaliveDirectPaths()
	if packets := readUDPPackets(t, direct, 1); len(packets) != 0 {
		t.Fatalf("second keepalive inside throttle sent %d packets", len(packets))
	}
}

func readUDPPackets(t *testing.T, conn *net.UDPConn, max int) [][]byte {
	t.Helper()
	packets := make([][]byte, 0, max)
	for i := 0; i < max; i++ {
		if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		var buf [4096]byte
		n, _, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return packets
			}
			t.Fatalf("read udp packet: %v", err)
		}
		packets = append(packets, append([]byte(nil), buf[:n]...))
	}
	return packets
}

func readStunMessages(t *testing.T, conn *net.UDPConn, max int) []stunMessage {
	t.Helper()
	messages := make([]stunMessage, 0, max)
	for i := 0; i < max; i++ {
		if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		var buf [4096]byte
		n, _, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return messages
			}
			t.Fatalf("read relay message: %v", err)
		}
		message, err := parseStunMessage(buf[:n])
		if err != nil {
			t.Fatalf("decode stun message: %v; raw=%x", err, buf[:n])
		}
		messages = append(messages, *message)
	}
	return messages
}
