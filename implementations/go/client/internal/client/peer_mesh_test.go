package client

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
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

func TestPeerMeshAnnounceCandidatesReusesExistingSession(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udp.Close()

	var sent peerControlMessage
	sessionID := int64(9001)
	expiresAt := time.Now().Add(time.Hour).UTC()
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
		sessions: map[int64]*peerMeshSession{
			2: {ID: sessionID, PeerID: 2, Token: "session-token", ExpiresAt: expiresAt},
		},
		sessionsByID: map[int64]*peerMeshSession{},
		srflx: &peerCandidate{
			Type:       "srflx",
			Transport:  "udp",
			Address:    "203.0.113.10",
			Port:       34567,
			Priority:   800,
			Foundation: "server-reflexive",
		},
		sender: func(_ net.Conn, _ string, message any) error {
			cast, ok := message.(peerControlMessage)
			if !ok {
				t.Fatalf("unexpected message type %T", message)
			}
			sent = cast
			return nil
		},
	}

	mesh.announceCandidates()

	if sent.SessionID == nil || *sent.SessionID != sessionID {
		t.Fatalf("session id = %v, want %d", sent.SessionID, sessionID)
	}
	if sent.Token != "session-token" {
		t.Fatalf("token = %q, want existing session token", sent.Token)
	}
	if sent.ExpiresAt == "" {
		t.Fatal("expiresAt missing from candidates message")
	}
}

func TestPeerMeshStartLightweightRefreshPreservesRosterAndSession(t *testing.T) {
	var sent []peerControlMessage
	runtime := RuntimeConfig{PeerMesh: PeerMeshConfig{
		Enabled:         true,
		ClientID:        1,
		ClientName:      "go-a",
		VirtualIP:       "100.96.0.1",
		CIDR:            "100.96.0.0/11",
		ClientPublicKey: "local-key",
	}}
	mesh := newPeerMeshClient(Config{PeerMeshDevice: "noop", PeerMeshTunName: "shuai0", PeerMeshMTU: 1280}, log.New(io.Discard, "", 0))
	sender := func(_ net.Conn, _ string, message any) error {
		if cast, ok := message.(peerControlMessage); ok {
			sent = append(sent, cast)
		}
		return nil
	}
	mesh.start(nil, runtime, sender)
	defer mesh.stop()

	sessionID := int64(9002)
	mesh.mu.Lock()
	mesh.peers[2] = &peerMeshPeer{ClientID: 2, ClientName: "java-b", VirtualIP: "100.96.0.2", PublicKey: "peer-key", Online: true}
	mesh.sessions[2] = &peerMeshSession{ID: sessionID, PeerID: 2, Token: "session-token", ExpiresAt: time.Now().Add(time.Hour)}
	mesh.sessionsByID[sessionID] = mesh.sessions[2]
	mesh.srflx = &peerCandidate{Type: "srflx", Transport: "udp", Address: "203.0.113.10", Port: 34567, Priority: 800}
	mesh.mu.Unlock()

	mesh.start(nil, runtime, sender)

	mesh.mu.Lock()
	peer := mesh.peers[2]
	session := mesh.sessions[2]
	mesh.mu.Unlock()
	if peer == nil || session == nil || session.ID != sessionID {
		t.Fatalf("lightweight refresh cleared peer/session: peer=%+v session=%+v", peer, session)
	}
	foundCandidateWithSession := false
	for _, message := range sent {
		if message.Type == peerControlTypeCandidates && message.SessionID != nil && *message.SessionID == sessionID {
			foundCandidateWithSession = true
		}
	}
	if !foundCandidateWithSession {
		t.Fatalf("missing candidates announcement with reused session: %+v", sent)
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

func TestPeerMeshMergeSessionPreservesNominatedPathAcrossRefreshLikeJava(t *testing.T) {
	oldEndpoint := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 20), Port: 52099}
	oldDirectAt := time.Now().Add(-5 * time.Second)
	oldKeepaliveAt := time.Now().Add(-2 * time.Second)
	oldReportAt := time.Now().Add(-time.Minute)
	oldLogAt := time.Now().Add(-time.Minute)
	replay := peerReplayWindow{}
	replay.accept(6)
	replay.accept(7)
	oldSession := &peerMeshSession{
		ID:                  1001,
		PeerID:              2,
		PeerName:            "java-b",
		PeerVirtualIP:       "100.112.186.105",
		PeerPublicKey:       "peer-key",
		Token:               "old-token",
		ExpiresAt:           time.Now().Add(time.Minute),
		RemoteEndpoint:      oldEndpoint,
		PathType:            "DIRECT",
		LastDirectSuccess:   oldDirectAt,
		LastDirectKeepalive: oldKeepaliveAt,
		LastRelaySuccess:    time.Now().Add(-10 * time.Second),
		LastPathLog:         oldLogAt,
		LastPathReport:      oldReportAt,
		LastPathRemoteText:  oldEndpoint.String(),
		AESKey:              []byte("0123456789abcdef0123456789abcdef"),
		LocalKeyEpoch:       "epoch-local",
		RemoteKeyEpoch:      "epoch-remote",
		Sequence:            42,
		Replay:              replay,
		DirectBytes:         100,
		DirectBytesPending:  25,
	}
	mesh := &peerMeshClient{
		logger: log.New(io.Discard, "", 0),
		runtime: RuntimeConfig{PeerMesh: PeerMeshConfig{
			ClientID: 1,
			CIDR:     "100.96.0.0/11",
		}},
		peers: map[int64]*peerMeshPeer{
			2: {ClientID: 2, ClientName: "java-b", VirtualIP: "100.112.186.105", PublicKey: "peer-key", Online: true},
		},
		sessions: map[int64]*peerMeshSession{2: oldSession},
	}
	newSessionID := int64(2002)

	mesh.mergeSession(peerControlMessage{
		DataFrameVersion: 2,
		SourceClientID:   1,
		TargetClientID:   2,
		TargetClientName: "java-b",
		TargetVirtualIP:  "100.112.186.105",
		TargetPublicKey:  "peer-key",
		SessionID:        &newSessionID,
		Token:            "new-token",
		ExpiresAt:        time.Now().Add(time.Hour).Format(time.RFC3339Nano),
		PathType:         "",
		CreatedAtMillis:  time.Now().UnixMilli(),
	})

	session := mesh.sessions[2]
	if session == nil {
		t.Fatal("session missing after merge")
	}
	if session.ID != newSessionID {
		t.Fatalf("session ID = %d, want %d", session.ID, newSessionID)
	}
	if session.RemoteEndpoint == nil || session.RemoteEndpoint.String() != oldEndpoint.String() {
		t.Fatalf("remote endpoint = %v, want %v", session.RemoteEndpoint, oldEndpoint)
	}
	if session.PathType != "DIRECT" {
		t.Fatalf("path type = %q, want DIRECT", session.PathType)
	}
	if !session.LastDirectSuccess.Equal(oldDirectAt) || !session.LastDirectKeepalive.Equal(oldKeepaliveAt) {
		t.Fatalf("direct timestamps not preserved: success=%v keepalive=%v", session.LastDirectSuccess, session.LastDirectKeepalive)
	}
	if session.LastPathRemoteText != oldEndpoint.String() {
		t.Fatalf("last path remote = %q, want %q", session.LastPathRemoteText, oldEndpoint.String())
	}
	if session.Sequence != 0 || session.Replay.highest != 0 {
		t.Fatalf("new session copied replay state: sequence=%d replay=%+v", session.Sequence, session.Replay)
	}
	if session.DirectBytes != 100 || session.DirectBytesPending != 25 {
		t.Fatalf("traffic counters = %d/%d, want 100/25", session.DirectBytes, session.DirectBytesPending)
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

func TestPeerMeshUsesIndependentStunAndTurnEndpoints(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	defer udp.Close()
	stunServer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen STUN udp: %v", err)
	}
	defer stunServer.Close()
	turnServer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen TURN udp: %v", err)
	}
	defer turnServer.Close()

	stopCh := make(chan struct{})
	defer close(stopCh)
	mesh := &peerMeshClient{
		udp:             udp,
		stopCh:          stopCh,
		logger:          log.New(io.Discard, "", 0),
		pendingStun:     make(map[string]pendingStunBinding),
		srflxCandidates: make(map[string]peerCandidate),
		natByRole:       make(map[string]string),
		natBehavior:     &natBehaviorDiscovery{},
		runtime: RuntimeConfig{PeerMesh: PeerMeshConfig{
			StunHost: "127.0.0.1",
			StunPort: stunServer.LocalAddr().(*net.UDPAddr).Port,
			TurnHost: "127.0.0.1",
			TurnPort: turnServer.LocalAddr().(*net.UDPAddr).Port,
		}},
	}

	mesh.requestRelayCandidates()
	binding := readStunMessages(t, stunServer, 1)
	allocate := readStunMessages(t, turnServer, 1)
	if len(binding) != 1 || binding[0].Type != stunBindingRequest {
		t.Fatalf("STUN endpoint messages = %+v, want binding", binding)
	}
	if len(allocate) != 1 || allocate[0].Type != stunAllocateRequest {
		t.Fatalf("TURN endpoint messages = %+v, want allocate", allocate)
	}
	if extra := readStunMessages(t, turnServer, 1); len(extra) != 0 {
		t.Fatalf("TURN endpoint received unexpected STUN binding: %+v", extra)
	}

	primary := stunServer.LocalAddr().(*net.UDPAddr)
	otherPort := primary.Port + 1
	if otherPort > 65535 {
		otherPort = primary.Port - 1
	}
	other := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: otherPort}
	mapped := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 52000}
	success := newStunMessage(
		stunBindingSuccess,
		binding[0].TransactionID,
		stunAttribute{Type: stunAttrXorMappedAddress, Value: encodeStunXorAddress(mapped, binding[0].TransactionID)},
		stunAttrResponseOriginValue(primary),
		stunAttrOtherAddressValue(other))
	mesh.handleStunTurnMessage(success, primary)

	filterProbe := readStunMessages(t, stunServer, 1)
	if len(filterProbe) != 1 || filterProbe[0].Type != stunBindingRequest {
		t.Fatalf("filter probe = %+v", filterProbe)
	}
	changeIP, changePort, ok := filterProbe[0].changeRequest()
	if !ok || !changeIP || !changePort {
		t.Fatalf("filter probe change request = ip:%v port:%v ok:%v", changeIP, changePort, ok)
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
	role := mesh.pendingStun[stunTransactionHex(first[0].TransactionID)].Role
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
		LocalKeyEpoch:           "epoch-local",
		RemoteKeyEpoch:          "epoch-remote",
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
	relayMessages := readStunMessages(t, relay, 3)
	if len(relayMessages) != 3 || relayMessages[0].Type != stunCreatePermissionRequest ||
		relayMessages[1].Type != stunChannelBindRequest || relayMessages[2].Type != stunSendIndication {
		t.Fatalf("relay messages = %+v, want permission+channel bind+send indication", relayMessages)
	}
	peer, ok := relayMessages[2].xorPeerAddress()
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
		LocalKeyEpoch:     "epoch-local",
		RemoteKeyEpoch:    "epoch-remote",
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
		LocalKeyEpoch:     "epoch-local",
		RemoteKeyEpoch:    "epoch-remote",
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

	packets := readUDPPackets(t, direct, peerProbeBurstCount)
	if len(packets) != peerProbeBurstCount {
		t.Fatalf("direct keepalive packets = %d, want %d burst packets", len(packets), peerProbeBurstCount)
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

func TestPeerHostCandidateAddressFamilies(t *testing.T) {
	tests := []struct {
		address string
		usable  bool
		family  string
	}{
		{address: "192.0.2.20", usable: true, family: "IPv4"},
		{address: "100.96.0.20", usable: false, family: "IPv4"},
		{address: "2001:db8::20", usable: true, family: "IPv6"},
		{address: "fd00::20", usable: false, family: "IPv6"},
		{address: "fe80::20", usable: false, family: "IPv6"},
		{address: "::ffff:192.0.2.20", usable: true, family: "IPv4"},
	}
	for _, test := range tests {
		ip := net.ParseIP(test.address)
		if got := usablePeerHostIP(ip, "100.96.0.0/11"); got != test.usable {
			t.Errorf("usablePeerHostIP(%s) = %v, want %v", test.address, got, test.usable)
		}
		if got := peerAddressFamily(ip); got != test.family {
			t.Errorf("peerAddressFamily(%s) = %s, want %s", test.address, got, test.family)
		}
	}
}

// TestSortedConnectivityCandidatesOrdersByPriorityDescending 校验 H-3：连通性检查候选
// 按 priority 降序排列，高优先级（host/port-map）排在前面先被探测。
func TestSortedConnectivityCandidatesOrdersByPriorityDescending(t *testing.T) {
	mesh := &peerMeshClient{
		logger: log.New(io.Discard, "", 0),
	}
	input := []peerCandidate{
		{Type: "srflx", Transport: "udp", Address: "203.0.113.10", Port: 30001, Priority: 800, Foundation: "standard-stun"},
		{Type: "host", Transport: "udp", Address: "192.168.1.5", Port: 40000, Priority: 1000, Foundation: "host"},
		{Type: "srflx", Transport: "udp", Address: "203.0.113.20", Port: 30002, Priority: 900, Foundation: "public-stun"},
	}
	sorted := mesh.sortedConnectivityCandidates(input)
	if len(sorted) != 3 {
		t.Fatalf("len = %d, want 3", len(sorted))
	}
	// 期望顺序：1000 (host) -> 900 (public-stun) -> 800 (srflx)
	if sorted[0].Priority != 1000 || sorted[1].Priority != 900 || sorted[2].Priority != 800 {
		t.Fatalf("priorities = [%d,%d,%d], want [1000,900,800]",
			sorted[0].Priority, sorted[1].Priority, sorted[2].Priority)
	}
}

// TestSortedConnectivityCandidatesDemotesSameNatReflexive 校验 H-6：与本地 STUN 公网地址相同的
// reflexive 候选被降到 priority=1（排到末尾），而非被剪除。
func TestSortedConnectivityCandidatesDemotesSameNatReflexive(t *testing.T) {
	localSrflx := "203.0.113.42"
	mesh := &peerMeshClient{
		logger: log.New(io.Discard, "", 0),
		srflx: &peerCandidate{
			Type:       "srflx",
			Transport:  "udp",
			Address:    localSrflx,
			Port:       34567,
			Priority:   800,
			Foundation: "standard-stun",
		},
		srflxCandidates: map[string]peerCandidate{
			"srflx|udp|" + localSrflx + ":34567": {
				Type: "srflx", Transport: "udp", Address: localSrflx, Port: 34567, Priority: 800, Foundation: "standard-stun",
			},
		},
	}
	input := []peerCandidate{
		// 同 NAT 的 srflx：应被降权到 priority=1
		{Type: "srflx", Transport: "udp", Address: localSrflx, Port: 34567, Priority: 800, Foundation: "standard-stun"},
		// 不同地址的 srflx：保持原 priority
		{Type: "srflx", Transport: "udp", Address: "203.0.113.99", Port: 35000, Priority: 800, Foundation: "public-stun"},
		// host 候选：不受影响
		{Type: "host", Transport: "udp", Address: "192.168.1.5", Port: 40000, Priority: 1000, Foundation: "host"},
	}
	sorted := mesh.sortedConnectivityCandidates(input)
	if len(sorted) != 3 {
		t.Fatalf("len = %d, want 3 (demotion must not prune)", len(sorted))
	}
	// 期望顺序：1000 (host) -> 800 (不同地址 srflx) -> 1 (同 NAT 被降权 srflx)
	if sorted[0].Priority != 1000 {
		t.Fatalf("first priority = %d, want 1000 (host)", sorted[0].Priority)
	}
	if sorted[2].Priority != 1 || sorted[2].Address != localSrflx {
		t.Fatalf("last candidate = %+v, want priority=1 same-NAT srflx", sorted[2])
	}
	// 不同地址的 srflx 必须保持原 priority=800
	var remoteSrflx *peerCandidate
	for i := range sorted {
		if sorted[i].Address == "203.0.113.99" {
			remoteSrflx = &sorted[i]
		}
	}
	if remoteSrflx == nil || remoteSrflx.Priority != 800 {
		t.Fatalf("non-same-NAT srflx priority = %v, want 800 (unchanged)", remoteSrflx)
	}
}

// TestDemoteSameNatReflexiveCandidatesKeepsPortMapCandidates 校验 H-6 也覆盖 port-map 候选
// （foundation 以 "port-map-" 开头），且降权不改变候选数量。
func TestDemoteSameNatReflexiveCandidatesKeepsPortMapCandidates(t *testing.T) {
	localAddr := "203.0.113.42"
	mesh := &peerMeshClient{
		logger: log.New(io.Discard, "", 0),
		srflx: &peerCandidate{
			Type: "srflx", Transport: "udp", Address: localAddr, Port: 34567, Priority: 900, Foundation: "standard-stun",
		},
		srflxCandidates: map[string]peerCandidate{},
	}
	input := []peerCandidate{
		{Type: "srflx", Transport: "udp", Address: localAddr, Port: 34567, Priority: 900, Foundation: "port-map-1"},
		{Type: "host", Transport: "udp", Address: "192.168.1.5", Port: 40000, Priority: 1000, Foundation: "host"},
	}
	demoted := mesh.demoteSameNatReflexiveCandidates(input)
	if len(demoted) != 2 {
		t.Fatalf("len = %d, want 2 (no pruning)", len(demoted))
	}
	if demoted[0].Foundation == "port-map-1" && demoted[0].Priority != 1 {
		t.Fatalf("same-NAT port-map candidate priority = %d, want 1", demoted[0].Priority)
	}
	if demoted[1].Foundation == "port-map-1" && demoted[1].Priority != 1 {
		t.Fatalf("same-NAT port-map candidate priority = %d, want 1", demoted[1].Priority)
	}
}

// TestCandidateReciprocationThrottlesPerPeer 校验 H-1：收到对端候选后本端无健康 direct 路径时
// 回发自身候选，但 2s 内对同一 peer 只回发一次，防止两端互触发形成信令循环。
func TestCandidateReciprocationThrottlesPerPeer(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udp.Close()

	var sentCount int
	var mu sync.Mutex
	mesh := &peerMeshClient{
		config: Config{PeerMeshDevice: "noop", PeerMeshTunName: "shuai0"},
		logger: log.New(io.Discard, "", 0),
		runtime: RuntimeConfig{PeerMesh: PeerMeshConfig{
			Enabled: true, ClientID: 1, ClientName: "go-a", VirtualIP: "100.96.0.1",
			CIDR: "100.96.0.0/11", ClientPublicKey: "local-key",
		}},
		udp: udp,
		peers: map[int64]*peerMeshPeer{
			2: {ClientID: 2, ClientName: "java-b", VirtualIP: "100.96.0.2", PublicKey: "peer-key", Online: true},
		},
		// 无 session 或 session 无健康 direct -> 应触发回礼
		sessions:               map[int64]*peerMeshSession{},
		candidateReciprocateAt: map[int64]time.Time{},
		srflx: &peerCandidate{
			Type: "srflx", Transport: "udp", Address: "203.0.113.10", Port: 34567, Priority: 800, Foundation: "standard-stun",
		},
		sender: func(_ net.Conn, _ string, _ any) error {
			mu.Lock()
			sentCount++
			mu.Unlock()
			return nil
		},
	}

	// 第一次回礼：应发送
	mesh.reciprocateCandidates(2)
	// 立即第二次：2s 节流内，不应发送
	mesh.reciprocateCandidates(2)

	mu.Lock()
	got := sentCount
	mu.Unlock()
	if got != 1 {
		t.Fatalf("reciprocate sent count = %d, want 1 (throttled)", got)
	}
}

// TestCandidateReciprocationSkipsHealthyDirect 校验 H-1：已有健康 direct 路径时不回礼
// （避免对已经打通的路径制造冗余信令）。
func TestCandidateReciprocationSkipsHealthyDirect(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udp.Close()

	var sentCount int
	now := time.Now()
	mesh := &peerMeshClient{
		config: Config{PeerMeshDevice: "noop", PeerMeshTunName: "shuai0"},
		logger: log.New(io.Discard, "", 0),
		runtime: RuntimeConfig{PeerMesh: PeerMeshConfig{
			Enabled: true, ClientID: 1, ClientName: "go-a", VirtualIP: "100.96.0.1",
			CIDR: "100.96.0.0/11", ClientPublicKey: "local-key",
		}},
		udp: udp,
		peers: map[int64]*peerMeshPeer{
			2: {ClientID: 2, ClientName: "java-b", VirtualIP: "100.96.0.2", PublicKey: "peer-key", Online: true},
		},
		sessions: map[int64]*peerMeshSession{
			2: {ID: 9001, PeerID: 2, Token: "tok", ExpiresAt: now.Add(time.Hour), PathType: "DIRECT", LastDirectSuccess: now},
		},
		candidateReciprocateAt: map[int64]time.Time{},
		srflx: &peerCandidate{
			Type: "srflx", Transport: "udp", Address: "203.0.113.10", Port: 34567, Priority: 800, Foundation: "standard-stun",
		},
		sender: func(_ net.Conn, _ string, _ any) error {
			sentCount++
			return nil
		},
	}

	mesh.reciprocateCandidates(2)
	if sentCount != 0 {
		t.Fatalf("reciprocate sent count = %d, want 0 (healthy direct)", sentCount)
	}
}

// TestScheduleHolePunchRetriesStopsOnHealthyDirect 校验 H-2：session 无健康 direct 时排程
// 退避重试，建立健康 direct 后停止重试（不再触发 sendConnectivityChecks）。
func TestScheduleHolePunchRetriesStopsOnHealthyDirect(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udp.Close()

	sessionID := int64(7001)
	now := time.Now()
	probeTarget, err := net.ResolveUDPAddr("udp4", "127.0.0.1:9")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	mesh := &peerMeshClient{
		config: Config{PeerMeshDevice: "noop", PeerMeshTunName: "shuai0"},
		logger: log.New(io.Discard, "", 0),
		runtime: RuntimeConfig{PeerMesh: PeerMeshConfig{
			Enabled: true, ClientID: 1, ClientName: "go-a", VirtualIP: "100.96.0.1",
			CIDR: "100.96.0.0/11", ClientPublicKey: "local-key",
		}},
		udp:      udp,
		stopCh:   make(chan struct{}),
		peers:    map[int64]*peerMeshPeer{},
		sessions: map[int64]*peerMeshSession{},
		sessionsByID: map[int64]*peerMeshSession{
			sessionID: {ID: sessionID, PeerID: 2, Token: "tok", ExpiresAt: now.Add(time.Hour)},
		},
		holePunchRetryScheduled: map[int64]bool{},
		pending:                 map[string]pendingPeerProbe{},
	}
	_ = probeTarget

	// 无健康 direct：排程应成功标记
	mesh.scheduleHolePunchRetries(mesh.sessionsByID[sessionID])
	mesh.mu.Lock()
	scheduled := mesh.holePunchRetryScheduled[sessionID]
	mesh.mu.Unlock()
	if !scheduled {
		t.Fatalf("expected holePunchRetryScheduled[%d]=true", sessionID)
	}

	// 建立健康 direct 路径后，retryHolePunch 应清除标记并停止
	mesh.mu.Lock()
	mesh.sessionsByID[sessionID].PathType = "DIRECT"
	mesh.sessionsByID[sessionID].LastDirectSuccess = time.Now()
	mesh.mu.Unlock()
	mesh.retryHolePunch(sessionID)

	mesh.mu.Lock()
	scheduled = mesh.holePunchRetryScheduled[sessionID]
	mesh.mu.Unlock()
	if scheduled {
		t.Fatalf("expected holePunchRetryScheduled[%d] cleared after healthy direct", sessionID)
	}
}

// TestScheduleHolePunchRetriesDoesNotReschedule 校验 H-2：同一 session 在本轮退避完成前
// 不会被重复排程（holePunchRetryScheduled 守卫生效）。
func TestScheduleHolePunchRetriesDoesNotReschedule(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udp.Close()

	sessionID := int64(7002)
	now := time.Now()
	mesh := &peerMeshClient{
		config: Config{PeerMeshDevice: "noop", PeerMeshTunName: "shuai0"},
		logger: log.New(io.Discard, "", 0),
		runtime: RuntimeConfig{PeerMesh: PeerMeshConfig{
			Enabled: true, ClientID: 1, ClientName: "go-a", VirtualIP: "100.96.0.1",
			CIDR: "100.96.0.0/11", ClientPublicKey: "local-key",
		}},
		udp:      udp,
		stopCh:   make(chan struct{}),
		peers:    map[int64]*peerMeshPeer{},
		sessions: map[int64]*peerMeshSession{},
		sessionsByID: map[int64]*peerMeshSession{
			sessionID: {ID: sessionID, PeerID: 2, Token: "tok", ExpiresAt: now.Add(time.Hour)},
		},
		holePunchRetryScheduled: map[int64]bool{},
		pending:                 map[string]pendingPeerProbe{},
	}

	session := mesh.sessionsByID[sessionID]
	mesh.scheduleHolePunchRetries(session)
	// 手动标记后再次调用，应被守卫拦截（不会 panic 或重复排程）
	mesh.scheduleHolePunchRetries(session)
	mesh.mu.Lock()
	scheduled := mesh.holePunchRetryScheduled[sessionID]
	mesh.mu.Unlock()
	if !scheduled {
		t.Fatalf("expected guard to remain set after duplicate schedule attempt")
	}
}
