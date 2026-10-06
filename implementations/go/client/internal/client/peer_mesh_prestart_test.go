package client

import (
	"encoding/json"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The server pushes the peer-config that enables a device from one thread and the session signals
// for that device from another, so a session-grant or a peer's candidates can reach the client
// before its mesh runs. These cases hold down that such a signal is dropped rather than taken into
// a mesh that has no session table yet, and that the mesh takes the same signals once it runs.

const prestartSessionID = int64(4101)

// newPrestartMeshHarness is a mesh that can be started and stopped without touching this machine:
// its route journal, routing table and DNS are fakes, and no gateway is asked for a port mapping.
func newPrestartMeshHarness(t *testing.T) *peerMeshClient {
	t.Helper()
	mesh := newConsumerMeshHarness(t)
	mesh.egressCommander = newFakeRouteCommander()
	mesh.egressDNSHost = newFakeDNSHost()
	mesh.egressDNSPlatform = "linux"
	mesh.egressDNSJournalPath = filepath.Join(t.TempDir(), "egress-dns-journal.json")
	mesh.egressDNSTunnelAddresses = func(string) []string { return nil }
	// No UPnP, NAT-PMP or PCP: every full start would otherwise ask the gateway for a mapping.
	mesh.portMappingService = &natPortMappingService{logger: mesh.logger}
	return mesh
}

func prestartRuntime(enabled bool) RuntimeConfig {
	return RuntimeConfig{PeerMesh: PeerMeshConfig{
		Enabled:         enabled,
		ClientID:        1,
		ClientName:      "go-a",
		VirtualIP:       "100.96.0.1",
		CIDR:            "100.96.0.0/11",
		ClientPublicKey: "local-key",
	}}
}

// prestartSignals are the grant the server sends this side as the initiator and the candidates it
// forwards from the peer, both for the same session. The peer's only candidate is probeTarget.
func prestartSignals(t *testing.T, probeTarget *net.UDPAddr) (string, string) {
	t.Helper()
	sessionID := prestartSessionID
	expiresAt := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	grant, err := json.Marshal(peerControlMessage{
		Type:             peerControlTypeSessionGrant,
		SessionID:        &sessionID,
		SourceClientID:   1,
		SourceClientName: "go-a",
		TargetClientID:   2,
		TargetClientName: "go-b",
		TargetVirtualIP:  "100.96.0.2",
		TargetPublicKey:  "peer-key",
		Token:            "session-token",
		ExpiresAt:        expiresAt,
		PathType:         "DIRECT",
		Status:           "NEGOTIATING",
		DataFrameVersion: 2,
	})
	if err != nil {
		t.Fatalf("encode grant: %v", err)
	}
	candidates, err := json.Marshal(peerControlMessage{
		Type:             peerControlTypeCandidates,
		SessionID:        &sessionID,
		SourceClientID:   2,
		SourceClientName: "go-b",
		SourceVirtualIP:  "100.96.0.2",
		SourcePublicKey:  "peer-key",
		SourceKeyEpoch:   "peer-epoch",
		TargetClientID:   1,
		TargetClientName: "go-a",
		Token:            "session-token",
		ExpiresAt:        expiresAt,
		Candidates: []peerCandidate{{
			Type: "host", Transport: "udp", Address: probeTarget.IP.String(), Port: probeTarget.Port,
			Priority: 1000, Foundation: "host", AddressFamily: "IPv4",
		}},
		DataFrameVersion: 2,
	})
	if err != nil {
		t.Fatalf("encode candidates: %v", err)
	}
	return string(grant), string(candidates)
}

// listenProbeTarget is the peer's candidate: a socket that is really there, so probes sent to it
// are delivered rather than answered with a port-unreachable the mesh socket would then read.
func listenProbeTarget(t *testing.T) *net.UDPConn {
	t.Helper()
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen probe target: %v", err)
	}
	t.Cleanup(func() { _ = target.Close() })
	return target
}

func discardPeerControl(net.Conn, string, any) error { return nil }

func (mesh *peerMeshClient) sessionCountsForTest() (int, int) {
	mesh.mu.Lock()
	defer mesh.mu.Unlock()
	return len(mesh.sessions), len(mesh.sessionsByID)
}

// assertSessionTaken checks that the mesh keeps the granted session under the peer and its id, and
// that the peer's candidate is probed for it: what the signals are for once the mesh runs.
func assertSessionTaken(t *testing.T, mesh *peerMeshClient, grant, candidates string, target *net.UDPConn) {
	t.Helper()
	mesh.handleControl(nil, grant, RuntimeConfig{}, discardPeerControl)
	mesh.handleControl(nil, candidates, RuntimeConfig{}, discardPeerControl)

	mesh.mu.Lock()
	session := mesh.sessions[2]
	byID := mesh.sessionsByID[prestartSessionID]
	peer := mesh.peers[2]
	mesh.mu.Unlock()
	if session == nil || session.ID != prestartSessionID || session.Token != "session-token" {
		t.Fatalf("the granted session was not kept once the mesh ran: %+v", session)
	}
	if byID != session {
		t.Fatalf("the session is not indexed by its id: byID=%p session=%p", byID, session)
	}
	if session.RemoteKeyEpoch != "peer-epoch" {
		t.Errorf("remote key epoch = %q, want the one the peer's candidates carried", session.RemoteKeyEpoch)
	}
	if peer == nil || len(peer.Candidates) != 1 {
		t.Errorf("the peer's candidates were not kept: %+v", peer)
	}

	buf := make([]byte, 2048)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_ = target.SetReadDeadline(deadline)
		n, _, err := target.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("no connectivity check reached the peer's candidate: %v", err)
		}
		var probe peerUDPProbe
		if json.Unmarshal(buf[:n], &probe) == nil && probe.Magic == peerProbeMagic &&
			probe.SessionID == prestartSessionID {
			if probe.FromClientID != 1 || probe.ToClientID != 2 || probe.Token != "session-token" {
				t.Fatalf("probe for the wrong session: %+v", probe)
			}
			return
		}
	}
}

// A grant and candidates that arrive before the peer-config enabling the device are dropped: the
// mesh has no session table to keep them in, and its start would clear one anyway. They used to be
// written into the nil table and take the whole client down.
func TestPeerMeshSessionSignalsBeforeStartAreDropped(t *testing.T) {
	target := listenProbeTarget(t)
	mesh := newPrestartMeshHarness(t)
	grant, candidates := prestartSignals(t, target.LocalAddr().(*net.UDPAddr))

	mesh.handleControl(nil, grant, RuntimeConfig{}, discardPeerControl)
	mesh.handleControl(nil, candidates, RuntimeConfig{}, discardPeerControl)
	if sessions, byID := mesh.sessionCountsForTest(); sessions != 0 || byID != 0 {
		t.Fatalf("a mesh that is not running kept a session: sessions=%d byID=%d", sessions, byID)
	}

	mesh.start(nil, prestartRuntime(true), discardPeerControl)
	defer mesh.stop()
	assertSessionTaken(t, mesh, grant, candidates, target)
}

// A mesh the server has disabled is no better a place for them than one never started.
func TestPeerMeshSessionSignalsAfterDisableAreDropped(t *testing.T) {
	target := listenProbeTarget(t)
	mesh := newPrestartMeshHarness(t)
	grant, candidates := prestartSignals(t, target.LocalAddr().(*net.UDPAddr))
	mesh.start(nil, prestartRuntime(true), discardPeerControl)
	defer mesh.stop()
	mesh.handleControl(nil, `{"type":"peer-config","peerMesh":{"enabled":false,"clientId":1}}`,
		prestartRuntime(true), discardPeerControl)

	mesh.handleControl(nil, grant, RuntimeConfig{}, discardPeerControl)
	mesh.handleControl(nil, candidates, RuntimeConfig{}, discardPeerControl)
	if sessions, byID := mesh.sessionCountsForTest(); sessions != 0 || byID != 0 {
		t.Fatalf("a disabled mesh kept a session: sessions=%d byID=%d", sessions, byID)
	}

	mesh.start(nil, prestartRuntime(true), discardPeerControl)
	assertSessionTaken(t, mesh, grant, candidates, target)
}

// The signals keep coming while the mesh is started, stopped and started again on another
// goroutine, the way a token refresh restarts it beside the control read loop. Whichever side of a
// transition a signal lands on, it must not find a table that has gone; and the mesh that ends up
// running takes the session as usual.
func TestPeerMeshSessionSignalsRacingStartDoNotPanic(t *testing.T) {
	target := listenProbeTarget(t)
	mesh := newPrestartMeshHarness(t)
	defer mesh.stop()
	grant, candidates := prestartSignals(t, target.LocalAddr().(*net.UDPAddr))

	done := make(chan struct{})
	first := make(chan struct{})
	var signalled sync.WaitGroup
	signalled.Add(1)
	delivered := 0
	go func() {
		defer signalled.Done()
		for {
			mesh.handleControl(nil, grant, RuntimeConfig{}, discardPeerControl)
			mesh.handleControl(nil, candidates, RuntimeConfig{}, discardPeerControl)
			delivered++
			if delivered == 1 {
				close(first)
			}
			select {
			case <-done:
				return
			default:
			}
		}
	}()
	// The first pair lands before any start, the rest across every transition after it.
	<-first
	for round := 0; round < 20; round++ {
		mesh.start(nil, prestartRuntime(true), discardPeerControl)
		mesh.start(nil, prestartRuntime(false), discardPeerControl)
	}
	mesh.start(nil, prestartRuntime(true), discardPeerControl)
	close(done)
	signalled.Wait()
	t.Logf("%d grant and candidates pairs delivered across the transitions", delivered)

	assertSessionTaken(t, mesh, grant, candidates, target)
}
