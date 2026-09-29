package client

import (
	"net"
	"testing"
	"time"
)

// relayTestMesh wires one TURN channel to the test session's peer, so a frame can arrive over the
// relay as well as direct.
func relayTestMesh(t *testing.T) (*peerMeshClient, *peerMeshSession, *recordingVirtualDevice, func(sequence uint64)) {
	t.Helper()
	device := newRecordingVirtualDevice()
	mesh, session := newDataPlaneTestMesh(t, device)
	relay := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 20), Port: 3478}
	peer := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 30), Port: 43000}
	mesh.mu.Lock()
	mesh.runtime.PeerMesh.TurnHost = relay.IP.String()
	mesh.runtime.PeerMesh.TurnPort = relay.Port
	mesh.relay = &peerCandidate{Type: "relay", Transport: "udp", Address: relay.IP.String(), Port: relay.Port}
	mesh.turnChannelsByNumber = map[uint16]*turnChannelBinding{
		0x4001: {Channel: 0x4001, Peer: peer, Active: true, ExpiresAt: time.Now().Add(time.Hour)},
	}
	mesh.mu.Unlock()
	send := func(sequence uint64) {
		t.Helper()
		channelData, err := encodeTurnChannelData(0x4001, encodeInbound(t, session, sequence, authenticatedPeerTestPacket()))
		if err != nil {
			t.Fatalf("encode channel data: %v", err)
		}
		mesh.handleUDP(channelData, relay)
		select {
		case <-device.written:
		case <-time.After(2 * time.Second):
			t.Fatal("a relayed data frame never reached the virtual device")
		}
	}
	return mesh, session, device, send
}

func pathOf(mesh *peerMeshClient, session *peerMeshSession) (string, string, *net.UDPAddr) {
	mesh.mu.Lock()
	defer mesh.mu.Unlock()
	return session.PathType, session.RelayTargetAllocationID, session.RemoteEndpoint
}

// A frame that arrives over the relay while the peer is still heard direct was already in flight,
// or was sent by a peer that is about to come back. Following it would move this side to the relay,
// and the peer, seeing this side's frames arrive there, would follow in turn.
func TestRelayFrameDoesNotMoveASessionThatStillHearsItsPeerDirect(t *testing.T) {
	mesh, session, _, sendRelay := relayTestMesh(t)
	direct := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 42000}
	mesh.mu.Lock()
	session.RemoteEndpoint = direct
	session.LastDirectSuccess = time.Now()
	mesh.mu.Unlock()

	sendRelay(1)
	path, relayTarget, endpoint := pathOf(mesh, session)
	if path != "DIRECT" || relayTarget != "" || endpoint == nil || endpoint.String() != direct.String() {
		t.Fatalf("path = %s relay=%q via %v, want DIRECT via %v", path, relayTarget, endpoint, direct)
	}
	mesh.mu.Lock()
	lastRelay := session.LastRelaySuccess
	mesh.mu.Unlock()
	if lastRelay.IsZero() {
		t.Error("the relay delivered a frame, and that success should still be recorded")
	}
}

// Once the direct path has been quiet for longer than the window, the peer has moved to the relay
// and this side follows.
func TestRelayFrameMovesASessionWhoseDirectPathWentQuiet(t *testing.T) {
	mesh, session, _, sendRelay := relayTestMesh(t)
	mesh.mu.Lock()
	session.RemoteEndpoint = &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 42000}
	session.LastDirectSuccess = time.Now().Add(-peerRelayFollowQuiet - time.Second)
	mesh.mu.Unlock()

	sendRelay(1)
	if path, relayTarget, _ := pathOf(mesh, session); path != "RELAY" || relayTarget == "" {
		t.Fatalf("path = %s relay=%q, want RELAY with a target", path, relayTarget)
	}
}

// A peer checks its relay the whole time a direct path works. The check is answered over the relay,
// and this side keeps sending direct.
func TestRelayCheckDoesNotMoveAHealthyDirectSession(t *testing.T) {
	mesh, session, _, _ := relayTestMesh(t)
	direct := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 42000}
	mesh.mu.Lock()
	session.RemoteEndpoint = direct
	session.LastDirectSuccess = time.Now().Add(-10 * time.Second)
	mesh.mu.Unlock()

	mesh.markPathFromInboundCheck(session, nil, "allocation-1")
	path, relayTarget, endpoint := pathOf(mesh, session)
	if path != "DIRECT" || relayTarget != "" || endpoint == nil {
		t.Fatalf("path = %s relay=%q via %v, want DIRECT", path, relayTarget, endpoint)
	}
}

// Without a healthy direct path, a relay check is what first gives the session a way to send.
func TestRelayCheckMovesASessionWithoutAHealthyDirectPath(t *testing.T) {
	mesh, session, _, _ := relayTestMesh(t)
	mesh.mu.Lock()
	session.LastDirectSuccess = time.Now().Add(-peerDirectStaleInterval - time.Second)
	mesh.mu.Unlock()

	mesh.markPathFromInboundCheck(session, nil, "allocation-1")
	if path, relayTarget, _ := pathOf(mesh, session); path != "RELAY" || relayTarget != "allocation-1" {
		t.Fatalf("path = %s relay=%q, want RELAY via allocation-1", path, relayTarget)
	}
}

// A peer that restarted answers from a new socket. What this side learned about the old one, a
// sticky endpoint and a direct path still counted healthy, must not keep the session on a socket
// whose process is gone.
func TestAPeerRestartLetsItsNewEndpointTakeOver(t *testing.T) {
	mesh, session, _, _ := relayTestMesh(t)
	old := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 42000}
	fresh := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 43000}
	mesh.mu.Lock()
	session.RemoteEndpoint = old
	session.EndpointSuccess = time.Now()
	session.EndpointRTT = 1
	session.LastDirectSuccess = time.Now()
	restarted := session.applyRemoteKeyEpoch("epoch-restarted")
	mesh.mu.Unlock()
	if !restarted {
		t.Fatal("precondition: a second epoch is a restart")
	}

	mesh.markPathFromInboundCheck(session, fresh, "")
	if _, _, endpoint := pathOf(mesh, session); endpoint == nil || endpoint.String() != fresh.String() {
		t.Fatalf("endpoint = %v, want the restarted peer's %v", endpoint, fresh)
	}
}

// The same restart seen first over the relay: the old direct path no longer counts as healthy, so
// the relay check gives the session a way to send.
func TestAPeerRestartLetsItsRelayCheckTakeOver(t *testing.T) {
	mesh, session, _, _ := relayTestMesh(t)
	mesh.mu.Lock()
	session.RemoteEndpoint = &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 42000}
	session.EndpointSuccess = time.Now()
	session.LastDirectSuccess = time.Now()
	session.applyRemoteKeyEpoch("epoch-restarted")
	mesh.mu.Unlock()

	mesh.markPathFromInboundCheck(session, nil, "allocation-9")
	if path, relayTarget, _ := pathOf(mesh, session); path != "RELAY" || relayTarget != "allocation-9" {
		t.Fatalf("path = %s relay=%q, want RELAY via allocation-9", path, relayTarget)
	}
}
