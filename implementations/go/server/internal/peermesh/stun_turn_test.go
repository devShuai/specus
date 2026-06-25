package peermesh

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/config"
)

func TestStunTurnAllocateReusesExpiredAllocationBeforeCleanup(t *testing.T) {
	server := newStunTurnTestServer()
	remote := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 50000}

	first := server.allocate(remote)
	expireAllocation(server, first.ID, remote)

	again := server.allocate(remote)
	if again.ID != first.ID {
		t.Fatalf("allocate created new id for expired allocation before cleanup: got %q want %q", again.ID, first.ID)
	}
	if !again.ExpiresAt.After(time.Now()) {
		t.Fatalf("reused allocation was not refreshed: %+v", again)
	}
}

func TestStunTurnRefreshReusesExpiredAllocationBeforeCleanup(t *testing.T) {
	server := newStunTurnTestServer()
	remote := &net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: 50001}

	allocation := server.allocate(remote)
	expireAllocation(server, allocation.ID, remote)

	if err := server.refresh(relayMessage{AllocationID: allocation.ID}, remote); err != nil {
		t.Fatalf("refresh expired allocation before cleanup: %v", err)
	}
	stored := server.allocations[allocation.ID]
	if !stored.ExpiresAt.After(time.Now()) {
		t.Fatalf("expired allocation was not refreshed: %+v", stored)
	}
}

func TestStunTurnSourceAllocationAcceptsExpiredAllocationBeforeCleanup(t *testing.T) {
	server := newStunTurnTestServer()
	remote := &net.UDPAddr{IP: net.ParseIP("192.0.2.12"), Port: 50002}

	allocation := server.allocate(remote)
	expireAllocation(server, allocation.ID, remote)

	source := server.sourceAllocation(relayMessage{AllocationID: allocation.ID}, remote)
	if source == nil || source.ID != allocation.ID {
		t.Fatalf("source allocation mismatch: got %+v want id %q", source, allocation.ID)
	}
	if found := server.findAllocation(allocation.ID); found == nil || found.ID != allocation.ID {
		t.Fatalf("find allocation mismatch: got %+v want id %q", found, allocation.ID)
	}
}

func TestStunTurnCleanupRemovesExpiredAllocation(t *testing.T) {
	server := newStunTurnTestServer()
	remote := &net.UDPAddr{IP: net.ParseIP("192.0.2.13"), Port: 50003}

	allocation := server.allocate(remote)
	expireAllocation(server, allocation.ID, remote)

	server.cleanupExpired()

	if _, ok := server.allocations[allocation.ID]; ok {
		t.Fatalf("cleanup kept expired allocation: %+v", server.allocations[allocation.ID])
	}
	if _, ok := server.allocationByEndpoint[endpointKey(remote)]; ok {
		t.Fatalf("cleanup kept endpoint index for expired allocation")
	}
}

func TestStunTurnRelayDataRejectsMissingSourceAllocation(t *testing.T) {
	server := newStunTurnTestServer()
	primary := listenUDP(t)
	sourceSocket := listenUDP(t)
	server.primary = primary

	err := server.relayData(context.Background(), relayMessage{
		AllocationID:   "missing-source",
		ToAllocationID: "missing-target",
		PayloadBase64:  base64.StdEncoding.EncodeToString([]byte("hello")),
	}, udpAddr(sourceSocket))
	if err != nil {
		t.Fatalf("relay data missing source: %v", err)
	}

	response := readRelayMessage(t, sourceSocket)
	if response.Type != relayTypeError || response.Error != "allocation-not-found" {
		t.Fatalf("source allocation error mismatch: %+v", response)
	}
}

func TestStunTurnRelayDataRejectsMissingTargetAllocation(t *testing.T) {
	server := newStunTurnTestServer()
	primary := listenUDP(t)
	sourceSocket := listenUDP(t)
	server.primary = primary
	source := server.allocate(udpAddr(sourceSocket))

	err := server.relayData(context.Background(), relayMessage{
		AllocationID:   source.ID,
		ToAllocationID: "missing-target",
		PayloadBase64:  base64.StdEncoding.EncodeToString([]byte("hello")),
	}, udpAddr(sourceSocket))
	if err != nil {
		t.Fatalf("relay data missing target: %v", err)
	}

	response := readRelayMessage(t, sourceSocket)
	if response.Type != relayTypeError || response.Error != "target-allocation-not-found" {
		t.Fatalf("target allocation error mismatch: %+v", response)
	}
}

func TestStunTurnRelayDataRejectsInvalidPayload(t *testing.T) {
	server := newStunTurnTestServer()
	primary := listenUDP(t)
	sourceSocket := listenUDP(t)
	targetSocket := listenUDP(t)
	server.primary = primary
	source := server.allocate(udpAddr(sourceSocket))
	target := server.allocate(udpAddr(targetSocket))

	err := server.relayData(context.Background(), relayMessage{
		AllocationID:   source.ID,
		ToAllocationID: target.ID,
		PayloadBase64:  "not-base64%",
	}, udpAddr(sourceSocket))
	if err != nil {
		t.Fatalf("relay data invalid payload: %v", err)
	}

	response := readRelayMessage(t, sourceSocket)
	if response.Type != relayTypeError || response.Error != "invalid-payload" {
		t.Fatalf("invalid payload error mismatch: %+v", response)
	}
}

func TestStunTurnRelayDataRejectsDeniedPeerFrame(t *testing.T) {
	server := newStunTurnTestServer()
	server.service.db = openPeerMeshTestDB(t)
	primary := listenUDP(t)
	sourceSocket := listenUDP(t)
	targetSocket := listenUDP(t)
	server.primary = primary
	source := server.allocate(udpAddr(sourceSocket))
	target := server.allocate(udpAddr(targetSocket))

	err := server.relayData(context.Background(), relayMessage{
		AllocationID:   source.ID,
		ToAllocationID: target.ID,
		PayloadBase64:  base64.StdEncoding.EncodeToString(testPeerDataFrame(9901, 1, 2)),
	}, udpAddr(sourceSocket))
	if err != nil {
		t.Fatalf("relay data denied peer frame: %v", err)
	}

	response := readRelayMessage(t, sourceSocket)
	if response.Type != relayTypeError || response.Error != "relay-session-denied" {
		t.Fatalf("relay denied error mismatch: %+v", response)
	}
}

func TestStunTurnRelayDataForwardsOpaquePayload(t *testing.T) {
	server := newStunTurnTestServer()
	primary := listenUDP(t)
	sourceSocket := listenUDP(t)
	targetSocket := listenUDP(t)
	server.primary = primary
	source := server.allocate(udpAddr(sourceSocket))
	target := server.allocate(udpAddr(targetSocket))
	payload := base64.StdEncoding.EncodeToString([]byte("hello"))

	err := server.relayData(context.Background(), relayMessage{
		TransactionID:  "tx-1",
		AllocationID:   source.ID,
		ToAllocationID: target.ID,
		PayloadBase64:  payload,
	}, udpAddr(sourceSocket))
	if err != nil {
		t.Fatalf("relay data forward opaque payload: %v", err)
	}

	response := readRelayMessage(t, targetSocket)
	if response.Type != relayTypeData || response.FromAllocationID != source.ID ||
		response.ToAllocationID != target.ID || response.PayloadBase64 != payload || response.TransactionID != "tx-1" {
		t.Fatalf("forwarded data mismatch: %+v", response)
	}
}

func newStunTurnTestServer() *stunTurnServer {
	return &stunTurnServer{
		service: &Service{cfg: config.PeerMeshConfig{
			Enabled:              true,
			AllocationTTLSeconds: 60,
			StunTurnPort:         3478,
		}},
		allocations:          make(map[string]relayAllocation),
		allocationByEndpoint: make(map[string]string),
	}
}

func expireAllocation(server *stunTurnServer, id string, remote *net.UDPAddr) {
	server.mu.Lock()
	defer server.mu.Unlock()
	server.allocations[id] = relayAllocation{
		ID:        id,
		Remote:    cloneUDPAddr(remote),
		ExpiresAt: time.Now().Add(-time.Second),
	}
	server.allocationByEndpoint[endpointKey(remote)] = id
}

func listenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func udpAddr(conn *net.UDPConn) *net.UDPAddr {
	return conn.LocalAddr().(*net.UDPAddr)
}

func readRelayMessage(t *testing.T, conn *net.UDPConn) relayMessage {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	var buf [65507]byte
	n, _, err := conn.ReadFromUDP(buf[:])
	if err != nil {
		t.Fatalf("read relay message: %v", err)
	}
	var message relayMessage
	if err := json.Unmarshal(buf[:n], &message); err != nil {
		t.Fatalf("decode relay message: %v; raw=%s", err, string(buf[:n]))
	}
	return message
}

func testPeerDataFrame(sessionID, fromClientID, toClientID int64) []byte {
	frame := make([]byte, peerDataHeaderBytes)
	binary.BigEndian.PutUint32(frame[:4], peerDataMagic)
	frame[4] = peerDataVersion
	frame[5] = peerDataTypeData
	binary.BigEndian.PutUint64(frame[6:14], uint64(sessionID))
	binary.BigEndian.PutUint64(frame[14:22], uint64(fromClientID))
	binary.BigEndian.PutUint64(frame[22:30], uint64(toClientID))
	binary.BigEndian.PutUint64(frame[30:38], 1)
	return frame
}
