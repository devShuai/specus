package peermesh

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/config"
)

func TestStunTurnBindingReturnsMappedAndOtherAddress(t *testing.T) {
	server := newStunTurnTestServer(t)
	primary := listenUDP(t)
	alternate := listenUDP(t)
	client := listenUDP(t)
	server.primary = primary
	server.alternate = alternate

	tx := newStunTransactionID()
	err := server.binding(primary, "primary", newStunMessage(stunBindingRequest, tx), udpAddr(client))
	if err != nil {
		t.Fatalf("binding: %v", err)
	}

	response := readStunMessage(t, client)
	if response.Type != stunBindingSuccess {
		t.Fatalf("binding response type = 0x%x", response.Type)
	}
	mapped, ok := response.xorMappedAddress()
	if !ok || mapped.Port != udpAddr(client).Port {
		t.Fatalf("mapped address = %+v", mapped)
	}
	other, ok := response.otherAddress()
	if !ok || other.Port != udpAddr(alternate).Port {
		t.Fatalf("other address = %+v", other)
	}
}

func TestStunTurnAllocateReplacesExpiredAllocationBeforeCleanup(t *testing.T) {
	server := newStunTurnTestServer(t)
	remote := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 50000}

	first, err := server.allocate(context.Background(), remote)
	if err != nil {
		t.Fatalf("first allocate: %v", err)
	}
	expireAllocation(server, first.ID, remote)

	again, err := server.allocate(context.Background(), remote)
	if err != nil {
		t.Fatalf("second allocate: %v", err)
	}
	if again.ID == first.ID {
		t.Fatalf("allocate reused expired allocation id: %q", again.ID)
	}
	if !again.ExpiresAt.After(time.Now()) {
		t.Fatalf("new allocation was not refreshed: %+v", again)
	}
}

func TestStunTurnAllocateRequestReturnsRelayedAddress(t *testing.T) {
	server := newStunTurnTestServer(t)
	primary := listenUDP(t)
	client := listenUDP(t)
	server.primary = primary

	tx := newStunTransactionID()
	request := newStunMessage(stunAllocateRequest, tx, stunAttrRequestedUDPTransport())
	if err := server.allocateRequest(context.Background(), request, udpAddr(client)); err != nil {
		t.Fatalf("allocate request: %v", err)
	}

	response := readStunMessage(t, client)
	if response.Type != stunAllocateSuccess {
		t.Fatalf("allocate response type = 0x%x", response.Type)
	}
	relayed, ok := response.xorRelayedAddress()
	if !ok || relayed.Port <= 0 {
		t.Fatalf("relayed address = %+v", relayed)
	}
	if response.lifetimeSeconds(0) != 60 {
		t.Fatalf("lifetime = %d", response.lifetimeSeconds(0))
	}
}

func TestStunTurnRefreshRejectsExpiredAllocationBeforeCleanup(t *testing.T) {
	server := newStunTurnTestServer(t)
	primary := listenUDP(t)
	client := listenUDP(t)
	server.primary = primary

	allocation, err := server.allocate(context.Background(), udpAddr(client))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	expireAllocation(server, allocation.ID, udpAddr(client))

	tx := newStunTransactionID()
	request := newStunMessage(stunRefreshRequest, tx, stunAttrLifetimeValue(30))
	if err := server.refresh(request, udpAddr(client)); err != nil {
		t.Fatalf("refresh expired allocation: %v", err)
	}
	stored := server.allocations[allocation.ID]
	if stored != nil {
		t.Fatalf("expired allocation was not removed: %+v", stored)
	}
	response := readStunMessage(t, client)
	if response.Type != stunRefreshError {
		t.Fatalf("refresh response type = 0x%x, want error", response.Type)
	}
}

func TestStunTurnRefreshReturnsGrantedServerLifetime(t *testing.T) {
	server := newStunTurnTestServer(t)
	primary := listenUDP(t)
	client := listenUDP(t)
	server.primary = primary

	if _, err := server.allocate(context.Background(), udpAddr(client)); err != nil {
		t.Fatalf("allocate: %v", err)
	}

	tx := newStunTransactionID()
	request := newStunMessage(stunRefreshRequest, tx, stunAttrLifetimeValue(120))
	if err := server.refresh(request, udpAddr(client)); err != nil {
		t.Fatalf("refresh allocation: %v", err)
	}
	response := readStunMessage(t, client)
	if response.Type != stunRefreshSuccess {
		t.Fatalf("refresh response type = 0x%x, want success", response.Type)
	}
	if got := response.lifetimeSeconds(0); got != 60 {
		t.Fatalf("refresh lifetime = %d, want granted server ttl 60", got)
	}
}

func TestStunTurnCleanupRemovesExpiredAllocation(t *testing.T) {
	server := newStunTurnTestServer(t)
	remote := &net.UDPAddr{IP: net.ParseIP("192.0.2.13"), Port: 50003}

	allocation, err := server.allocate(context.Background(), remote)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	expireAllocation(server, allocation.ID, remote)

	server.cleanupExpired()

	if _, ok := server.allocations[allocation.ID]; ok {
		t.Fatalf("cleanup kept expired allocation: %+v", server.allocations[allocation.ID])
	}
	if _, ok := server.allocationByEndpoint[endpointKey(remote)]; ok {
		t.Fatalf("cleanup kept endpoint index for expired allocation")
	}
}

func TestStunTurnSendIndicationForwardsOpaquePayload(t *testing.T) {
	server := newStunTurnTestServer(t)
	primary := listenUDP(t)
	client := listenUDP(t)
	peer := listenUDP(t)
	server.primary = primary
	allocation, err := server.allocate(context.Background(), udpAddr(client))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	allocation.Permission[permissionKey(udpAddr(peer))] = time.Now().Add(time.Minute)

	tx := newStunTransactionID()
	request := newStunMessage(stunSendIndication, tx,
		newStunAttrXorPeerAddress(udpAddr(peer), tx),
		stunAttrDataValue([]byte("hello")))
	if err := server.sendIndication(context.Background(), request, udpAddr(client)); err != nil {
		t.Fatalf("send indication: %v", err)
	}

	if got := readUDPBytes(t, peer); string(got) != "hello" {
		t.Fatalf("peer payload = %q", string(got))
	}
}

func TestStunTurnSendIndicationRejectsDeniedPeerFrame(t *testing.T) {
	server := newStunTurnTestServer(t)
	server.service.db = openPeerMeshTestDB(t)
	client := listenUDP(t)
	peer := listenUDP(t)
	allocation, err := server.allocate(context.Background(), udpAddr(client))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	allocation.Permission[permissionKey(udpAddr(peer))] = time.Now().Add(time.Minute)

	tx := newStunTransactionID()
	request := newStunMessage(stunSendIndication, tx,
		newStunAttrXorPeerAddress(udpAddr(peer), tx),
		stunAttrDataValue(testPeerDataFrame(9901, 1, 2)))
	if err := server.sendIndication(context.Background(), request, udpAddr(client)); err != nil {
		t.Fatalf("send indication denied frame: %v", err)
	}
	if got := readOptionalUDPBytes(t, peer); len(got) != 0 {
		t.Fatalf("denied peer received payload: %x", got)
	}
}

func TestStunTurnRelayReceiveDispatchesDataIndication(t *testing.T) {
	server := newStunTurnTestServer(t)
	primary := listenUDP(t)
	client := listenUDP(t)
	peer := listenUDP(t)
	server.primary = primary
	allocation, err := server.allocate(context.Background(), udpAddr(client))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	allocation.Permission[permissionKey(udpAddr(peer))] = time.Now().Add(time.Minute)

	if err := server.dispatchDataIndication(allocation, udpAddr(peer), []byte("world")); err != nil {
		t.Fatalf("dispatch data indication: %v", err)
	}
	response := readStunMessage(t, client)
	if response.Type != stunDataIndication {
		t.Fatalf("data indication type = 0x%x", response.Type)
	}
	peerAddr, ok := response.xorPeerAddress()
	if !ok || peerAddr.Port != udpAddr(peer).Port {
		t.Fatalf("peer address = %+v", peerAddr)
	}
	payload, ok := response.data()
	if !ok || string(payload) != "world" {
		t.Fatalf("payload = %q", string(payload))
	}
}

func newStunTurnTestServer(t *testing.T) *stunTurnServer {
	t.Helper()
	server := &stunTurnServer{
		service: &Service{cfg: config.PeerMeshConfig{
			Enabled:              true,
			AllocationTTLSeconds: 60,
			StunTurnPort:         3478,
			RelayMinPort:         0,
			RelayMaxPort:         0,
		}},
		logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		allocations:          make(map[string]*relayAllocation),
		allocationByEndpoint: make(map[string]string),
	}
	t.Cleanup(server.closeAllAllocations)
	return server
}

func expireAllocation(server *stunTurnServer, id string, remote *net.UDPAddr) {
	server.mu.Lock()
	defer server.mu.Unlock()
	allocation := server.allocations[id]
	if allocation == nil {
		allocation = &relayAllocation{ID: id, Client: cloneUDPAddr(remote), Permission: make(map[string]time.Time)}
		server.allocations[id] = allocation
	}
	allocation.Client = cloneUDPAddr(remote)
	allocation.ExpiresAt = time.Now().Add(-time.Second)
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

func readStunMessage(t *testing.T, conn *net.UDPConn) stunMessage {
	t.Helper()
	packet := readUDPBytes(t, conn)
	message, err := parseStunMessage(packet)
	if err != nil {
		t.Fatalf("parse stun message: %v; raw=%x", err, packet)
	}
	return *message
}

func readUDPBytes(t *testing.T, conn *net.UDPConn) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	var buf [65507]byte
	n, _, err := conn.ReadFromUDP(buf[:])
	if err != nil {
		t.Fatalf("read udp: %v", err)
	}
	return append([]byte(nil), buf[:n]...)
}

func readOptionalUDPBytes(t *testing.T, conn *net.UDPConn) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	var buf [65507]byte
	n, _, err := conn.ReadFromUDP(buf[:])
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil
		}
		t.Fatalf("read udp: %v", err)
	}
	return append([]byte(nil), buf[:n]...)
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
