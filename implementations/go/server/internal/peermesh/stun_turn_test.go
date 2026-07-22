package peermesh

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/config"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/stunserver"
)

const (
	stunAttrMappedAddress = 0x0001
	stunAttrChangeRequest = 0x0003
	stunAttrUnknownAttrs  = 0x000A
	stunAttrPadding       = 0x0026
	stunAttrResponsePort  = 0x0027
)

func TestStunTurnBindingReturnsMappedAndOtherAddress(t *testing.T) {
	server, sockets := basicBindingTestServer(t)
	client := listenUDP(t)

	tx := sendBindingRequest(t, server, stunserver.Primary, udpAddr(client))
	response := readStunMessage(t, client)
	if response.Type != stunBindingSuccess {
		t.Fatalf("binding response type = 0x%x", response.Type)
	}
	mapped, ok := response.xorMappedAddress()
	if !ok || mapped.Port != udpAddr(client).Port {
		t.Fatalf("xor mapped address = %+v", mapped)
	}
	// Java StunBindingService 始终同时返回明文 MAPPED-ADDRESS 与 XOR-MAPPED-ADDRESS。
	plain, ok := response.first(stunAttrMappedAddress)
	if !ok {
		t.Fatalf("mapped address attribute missing")
	}
	if got := int(binary.BigEndian.Uint16(plain.Value[2:4])); got != udpAddr(client).Port {
		t.Fatalf("mapped address port = %d", got)
	}
	// basic 拓扑走 legacy 分支：RESPONSE-ORIGIN/OTHER-ADDRESS 为 XOR 编码（对齐 Java）。
	origin, ok := response.first(stunAttrResponseOrigin)
	if !ok {
		t.Fatalf("response origin attribute missing")
	}
	originAddr, ok := decodeStunXorAddress(origin.Value, tx)
	if !ok || originAddr.Port != udpAddr(sockets[stunserver.Primary]).Port {
		t.Fatalf("response origin = %+v", originAddr)
	}
	other, ok := response.otherAddress()
	if !ok || other.Port != udpAddr(sockets[stunserver.PrimaryAlternatePort]).Port {
		t.Fatalf("other address = %+v", other)
	}
}

func TestStunTurnBindingChangeRequestUnsupportedWithoutRFC5780(t *testing.T) {
	server, _ := basicBindingTestServer(t)
	client := listenUDP(t)

	sendBindingRequest(t, server, stunserver.Primary, udpAddr(client), stunChangeRequestAttr(0x02))
	response, _ := readBindingResponse(t, client)
	if response.Type != stunserver.BindingError {
		t.Fatalf("binding response type = 0x%x, want error", response.Type)
	}
	if got := response.ErrorCode(); got != 420 {
		t.Fatalf("error code = %d, want 420", got)
	}
	if got := bindingErrorReason(t, response); got != "unsupported-change-request" {
		t.Fatalf("error reason = %q", got)
	}
	unknown, ok := response.First(stunserver.AttrUnknownAttrs)
	if !ok || len(unknown.Value) != 2 || binary.BigEndian.Uint16(unknown.Value) != stunAttrChangeRequest {
		t.Fatalf("unknown attributes = %x", unknown.Value)
	}
}

func TestStunTurnBindingChangeRequestValidation(t *testing.T) {
	server, _ := basicBindingTestServer(t)
	client := listenUDP(t)

	sendBindingRequest(t, server, stunserver.Primary, udpAddr(client),
		stunAttribute{Type: stunAttrChangeRequest, Value: []byte{0, 2}})
	response, _ := readBindingResponse(t, client)
	if got := response.ErrorCode(); got != 400 {
		t.Fatalf("short change-request error code = %d, want 400", got)
	}
	if got := bindingErrorReason(t, response); got != "invalid-change-request" {
		t.Fatalf("error reason = %q", got)
	}

	sendBindingRequest(t, server, stunserver.Primary, udpAddr(client), stunChangeRequestAttr(0x08))
	response, _ = readBindingResponse(t, client)
	if got := response.ErrorCode(); got != 400 {
		t.Fatalf("unknown-flag change-request error code = %d, want 400", got)
	}
	if got := bindingErrorReason(t, response); got != "invalid-change-request-flags" {
		t.Fatalf("error reason = %q", got)
	}
}

func TestStunTurnBindingChangeRequestSelectsResponseEndpoint(t *testing.T) {
	server, sockets, topology := rfc5780BindingTestServer(t)

	cases := []struct {
		name     string
		flags    uint32
		expected stunserver.EndpointID
	}{
		{"none", 0x00, stunserver.Primary},
		{"change-port", 0x02, stunserver.PrimaryAlternatePort},
		{"change-address", 0x04, stunserver.AlternatePrimaryPort},
		{"change-both", 0x06, stunserver.Alternate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := listenUDP(t)
			sendBindingRequest(t, server, stunserver.Primary, udpAddr(client), stunChangeRequestAttr(tc.flags))
			response, source := readBindingResponse(t, client)
			if response.Type != stunserver.BindingSuccess {
				t.Fatalf("binding response type = 0x%x, want success", response.Type)
			}
			if want := udpAddr(sockets[tc.expected]).Port; source.Port != want {
				t.Fatalf("response source port = %d, want endpoint %s port %d", source.Port, tc.expected, want)
			}
			origin, ok := response.ResponseOrigin()
			if !ok {
				t.Fatalf("response origin missing")
			}
			endpoint, ok := topology.Endpoint(tc.expected)
			if !ok {
				t.Fatalf("topology endpoint %s missing", tc.expected)
			}
			if origin.Port != endpoint.Advertised.Port || !origin.IP.Equal(endpoint.Advertised.IP) {
				t.Fatalf("response origin = %v, want %v", origin, endpoint.Advertised)
			}
		})
	}
}

func TestStunTurnBindingResponsePortRedirectsResponse(t *testing.T) {
	server, _ := basicBindingTestServer(t)
	client := listenUDP(t)
	redirected := listenUDP(t)

	sendBindingRequest(t, server, stunserver.Primary, udpAddr(client), stunResponsePortAttr(udpAddr(redirected).Port))
	response, _ := readBindingResponse(t, redirected)
	if response.Type != stunserver.BindingSuccess {
		t.Fatalf("binding response type = 0x%x, want success", response.Type)
	}
	mapped, ok := response.XorMappedAddress()
	if !ok || mapped.Port != udpAddr(client).Port {
		t.Fatalf("xor mapped address = %+v, want client port %d", mapped, udpAddr(client).Port)
	}
}

func TestStunTurnBindingResponsePortInvalid(t *testing.T) {
	server, _ := basicBindingTestServer(t)
	client := listenUDP(t)

	sendBindingRequest(t, server, stunserver.Primary, udpAddr(client),
		stunAttribute{Type: stunAttrResponsePort, Value: []byte{0, 0, 0, 80}})
	response, _ := readBindingResponse(t, client)
	if got := response.ErrorCode(); got != 400 {
		t.Fatalf("error code = %d, want 400", got)
	}
	if got := bindingErrorReason(t, response); got != "invalid-response-port" {
		t.Fatalf("error reason = %q", got)
	}

	sendBindingRequest(t, server, stunserver.Primary, udpAddr(client), stunResponsePortAttr(0))
	response, _ = readBindingResponse(t, client)
	if got := response.ErrorCode(); got != 400 {
		t.Fatalf("zero response-port error code = %d, want 400", got)
	}
	if got := bindingErrorReason(t, response); got != "invalid-response-port" {
		t.Fatalf("error reason = %q", got)
	}
}

func TestStunTurnBindingResponsePortAndPaddingAreMutuallyExclusive(t *testing.T) {
	server, _ := basicBindingTestServer(t)
	client := listenUDP(t)

	sendBindingRequest(t, server, stunserver.Primary, udpAddr(client),
		stunResponsePortAttr(udpAddr(client).Port), stunPaddingAttr(16))
	response, _ := readBindingResponse(t, client)
	if got := response.ErrorCode(); got != 400 {
		t.Fatalf("error code = %d, want 400", got)
	}
	if got := bindingErrorReason(t, response); got != "response-port-and-padding-are-mutually-exclusive" {
		t.Fatalf("error reason = %q", got)
	}
}

func TestStunTurnBindingPaddingMirrorsRequestPadding(t *testing.T) {
	server, _ := basicBindingTestServer(t)

	cases := []struct {
		name        string
		requestPad  int
		expectedPad int
	}{
		// boundedByDatagram = len(payload)-20 = 4+requestPad，大于 requestPad，回显原长度。
		{"echo", 100, 100},
		// 响应填充上限 1472（对齐 Java DEFAULT_MAX_PADDING_RESPONSE_BYTES）。
		{"capped", 2000, stunMaxPaddingResponseBytes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := listenUDP(t)
			sendBindingRequest(t, server, stunserver.Primary, udpAddr(client), stunPaddingAttr(tc.requestPad))
			response, _ := readBindingResponse(t, client)
			if response.Type != stunserver.BindingSuccess {
				t.Fatalf("binding response type = 0x%x, want success", response.Type)
			}
			padding, ok := response.First(stunserver.AttrPadding)
			if !ok {
				t.Fatalf("padding attribute missing")
			}
			if len(padding.Value) != tc.expectedPad {
				t.Fatalf("padding bytes = %d, want %d", len(padding.Value), tc.expectedPad)
			}
		})
	}
}

func stunChangeRequestAttr(flags uint32) stunAttribute {
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value, flags)
	return stunAttribute{Type: stunAttrChangeRequest, Value: value}
}

func stunResponsePortAttr(port int) stunAttribute {
	value := make([]byte, 2)
	binary.BigEndian.PutUint16(value, uint16(port))
	return stunAttribute{Type: stunAttrResponsePort, Value: value}
}

func stunPaddingAttr(length int) stunAttribute {
	return stunAttribute{Type: stunAttrPadding, Value: make([]byte, length)}
}

func sendBindingRequest(t *testing.T, server *stunTurnServer, incoming stunserver.EndpointID,
	remote *net.UDPAddr, attrs ...stunAttribute) [stunTransactionIDBytes]byte {
	t.Helper()
	tx := newStunTransactionID()
	payload := newStunMessage(stunBindingRequest, tx, attrs...).bytes()
	if err := server.bindingRequest(incoming, payload, remote); err != nil {
		t.Fatalf("binding request: %v", err)
	}
	return tx
}

func readBindingResponse(t *testing.T, conn *net.UDPConn) (stunserver.Message, *net.UDPAddr) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	var buf [65507]byte
	n, source, err := conn.ReadFromUDP(buf[:])
	if err != nil {
		t.Fatalf("read udp: %v", err)
	}
	message, err := stunserver.ParseMessage(buf[:n])
	if err != nil {
		t.Fatalf("parse stun message: %v; raw=%x", err, buf[:n])
	}
	return message, source
}

func bindingErrorReason(t *testing.T, message stunserver.Message) string {
	t.Helper()
	attr, ok := message.First(stunserver.AttrErrorCode)
	if !ok || len(attr.Value) < 4 {
		t.Fatalf("error code attribute missing: %+v", message.Attributes)
	}
	return string(attr.Value[4:])
}

func newBindingTestServer(t *testing.T, topology stunserver.Topology,
	sockets map[stunserver.EndpointID]*net.UDPConn) *stunTurnServer {
	t.Helper()
	server := newStunTurnTestServer(t)
	server.sockets = sockets
	server.primary = sockets[stunserver.Primary]
	server.binding = stunserver.NewBindingService(
		topology, stunTurnSoftware, !topology.SupportsRFC5780(), stunMaxPaddingResponseBytes)
	return server
}

func basicBindingTestServer(t *testing.T) (*stunTurnServer, map[stunserver.EndpointID]*net.UDPConn) {
	t.Helper()
	primary := listenUDP(t)
	alternate := listenUDP(t)
	alternateEndpoint := stunserver.Endpoint{
		ID:         stunserver.PrimaryAlternatePort,
		Bind:       udpAddr(alternate),
		Advertised: udpAddr(alternate),
	}
	topology, err := stunserver.NewBasicTopology(
		stunserver.Endpoint{ID: stunserver.Primary, Bind: udpAddr(primary), Advertised: udpAddr(primary)},
		&alternateEndpoint)
	if err != nil {
		t.Fatalf("basic topology: %v", err)
	}
	sockets := map[stunserver.EndpointID]*net.UDPConn{
		stunserver.Primary:              primary,
		stunserver.PrimaryAlternatePort: alternate,
	}
	return newBindingTestServer(t, topology, sockets), sockets
}

// rfc5780BindingTestServer 构造四端点拓扑。macOS 默认不为 127.0.0.2 配置回环别名，
// 因此备用 IP 只出现在拓扑的 advertised/bind 元数据里，实际 socket 全部绑在 127.0.0.1；
// 端点选择通过响应来源端口验证。
func rfc5780BindingTestServer(t *testing.T) (*stunTurnServer, map[stunserver.EndpointID]*net.UDPConn, stunserver.Topology) {
	t.Helper()
	sockets := make(map[stunserver.EndpointID]*net.UDPConn, 4)
	for _, id := range []stunserver.EndpointID{
		stunserver.Primary, stunserver.PrimaryAlternatePort,
		stunserver.AlternatePrimaryPort, stunserver.Alternate,
	} {
		sockets[id] = listenUDP(t)
	}
	primaryIP := net.ParseIP("127.0.0.1")
	alternateIP := net.ParseIP("127.0.0.2")
	primaryPort := udpAddr(sockets[stunserver.Primary]).Port
	alternatePort := udpAddr(sockets[stunserver.PrimaryAlternatePort]).Port
	endpoint := func(id stunserver.EndpointID, ip net.IP, port int) stunserver.Endpoint {
		return stunserver.Endpoint{
			ID:         id,
			Bind:       &net.UDPAddr{IP: ip, Port: port},
			Advertised: &net.UDPAddr{IP: ip, Port: port},
		}
	}
	topology, err := stunserver.NewRFC5780Topology(
		endpoint(stunserver.Primary, primaryIP, primaryPort),
		endpoint(stunserver.PrimaryAlternatePort, primaryIP, alternatePort),
		endpoint(stunserver.AlternatePrimaryPort, alternateIP, primaryPort),
		endpoint(stunserver.Alternate, alternateIP, alternatePort))
	if err != nil {
		t.Fatalf("rfc5780 topology: %v", err)
	}
	return newBindingTestServer(t, topology, sockets), sockets, topology
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

func TestStunTurnSendIndicationRejectsOpaquePayload(t *testing.T) {
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

	if got := readOptionalUDPBytes(t, peer); len(got) != 0 {
		t.Fatalf("peer received forbidden opaque payload: %x", got)
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

	if err := server.dispatchRelayPayload(allocation, udpAddr(peer), []byte("world")); err != nil {
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

func TestStunTurnChannelBindDispatchesChannelData(t *testing.T) {
	server := newStunTurnTestServer(t)
	primary := listenUDP(t)
	client := listenUDP(t)
	peer := listenUDP(t)
	server.primary = primary
	allocation, err := server.allocate(context.Background(), udpAddr(client))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	channel := uint16(turnChannelMin)
	tx := newStunTransactionID()
	request := newStunMessage(stunChannelBindRequest, tx,
		stunAttrChannelNumberValue(channel), newStunAttrXorPeerAddress(udpAddr(peer), tx))
	if err := server.channelBind(request, udpAddr(client)); err != nil {
		t.Fatalf("channel bind: %v", err)
	}
	if response := readStunMessage(t, client); response.Type != stunChannelBindSuccess {
		t.Fatalf("channel bind response type = 0x%x", response.Type)
	}
	if err := server.dispatchRelayPayload(allocation, udpAddr(peer), []byte("world")); err != nil {
		t.Fatalf("dispatch ChannelData: %v", err)
	}
	packet := readUDPBytes(t, client)
	frame, err := parseTurnChannelData(packet)
	if err != nil || frame.Channel != channel || string(frame.Payload) != "world" {
		t.Fatalf("ChannelData = %+v err=%v raw=%x", frame, err, packet)
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
	frame := make([]byte, peerDataHeaderBytes+peerDataTagBytes)
	binary.BigEndian.PutUint32(frame[:4], peerDataMagic)
	binary.BigEndian.PutUint64(frame[4:12], uint64(sessionID))
	binary.BigEndian.PutUint64(frame[12:20], 1)
	return frame
}

func TestGeneralRelayDestinationPolicy(t *testing.T) {
	// General relay destinations come straight from the browser, so anything pointing back into
	// the server's own network must be refused.
	allowed := []string{"203.0.113.10", "2001:db8::10"}
	for _, host := range allowed {
		addr := &net.UDPAddr{IP: net.ParseIP(host), Port: 50000}
		if !isRelayableDestination(addr) {
			t.Fatalf("isRelayableDestination(%s) = false, want true", host)
		}
	}
	refused := []string{"127.0.0.1", "0.0.0.0", "192.168.1.10", "10.0.0.5",
		"169.254.1.10", "239.1.1.1", "100.96.0.2", "fd00::1"}
	for _, host := range refused {
		addr := &net.UDPAddr{IP: net.ParseIP(host), Port: 50000}
		if isRelayableDestination(addr) {
			t.Fatalf("isRelayableDestination(%s) = true, want false", host)
		}
	}
	if isRelayableDestination(&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 0}) {
		t.Fatalf("zero port must be refused")
	}
	if isRelayableDestination(nil) {
		t.Fatalf("nil address must be refused")
	}
}
