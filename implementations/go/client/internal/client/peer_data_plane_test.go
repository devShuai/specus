package client

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// slowVirtualDevice blocks inside WritePacket until it is released, standing in for a TUN device
// whose write stalls (a full queue, a suspended interface, a slow hypervisor).
type slowVirtualDevice struct {
	release chan struct{}
	entered chan struct{}
	writes  atomic.Int64
	once    sync.Once
}

func newSlowVirtualDevice() *slowVirtualDevice {
	return &slowVirtualDevice{release: make(chan struct{}), entered: make(chan struct{}, 64)}
}

func (d *slowVirtualDevice) Name() string                              { return "slow" }
func (d *slowVirtualDevice) Start(<-chan struct{}, func([]byte)) error { return nil }
func (d *slowVirtualDevice) SyncPeerRoutes([]string)                   {}
func (d *slowVirtualDevice) Close() error                              { d.unblock(); return nil }
func (d *slowVirtualDevice) Status() string                            { return "SLOW" }
func (d *slowVirtualDevice) Error() string                             { return "" }

func (d *slowVirtualDevice) WritePacket(packet []byte) error {
	select {
	case d.entered <- struct{}{}:
	default:
	}
	<-d.release
	d.writes.Add(1)
	return nil
}

func (d *slowVirtualDevice) unblock() {
	d.once.Do(func() { close(d.release) })
}

func newDataPlaneTestMesh(t *testing.T, device peerVirtualDevice) (*peerMeshClient, *peerMeshSession) {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = udp.Close() })

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	session := &peerMeshSession{
		ID: 4242, PeerID: 2, PeerVirtualIP: "100.96.0.2", Token: "token",
		ExpiresAt: time.Now().Add(time.Hour), AESKey: key,
		LocalKeyEpoch: "epoch-local", RemoteKeyEpoch: "epoch-remote",
		PathType: "DIRECT",
	}
	if err := session.ensureTrafficCodecs(1); err != nil {
		t.Fatalf("ensure codecs: %v", err)
	}
	mesh := &peerMeshClient{
		config: Config{PeerMeshDevice: "noop"},
		logger: log.New(io.Discard, "", 0),
		runtime: RuntimeConfig{PeerMesh: PeerMeshConfig{
			Enabled: true, ClientID: 1, ClientName: "go-a",
			VirtualIP: "100.96.0.1", CIDR: "100.96.0.0/11",
		}},
		udp:                udp,
		peers:              map[int64]*peerMeshPeer{2: {ClientID: 2, VirtualIP: "100.96.0.2", Online: true}},
		sessions:           map[int64]*peerMeshSession{2: session},
		sessionsByID:       map[int64]*peerMeshSession{session.ID: session},
		packets:            map[int64][]pendingPeerPacket{},
		pending:            map[string]pendingPeerProbe{},
		prepared:           map[int64]time.Time{},
		ignoredPacketLogAt: map[string]time.Time{},
		pathMTUCache:       map[string]cachedPeerPathMTU{},
		device:             device,
	}
	mesh.dataPlane = newPeerDataPlane(2, 8, mesh.handlePeerDataFrame)
	t.Cleanup(func() { mesh.dataPlane.close() })
	return mesh, session
}

// peerProbeDatagram builds a keepalive-style probe: one of the datagram classes that must keep
// flowing while the virtual device is stalled.
func peerProbeDatagram(t *testing.T, session *peerMeshSession) []byte {
	t.Helper()
	probe := peerUDPProbe{
		Magic: peerProbeMagic, Type: peerProbeTypeCheck, SessionID: session.ID,
		FromClientID: session.PeerID, ToClientID: 1, Token: session.Token,
		Nonce: "probe-nonce", SentAtMillis: time.Now().UnixMilli(),
	}
	encoded, err := json.Marshal(probe)
	if err != nil {
		t.Fatalf("marshal probe: %v", err)
	}
	return encoded
}

// encodeInbound produces a frame the mesh will accept as coming from the peer.
func encodeInbound(t *testing.T, session *peerMeshSession, sequence uint64, payload []byte) []byte {
	t.Helper()
	frame, err := encodePeerDataFrame(session.AESKey, session.ID, session.PeerID, 1,
		session.RemoteKeyEpoch, sequence, payload)
	if err != nil {
		t.Fatalf("encode frame: %v", err)
	}
	return frame
}

// A stalled virtual-device write must not stop the receive loop from serving STUN, keepalive and
// probe traffic — those are exactly what path switching depends on when a path degrades.
func TestSlowVirtualDeviceWriteDoesNotBlockTheReceiveLoop(t *testing.T) {
	device := newSlowVirtualDevice()
	defer device.unblock()
	mesh, session := newDataPlaneTestMesh(t, device)
	remote := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 40000}

	// Enough frames to occupy both workers and fill the queues, so the pool is fully stalled.
	payload := make([]byte, 64)
	payload[0] = 0x45
	for sequence := uint64(1); sequence <= 64; sequence++ {
		mesh.handleUDP(encodeInbound(t, session, sequence, payload), remote)
	}
	select {
	case <-device.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("no frame reached the virtual device")
	}

	// The receive loop is what calls handleUDP; with the writes stalled it must still return
	// promptly for every other datagram class.
	done := make(chan struct{})
	go func() {
		defer close(done)
		mesh.handleUDP(peerProbeDatagram(t, session), remote)
		mesh.keepaliveDirectPaths()
		mesh.fallbackStaleDirectPaths()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a stalled virtual-device write blocked probe, keepalive or path handling")
	}

	// Saturation drops frames instead of growing without bound.
	stats := mesh.dataPlane.stats()
	if stats.Rejected == 0 {
		t.Fatalf("expected saturated shards to drop frames, stats=%+v", stats)
	}
	if int(stats.HighWater) > 8 {
		t.Fatalf("queue depth %d exceeded the configured capacity", stats.HighWater)
	}
}

// A UDP flood of data frames must be bounded by the queues rather than buffered without limit, and
// must not stall the loop that reads the socket.
func TestPeerDataFrameFloodIsBoundedAndNonBlocking(t *testing.T) {
	device := newSlowVirtualDevice()
	defer device.unblock()
	mesh, session := newDataPlaneTestMesh(t, device)
	remote := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 8), Port: 41000}

	payload := make([]byte, 64)
	payload[0] = 0x45
	frames := make([][]byte, 0, 2000)
	for sequence := uint64(1); sequence <= 2000; sequence++ {
		frames = append(frames, encodeInbound(t, session, sequence, payload))
	}

	start := time.Now()
	for _, frame := range frames {
		mesh.handleUDP(frame, remote)
	}
	elapsed := time.Since(start)
	if elapsed > 10*time.Second {
		t.Fatalf("feeding %d frames took %v; the receive path is blocking on the device", len(frames), elapsed)
	}

	stats := mesh.dataPlane.stats()
	if stats.Accepted+stats.Rejected != int64(len(frames)) {
		t.Fatalf("accounting mismatch: %+v for %d frames", stats, len(frames))
	}
	if stats.Rejected < int64(len(frames))/2 {
		t.Fatalf("expected the flood to be shed, stats=%+v", stats)
	}
	if int(stats.HighWater) > 8 {
		t.Fatalf("queue high water %d exceeded the capacity", stats.HighWater)
	}
}

func TestPeerDataPlaneShardingIsStableAndInRange(t *testing.T) {
	for _, shards := range []int{1, 2, 4, 8} {
		for _, sessionID := range []int64{0, 1, 7, -7, 1 << 40, -(1 << 40)} {
			shard := peerDataPlaneShard(sessionID, shards)
			if shard < 0 || shard >= shards {
				t.Fatalf("shard(%d, %d) = %d out of range", sessionID, shards, shard)
			}
			if again := peerDataPlaneShard(sessionID, shards); again != shard {
				t.Fatalf("shard(%d, %d) is not stable: %d then %d", sessionID, shards, shard, again)
			}
		}
	}
}

func TestPeerDataPlaneWorkerCountIsClamped(t *testing.T) {
	for _, tt := range []struct{ in, want int }{
		{-1, minPeerDataPlaneWorkers}, {0, minPeerDataPlaneWorkers}, {1, minPeerDataPlaneWorkers},
		{4, 4}, {8, 8}, {64, maxPeerDataPlaneWorkers},
	} {
		if got := boundPeerDataPlaneWorkers(tt.in); got != tt.want {
			t.Fatalf("boundPeerDataPlaneWorkers(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
	if got := defaultPeerDataPlaneWorkers(); got < minPeerDataPlaneWorkers || got > maxPeerDataPlaneWorkers {
		t.Fatalf("defaultPeerDataPlaneWorkers() = %d, out of the clamped range", got)
	}
}

func TestPeerDataPlaneSubmitAfterCloseIsRefused(t *testing.T) {
	var handled atomic.Int64
	plane := newPeerDataPlane(2, 4, func([]byte, *net.UDPAddr, string) { handled.Add(1) })
	plane.close()
	plane.wait()
	if plane.submit(1, peerDataFrameTask{payload: []byte{0}}) {
		t.Fatal("a closed data plane must refuse new frames")
	}
	if handled.Load() != 0 {
		t.Fatalf("handled %d frames after close", handled.Load())
	}
	// Closing twice is harmless.
	plane.close()
}

// recordingVirtualDevice accepts writes immediately and remembers them.
type recordingVirtualDevice struct {
	written chan []byte
}

func newRecordingVirtualDevice() *recordingVirtualDevice {
	return &recordingVirtualDevice{written: make(chan []byte, 16)}
}

func (d *recordingVirtualDevice) Name() string                              { return "recording" }
func (d *recordingVirtualDevice) Start(<-chan struct{}, func([]byte)) error { return nil }
func (d *recordingVirtualDevice) SyncPeerRoutes([]string)                   {}
func (d *recordingVirtualDevice) Close() error                              { return nil }
func (d *recordingVirtualDevice) Status() string                            { return "RECORDING" }
func (d *recordingVirtualDevice) Error() string                             { return "" }

func (d *recordingVirtualDevice) WritePacket(packet []byte) error {
	select {
	case d.written <- append([]byte(nil), packet...):
	default:
	}
	return nil
}

// The SPM2 magic 0x53504d32 opens with 0x5350, which lies inside the TURN ChannelData channel range,
// so classifying datagrams by that range alone consumed every direct data frame and dropped it. A
// direct frame must reach the virtual device.
func TestDirectDataFrameIsNotMistakenForTurnChannelData(t *testing.T) {
	device := newRecordingVirtualDevice()
	mesh, session := newDataPlaneTestMesh(t, device)
	remote := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 42000}

	packet := make([]byte, 64)
	packet[0] = 0x45
	copy(packet[20:], []byte("payload-marker"))
	frame := encodeInbound(t, session, 1, packet)

	// Precondition: the frame really does look like ChannelData by channel number alone.
	if !looksLikeTurnChannelData(frame) {
		t.Fatal("precondition: the SPM2 magic is expected to collide with the ChannelData range")
	}

	mesh.handleUDP(frame, remote)
	select {
	case written := <-device.written:
		if string(written) != string(packet) {
			t.Fatalf("virtual device received %q, want the frame payload", written)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a direct SPM2 data frame never reached the virtual device")
	}

	// The successful direct frame is also what promotes the path to DIRECT.
	mesh.mu.Lock()
	pathType := session.PathType
	endpoint := session.RemoteEndpoint
	mesh.mu.Unlock()
	if pathType != "DIRECT" || endpoint == nil || endpoint.String() != remote.String() {
		t.Fatalf("path = %s via %v, want DIRECT via %v", pathType, endpoint, remote)
	}
}

// Real TURN ChannelData must still take the relay branch.
func TestTurnChannelDataStillReachesTheRelayBranch(t *testing.T) {
	device := newRecordingVirtualDevice()
	mesh, session := newDataPlaneTestMesh(t, device)
	relay := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 20), Port: 3478}
	peer := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 30), Port: 43000}

	mesh.mu.Lock()
	// relayEndpoint() is derived from the runtime TURN host/port, which is what gates the branch.
	mesh.runtime.PeerMesh.TurnHost = relay.IP.String()
	mesh.runtime.PeerMesh.TurnPort = relay.Port
	mesh.relay = &peerCandidate{Type: "relay", Transport: "udp",
		Address: relay.IP.String(), Port: relay.Port}
	mesh.turnChannelsByNumber = map[uint16]*turnChannelBinding{
		0x4001: {Channel: 0x4001, Peer: peer, Active: true, ExpiresAt: time.Now().Add(time.Hour)},
	}
	mesh.mu.Unlock()

	packet := make([]byte, 64)
	packet[0] = 0x45
	copy(packet[20:], []byte("relayed-marker"))
	inner := encodeInbound(t, session, 1, packet)
	channelData, err := encodeTurnChannelData(0x4001, inner)
	if err != nil {
		t.Fatalf("encode channel data: %v", err)
	}

	mesh.handleUDP(channelData, relay)
	select {
	case written := <-device.written:
		if string(written) != string(packet) {
			t.Fatalf("virtual device received %q, want the relayed payload", written)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a relayed data frame never reached the virtual device")
	}
	mesh.mu.Lock()
	pathType := session.PathType
	mesh.mu.Unlock()
	if pathType != "RELAY" {
		t.Fatalf("path = %s, want RELAY", pathType)
	}
}
