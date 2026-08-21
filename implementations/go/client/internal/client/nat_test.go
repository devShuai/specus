package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/client/internal/protocol"
)

func TestConnectLocalSpecusRejectsInvalidTCPStream(t *testing.T) {
	cases := []struct {
		name     string
		metadata map[string]any
	}{
		{
			name:     "missing port",
			metadata: map[string]any{"channelId": "channel-1"},
		},
		{
			name:     "missing channel id",
			metadata: map[string]any{"port": float64(10022)},
		},
		{
			name:     "unknown port",
			metadata: map[string]any{"channelId": "channel-1", "port": float64(10022)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			control := &captureConn{}
			specusClient := New(Config{}, log.New(io.Discard, "", 0))

			specusClient.openNatFlow(1)
			flow := specusClient.natFlow(1)
			dialContext, started := flow.beginTCPConnect()
			if !started {
				t.Fatal("beginTCPConnect() = false, want true")
			}
			specusClient.connectLocalSpecus(control, 1, tc.metadata, flow, dialContext)

			if control.Len() == 0 {
				t.Fatal("invalid TCP OPEN must produce an RST frame")
			}
			if specusClient.hasNatFlow(1) {
				t.Fatal("invalid TCP OPEN must release its NAT flow")
			}
		})
	}
}

func TestTCPNatFlowResetsDuplicateFinAndDataAfterFinWithoutClosingDataConnection(t *testing.T) {
	t.Run("duplicate FIN", func(t *testing.T) {
		control := &captureConn{}
		client := New(Config{}, log.New(io.Discard, "", 0))
		if !client.openNatFlow(7) {
			t.Fatal("openNatFlow() = false, want true")
		}

		client.handleRemoteFin(control, 7)
		if !client.hasNatFlow(7) {
			t.Fatal("first FIN must preserve the reverse direction")
		}
		client.handleRemoteFin(control, 7)
		assertCapturedRST(t, control, 7)
		if client.hasNatFlow(7) {
			t.Fatal("duplicate FIN must reset only the affected stream")
		}
	})

	t.Run("DATA after FIN", func(t *testing.T) {
		control := &captureConn{}
		client := New(Config{}, log.New(io.Discard, "", 0))
		if !client.openNatFlow(8) {
			t.Fatal("openNatFlow() = false, want true")
		}
		client.handleRemoteFin(control, 8)
		if err := handleNatForTest(client, control, protocol.NatMessage{
			Type: protocol.NatData, StreamID: 8, Data: []byte("late"),
		}); err != nil {
			t.Fatalf("DATA after FIN closed the data connection: %v", err)
		}
		assertCapturedRST(t, control, 8)
		if client.hasNatFlow(8) {
			t.Fatal("DATA after FIN must reset only the affected stream")
		}
	})
}

func TestTCPNatFlowResetsUnknownDataAndFinButRejectsNeverOpenedRST(t *testing.T) {
	client := New(Config{}, log.New(io.Discard, "", 0))
	control := &captureConn{}
	for index, messageType := range []int{protocol.NatData, protocol.NatFin} {
		streamID := uint32(88 + index)
		message := protocol.NatMessage{Type: messageType, StreamID: streamID}
		if messageType == protocol.NatData {
			message.Data = []byte("unknown")
		}
		if err := handleNatForTest(client, control, message); err != nil {
			t.Fatalf("unknown frame type %d closed the data connection: %v", messageType, err)
		}
		assertCapturedRST(t, control, streamID)
	}

	if err := handleNatForTest(client, control, protocol.NatMessage{
		Type: protocol.NatRST, StreamID: 90,
	}); err == nil {
		t.Fatal("RST for a never-opened stream must close the data connection")
	}
}

func TestTCPNatFlowIgnoresLateRSTForRecentlyClosedStream(t *testing.T) {
	client := New(Config{}, log.New(io.Discard, "", 0))
	control := &captureConn{}
	client.openNatFlow(91)
	client.closeNatFlow(91)

	if err := handleNatForTest(client, control, protocol.NatMessage{
		Type: protocol.NatRST, StreamID: 91,
	}); err != nil {
		t.Fatalf("late RST closed the data connection: %v", err)
	}
	if control.Len() != 0 {
		t.Fatal("late RST must be ignored without starting a reset loop")
	}
}

func TestNatFlowIgnoresLateWindowUpdate(t *testing.T) {
	client := New(Config{}, log.New(io.Discard, "", 0))
	control := &captureConn{}

	client.openNatFlow(93)
	client.closeNatFlow(93)
	if err := handleNatForTest(client, control, protocol.NatMessage{
		Type: protocol.NatWindowUpdate, StreamID: 93, Value: 1024,
	}); err != nil {
		t.Fatalf("late WINDOW_UPDATE closed the data connection: %v", err)
	}

	if err := handleNatForTest(client, control, protocol.NatMessage{
		Type: protocol.NatWindowUpdate, StreamID: 94, Value: 1024,
	}); err != nil {
		t.Fatalf("WINDOW_UPDATE for an unknown stream closed the data connection: %v", err)
	}
	if control.Len() != 0 {
		t.Fatal("late WINDOW_UPDATE must not emit a frame")
	}
}

func TestNatFlowRejectsOverflowWindowUpdateOnLiveStream(t *testing.T) {
	client := New(Config{}, log.New(io.Discard, "", 0))
	control := &captureConn{}
	if !client.openNatFlow(95) {
		t.Fatal("openNatFlow() = false, want true")
	}

	if err := handleNatForTest(client, control, protocol.NatMessage{
		Type: protocol.NatWindowUpdate, StreamID: 95, Value: natMaximumWindowBytes,
	}); err == nil {
		t.Fatal("overflow WINDOW_UPDATE on a live stream must close the data connection")
	}
}

func TestNatFlowAddConsumesCreditAfterClose(t *testing.T) {
	state := newNatFlowState()
	state.close()
	if !state.add(1024) {
		t.Fatal("late credit on a closed flow must be consumed")
	}
	if state.add(0) || state.add(natMaximumWindowBytes+1) {
		t.Fatal("malformed credit must still be rejected after close")
	}
}

func TestDuplicateOpenResetsStreamWithoutClosingDataConnection(t *testing.T) {
	client := New(Config{}, log.New(io.Discard, "", 0))
	control := &captureConn{}
	client.openNatFlow(92)

	if err := handleNatForTest(client, control, protocol.NatMessage{
		Type: protocol.NatOpen, StreamID: 92,
	}); err != nil {
		t.Fatalf("duplicate OPEN closed the data connection: %v", err)
	}
	assertCapturedRST(t, control, 92)
	if client.hasNatFlow(92) {
		t.Fatal("duplicate OPEN must reset only the affected stream")
	}
}

func TestTCPNatFlowStagesPendingFinAfterData(t *testing.T) {
	flow := newNatFlowState()
	_, started := flow.beginTCPConnect()
	if !started {
		t.Fatal("beginTCPConnect() = false, want true")
	}
	defer flow.close()
	if disposition := flow.stageTCPData([]byte("before-fin"), false); disposition != tcpDataQueued {
		t.Fatalf("stageTCPData() = %d, want queued", disposition)
	}
	complete, accepted, connecting := flow.receiveRemoteFin()
	if complete || !accepted || !connecting {
		t.Fatalf("receiveRemoteFin() = %v/%v/%v, want false/true/true", complete, accepted, connecting)
	}
	if disposition := flow.stageTCPData([]byte("after-fin"), false); disposition != tcpDataAfterFin {
		t.Fatalf("DATA after pending FIN = %d, want after-fin rejection", disposition)
	}
	pending, remoteFinished, complete, activated := flow.activateTCPConnection()
	if !activated || !remoteFinished || complete {
		t.Fatalf("activateTCPConnection() = activated:%v remote:%v complete:%v", activated, remoteFinished, complete)
	}
	if len(pending) != 1 || string(pending[0]) != "before-fin" {
		t.Fatalf("pending data = %q, want [before-fin]", pending)
	}
}

func TestTCPNatFlowBuffersDataAndEndStreamWhileDialIsPending(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	controlClient, controlServer := net.Pipe()
	defer controlClient.Close()
	defer controlServer.Close()
	specusClient := New(Config{}, log.New(io.Discard, "", 0))
	writerContext, cancelWriter := context.WithCancel(context.Background())
	defer cancelWriter()
	stopWriter := specusClient.startPriorityWriter(writerContext, controlClient)
	defer stopWriter()

	frames := make(chan protocol.NatMessage, 8)
	readErrors := make(chan error, 1)
	go func() {
		for {
			packet, readErr := protocol.ReadPacket(controlServer)
			if readErr != nil {
				readErrors <- readErr
				return
			}
			message, decodeErr := protocol.DecodeNatMessage(packet.Body)
			if decodeErr != nil {
				readErrors <- decodeErr
				return
			}
			frames <- message
		}
	}()

	target := listener.Addr().(*net.TCPAddr)
	specusClient.specusMappings[18080] = SpecusConfig{
		Port: 18080, SpecusAddress: target.IP.String(), SpecusPort: target.Port,
	}
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	specusClient.localTCPDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		close(dialStarted)
		select {
		case <-releaseDial:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		return dialer.DialContext(ctx, network, address)
	}

	if err := handleNatForTest(specusClient, controlClient, protocol.NatMessage{
		Type: protocol.NatOpen, StreamID: 41,
		Metadata: map[string]any{"port": 18080, "channelId": "pending-41"},
	}); err != nil {
		t.Fatalf("OPEN: %v", err)
	}
	select {
	case <-dialStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("local dial did not start")
	}

	first := []byte("first-")
	second := []byte("second")
	if err := handleNatForTest(specusClient, controlClient, protocol.NatMessage{
		Type: protocol.NatData, StreamID: 41, Data: first,
	}); err != nil {
		t.Fatalf("first DATA: %v", err)
	}
	if err := handleNatForTest(specusClient, controlClient, protocol.NatMessage{
		Type: protocol.NatData, Flags: protocol.NatFlagEndStream, StreamID: 41, Data: second,
	}); err != nil {
		t.Fatalf("DATA|END_STREAM: %v", err)
	}
	select {
	case frame := <-frames:
		t.Fatalf("frame before pending data was flushed: type=%d", frame.Type)
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseDial)
	accepted, err := listener.AcceptTCP()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer accepted.Close()
	_ = accepted.SetDeadline(time.Now().Add(5 * time.Second))
	received, err := io.ReadAll(accepted)
	if err != nil {
		t.Fatalf("read flushed local data: %v", err)
	}
	if want := string(first) + string(second); string(received) != want {
		t.Fatalf("flushed local data = %q, want %q", received, want)
	}
	if err := accepted.CloseWrite(); err != nil {
		t.Fatalf("close local response direction: %v", err)
	}

	wantCredit := len(first) + len(second)
	gotCredit := 0
	deadline := time.After(5 * time.Second)
	for gotCredit < wantCredit {
		select {
		case frame := <-frames:
			if frame.Type == protocol.NatWindowUpdate && frame.StreamID == 41 {
				gotCredit += int(frame.Value)
			}
		case readErr := <-readErrors:
			t.Fatalf("read control frame: %v", readErr)
		case <-deadline:
			t.Fatalf("WINDOW_UPDATE credit = %d, want %d", gotCredit, wantCredit)
		}
	}
}

func TestTCPNatFlowRSTCancelsPendingDialAndReleasesBuffer(t *testing.T) {
	specusClient := New(Config{}, log.New(io.Discard, "", 0))
	control := &captureConn{}
	specusClient.specusMappings[18081] = SpecusConfig{
		Port: 18081, SpecusAddress: "127.0.0.1", SpecusPort: 18081,
	}
	dialStarted := make(chan struct{})
	dialCanceled := make(chan struct{})
	specusClient.localTCPDial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(dialStarted)
		<-ctx.Done()
		close(dialCanceled)
		return nil, ctx.Err()
	}
	if err := handleNatForTest(specusClient, control, protocol.NatMessage{
		Type: protocol.NatOpen, StreamID: 42,
		Metadata: map[string]any{"port": 18081, "channelId": "pending-42"},
	}); err != nil {
		t.Fatalf("OPEN: %v", err)
	}
	<-dialStarted
	flow := specusClient.natFlow(42)
	if err := handleNatForTest(specusClient, control, protocol.NatMessage{
		Type: protocol.NatData, StreamID: 42, Data: []byte("pending"),
	}); err != nil {
		t.Fatalf("DATA: %v", err)
	}
	if err := handleNatForTest(specusClient, control, protocol.NatMessage{
		Type: protocol.NatRST, StreamID: 42, Value: 1,
	}); err != nil {
		t.Fatalf("RST: %v", err)
	}
	select {
	case <-dialCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("RST did not cancel pending local dial")
	}
	if specusClient.hasNatFlow(42) {
		t.Fatal("RST must release pending NAT flow")
	}
	flow.mu.Lock()
	closed := flow.closed
	pendingBytes := flow.tcpPendingBytes
	pendingFrames := len(flow.tcpPendingData)
	flow.mu.Unlock()
	if !closed || pendingBytes != 0 || pendingFrames != 0 {
		t.Fatalf("closed/pending state = %v/%d/%d, want true/0/0", closed, pendingBytes, pendingFrames)
	}
}

func TestTCPNatFlowPendingBufferIsBoundedByReceiveWindow(t *testing.T) {
	specusClient := New(Config{}, log.New(io.Discard, "", 0))
	control := &captureConn{}
	specusClient.specusMappings[18082] = SpecusConfig{
		Port: 18082, SpecusAddress: "127.0.0.1", SpecusPort: 18082,
	}
	dialStarted := make(chan struct{})
	specusClient.localTCPDial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(dialStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err := handleNatForTest(specusClient, control, protocol.NatMessage{
		Type: protocol.NatOpen, StreamID: 43,
		Metadata: map[string]any{"port": 18082, "channelId": "pending-43"},
	}); err != nil {
		t.Fatalf("OPEN: %v", err)
	}
	<-dialStarted
	if err := handleNatForTest(specusClient, control, protocol.NatMessage{
		Type: protocol.NatData, StreamID: 43, Data: make([]byte, 600*1024),
	}); err != nil {
		t.Fatalf("first DATA: %v", err)
	}
	if err := handleNatForTest(specusClient, control, protocol.NatMessage{
		Type: protocol.NatData, StreamID: 43, Data: make([]byte, 500*1024),
	}); err != nil {
		t.Fatalf("overflowing DATA: %v", err)
	}
	if specusClient.hasNatFlow(43) {
		t.Fatal("pending buffer overflow must release NAT flow")
	}
	packet, err := protocol.ReadPacket(bytes.NewReader(control.Bytes()))
	if err != nil {
		t.Fatalf("read overflow RST: %v", err)
	}
	message, err := protocol.DecodeNatMessage(packet.Body)
	if err != nil {
		t.Fatalf("decode overflow RST: %v", err)
	}
	if message.Type != protocol.NatRST || message.StreamID != 43 {
		t.Fatalf("overflow response = type %d stream %d, want RST/43", message.Type, message.StreamID)
	}
}

func TestTCPNatFlowPreservesReverseDirectionAfterRemoteFin(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan *net.TCPConn, 1)
	go func() {
		connection, acceptErr := listener.AcceptTCP()
		if acceptErr == nil {
			accepted <- connection
		}
	}()
	local, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer local.Close()
	public := <-accepted
	defer public.Close()
	deadline := time.Now().Add(5 * time.Second)
	_ = local.SetDeadline(deadline)
	_ = public.SetDeadline(deadline)

	client := New(Config{}, log.New(io.Discard, "", 0))
	control := &captureConn{}
	client.openNatFlow(9)
	client.locals[9] = local
	client.handleRemoteFin(control, 9)

	one := make([]byte, 1)
	if read, err := public.Read(one); read != 0 || err != io.EOF {
		t.Fatalf("public read after FIN = %d, %v; want 0, EOF", read, err)
	}
	if _, err := public.Write([]byte("reply")); err != nil {
		t.Fatalf("write reverse data: %v", err)
	}
	reply := make([]byte, len("reply"))
	if _, err := io.ReadFull(local, reply); err != nil {
		t.Fatalf("read reverse data: %v", err)
	}
	if string(reply) != "reply" {
		t.Fatalf("reverse data = %q, want reply", reply)
	}

	client.finishLocalDirection(control, 9)
	if control.Len() == 0 {
		t.Fatal("local EOF must send FIN")
	}
	if client.hasNatFlow(9) {
		t.Fatal("both FIN directions must release the NAT flow")
	}
}

func TestNatMetadataHelpersMatchJavaCoercion(t *testing.T) {
	text, err := metadataString(map[string]any{"channelId": 12345}, "channelId")
	if err != nil {
		t.Fatalf("metadataString() error = %v", err)
	}
	if text != "12345" {
		t.Fatalf("metadataString() = %q, want Java toString value", text)
	}

	for _, tc := range []struct {
		name  string
		value any
		want  int
	}{
		{name: "string", value: "10022", want: 10022},
		{name: "json-number", value: json.Number("10023"), want: 10023},
		{name: "float", value: float64(10024.9), want: 10024},
		{name: "int64", value: int64(10025), want: 10025},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := metadataInt(map[string]any{"port": tc.value}, "port")
			if err != nil {
				t.Fatalf("metadataInt() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("metadataInt() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRegisterFailureClearsPortForRetryWithoutClosingSession(t *testing.T) {
	specusClient := New(Config{}, log.New(io.Discard, "", 0))
	specusClient.registered[19090] = struct{}{}

	specusClient.handleNatRegisterResult(map[string]any{
		"port":    19090,
		"success": false,
		"reason":  "address already in use",
	})

	specusClient.registeredMu.Lock()
	_, stillRegistered := specusClient.registered[19090]
	specusClient.registeredMu.Unlock()
	if stillRegistered {
		t.Fatal("failed NAT port must be cleared so a later config refresh can retry it")
	}
}

type captureConn struct {
	bytes.Buffer
}

func handleNatForTest(client *Client, connection net.Conn, message protocol.NatMessage) error {
	body, err := protocol.EncodeNatMessage(message)
	if err != nil {
		return err
	}
	return client.handleNatMessage(connection, body)
}

func assertCapturedRST(t *testing.T, connection *captureConn, streamID uint32) {
	t.Helper()
	frame := append([]byte(nil), connection.Bytes()...)
	connection.Reset()
	packet, err := protocol.ReadPacket(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("read captured RST: %v", err)
	}
	message, err := protocol.DecodeNatMessage(packet.Body)
	if err != nil {
		t.Fatalf("decode captured RST: %v", err)
	}
	if message.Type != protocol.NatRST || message.StreamID != streamID {
		t.Fatalf("captured frame = type %d stream %d, want RST/%d",
			message.Type, message.StreamID, streamID)
	}
}

func (conn *captureConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (conn *captureConn) Close() error {
	return nil
}

func (conn *captureConn) LocalAddr() net.Addr {
	return captureAddr("local")
}

func (conn *captureConn) RemoteAddr() net.Addr {
	return captureAddr("remote")
}

func (conn *captureConn) SetDeadline(_ time.Time) error {
	return nil
}

func (conn *captureConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (conn *captureConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

type captureAddr string

func (addr captureAddr) Network() string {
	return string(addr)
}

func (addr captureAddr) String() string {
	return string(addr)
}
