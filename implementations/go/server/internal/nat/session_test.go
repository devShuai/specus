package nat

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/directhttp"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
)

func TestNatMetadataHelpersMatchJavaCoercion(t *testing.T) {
	meta := map[string]any{
		"channelId":  12345,
		"stringPort": "10022",
		"jsonPort":   json.Number("10023"),
		"floatPort":  float64(10024.9),
		"int64Port":  int64(10025),
	}

	if got := asString(meta, "channelId"); got != "12345" {
		t.Fatalf("asString should match Java Object.toString for numeric values, got %q", got)
	}

	cases := map[string]int{
		"stringPort": 10022,
		"jsonPort":   10023,
		"floatPort":  10024,
		"int64Port":  10025,
	}
	for key, want := range cases {
		got, ok := asInt(meta, key)
		if !ok || got != want {
			t.Fatalf("asInt(%s) = %d, %t; want %d, true", key, got, ok, want)
		}
	}
}

func TestUnknownTCPStreamResetsDataAndFinButRejectsNeverOpenedRST(t *testing.T) {
	session := &clientSession{
		httpStreams: map[uint32]*HTTPStream{},
		wsStreams:   map[uint32]*directhttp.WebSocketSpecus{},
		externals:   map[uint32]*externalConn{},
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	for index, messageType := range []int{protocol.NatData, protocol.NatFin} {
		streamID := uint32(42 + index)
		if err := session.handle(protocol.NatMessage{
			Type: messageType, StreamID: streamID, Data: []byte("late"),
		}); err != nil {
			t.Fatalf("unknown frame type %d closed the data connection: %v", messageType, err)
		}
		if !session.recentlyClosedStreams.contains(streamID) {
			t.Fatalf("unknown frame type %d did not leave a stream tombstone", messageType)
		}
	}

	if err := session.handle(protocol.NatMessage{
		Type: protocol.NatRST, StreamID: 44,
	}); err == nil {
		t.Fatal("RST for a never-opened stream must close the data connection")
	}
}

func TestTCPStreamIgnoresLateRSTForRecentlyClosedStream(t *testing.T) {
	session := &clientSession{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	session.markStreamClosed(45)
	if err := session.handle(protocol.NatMessage{
		Type: protocol.NatRST, StreamID: 45,
	}); err != nil {
		t.Fatalf("late RST closed the data connection: %v", err)
	}
}

func TestTCPStreamResetsDuplicateFinAndDataAfterFin(t *testing.T) {
	t.Run("duplicate FIN", func(t *testing.T) {
		streamID := uint32(50)
		connection := &halfCloseTestConn{}
		external := newExternalConn(connection, nil, streamID, 10022, 0, 0)
		session := &clientSession{
			externals: map[uint32]*externalConn{streamID: external},
			logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		}

		if err := session.handleClientClose(protocol.NatMessage{
			Type: protocol.NatFin, StreamID: streamID,
		}); err != nil {
			t.Fatalf("first FIN: %v", err)
		}
		if connection.closeWriteCalls != 1 {
			t.Fatalf("CloseWrite calls = %d, want 1", connection.closeWriteCalls)
		}
		if err := session.handleClientClose(protocol.NatMessage{
			Type: protocol.NatFin, StreamID: streamID,
		}); err != nil {
			t.Fatalf("duplicate FIN closed the data connection: %v", err)
		}
		if session.externals[streamID] != nil || !session.recentlyClosedStreams.contains(streamID) {
			t.Fatal("duplicate FIN must reset only the affected stream")
		}
	})

	t.Run("DATA after FIN", func(t *testing.T) {
		streamID := uint32(51)
		external := newExternalConn(&halfCloseTestConn{}, nil, streamID, 10022, 0, 0)
		session := &clientSession{
			externals: map[uint32]*externalConn{streamID: external},
			logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		if _, accepted := external.markClientFinished(); !accepted {
			t.Fatal("failed to establish client-finished state")
		}
		if err := session.handleData(protocol.NatMessage{
			Type: protocol.NatData, StreamID: streamID, Data: []byte("late"),
		}); err != nil {
			t.Fatalf("DATA after FIN closed the data connection: %v", err)
		}
		if session.externals[streamID] != nil || !session.recentlyClosedStreams.contains(streamID) {
			t.Fatal("DATA after FIN must reset only the affected stream")
		}
	})
}

func TestTCPStreamCompletesOnlyAfterBothDirectionsFinish(t *testing.T) {
	external := newExternalConn(&halfCloseTestConn{}, nil, 51, 10022, 0, 0)
	if complete, accepted := external.markClientFinished(); complete || !accepted {
		t.Fatalf("client FIN = (%t, %t), want (false, true)", complete, accepted)
	}
	if complete, accepted := external.markPublicFinished(); !complete || !accepted {
		t.Fatalf("public FIN = (%t, %t), want (true, true)", complete, accepted)
	}
	if _, accepted := external.markPublicFinished(); accepted {
		t.Fatal("duplicate public FIN must be rejected")
	}
}

func TestServerTCPHalfClosePreservesPublicToClientDirection(t *testing.T) {
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
	public, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer public.Close()
	externalSocket := <-accepted
	defer externalSocket.Close()
	deadline := time.Now().Add(5 * time.Second)
	_ = public.SetDeadline(deadline)
	_ = externalSocket.SetDeadline(deadline)

	streamID := uint32(52)
	external := newExternalConn(externalSocket, nil, streamID, 10022, 0, 0)
	session := &clientSession{
		externals: map[uint32]*externalConn{streamID: external},
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := session.handleClientClose(protocol.NatMessage{
		Type: protocol.NatFin, StreamID: streamID,
	}); err != nil {
		t.Fatalf("client FIN: %v", err)
	}

	one := make([]byte, 1)
	if read, err := public.Read(one); read != 0 || err != io.EOF {
		t.Fatalf("public read after client FIN = %d, %v; want 0, EOF", read, err)
	}
	if _, err := public.Write([]byte("reply")); err != nil {
		t.Fatalf("write reverse data: %v", err)
	}
	reply := make([]byte, len("reply"))
	if _, err := io.ReadFull(externalSocket, reply); err != nil {
		t.Fatalf("read reverse data: %v", err)
	}
	if string(reply) != "reply" {
		t.Fatalf("reverse data = %q, want reply", reply)
	}
}

func TestClosingHTTPStreamPointerDropsRacingData(t *testing.T) {
	streamID := uint32(43)
	stream := newHTTPStream(nil, streamID, nil)
	if result := stream.onHead(httpResponseMetadata(200)); result != httpStreamFrameAccepted {
		t.Fatalf("response head result = %d, want accepted", result)
	}
	stream.Close()
	session := &clientSession{
		httpStreams: map[uint32]*HTTPStream{streamID: stream},
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	if err := session.handle(protocol.NatMessage{
		Type: protocol.NatData, StreamID: streamID, Data: []byte("racing"),
	}); err != nil {
		t.Fatalf("racing DATA returned error: %v", err)
	}
}

func TestHTTPStreamReportsEventQueueSaturationSeparately(t *testing.T) {
	stream := newHTTPStream(nil, 44, nil)
	if result := stream.onHead(httpResponseMetadata(200)); result != httpStreamFrameAccepted {
		t.Fatalf("response head result = %d, want accepted", result)
	}
	for index := 0; index < httpMaxQueuedDataEvents; index++ {
		if result := stream.onData([]byte{1}); result != httpStreamFrameAccepted {
			t.Fatalf("DATA %d result = %d, want accepted", index, result)
		}
	}
	if result := stream.onData([]byte{1}); result != httpStreamFrameQueueFull {
		t.Fatalf("saturated DATA result = %d, want queue full", result)
	}
	if result := stream.onEnd(nil); result != httpStreamFrameAccepted {
		t.Fatalf("terminal result = %d, want accepted with a full DATA queue", result)
	}
	if result := stream.onEnd(nil); result != httpStreamFrameInvalidState {
		t.Fatalf("duplicate terminal result = %d, want invalid state", result)
	}
}

func TestHTTPStreamBatchesReceiveCreditAtLowWater(t *testing.T) {
	stream := newHTTPStream(nil, 45, nil)
	if result := stream.onHead(httpResponseMetadata(200)); result != httpStreamFrameAccepted {
		t.Fatalf("response head result = %d, want accepted", result)
	}
	chunk := make([]byte, natInitialWindowBytes/4)
	for index := 0; index < 3; index++ {
		if result := stream.onData(chunk); result != httpStreamFrameAccepted {
			t.Fatalf("DATA %d result = %d, want accepted", index, result)
		}
		credit, err := stream.consumeReceiveCredit(len(chunk))
		if err != nil {
			t.Fatalf("consume DATA %d: %v", index, err)
		}
		if index < 2 && credit != 0 {
			t.Fatalf("early credit after DATA %d = %d, want 0", index, credit)
		}
		if index == 2 && credit != uint32(3*len(chunk)) {
			t.Fatalf("batched credit = %d, want %d", credit, 3*len(chunk))
		}
	}
}

func TestHTTPStreamRejectsRequestFramesAfterClose(t *testing.T) {
	stream := newHTTPStream(nil, 46, nil)
	stream.Close()

	if err := stream.SendData(t.Context(), []byte("late")); err == nil {
		t.Fatal("late request DATA should be rejected after close")
	}
	if err := stream.FinishRequest(nil); err == nil {
		t.Fatal("late request FIN should be rejected after close")
	}
}

func TestHTTPStreamTreatsDuplicateRequestFinAsIdempotent(t *testing.T) {
	stream := newHTTPStream(nil, 47, nil)
	stream.requestEnded = true

	if err := stream.FinishRequest(nil); err != nil {
		t.Fatalf("duplicate request FIN returned error: %v", err)
	}
}

func TestHTTPStreamValidatesResponseHeadLikeJava(t *testing.T) {
	for name, metadata := range map[string]map[string]any{
		"missing source": {"phase": "response", "statusCode": 200},
		"wrong phase":    {"source": "http", "phase": "request", "statusCode": 200},
		"low status":     {"source": "http", "phase": "response", "statusCode": 99},
		"high status":    {"source": "http", "phase": "response", "statusCode": 600},
	} {
		t.Run(name, func(t *testing.T) {
			stream := newHTTPStream(nil, 48, nil)
			if result := stream.onHead(metadata); result != httpStreamFrameInvalidState {
				t.Fatalf("response head result = %d, want invalid state", result)
			}
		})
	}
}

func TestHTTPStreamRequiresExactlyOneResponseHeadBeforeDataAndFin(t *testing.T) {
	if result := newHTTPStream(nil, 49, nil).onData([]byte("early")); result != httpStreamFrameInvalidState {
		t.Fatalf("DATA before OPEN result = %d, want invalid state", result)
	}
	if result := newHTTPStream(nil, 50, nil).onEnd(nil); result != httpStreamFrameInvalidState {
		t.Fatalf("FIN before OPEN result = %d, want invalid state", result)
	}

	stream := newHTTPStream(nil, 51, nil)
	if result := stream.onHead(httpResponseMetadata(200)); result != httpStreamFrameAccepted {
		t.Fatalf("response OPEN result = %d, want accepted", result)
	}
	if result := stream.onHead(httpResponseMetadata(201)); result != httpStreamFrameInvalidState {
		t.Fatalf("duplicate OPEN result = %d, want invalid state", result)
	}
	if result := stream.onData([]byte("body")); result != httpStreamFrameAccepted {
		t.Fatalf("DATA after OPEN result = %d, want accepted", result)
	}
	if result := stream.onEnd(nil); result != httpStreamFrameAccepted {
		t.Fatalf("FIN after OPEN result = %d, want accepted", result)
	}
	if result := stream.onEnd(nil); result != httpStreamFrameInvalidState {
		t.Fatalf("duplicate FIN result = %d, want invalid state", result)
	}
	if result := stream.onData([]byte("late")); result != httpStreamFrameInvalidState {
		t.Fatalf("DATA after FIN result = %d, want invalid state", result)
	}
	if result := stream.onHead(httpResponseMetadata(202)); result != httpStreamFrameInvalidState {
		t.Fatalf("OPEN after FIN result = %d, want invalid state", result)
	}

	reset := newHTTPStream(nil, 52, nil)
	reset.onReset("cancelled")
	if !reset.isClosed() {
		t.Fatal("RST must close the response stream")
	}
	if result := reset.onHead(httpResponseMetadata(200)); result != httpStreamFrameInvalidState {
		t.Fatalf("OPEN after RST result = %d, want invalid state", result)
	}
	if result := reset.onData([]byte("late")); result != httpStreamFrameInvalidState {
		t.Fatalf("DATA after RST result = %d, want invalid state", result)
	}
	if result := reset.onEnd(nil); result != httpStreamFrameInvalidState {
		t.Fatalf("FIN after RST result = %d, want invalid state", result)
	}
}

func httpResponseMetadata(status int) map[string]any {
	return map[string]any{"source": "http", "phase": "response", "statusCode": status}
}

type halfCloseTestConn struct {
	closeWriteCalls int
}

func (connection *halfCloseTestConn) Read([]byte) (int, error) { return 0, io.EOF }
func (connection *halfCloseTestConn) Write(data []byte) (int, error) {
	return len(data), nil
}
func (connection *halfCloseTestConn) Close() error                     { return nil }
func (connection *halfCloseTestConn) LocalAddr() net.Addr              { return testAddr("local") }
func (connection *halfCloseTestConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (connection *halfCloseTestConn) SetDeadline(time.Time) error      { return nil }
func (connection *halfCloseTestConn) SetReadDeadline(time.Time) error  { return nil }
func (connection *halfCloseTestConn) SetWriteDeadline(time.Time) error { return nil }
func (connection *halfCloseTestConn) CloseWrite() error {
	connection.closeWriteCalls++
	return nil
}

type testAddr string

func (address testAddr) Network() string { return string(address) }
func (address testAddr) String() string  { return string(address) }

func TestHTTPDataEndStreamQueuesDataBeforeEnd(t *testing.T) {
	streamID := uint32(50)
	stream := newHTTPStream(nil, streamID, nil)
	if result := stream.onHead(httpResponseMetadata(200)); result != httpStreamFrameAccepted {
		t.Fatalf("response head result = %d, want accepted", result)
	}
	session := &clientSession{
		httpStreams: map[uint32]*HTTPStream{streamID: stream},
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	payload := []byte("final-response-chunk")
	if err := session.handle(protocol.NatMessage{
		Type: protocol.NatData, StreamID: streamID, Data: payload,
		Flags: protocol.NatFlagEndStream,
	}); err != nil {
		t.Fatalf("handle DATA|END_STREAM: %v", err)
	}

	data, _, end, err := stream.ReadResponse(t.Context())
	if err != nil || end || !bytes.Equal(data, payload) {
		t.Fatalf("first response event = data %q, end %v, err %v", data, end, err)
	}
	data, _, end, err = stream.ReadResponse(t.Context())
	if err != nil || !end || data != nil {
		t.Fatalf("second response event = data %q, end %v, err %v", data, end, err)
	}
}
