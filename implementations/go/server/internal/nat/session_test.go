package nat

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"

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

func TestUnknownStreamDropsLateDataAndTerminalFrames(t *testing.T) {
	streamID := uint32(42)
	session := &clientSession{
		httpStreams: map[uint32]*HTTPStream{},
		wsStreams:   map[uint32]*directhttp.WebSocketSpecus{},
		externals:   map[uint32]*externalConn{},
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	for _, messageType := range []int{
		protocol.NatData,
		protocol.NatFin,
		protocol.NatRST,
	} {
		if err := session.handle(protocol.NatMessage{
			Type: messageType, StreamID: streamID, Data: []byte("late"),
		}); err != nil {
			t.Fatalf("late frame type %d returned error: %v", messageType, err)
		}
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
	if result := stream.onEnd(nil); result != httpStreamFrameAccepted {
		t.Fatalf("duplicate terminal result = %d, want idempotent acceptance", result)
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

func TestHTTPStreamAllowsDataBeforeHeadLikeJavaExchange(t *testing.T) {
	stream := newHTTPStream(nil, 49, nil)
	if result := stream.onData([]byte("early")); result != httpStreamFrameAccepted {
		t.Fatalf("early DATA result = %d, want accepted", result)
	}
	if result := stream.onHead(httpResponseMetadata(200)); result != httpStreamFrameAccepted {
		t.Fatalf("response head result = %d, want accepted", result)
	}
}

func httpResponseMetadata(status int) map[string]any {
	return map[string]any{"source": "http", "phase": "response", "statusCode": status}
}
