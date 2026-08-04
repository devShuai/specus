package client

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/client/internal/protocol"
)

func TestBuildWebSocketTarget(t *testing.T) {
	target, err := buildWebSocketTarget("http://127.0.0.1:8080/api", "/socket", "transport=websocket")
	if err != nil {
		t.Fatalf("buildWebSocketTarget() error = %v", err)
	}
	if got, want := target.String(), "ws://127.0.0.1:8080/api/socket?transport=websocket"; got != want {
		t.Fatalf("target = %q, want %q", got, want)
	}

	target, err = buildWebSocketTarget("https://example.test/base/", "/events", "")
	if err != nil {
		t.Fatalf("buildWebSocketTarget() error = %v", err)
	}
	if got, want := target.String(), "wss://example.test/base/events"; got != want {
		t.Fatalf("target = %q, want %q", got, want)
	}
}

func TestBuildWebSocketTargetPreservesDoubleSlashPathLikeJava(t *testing.T) {
	target, err := buildWebSocketTarget("http://example.test/base", "//assets/socket", "")
	if err != nil {
		t.Fatalf("buildWebSocketTarget() error = %v", err)
	}
	if got, want := target.String(), "ws://example.test/base//assets/socket"; got != want {
		t.Fatalf("target = %q, want %q", got, want)
	}
}

func TestBuildWebSocketTargetPreservesEncodedPath(t *testing.T) {
	target, err := buildWebSocketTarget(
		"http://example.test/base%2Froot", "/%E4%BD%A0%2F%252F", "next=%2Fraw",
	)
	if err != nil {
		t.Fatalf("buildWebSocketTarget() error = %v", err)
	}
	if got, want := target.String(), "ws://example.test/base%2Froot/%E4%BD%A0%2F%252F?next=%2Fraw"; got != want {
		t.Fatalf("target = %q, want %q", got, want)
	}
}

func TestBuildWebSocketTargetRejectsDotSegments(t *testing.T) {
	for _, relativePath := range []string{"/../admin", "/%2e%2e/admin"} {
		t.Run(relativePath, func(t *testing.T) {
			_, err := buildWebSocketTarget("http://example.test/base", relativePath, "")
			if err == nil || err.Error() != "HTTP 转发路径越界" {
				t.Fatalf("error = %v, want HTTP 转发路径越界", err)
			}
		})
	}
}

func TestBuildWebSocketTargetErrorsUseJavaMessages(t *testing.T) {
	cases := []struct {
		name          string
		targetBaseURL string
		relativePath  string
		want          string
	}{
		{name: "missing route", targetBaseURL: "", relativePath: "/", want: "未配置 HTTP route"},
		{name: "unsupported scheme", targetBaseURL: "ftp://example.test/base", relativePath: "/", want: "HTTP route 仅支持 http/https/ws/wss"},
		{name: "query in route", targetBaseURL: "http://example.test/base?x=1", relativePath: "/", want: "HTTP route 地址无效"},
		{name: "fragment in route", targetBaseURL: "http://example.test/base#x", relativePath: "/", want: "HTTP route 地址无效"},
		{name: "control char path", targetBaseURL: "http://example.test/base", relativePath: "/socket\r\nBad: value", want: "relativePath 含有非法控制字符"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildWebSocketTarget(tc.targetBaseURL, tc.relativePath, "")
			if err == nil {
				t.Fatal("buildWebSocketTarget() error = nil")
			}
			if got := err.Error(); got != tc.want {
				t.Fatalf("error = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWebSocketHandshakeHeadersFiltersHopByHop(t *testing.T) {
	headers := webSocketHandshakeHeaders(map[string]any{
		"headers": []any{
			"Origin:http://127.0.0.1:8088",
			"Connection:Upgrade",
			"Sec-WebSocket-Key:bad",
			"X-Trace:abc",
		},
	})
	want := []string{"Origin:http://127.0.0.1:8088", "X-Trace:abc"}
	if len(headers) != len(want) {
		t.Fatalf("headers = %#v, want %#v", headers, want)
	}
	for i := range headers {
		if headers[i] != want[i] {
			t.Fatalf("headers = %#v, want %#v", headers, want)
		}
	}
}

func TestConnectWebSocketSpecusForwardsLocalTextFrame(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		request, err := http.ReadRequest(reader)
		if err != nil {
			serverDone <- err
			return
		}
		if got, want := request.URL.RequestURI(), "/base/socket?transport=websocket"; got != want {
			serverDone <- &testError{message: "unexpected request uri: " + got}
			return
		}
		if got := request.Header.Get("X-Trace"); got != "abc" {
			serverDone <- &testError{message: "missing forwarded X-Trace header"}
			return
		}
		accept := testWebSocketAccept(request.Header.Get("Sec-WebSocket-Key"))
		response := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
		if _, err := conn.Write([]byte(response)); err != nil {
			serverDone <- err
			return
		}
		if err := writeServerWebSocketFrame(conn, webSocketOpcodeText, []byte("hello")); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	controlClient, controlServer := net.Pipe()
	defer controlClient.Close()
	defer controlServer.Close()

	specusClient := New(Config{}, log.New(io.Discard, "", 0))
	specusClient.syncHTTPSpecusConfigs([]HTTPSpecusConfig{
		{Route: "app", TargetBaseURL: "http://" + listener.Addr().String() + "/base"},
	})
	specusClient.openNatFlow(1)
	specusClient.connectWebSocketSpecus(controlClient, 1, map[string]any{
		"channelId":    "ws1",
		"source":       "ws",
		"route":        "app",
		"relativePath": "/socket",
		"rawQuery":     "transport=websocket",
		"headers":      []any{"X-Trace:abc", "Connection:Upgrade"},
	})

	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	_ = controlServer.SetReadDeadline(time.Now().Add(2 * time.Second))
	packet, err := protocol.ReadPacket(controlServer)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Command != protocol.CommandNatMessage {
		t.Fatalf("command = %d, want NAT_MESSAGE", packet.Command)
	}
	message, err := protocol.DecodeNatMessage(packet.Body)
	if err != nil {
		t.Fatal(err)
	}
	if message.Type != protocol.NatData {
		t.Fatalf("NAT type = %d, want DATA", message.Type)
	}
	if message.StreamID != 1 || len(message.Metadata) != 0 {
		t.Fatalf("stream frame = %#v, want stream 1 without metadata", message)
	}
	frame, err := decodeWebSocketSpecusFrame(message.Data)
	if err != nil {
		t.Fatalf("decode SWS2: %v", err)
	}
	if frame.opcode != webSocketOpcodeText || !frame.fin || frame.rsv != 0 ||
		frame.closeCode != 0 || string(frame.payload) != "hello" {
		t.Fatalf("SWS2 frame = %#v, want final text hello", frame)
	}
}

func TestWebSocketSpecusFrameRejectsLegacyPrefix(t *testing.T) {
	if _, err := decodeWebSocketSpecusFrame([]byte{0x01, 'o', 'l', 'd'}); err == nil {
		t.Fatal("legacy websocket prefix was accepted")
	}
}

func TestWebSocketSpecusFrameRoundTripClose(t *testing.T) {
	want := webSocketSpecusFrame{
		opcode: webSocketOpcodeClose, fin: true, closeCode: 1001, payload: []byte("going away"),
	}
	encoded, err := encodeWebSocketSpecusFrame(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeWebSocketSpecusFrame(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.opcode != want.opcode || !got.fin || got.closeCode != want.closeCode ||
		string(got.payload) != string(want.payload) {
		t.Fatalf("round trip = %#v, want %#v", got, want)
	}
}

type testError struct {
	message string
}

func (err *testError) Error() string {
	return err.message
}

func testWebSocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func writeServerWebSocketFrame(conn net.Conn, opcode byte, payload []byte) error {
	header := []byte{0x80 | opcode}
	switch {
	case len(payload) < 126:
		header = append(header, byte(len(payload)))
	case len(payload) <= 0xFFFF:
		header = append(header, 126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(len(payload)))
		header = append(header, ext[:]...)
	default:
		header = append(header, 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(len(payload)))
		header = append(header, ext[:]...)
	}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}
