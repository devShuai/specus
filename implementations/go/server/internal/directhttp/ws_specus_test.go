package directhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	gorillaws "github.com/gorilla/websocket"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// wsHarness 建立一对真实 WebSocket 连接：隧道持有服务器侧连接，测试操纵浏览器侧连接。
type wsHarness struct {
	specus   *WebSocketSpecus
	browser  *websocket.Conn
	frames   chan []byte
	finishes atomic.Int32
	closed   chan *WebSocketSpecus
}

func newWSHarness(t *testing.T) *wsHarness {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	serverConn, browser := dialWSPair(t, ctx)
	h := &wsHarness{browser: browser, frames: make(chan []byte, 16), closed: make(chan *WebSocketSpecus, 1)}
	h.specus = NewWebSocketSpecus(serverConn, 7, "Demo client",
		func(frame []byte) error {
			h.frames <- frame
			return nil
		},
		func() error {
			h.finishes.Add(1)
			return nil
		},
		func(specus *WebSocketSpecus) { h.closed <- specus })
	t.Cleanup(func() {
		// 先断开浏览器侧，避免 specus.Close 的关闭握手空等对端回包。
		h.browser.CloseNow()
		h.specus.Close()
	})
	return h
}

// dialWSPair 在 httptest 服务器上完成一次 WS 握手，返回服务器侧与浏览器侧连接。
func dialWSPair(t *testing.T, ctx context.Context) (*gorillaws.Conn, *websocket.Conn) {
	t.Helper()
	accepted := make(chan *gorillaws.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&gorillaws.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		accepted <- conn
	}))
	t.Cleanup(server.Close)
	browser, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatalf("websocket.Dial failed: %v", err)
	}
	select {
	case serverConn := <-accepted:
		return serverConn, browser
	case <-ctx.Done():
		t.Fatalf("accept timed out: %v", ctx.Err())
		return nil, nil
	}
}

func (h *wsHarness) nextFrame(t *testing.T) sws2Frame {
	t.Helper()
	select {
	case raw := <-h.frames:
		frame, err := decodeSWS2(raw)
		if err != nil {
			t.Fatalf("decode captured frame failed: %v", err)
		}
		return frame
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for SWS2 frame")
		return sws2Frame{}
	}
}

// readAsync 让浏览器侧先阻塞在 Read 上，以处理服务器发来的控制帧和关闭握手。
func (h *wsHarness) readAsync(ctx context.Context) <-chan error {
	result := make(chan error, 1)
	go func() {
		_, _, err := h.browser.Read(ctx)
		result <- err
	}()
	time.Sleep(50 * time.Millisecond)
	return result
}

// TestServeWebSocketOpenDataCloseLifecycle 覆盖完整生命周期（对齐 Java WebSocketSpecusHandler）：
// Upgrade 分支 -> OPEN metadata(source=ws) -> 浏览器消息封装为 SWS2 DATA -> 浏览器关闭触发 CLOSE+FIN。
func TestServeWebSocketOpenDataCloseLifecycle(t *testing.T) {
	frames := make(chan []byte, 16)
	var finishes atomic.Int32
	// openWS 回调运行在 httptest 处理协程，握手返回先于回调执行，须经 channel 同步。
	openedCh := make(chan map[string]any, 1)
	service := NewService(onlineRegistry("Demo client"), nil,
		func(clientName string, metadata map[string]any, conn *gorillaws.Conn) (*WebSocketSpecus, error) {
			openedCh <- metadata
			return NewWebSocketSpecus(conn, 1, clientName,
				func(frame []byte) error {
					frames <- frame
					return nil
				},
				func() error {
					finishes.Add(1)
					return nil
				}, nil), nil
		}, time.Second, 1024, 1024, nil, &staticRouteSettings{policy: &store.HTTPRouteAccessPolicy{
			Enabled: true, AuthEnabled: true, AuthUsername: "ws-user", AuthPasswordHash: auth.HashToken("ws-password"),
		}}, nil, store.TrafficDetailOptions{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("clientName", "Demo client")
		r.SetPathValue("route", "api")
		service.ServeHTTP(w, r)
	}))
	defer server.Close()

	authRequest := httptest.NewRequest(http.MethodGet, server.URL, nil)
	authRequest.SetBasicAuth("ws-user", "ws-password")
	browser, _, err := websocket.Dial(ctx,
		"ws"+strings.TrimPrefix(server.URL, "http")+"/http/Demo%20client/api/ws/chat?x=%2F",
		&websocket.DialOptions{HTTPHeader: authRequest.Header})
	if err != nil {
		t.Fatalf("websocket.Dial failed: %v", err)
	}
	defer browser.CloseNow()

	var opened map[string]any
	select {
	case opened = <-openedCh:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for OPEN metadata: %v", ctx.Err())
	}

	if opened["source"] != "ws" || opened["route"] != "api" ||
		opened["relativePath"] != "/ws/chat" || opened["rawQuery"] != "x=%2F" {
		t.Fatalf("unexpected OPEN metadata: %+v", opened)
	}
	for _, header := range metadataStrings(opened, "headers") {
		lowerHeader := strings.ToLower(header)
		if strings.HasPrefix(lowerHeader, "sec-websocket-") || strings.HasPrefix(lowerHeader, "authorization:") {
			t.Fatalf("WS handshake/auth header should be skipped: %q", header)
		}
	}

	if err := browser.Write(ctx, websocket.MessageText, []byte("hello")); err != nil {
		t.Fatalf("browser write failed: %v", err)
	}
	select {
	case raw := <-frames:
		frame, err := decodeSWS2(raw)
		if err != nil {
			t.Fatalf("decode captured frame failed: %v", err)
		}
		if frame.opcode != sws2OpcodeText || !frame.fin || string(frame.payload) != "hello" {
			t.Fatalf("unexpected DATA frame: %+v", frame)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for DATA frame: %v", ctx.Err())
	}

	if err := browser.Close(1000, "done"); err != nil {
		t.Fatalf("browser close failed: %v", err)
	}
	select {
	case raw := <-frames:
		frame, err := decodeSWS2(raw)
		if err != nil {
			t.Fatalf("decode captured CLOSE frame failed: %v", err)
		}
		if frame.opcode != sws2OpcodeClose || frame.closeCode != 1000 || string(frame.payload) != "done" {
			t.Fatalf("unexpected CLOSE frame: %+v", frame)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for CLOSE frame: %v", ctx.Err())
	}
	deadline := time.Now().Add(2 * time.Second)
	for finishes.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if finishes.Load() != 1 {
		t.Fatalf("finishes = %d, want 1", finishes.Load())
	}
}

func TestServeWebSocketRejectsMissingBasicAuthBeforeUpgrade(t *testing.T) {
	opened := false
	service := NewService(onlineRegistry("Demo client"), nil,
		func(string, map[string]any, *gorillaws.Conn) (*WebSocketSpecus, error) {
			opened = true
			return nil, nil
		}, time.Second, 1024, 1024, nil, &staticRouteSettings{policy: &store.HTTPRouteAccessPolicy{
			Enabled: true, AuthEnabled: true, AuthUsername: "ws-user", AuthPasswordHash: auth.HashToken("ws-password"),
		}}, nil, store.TrafficDetailOptions{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("clientName", "Demo client")
		r.SetPathValue("route", "api")
		service.ServeHTTP(w, r)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, response, err := websocket.Dial(ctx,
		"ws"+strings.TrimPrefix(server.URL, "http")+"/http/Demo%20client/api/ws/chat", nil)
	if conn != nil {
		conn.CloseNow()
	}
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err == nil || response == nil || response.StatusCode != http.StatusUnauthorized || opened {
		t.Fatalf("err/status/opened = %v/%v/%t, want dial error/401/false", err, responseStatus(response), opened)
	}
	if challenge := response.Header.Get("WWW-Authenticate"); !strings.HasPrefix(challenge, "Basic ") {
		t.Fatalf("WWW-Authenticate = %q", challenge)
	}
}

func responseStatus(response *http.Response) any {
	if response == nil {
		return nil
	}
	return response.StatusCode
}

// TestWSSpecusChunksLargeBrowserMessage 大消息切成 maxSWS2Payload 的帧，
// 首帧保留原 opcode，后续为 CONTINUATION（对齐 Java handleAppFrame）。
func TestWSSpecusChunksLargeBrowserMessage(t *testing.T) {
	h := newWSHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go h.specus.ReadLoop(ctx)

	payload := make([]byte, maxSWS2Payload+100)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := h.browser.Write(ctx, websocket.MessageBinary, payload); err != nil {
		t.Fatalf("browser write failed: %v", err)
	}

	first := h.nextFrame(t)
	if first.opcode != sws2OpcodeBinary || first.fin || len(first.payload) != maxSWS2Payload {
		t.Fatalf("first chunk = opcode %d fin %t len %d", first.opcode, first.fin, len(first.payload))
	}
	second := h.nextFrame(t)
	if second.opcode != sws2OpcodeContinuation || !second.fin || len(second.payload) != 100 {
		t.Fatalf("second chunk = opcode %d fin %t len %d", second.opcode, second.fin, len(second.payload))
	}
	if string(first.payload) != string(payload[:maxSWS2Payload]) ||
		string(second.payload) != string(payload[maxSWS2Payload:]) {
		t.Fatal("chunk payloads do not reassemble the original message")
	}
}

// TestWSSpecusWritesClientFramesToBrowser 客户端 DATA 的 SWS2 帧还原成 WS 消息：
// 分片在 FIN 后重组为一条消息（与 Java 分片发送在浏览器端等价）。
func TestWSSpecusWritesClientFramesToBrowser(t *testing.T) {
	h := newWSHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	first, err := encodeSWS2(sws2OpcodeBinary, false, 0, 0, []byte("abc"))
	if err != nil {
		t.Fatalf("encodeSWS2 failed: %v", err)
	}
	last, err := encodeSWS2(sws2OpcodeContinuation, true, 0, 0, []byte("def"))
	if err != nil {
		t.Fatalf("encodeSWS2 failed: %v", err)
	}
	h.specus.WriteFrame(ctx, first)
	h.specus.WriteFrame(ctx, last)

	typ, payload, err := h.browser.Read(ctx)
	if err != nil {
		t.Fatalf("browser read failed: %v", err)
	}
	if typ != websocket.MessageBinary || string(payload) != "abcdef" {
		t.Fatalf("browser message = %v/%q, want binary/abcdef", typ, payload)
	}

	text, err := encodeSWS2(sws2OpcodeText, true, 0, 0, []byte("你好"))
	if err != nil {
		t.Fatalf("encodeSWS2 failed: %v", err)
	}
	h.specus.WriteFrame(ctx, text)
	typ, payload, err = h.browser.Read(ctx)
	if err != nil {
		t.Fatalf("browser read failed: %v", err)
	}
	if typ != websocket.MessageText || string(payload) != "你好" {
		t.Fatalf("browser message = %v/%q, want text/你好", typ, payload)
	}
}

func TestWSSpecusWritesPingAndPongPayloadsToBrowser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan *gorillaws.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&gorillaws.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err == nil {
			accepted <- conn
		}
	}))
	defer server.Close()
	pingPayloads := make(chan []byte, 1)
	pongPayloads := make(chan []byte, 1)
	browser, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), &websocket.DialOptions{
		OnPingReceived: func(_ context.Context, payload []byte) bool {
			pingPayloads <- append([]byte(nil), payload...)
			return false
		},
		OnPongReceived: func(_ context.Context, payload []byte) {
			pongPayloads <- append([]byte(nil), payload...)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer browser.CloseNow()
	serverConn := <-accepted
	specus := NewWebSocketSpecus(serverConn, 11, "client", func([]byte) error { return nil },
		func() error { return nil }, nil)
	defer specus.Close()
	go func() {
		for {
			if _, _, err := browser.Read(ctx); err != nil {
				return
			}
		}
	}()

	ping, _ := encodeSWS2(sws2OpcodePing, true, 0, 0, []byte("ping-payload"))
	pong, _ := encodeSWS2(sws2OpcodePong, true, 0, 0, []byte("pong-payload"))
	specus.WriteFrame(ctx, ping)
	specus.WriteFrame(ctx, pong)
	if got := <-pingPayloads; string(got) != "ping-payload" {
		t.Fatalf("PING payload = %q", got)
	}
	if got := <-pongPayloads; string(got) != "pong-payload" {
		t.Fatalf("PONG payload = %q", got)
	}
}

func TestServeWebSocketAutoRepliesToPingAndForwardsBrowserPongPayload(t *testing.T) {
	frames := make(chan []byte, 4)
	opened := make(chan struct{}, 1)
	service := NewService(onlineRegistry("Demo client"), nil,
		func(clientName string, _ map[string]any, conn *gorillaws.Conn) (*WebSocketSpecus, error) {
			opened <- struct{}{}
			return NewWebSocketSpecus(conn, 12, clientName, func(frame []byte) error {
				frames <- frame
				return nil
			}, func() error { return nil }, nil), nil
		}, time.Second, 1024, 1024, nil, &staticRouteSettings{policy: &store.HTTPRouteAccessPolicy{Enabled: true}},
		nil, store.TrafficDetailOptions{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("clientName", "Demo client")
		r.SetPathValue("route", "api")
		service.ServeHTTP(w, r)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	browser, _, err := gorillaws.DefaultDialer.DialContext(ctx,
		"ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer browser.Close()
	<-opened
	autoPong := make(chan string, 1)
	browser.SetPongHandler(func(payload string) error {
		autoPong <- payload
		return nil
	})
	go func() {
		_, _, _ = browser.ReadMessage()
	}()
	if err := browser.WriteControl(gorillaws.PingMessage, []byte("browser-ping"),
		webSocketWriteDeadline(ctx)); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-autoPong:
		if payload != "browser-ping" {
			t.Fatalf("automatic PONG payload = %q, want browser-ping", payload)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for automatic PONG")
	}
	if err := browser.WriteControl(gorillaws.PongMessage, []byte("browser-pong"),
		webSocketWriteDeadline(ctx)); err != nil {
		t.Fatal(err)
	}
	select {
	case raw := <-frames:
		frame, err := decodeSWS2(raw)
		if err != nil || frame.opcode != sws2OpcodePong || string(frame.payload) != "browser-pong" {
			t.Fatalf("control frame = %+v err=%v, want PONG payload browser-pong", frame, err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for SWS2 PONG frame")
	}
}

// TestWSSpecusClientCloseFrames 客户端发来 SWS2 CLOSE：浏览器会话按相同关闭码关闭，
// 随后 ReadLoop 退出并向客户端回送 CLOSE+FIN（对齐 Java session.close -> afterConnectionClosed
// -> detachBrowser 的 CLOSE+DISCONNECTED 回送）。
func TestWSSpecusClientCloseFrames(t *testing.T) {
	h := newWSHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	frame, err := encodeSWS2(sws2OpcodeClose, true, 0, 1001, []byte("gone"))
	if err != nil {
		t.Fatalf("encodeSWS2 failed: %v", err)
	}
	go h.specus.ReadLoop(ctx)
	readResult := h.readAsync(ctx)
	h.specus.WriteFrame(ctx, frame)

	readErr := <-readResult
	if websocket.CloseStatus(readErr) != 1001 {
		t.Fatalf("browser close status = %v, want 1001 (err=%v)", websocket.CloseStatus(readErr), readErr)
	}
	if echoed := h.nextFrame(t); echoed.opcode != sws2OpcodeClose {
		t.Fatalf("echoed frame = opcode %d, want CLOSE", echoed.opcode)
	}
	select {
	case <-h.closed:
	case <-ctx.Done():
		t.Fatal("specus did not deregister after client CLOSE")
	}
	if h.finishes.Load() != 1 {
		t.Fatalf("finishes = %d, want 1", h.finishes.Load())
	}
}

// TestWSSpecusOrphanContinuationClosesSpecus 孤立 CONTINUATION 按非法帧处理（对齐 Java writeFrame）。
func TestWSSpecusOrphanContinuationClosesSpecus(t *testing.T) {
	h := newWSHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	frame, err := encodeSWS2(sws2OpcodeContinuation, true, 0, 0, []byte("x"))
	if err != nil {
		t.Fatalf("encodeSWS2 failed: %v", err)
	}
	readResult := h.readAsync(ctx)
	h.specus.WriteFrame(ctx, frame)

	if readErr := <-readResult; readErr == nil {
		t.Fatal("browser read should fail after orphan continuation")
	}
	select {
	case <-h.closed:
	case <-ctx.Done():
		t.Fatal("specus did not deregister after orphan continuation")
	}
}

// TestWSSpecusRejectsNewMessageDuringFragmentation prevents a second data opcode from
// silently replacing an unfinished fragmented message.
func TestWSSpecusRejectsNewMessageDuringFragmentation(t *testing.T) {
	h := newWSHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	first, err := encodeSWS2(sws2OpcodeBinary, false, 0, 0, []byte("unfinished"))
	if err != nil {
		t.Fatalf("encode first SWS2 failed: %v", err)
	}
	replacement, err := encodeSWS2(sws2OpcodeText, true, 0, 0, []byte("replacement"))
	if err != nil {
		t.Fatalf("encode replacement SWS2 failed: %v", err)
	}
	readResult := h.readAsync(ctx)
	h.specus.WriteFrame(ctx, first)
	h.specus.WriteFrame(ctx, replacement)

	if readErr := <-readResult; readErr == nil {
		t.Fatal("browser read should fail after overlapping fragmented messages")
	}
	select {
	case <-h.closed:
	case <-ctx.Done():
		t.Fatal("specus did not deregister after overlapping fragmented messages")
	}
}

// TestWSSpecusSendCredit 验证与 HTTPStream 一致的窗口语义：
// 发送消耗 credit，WINDOW_UPDATE 按 outstanding 返还，非法增量被拒绝。
func TestWSSpecusSendCredit(t *testing.T) {
	h := newWSHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if h.specus.AddSendCredit(0) || h.specus.AddSendCredit(wsMaximumWindowBytes+1) {
		t.Fatal("zero/oversized credit must be rejected")
	}
	if h.specus.AddSendCredit(1) {
		t.Fatal("credit without outstanding bytes must be rejected")
	}

	if err := h.specus.sendAppFrame(ctx, sws2OpcodeText, []byte("hi")); err != nil {
		t.Fatalf("sendAppFrame failed: %v", err)
	}
	sent := h.nextFrame(t)
	frameBytes := sws2HeaderBytes + len(sent.payload)
	if h.specus.AddSendCredit(uint32(frameBytes) + 1) {
		t.Fatal("credit exceeding outstanding bytes must be rejected")
	}
	if !h.specus.AddSendCredit(uint32(frameBytes)) {
		t.Fatal("credit matching outstanding bytes must be accepted")
	}
}

func TestWSSpecusBrowserCloseStopsWaitingWhenClientWithholdsCredit(t *testing.T) {
	h := newWSHarness(t)
	if !h.specus.takeSendCredit(context.Background(), wsInitialWindowBytes) {
		t.Fatal("failed to exhaust initial WebSocket send credit")
	}
	h.browser.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	h.specus.closeFromBrowserContext(ctx, gorillaws.CloseNormalClosure, "done")

	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("browser close waited too long for withheld credit: %s", elapsed)
	}
	if h.finishes.Load() != 1 {
		t.Fatalf("FIN count = %d, want 1", h.finishes.Load())
	}
	select {
	case <-h.closed:
	case <-time.After(time.Second):
		t.Fatal("specus did not close after credit timeout")
	}
}
