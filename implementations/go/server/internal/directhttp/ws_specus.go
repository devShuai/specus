package directhttp

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WS 流复用与 HTTPStream 相同的窗口尺寸（对齐 Java StreamFlowController 的默认值）。
const (
	wsInitialWindowBytes = 1024 * 1024
	wsMaximumWindowBytes = 16 * 1024 * 1024
	// wsMaxMessageBytes 是客户端->浏览器方向重组分片消息的上限，与 Go client 的读取上限一致。
	wsMaxMessageBytes = 16 * 1024 * 1024
	// Browser close must not hold the HTTP handler forever while the client withholds credit.
	wsCloseSendTimeout = 5 * time.Second
)

var errWSSpecusClosed = errors.New("WS 隧道已关闭")

// WSSendFunc 把一帧 SWS2 封装作为 DATA 写入客户端控制通道。
type WSSendFunc func(frame []byte) error

// WSFinishFunc 通知客户端流结束（FIN）。
type WSFinishFunc func() error

// WSClosedFunc 在隧道关闭后从 wsStreams 注销。
type WSClosedFunc func(*WebSocketSpecus)

// WebSocketSpecus 是 HTTP 直转通道的一条浏览器侧 WebSocket 隧道，对齐 Java WebSocketSpecusHandler：
// 浏览器 WS 消息 -> SWS2 -> DATA(streamID) 发往客户端；客户端回送的 DATA(streamID) 经
// WriteFrame 还原成 WS 消息写回浏览器；任一端断开时 CLOSE+FIN 传播到对端。
type WebSocketSpecus struct {
	conn       *websocket.Conn
	streamID   uint32
	clientName string
	sendData   WSSendFunc
	finish     WSFinishFunc
	onClosed   WSClosedFunc

	writeMu    sync.Mutex // 对齐 Java synchronized(session)，串行化浏览器侧写
	notifyOnce sync.Once  // 浏览器->客户端方向的 CLOSE+FIN 只发一次（对齐 Java detachBrowser first-wins）
	closeOnce  sync.Once
	done       chan struct{}

	windowMu        sync.Mutex
	sendCredit      uint64
	sendOutstanding uint64
	notifyWindow    chan struct{}

	// 客户端->浏览器方向的分片重组状态：gorilla/websocket 只写完整消息，
	// 因此把 SWS2 分片缓冲到 FIN 后一次性写出，浏览器看到的仍是一条消息（与 Java 等价）。
	fragmentOpcode int
	fragmentBuffer []byte
}

func NewWebSocketSpecus(conn *websocket.Conn, streamID uint32, clientName string,
	sendData WSSendFunc, finish WSFinishFunc, onClosed WSClosedFunc) *WebSocketSpecus {
	conn.SetReadLimit(int64(wsMaxMessageBytes))
	return &WebSocketSpecus{
		conn: conn, streamID: streamID, clientName: clientName,
		sendData: sendData, finish: finish, onClosed: onClosed,
		done: make(chan struct{}), notifyWindow: make(chan struct{}, 1),
		sendCredit: wsInitialWindowBytes, fragmentOpcode: -1,
	}
}

// StreamID returns the NAT stream identifier of this specus.
func (t *WebSocketSpecus) StreamID() uint32 { return t.streamID }

// ReadLoop 把浏览器 WS 消息封装成 SWS2 帧转发到客户端，直到任一端关闭后返回。
// Gorilla 端点自动以同 payload PONG 响应浏览器 PING；浏览器 PONG 由 read handler
// 按原始 payload 编码为 SWS2 控制帧。
func (t *WebSocketSpecus) ReadLoop(ctx context.Context) {
	stopClose := context.AfterFunc(ctx, func() { _ = t.conn.Close() })
	defer stopClose()
	for {
		typ, payload, err := t.conn.ReadMessage()
		if err != nil {
			code := websocket.CloseInternalServerErr
			reason := ""
			var closeErr *websocket.CloseError
			if errors.As(err, &closeErr) {
				code = closeErr.Code
				reason = closeErr.Text
			}
			t.closeFromBrowser(code, reason)
			return
		}
		opcode := sws2OpcodeBinary
		if typ == websocket.TextMessage {
			opcode = sws2OpcodeText
		}
		if err := t.sendAppFrame(ctx, opcode, payload); err != nil {
			t.closeFromBrowser(websocket.CloseInternalServerErr, "")
			return
		}
	}
}

// sendAppFrame 把一条 WS 消息切成 maxSWS2Payload 的 SWS2 帧，后续分片用 CONTINUATION
// （对齐 Java handleAppFrame；空 payload 也发一帧）。
func (t *WebSocketSpecus) sendAppFrame(ctx context.Context, opcode byte, payload []byte) error {
	offset := 0
	first := true
	for {
		length := min(maxSWS2Payload, len(payload)-offset)
		last := offset+length == len(payload)
		chunkOpcode := opcode
		if !first {
			chunkOpcode = sws2OpcodeContinuation
		}
		frame, err := encodeSWS2(chunkOpcode, last, 0, 0, payload[offset:offset+length])
		if err != nil {
			return err
		}
		if !t.takeSendCredit(ctx, len(frame)) {
			return errWSSpecusClosed
		}
		if err := t.sendData(frame); err != nil {
			return err
		}
		offset += length
		first = false
		if last {
			return nil
		}
	}
}

func (t *WebSocketSpecus) sendControlFrame(ctx context.Context, opcode byte, payload []byte) error {
	frame, err := encodeSWS2(opcode, true, 0, 0, append([]byte(nil), payload...))
	if err != nil {
		return err
	}
	if !t.takeSendCredit(ctx, len(frame)) {
		return errWSSpecusClosed
	}
	return t.sendData(frame)
}

// WriteFrame 由 NAT 会话在收到客户端 DATA(streamID) 时调用：解码 SWS2、还原 WS 消息写回浏览器。
// 帧非法或写失败时按 Java writeFrame 的语义只关闭浏览器会话（CloseFromClient）。
func (t *WebSocketSpecus) WriteFrame(ctx context.Context, data []byte) {
	frame, err := decodeSWS2(data)
	if err != nil || frame.rsv != 0 {
		// 对齐 Java：RSV 扩展在浏览器端点不可用，非法帧直接关闭隧道。
		t.CloseFromClient()
		return
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	var writeErr error
	switch frame.opcode {
	case sws2OpcodeText, sws2OpcodeBinary:
		if t.fragmentOpcode >= 0 {
			t.CloseFromClient()
			return
		}
		if frame.fin {
			writeErr = t.writeMessage(ctx, frame.opcode, frame.payload)
		} else {
			t.fragmentOpcode = int(frame.opcode)
			t.fragmentBuffer = append(t.fragmentBuffer[:0], frame.payload...)
		}
	case sws2OpcodeContinuation:
		if t.fragmentOpcode < 0 {
			t.CloseFromClient()
			return
		}
		t.fragmentBuffer = append(t.fragmentBuffer, frame.payload...)
		if len(t.fragmentBuffer) > wsMaxMessageBytes {
			t.CloseFromClient()
			return
		}
		if frame.fin {
			writeErr = t.writeMessage(ctx, byte(t.fragmentOpcode), t.fragmentBuffer)
			t.fragmentOpcode = -1
			t.fragmentBuffer = nil
		}
	case sws2OpcodePing:
		writeErr = writeWebSocketControl(t.conn, ctx, sws2OpcodePing, frame.payload)
	case sws2OpcodePong:
		writeErr = writeWebSocketControl(t.conn, ctx, sws2OpcodePong, frame.payload)
	case sws2OpcodeClose:
		code := frame.closeCode
		if code == 0 {
			code = websocket.CloseNormalClosure
		}
		_ = closeWebSocket(t.conn, ctx, int(code), string(frame.payload))
	default:
		t.CloseFromClient()
	}
	if writeErr != nil {
		t.CloseFromClient()
	}
}

func (t *WebSocketSpecus) writeMessage(ctx context.Context, opcode byte, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.conn.SetWriteDeadline(webSocketWriteDeadline(ctx)); err != nil {
		return err
	}
	if opcode == sws2OpcodeText {
		return t.conn.WriteMessage(websocket.TextMessage, payload)
	}
	return t.conn.WriteMessage(websocket.BinaryMessage, payload)
}

// CloseFromClient 客户端 FIN/RST：只关浏览器会话，不回送 FIN（对齐 Java closeFromClient）。
func (t *WebSocketSpecus) CloseFromClient() {
	t.notifyOnce.Do(func() {})
	t.Close()
}

// closeFromBrowser 浏览器侧关闭或写失败：向客户端发 SWS2 CLOSE + FIN 后关闭会话
// （对齐 Java detachBrowser；close reason 截断到 123 字节）。
func (t *WebSocketSpecus) closeFromBrowser(code int, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), wsCloseSendTimeout)
	defer cancel()
	t.closeFromBrowserContext(ctx, code, reason)
}

func (t *WebSocketSpecus) closeFromBrowserContext(ctx context.Context, code int, reason string) {
	t.notifyOnce.Do(func() {
		reasonBytes := []byte(reason)
		if len(reasonBytes) > sws2MaxCloseReasonBytes {
			reasonBytes = reasonBytes[:sws2MaxCloseReasonBytes]
		}
		if frame, err := encodeSWS2(sws2OpcodeClose, true, 0, uint16(code), reasonBytes); err == nil {
			if t.takeSendCredit(ctx, len(frame)) {
				_ = t.sendData(frame)
			}
		}
		_ = t.finish()
	})
	t.Close()
}

// Close 关闭浏览器会话并注销流（对齐 Java closeAll 的 GOING_AWAY），幂等。
func (t *WebSocketSpecus) Close() {
	t.closeOnce.Do(func() {
		close(t.done)
		t.signalWindow()
		_ = closeWebSocket(t.conn, context.Background(), websocket.CloseGoingAway, "")
		if t.onClosed != nil {
			t.onClosed(t)
		}
	})
}

// AddSendCredit 处理客户端回送的 WINDOW_UPDATE，语义与 HTTPStream.addSendCredit 一致。
func (t *WebSocketSpecus) AddSendCredit(credit uint32) bool {
	if credit == 0 || credit > wsMaximumWindowBytes {
		return false
	}
	t.windowMu.Lock()
	credit64 := uint64(credit)
	if credit64 > t.sendOutstanding || t.sendCredit+credit64 > wsMaximumWindowBytes {
		t.windowMu.Unlock()
		return false
	}
	t.sendOutstanding -= credit64
	t.sendCredit += credit64
	t.windowMu.Unlock()
	t.signalWindow()
	return true
}

func (t *WebSocketSpecus) takeSendCredit(ctx context.Context, size int) bool {
	if size <= 0 || size > wsMaximumWindowBytes {
		return false
	}
	needed := uint64(size)
	for {
		t.windowMu.Lock()
		if t.sendCredit >= needed {
			t.sendCredit -= needed
			t.sendOutstanding += needed
			t.windowMu.Unlock()
			return true
		}
		t.windowMu.Unlock()
		select {
		case <-ctx.Done():
			return false
		case <-t.done:
			return false
		case <-t.notifyWindow:
		}
	}
}

func (t *WebSocketSpecus) signalWindow() {
	select {
	case t.notifyWindow <- struct{}{}:
	default:
	}
}
