package directhttp

import (
	"context"
	"fmt"
	"time"

	"github.com/gorilla/websocket"
)

func writeWebSocketControl(conn *websocket.Conn, ctx context.Context, opcode byte, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	messageType := 0
	switch opcode {
	case sws2OpcodePing:
		messageType = websocket.PingMessage
	case sws2OpcodePong:
		messageType = websocket.PongMessage
	default:
		return fmt.Errorf("unsupported WebSocket control opcode %d", opcode)
	}
	return conn.WriteControl(messageType, payload, webSocketWriteDeadline(ctx))
}

func closeWebSocket(conn *websocket.Conn, ctx context.Context, code int, reason string) error {
	writeErr := conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason),
		webSocketWriteDeadline(ctx))
	closeErr := conn.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func webSocketWriteDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(wsCloseSendTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}
