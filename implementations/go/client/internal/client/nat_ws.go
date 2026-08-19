package client

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/devShuai/specus/implementations/go/client/internal/protocol"
)

const (
	webSocketOpcodeContinuation byte = 0x0
	webSocketOpcodeText         byte = 0x1
	webSocketOpcodeBinary       byte = 0x2
	webSocketOpcodeClose        byte = 0x8
	webSocketOpcodePing         byte = 0x9
	webSocketOpcodePong         byte = 0xA

	maxWebSocketMessageBytes = 16 * 1024 * 1024
)

var (
	errWebSocketCloseCreditTimeout = errors.New("websocket close credit timeout")
	webSocketCloseCreditTimeout    = 5 * time.Second
	webSocketCloseCleanupTimeout   = 5 * time.Second
)

var skippedWebSocketHeaders = map[string]struct{}{
	"connection":               {},
	"content-length":           {},
	"host":                     {},
	"keep-alive":               {},
	"proxy-authenticate":       {},
	"proxy-authorization":      {},
	"te":                       {},
	"trailer":                  {},
	"transfer-encoding":        {},
	"upgrade":                  {},
	"sec-websocket-key":        {},
	"sec-websocket-version":    {},
	"sec-websocket-extensions": {},
	"sec-websocket-protocol":   {},
	"sec-websocket-accept":     {},
}

type webSocketLocalConnection struct {
	conn      net.Conn
	reader    *bufio.Reader
	writeMu   sync.Mutex
	closeSent bool
}

func (client *Client) connectWebSocketSpecus(connection net.Conn, streamID uint32, metadata map[string]any) {
	channelID, err := metadataString(metadata, "channelId")
	if err != nil {
		client.logger.Printf("[ws-specus][client] invalid CONNECTED message: %v", err)
		return
	}
	route, err := metadataString(metadata, "route")
	if err != nil {
		client.logger.Printf("[ws-specus][client] CONNECTED missing route: %v", err)
		client.sendNatReset(connection, streamID, 2, "websocket route missing")
		return
	}
	targetBaseURL := client.routeTarget(route)
	if strings.TrimSpace(targetBaseURL) == "" {
		client.logger.Printf("[ws-specus][client] CONNECTED for unknown route %q", route)
		client.sendNatReset(connection, streamID, 3, "unknown websocket route")
		return
	}
	relativePath, _ := metadataStringOptional(metadata, "relativePath")
	rawQuery, _ := metadataStringOptional(metadata, "rawQuery")
	target, err := buildWebSocketTarget(targetBaseURL, relativePath, rawQuery)
	if err != nil {
		client.logger.Printf("[ws-specus][client] CONNECTED route=%q build-target-failed: %v", route, err)
		client.sendNatReset(connection, streamID, 4, "invalid websocket target")
		return
	}
	localConnection, err := dialLocalWebSocket(target, webSocketHandshakeHeaders(metadata),
		client.upstreamTLSFactory())
	if err != nil {
		client.logger.Printf("[ws-specus][client] connect local ws failed channelId=%q route=%q target=%s: %v",
			channelID, route, targetWithoutRawQuery(target), err)
		client.sendNatReset(connection, streamID, 5, "websocket connect failed")
		client.closeNatFlow(streamID)
		return
	}

	client.wsLocalsMu.Lock()
	if previous := client.wsLocals[streamID]; previous != nil {
		_ = previous.close()
	}
	client.wsLocals[streamID] = localConnection
	client.wsLocalsMu.Unlock()
	client.logger.Printf("[ws-specus][client] ws handshake ok channelId=%q route=%q target=%s",
		channelID, route, targetWithoutRawQuery(target))
	go client.copyWebSocketData(connection, streamID, channelID, localConnection)
}

func buildWebSocketTarget(targetBaseURL, relativePath, rawQuery string) (*url.URL, error) {
	if strings.TrimSpace(targetBaseURL) == "" {
		return nil, fmt.Errorf("未配置 HTTP route")
	}
	baseURL := strings.TrimSpace(targetBaseURL)
	lower := strings.ToLower(baseURL)
	var httpBaseURL string
	var targetScheme string
	switch {
	case strings.HasPrefix(lower, "http://"):
		httpBaseURL = "http://" + baseURL[len("http://"):]
		targetScheme = "ws"
	case strings.HasPrefix(lower, "https://"):
		httpBaseURL = "https://" + baseURL[len("https://"):]
		targetScheme = "wss"
	case strings.HasPrefix(lower, "ws://"):
		httpBaseURL = "http://" + baseURL[len("ws://"):]
		targetScheme = "ws"
	case strings.HasPrefix(lower, "wss://"):
		httpBaseURL = "https://" + baseURL[len("wss://"):]
		targetScheme = "wss"
	default:
		return nil, fmt.Errorf("HTTP route 仅支持 http/https/ws/wss")
	}
	if strings.ContainsAny(relativePath, "\r\n") {
		return nil, fmt.Errorf("relativePath 含有非法控制字符")
	}
	target, err := buildTarget(httpBaseURL, relativePath, rawQuery)
	if err != nil {
		return nil, err
	}
	target.Scheme = targetScheme
	return target, nil
}

func webSocketHandshakeHeaders(metadata map[string]any) []string {
	raw, ok := metadata["headers"]
	if !ok || raw == nil {
		return nil
	}
	var values []any
	switch typed := raw.(type) {
	case []any:
		values = typed
	case []string:
		values = make([]any, 0, len(typed))
		for _, value := range typed {
			values = append(values, value)
		}
	default:
		return nil
	}
	headers := make([]string, 0, len(values))
	for _, value := range values {
		line, ok := value.(string)
		if !ok {
			continue
		}
		separator := strings.IndexByte(line, ':')
		if separator <= 0 {
			continue
		}
		name := strings.ToLower(line[:separator])
		if _, skipped := skippedWebSocketHeaders[name]; skipped {
			continue
		}
		headers = append(headers, line)
	}
	return headers
}

func dialLocalWebSocket(target *url.URL, headers []string,
	upstreamTLS *upstreamTLSFactory) (*webSocketLocalConnection, error) {
	address := target.Host
	if _, _, err := net.SplitHostPort(address); err != nil {
		switch strings.ToLower(target.Scheme) {
		case "wss":
			address = net.JoinHostPort(target.Host, "443")
		default:
			address = net.JoinHostPort(target.Host, "80")
		}
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	var conn net.Conn
	var err error
	if strings.EqualFold(target.Scheme, "wss") {
		// Verified like any other upstream connection; see upstream_tls.go for why this is not
		// simply skipped and how a self-signed target is configured.
		tlsConfig, configErr := upstreamTLS.forHost(target.Hostname())
		if configErr != nil {
			return nil, configErr
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	} else {
		conn, err = dialer.Dial("tcp", address)
	}
	if err != nil {
		return nil, err
	}

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		_ = conn.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	requestURI := target.RequestURI()
	if requestURI == "" {
		requestURI = "/"
	}

	var request bytes.Buffer
	fmt.Fprintf(&request, "GET %s HTTP/1.1\r\n", requestURI)
	fmt.Fprintf(&request, "Host: %s\r\n", target.Host)
	request.WriteString("Upgrade: websocket\r\n")
	request.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&request, "Sec-WebSocket-Key: %s\r\n", key)
	request.WriteString("Sec-WebSocket-Version: 13\r\n")
	for _, header := range headers {
		request.WriteString(header)
		request.WriteString("\r\n")
	}
	request.WriteString("\r\n")
	if _, err := conn.Write(request.Bytes()); err != nil {
		_ = conn.Close()
		return nil, err
	}

	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		_ = conn.Close()
		return nil, fmt.Errorf("websocket handshake failed: HTTP %d", response.StatusCode)
	}
	if !strings.EqualFold(response.Header.Get("Upgrade"), "websocket") ||
		!headerHasToken(response.Header.Get("Connection"), "upgrade") {
		_ = conn.Close()
		return nil, fmt.Errorf("websocket handshake missing upgrade headers")
	}
	if response.Header.Get("Sec-WebSocket-Accept") != webSocketAccept(key) {
		_ = conn.Close()
		return nil, fmt.Errorf("websocket handshake accept mismatch")
	}

	return &webSocketLocalConnection{conn: conn, reader: reader}, nil
}

func webSocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func headerHasToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func (client *Client) copyWebSocketData(connection net.Conn, streamID uint32, channelID string,
	localConnection *webSocketLocalConnection) {
	for {
		fin, rsv, opcode, payload, err := localConnection.readFrame()
		if err != nil {
			if err != io.EOF {
				client.logger.Printf("[ws-specus][client] read local ws %q failed: %v", channelID, err)
			}
			client.disconnectWebSocketSpecus(connection, streamID)
			return
		}
		closeCode := uint16(0)
		if opcode == webSocketOpcodeClose {
			if len(payload) == 1 {
				client.sendNatReset(connection, streamID, 7, "invalid websocket close payload")
				client.removeWebSocketConnection(streamID)
				client.closeNatFlow(streamID)
				return
			}
			if len(payload) >= 2 {
				closeCode = binary.BigEndian.Uint16(payload[:2])
				payload = payload[2:]
			}
		}
		if err := client.sendWebSocketFrames(connection, streamID, opcode, fin, rsv, closeCode, payload); err != nil {
			if opcode == webSocketOpcodeClose && errors.Is(err, errWebSocketCloseCreditTimeout) {
				client.sendNatReset(connection, streamID, 8, "websocket close credit timeout")
				client.removeWebSocketConnection(streamID)
				client.closeNatFlow(streamID)
				return
			}
			client.disconnectWebSocketSpecus(connection, streamID)
			return
		}
		if opcode == webSocketOpcodeClose {
			client.sendNatFin(connection, streamID)
			client.markNatLocalFinished(streamID)
			// Keep the local half briefly so an echoed CLOSE can complete the
			// WebSocket handshake.  Some servers do not return FIN after consuming
			// CLOSE+FIN, so a bounded fallback owns final cleanup.
			client.scheduleWebSocketCloseCleanup(streamID, localConnection)
			return
		}
	}
}

func (client *Client) sendWebSocketFrames(connection net.Conn, streamID uint32, opcode byte,
	fin bool, rsv byte, closeCode uint16, payload []byte) error {
	offset := 0
	first := true
	for {
		length := len(payload) - offset
		if length > maxWebSocketFramePayload {
			length = maxWebSocketFramePayload
		}
		chunkOpcode := opcode
		chunkRSV := rsv
		chunkCloseCode := closeCode
		if !first {
			chunkOpcode = webSocketOpcodeContinuation
			chunkRSV = 0
			chunkCloseCode = 0
		}
		last := offset+length == len(payload)
		encoded, err := encodeWebSocketSpecusFrame(webSocketSpecusFrame{
			opcode: chunkOpcode, fin: fin && last, rsv: chunkRSV,
			closeCode: chunkCloseCode, payload: payload[offset : offset+length],
		})
		if err != nil {
			return err
		}
		if opcode == webSocketOpcodeClose {
			taken, timedOut := client.takeNatCreditWithin(
				streamID, len(encoded), webSocketCloseCreditTimeout)
			if !taken {
				if timedOut {
					return errWebSocketCloseCreditTimeout
				}
				return io.ErrClosedPipe
			}
		} else if !client.takeNatCredit(streamID, len(encoded)) {
			return io.ErrClosedPipe
		}
		body, err := protocol.EncodeNatMessage(protocol.NatMessage{
			Type: protocol.NatData, StreamID: streamID, Data: encoded,
		})
		if err != nil {
			return err
		}
		if err := client.send(connection, protocol.CommandNatMessage, body); err != nil {
			return err
		}
		offset += length
		first = false
		if last {
			return nil
		}
	}
}

func (connection *webSocketLocalConnection) readFrame() (bool, byte, byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(connection.reader, header); err != nil {
		return false, 0, 0, nil, err
	}
	fin := header[0]&0x80 != 0
	rsv := (header[0] >> 4) & 0x07
	opcode := header[0] & 0x0F
	masked := header[1]&0x80 != 0
	if masked {
		return false, 0, 0, nil, fmt.Errorf("server websocket frame must not be masked")
	}
	length := uint64(header[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(connection.reader, ext[:]); err != nil {
			return false, 0, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(connection.reader, ext[:]); err != nil {
			return false, 0, 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > maxWebSocketMessageBytes {
		return false, 0, 0, nil, fmt.Errorf("websocket frame exceeds limit")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(connection.reader, payload); err != nil {
		return false, 0, 0, nil, err
	}
	return fin, rsv, opcode, payload, nil
}

func (connection *webSocketLocalConnection) writeFrame(fin bool, rsv byte, opcode byte, payload []byte) error {
	if len(payload) > maxWebSocketMessageBytes {
		return fmt.Errorf("websocket message exceeds limit")
	}
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	return connection.writeFrameLocked(fin, rsv, opcode, payload)
}

func (connection *webSocketLocalConnection) writeFrameLocked(
	fin bool, rsv byte, opcode byte, payload []byte) error {
	header := make([]byte, 0, 14)
	first := opcode | ((rsv & 7) << 4)
	if fin {
		first |= 0x80
	}
	header = append(header, first)
	switch {
	case len(payload) < 126:
		header = append(header, 0x80|byte(len(payload)))
	case len(payload) <= 0xFFFF:
		header = append(header, 0x80|126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(len(payload)))
		header = append(header, ext[:]...)
	default:
		header = append(header, 0x80|127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(len(payload)))
		header = append(header, ext[:]...)
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	header = append(header, mask[:]...)
	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}
	if _, err := connection.conn.Write(header); err != nil {
		return err
	}
	_, err := connection.conn.Write(masked)
	if err == nil && opcode == webSocketOpcodeClose {
		connection.closeSent = true
	}
	return err
}

func (connection *webSocketLocalConnection) close() error {
	connection.writeMu.Lock()
	if !connection.closeSent {
		_ = connection.writeFrameLocked(true, 0, webSocketOpcodeClose, nil)
	}
	connection.writeMu.Unlock()
	return connection.conn.Close()
}

func (client *Client) writeWebSocketData(streamID uint32, data []byte) (bool, error) {
	client.wsLocalsMu.Lock()
	connection := client.wsLocals[streamID]
	client.wsLocalsMu.Unlock()
	if connection == nil {
		return false, nil
	}
	frame, err := decodeWebSocketSpecusFrame(data)
	if err != nil {
		return true, err
	}
	payload := frame.payload
	if frame.opcode == webSocketOpcodeClose && frame.closeCode != 0 {
		payload = make([]byte, 2+len(frame.payload))
		binary.BigEndian.PutUint16(payload[:2], frame.closeCode)
		copy(payload[2:], frame.payload)
	}
	return true, connection.writeFrame(frame.fin, frame.rsv, frame.opcode, payload)
}

func (client *Client) disconnectWebSocketSpecus(connection net.Conn, streamID uint32) {
	if client.removeWebSocketConnection(streamID) {
		client.sendNatFin(connection, streamID)
	}
	client.closeNatFlow(streamID)
}

func (client *Client) removeWebSocketConnection(streamID uint32) bool {
	return client.removeWebSocketConnectionIf(streamID, nil)
}

func (client *Client) removeWebSocketConnectionIf(
	streamID uint32, expected *webSocketLocalConnection) bool {
	client.wsLocalsMu.Lock()
	connection := client.wsLocals[streamID]
	if expected != nil && connection != expected {
		client.wsLocalsMu.Unlock()
		return false
	}
	delete(client.wsLocals, streamID)
	client.wsLocalsMu.Unlock()
	if connection == nil {
		return false
	}
	_ = connection.close()
	client.logger.Printf("[ws-specus][client] closed local ws stream=%d", streamID)
	return true
}

func (client *Client) scheduleWebSocketCloseCleanup(
	streamID uint32, expected *webSocketLocalConnection) {
	time.AfterFunc(webSocketCloseCleanupTimeout, func() {
		if client.removeWebSocketConnectionIf(streamID, expected) {
			client.closeNatFlow(streamID)
		}
	})
}

func (client *Client) closeWebSocketConnections() {
	client.wsLocalsMu.Lock()
	connections := client.wsLocals
	client.wsLocals = make(map[uint32]*webSocketLocalConnection)
	client.wsLocalsMu.Unlock()
	for _, connection := range connections {
		_ = connection.close()
	}
}

func targetWithoutRawQuery(target *url.URL) string {
	clone := *target
	clone.RawQuery = ""
	return clone.String()
}
