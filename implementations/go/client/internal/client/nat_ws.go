package client

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/client/internal/protocol"
)

const (
	webSocketFrameText   byte = 0x01
	webSocketFrameBinary byte = 0x02

	webSocketOpcodeContinuation byte = 0x0
	webSocketOpcodeText         byte = 0x1
	webSocketOpcodeBinary       byte = 0x2
	webSocketOpcodeClose        byte = 0x8
	webSocketOpcodePing         byte = 0x9
	webSocketOpcodePong         byte = 0xA

	maxWebSocketMessageBytes = 16 * 1024 * 1024
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
	conn    net.Conn
	reader  *bufio.Reader
	writeMu sync.Mutex
}

func (client *Client) connectWebSocketTunnel(connection net.Conn, metadata map[string]any) {
	channelID, err := metadataString(metadata, "channelId")
	if err != nil {
		client.logger.Printf("[ws-tunnel][client] invalid CONNECTED message: %v", err)
		return
	}
	route, err := metadataString(metadata, "route")
	if err != nil {
		client.logger.Printf("[ws-tunnel][client] CONNECTED missing route: %v", err)
		client.sendWebSocketNatDisconnected(connection, channelID)
		return
	}
	targetBaseURL := client.routeTarget(route)
	if strings.TrimSpace(targetBaseURL) == "" {
		client.logger.Printf("[ws-tunnel][client] CONNECTED for unknown route %q", route)
		client.sendWebSocketNatDisconnected(connection, channelID)
		return
	}
	relativePath, _ := metadataStringOptional(metadata, "relativePath")
	rawQuery, _ := metadataStringOptional(metadata, "rawQuery")
	target, err := buildWebSocketTarget(targetBaseURL, relativePath, rawQuery)
	if err != nil {
		client.logger.Printf("[ws-tunnel][client] CONNECTED route=%q build-target-failed: %v", route, err)
		client.sendWebSocketNatDisconnected(connection, channelID)
		return
	}
	localConnection, err := dialLocalWebSocket(target, webSocketHandshakeHeaders(metadata))
	if err != nil {
		client.logger.Printf("[ws-tunnel][client] connect local ws failed channelId=%q route=%q target=%s: %v",
			channelID, route, targetWithoutRawQuery(target), err)
		client.sendWebSocketNatDisconnected(connection, channelID)
		return
	}

	client.wsLocalsMu.Lock()
	if previous := client.wsLocals[channelID]; previous != nil {
		_ = previous.close()
	}
	client.wsLocals[channelID] = localConnection
	client.wsLocalsMu.Unlock()
	client.logger.Printf("[ws-tunnel][client] ws handshake ok channelId=%q route=%q target=%s",
		channelID, route, targetWithoutRawQuery(target))
	go client.copyWebSocketData(connection, channelID, localConnection)
}

func buildWebSocketTarget(targetBaseURL, relativePath, rawQuery string) (*url.URL, error) {
	if strings.TrimSpace(targetBaseURL) == "" {
		return nil, fmt.Errorf("未配置 HTTP route")
	}
	wsURL := strings.TrimSpace(targetBaseURL)
	lower := strings.ToLower(wsURL)
	switch {
	case strings.HasPrefix(lower, "http://"):
		wsURL = "ws://" + wsURL[len("http://"):]
	case strings.HasPrefix(lower, "https://"):
		wsURL = "wss://" + wsURL[len("https://"):]
	case strings.HasPrefix(lower, "ws://") || strings.HasPrefix(lower, "wss://"):
	default:
		return nil, fmt.Errorf("HTTP route 仅支持 http/https/ws/wss")
	}

	base, err := url.Parse(wsURL)
	if err != nil || base.Hostname() == "" || base.RawQuery != "" || base.Fragment != "" {
		return nil, fmt.Errorf("HTTP route 地址无效")
	}
	tail := relativePath
	if strings.TrimSpace(tail) == "" {
		tail = "/"
	}
	if strings.ContainsAny(tail, "\r\n") {
		return nil, fmt.Errorf("relativePath 含有非法控制字符")
	}

	basePath := base.EscapedPath()
	if basePath == "/" {
		basePath = ""
	}
	var path string
	switch {
	case strings.HasSuffix(basePath, "/") && strings.HasPrefix(tail, "/"):
		path = basePath + tail[1:]
	case basePath != "" && !strings.HasSuffix(basePath, "/") && !strings.HasPrefix(tail, "/"):
		path = basePath + "/" + tail
	default:
		path = basePath + tail
	}
	if path == "" {
		path = "/"
	}

	target := *base
	target.Path = path
	target.RawPath = ""
	target.RawQuery = rawQuery
	return &target, nil
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

func dialLocalWebSocket(target *url.URL, headers []string) (*webSocketLocalConnection, error) {
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
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			ServerName:         target.Hostname(),
			InsecureSkipVerify: true,
		})
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

func (client *Client) copyWebSocketData(connection net.Conn, channelID string, localConnection *webSocketLocalConnection) {
	for {
		opcode, payload, err := localConnection.readMessage()
		if err != nil {
			if err != io.EOF {
				client.logger.Printf("[ws-tunnel][client] read local ws %q failed: %v", channelID, err)
			}
			client.disconnectWebSocketTunnel(connection, channelID)
			return
		}
		frameType := webSocketFrameBinary
		if opcode == webSocketOpcodeText {
			frameType = webSocketFrameText
		}
		data := make([]byte, len(payload)+1)
		data[0] = frameType
		copy(data[1:], payload)
		body, encodeErr := protocol.EncodeNatMessage(protocol.NatMessage{
			Type:     protocol.NatData,
			Metadata: map[string]any{"channelId": channelID, "source": "ws"},
			Data:     data,
		})
		if encodeErr != nil || client.send(connection, protocol.CommandNatMessage, body) != nil {
			client.disconnectWebSocketTunnel(connection, channelID)
			return
		}
	}
}

func (connection *webSocketLocalConnection) readMessage() (byte, []byte, error) {
	var currentOpcode byte
	var current bytes.Buffer
	for {
		fin, opcode, payload, err := connection.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch opcode {
		case webSocketOpcodeText, webSocketOpcodeBinary:
			if fin {
				return opcode, payload, nil
			}
			currentOpcode = opcode
			current.Reset()
			current.Write(payload)
		case webSocketOpcodeContinuation:
			if currentOpcode == 0 {
				return 0, nil, fmt.Errorf("unexpected websocket continuation frame")
			}
			current.Write(payload)
			if current.Len() > maxWebSocketMessageBytes {
				return 0, nil, fmt.Errorf("websocket message exceeds limit")
			}
			if fin {
				return currentOpcode, current.Bytes(), nil
			}
		case webSocketOpcodeClose:
			_ = connection.writeFrame(webSocketOpcodeClose, nil)
			return 0, nil, io.EOF
		case webSocketOpcodePing:
			if err := connection.writeFrame(webSocketOpcodePong, payload); err != nil {
				return 0, nil, err
			}
		case webSocketOpcodePong:
			continue
		default:
			return 0, nil, fmt.Errorf("unsupported websocket opcode %d", opcode)
		}
	}
}

func (connection *webSocketLocalConnection) readFrame() (bool, byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(connection.reader, header); err != nil {
		return false, 0, nil, err
	}
	fin := header[0]&0x80 != 0
	opcode := header[0] & 0x0F
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(connection.reader, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(connection.reader, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > maxWebSocketMessageBytes {
		return false, 0, nil, fmt.Errorf("websocket frame exceeds limit")
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(connection.reader, mask[:]); err != nil {
			return false, 0, nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(connection.reader, payload); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return fin, opcode, payload, nil
}

func (connection *webSocketLocalConnection) writeFrame(opcode byte, payload []byte) error {
	if len(payload) > maxWebSocketMessageBytes {
		return fmt.Errorf("websocket message exceeds limit")
	}
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()

	header := make([]byte, 0, 14)
	header = append(header, 0x80|opcode)
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
	return err
}

func (connection *webSocketLocalConnection) close() error {
	_ = connection.writeFrame(webSocketOpcodeClose, nil)
	return connection.conn.Close()
}

func (client *Client) writeWebSocketData(channelID string, data []byte) (bool, error) {
	client.wsLocalsMu.Lock()
	connection := client.wsLocals[channelID]
	client.wsLocalsMu.Unlock()
	if connection == nil {
		return false, nil
	}
	if len(data) == 0 {
		return true, nil
	}
	switch data[0] {
	case webSocketFrameText:
		return true, connection.writeFrame(webSocketOpcodeText, data[1:])
	case webSocketFrameBinary:
		return true, connection.writeFrame(webSocketOpcodeBinary, data[1:])
	default:
		return true, nil
	}
}

func (client *Client) disconnectWebSocketTunnel(connection net.Conn, channelID string) {
	if client.removeWebSocketConnection(channelID) {
		client.sendWebSocketNatDisconnected(connection, channelID)
	}
}

func (client *Client) sendWebSocketNatDisconnected(connection net.Conn, channelID string) {
	body, err := protocol.EncodeNatMessage(protocol.NatMessage{
		Type:     protocol.NatDisconnected,
		Metadata: map[string]any{"channelId": channelID, "source": "ws"},
	})
	if err == nil {
		err = client.send(connection, protocol.CommandNatMessage, body)
	}
	if err != nil {
		client.logger.Printf("[ws-tunnel][client] send NAT disconnected for %q failed: %v", channelID, err)
	}
}

func (client *Client) removeWebSocketConnection(channelID string) bool {
	client.wsLocalsMu.Lock()
	connection := client.wsLocals[channelID]
	delete(client.wsLocals, channelID)
	client.wsLocalsMu.Unlock()
	if connection == nil {
		return false
	}
	_ = connection.close()
	client.logger.Printf("[ws-tunnel][client] closed local ws channel=%q", channelID)
	return true
}

func (client *Client) closeWebSocketConnections() {
	client.wsLocalsMu.Lock()
	connections := client.wsLocals
	client.wsLocals = make(map[string]*webSocketLocalConnection)
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
