package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/client/internal/protocol"
)

const (
	natInitialWindowBytes = 1024 * 1024
	natMaximumWindowBytes = 16 * 1024 * 1024
)

type natFlowState struct {
	mu             sync.Mutex
	cond           *sync.Cond
	credit         uint64
	closed         bool
	localFinished  bool
	remoteFinished bool
}

func newNatFlowState() *natFlowState {
	state := &natFlowState{credit: natInitialWindowBytes}
	state.cond = sync.NewCond(&state.mu)
	return state
}

func (state *natFlowState) take(size int) bool {
	if size <= 0 || size > natMaximumWindowBytes {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	needed := uint64(size)
	for state.credit < needed && !state.closed {
		state.cond.Wait()
	}
	if state.closed {
		return false
	}
	state.credit -= needed
	return true
}

func (state *natFlowState) add(credit uint32) bool {
	if credit == 0 || credit > natMaximumWindowBytes {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed || state.credit+uint64(credit) > natMaximumWindowBytes {
		return false
	}
	state.credit += uint64(credit)
	state.cond.Broadcast()
	return true
}

func (state *natFlowState) close() {
	state.mu.Lock()
	state.closed = true
	state.cond.Broadcast()
	state.mu.Unlock()
}

func (state *natFlowState) markLocalFinished() bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.localFinished = true
	return state.remoteFinished
}

func (state *natFlowState) markRemoteFinished() bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.remoteFinished = true
	return state.localFinished
}

func (client *Client) syncTunnelConfigs(connection net.Conn, configs []TunnelConfig) {
	desired := make(map[int]TunnelConfig, len(configs))
	for _, config := range configs {
		desired[config.Port] = config
	}
	client.tunnelsMu.Lock()
	client.tunnels = desired
	client.tunnelsMu.Unlock()

	client.registeredMu.Lock()
	var removedPorts []int
	for port := range client.registered {
		if _, exists := desired[port]; !exists {
			delete(client.registered, port)
			removedPorts = append(removedPorts, port)
		}
	}
	client.registeredMu.Unlock()
	for _, port := range removedPorts {
		client.unregisterTunnel(connection, port)
	}
	client.registerConfiguredTunnels(connection)
}

func (client *Client) unregisterTunnel(connection net.Conn, port int) {
	body, err := protocol.EncodeNatMessage(protocol.NatMessage{
		Type:     protocol.NatUnregister,
		Metadata: map[string]any{"port": port},
	})
	if err == nil {
		err = client.send(connection, protocol.CommandNatMessage, body)
	}
	if err != nil {
		client.logger.Printf("unregister NAT port %d failed: %v", port, err)
	}
}

func (client *Client) registerConfiguredTunnels(connection net.Conn) {
	client.tunnelsMu.RLock()
	configs := make([]TunnelConfig, 0, len(client.tunnels))
	for _, config := range client.tunnels {
		configs = append(configs, config)
	}
	client.tunnelsMu.RUnlock()
	for _, config := range configs {
		client.registerTunnel(connection, config)
	}
}

func (client *Client) registerTunnel(connection net.Conn, config TunnelConfig) {
	client.registeredMu.Lock()
	if _, exists := client.registered[config.Port]; exists {
		client.registeredMu.Unlock()
		return
	}
	client.registered[config.Port] = struct{}{}
	client.registeredMu.Unlock()

	body, err := protocol.EncodeNatMessage(protocol.NatMessage{
		Type: protocol.NatRegister,
		Metadata: map[string]any{
			"port":          config.Port,
			"tunnelAddress": config.TunnelAddress,
			"tunnelPort":    config.TunnelPort,
			"clientName":    client.currentClientName(),
		},
	})
	if err == nil {
		err = client.send(connection, protocol.CommandNatMessage, body)
	}
	if err != nil {
		client.registeredMu.Lock()
		delete(client.registered, config.Port)
		client.registeredMu.Unlock()
		client.logger.Printf("register NAT port %d failed: %v", config.Port, err)
	}
}

func (client *Client) handleNatMessage(connection net.Conn, body []byte) error {
	message, err := protocol.DecodeNatMessage(body)
	if err != nil {
		return fmt.Errorf("decode NAT message: %w", err)
	}
	switch message.Type {
	case protocol.NatRegisterResult:
		client.handleNatRegisterResult(message.Metadata)
	case protocol.NatOpen:
		client.openNatFlow(message.StreamID)
		if source, _ := metadataStringOptional(message.Metadata, "source"); source == "http" {
			client.openHTTPStream(connection, message.StreamID, message.Metadata)
		} else if source == "ws" {
			go client.connectWebSocketTunnel(connection, message.StreamID, message.Metadata)
		} else {
			go client.connectLocalTunnel(connection, message.StreamID, message.Metadata)
		}
	case protocol.NatFin:
		if client.finishHTTPRequest(message.StreamID, message.Metadata) {
			return nil
		}
		client.handleRemoteFin(message.StreamID)
	case protocol.NatRST:
		if client.resetHTTPStream(message.StreamID, metadataReason(message.Metadata)) {
			client.closeNatFlow(message.StreamID)
			return nil
		}
		client.removeWebSocketConnection(message.StreamID)
		client.removeLocalConnection(message.StreamID)
		client.closeNatFlow(message.StreamID)
	case protocol.NatData:
		if client.writeHTTPData(message.StreamID, message.Data) {
			return nil
		}
		if handled, err := client.writeWebSocketData(message.StreamID, message.Data); handled {
			if err != nil {
				client.logger.Printf("write local websocket stream %d failed: %v", message.StreamID, err)
				client.disconnectWebSocketTunnel(connection, message.StreamID)
			} else {
				client.sendNatWindowUpdate(connection, message.StreamID, len(message.Data))
				if message.Flags&protocol.NatFlagEndStream != 0 {
					client.handleRemoteFin(message.StreamID)
				}
			}
			return nil
		}
		if err := client.writeLocalData(message.StreamID, message.Data); err != nil {
			client.logger.Printf("write local tunnel stream %d failed: %v", message.StreamID, err)
			client.disconnectLocalTunnel(connection, message.StreamID)
		} else {
			client.sendNatWindowUpdate(connection, message.StreamID, len(message.Data))
			if message.Flags&protocol.NatFlagEndStream != 0 {
				client.handleRemoteFin(message.StreamID)
			}
		}
	case protocol.NatWindowUpdate:
		if !client.addNatCredit(message.StreamID, message.Value) {
			return fmt.Errorf("invalid NAT WINDOW_UPDATE for stream %d", message.StreamID)
		}
	case protocol.NatKeepalive:
		return nil
	default:
		client.logger.Printf("ignored unsupported NAT message type %d", message.Type)
	}
	return nil
}

func (client *Client) handleNatRegisterResult(metadata map[string]any) {
	success, _ := metadata["success"].(bool)
	port, _ := metadataInt(metadata, "port")
	if !success {
		client.registeredMu.Lock()
		delete(client.registered, port)
		client.registeredMu.Unlock()
		reason, _ := metadataString(metadata, "reason")
		client.logger.Printf("register NAT port %d failed: %s", port, reason)
		return
	}
	client.tunnelsMu.RLock()
	config := client.tunnels[port]
	client.tunnelsMu.RUnlock()
	client.logger.Printf("registered NAT port %d -> %s:%d", port, config.TunnelAddress, config.TunnelPort)
}

func (client *Client) connectLocalTunnel(connection net.Conn, streamID uint32, metadata map[string]any) {
	port, err := metadataInt(metadata, "port")
	if err != nil {
		client.logger.Printf("invalid NAT connected message: %v", err)
		return
	}
	channelID, err := metadataString(metadata, "channelId")
	if err != nil {
		client.logger.Printf("invalid NAT connected message: %v", err)
		return
	}
	client.tunnelsMu.RLock()
	config, exists := client.tunnels[port]
	client.tunnelsMu.RUnlock()
	if !exists {
		client.logger.Printf("no local tunnel configured for NAT port %d", port)
		return
	}
	address := net.JoinHostPort(config.TunnelAddress, strconv.Itoa(config.TunnelPort))
	localConnection, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		client.logger.Printf("connect local tunnel %s failed: %v", address, err)
		client.sendNatReset(connection, streamID, 1, "local connect failed")
		client.closeNatFlow(streamID)
		return
	}
	client.localsMu.Lock()
	if previous := client.locals[streamID]; previous != nil {
		_ = previous.Close()
	}
	client.locals[streamID] = localConnection
	client.localsMu.Unlock()
	client.logger.Printf("opened local tunnel channel=%q target=%s", channelID, address)
	go client.copyLocalData(connection, streamID, channelID, localConnection)
}

func (client *Client) copyLocalData(connection net.Conn, streamID uint32, channelID string, localConnection net.Conn) {
	buffer := make([]byte, 32*1024)
	for {
		length, err := localConnection.Read(buffer)
		if length > 0 {
			if !client.takeNatCredit(streamID, length) {
				return
			}
			body, encodeErr := protocol.EncodeNatMessage(protocol.NatMessage{
				Type: protocol.NatData, StreamID: streamID, Data: append([]byte(nil), buffer[:length]...),
			})
			if encodeErr != nil || client.send(connection, protocol.CommandNatMessage, body) != nil {
				client.disconnectLocalTunnel(connection, streamID)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				client.logger.Printf("read local tunnel %q failed: %v", channelID, err)
			}
			client.finishLocalDirection(connection, streamID)
			return
		}
	}
}

func (client *Client) writeLocalData(streamID uint32, data []byte) error {
	client.localsMu.Lock()
	connection := client.locals[streamID]
	client.localsMu.Unlock()
	if connection == nil {
		return fmt.Errorf("local tunnel stream %d is not connected", streamID)
	}
	for len(data) > 0 {
		written, err := connection.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func (client *Client) disconnectLocalTunnel(connection net.Conn, streamID uint32) {
	if client.removeLocalConnection(streamID) {
		client.sendNatFin(connection, streamID)
	}
	client.closeNatFlow(streamID)
}

func (client *Client) sendNatFin(connection net.Conn, streamID uint32) {
	body, err := protocol.EncodeNatMessage(protocol.NatMessage{
		Type: protocol.NatFin, StreamID: streamID,
	})
	if err == nil {
		err = client.send(connection, protocol.CommandNatMessage, body)
	}
	if err != nil {
		client.logger.Printf("send NAT FIN for stream %d failed: %v", streamID, err)
	}
}

func (client *Client) sendNatReset(connection net.Conn, streamID uint32, code uint32, reason string) {
	body, err := protocol.EncodeNatMessage(protocol.NatMessage{
		Type: protocol.NatRST, StreamID: streamID, Value: code, Metadata: map[string]any{"reason": reason},
	})
	if err == nil {
		err = client.send(connection, protocol.CommandNatMessage, body)
	}
	if err != nil {
		client.logger.Printf("send NAT RST for stream %d failed: %v", streamID, err)
	}
}

func (client *Client) sendNatWindowUpdate(connection net.Conn, streamID uint32, credit int) {
	if credit <= 0 {
		return
	}
	body, err := protocol.EncodeNatMessage(protocol.NatMessage{
		Type: protocol.NatWindowUpdate, StreamID: streamID, Value: uint32(credit),
	})
	if err == nil {
		err = client.sendPriority(connection, protocol.CommandNatMessage, body)
	}
	if err != nil {
		client.logger.Printf("send NAT WINDOW_UPDATE for stream %d failed: %v", streamID, err)
	}
}

func (client *Client) openNatFlow(streamID uint32) {
	client.natFlowsMu.Lock()
	previous := client.natFlows[streamID]
	client.natFlows[streamID] = newNatFlowState()
	client.natFlowsMu.Unlock()
	if previous != nil {
		previous.close()
	}
}

func (client *Client) takeNatCredit(streamID uint32, size int) bool {
	client.natFlowsMu.Lock()
	flow := client.natFlows[streamID]
	client.natFlowsMu.Unlock()
	return flow != nil && flow.take(size)
}

func (client *Client) addNatCredit(streamID uint32, credit uint32) bool {
	client.natFlowsMu.Lock()
	flow := client.natFlows[streamID]
	client.natFlowsMu.Unlock()
	return flow == nil || flow.add(credit)
}

func (client *Client) closeNatFlow(streamID uint32) {
	client.natFlowsMu.Lock()
	flow := client.natFlows[streamID]
	delete(client.natFlows, streamID)
	client.natFlowsMu.Unlock()
	if flow != nil {
		flow.close()
	}
}

func (client *Client) finishLocalDirection(connection net.Conn, streamID uint32) {
	client.sendNatFin(connection, streamID)
	client.localsMu.Lock()
	local := client.locals[streamID]
	client.localsMu.Unlock()
	if tcp, ok := local.(*net.TCPConn); ok {
		_ = tcp.CloseRead()
	}
	if client.markNatLocalFinished(streamID) {
		client.removeLocalConnection(streamID)
		client.closeNatFlow(streamID)
	}
}

func (client *Client) markNatLocalFinished(streamID uint32) bool {
	client.natFlowsMu.Lock()
	flow := client.natFlows[streamID]
	client.natFlowsMu.Unlock()
	return flow != nil && flow.markLocalFinished()
}

func (client *Client) handleRemoteFin(streamID uint32) {
	if client.removeWebSocketConnection(streamID) {
		client.closeNatFlow(streamID)
		return
	}
	client.localsMu.Lock()
	local := client.locals[streamID]
	client.localsMu.Unlock()
	if local == nil {
		client.closeNatFlow(streamID)
		return
	}
	if tcp, ok := local.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	} else {
		_ = local.Close()
	}
	client.natFlowsMu.Lock()
	flow := client.natFlows[streamID]
	client.natFlowsMu.Unlock()
	if flow != nil && flow.markRemoteFinished() {
		client.removeLocalConnection(streamID)
		client.closeNatFlow(streamID)
	}
}

func (client *Client) removeLocalConnection(streamID uint32) bool {
	client.localsMu.Lock()
	connection := client.locals[streamID]
	delete(client.locals, streamID)
	client.localsMu.Unlock()
	if connection == nil {
		return false
	}
	_ = connection.Close()
	client.logger.Printf("closed local tunnel stream=%d", streamID)
	return true
}

func (client *Client) closeLocalConnections() {
	client.localsMu.Lock()
	connections := client.locals
	client.locals = make(map[uint32]net.Conn)
	client.localsMu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	client.natFlowsMu.Lock()
	flows := client.natFlows
	client.natFlows = make(map[uint32]*natFlowState)
	client.natFlowsMu.Unlock()
	for _, flow := range flows {
		flow.close()
	}
	client.closeHTTPStreams()
	client.closeWebSocketConnections()
}

func metadataReason(metadata map[string]any) string {
	reason, _ := metadataStringOptional(metadata, "reason")
	return reason
}

func metadataString(metadata map[string]any, name string) (string, error) {
	value, exists := metadata[name]
	if !exists {
		return "", fmt.Errorf("NAT metadata is missing %q", name)
	}
	if value == nil {
		return "", fmt.Errorf("NAT metadata %q is null", name)
	}
	if text, ok := value.(string); ok {
		return text, nil
	}
	return fmt.Sprint(value), nil
}

func metadataStringOptional(metadata map[string]any, name string) (string, bool) {
	value, exists := metadata[name]
	if !exists || value == nil {
		return "", false
	}
	text, ok := value.(string)
	if !ok {
		return fmt.Sprint(value), true
	}
	return text, true
}

func metadataInt(metadata map[string]any, name string) (int, error) {
	value, exists := metadata[name]
	if !exists {
		return 0, fmt.Errorf("NAT metadata is missing %q", name)
	}
	switch number := value.(type) {
	case float64:
		return int(number), nil
	case float32:
		return int(number), nil
	case int:
		return number, nil
	case int64:
		return int(number), nil
	case int32:
		return int(number), nil
	case json.Number:
		parsed, err := strconv.ParseInt(number.String(), 10, 32)
		if err != nil {
			return 0, fmt.Errorf("NAT metadata %q is not a number", name)
		}
		return int(parsed), nil
	case string:
		parsed, err := strconv.ParseInt(number, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("NAT metadata %q is not a number", name)
		}
		return int(parsed), nil
	default:
		return 0, fmt.Errorf("NAT metadata %q is not a number", name)
	}
}
