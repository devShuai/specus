package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/devShuai/specus/implementations/go/client/internal/protocol"
)

const (
	natInitialWindowBytes = 1024 * 1024
	natMaximumWindowBytes = 16 * 1024 * 1024
)

type natFlowState struct {
	mu               sync.Mutex
	cond             *sync.Cond
	tcpWriteMu       sync.Mutex
	credit           uint64
	closed           bool
	localFinished    bool
	remoteFinished   bool
	tcpConnecting    bool
	tcpConnectCancel context.CancelFunc
	tcpPendingData   [][]byte
	tcpPendingBytes  int
}

type tcpDataDisposition uint8

const (
	tcpDataReady tcpDataDisposition = iota
	tcpDataQueued
	tcpDataAfterFin
	tcpDataOverflow
	tcpDataClosed
)

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

// takeWithin is the bounded variant used by terminal WebSocket frames.  A peer
// is allowed to stop granting credit while a close handshake is in flight; in
// that case the stream must be released instead of leaving a goroutine parked
// on the condition variable forever.
func (state *natFlowState) takeWithin(size int, timeout time.Duration) (taken bool, timedOut bool) {
	if size <= 0 || size > natMaximumWindowBytes || timeout <= 0 {
		return false, false
	}
	deadline := time.Now().Add(timeout)
	timer := time.AfterFunc(timeout, func() {
		state.mu.Lock()
		state.cond.Broadcast()
		state.mu.Unlock()
	})
	defer timer.Stop()

	state.mu.Lock()
	defer state.mu.Unlock()
	needed := uint64(size)
	for state.credit < needed && !state.closed {
		if !time.Now().Before(deadline) {
			return false, true
		}
		state.cond.Wait()
	}
	if state.closed {
		return false, false
	}
	if state.credit < needed {
		return false, true
	}
	state.credit -= needed
	return true, false
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
	state.tcpConnecting = false
	if state.tcpConnectCancel != nil {
		state.tcpConnectCancel()
		state.tcpConnectCancel = nil
	}
	state.tcpPendingData = nil
	state.tcpPendingBytes = 0
	state.cond.Broadcast()
	state.mu.Unlock()
}

func (state *natFlowState) beginTCPConnect() (context.Context, bool) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed || state.tcpConnecting {
		return nil, false
	}
	ctx, cancel := context.WithCancel(context.Background())
	state.tcpConnecting = true
	state.tcpConnectCancel = cancel
	return ctx, true
}

func (state *natFlowState) stageTCPData(data []byte, endStream bool) tcpDataDisposition {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return tcpDataClosed
	}
	if state.remoteFinished {
		return tcpDataAfterFin
	}
	if !state.tcpConnecting {
		return tcpDataReady
	}
	if len(data) > natInitialWindowBytes-state.tcpPendingBytes {
		return tcpDataOverflow
	}
	if len(data) > 0 {
		state.tcpPendingData = append(state.tcpPendingData, append([]byte(nil), data...))
		state.tcpPendingBytes += len(data)
	}
	if endStream {
		state.remoteFinished = true
	}
	return tcpDataQueued
}

func (state *natFlowState) activateTCPConnection() (pending [][]byte, remoteFinished bool, complete bool, ok bool) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed || !state.tcpConnecting {
		return nil, false, false, false
	}
	state.tcpConnecting = false
	if state.tcpConnectCancel != nil {
		state.tcpConnectCancel()
		state.tcpConnectCancel = nil
	}
	pending = state.tcpPendingData
	state.tcpPendingData = nil
	state.tcpPendingBytes = 0
	return pending, state.remoteFinished, state.localFinished, true
}

func (state *natFlowState) receiveRemoteFin() (complete bool, accepted bool, connecting bool) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed || state.remoteFinished {
		return false, false, false
	}
	state.remoteFinished = true
	return state.localFinished, true, state.tcpConnecting
}

func (state *natFlowState) canReceiveRemoteData() bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	return !state.closed && !state.remoteFinished
}

func (client *Client) syncSpecusConfigs(connection net.Conn, configs []SpecusConfig) {
	desired := make(map[int]SpecusConfig, len(configs))
	for _, config := range configs {
		desired[config.Port] = config
	}
	client.specusMappingsMu.Lock()
	client.specusMappings = desired
	client.specusMappingsMu.Unlock()

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
		client.unregisterSpecus(connection, port)
	}
	client.registerConfiguredSpecusMappings(connection)
}

func (client *Client) unregisterSpecus(connection net.Conn, port int) {
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

func (client *Client) registerConfiguredSpecusMappings(connection net.Conn) {
	client.specusMappingsMu.RLock()
	configs := make([]SpecusConfig, 0, len(client.specusMappings))
	for _, config := range client.specusMappings {
		configs = append(configs, config)
	}
	client.specusMappingsMu.RUnlock()
	for _, config := range configs {
		client.registerSpecus(connection, config)
	}
}

func (client *Client) registerSpecus(connection net.Conn, config SpecusConfig) {
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
			"specusAddress": config.SpecusAddress,
			"specusPort":    config.SpecusPort,
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
		if !client.openNatFlow(message.StreamID) {
			client.resetNatStream(connection, message.StreamID, 7, "duplicate NAT OPEN")
			return nil
		}
		if source, _ := metadataStringOptional(message.Metadata, "source"); source == "http" {
			client.openHTTPStream(connection, message.StreamID, message.Metadata)
		} else if source == "ws" {
			go client.connectWebSocketSpecus(connection, message.StreamID, message.Metadata)
		} else {
			flow := client.natFlow(message.StreamID)
			dialContext, started := flow.beginTCPConnect()
			if !started {
				return fmt.Errorf("failed to start local TCP connection for stream %d", message.StreamID)
			}
			go client.connectLocalSpecus(connection, message.StreamID, message.Metadata, flow, dialContext)
		}
	case protocol.NatFin:
		if handled, accepted := client.finishHTTPRequest(message.StreamID, message.Metadata); handled {
			if !accepted {
				client.resetNatStream(connection, message.StreamID, 8, "duplicate HTTP FIN")
			}
			return nil
		}
		client.handleRemoteFin(connection, message.StreamID)
	case protocol.NatRST:
		if client.resetHTTPStream(message.StreamID, metadataReason(message.Metadata)) {
			client.closeNatFlow(message.StreamID)
			return nil
		}
		removedWebSocket := client.removeWebSocketConnection(message.StreamID)
		removedLocal := client.removeLocalConnection(message.StreamID)
		if !removedWebSocket && !removedLocal && !client.hasNatFlow(message.StreamID) {
			if client.recentlyClosedStreams.contains(message.StreamID) {
				return nil
			}
			return fmt.Errorf("NAT RST for unknown stream %d", message.StreamID)
		}
		client.closeNatFlow(message.StreamID)
	case protocol.NatData:
		if handled, accepted := client.writeHTTPData(message.StreamID, message.Data); handled {
			if !accepted {
				return nil
			}
			if message.Flags&protocol.NatFlagEndStream != 0 {
				endHandled, endAccepted := client.finishHTTPRequest(message.StreamID, message.Metadata)
				if !endHandled {
					return fmt.Errorf("HTTP stream %d closed before END_STREAM", message.StreamID)
				}
				if !endAccepted {
					return fmt.Errorf("duplicate HTTP FIN for stream %d", message.StreamID)
				}
			}
			return nil
		}
		if handled, err := client.writeWebSocketData(message.StreamID, message.Data); handled {
			if err != nil {
				client.logger.Printf("write local websocket stream %d failed: %v", message.StreamID, err)
				client.disconnectWebSocketSpecus(connection, message.StreamID)
			} else {
				client.sendNatWindowUpdate(connection, message.StreamID, len(message.Data))
				if message.Flags&protocol.NatFlagEndStream != 0 {
					client.handleRemoteFin(connection, message.StreamID)
				}
			}
			return nil
		}
		flow := client.natFlow(message.StreamID)
		if flow == nil {
			client.sendNatReset(connection, message.StreamID, 7, "DATA for unknown TCP stream")
			return nil
		}
		endStream := message.Flags&protocol.NatFlagEndStream != 0
		switch flow.stageTCPData(message.Data, endStream) {
		case tcpDataQueued:
			return nil
		case tcpDataAfterFin:
			client.resetNatStream(connection, message.StreamID, 7, "remote TCP DATA after FIN")
			return nil
		case tcpDataOverflow:
			client.abortLocalSpecusFlow(connection, message.StreamID, flow, 8,
				"pending local TCP data exceeds receive window")
			return nil
		case tcpDataClosed:
			client.resetNatStream(connection, message.StreamID, 7, "TCP DATA for closed stream")
			return nil
		}
		if err := client.writeLocalData(message.StreamID, flow, message.Data); err != nil {
			client.logger.Printf("write local specus stream %d failed: %v", message.StreamID, err)
			client.abortLocalSpecusFlow(connection, message.StreamID, flow, 9,
				"write to local TCP stream failed")
		} else {
			client.sendNatWindowUpdate(connection, message.StreamID, len(message.Data))
			if endStream {
				client.handleTCPRemoteFin(connection, message.StreamID, flow)
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
	client.specusMappingsMu.RLock()
	config := client.specusMappings[port]
	client.specusMappingsMu.RUnlock()
	client.logger.Printf("registered NAT port %d -> %s:%d", port, config.SpecusAddress, config.SpecusPort)
}

func (client *Client) connectLocalSpecus(connection net.Conn, streamID uint32, metadata map[string]any,
	flow *natFlowState, dialContext context.Context) {
	port, err := metadataInt(metadata, "port")
	if err != nil {
		client.logger.Printf("invalid NAT connected message: %v", err)
		client.abortLocalSpecusFlow(connection, streamID, flow, 7, "invalid TCP OPEN metadata")
		return
	}
	channelID, err := metadataString(metadata, "channelId")
	if err != nil {
		client.logger.Printf("invalid NAT connected message: %v", err)
		client.abortLocalSpecusFlow(connection, streamID, flow, 7, "invalid TCP OPEN metadata")
		return
	}
	client.specusMappingsMu.RLock()
	config, exists := client.specusMappings[port]
	client.specusMappingsMu.RUnlock()
	if !exists {
		client.logger.Printf("no local specus configured for NAT port %d", port)
		client.abortLocalSpecusFlow(connection, streamID, flow, 1, "local TCP mapping is not configured")
		return
	}
	address := net.JoinHostPort(config.SpecusAddress, strconv.Itoa(config.SpecusPort))
	localConnection, err := client.dialLocalTCP(dialContext, address)
	if err != nil {
		if !client.isNatFlow(streamID, flow) {
			return
		}
		client.logger.Printf("connect local specus %s failed: %v", address, err)
		client.abortLocalSpecusFlow(connection, streamID, flow, 1, "local connect failed")
		return
	}
	if !client.isNatFlow(streamID, flow) {
		_ = localConnection.Close()
		return
	}
	client.localsMu.Lock()
	if previous := client.locals[streamID]; previous != nil {
		_ = previous.Close()
	}
	client.locals[streamID] = localConnection
	client.localsMu.Unlock()

	flow.tcpWriteMu.Lock()
	pendingData, remoteFinished, complete, activated := flow.activateTCPConnection()
	if !activated || !client.isNatFlow(streamID, flow) {
		flow.tcpWriteMu.Unlock()
		client.removeLocalConnectionIfSame(streamID, localConnection)
		return
	}
	for _, data := range pendingData {
		if !client.isNatFlow(streamID, flow) {
			flow.tcpWriteMu.Unlock()
			client.removeLocalConnectionIfSame(streamID, localConnection)
			return
		}
		if err := writeAllLocalData(localConnection, data); err != nil {
			flow.tcpWriteMu.Unlock()
			client.logger.Printf("flush pending local specus stream %d failed: %v", streamID, err)
			client.abortLocalSpecusFlow(connection, streamID, flow, 9,
				"write pending data to local TCP stream failed")
			return
		}
		client.sendNatWindowUpdate(connection, streamID, len(data))
	}
	if remoteFinished {
		tcp, ok := localConnection.(*net.TCPConn)
		if !ok {
			flow.tcpWriteMu.Unlock()
			client.abortLocalSpecusFlow(connection, streamID, flow, 7,
				"local TCP stream does not support half-close")
			return
		}
		if err := tcp.CloseWrite(); err != nil {
			flow.tcpWriteMu.Unlock()
			client.abortLocalSpecusFlow(connection, streamID, flow, 9,
				"failed to apply pending TCP half-close")
			return
		}
	}
	flow.tcpWriteMu.Unlock()
	if complete {
		client.removeLocalConnectionIfSame(streamID, localConnection)
		client.closeNatFlowIfSame(streamID, flow)
		return
	}
	if !client.isNatFlow(streamID, flow) {
		client.removeLocalConnectionIfSame(streamID, localConnection)
		return
	}
	client.logger.Printf("opened local specus channel=%q target=%s", channelID, address)
	go client.copyLocalData(connection, streamID, channelID, localConnection)
}

func (client *Client) dialLocalTCP(ctx context.Context, address string) (net.Conn, error) {
	if client.localTCPDial != nil {
		return client.localTCPDial(ctx, "tcp", address)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, "tcp", address)
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
				client.removeLocalConnection(streamID)
				client.closeNatFlow(streamID)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				client.logger.Printf("read local specus %q failed: %v", channelID, err)
				client.abortLocalSpecus(connection, streamID, 9, "read from local TCP stream failed")
				return
			}
			client.finishLocalDirection(connection, streamID)
			return
		}
	}
}

func (client *Client) writeLocalData(streamID uint32, flow *natFlowState, data []byte) error {
	flow.tcpWriteMu.Lock()
	defer flow.tcpWriteMu.Unlock()
	if !client.isNatFlow(streamID, flow) {
		return fmt.Errorf("local specus stream %d is closed", streamID)
	}
	client.localsMu.Lock()
	connection := client.locals[streamID]
	client.localsMu.Unlock()
	if connection == nil {
		return fmt.Errorf("local specus stream %d is not connected", streamID)
	}
	return writeAllLocalData(connection, data)
}

func writeAllLocalData(connection net.Conn, data []byte) error {
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

func (client *Client) abortLocalSpecus(connection net.Conn, streamID uint32, code uint32, reason string) {
	flow := client.natFlow(streamID)
	if flow != nil {
		client.abortLocalSpecusFlow(connection, streamID, flow, code, reason)
	}
}

func (client *Client) abortLocalSpecusFlow(connection net.Conn, streamID uint32,
	flow *natFlowState, code uint32, reason string) {
	if !client.closeNatFlowIfSame(streamID, flow) {
		return
	}
	client.removeLocalConnection(streamID)
	client.sendNatReset(connection, streamID, code, reason)
}

func (client *Client) sendNatFin(connection net.Conn, streamID uint32) error {
	body, err := protocol.EncodeNatMessage(protocol.NatMessage{
		Type: protocol.NatFin, StreamID: streamID,
	})
	if err == nil {
		err = client.send(connection, protocol.CommandNatMessage, body)
	}
	if err != nil {
		client.logger.Printf("send NAT FIN for stream %d failed: %v", streamID, err)
	}
	return err
}

func (client *Client) sendNatReset(connection net.Conn, streamID uint32, code uint32, reason string) {
	client.closeNatFlow(streamID)
	client.recentlyClosedStreams.add(streamID)
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

func (client *Client) resetNatStream(connection net.Conn, streamID uint32, code uint32, reason string) {
	client.resetHTTPStream(streamID, reason)
	client.removeWebSocketConnection(streamID)
	client.removeLocalConnection(streamID)
	client.closeNatFlow(streamID)
	client.sendNatReset(connection, streamID, code, reason)
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

func (client *Client) openNatFlow(streamID uint32) bool {
	client.natFlowsMu.Lock()
	if client.natFlows[streamID] != nil {
		client.natFlowsMu.Unlock()
		return false
	}
	client.natFlows[streamID] = newNatFlowState()
	client.natFlowsMu.Unlock()
	client.recentlyClosedStreams.remove(streamID)
	return true
}

func (client *Client) takeNatCredit(streamID uint32, size int) bool {
	client.natFlowsMu.Lock()
	flow := client.natFlows[streamID]
	client.natFlowsMu.Unlock()
	return flow != nil && flow.take(size)
}

func (client *Client) takeNatCreditWithin(streamID uint32, size int,
	timeout time.Duration) (taken bool, timedOut bool) {
	client.natFlowsMu.Lock()
	flow := client.natFlows[streamID]
	client.natFlowsMu.Unlock()
	if flow == nil {
		return false, false
	}
	return flow.takeWithin(size, timeout)
}

func (client *Client) addNatCredit(streamID uint32, credit uint32) bool {
	client.natFlowsMu.Lock()
	flow := client.natFlows[streamID]
	client.natFlowsMu.Unlock()
	return flow != nil && flow.add(credit)
}

func (client *Client) hasNatFlow(streamID uint32) bool {
	return client.natFlow(streamID) != nil
}

func (client *Client) canReceiveNatData(streamID uint32) bool {
	flow := client.natFlow(streamID)
	return flow != nil && flow.canReceiveRemoteData()
}

func (client *Client) natFlow(streamID uint32) *natFlowState {
	client.natFlowsMu.Lock()
	flow := client.natFlows[streamID]
	client.natFlowsMu.Unlock()
	return flow
}

func (client *Client) isNatFlow(streamID uint32, expected *natFlowState) bool {
	return expected != nil && client.natFlow(streamID) == expected
}

func (client *Client) closeNatFlowIfSame(streamID uint32, expected *natFlowState) bool {
	client.natFlowsMu.Lock()
	if client.natFlows[streamID] != expected || expected == nil {
		client.natFlowsMu.Unlock()
		return false
	}
	delete(client.natFlows, streamID)
	client.natFlowsMu.Unlock()
	client.recentlyClosedStreams.add(streamID)
	expected.close()
	return true
}

func (client *Client) closeNatFlow(streamID uint32) {
	client.natFlowsMu.Lock()
	flow := client.natFlows[streamID]
	delete(client.natFlows, streamID)
	client.natFlowsMu.Unlock()
	if flow != nil {
		client.recentlyClosedStreams.add(streamID)
		flow.close()
	}
}

func (client *Client) finishLocalDirection(connection net.Conn, streamID uint32) {
	complete, accepted := client.markNatLocalFinished(streamID)
	if !accepted {
		return
	}
	if err := client.sendNatFin(connection, streamID); err != nil {
		client.removeLocalConnection(streamID)
		client.closeNatFlow(streamID)
		return
	}
	client.localsMu.Lock()
	local := client.locals[streamID]
	client.localsMu.Unlock()
	if tcp, ok := local.(*net.TCPConn); ok {
		_ = tcp.CloseRead()
	}
	if complete {
		client.removeLocalConnection(streamID)
		client.closeNatFlow(streamID)
	}
}

func (client *Client) markNatLocalFinished(streamID uint32) (complete bool, accepted bool) {
	client.natFlowsMu.Lock()
	flow := client.natFlows[streamID]
	client.natFlowsMu.Unlock()
	if flow == nil {
		return false, false
	}
	flow.mu.Lock()
	defer flow.mu.Unlock()
	if flow.closed || flow.localFinished {
		return false, false
	}
	flow.localFinished = true
	return flow.remoteFinished, true
}

func (client *Client) handleRemoteFin(connection net.Conn, streamID uint32) {
	if client.removeWebSocketConnection(streamID) {
		client.closeNatFlow(streamID)
		return
	}
	flow := client.natFlow(streamID)
	if flow == nil {
		client.sendNatReset(connection, streamID, 7, "FIN for unknown TCP stream")
		return
	}
	client.handleTCPRemoteFin(connection, streamID, flow)
}

func (client *Client) handleTCPRemoteFin(connection net.Conn, streamID uint32, flow *natFlowState) {
	complete, accepted, connecting := flow.receiveRemoteFin()
	if !accepted {
		client.resetNatStream(connection, streamID, 7, "duplicate remote TCP FIN")
		return
	}
	if connecting {
		return
	}
	flow.tcpWriteMu.Lock()
	defer flow.tcpWriteMu.Unlock()
	if !client.isNatFlow(streamID, flow) {
		return
	}
	client.localsMu.Lock()
	local := client.locals[streamID]
	client.localsMu.Unlock()
	if local == nil {
		return
	}
	if tcp, ok := local.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil {
			client.resetNatStream(connection, streamID, 9, "failed to half-close local TCP output")
			return
		}
	} else {
		client.resetNatStream(connection, streamID, 7, "local TCP channel does not support half-close")
		return
	}
	if complete {
		client.removeLocalConnectionIfSame(streamID, local)
		client.closeNatFlowIfSame(streamID, flow)
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
	client.logger.Printf("closed local specus stream=%d", streamID)
	return true
}

func (client *Client) removeLocalConnectionIfSame(streamID uint32, expected net.Conn) bool {
	client.localsMu.Lock()
	connection := client.locals[streamID]
	if connection == expected && expected != nil {
		delete(client.locals, streamID)
	} else {
		connection = nil
	}
	client.localsMu.Unlock()
	if connection == nil {
		return false
	}
	_ = connection.Close()
	client.logger.Printf("closed local specus stream=%d", streamID)
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
	client.recentlyClosedStreams.clear()
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
