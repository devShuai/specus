package client

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-client-go/internal/protocol"
)

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
			"clientName":    client.config.ClientName,
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
	case protocol.NatConnected:
		go client.connectLocalTunnel(connection, message.Metadata)
	case protocol.NatDisconnected:
		channelID, err := metadataString(message.Metadata, "channelId")
		if err != nil {
			return err
		}
		client.removeLocalConnection(channelID)
	case protocol.NatData:
		channelID, err := metadataString(message.Metadata, "channelId")
		if err != nil {
			return err
		}
		if err := client.writeLocalData(channelID, message.Data); err != nil {
			client.logger.Printf("write local tunnel %q failed: %v", channelID, err)
			client.disconnectLocalTunnel(connection, channelID)
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
		reason, _ := metadataString(metadata, "reason")
		client.logger.Printf("register NAT port %d failed: %s", port, reason)
		return
	}
	client.tunnelsMu.RLock()
	config := client.tunnels[port]
	client.tunnelsMu.RUnlock()
	client.logger.Printf("registered NAT port %d -> %s:%d", port, config.TunnelAddress, config.TunnelPort)
}

func (client *Client) connectLocalTunnel(connection net.Conn, metadata map[string]any) {
	channelID, err := metadataString(metadata, "channelId")
	if err != nil {
		client.logger.Printf("invalid NAT connected message: %v", err)
		return
	}
	port, err := metadataInt(metadata, "port")
	if err != nil {
		client.logger.Printf("invalid NAT connected message: %v", err)
		client.sendNatDisconnected(connection, channelID)
		return
	}
	client.tunnelsMu.RLock()
	config, exists := client.tunnels[port]
	client.tunnelsMu.RUnlock()
	if !exists {
		client.logger.Printf("no local tunnel configured for NAT port %d", port)
		client.sendNatDisconnected(connection, channelID)
		return
	}
	address := net.JoinHostPort(config.TunnelAddress, strconv.Itoa(config.TunnelPort))
	localConnection, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		client.logger.Printf("connect local tunnel %s failed: %v", address, err)
		client.sendNatDisconnected(connection, channelID)
		return
	}
	client.localsMu.Lock()
	if previous := client.locals[channelID]; previous != nil {
		_ = previous.Close()
	}
	client.locals[channelID] = localConnection
	client.localsMu.Unlock()
	client.logger.Printf("opened local tunnel channel=%q target=%s", channelID, address)
	go client.copyLocalData(connection, channelID, localConnection)
}

func (client *Client) copyLocalData(connection net.Conn, channelID string, localConnection net.Conn) {
	buffer := make([]byte, 32*1024)
	for {
		length, err := localConnection.Read(buffer)
		if length > 0 {
			body, encodeErr := protocol.EncodeNatMessage(protocol.NatMessage{
				Type:     protocol.NatData,
				Metadata: map[string]any{"channelId": channelID},
				Data:     append([]byte(nil), buffer[:length]...),
			})
			if encodeErr != nil || client.send(connection, protocol.CommandNatMessage, body) != nil {
				client.disconnectLocalTunnel(connection, channelID)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				client.logger.Printf("read local tunnel %q failed: %v", channelID, err)
			}
			client.disconnectLocalTunnel(connection, channelID)
			return
		}
	}
}

func (client *Client) writeLocalData(channelID string, data []byte) error {
	client.localsMu.Lock()
	connection := client.locals[channelID]
	client.localsMu.Unlock()
	if connection == nil {
		return fmt.Errorf("local tunnel %q is not connected", channelID)
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

func (client *Client) disconnectLocalTunnel(connection net.Conn, channelID string) {
	if client.removeLocalConnection(channelID) {
		client.sendNatDisconnected(connection, channelID)
	}
}

func (client *Client) sendNatDisconnected(connection net.Conn, channelID string) {
	body, err := protocol.EncodeNatMessage(protocol.NatMessage{
		Type:     protocol.NatDisconnected,
		Metadata: map[string]any{"channelId": channelID},
	})
	if err == nil {
		err = client.send(connection, protocol.CommandNatMessage, body)
	}
	if err != nil {
		client.logger.Printf("send NAT disconnected for %q failed: %v", channelID, err)
	}
}

func (client *Client) removeLocalConnection(channelID string) bool {
	client.localsMu.Lock()
	connection := client.locals[channelID]
	delete(client.locals, channelID)
	client.localsMu.Unlock()
	if connection == nil {
		return false
	}
	_ = connection.Close()
	client.logger.Printf("closed local tunnel channel=%q", channelID)
	return true
}

func (client *Client) closeLocalConnections() {
	client.localsMu.Lock()
	connections := client.locals
	client.locals = make(map[string]net.Conn)
	client.localsMu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func metadataString(metadata map[string]any, name string) (string, error) {
	value, exists := metadata[name]
	if !exists {
		return "", fmt.Errorf("NAT metadata is missing %q", name)
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("NAT metadata %q is not a string", name)
	}
	return text, nil
}

func metadataInt(metadata map[string]any, name string) (int, error) {
	value, exists := metadata[name]
	if !exists {
		return 0, fmt.Errorf("NAT metadata is missing %q", name)
	}
	switch number := value.(type) {
	case float64:
		return int(number), nil
	case int:
		return number, nil
	default:
		return 0, fmt.Errorf("NAT metadata %q is not a number", name)
	}
}
