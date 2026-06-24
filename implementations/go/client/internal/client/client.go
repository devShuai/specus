package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-client-go/internal/protocol"
)

const reconnectDelay = 5 * time.Second

type Client struct {
	config Config
	logger *log.Logger

	routesMu sync.RWMutex
	routes   map[string]string

	writeMu sync.Mutex

	tunnelsMu sync.RWMutex
	tunnels   map[int]TunnelConfig
	runtimeMu sync.RWMutex
	runtime   RuntimeConfig

	registeredMu sync.Mutex
	registered   map[int]struct{}

	httpRoutesReportedMu sync.Mutex
	httpRoutesReported   bool

	localsMu sync.Mutex
	locals   map[string]net.Conn
}

type natControlConfig struct {
	TunnelConfigList     []TunnelConfig      `json:"tunnelConfigList"`
	HTTPTunnelConfigList *[]HTTPTunnelConfig `json:"httpTunnelConfigList"`
}

func New(config Config, logger *log.Logger) *Client {
	if logger == nil {
		logger = log.Default()
	}
	return &Client{
		config:     config,
		logger:     logger,
		routes:     make(map[string]string),
		tunnels:    make(map[int]TunnelConfig),
		registered: make(map[int]struct{}),
		locals:     make(map[string]net.Conn),
	}
}

func (client *Client) Run(ctx context.Context) error {
	for {
		if err := client.runOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			client.logger.Printf("control connection closed: %v", err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		client.logger.Printf("reconnecting in %s", reconnectDelay)
		timer := time.NewTimer(reconnectDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (client *Client) runOnce(ctx context.Context) error {
	runtime, err := client.login(ctx)
	if err != nil {
		return err
	}
	client.applyRuntime(runtime)
	address := net.JoinHostPort(runtime.NettyHost, strconv.Itoa(runtime.NettyPort))
	connection, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect %s: %w", address, err)
	}
	client.logger.Printf("connected to tunnel server %s", address)
	client.resetConnectionState()
	defer func() {
		_ = connection.Close()
		client.closeLocalConnections()
	}()

	connectionContext, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-connectionContext.Done()
		_ = connection.Close()
	}()
	go client.heartbeatLoop(connectionContext, connection)

	body, err := protocol.EncodeLoginRequest(runtime.ClientName, runtime.ClientSessionID, runtime.AccessToken)
	if err != nil {
		return err
	}
	if err := client.send(connection, protocol.CommandLoginRequest, body); err != nil {
		return fmt.Errorf("send login request: %w", err)
	}

	for {
		packet, err := protocol.ReadPacket(connection)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if err := client.handlePacket(connection, packet); err != nil {
			return err
		}
	}
}

func (client *Client) applyRuntime(runtime RuntimeConfig) {
	client.runtimeMu.Lock()
	client.runtime = runtime
	client.runtimeMu.Unlock()
	client.syncHTTPTunnelConfigs(runtime.HTTPTunnelConfigList)
	client.tunnelsMu.Lock()
	client.tunnels = make(map[int]TunnelConfig, len(runtime.TunnelConfigList))
	for _, tunnel := range runtime.TunnelConfigList {
		client.tunnels[tunnel.Port] = tunnel
	}
	client.tunnelsMu.Unlock()
}

func (client *Client) currentClientName() string {
	client.runtimeMu.RLock()
	defer client.runtimeMu.RUnlock()
	return client.runtime.ClientName
}

func (client *Client) heartbeatLoop(ctx context.Context, connection net.Conn) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := client.send(connection, protocol.CommandHeartbeatRequest, protocol.EncodeHeartbeat()); err != nil {
				client.logger.Printf("send heartbeat failed: %v", err)
				_ = connection.Close()
				return
			}
		}
	}
}

func (client *Client) handlePacket(connection net.Conn, packet protocol.Packet) error {
	switch packet.Command {
	case protocol.CommandLoginResponse:
		response, err := protocol.DecodeLoginResponse(packet.Body)
		if err != nil {
			return fmt.Errorf("decode login response: %w", err)
		}
		if !response.Success {
			return fmt.Errorf("login failed: %s", response.Reason)
		}
		client.logger.Printf("login succeeded as %q", response.ClientName)
		client.registerConfiguredTunnels(connection)
		client.reportHTTPRoutes(connection)
	case protocol.CommandHeartbeatRequest:
		return client.send(connection, protocol.CommandHeartbeatResponse, protocol.EncodeHeartbeat())
	case protocol.CommandHeartbeatResponse:
		return nil
	case protocol.CommandMessageResponse:
		return client.handleMessageResponse(connection, packet.Body)
	case protocol.CommandNatMessage:
		return client.handleNatMessage(connection, packet.Body)
	case protocol.CommandDirectHTTPRequest:
		go client.forwardDirectHTTP(connection, packet.Body)
	case protocol.CommandLegacyHTTPRequest:
		go client.forwardLegacyHTTP(connection, packet.Body)
	default:
		client.logger.Printf("ignored unsupported command %d", packet.Command)
	}
	return nil
}

func (client *Client) handleMessageResponse(connection net.Conn, body []byte) error {
	response, err := protocol.DecodeMessageResponse(body)
	if err != nil {
		return fmt.Errorf("decode message response: %w", err)
	}
	if response.MessageType != protocol.MessageTypeNatControl {
		client.logger.Printf("received message type=%d from=%q: %s", response.MessageType, response.ClientName, response.Message)
		return nil
	}
	var config natControlConfig
	if err := json.Unmarshal([]byte(response.Message), &config); err != nil {
		return fmt.Errorf("decode NAT control config: %w", err)
	}
	client.syncTunnelConfigs(connection, config.TunnelConfigList)
	if config.HTTPTunnelConfigList != nil {
		client.syncHTTPTunnelConfigs(*config.HTTPTunnelConfigList)
	}
	return nil
}

func (client *Client) send(connection net.Conn, command int8, body []byte) error {
	client.writeMu.Lock()
	defer client.writeMu.Unlock()
	return protocol.WritePacket(connection, command, body)
}

func (client *Client) resetConnectionState() {
	client.registeredMu.Lock()
	defer client.registeredMu.Unlock()
	client.registered = make(map[int]struct{})
	client.httpRoutesReportedMu.Lock()
	client.httpRoutesReported = false
	client.httpRoutesReportedMu.Unlock()
}
