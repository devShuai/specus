package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-client-go/internal/protocol"
)

const (
	reconnectBaseDelay         = 2 * time.Second
	reconnectMaxDelay          = 60 * time.Second
	tokenRefreshMaxLead        = 5 * time.Minute
	tokenRefreshMinLead        = 30 * time.Second
	tokenRefreshMinDelay       = 5 * time.Second
	tokenRefreshRetryDelay     = 60 * time.Second
	tokenRefreshRequestTimeout = 25 * time.Second
	controlReadIdleTimeout     = 60 * time.Second
	controlWriteIdleHeartbeat  = 5 * time.Second
	controlIdleTickInterval    = time.Second
)

type Client struct {
	config Config
	logger *log.Logger

	routesMu sync.RWMutex
	routes   map[string]string

	writeMu           sync.Mutex
	lastWriteUnixNano atomic.Int64

	reconnectMu                 sync.Mutex
	reconnectAttempts           int
	resetBackoffOnNextHTTPLogin bool

	tunnelsMu sync.RWMutex
	tunnels   map[int]TunnelConfig
	runtimeMu sync.RWMutex
	runtime   RuntimeConfig

	registeredMu sync.Mutex
	registered   map[int]struct{}

	httpRoutesReportedMu sync.Mutex
	httpRoutesReported   bool

	localsMu   sync.Mutex
	locals     map[string]net.Conn
	wsLocalsMu sync.Mutex
	wsLocals   map[string]*webSocketLocalConnection

	peerMesh *peerMeshClient
}

type natControlConfig struct {
	TunnelConfigList     []TunnelConfig      `json:"tunnelConfigList"`
	HTTPTunnelConfigList *[]HTTPTunnelConfig `json:"httpTunnelConfigList"`
}

type controlLoginAction int

const (
	controlLoginBackoff controlLoginAction = iota
	controlLoginRefreshImmediately
	controlLoginStop
)

type controlLoginRejectedError struct {
	reason string
	action controlLoginAction
}

func newControlLoginRejectedError(reason string) *controlLoginRejectedError {
	return &controlLoginRejectedError{
		reason: reason,
		action: classifyControlLoginFailure(reason),
	}
}

func (err *controlLoginRejectedError) Error() string {
	return "control login failed: " + err.reasonOrDefault()
}

func (err *controlLoginRejectedError) reasonOrDefault() string {
	if strings.TrimSpace(err.reason) == "" {
		return "login rejected"
	}
	return err.reason
}

func classifyControlLoginFailure(reason string) controlLoginAction {
	if strings.Contains(reason, "访问令牌已过期") {
		return controlLoginRefreshImmediately
	}
	if strings.Contains(reason, "服务器繁忙") || strings.Contains(reason, "连接频率超过限制") {
		return controlLoginBackoff
	}
	return controlLoginStop
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
		wsLocals:   make(map[string]*webSocketLocalConnection),
		peerMesh:   newPeerMeshClient(config, logger),
	}
}

func (client *Client) Run(ctx context.Context) error {
	for {
		err := client.runOnce(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return ctx.Err()
			}
			var loginRejected *controlLoginRejectedError
			if errors.As(err, &loginRejected) {
				switch loginRejected.action {
				case controlLoginRefreshImmediately:
					client.logger.Printf("control login failed: %s; refreshing credentials and reconnecting immediately", loginRejected.reasonOrDefault())
					if ctx.Err() != nil {
						return ctx.Err()
					}
					client.resetReconnectBackoffAfterNextHTTPLogin()
					continue
				case controlLoginStop:
					client.logger.Printf("control login rejected: %s; stopping reconnect", loginRejected.reasonOrDefault())
					return err
				case controlLoginBackoff:
					client.logger.Printf("control login failed: %s; reconnecting with backoff", loginRejected.reasonOrDefault())
				}
			} else {
				client.logger.Printf("control connection closed: %v", err)
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		attempt, delay := client.nextReconnectDelay()
		client.logger.Printf("reconnect attempt %d in %s", attempt, delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (client *Client) nextReconnectDelay() (int, time.Duration) {
	client.reconnectMu.Lock()
	defer client.reconnectMu.Unlock()
	client.reconnectAttempts++
	return client.reconnectAttempts, reconnectDelayForAttempt(client.reconnectAttempts)
}

func (client *Client) resetReconnectBackoff() int {
	client.reconnectMu.Lock()
	defer client.reconnectMu.Unlock()
	previous := client.reconnectAttempts
	client.reconnectAttempts = 0
	return previous
}

func (client *Client) resetReconnectBackoffAfterNextHTTPLogin() {
	client.reconnectMu.Lock()
	defer client.reconnectMu.Unlock()
	client.resetBackoffOnNextHTTPLogin = true
}

func (client *Client) consumeHTTPLoginBackoffReset() int {
	client.reconnectMu.Lock()
	defer client.reconnectMu.Unlock()
	if !client.resetBackoffOnNextHTTPLogin {
		return -1
	}
	client.resetBackoffOnNextHTTPLogin = false
	previous := client.reconnectAttempts
	client.reconnectAttempts = 0
	return previous
}

func reconnectDelayForAttempt(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > 5 {
		shift = 5
	}
	delay := reconnectBaseDelay * time.Duration(1<<shift)
	if delay > reconnectMaxDelay {
		return reconnectMaxDelay
	}
	return delay
}

func (client *Client) runOnce(ctx context.Context) error {
	runtime, err := client.login(ctx)
	if err != nil {
		return err
	}
	if previous := client.consumeHTTPLoginBackoffReset(); previous > 0 {
		client.logger.Printf("client access token refreshed, reconnect backoff reset (was attempt %d)", previous)
	}
	client.applyRuntime(runtime)
	address := net.JoinHostPort(runtime.NettyHost, strconv.Itoa(runtime.NettyPort))
	connection, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect %s: %w", address, err)
	}
	client.logger.Printf("connected to tunnel server %s", address)
	client.resetConnectionState()
	client.markControlWrite()
	defer func() {
		client.peerMesh.stop()
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
	go client.tokenRefreshLoop(connectionContext, connection)

	body, err := protocol.EncodeLoginRequest(runtime.ClientName, runtime.ClientSessionID, runtime.AccessToken)
	if err != nil {
		return err
	}
	if err := client.send(connection, protocol.CommandLoginRequest, body); err != nil {
		return fmt.Errorf("send login request: %w", err)
	}

	for {
		if err := connection.SetReadDeadline(time.Now().Add(controlReadIdleTimeout)); err != nil {
			client.logger.Printf("set control read deadline failed: %v", err)
		}
		packet, err := protocol.ReadPacket(connection)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var netError net.Error
			if errors.As(err, &netError) && netError.Timeout() {
				return fmt.Errorf("60秒内未读到数据, 关闭连接: %w", err)
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

func (client *Client) applyRefreshedRuntime(connection net.Conn, runtime RuntimeConfig) {
	client.runtimeMu.Lock()
	client.runtime = runtime
	client.runtimeMu.Unlock()
	client.syncTunnelConfigs(connection, runtime.TunnelConfigList)
	client.syncHTTPTunnelConfigs(runtime.HTTPTunnelConfigList)
	client.httpRoutesReportedMu.Lock()
	client.httpRoutesReported = false
	client.httpRoutesReportedMu.Unlock()
	client.reportHTTPRoutes(connection)
	client.peerMesh.start(connection, runtime, client.sendPeerControl)
}

func (client *Client) currentClientName() string {
	client.runtimeMu.RLock()
	defer client.runtimeMu.RUnlock()
	return client.runtime.ClientName
}

func (client *Client) heartbeatLoop(ctx context.Context, connection net.Conn) {
	ticker := time.NewTicker(controlIdleTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lastWrite := client.lastWriteUnixNano.Load()
			if lastWrite > 0 && time.Since(time.Unix(0, lastWrite)) < controlWriteIdleHeartbeat {
				continue
			}
			if err := client.send(connection, protocol.CommandHeartbeatRequest, protocol.EncodeHeartbeat()); err != nil {
				client.logger.Printf("send heartbeat failed: %v", err)
				_ = connection.Close()
				return
			}
		}
	}
}

func (client *Client) tokenRefreshLoop(ctx context.Context, connection net.Conn) {
	for {
		runtime := client.currentRuntime()
		if runtime.TokenExpiresAt.IsZero() {
			return
		}
		delay := tokenRefreshDelay(time.Now(), runtime.TokenExpiresAt)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		refreshCtx, cancel := context.WithTimeout(ctx, tokenRefreshRequestTimeout)
		refreshed, err := client.login(refreshCtx)
		cancel()
		if err != nil {
			client.logger.Printf("client access token refresh failed: %v; retrying in %s", err, tokenRefreshRetryDelay)
			timer = time.NewTimer(tokenRefreshRetryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		client.applyRefreshedRuntime(connection, refreshed)
		client.logger.Printf("client access token refreshed: client=%s session=%d", refreshed.ClientName, refreshed.ClientSessionID)
	}
}

func tokenRefreshDelay(now, expiresAt time.Time) time.Duration {
	remaining := time.Until(expiresAt)
	if !now.IsZero() {
		remaining = expiresAt.Sub(now)
	}
	if remaining <= 0 {
		return tokenRefreshMinDelay
	}
	lead := tokenRefreshLead(remaining)
	delay := remaining - lead
	if delay < tokenRefreshMinDelay {
		return tokenRefreshMinDelay
	}
	return delay
}

func tokenRefreshLead(remaining time.Duration) time.Duration {
	if remaining <= 2*tokenRefreshMinLead {
		half := remaining / 2
		if half < tokenRefreshMinDelay {
			return tokenRefreshMinDelay
		}
		return half
	}
	tenth := remaining / 10
	if tenth < tokenRefreshMinLead {
		return tokenRefreshMinLead
	}
	if tenth > tokenRefreshMaxLead {
		return tokenRefreshMaxLead
	}
	return tenth
}

func (client *Client) handlePacket(connection net.Conn, packet protocol.Packet) error {
	switch packet.Command {
	case protocol.CommandLoginResponse:
		response, err := protocol.DecodeLoginResponse(packet.Body)
		if err != nil {
			return fmt.Errorf("decode login response: %w", err)
		}
		if !response.Success {
			return newControlLoginRejectedError(response.Reason)
		}
		client.logger.Printf("login succeeded as %q", response.ClientName)
		if previous := client.resetReconnectBackoff(); previous > 0 {
			client.logger.Printf("login succeeded, reconnect backoff reset (was attempt %d)", previous)
		}
		client.registerConfiguredTunnels(connection)
		client.reportHTTPRoutes(connection)
		client.peerMesh.start(connection, client.currentRuntime(), client.sendPeerControl)
	case protocol.CommandHeartbeatRequest:
		return client.send(connection, protocol.CommandHeartbeatResponse, protocol.EncodeHeartbeat())
	case protocol.CommandHeartbeatResponse:
		return nil
	case protocol.CommandLogoutRequest:
		client.logger.Printf("received server logout request; closing control connection")
		_ = connection.Close()
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
		if response.MessageType == protocol.MessageTypePeerControl {
			return client.handlePeerControl(connection, response.Message)
		}
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

func (client *Client) handlePeerControl(connection net.Conn, payload string) error {
	client.peerMesh.handleControl(connection, payload, client.currentRuntime(), client.sendPeerControl)
	return nil
}

func (client *Client) sendPeerControl(connection net.Conn, toClientName string, message any) error {
	runtime := client.currentRuntime()
	body, err := json.Marshal(message)
	if err != nil {
		return err
	}
	packet := protocol.EncodeMessageRequest(
		runtime.ClientName,
		toClientName,
		protocol.MessageTypePeerControl,
		string(body),
	)
	return client.send(connection, protocol.CommandMessageRequest, packet)
}

func (client *Client) currentRuntime() RuntimeConfig {
	client.runtimeMu.RLock()
	defer client.runtimeMu.RUnlock()
	return client.runtime
}

func (client *Client) send(connection net.Conn, command int8, body []byte) error {
	client.writeMu.Lock()
	defer client.writeMu.Unlock()
	if err := protocol.WritePacket(connection, command, body); err != nil {
		return err
	}
	client.markControlWrite()
	return nil
}

func (client *Client) markControlWrite() {
	client.lastWriteUnixNano.Store(time.Now().UnixNano())
}

func (client *Client) resetConnectionState() {
	client.registeredMu.Lock()
	defer client.registeredMu.Unlock()
	client.registered = make(map[int]struct{})
	client.httpRoutesReportedMu.Lock()
	client.httpRoutesReported = false
	client.httpRoutesReportedMu.Unlock()
}
