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

	"github.com/devShuai/specus/implementations/go/client/internal/protocol"
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
	priorityWriteQueueCapacity = 256
)

type priorityPacket struct {
	command int8
	body    []byte
}

type priorityWriter struct {
	connection net.Conn
	ctx        context.Context
	cancel     context.CancelFunc
	queue      chan priorityPacket
}

type Client struct {
	config Config
	logger *log.Logger

	routesMu sync.RWMutex
	routes   map[string]string

	controlWriteMu        sync.Mutex
	dataWriteMu           sync.Mutex
	priorityMu            sync.RWMutex
	priorityWriter        *priorityWriter
	lastWriteUnixNano     atomic.Int64
	dataLastWriteUnixNano atomic.Int64
	controlMu             sync.RWMutex
	controlConn           net.Conn
	dataConn              net.Conn
	messageHandler        func(ClientMessage)

	reconnectMu                 sync.Mutex
	reconnectAttempts           int
	resetBackoffOnNextHTTPLogin bool

	specusMappingsMu sync.RWMutex
	specusMappings   map[int]SpecusConfig
	runtimeMu        sync.RWMutex
	runtime          RuntimeConfig

	registeredMu sync.Mutex
	registered   map[int]struct{}

	localsMu              sync.Mutex
	locals                map[uint32]net.Conn
	localTCPDial          func(context.Context, string, string) (net.Conn, error)
	wsLocalsMu            sync.Mutex
	wsLocals              map[uint32]*webSocketLocalConnection
	httpMu                sync.Mutex
	httpStreams           map[uint32]*httpRequestStream
	natFlowsMu            sync.Mutex
	natFlows              map[uint32]*natFlowState
	recentlyClosedStreams recentStreamTombstones

	peerMesh *peerMeshClient
}

// ClientMessage is an application message delivered through either the encrypted
// Peer Mesh app-message channel or the CLIENT_TO_CLIENT control-channel fallback.
type ClientMessage struct {
	FromClientName string
	ToClientName   string
	Message        string
}

type natControlConfig struct {
	SpecusConfigList     []SpecusConfig      `json:"specusConfigList"`
	HTTPSpecusConfigList *[]HTTPSpecusConfig `json:"httpSpecusConfigList"`
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
		config:                config,
		logger:                logger,
		routes:                make(map[string]string),
		specusMappings:        make(map[int]SpecusConfig),
		registered:            make(map[int]struct{}),
		locals:                make(map[uint32]net.Conn),
		wsLocals:              make(map[uint32]*webSocketLocalConnection),
		httpStreams:           make(map[uint32]*httpRequestStream),
		natFlows:              make(map[uint32]*natFlowState),
		recentlyClosedStreams: newRecentStreamTombstones(recentStreamTombstoneLimit),
		peerMesh:              newPeerMeshClient(config, logger),
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
	controlConnection, err := client.dialServerConnection(
		ctx, address, serverConnectionTimeout, runtime.NettyTLS)
	if err != nil {
		return fmt.Errorf("connect %s: %w", address, err)
	}
	client.logger.Printf("control connection established to %s", address)
	client.controlMu.Lock()
	client.controlConn = controlConnection
	client.controlMu.Unlock()
	client.resetConnectionState()
	client.markControlWrite()
	connectionContext, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		client.controlMu.Lock()
		if client.controlConn == controlConnection {
			client.controlConn = nil
		}
		dataConnection := client.dataConn
		client.dataConn = nil
		client.controlMu.Unlock()
		client.peerMesh.stop()
		_ = controlConnection.Close()
		if dataConnection != nil {
			_ = dataConnection.Close()
		}
		client.closeLocalConnections()
	}()
	go func() {
		<-connectionContext.Done()
		_ = controlConnection.Close()
	}()
	go client.heartbeatLoop(connectionContext, controlConnection)
	if err := client.loginConnection(controlConnection, runtime, protocol.ConnectionRoleControl); err != nil {
		return err
	}

	dataConnection, err := client.dialServerConnection(
		ctx, address, serverConnectionTimeout, runtime.NettyTLS)
	if err != nil {
		return fmt.Errorf("connect dedicated data channel %s: %w", address, err)
	}
	client.controlMu.Lock()
	client.dataConn = dataConnection
	client.controlMu.Unlock()
	client.dataLastWriteUnixNano.Store(time.Now().UnixNano())
	client.logger.Printf("data connection established to %s", address)
	go func() {
		<-connectionContext.Done()
		_ = dataConnection.Close()
	}()
	go client.heartbeatLoop(connectionContext, dataConnection)
	if err := client.loginConnection(dataConnection, runtime, protocol.ConnectionRoleData); err != nil {
		return err
	}
	stopPriorityWriter := client.startPriorityWriter(connectionContext, dataConnection)
	defer stopPriorityWriter()
	go client.tokenRefreshLoop(connectionContext, controlConnection)

	errorsOut := make(chan error, 2)
	go func() {
		errorsOut <- client.readAuthenticatedLoop(connectionContext, controlConnection, protocol.ConnectionRoleControl)
	}()
	go func() {
		errorsOut <- client.readAuthenticatedLoop(connectionContext, dataConnection, protocol.ConnectionRoleData)
	}()
	err = <-errorsOut
	cancel()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (client *Client) loginConnection(connection net.Conn, runtime RuntimeConfig, role string) error {
	body, err := protocol.EncodeLoginRequest(
		runtime.ClientName, runtime.ClientSessionID, runtime.AccessToken, role)
	if err != nil {
		return err
	}
	if err := client.send(connection, protocol.CommandLoginRequest, body); err != nil {
		return fmt.Errorf("send %s login request: %w", role, err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(controlReadIdleTimeout)); err != nil {
		client.logger.Printf("set %s read deadline failed: %v", role, err)
	}
	packet, err := protocol.ReadPacketLimit(connection, protocol.PreAuthMaxFrameSize())
	if err != nil {
		return err
	}
	if packet.Command != protocol.CommandLoginResponse {
		return fmt.Errorf("expected %s login response, received command %d", role, packet.Command)
	}
	return client.handleLoginResponse(connection, packet, role)
}

func (client *Client) readAuthenticatedLoop(ctx context.Context, connection net.Conn, role string) error {
	for {
		if err := connection.SetReadDeadline(time.Now().Add(controlReadIdleTimeout)); err != nil {
			client.logger.Printf("set %s read deadline failed: %v", role, err)
		}
		packet, err := protocol.ReadPacket(connection)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var netError net.Error
			if errors.As(err, &netError) && netError.Timeout() {
				return fmt.Errorf("%s connection read idle timeout: %w", role, err)
			}
			return err
		}
		if err := client.handlePacket(connection, packet, role); err != nil {
			return err
		}
	}
}

func (client *Client) applyRuntime(runtime RuntimeConfig) {
	client.runtimeMu.Lock()
	client.runtime = runtime
	client.runtimeMu.Unlock()
	client.syncHTTPSpecusConfigs(runtime.HTTPSpecusConfigList)
	client.specusMappingsMu.Lock()
	client.specusMappings = make(map[int]SpecusConfig, len(runtime.SpecusConfigList))
	for _, specus := range runtime.SpecusConfigList {
		client.specusMappings[specus.Port] = specus
	}
	client.specusMappingsMu.Unlock()
}

func (client *Client) applyRefreshedRuntime(connection net.Conn, runtime RuntimeConfig) {
	client.runtimeMu.Lock()
	client.runtime = runtime
	client.runtimeMu.Unlock()
	client.controlMu.RLock()
	dataConnection := client.dataConn
	client.controlMu.RUnlock()
	if dataConnection != nil {
		client.syncSpecusConfigs(dataConnection, runtime.SpecusConfigList)
	}
	client.syncHTTPSpecusConfigs(runtime.HTTPSpecusConfigList)
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
			lastWrite := client.lastWriteFor(connection).Load()
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

func (client *Client) handlePacket(connection net.Conn, packet protocol.Packet, role string) error {
	switch packet.Command {
	case protocol.CommandLoginResponse:
		return errors.New("duplicate LOGIN_RESPONSE on authenticated connection")
	case protocol.CommandHeartbeatRequest:
		return client.send(connection, protocol.CommandHeartbeatResponse, protocol.EncodeHeartbeat())
	case protocol.CommandHeartbeatResponse:
		return nil
	case protocol.CommandLogoutRequest:
		client.logger.Printf("received server logout request; closing control connection")
		_ = connection.Close()
		return nil
	case protocol.CommandMessageResponse:
		if role != protocol.ConnectionRoleControl {
			return errors.New("message packet received on data connection")
		}
		return client.handleMessageResponse(connection, packet.Body)
	case protocol.CommandNatMessage:
		if role != protocol.ConnectionRoleData {
			return errors.New("NAT packet received on control connection")
		}
		return client.handleNatMessage(connection, packet.Body)
	default:
		client.logger.Printf("ignored unsupported command %d", packet.Command)
	}
	return nil
}

func (client *Client) handleLoginResponse(connection net.Conn, packet protocol.Packet, role string) error {
	response, err := protocol.DecodeLoginResponse(packet.Body)
	if err != nil {
		return fmt.Errorf("decode login response: %w", err)
	}
	if !response.Success {
		return newControlLoginRejectedError(response.Reason)
	}
	client.logger.Printf("login succeeded as %q", response.ClientName)
	if role == protocol.ConnectionRoleControl {
		if previous := client.resetReconnectBackoff(); previous > 0 {
			client.logger.Printf("login succeeded, reconnect backoff reset (was attempt %d)", previous)
		}
		client.peerMesh.start(connection, client.currentRuntime(), client.sendPeerControl)
	} else {
		client.registerConfiguredSpecusMappings(connection)
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
		if response.MessageType == protocol.MessageTypeClientToClient {
			client.controlMu.RLock()
			handler := client.messageHandler
			client.controlMu.RUnlock()
			if handler != nil {
				handler(ClientMessage{FromClientName: response.ClientName, ToClientName: response.ToClientName, Message: response.Message})
			}
		}
		return nil
	}
	var config natControlConfig
	if err := json.Unmarshal([]byte(response.Message), &config); err != nil {
		return fmt.Errorf("decode NAT control config: %w", err)
	}
	client.controlMu.RLock()
	dataConnection := client.dataConn
	client.controlMu.RUnlock()
	if dataConnection != nil {
		client.syncSpecusConfigs(dataConnection, config.SpecusConfigList)
	}
	if config.HTTPSpecusConfigList != nil {
		client.syncHTTPSpecusConfigs(*config.HTTPSpecusConfigList)
	}
	return nil
}

// SetMessageHandler installs a callback for received CLIENT_TO_CLIENT messages.
func (client *Client) SetMessageHandler(handler func(ClientMessage)) {
	client.controlMu.Lock()
	client.messageHandler = handler
	client.controlMu.Unlock()
	client.peerMesh.setMessageHandler(handler)
}

// SendMessage delivers an application message through the control-channel fallback.
func (client *Client) SendMessage(toClientName, message string) error {
	toClientName = strings.TrimSpace(toClientName)
	message = strings.TrimSpace(message)
	if toClientName == "" || message == "" {
		return errors.New("target and message are required")
	}
	client.controlMu.RLock()
	connection := client.controlConn
	client.controlMu.RUnlock()
	if connection == nil {
		return errors.New("control connection is not online")
	}
	runtime := client.currentRuntime()
	packet := protocol.EncodeMessageRequest(runtime.ClientName, toClientName,
		protocol.MessageTypeClientToClient, message)
	return client.send(connection, protocol.CommandMessageRequest, packet)
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
	writeMu := client.writeLockFor(connection)
	writeMu.Lock()
	defer writeMu.Unlock()
	if err := protocol.WritePacket(connection, command, body); err != nil {
		return err
	}
	client.lastWriteFor(connection).Store(time.Now().UnixNano())
	return nil
}

func (client *Client) writeLockFor(connection net.Conn) *sync.Mutex {
	client.controlMu.RLock()
	data := client.dataConn
	client.controlMu.RUnlock()
	if data != nil && connection == data {
		return &client.dataWriteMu
	}
	return &client.controlWriteMu
}

func (client *Client) startPriorityWriter(ctx context.Context, connection net.Conn) func() {
	writerCtx, cancel := context.WithCancel(ctx)
	writer := &priorityWriter{
		connection: connection, ctx: writerCtx, cancel: cancel,
		queue: make(chan priorityPacket, priorityWriteQueueCapacity),
	}
	client.priorityMu.Lock()
	client.priorityWriter = writer
	client.priorityMu.Unlock()
	go func() {
		for {
			select {
			case packet := <-writer.queue:
				if err := client.send(connection, packet.command, packet.body); err != nil {
					client.logger.Printf("priority control write failed: %v", err)
					_ = connection.Close()
					return
				}
			case <-writerCtx.Done():
				return
			}
		}
	}()
	return func() {
		cancel()
		client.priorityMu.Lock()
		if client.priorityWriter == writer {
			client.priorityWriter = nil
		}
		client.priorityMu.Unlock()
	}
}

func (client *Client) sendPriority(connection net.Conn, command int8, body []byte) error {
	client.priorityMu.RLock()
	writer := client.priorityWriter
	client.priorityMu.RUnlock()
	if writer == nil || writer.connection != connection {
		return errors.New("priority control writer is not active")
	}
	packet := priorityPacket{command: command, body: append([]byte(nil), body...)}
	select {
	case writer.queue <- packet:
		return nil
	case <-writer.ctx.Done():
		return writer.ctx.Err()
	}
}

func (client *Client) markControlWrite() {
	client.lastWriteUnixNano.Store(time.Now().UnixNano())
}

func (client *Client) lastWriteFor(connection net.Conn) *atomic.Int64 {
	client.controlMu.RLock()
	data := client.dataConn
	client.controlMu.RUnlock()
	if data != nil && connection == data {
		return &client.dataLastWriteUnixNano
	}
	return &client.lastWriteUnixNano
}

func (client *Client) resetConnectionState() {
	client.registeredMu.Lock()
	defer client.registeredMu.Unlock()
	client.registered = make(map[int]struct{})
}
