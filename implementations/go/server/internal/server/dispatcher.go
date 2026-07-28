// Package server wires the transport, auth, persistence, and (later) NAT/HTTP/management
// layers together. The Dispatcher implements control.Handler and is the equivalent of the
// C# ControlChannelDispatcher.
package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/control"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// Dispatcher routes inbound control-channel packets: auth gate, login (offloaded), heartbeat,
// logout, NAT stream v2, and application control messages.
type Dispatcher struct {
	db       *store.DB
	auth     *auth.Authenticator
	sessions *session.Registry
	executor *control.LoginExecutor
	logger   *slog.Logger

	// Optional hooks wired in later phases (nil-safe).
	natHandler        func(conn *control.Conn, message protocol.NatMessage) error
	peerControl       func(conn *control.Conn, request protocol.MessageRequest) error
	clientMessage     func(conn *control.Conn, request protocol.MessageRequest) error
	onLoginSuccess    func(conn *control.Conn)
	onDataLogin       func(conn *control.Conn)
	onDisconnect      func(conn *control.Conn)
	onConnectionEvent func(eventType string, record store.ConnectionRecord)
}

// NewDispatcher builds the control-channel dispatcher.
func NewDispatcher(db *store.DB, authenticator *auth.Authenticator, sessions *session.Registry,
	executor *control.LoginExecutor, logger *slog.Logger) *Dispatcher {
	return &Dispatcher{db: db, auth: authenticator, sessions: sessions, executor: executor, logger: logger}
}

// SetNatHandler installs the NAT message handler (G3).
func (d *Dispatcher) SetNatHandler(handler func(conn *control.Conn, message protocol.NatMessage) error) {
	d.natHandler = handler
}

// SetOnLoginSuccess installs a post-login hook, e.g. to push NAT_CONTROL (G3).
func (d *Dispatcher) SetOnLoginSuccess(hook func(conn *control.Conn)) { d.onLoginSuccess = hook }

// SetOnDataLoginSuccess installs the dedicated data-plane attachment hook.
func (d *Dispatcher) SetOnDataLoginSuccess(hook func(conn *control.Conn)) { d.onDataLogin = hook }

// SetOnDisconnect installs a connection-teardown hook, e.g. to release NAT state (G3).
func (d *Dispatcher) SetOnDisconnect(hook func(conn *control.Conn)) { d.onDisconnect = hook }

// SetPeerControlHandler installs the Peer Mesh control-plane signal handler.
func (d *Dispatcher) SetPeerControlHandler(handler func(conn *control.Conn, request protocol.MessageRequest) error) {
	d.peerControl = handler
}

// SetClientMessageHandler installs CLIENT_TO_CLIENT/CLIENT_TO_SERVER routing.
func (d *Dispatcher) SetClientMessageHandler(handler func(conn *control.Conn, request protocol.MessageRequest) error) {
	d.clientMessage = handler
}

// SetOnConnectionEvent installs a hook fired when a connection record is created/updated (G4).
func (d *Dispatcher) SetOnConnectionEvent(hook func(eventType string, record store.ConnectionRecord)) {
	d.onConnectionEvent = hook
}

// OnConnect logs a new connection.
func (d *Dispatcher) OnConnect(conn *control.Conn) {
	d.logger.Debug("control connection opened", "channel", conn.ChannelID(), "remote", conn.RemoteAddress())
}

// OnPacket dispatches a single decoded packet.
func (d *Dispatcher) OnPacket(conn *control.Conn, packet protocol.Packet) error {
	_, isLogin := packet.(protocol.LoginRequest)
	if isLogin && conn.ClientName() != "" {
		conn.MarkReason(store.ReasonProtocolViolation)
		d.logger.Warn("duplicate login on authenticated channel", "channel", conn.ChannelID())
		return errUnauthenticated
	}
	if !isLogin && conn.ClientName() == "" {
		conn.MarkReason(store.ReasonProtocolViolation)
		d.logger.Warn("packet on unauthenticated channel", "channel", conn.ChannelID(), "cmd", packet.Command())
		return errUnauthenticated
	}
	if conn.ClientName() != "" && !packetAllowedForRole(conn.ConnectionRole(), packet) {
		conn.MarkReason(store.ReasonProtocolViolation)
		return errUnauthenticated
	}

	switch p := packet.(type) {
	case protocol.LoginRequest:
		d.handleLogin(conn, p)
		return nil
	case protocol.HeartbeatRequest:
		return conn.Send(protocol.HeartbeatResponse{})
	case protocol.HeartbeatResponse:
		return nil
	case protocol.LogoutRequest:
		if name := conn.ClientName(); name != "" {
			d.sessions.Unbind(name, conn)
		}
		return conn.Send(protocol.LogoutResponse{Success: true})
	case protocol.NatMessage:
		if d.natHandler != nil {
			return d.natHandler(conn, p)
		}
		return nil
	case protocol.MessageRequest:
		if p.MessageType == protocol.MessageTypePeerControl {
			if d.peerControl == nil {
				d.logger.Info("dropped PEER_CONTROL: peer mesh handler is not configured",
					"channel", conn.ChannelID(), "client", conn.ClientName(), "bytes", len(p.Message))
				return nil
			}
			return d.peerControl(conn, p)
		}
		if d.clientMessage != nil {
			return d.clientMessage(conn, p)
		}
		d.logger.Debug("dropped unhandled message request",
			"channel", conn.ChannelID(), "client", conn.ClientName(), "messageType", p.MessageType)
		return nil
	default:
		d.logger.Debug("dropped unhandled packet", "channel", conn.ChannelID(), "cmd", packet.Command())
		return nil
	}
}

func packetAllowedForRole(role string, packet protocol.Packet) bool {
	if role == protocol.ConnectionRoleControl {
		_, isNat := packet.(protocol.NatMessage)
		return !isNat
	}
	if role != protocol.ConnectionRoleData {
		return false
	}
	switch packet.(type) {
	case protocol.NatMessage, protocol.HeartbeatRequest, protocol.HeartbeatResponse, protocol.LogoutRequest:
		return true
	default:
		return false
	}
}

// OnDisconnect unbinds the session and stamps the audit row.
func (d *Dispatcher) OnDisconnect(conn *control.Conn) {
	if conn.ClientName() == "" {
		d.logger.Debug("unauthenticated control connection closed",
			"channel", conn.ChannelID(), "reason", conn.Reason())
	} else {
		d.logger.Info("client connection closed", "channel", conn.ChannelID(),
			"client", conn.ClientName(), "role", conn.ConnectionRole(),
			"session", conn.ClientSessionID(), "reason", conn.Reason())
	}
	dataConnection := conn.ConnectionRole() == protocol.ConnectionRoleData
	if dataConnection && d.onDisconnect != nil {
		d.onDisconnect(conn)
	}
	if name := conn.ClientName(); name != "" {
		d.sessions.Unbind(name, conn)
	}
	if dataConnection {
		return
	}
	if data, ok := d.sessions.FindData(conn.ClientName()); ok {
		if dataConn, concrete := data.(*control.Conn); concrete &&
			dataConn.ClientSessionID() == conn.ClientSessionID() {
			data.Close(store.ReasonClientClosed)
		}
	}
	d.auth.MarkDisconnected(conn.ClientSessionID())
	if sessionID := conn.ClientSessionID(); sessionID > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := d.db.MarkClientSessionDisconnected(ctx, sessionID, auth.StatusDisconnected, time.Now()); err != nil {
			d.logger.Error("mark client session disconnected failed", "session", sessionID, "err", err)
		}
		cancel()
	}
	recordID := conn.ConnectionRecordID()
	if recordID == 0 {
		return
	}
	reason := conn.Reason()
	if reason == "" {
		reason = store.ReasonClientClosed
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.db.MarkDisconnect(ctx, recordID, reason, time.Now()); err != nil {
		d.logger.Error("record disconnect failed", "channel", conn.ChannelID(), "err", err)
		return
	}
	if d.onConnectionEvent != nil {
		now := time.Now()
		channelID := conn.ChannelID()
		reasonCopy := reason
		d.onConnectionEvent("updated", store.ConnectionRecord{
			ID: recordID, TenantID: conn.TenantID(), ClientName: conn.ClientName(), ChannelID: &channelID,
			ConnectedAt: now, DisconnectedAt: &now, Success: true, DisconnectReason: &reasonCopy,
		})
	}
}

func (d *Dispatcher) handleLogin(conn *control.Conn, request protocol.LoginRequest) {
	conn.ReadGate.Pause()
	enqueued := d.executor.TryEnqueue(func() { d.processLogin(conn, request) })
	if enqueued {
		return
	}
	d.logger.Warn("login executor full", "channel", conn.ChannelID(), "client", request.ClientName)
	conn.MarkReason(store.ReasonServerBusy)
	reason := "服务器繁忙，请稍后重试"
	_ = conn.Send(protocol.LoginResponse{ClientName: request.ClientName, Success: false, Reason: &reason})
	conn.Close(store.ReasonServerBusy)
}

func (d *Dispatcher) processLogin(conn *control.Conn, request protocol.LoginRequest) {
	defer conn.ReadGate.Resume()
	ctx := conn.Context()
	if request.ConnectionRole != protocol.ConnectionRoleControl && request.ConnectionRole != protocol.ConnectionRoleData {
		reason := "登录包缺少有效 connectionRole"
		_ = conn.Send(protocol.LoginResponse{ClientName: request.ClientName, Success: false, Reason: &reason})
		conn.Close(store.ReasonLoginFailure)
		return
	}
	dataConnection := request.ConnectionRole == protocol.ConnectionRoleData
	var result auth.Result
	var err error
	if dataConnection {
		result, err = d.auth.AuthenticateData(ctx, request)
	} else {
		result, err = d.auth.Authenticate(ctx, request)
	}
	if err != nil {
		d.logger.Error("authentication failed", "channel", conn.ChannelID(), "client", request.ClientName, "err", err)
		conn.Close(store.ReasonIOError)
		return
	}

	clientName := request.ClientName
	if result.Account != nil {
		clientName = result.Account.ClientName
	}
	if result.Success && dataConnection {
		bound, ok := d.sessions.Find(clientName)
		controlConn, concrete := bound.(*control.Conn)
		if !ok || !concrete || controlConn.ClientSessionID() != result.Session.ID {
			result.Success = false
			result.Reason = "数据连接未找到匹配的控制连接"
		}
	}

	var recordID int64
	var record store.ConnectionRecord
	if !dataConnection {
		record = store.ConnectionRecord{
			TenantID: "default", ClientName: clientName,
			ConnectedAt: time.Now(), Success: result.Success,
		}
		channelID := conn.ChannelID()
		record.ChannelID = &channelID
		if remote := conn.RemoteAddress(); remote != "" {
			record.RemoteAddress = &remote
		}
		if result.Account != nil {
			record.TenantID = result.Account.TenantID
			record.ClientID = &result.Account.ID
		}
		if !result.Success {
			now := time.Now()
			record.DisconnectedAt = &now
			reason := store.ReasonLoginFailure
			record.DisconnectReason = &reason
			if result.Reason != "" {
				failure := result.Reason
				record.FailureReason = &failure
			}
		}
		recordID, err = d.db.InsertConnectionRecord(ctx, record)
		if err != nil {
			d.logger.Error("write connection record failed", "channel", conn.ChannelID(), "err", err)
			conn.Close(store.ReasonIOError)
			return
		}
		if d.onConnectionEvent != nil {
			record.ID = recordID
			d.onConnectionEvent("created", record)
		}
	}

	if result.Success && !dataConnection {
		now := time.Now()
		if err := d.db.MarkClientSessionOnline(ctx, result.Session.ID, auth.StatusNettyOnline,
			conn.ChannelID(), conn.RemoteAddress(), now); err != nil {
			d.logger.Error("mark client session online failed", "channel", conn.ChannelID(),
				"client", clientName, "err", err)
			result.Success = false
			result.Reason = "保存客户端会话状态失败"
			record.DisconnectedAt = &now
			reason := store.ReasonIOError
			record.DisconnectReason = &reason
			conn.MarkReason(store.ReasonIOError)
		} else {
			d.auth.MarkOnline(result.Session.ID)
		}
	}

	response := protocol.LoginResponse{ClientName: clientName, Success: result.Success}
	if result.Reason != "" {
		reason := result.Reason
		response.Reason = &reason
	}
	var displaced session.Session
	if result.Success {
		// Commit authenticated connection state before publishing the success response.
		// Once the client observes success it may immediately send heartbeat/NAT frames.
		if recordID > 0 {
			conn.SetConnectionRecordID(recordID)
		}
		conn.OnLoginSuccess(clientName, result.Account.TenantID, result.Session.ID,
			time.Now().UnixMilli(), request.ConnectionRole)
		if dataConnection {
			displaced = d.sessions.ReplaceData(conn)
		} else {
			displaced = d.sessions.Replace(conn)
		}
	}
	if err := conn.Send(response); err != nil {
		conn.Close(store.ReasonIOError)
		return
	}

	if !result.Success {
		conn.MarkReason(store.ReasonLoginFailure)
		conn.Close(store.ReasonLoginFailure)
		return
	}

	if dataConnection {
		if displaced != nil {
			displaced.Close(store.ReasonReplacedByNewLogin)
		}
		d.logger.Info("client data connection logged in", "channel", conn.ChannelID(), "client", clientName)
		if d.onDataLogin != nil {
			d.onDataLogin(conn)
		}
		return
	}
	if displaced != nil {
		displaced.Close(store.ReasonReplacedByNewLogin)
	}

	d.logger.Info("client logged in", "channel", conn.ChannelID(), "client", request.ClientName)
	if d.onLoginSuccess != nil {
		d.onLoginSuccess(conn)
	}
}
