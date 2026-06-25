// Package server wires the transport, auth, persistence, and (later) NAT/HTTP/management
// layers together. The Dispatcher implements control.Handler and is the equivalent of the
// C# ControlChannelDispatcher.
package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/auth"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/control"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/protocol"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/session"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/store"
)

// Dispatcher routes inbound control-channel packets: auth gate, login (offloaded), heartbeat,
// logout, NAT (G3), and Direct HTTP responses (G4).
type Dispatcher struct {
	db       *store.DB
	auth     *auth.Authenticator
	sessions *session.Registry
	executor *control.LoginExecutor
	logger   *slog.Logger

	// Optional hooks wired in later phases (nil-safe).
	natHandler        func(conn *control.Conn, message protocol.NatMessage) error
	directHTTPAck     func(response protocol.DirectHTTPResponse)
	peerControl       func(conn *control.Conn, request protocol.MessageRequest) error
	onLoginSuccess    func(conn *control.Conn)
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

// SetOnDisconnect installs a connection-teardown hook, e.g. to release NAT state (G3).
func (d *Dispatcher) SetOnDisconnect(hook func(conn *control.Conn)) { d.onDisconnect = hook }

// SetDirectHTTPAck installs the Direct HTTP response handler (G4).
func (d *Dispatcher) SetDirectHTTPAck(ack func(response protocol.DirectHTTPResponse)) {
	d.directHTTPAck = ack
}

// SetPeerControlHandler installs the Peer Mesh control-plane signal handler.
func (d *Dispatcher) SetPeerControlHandler(handler func(conn *control.Conn, request protocol.MessageRequest) error) {
	d.peerControl = handler
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
	if _, isLogin := packet.(protocol.LoginRequest); !isLogin && conn.ClientName() == "" {
		conn.MarkReason(store.ReasonProtocolViolation)
		d.logger.Warn("packet on unauthenticated channel", "channel", conn.ChannelID(), "cmd", packet.Command())
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
	case protocol.DirectHTTPResponse:
		if d.directHTTPAck != nil {
			d.directHTTPAck(p)
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
		d.logger.Debug("dropped unhandled message request",
			"channel", conn.ChannelID(), "client", conn.ClientName(), "messageType", p.MessageType)
		return nil
	default:
		d.logger.Debug("dropped unhandled packet", "channel", conn.ChannelID(), "cmd", packet.Command())
		return nil
	}
}

// OnDisconnect unbinds the session and stamps the audit row.
func (d *Dispatcher) OnDisconnect(conn *control.Conn) {
	if d.onDisconnect != nil {
		d.onDisconnect(conn)
	}
	if name := conn.ClientName(); name != "" {
		d.sessions.Unbind(name, conn)
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
	ctx := conn.Context()
	result, err := d.auth.Authenticate(ctx, request)
	if err != nil {
		d.logger.Error("authentication failed", "channel", conn.ChannelID(), "client", request.ClientName, "err", err)
		conn.Close(store.ReasonIOError)
		return
	}

	clientName := request.ClientName
	if result.Account != nil {
		clientName = result.Account.ClientName
	}
	record := store.ConnectionRecord{
		TenantID:    "default",
		ClientName:  clientName,
		ConnectedAt: time.Now(),
		Success:     result.Success,
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

	recordID, err := d.db.InsertConnectionRecord(ctx, record)
	if err != nil {
		d.logger.Error("write connection record failed", "channel", conn.ChannelID(), "err", err)
		conn.Close(store.ReasonIOError)
		return
	}
	if d.onConnectionEvent != nil {
		record.ID = recordID
		d.onConnectionEvent("created", record)
	}

	if result.Success {
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
	if err := conn.Send(response); err != nil {
		conn.Close(store.ReasonIOError)
		return
	}

	if !result.Success {
		conn.MarkReason(store.ReasonLoginFailure)
		conn.Close(store.ReasonLoginFailure)
		return
	}

	conn.SetConnectionRecordID(recordID)
	conn.OnLoginSuccess(clientName, result.Account.TenantID, result.Session.ID, time.Now().UnixMilli())

	if displaced := d.sessions.Replace(conn); displaced != nil {
		displaced.Close(store.ReasonReplacedByNewLogin)
	}

	d.logger.Info("client logged in", "channel", conn.ChannelID(), "client", request.ClientName)
	if d.onLoginSuccess != nil {
		d.onLoginSuccess(conn)
	}
}
