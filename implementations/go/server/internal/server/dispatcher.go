// Package server wires the transport, auth, persistence, and (later) NAT/HTTP/management
// layers together. The Dispatcher implements control.Handler and is the equivalent of the
// C# ControlChannelDispatcher.
package server

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/control"
	"github.com/devShuai/specus/implementations/go/server/internal/peermesh"
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
	onDataBinding     func(conn *control.Conn) func()
	onDisconnect      func(conn *control.Conn)
	onControlGone     func(conn *control.Conn)
	onControlBinding  func(conn *control.Conn, account store.ClientAccount)
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

// SetOnDataLoginSuccess installs the dedicated data-plane attachment hook. It runs after the
// data connection authenticates but before the registry lists it and before the success
// response is written, with conn's write lock held, so it must not write to conn.
func (d *Dispatcher) SetOnDataLoginSuccess(hook func(conn *control.Conn)) { d.onDataLogin = hook }

// SetOnDataBinding publishes the mandatory namespace before login success. Its returned
// retirement cleanup runs after the reply and outside the write/lifecycle locks.
func (d *Dispatcher) SetOnDataBinding(hook func(conn *control.Conn) func()) { d.onDataBinding = hook }

// SetOnDisconnect installs a connection-teardown hook, e.g. to release NAT state (G3).
func (d *Dispatcher) SetOnDisconnect(hook func(conn *control.Conn)) { d.onDisconnect = hook }

// SetOnControlGone installs a hook fired once an authenticated control connection has been
// unbound: the point from which everyone else sees that client as offline. The teardown hook
// above runs for the data connection and before any unbinding, so it cannot say that.
func (d *Dispatcher) SetOnControlGone(hook func(conn *control.Conn)) { d.onControlGone = hook }

// SetOnControlBinding runs before a new control binding is published, under its lifecycle
// lease but outside CommitAndSend's socket write lock. It must not write to the new socket.
func (d *Dispatcher) SetOnControlBinding(hook func(conn *control.Conn, account store.ClientAccount)) {
	d.onControlBinding = hook
}

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
		leaseCtx, cancel := context.WithTimeout(conn.Context(), 5*time.Second)
		release, err := d.sessions.AcquireControlLease(leaseCtx, conn.ClientName())
		cancel()
		if err != nil {
			return err
		}
		defer release()
		current := d.sessions.IsBound(conn)
		if conn.ConnectionRole() == protocol.ConnectionRoleData {
			data, found := d.sessions.FindData(conn.ClientName())
			current = found && data == conn
		}
		if !current {
			return errUnauthenticated
		}
		d.sessions.Unbind(conn.ClientName(), conn)
		return conn.Send(protocol.LogoutResponse{Success: true})
	case protocol.NatMessage:
		controlSession, controlBound := d.sessions.CurrentDataControl(conn)
		owner, concrete := controlSession.(*control.Conn)
		current := controlBound && concrete && conn.Context().Err() == nil &&
			owner.ClientSessionID() == conn.ClientSessionID() && owner.Context().Err() == nil
		// Do not wait on a control lifecycle lease for stream credit or data. The coordinator's
		// registered namespace and terminal retirement protect this admitted reference.
		if !current {
			return errUnauthenticated
		}
		if d.natHandler != nil {
			return d.natHandler(conn, p)
		}
		return nil
	case protocol.MessageRequest:
		if conn.Context().Err() != nil || !d.sessions.IsBound(conn) {
			return errUnauthenticated
		}
		peerControl := p.MessageType == protocol.MessageTypePeerControl
		names := []string{conn.ClientName()}
		var targetName string
		var originalTarget session.Session
		if requested := strings.TrimSpace(p.ToClientName); peerControl && peermesh.SignalTargetsPeer(p.Message) && requested != "" {
			// Resolve the canonical SQL name BEFORE taking any lifecycle stripe. Native
			// collations can match aliases with a different case. Protect the actual name,
			// and fence the later lookup rather than acquiring an unprotected extra stripe.
			targetName = requested
			target, err := d.db.FindClientByName(conn.Context(), requested)
			if err == nil && target != nil {
				targetName = target.ClientName
			}
			// A failed/absent prelookup must not skip server-bound reports, close effects
			// or protocol validation. Protect the literal name in that case; the mesh's
			// exact canonical-name fence rejects any later differently-cased SQL alias.
			p.ToClientName = targetName
			names = append(names, targetName)
			originalTarget, _ = d.sessions.Find(targetName)
		}
		leaseCtx, cancel := context.WithTimeout(conn.Context(), 5*time.Second)
		release, err := d.sessions.AcquireControlLeases(leaseCtx, names...)
		cancel()
		if err != nil {
			if peerControl {
				d.logger.Debug("dropped Peer signal waiting for lifecycle leases", "client", conn.ClientName(), "err", err)
				return nil
			}
			return err
		}
		defer release()
		if !d.sessions.IsBound(conn) {
			return errUnauthenticated
		}
		if peerControl {
			if targetName != "" {
				currentTarget, _ := d.sessions.Find(targetName)
				if currentTarget != originalTarget {
					d.logger.Debug("dropped Peer signal for superseded target control", "client", conn.ClientName(), "to", targetName)
					return nil
				}
			}
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
		switch packet.(type) {
		case protocol.MessageRequest, protocol.HeartbeatRequest,
			protocol.HeartbeatResponse, protocol.LogoutRequest:
			return true
		default:
			return false
		}
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
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		release, err := d.sessions.AcquireControlLease(ctx, name)
		if err != nil {
			d.logger.Error("acquire disconnect lifecycle lease failed", "channel", conn.ChannelID(), "err", err)
		} else {
			d.sessions.Unbind(name, conn)
			if !dataConnection {
				d.retireControl(ctx, conn)
			}
			release()
		}
		cancel()
	}
	if dataConnection {
		return
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
		record, err := d.db.GetConnectionRecord(ctx, recordID)
		if err != nil {
			d.logger.Error("read disconnected connection record failed", "channel", conn.ChannelID(), "err", err)
			return
		}
		if record != nil {
			d.onConnectionEvent("updated", *record)
		}
	}
}

func (d *Dispatcher) retireControl(ctx context.Context, conn *control.Conn) {
	if current, ok := d.sessions.Find(conn.ClientName()); ok {
		if successor, concrete := current.(*control.Conn); concrete && successor != conn && successor.ClientSessionID() == conn.ClientSessionID() {
			return // The local auth/data/catalog key now belongs to this physical successor.
		}
	}
	_, err := d.db.MarkClientSessionDisconnectedForChannel(ctx, conn.ClientSessionID(), conn.ChannelID(), auth.StatusDisconnected, time.Now())
	if err != nil {
		d.logger.Error("mark current client session disconnected failed", "channel", conn.ChannelID(), "err", err)
	}
	// Native status may already be retired by HTTP re-authentication/admin actions. The
	// departed local generation still owns its old cache key unless a same-ID successor
	// is bound above. Never let that suppress withdrawal or leak an online quota slot.
	d.auth.MarkDisconnected(conn.ClientSessionID())
	if data, ok := d.sessions.FindData(conn.ClientName()); ok {
		if dataConn, concrete := data.(*control.Conn); concrete && dataConn.ClientSessionID() == conn.ClientSessionID() {
			d.sessions.Unbind(conn.ClientName(), data)
			data.Close(store.ReasonClientClosed)
		}
	}
	if d.onControlGone != nil {
		d.onControlGone(conn)
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
	resumeLogin := loginReadResume(conn)
	defer resumeLogin()
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
	if result.Success {
		leaseCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		release, leaseErr := d.sessions.AcquireControlLease(leaseCtx, clientName)
		cancel()
		if leaseErr != nil {
			conn.Close(store.ReasonServerBusy)
			return
		}
		defer release()
		d.finishLogin(conn, request, result, clientName, dataConnection, release, resumeLogin)
		return
	}
	d.finishLogin(conn, request, result, clientName, dataConnection, func() {}, resumeLogin)
}

// Called only by the same login worker. A later NAT backpressure pause must not be
// overwritten when deferred old-browser cleanup finally lets that worker return.
func loginReadResume(conn *control.Conn) func() {
	resumed := false
	return func() {
		if !resumed {
			resumed = true
			conn.ReadGate.Resume()
		}
	}
}

func (d *Dispatcher) finishLogin(conn *control.Conn, request protocol.LoginRequest, result auth.Result, clientName string, dataConnection bool, release, resumeLogin func()) {
	var dataRetirement func()
	defer func() {
		release()
		if dataRetirement != nil {
			// The new authenticated namespace is already published and its reply sent.
			// Resume its reader before any slow old-browser close handshake.
			resumeLogin()
			dataRetirement()
		}
	}()
	ctx := conn.Context()
	var err error
	if result.Success && dataConnection {
		bound, ok := d.sessions.Find(clientName)
		controlConn, concrete := bound.(*control.Conn)
		if !ok || !concrete || controlConn.ClientSessionID() != result.Session.ID || controlConn.Context().Err() != nil {
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
	var publish func()
	if result.Success {
		if !dataConnection {
			// Detach the old companion before a same-token replacement can attach its own.
			if data, found := d.sessions.FindData(clientName); found {
				d.sessions.Unbind(clientName, data)
				data.Close(store.ReasonReplacedByNewLogin)
			}
		}
		// Commit authenticated connection state before publishing the success response.
		// Once the client observes success it may immediately send heartbeat/NAT frames, and a
		// public request may at once open a stream on a new data connection.
		if recordID > 0 {
			conn.SetConnectionRecordID(recordID)
		}
		if !conn.BindRuntimeReference(store.RuntimeClientReference{SessionID: result.Session.ID, CredentialID: result.Session.CredentialID, IdentityID: result.Session.IdentityID, ClientID: result.Account.ID, TenantID: result.Account.TenantID, ClientName: clientName, TokenHash: result.Session.TokenHash, MachineFingerprint: result.Session.MachineFingerprint, OSUser: result.Session.OSUser, ExpiresAt: result.Session.ExpiresAt}) {
			conn.Close(store.ReasonProtocolViolation)
			return
		}
		conn.OnLoginSuccess(clientName, result.Account.TenantID, result.Session.ID,
			time.Now().UnixMilli(), request.ConnectionRole)
		conn.SetHTTPRouteCapability(result.Session.HTTPRouteCapability)
		if !dataConnection && d.onControlBinding != nil {
			d.onControlBinding(conn, *result.Account)
		}
		publish = func() {
			if !dataConnection {
				displaced = d.sessions.Replace(conn)
				return
			}
			// Attach the stream namespace before the registry lists the data connection, so a
			// request that finds the client online can open a stream on it.
			if d.onDataBinding != nil {
				dataRetirement = d.onDataBinding(conn)
			}
			if d.onDataLogin != nil {
				d.onDataLogin(conn)
			}
			displaced = d.sessions.ReplaceData(conn)
		}
	}
	// The client reads the login response before any other frame, so whatever the published
	// state lets other goroutines send on conn must queue behind it.
	if err := conn.CommitAndSend(publish, response); err != nil {
		if displaced != nil {
			displaced.Close(store.ReasonReplacedByNewLogin)
		}
		conn.Close(store.ReasonIOError)
		return
	}
	release()

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
