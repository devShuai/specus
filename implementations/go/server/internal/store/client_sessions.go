package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// InsertClientSession persists an HTTP-authenticated client runtime session.
func (db *DB) InsertClientSession(ctx context.Context, session ClientSession) error {
	query := db.rebind(`INSERT INTO tunnel_client_session
		(id, tenant_id, credential_id, identity_id, client_id, client_name, token_hash, status,
		 machine_fingerprint, os_user, hostname, os_name, os_version, os_arch, client_version,
		 java_version, local_addresses, message_send_capable, message_receive_capable,
		 message_attachments_capable, message_media_preview_capable, message_max_attachment_bytes,
		 http_login_at, netty_connected_at, disconnected_at,
		 expires_at, channel_id, remote_address)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query,
		session.ID, defaultTenant(session.TenantID), session.CredentialID, session.IdentityID,
		session.ClientID, session.ClientName, session.TokenHash, session.Status,
		session.MachineFingerprint, session.OSUser, session.Hostname, session.OSName,
		session.OSVersion, session.OSArch, session.ClientVersion, session.JavaVersion,
		session.LocalAddresses, db.clientMessageCapabilityValue(session.MessageSendCapable),
		db.clientMessageCapabilityValue(session.MessageReceiveCapable),
		db.clientMessageCapabilityValue(session.MessageAttachmentsCapable),
		db.clientMessageCapabilityValue(session.MessageMediaPreviewCapable), session.MessageMaxAttachmentBytes,
		formatTime(session.HTTPLoginAt), nullableTime(session.NettyConnectedAt),
		nullableTime(session.DisconnectedAt), formatTime(session.ExpiresAt), session.ChannelID,
		session.RemoteAddress)
	return err
}

// GetClientSession returns a runtime client session by id, or ErrNotFound.
func (db *DB) GetClientSession(ctx context.Context, id int64) (*ClientSession, error) {
	query := db.rebind(`SELECT id, tenant_id, credential_id, identity_id, client_id, client_name,
		token_hash, status, machine_fingerprint, os_user, hostname, os_name, os_version, os_arch,
		client_version, java_version, local_addresses, message_send_capable, message_receive_capable,
		message_attachments_capable, message_media_preview_capable, message_max_attachment_bytes,
		http_login_at, netty_connected_at,
		disconnected_at, expires_at, channel_id, remote_address
		FROM tunnel_client_session WHERE id = ?`)
	session, err := scanClientSession(db.sql.QueryRowContext(ctx, query, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// GetOnlineClientSession returns the newest NETTY_ONLINE session for a client.
func (db *DB) GetOnlineClientSession(ctx context.Context, tenantID string, clientID int64, status string) (*ClientSession, error) {
	query := db.rebind(`SELECT id, tenant_id, credential_id, identity_id, client_id, client_name,
		token_hash, status, machine_fingerprint, os_user, hostname, os_name, os_version, os_arch,
		client_version, java_version, local_addresses, message_send_capable, message_receive_capable,
		message_attachments_capable, message_media_preview_capable, message_max_attachment_bytes,
		http_login_at, netty_connected_at, disconnected_at, expires_at, channel_id, remote_address
		FROM tunnel_client_session
		WHERE tenant_id = ? AND client_id = ? AND status = ?
		ORDER BY netty_connected_at DESC, id DESC LIMIT 1`)
	session, err := scanClientSession(db.sql.QueryRowContext(ctx, query, defaultTenant(tenantID), clientID, status))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// ClientHasOnlineMessageReceiveCapability matches Java's anyMatch across all online sessions.
func (db *DB) ClientHasOnlineMessageReceiveCapability(ctx context.Context, tenantID string, clientID int64, status string) (bool, error) {
	query := db.rebind(`SELECT COUNT(*) FROM tunnel_client_session
		WHERE tenant_id = ? AND client_id = ? AND status = ? AND ` + db.clientMessageReceivePredicate())
	var count int64
	if err := db.sql.QueryRowContext(ctx, query, defaultTenant(tenantID), clientID, status).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (db *DB) clientMessageCapabilityValue(value bool) any {
	if db.dialect == DialectPostgres {
		return value
	}
	return boolToInt(value)
}

func (db *DB) clientMessageReceivePredicate() string {
	if db.dialect == DialectPostgres {
		return "message_receive_capable"
	}
	return "message_receive_capable <> 0"
}

// MarkClientSessionOnline records the successful control-channel authentication.
func (db *DB) MarkClientSessionOnline(ctx context.Context, id int64, status, channelID, remoteAddress string, when time.Time) error {
	if id <= 0 {
		return nil
	}
	query := db.rebind(`UPDATE tunnel_client_session
		SET status = ?, netty_connected_at = ?, disconnected_at = NULL, channel_id = ?, remote_address = ?
		WHERE id = ?`)
	_, err := db.sql.ExecContext(ctx, query, status, formatTime(when), nullableSessionText(channelID),
		nullableSessionText(remoteAddress), id)
	return err
}

// MarkClientSessionDisconnected stamps a client runtime session as disconnected.
func (db *DB) MarkClientSessionDisconnected(ctx context.Context, id int64, status string, when time.Time) error {
	if id <= 0 {
		return nil
	}
	query := db.rebind(`UPDATE tunnel_client_session
		SET status = ?, disconnected_at = COALESCE(disconnected_at, ?)
		WHERE id = ?`)
	_, err := db.sql.ExecContext(ctx, query, status, formatTime(when), id)
	return err
}

// CloseHTTPAuthenticatedClientSessions closes stale startup-login sessions for the same machine user.
func (db *DB) CloseHTTPAuthenticatedClientSessions(ctx context.Context, credentialID int64,
	machineFingerprint, osUser, fromStatus, toStatus string, when time.Time) (int64, error) {
	query := db.rebind(`UPDATE tunnel_client_session
		SET status = ?, disconnected_at = ?
		WHERE credential_id = ? AND machine_fingerprint = ? AND os_user = ? AND status = ?`)
	result, err := db.sql.ExecContext(ctx, query, toStatus, formatTime(when), credentialID,
		machineFingerprint, osUser, fromStatus)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// CloseClientSessionsByStatus closes every session currently in fromStatus.
func (db *DB) CloseClientSessionsByStatus(ctx context.Context, fromStatus, toStatus string, when time.Time) (int64, error) {
	query := db.rebind(`UPDATE tunnel_client_session
		SET status = ?, disconnected_at = COALESCE(disconnected_at, ?)
		WHERE status = ?`)
	result, err := db.sql.ExecContext(ctx, query, toStatus, formatTime(when), fromStatus)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

type clientSessionScanner interface {
	Scan(dest ...any) error
}

func scanClientSession(scanner clientSessionScanner) (ClientSession, error) {
	var (
		session                             ClientSession
		hostname, osName, osVersion, osArch sql.NullString
		clientVersion, javaVersion          sql.NullString
		localAddresses                      sql.NullString
		nettyAt, disconnectedAt             sql.NullString
		channelID, remoteAddress            sql.NullString
		httpLoginAt, expiresAt              string
		messageSend, messageReceive         databaseBoolean
		messageAttachments, messagePreview  databaseBoolean
	)
	err := scanner.Scan(&session.ID, &session.TenantID, &session.CredentialID, &session.IdentityID,
		&session.ClientID, &session.ClientName, &session.TokenHash, &session.Status,
		&session.MachineFingerprint, &session.OSUser, &hostname, &osName, &osVersion, &osArch,
		&clientVersion, &javaVersion, &localAddresses, &messageSend,
		&messageReceive, &messageAttachments,
		&messagePreview, &session.MessageMaxAttachmentBytes,
		&httpLoginAt, &nettyAt, &disconnectedAt,
		&expiresAt, &channelID, &remoteAddress)
	if err != nil {
		return ClientSession{}, err
	}
	session.Hostname = nullStringPtr(hostname)
	session.OSName = nullStringPtr(osName)
	session.OSVersion = nullStringPtr(osVersion)
	session.OSArch = nullStringPtr(osArch)
	session.ClientVersion = nullStringPtr(clientVersion)
	session.JavaVersion = nullStringPtr(javaVersion)
	session.LocalAddresses = nullStringPtr(localAddresses)
	session.MessageSendCapable = bool(messageSend)
	session.MessageReceiveCapable = bool(messageReceive)
	session.MessageAttachmentsCapable = bool(messageAttachments)
	session.MessageMediaPreviewCapable = bool(messagePreview)
	session.HTTPLoginAt = parseTime(httpLoginAt)
	session.NettyConnectedAt = nullTimePtr(nettyAt)
	session.DisconnectedAt = nullTimePtr(disconnectedAt)
	session.ExpiresAt = parseTime(expiresAt)
	session.ChannelID = nullStringPtr(channelID)
	session.RemoteAddress = nullStringPtr(remoteAddress)
	return session, nil
}

func nullableSessionText(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
