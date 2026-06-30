package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ---- peer mesh devices ---------------------------------------------------------------

func (db *DB) FindPeerMeshDeviceByClientID(ctx context.Context, tenantID string, clientID int64) (*PeerMeshDevice, error) {
	query := db.rebind(`SELECT id, tenant_id, owner_username, client_id, client_name, virtual_ip, cidr,
		public_key, nat_type, last_endpoint, virtual_device_mode, virtual_device_name,
		virtual_device_status, virtual_device_error, virtual_device_updated_at, enabled,
		last_seen_at, created_at, updated_at FROM peer_mesh_device
		WHERE tenant_id = ? AND client_id = ?`)
	row := db.sql.QueryRowContext(ctx, query, defaultTenant(tenantID), clientID)
	device, err := scanPeerMeshDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &device, nil
}

func (db *DB) FindPeerMeshDeviceByVirtualIP(ctx context.Context, tenantID, virtualIP string) (*PeerMeshDevice, error) {
	query := db.rebind(`SELECT id, tenant_id, owner_username, client_id, client_name, virtual_ip, cidr,
		public_key, nat_type, last_endpoint, virtual_device_mode, virtual_device_name,
		virtual_device_status, virtual_device_error, virtual_device_updated_at, enabled,
		last_seen_at, created_at, updated_at FROM peer_mesh_device
		WHERE tenant_id = ? AND virtual_ip = ?`)
	row := db.sql.QueryRowContext(ctx, query, defaultTenant(tenantID), virtualIP)
	device, err := scanPeerMeshDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &device, nil
}

func (db *DB) ListPeerMeshDevicesByTenant(ctx context.Context, tenantID string) ([]PeerMeshDevice, error) {
	query := db.rebind(`SELECT id, tenant_id, owner_username, client_id, client_name, virtual_ip, cidr,
		public_key, nat_type, last_endpoint, virtual_device_mode, virtual_device_name,
		virtual_device_status, virtual_device_error, virtual_device_updated_at, enabled,
		last_seen_at, created_at, updated_at FROM peer_mesh_device
		WHERE tenant_id = ? ORDER BY client_name ASC`)
	return db.listPeerMeshDevices(ctx, query, defaultTenant(tenantID))
}

func (db *DB) ListPeerMeshDevicesByOwner(ctx context.Context, tenantID, ownerUsername string) ([]PeerMeshDevice, error) {
	query := db.rebind(`SELECT id, tenant_id, owner_username, client_id, client_name, virtual_ip, cidr,
		public_key, nat_type, last_endpoint, virtual_device_mode, virtual_device_name,
		virtual_device_status, virtual_device_error, virtual_device_updated_at, enabled,
		last_seen_at, created_at, updated_at FROM peer_mesh_device
		WHERE tenant_id = ? AND owner_username = ? ORDER BY client_name ASC`)
	return db.listPeerMeshDevices(ctx, query, defaultTenant(tenantID), defaultOwner(ownerUsername))
}

func (db *DB) ListEnabledPeerMeshDevicesByOwner(ctx context.Context, tenantID, ownerUsername string) ([]PeerMeshDevice, error) {
	query := db.rebind(`SELECT id, tenant_id, owner_username, client_id, client_name, virtual_ip, cidr,
		public_key, nat_type, last_endpoint, virtual_device_mode, virtual_device_name,
		virtual_device_status, virtual_device_error, virtual_device_updated_at, enabled,
		last_seen_at, created_at, updated_at FROM peer_mesh_device
		WHERE tenant_id = ? AND owner_username = ? AND enabled = 1 ORDER BY client_name ASC`)
	return db.listPeerMeshDevices(ctx, query, defaultTenant(tenantID), defaultOwner(ownerUsername))
}

func (db *DB) listPeerMeshDevices(ctx context.Context, query string, args ...any) ([]PeerMeshDevice, error) {
	rows, err := db.sql.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []PeerMeshDevice
	for rows.Next() {
		device, err := scanPeerMeshDevice(rows)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, rows.Err()
}

func (db *DB) InsertPeerMeshDevice(ctx context.Context, device PeerMeshDevice) error {
	query := db.rebind(`INSERT INTO peer_mesh_device
		(id, tenant_id, owner_username, client_id, client_name, virtual_ip, cidr,
		 public_key, nat_type, last_endpoint, virtual_device_mode, virtual_device_name,
		 virtual_device_status, virtual_device_error, virtual_device_updated_at, enabled,
		 last_seen_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query,
		device.ID, defaultTenant(device.TenantID), defaultOwner(device.OwnerUsername),
		device.ClientID, device.ClientName, device.VirtualIP, device.CIDR,
		device.PublicKey, device.NatType, device.LastEndpoint, device.VirtualDeviceMode,
		device.VirtualDeviceName, device.VirtualDeviceStatus, device.VirtualDeviceError,
		nullableTime(device.VirtualDeviceUpdatedAt), boolToInt(device.Enabled),
		nullableTime(device.LastSeenAt), formatTime(device.CreatedAt), formatTime(device.UpdatedAt))
	return err
}

func (db *DB) UpdatePeerMeshDevice(ctx context.Context, device PeerMeshDevice) error {
	query := db.rebind(`UPDATE peer_mesh_device SET owner_username = ?, client_name = ?, virtual_ip = ?,
		cidr = ?, public_key = ?, nat_type = ?, last_endpoint = ?, virtual_device_mode = ?,
		virtual_device_name = ?, virtual_device_status = ?, virtual_device_error = ?,
		virtual_device_updated_at = ?, enabled = ?, last_seen_at = ?, updated_at = ?
		WHERE id = ?`)
	_, err := db.sql.ExecContext(ctx, query,
		defaultOwner(device.OwnerUsername), device.ClientName, device.VirtualIP, device.CIDR,
		device.PublicKey, device.NatType, device.LastEndpoint, device.VirtualDeviceMode,
		device.VirtualDeviceName, device.VirtualDeviceStatus, device.VirtualDeviceError,
		nullableTime(device.VirtualDeviceUpdatedAt), boolToInt(device.Enabled),
		nullableTime(device.LastSeenAt), formatTime(device.UpdatedAt), device.ID)
	return err
}

// ---- peer mesh ACL -------------------------------------------------------------------

func (db *DB) FindPeerMeshACL(ctx context.Context, tenantID string, sourceClientID, targetClientID int64) (*PeerMeshACL, error) {
	query := db.rebind(`SELECT id, tenant_id, owner_username, source_client_id, source_client_name,
		target_client_id, target_client_name, allowed, created_at, updated_at FROM peer_mesh_acl
		WHERE tenant_id = ? AND source_client_id = ? AND target_client_id = ?`)
	row := db.sql.QueryRowContext(ctx, query, defaultTenant(tenantID), sourceClientID, targetClientID)
	acl, err := scanPeerMeshACL(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &acl, nil
}

func (db *DB) ListPeerMeshACLsByTenant(ctx context.Context, tenantID string) ([]PeerMeshACL, error) {
	query := db.rebind(`SELECT id, tenant_id, owner_username, source_client_id, source_client_name,
		target_client_id, target_client_name, allowed, created_at, updated_at FROM peer_mesh_acl
		WHERE tenant_id = ? ORDER BY id DESC`)
	return db.listPeerMeshACLs(ctx, query, defaultTenant(tenantID))
}

func (db *DB) ListPeerMeshACLsByOwner(ctx context.Context, tenantID, ownerUsername string) ([]PeerMeshACL, error) {
	query := db.rebind(`SELECT id, tenant_id, owner_username, source_client_id, source_client_name,
		target_client_id, target_client_name, allowed, created_at, updated_at FROM peer_mesh_acl
		WHERE tenant_id = ? AND owner_username = ? ORDER BY id DESC`)
	return db.listPeerMeshACLs(ctx, query, defaultTenant(tenantID), defaultOwner(ownerUsername))
}

func (db *DB) listPeerMeshACLs(ctx context.Context, query string, args ...any) ([]PeerMeshACL, error) {
	rows, err := db.sql.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var acls []PeerMeshACL
	for rows.Next() {
		acl, err := scanPeerMeshACL(rows)
		if err != nil {
			return nil, err
		}
		acls = append(acls, acl)
	}
	return acls, rows.Err()
}

func (db *DB) InsertPeerMeshACL(ctx context.Context, acl PeerMeshACL) error {
	query := db.rebind(`INSERT INTO peer_mesh_acl
		(id, tenant_id, owner_username, source_client_id, source_client_name,
		 target_client_id, target_client_name, allowed, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, acl.ID, defaultTenant(acl.TenantID), defaultOwner(acl.OwnerUsername),
		acl.SourceClientID, acl.SourceClientName, acl.TargetClientID, acl.TargetClientName,
		boolToInt(acl.Allowed), formatTime(acl.CreatedAt), formatTime(acl.UpdatedAt))
	return err
}

func (db *DB) UpdatePeerMeshACL(ctx context.Context, acl PeerMeshACL) error {
	query := db.rebind(`UPDATE peer_mesh_acl SET owner_username = ?, source_client_name = ?,
		target_client_name = ?, allowed = ?, updated_at = ? WHERE id = ?`)
	_, err := db.sql.ExecContext(ctx, query, defaultOwner(acl.OwnerUsername), acl.SourceClientName,
		acl.TargetClientName, boolToInt(acl.Allowed), formatTime(acl.UpdatedAt), acl.ID)
	return err
}

func (db *DB) DeletePeerMeshACL(ctx context.Context, id int64) error {
	_, err := db.sql.ExecContext(ctx, db.rebind(`DELETE FROM peer_mesh_acl WHERE id = ?`), id)
	return err
}

func (db *DB) GetPeerMeshACL(ctx context.Context, id int64) (*PeerMeshACL, error) {
	query := db.rebind(`SELECT id, tenant_id, owner_username, source_client_id, source_client_name,
		target_client_id, target_client_name, allowed, created_at, updated_at FROM peer_mesh_acl
		WHERE id = ?`)
	row := db.sql.QueryRowContext(ctx, query, id)
	acl, err := scanPeerMeshACL(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &acl, nil
}

// ---- peer mesh sessions --------------------------------------------------------------

func (db *DB) InsertPeerMeshSession(ctx context.Context, session PeerMeshSession) error {
	query := db.rebind(`INSERT INTO peer_mesh_session
		(id, tenant_id, source_client_id, source_client_name, target_client_id, target_client_name,
		 path_type, status, token_hash, started_at, updated_at, expires_at, closed_at,
		 rtt_millis, local_endpoint, remote_endpoint, direct_bytes, relay_bytes, last_traffic_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query,
		session.ID, defaultTenant(session.TenantID), session.SourceClientID, session.SourceClientName,
		session.TargetClientID, session.TargetClientName, session.PathType, session.Status,
		session.TokenHash, formatTime(session.StartedAt), formatTime(session.UpdatedAt),
		formatTime(session.ExpiresAt), nullableTime(session.ClosedAt), session.RTTMillis,
		session.LocalEndpoint, session.RemoteEndpoint, session.DirectBytes, session.RelayBytes,
		nullableTime(session.LastTrafficAt))
	return err
}

func (db *DB) UpdatePeerMeshSession(ctx context.Context, session PeerMeshSession) error {
	query := db.rebind(`UPDATE peer_mesh_session SET path_type = ?, status = ?, updated_at = ?,
		expires_at = ?, closed_at = ?, rtt_millis = ?, local_endpoint = ?, remote_endpoint = ?,
		direct_bytes = ?, relay_bytes = ?, last_traffic_at = ? WHERE id = ?`)
	_, err := db.sql.ExecContext(ctx, query,
		session.PathType, session.Status, formatTime(session.UpdatedAt), formatTime(session.ExpiresAt),
		nullableTime(session.ClosedAt), session.RTTMillis, session.LocalEndpoint, session.RemoteEndpoint,
		session.DirectBytes, session.RelayBytes, nullableTime(session.LastTrafficAt), session.ID)
	return err
}

func (db *DB) GetPeerMeshSession(ctx context.Context, id int64) (*PeerMeshSession, error) {
	query := db.rebind(`SELECT id, tenant_id, source_client_id, source_client_name, target_client_id,
		target_client_name, path_type, status, token_hash, started_at, updated_at, expires_at,
		closed_at, rtt_millis, local_endpoint, remote_endpoint, direct_bytes, relay_bytes,
		last_traffic_at FROM peer_mesh_session WHERE id = ?`)
	row := db.sql.QueryRowContext(ctx, query, id)
	session, err := scanPeerMeshSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (db *DB) ListPeerMeshSessions(ctx context.Context, tenantID string, limit int) ([]PeerMeshSession, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	query := db.rebind(`SELECT id, tenant_id, source_client_id, source_client_name, target_client_id,
		target_client_name, path_type, status, token_hash, started_at, updated_at, expires_at,
		closed_at, rtt_millis, local_endpoint, remote_endpoint, direct_bytes, relay_bytes,
		last_traffic_at FROM peer_mesh_session
		WHERE tenant_id = ? ORDER BY updated_at DESC LIMIT ?`)
	return db.listPeerMeshSessions(ctx, query, defaultTenant(tenantID), limit)
}

func (db *DB) ListVisiblePeerMeshSessions(ctx context.Context, tenantID string, clientIDs []int64, limit int) ([]PeerMeshSession, error) {
	if len(clientIDs) == 0 {
		return nil, nil
	}
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	args := []any{defaultTenant(tenantID)}
	query := `SELECT id, tenant_id, source_client_id, source_client_name, target_client_id,
		target_client_name, path_type, status, token_hash, started_at, updated_at, expires_at,
		closed_at, rtt_millis, local_endpoint, remote_endpoint, direct_bytes, relay_bytes,
		last_traffic_at FROM peer_mesh_session
		WHERE tenant_id = ? AND (source_client_id IN (` + placeholders(len(clientIDs)) + `)
		OR target_client_id IN (` + placeholders(len(clientIDs)) + `)) ORDER BY updated_at DESC LIMIT ?`
	for _, id := range clientIDs {
		args = append(args, id)
	}
	for _, id := range clientIDs {
		args = append(args, id)
	}
	args = append(args, limit)
	return db.listPeerMeshSessions(ctx, db.rebind(query), args...)
}

func (db *DB) ListPeerMeshSessionsPage(ctx context.Context, tenantID string, clientIDs []int64, filterClientIDs bool, page, size int, openOnly bool, closedStatus string) ([]PeerMeshSession, int, error) {
	if filterClientIDs && len(clientIDs) == 0 {
		return nil, 0, nil
	}
	if page < 0 {
		page = 0
	}
	if size <= 0 || size > 200 {
		size = 100
	}
	args := []any{defaultTenant(tenantID)}
	where := ` WHERE tenant_id = ?`
	if openOnly {
		where += ` AND status <> ?`
		args = append(args, closedStatus)
	}
	if filterClientIDs {
		where += ` AND (source_client_id IN (` + placeholders(len(clientIDs)) + `)
			OR target_client_id IN (` + placeholders(len(clientIDs)) + `))`
		for _, id := range clientIDs {
			args = append(args, id)
		}
		for _, id := range clientIDs {
			args = append(args, id)
		}
	}
	var total int
	countQuery := db.rebind(`SELECT COUNT(*) FROM peer_mesh_session` + where)
	if err := db.sql.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	listArgs := append(append([]any{}, args...), size, page*size)
	listQuery := db.rebind(`SELECT id, tenant_id, source_client_id, source_client_name, target_client_id,
		target_client_name, path_type, status, token_hash, started_at, updated_at, expires_at,
		closed_at, rtt_millis, local_endpoint, remote_endpoint, direct_bytes, relay_bytes,
		last_traffic_at FROM peer_mesh_session` + where + ` ORDER BY updated_at DESC LIMIT ? OFFSET ?`)
	items, err := db.listPeerMeshSessions(ctx, listQuery, listArgs...)
	return items, total, err
}

func (db *DB) ListOpenPeerMeshSessions(ctx context.Context, tenantID string, clientIDs []int64, closedStatus string) ([]PeerMeshSession, error) {
	args := []any{defaultTenant(tenantID), closedStatus}
	query := `SELECT id, tenant_id, source_client_id, source_client_name, target_client_id,
		target_client_name, path_type, status, token_hash, started_at, updated_at, expires_at,
		closed_at, rtt_millis, local_endpoint, remote_endpoint, direct_bytes, relay_bytes,
		last_traffic_at FROM peer_mesh_session
		WHERE tenant_id = ? AND status <> ?`
	if len(clientIDs) > 0 {
		query += ` AND (source_client_id IN (` + placeholders(len(clientIDs)) + `)
			OR target_client_id IN (` + placeholders(len(clientIDs)) + `))`
		for _, id := range clientIDs {
			args = append(args, id)
		}
		for _, id := range clientIDs {
			args = append(args, id)
		}
	}
	query += ` ORDER BY updated_at DESC`
	return db.listPeerMeshSessions(ctx, db.rebind(query), args...)
}

func (db *DB) ListOpenPeerMeshSessionsForDevice(ctx context.Context, tenantID string, clientID int64, closedStatus string) ([]PeerMeshSession, error) {
	query := db.rebind(`SELECT id, tenant_id, source_client_id, source_client_name, target_client_id,
		target_client_name, path_type, status, token_hash, started_at, updated_at, expires_at,
		closed_at, rtt_millis, local_endpoint, remote_endpoint, direct_bytes, relay_bytes,
		last_traffic_at FROM peer_mesh_session
		WHERE tenant_id = ? AND status <> ? AND (source_client_id = ? OR target_client_id = ?)
		ORDER BY updated_at DESC`)
	return db.listPeerMeshSessions(ctx, query, defaultTenant(tenantID), closedStatus, clientID, clientID)
}

func (db *DB) ListExpiredPeerMeshSessions(ctx context.Context, closedStatus string, expiresAt time.Time, limit int) ([]PeerMeshSession, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	query := db.rebind(`SELECT id, tenant_id, source_client_id, source_client_name, target_client_id,
		target_client_name, path_type, status, token_hash, started_at, updated_at, expires_at,
		closed_at, rtt_millis, local_endpoint, remote_endpoint, direct_bytes, relay_bytes,
		last_traffic_at FROM peer_mesh_session
		WHERE status <> ? AND expires_at <= ? ORDER BY expires_at ASC LIMIT ?`)
	return db.listPeerMeshSessions(ctx, query, closedStatus, formatTime(expiresAt), limit)
}

func (db *DB) listPeerMeshSessions(ctx context.Context, query string, args ...any) ([]PeerMeshSession, error) {
	rows, err := db.sql.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []PeerMeshSession
	for rows.Next() {
		session, err := scanPeerMeshSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanPeerMeshDevice(scanner scanner) (PeerMeshDevice, error) {
	var (
		device              PeerMeshDevice
		publicKey, natType  sql.NullString
		lastEndpoint        sql.NullString
		mode, name, status  sql.NullString
		deviceError         sql.NullString
		deviceUpdated, seen sql.NullString
		created, updated    string
		enabled             int
	)
	err := scanner.Scan(&device.ID, &device.TenantID, &device.OwnerUsername, &device.ClientID,
		&device.ClientName, &device.VirtualIP, &device.CIDR, &publicKey, &natType,
		&lastEndpoint, &mode, &name, &status, &deviceError, &deviceUpdated, &enabled,
		&seen, &created, &updated)
	if err != nil {
		return PeerMeshDevice{}, err
	}
	device.PublicKey = nullStringPtr(publicKey)
	device.NatType = nullStringPtr(natType)
	device.LastEndpoint = nullStringPtr(lastEndpoint)
	device.VirtualDeviceMode = nullStringPtr(mode)
	device.VirtualDeviceName = nullStringPtr(name)
	device.VirtualDeviceStatus = nullStringPtr(status)
	device.VirtualDeviceError = nullStringPtr(deviceError)
	device.VirtualDeviceUpdatedAt = nullTimePtr(deviceUpdated)
	device.Enabled = enabled != 0
	device.LastSeenAt = nullTimePtr(seen)
	device.CreatedAt = parseTime(created)
	device.UpdatedAt = parseTime(updated)
	return device, nil
}

func scanPeerMeshACL(scanner scanner) (PeerMeshACL, error) {
	var acl PeerMeshACL
	var created, updated string
	var allowed int
	err := scanner.Scan(&acl.ID, &acl.TenantID, &acl.OwnerUsername, &acl.SourceClientID,
		&acl.SourceClientName, &acl.TargetClientID, &acl.TargetClientName, &allowed,
		&created, &updated)
	if err != nil {
		return PeerMeshACL{}, err
	}
	acl.Allowed = allowed != 0
	acl.CreatedAt = parseTime(created)
	acl.UpdatedAt = parseTime(updated)
	return acl, nil
}

func scanPeerMeshSession(scanner scanner) (PeerMeshSession, error) {
	var (
		session                       PeerMeshSession
		tokenHash, closed             sql.NullString
		localEndpoint, remoteEndpoint sql.NullString
		lastTraffic                   sql.NullString
		rtt                           sql.NullInt64
		started, updated, expires     string
	)
	err := scanner.Scan(&session.ID, &session.TenantID, &session.SourceClientID, &session.SourceClientName,
		&session.TargetClientID, &session.TargetClientName, &session.PathType, &session.Status,
		&tokenHash, &started, &updated, &expires, &closed, &rtt, &localEndpoint, &remoteEndpoint,
		&session.DirectBytes, &session.RelayBytes, &lastTraffic)
	if err != nil {
		return PeerMeshSession{}, err
	}
	session.TokenHash = nullStringPtr(tokenHash)
	session.StartedAt = parseTime(started)
	session.UpdatedAt = parseTime(updated)
	session.ExpiresAt = parseTime(expires)
	session.ClosedAt = nullTimePtr(closed)
	if rtt.Valid {
		session.RTTMillis = &rtt.Int64
	}
	session.LocalEndpoint = nullStringPtr(localEndpoint)
	session.RemoteEndpoint = nullStringPtr(remoteEndpoint)
	session.LastTrafficAt = nullTimePtr(lastTraffic)
	return session, nil
}

func nullTimePtr(value sql.NullString) *time.Time {
	if !value.Valid || strings.TrimSpace(value.String) == "" {
		return nil
	}
	parsed := parseTime(value.String)
	return &parsed
}
