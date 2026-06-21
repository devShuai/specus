package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return formatTime(*value)
}

// FindClientByName returns the account for name, or (nil, nil) when absent.
func (db *DB) FindClientByName(ctx context.Context, name string) (*ClientAccount, error) {
	query := db.rebind(`SELECT id, client_name, password_hash, enabled, connection_rate_limit_per_minute,
		created_at, updated_at FROM tunnel_client_account WHERE client_name = ?`)
	row := db.sql.QueryRowContext(ctx, query, name)
	var (
		account            ClientAccount
		enabled            int
		createdAt, updated string
	)
	err := row.Scan(&account.ID, &account.ClientName, &account.PasswordHash, &enabled,
		&account.ConnectionRateLimitPerMinute, &createdAt, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	account.Enabled = enabled != 0
	account.CreatedAt = parseTime(createdAt)
	account.UpdatedAt = parseTime(updated)
	return &account, nil
}

// CountConnectionsSince counts connection records for a client at or after the given time
// (used for per-client login rate limiting).
func (db *DB) CountConnectionsSince(ctx context.Context, clientID int64, since time.Time) (int, error) {
	query := db.rebind(`SELECT COUNT(*) FROM tunnel_connection_record
		WHERE client_id = ? AND connected_at >= ?`)
	var count int
	err := db.sql.QueryRowContext(ctx, query, clientID, formatTime(since)).Scan(&count)
	return count, err
}

// InsertConnectionRecord persists a login audit row and returns its generated id.
func (db *DB) InsertConnectionRecord(ctx context.Context, record ConnectionRecord) (int64, error) {
	const cols = `(client_id, client_name, channel_id, remote_address, connected_at,
		disconnected_at, success, failure_reason, disconnect_reason)`
	const vals = `(?, ?, ?, ?, ?, ?, ?, ?, ?)`
	args := []any{
		record.ClientID, record.ClientName, record.ChannelID, record.RemoteAddress,
		formatTime(record.ConnectedAt), nullableTime(record.DisconnectedAt),
		boolToInt(record.Success), record.FailureReason, record.DisconnectReason,
	}
	if db.dialect == DialectPostgres {
		query := db.rebind(`INSERT INTO tunnel_connection_record ` + cols + ` VALUES ` + vals + ` RETURNING id`)
		var id int64
		if err := db.sql.QueryRowContext(ctx, query, args...).Scan(&id); err != nil {
			return 0, err
		}
		return id, nil
	}
	result, err := db.sql.ExecContext(ctx, `INSERT INTO tunnel_connection_record `+cols+` VALUES `+vals, args...)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// MarkDisconnect stamps disconnected_at/disconnect_reason on a record if not already set.
func (db *DB) MarkDisconnect(ctx context.Context, recordID int64, reason string, when time.Time) error {
	query := db.rebind(`UPDATE tunnel_connection_record
		SET disconnected_at = COALESCE(disconnected_at, ?),
		    disconnect_reason = COALESCE(disconnect_reason, ?)
		WHERE id = ?`)
	_, err := db.sql.ExecContext(ctx, query, formatTime(when), reason, recordID)
	return err
}

// CountClients returns the number of client accounts.
func (db *DB) CountClients(ctx context.Context) (int64, error) {
	var count int64
	err := db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM tunnel_client_account`).Scan(&count)
	return count, err
}

// CountConnections counts a client's connection records, optionally only successful ones.
func (db *DB) CountConnections(ctx context.Context, clientName string, onlySuccess bool) (int, error) {
	query := `SELECT COUNT(*) FROM tunnel_connection_record WHERE client_name = ?`
	if onlySuccess {
		query += ` AND success = 1`
	}
	var count int
	err := db.sql.QueryRowContext(ctx, db.rebind(query), clientName).Scan(&count)
	return count, err
}

// SumTraffic returns the total upload/download bytes recorded for a client across all dates.
func (db *DB) SumTraffic(ctx context.Context, clientName string) (upload, download int64, err error) {
	query := db.rebind(`SELECT COALESCE(SUM(upload_bytes), 0), COALESCE(SUM(download_bytes), 0)
		FROM tunnel_traffic_usage WHERE client_name = ?`)
	err = db.sql.QueryRowContext(ctx, query, clientName).Scan(&upload, &download)
	return upload, download, err
}

// InsertClientIfAbsent inserts a client account when one with the same name does not exist.
// Returns true when a row was inserted.
func (db *DB) InsertClientIfAbsent(ctx context.Context, account ClientAccount) (bool, error) {
	existing, err := db.FindClientByName(ctx, account.ClientName)
	if err != nil {
		return false, err
	}
	if existing != nil {
		return false, nil
	}
	query := db.rebind(`INSERT INTO tunnel_client_account
		(id, client_name, password_hash, enabled, connection_rate_limit_per_minute, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	_, err = db.sql.ExecContext(ctx, query, account.ID, account.ClientName, account.PasswordHash,
		boolToInt(account.Enabled), account.ConnectionRateLimitPerMinute,
		formatTime(account.CreatedAt), formatTime(account.UpdatedAt))
	if err != nil {
		return false, err
	}
	return true, nil
}

// ListEnabledTunnels returns enabled tunnel mappings for a client, ordered by id.
func (db *DB) ListEnabledTunnels(ctx context.Context, clientID int64) ([]TunnelMapping, error) {
	query := db.rebind(`SELECT id, client_id, client_name, listen_port, target_address, target_port,
		enabled, created_at, updated_at FROM tunnel_mapping
		WHERE client_id = ? AND enabled = 1 ORDER BY id`)
	rows, err := db.sql.QueryContext(ctx, query, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var mappings []TunnelMapping
	for rows.Next() {
		var (
			mapping            TunnelMapping
			enabled            int
			createdAt, updated string
		)
		if err := rows.Scan(&mapping.ID, &mapping.ClientID, &mapping.ClientName, &mapping.ListenPort,
			&mapping.TargetAddress, &mapping.TargetPort, &enabled, &createdAt, &updated); err != nil {
			return nil, err
		}
		mapping.Enabled = enabled != 0
		mapping.CreatedAt = parseTime(createdAt)
		mapping.UpdatedAt = parseTime(updated)
		mappings = append(mappings, mapping)
	}
	return mappings, rows.Err()
}

// CountHTTPRoutes returns the number of HTTP route mappings for a client (any enabled state).
func (db *DB) CountHTTPRoutes(ctx context.Context, clientID int64) (int, error) {
	query := db.rebind(`SELECT COUNT(*) FROM http_route_mapping WHERE client_id = ?`)
	var count int
	err := db.sql.QueryRowContext(ctx, query, clientID).Scan(&count)
	return count, err
}

// ListEnabledHTTPRoutes returns enabled HTTP route mappings for a client, ordered by id.
func (db *DB) ListEnabledHTTPRoutes(ctx context.Context, clientID int64) ([]HTTPRouteMapping, error) {
	query := db.rebind(`SELECT id, client_id, client_name, route, target_base_url, enabled,
		created_at, updated_at FROM http_route_mapping
		WHERE client_id = ? AND enabled = 1 ORDER BY id`)
	rows, err := db.sql.QueryContext(ctx, query, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var routes []HTTPRouteMapping
	for rows.Next() {
		var (
			route              HTTPRouteMapping
			enabled            int
			createdAt, updated string
		)
		if err := rows.Scan(&route.ID, &route.ClientID, &route.ClientName, &route.Route,
			&route.TargetBaseURL, &enabled, &createdAt, &updated); err != nil {
			return nil, err
		}
		route.Enabled = enabled != 0
		route.CreatedAt = parseTime(createdAt)
		route.UpdatedAt = parseTime(updated)
		routes = append(routes, route)
	}
	return routes, rows.Err()
}

// AddTraffic increments today's upload/download byte counters for a client, upserting the row.
func (db *DB) AddTraffic(ctx context.Context, clientID int64, clientName, usageDate string, upload, download int64) error {
	now := formatTime(time.Now())
	switch db.dialect {
	case DialectMySQL:
		query := `INSERT INTO tunnel_traffic_usage
			(client_id, client_name, usage_date, upload_bytes, download_bytes, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE upload_bytes = upload_bytes + VALUES(upload_bytes),
				download_bytes = download_bytes + VALUES(download_bytes), updated_at = VALUES(updated_at)`
		_, err := db.sql.ExecContext(ctx, query, clientID, clientName, usageDate, upload, download, now)
		return err
	default:
		query := db.rebind(`INSERT INTO tunnel_traffic_usage
			(client_id, client_name, usage_date, upload_bytes, download_bytes, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (client_id, usage_date) DO UPDATE SET
				upload_bytes = tunnel_traffic_usage.upload_bytes + ?,
				download_bytes = tunnel_traffic_usage.download_bytes + ?,
				updated_at = ?`)
		_, err := db.sql.ExecContext(ctx, query, clientID, clientName, usageDate, upload, download, now,
			upload, download, now)
		return err
	}
}
