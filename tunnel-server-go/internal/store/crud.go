package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// ---- clients -------------------------------------------------------------------------

// ListClients returns all client accounts ordered by id.
func (db *DB) ListClients(ctx context.Context) ([]ClientAccount, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT id, client_name, password_hash, enabled,
		connection_rate_limit_per_minute, created_at, updated_at FROM tunnel_client_account ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var clients []ClientAccount
	for rows.Next() {
		var (
			account            ClientAccount
			enabled            int
			createdAt, updated string
		)
		if err := rows.Scan(&account.ID, &account.ClientName, &account.PasswordHash, &enabled,
			&account.ConnectionRateLimitPerMinute, &createdAt, &updated); err != nil {
			return nil, err
		}
		account.Enabled = enabled != 0
		account.CreatedAt = parseTime(createdAt)
		account.UpdatedAt = parseTime(updated)
		clients = append(clients, account)
	}
	return clients, rows.Err()
}

// GetClient returns the client account by id, or ErrNotFound.
func (db *DB) GetClient(ctx context.Context, id int64) (*ClientAccount, error) {
	query := db.rebind(`SELECT id, client_name, password_hash, enabled,
		connection_rate_limit_per_minute, created_at, updated_at FROM tunnel_client_account WHERE id = ?`)
	var (
		account            ClientAccount
		enabled            int
		createdAt, updated string
	)
	err := db.sql.QueryRowContext(ctx, query, id).Scan(&account.ID, &account.ClientName,
		&account.PasswordHash, &enabled, &account.ConnectionRateLimitPerMinute, &createdAt, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	account.Enabled = enabled != 0
	account.CreatedAt = parseTime(createdAt)
	account.UpdatedAt = parseTime(updated)
	return &account, nil
}

// InsertClient persists a new client account (id is caller-assigned).
func (db *DB) InsertClient(ctx context.Context, account ClientAccount) error {
	query := db.rebind(`INSERT INTO tunnel_client_account
		(id, client_name, password_hash, enabled, connection_rate_limit_per_minute, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, account.ID, account.ClientName, account.PasswordHash,
		boolToInt(account.Enabled), account.ConnectionRateLimitPerMinute,
		formatTime(account.CreatedAt), formatTime(account.UpdatedAt))
	return err
}

// UpdateClient updates a client account's mutable fields.
func (db *DB) UpdateClient(ctx context.Context, account ClientAccount) error {
	query := db.rebind(`UPDATE tunnel_client_account SET client_name = ?, password_hash = ?,
		enabled = ?, connection_rate_limit_per_minute = ?, updated_at = ? WHERE id = ?`)
	_, err := db.sql.ExecContext(ctx, query, account.ClientName, account.PasswordHash,
		boolToInt(account.Enabled), account.ConnectionRateLimitPerMinute,
		formatTime(account.UpdatedAt), account.ID)
	return err
}

// DeleteClient removes a client account and its tunnel/http-route mappings.
func (db *DB) DeleteClient(ctx context.Context, id int64) error {
	for _, table := range []string{"tunnel_mapping", "http_route_mapping"} {
		if _, err := db.sql.ExecContext(ctx, db.rebind(`DELETE FROM `+table+` WHERE client_id = ?`), id); err != nil {
			return err
		}
	}
	_, err := db.sql.ExecContext(ctx, db.rebind(`DELETE FROM tunnel_client_account WHERE id = ?`), id)
	return err
}

// ---- tunnels -------------------------------------------------------------------------

// ListTunnels returns tunnel mappings, optionally filtered by client id, ordered by id.
func (db *DB) ListTunnels(ctx context.Context, clientID *int64) ([]TunnelMapping, error) {
	query := `SELECT id, client_id, client_name, listen_port, target_address, target_port,
		enabled, created_at, updated_at FROM tunnel_mapping`
	var args []any
	if clientID != nil {
		query += ` WHERE client_id = ?`
		args = append(args, *clientID)
	}
	query += ` ORDER BY id`
	rows, err := db.sql.QueryContext(ctx, db.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var mappings []TunnelMapping
	for rows.Next() {
		var (
			m                  TunnelMapping
			enabled            int
			createdAt, updated string
		)
		if err := rows.Scan(&m.ID, &m.ClientID, &m.ClientName, &m.ListenPort, &m.TargetAddress,
			&m.TargetPort, &enabled, &createdAt, &updated); err != nil {
			return nil, err
		}
		m.Enabled = enabled != 0
		m.CreatedAt = parseTime(createdAt)
		m.UpdatedAt = parseTime(updated)
		mappings = append(mappings, m)
	}
	return mappings, rows.Err()
}

// GetTunnel returns a tunnel mapping by id, or ErrNotFound.
func (db *DB) GetTunnel(ctx context.Context, id int64) (*TunnelMapping, error) {
	mappings, err := db.ListTunnels(ctx, nil)
	if err != nil {
		return nil, err
	}
	for i := range mappings {
		if mappings[i].ID == id {
			return &mappings[i], nil
		}
	}
	return nil, ErrNotFound
}

// ListenPortInUse reports whether a listen port is already mapped (optionally excluding a row).
func (db *DB) ListenPortInUse(ctx context.Context, listenPort int, excludeID int64) (bool, error) {
	query := db.rebind(`SELECT COUNT(*) FROM tunnel_mapping WHERE listen_port = ? AND id <> ?`)
	var count int
	err := db.sql.QueryRowContext(ctx, query, listenPort, excludeID).Scan(&count)
	return count > 0, err
}

// InsertTunnel persists a new tunnel mapping (id is caller-assigned).
func (db *DB) InsertTunnel(ctx context.Context, m TunnelMapping) error {
	query := db.rebind(`INSERT INTO tunnel_mapping
		(id, client_id, client_name, listen_port, target_address, target_port, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, m.ID, m.ClientID, m.ClientName, m.ListenPort,
		m.TargetAddress, m.TargetPort, boolToInt(m.Enabled), formatTime(m.CreatedAt), formatTime(m.UpdatedAt))
	return err
}

// UpdateTunnel updates a tunnel mapping's mutable fields.
func (db *DB) UpdateTunnel(ctx context.Context, m TunnelMapping) error {
	query := db.rebind(`UPDATE tunnel_mapping SET listen_port = ?, target_address = ?, target_port = ?,
		enabled = ?, updated_at = ? WHERE id = ?`)
	_, err := db.sql.ExecContext(ctx, query, m.ListenPort, m.TargetAddress, m.TargetPort,
		boolToInt(m.Enabled), formatTime(m.UpdatedAt), m.ID)
	return err
}

// DeleteTunnel removes a tunnel mapping.
func (db *DB) DeleteTunnel(ctx context.Context, id int64) error {
	_, err := db.sql.ExecContext(ctx, db.rebind(`DELETE FROM tunnel_mapping WHERE id = ?`), id)
	return err
}

// ---- http routes ---------------------------------------------------------------------

// ListHTTPRoutes returns HTTP route mappings, optionally filtered by client id, ordered by id.
func (db *DB) ListHTTPRoutes(ctx context.Context, clientID *int64) ([]HTTPRouteMapping, error) {
	query := `SELECT id, client_id, client_name, route, target_base_url, enabled, created_at, updated_at
		FROM http_route_mapping`
	var args []any
	if clientID != nil {
		query += ` WHERE client_id = ?`
		args = append(args, *clientID)
	}
	query += ` ORDER BY id`
	rows, err := db.sql.QueryContext(ctx, db.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var routes []HTTPRouteMapping
	for rows.Next() {
		var (
			r                  HTTPRouteMapping
			enabled            int
			createdAt, updated string
		)
		if err := rows.Scan(&r.ID, &r.ClientID, &r.ClientName, &r.Route, &r.TargetBaseURL,
			&enabled, &createdAt, &updated); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		r.CreatedAt = parseTime(createdAt)
		r.UpdatedAt = parseTime(updated)
		routes = append(routes, r)
	}
	return routes, rows.Err()
}

// GetHTTPRoute returns an HTTP route mapping by id, or ErrNotFound.
func (db *DB) GetHTTPRoute(ctx context.Context, id int64) (*HTTPRouteMapping, error) {
	routes, err := db.ListHTTPRoutes(ctx, nil)
	if err != nil {
		return nil, err
	}
	for i := range routes {
		if routes[i].ID == id {
			return &routes[i], nil
		}
	}
	return nil, ErrNotFound
}

// RouteInUse reports whether (client_id, route) is taken (optionally excluding a row).
func (db *DB) RouteInUse(ctx context.Context, clientID int64, route string, excludeID int64) (bool, error) {
	query := db.rebind(`SELECT COUNT(*) FROM http_route_mapping WHERE client_id = ? AND route = ? AND id <> ?`)
	var count int
	err := db.sql.QueryRowContext(ctx, query, clientID, route, excludeID).Scan(&count)
	return count > 0, err
}

// InsertHTTPRoute persists a new HTTP route mapping (id is caller-assigned).
func (db *DB) InsertHTTPRoute(ctx context.Context, r HTTPRouteMapping) error {
	query := db.rebind(`INSERT INTO http_route_mapping
		(id, client_id, client_name, route, target_base_url, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, r.ID, r.ClientID, r.ClientName, r.Route,
		r.TargetBaseURL, boolToInt(r.Enabled), formatTime(r.CreatedAt), formatTime(r.UpdatedAt))
	return err
}

// UpdateHTTPRoute updates an HTTP route mapping's mutable fields.
func (db *DB) UpdateHTTPRoute(ctx context.Context, r HTTPRouteMapping) error {
	query := db.rebind(`UPDATE http_route_mapping SET route = ?, target_base_url = ?, enabled = ?,
		updated_at = ? WHERE id = ?`)
	_, err := db.sql.ExecContext(ctx, query, r.Route, r.TargetBaseURL, boolToInt(r.Enabled),
		formatTime(r.UpdatedAt), r.ID)
	return err
}

// DeleteHTTPRoute removes an HTTP route mapping.
func (db *DB) DeleteHTTPRoute(ctx context.Context, id int64) error {
	_, err := db.sql.ExecContext(ctx, db.rebind(`DELETE FROM http_route_mapping WHERE id = ?`), id)
	return err
}

// ---- connections / traffic / stats ---------------------------------------------------

// ConnectionFilter narrows a connection-record query.
type ConnectionFilter struct {
	ClientID *int64
	Success  *bool
	FromISO  string
	ToISO    string
	Page     int
	Size     int
}

// ListConnections returns a page of connection records (newest first) and the total count.
func (db *DB) ListConnections(ctx context.Context, filter ConnectionFilter) ([]ConnectionRecord, int, error) {
	where := ` WHERE 1=1`
	var args []any
	if filter.ClientID != nil {
		where += ` AND client_id = ?`
		args = append(args, *filter.ClientID)
	}
	if filter.Success != nil {
		where += ` AND success = ?`
		args = append(args, boolToInt(*filter.Success))
	}
	if filter.FromISO != "" {
		where += ` AND connected_at >= ?`
		args = append(args, filter.FromISO)
	}
	if filter.ToISO != "" {
		where += ` AND connected_at <= ?`
		args = append(args, filter.ToISO)
	}

	var total int
	if err := db.sql.QueryRowContext(ctx, db.rebind(`SELECT COUNT(*) FROM tunnel_connection_record`+where), args...).
		Scan(&total); err != nil {
		return nil, 0, err
	}

	size := filter.Size
	if size <= 0 || size > 200 {
		size = 20
	}
	page := filter.Page
	if page < 0 {
		page = 0
	}
	listArgs := append(append([]any{}, args...), size, page*size)
	query := db.rebind(`SELECT id, client_id, client_name, channel_id, remote_address, connected_at,
		disconnected_at, success, failure_reason, disconnect_reason FROM tunnel_connection_record` +
		where + ` ORDER BY id DESC LIMIT ? OFFSET ?`)
	rows, err := db.sql.QueryContext(ctx, query, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var records []ConnectionRecord
	for rows.Next() {
		var (
			r              ConnectionRecord
			success        int
			connectedAt    string
			disconnectedAt sql.NullString
			channelID      sql.NullString
			remoteAddress  sql.NullString
			failureReason  sql.NullString
			disconnectRsn  sql.NullString
			clientID       sql.NullInt64
		)
		if err := rows.Scan(&r.ID, &clientID, &r.ClientName, &channelID, &remoteAddress, &connectedAt,
			&disconnectedAt, &success, &failureReason, &disconnectRsn); err != nil {
			return nil, 0, err
		}
		if clientID.Valid {
			r.ClientID = &clientID.Int64
		}
		if channelID.Valid {
			r.ChannelID = &channelID.String
		}
		if remoteAddress.Valid {
			r.RemoteAddress = &remoteAddress.String
		}
		r.ConnectedAt = parseTime(connectedAt)
		if disconnectedAt.Valid {
			t := parseTime(disconnectedAt.String)
			r.DisconnectedAt = &t
		}
		r.Success = success != 0
		if failureReason.Valid {
			r.FailureReason = &failureReason.String
		}
		if disconnectRsn.Valid {
			r.DisconnectReason = &disconnectRsn.String
		}
		records = append(records, r)
	}
	return records, total, rows.Err()
}

// ListTraffic returns traffic usage rows, optionally filtered by client id, newest date first.
func (db *DB) ListTraffic(ctx context.Context, clientID *int64, limit int) ([]TrafficUsage, error) {
	query := `SELECT id, client_id, client_name, usage_date, upload_bytes, download_bytes, updated_at
		FROM tunnel_traffic_usage`
	var args []any
	if clientID != nil {
		query += ` WHERE client_id = ?`
		args = append(args, *clientID)
	}
	query += ` ORDER BY usage_date DESC, id DESC`
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query += ` LIMIT ?`
	args = append(args, limit)
	rows, err := db.sql.QueryContext(ctx, db.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var usages []TrafficUsage
	for rows.Next() {
		var (
			u       TrafficUsage
			updated string
		)
		if err := rows.Scan(&u.ID, &u.ClientID, &u.ClientName, &u.UsageDate, &u.UploadBytes,
			&u.DownloadBytes, &updated); err != nil {
			return nil, err
		}
		u.UpdatedAt = parseTime(updated)
		usages = append(usages, u)
	}
	return usages, rows.Err()
}

// ListConnectionStats returns archived monthly stats, optionally filtered by client name.
func (db *DB) ListConnectionStats(ctx context.Context, clientName string, limit int) ([]ConnectionStat, error) {
	query := `SELECT id, client_id, client_name, stat_month, total_count, success_count, failure_count, updated_at
		FROM tunnel_connection_stat`
	var args []any
	if clientName != "" {
		query += ` WHERE client_name = ?`
		args = append(args, clientName)
	}
	query += ` ORDER BY stat_month DESC, id DESC`
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query += ` LIMIT ?`
	args = append(args, limit)
	rows, err := db.sql.QueryContext(ctx, db.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var stats []ConnectionStat
	for rows.Next() {
		var (
			stat     ConnectionStat
			clientID sql.NullInt64
			updated  string
		)
		if err := rows.Scan(&stat.ID, &clientID, &stat.ClientName, &stat.StatMonth, &stat.TotalCount,
			&stat.SuccessCount, &stat.FailureCount, &updated); err != nil {
			return nil, err
		}
		if clientID.Valid {
			stat.ClientID = &clientID.Int64
		}
		stat.UpdatedAt = parseTime(updated)
		stats = append(stats, stat)
	}
	return stats, rows.Err()
}

// Overview aggregates the dashboard counters.
type Overview struct {
	Clients               int64
	SuccessfulConnections int64
	FailedConnections     int64
	UploadBytes           int64
	DownloadBytes         int64
}

// LoadOverview computes the dashboard summary counters.
func (db *DB) LoadOverview(ctx context.Context) (Overview, error) {
	var o Overview
	if err := db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM tunnel_client_account`).Scan(&o.Clients); err != nil {
		return o, err
	}
	if err := db.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM tunnel_connection_record WHERE success = 1`).Scan(&o.SuccessfulConnections); err != nil {
		return o, err
	}
	if err := db.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM tunnel_connection_record WHERE success = 0`).Scan(&o.FailedConnections); err != nil {
		return o, err
	}
	if err := db.sql.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(upload_bytes),0), COALESCE(SUM(download_bytes),0) FROM tunnel_traffic_usage`).
		Scan(&o.UploadBytes, &o.DownloadBytes); err != nil {
		return o, err
	}
	return o, nil
}

// ArchiveOldConnections aggregates connection records older than cutoff into monthly stats and
// deletes them, returning the number of archived rows. Mirrors the C# ConnectionArchiveService.
func (db *DB) ArchiveOldConnections(ctx context.Context, cutoff time.Time) (int64, error) {
	cutoffISO := formatTime(cutoff)
	rows, err := db.sql.QueryContext(ctx, db.rebind(`SELECT client_id, client_name, connected_at, success
		FROM tunnel_connection_record WHERE connected_at < ?`), cutoffISO)
	if err != nil {
		return 0, err
	}
	type key struct {
		clientName string
		month      string
	}
	type agg struct {
		clientID             *int64
		total, success, fail int64
	}
	buckets := make(map[key]*agg)
	var archived int64
	for rows.Next() {
		var (
			clientID    sql.NullInt64
			clientName  string
			connectedAt string
			success     int
		)
		if err := rows.Scan(&clientID, &clientName, &connectedAt, &success); err != nil {
			rows.Close()
			return 0, err
		}
		month := parseTime(connectedAt).Format("2006-01")
		k := key{clientName: clientName, month: month}
		bucket := buckets[k]
		if bucket == nil {
			bucket = &agg{}
			if clientID.Valid {
				id := clientID.Int64
				bucket.clientID = &id
			}
			buckets[k] = bucket
		}
		bucket.total++
		if success != 0 {
			bucket.success++
		} else {
			bucket.fail++
		}
		archived++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if archived == 0 {
		return 0, nil
	}

	for k, bucket := range buckets {
		if err := db.upsertStat(ctx, bucket.clientID, k.clientName, k.month,
			bucket.total, bucket.success, bucket.fail); err != nil {
			return 0, err
		}
	}
	if _, err := db.sql.ExecContext(ctx,
		db.rebind(`DELETE FROM tunnel_connection_record WHERE connected_at < ?`), cutoffISO); err != nil {
		return 0, err
	}
	return archived, nil
}

func (db *DB) upsertStat(ctx context.Context, clientID *int64, clientName, month string, total, success, fail int64) error {
	now := formatTime(time.Now())
	switch db.dialect {
	case DialectMySQL:
		query := `INSERT INTO tunnel_connection_stat
			(client_id, client_name, stat_month, total_count, success_count, failure_count, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE total_count = total_count + VALUES(total_count),
				success_count = success_count + VALUES(success_count),
				failure_count = failure_count + VALUES(failure_count), updated_at = VALUES(updated_at)`
		_, err := db.sql.ExecContext(ctx, query, clientID, clientName, month, total, success, fail, now)
		return err
	default:
		query := db.rebind(`INSERT INTO tunnel_connection_stat
			(client_id, client_name, stat_month, total_count, success_count, failure_count, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (client_name, stat_month) DO UPDATE SET
				total_count = tunnel_connection_stat.total_count + ?,
				success_count = tunnel_connection_stat.success_count + ?,
				failure_count = tunnel_connection_stat.failure_count + ?,
				updated_at = ?`)
		_, err := db.sql.ExecContext(ctx, query, clientID, clientName, month, total, success, fail, now,
			total, success, fail, now)
		return err
	}
}
