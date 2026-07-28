package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// databaseBoolean accepts the representations returned by SQLite, PostgreSQL and
// MySQL. In particular, Java/Hibernate commonly creates MySQL booleans as BIT(1),
// which go-sql-driver/mysql returns as a single binary byte rather than an integer.
type databaseBoolean bool

func (value *databaseBoolean) Scan(src any) error {
	var parsed bool
	switch raw := src.(type) {
	case bool:
		parsed = raw
	case int64:
		parsed = raw != 0
	case []byte:
		if len(raw) == 1 && (raw[0] == 0 || raw[0] == 1) {
			parsed = raw[0] == 1
			break
		}
		result, err := parseDatabaseBooleanText(string(raw))
		if err != nil {
			return err
		}
		parsed = result
	case string:
		result, err := parseDatabaseBooleanText(raw)
		if err != nil {
			return err
		}
		parsed = result
	default:
		return fmt.Errorf("scan database boolean from %T", src)
	}
	*value = databaseBoolean(parsed)
	return nil
}

func parseDatabaseBooleanText(value string) (bool, error) {
	trimmed := strings.TrimSpace(value)
	if parsed, err := strconv.ParseBool(trimmed); err == nil {
		return parsed, nil
	}
	if parsed, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		return parsed != 0, nil
	}
	return false, fmt.Errorf("scan database boolean from %q", value)
}

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

func defaultTenant(value string) string {
	if value == "" {
		return "default"
	}
	return value
}

func defaultOwner(value string) string {
	if value == "" {
		return "admin"
	}
	return value
}

// FindClientByName returns the account for name, or (nil, nil) when absent.
func (db *DB) FindClientByName(ctx context.Context, name string) (*ClientAccount, error) {
	query := db.rebind(`SELECT id, COALESCE(tenant_id, 'default'), COALESCE(owner_username, ''),
		client_name, password_hash, enabled, connection_rate_limit_per_minute,
		created_at, updated_at FROM specus_client_account WHERE client_name = ?`)
	row := db.sql.QueryRowContext(ctx, query, name)
	var (
		account            ClientAccount
		enabled            databaseBoolean
		createdAt, updated string
	)
	err := row.Scan(&account.ID, &account.TenantID, &account.OwnerUsername,
		&account.ClientName, &account.PasswordHash, &enabled,
		&account.ConnectionRateLimitPerMinute, &createdAt, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	account.Enabled = bool(enabled)
	account.CreatedAt = parseTime(createdAt)
	account.UpdatedAt = parseTime(updated)
	return &account, nil
}

// FindCredentialByAPIKey returns the client startup credential for apiKey, or (nil, nil).
func (db *DB) FindCredentialByAPIKey(ctx context.Context, apiKey string) (*ClientCredential, error) {
	query := db.rebind(`SELECT id, tenant_id, COALESCE(owner_username, ''), api_key, secret_hash,
		enabled, max_online_instances, created_at, updated_at
		FROM specus_client_credential WHERE api_key = ?`)
	row := db.sql.QueryRowContext(ctx, query, apiKey)
	var (
		credential         ClientCredential
		enabled            databaseBoolean
		createdAt, updated string
	)
	err := row.Scan(&credential.ID, &credential.TenantID, &credential.OwnerUsername,
		&credential.APIKey, &credential.SecretHash, &enabled, &credential.MaxOnlineInstances,
		&createdAt, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	credential.Enabled = bool(enabled)
	credential.CreatedAt = parseTime(createdAt)
	credential.UpdatedAt = parseTime(updated)
	return &credential, nil
}

func (db *DB) FindIdentity(ctx context.Context, credentialID int64, machineFingerprint, osUser string) (*ClientIdentity, error) {
	query := db.rebind(`SELECT id, tenant_id, credential_id, client_id, client_name,
		machine_fingerprint, os_user, COALESCE(hostname, ''), first_seen_at, last_seen_at
		FROM specus_client_identity
		WHERE credential_id = ? AND machine_fingerprint = ? AND os_user = ?`)
	row := db.sql.QueryRowContext(ctx, query, credentialID, machineFingerprint, osUser)
	var identity ClientIdentity
	var firstSeen, lastSeen string
	err := row.Scan(&identity.ID, &identity.TenantID, &identity.CredentialID, &identity.ClientID,
		&identity.ClientName, &identity.MachineFingerprint, &identity.OSUser, &identity.Hostname,
		&firstSeen, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	identity.FirstSeenAt = parseTime(firstSeen)
	identity.LastSeenAt = parseTime(lastSeen)
	return &identity, nil
}

func (db *DB) InsertIdentity(ctx context.Context, identity ClientIdentity) error {
	query := db.rebind(`INSERT INTO specus_client_identity
		(id, tenant_id, credential_id, client_id, client_name, machine_fingerprint, os_user,
		 hostname, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, identity.ID, defaultTenant(identity.TenantID),
		identity.CredentialID, identity.ClientID, identity.ClientName,
		identity.MachineFingerprint, identity.OSUser, identity.Hostname,
		formatTime(identity.FirstSeenAt), formatTime(identity.LastSeenAt))
	return err
}

func (db *DB) UpdateIdentityLastSeen(ctx context.Context, id int64, hostname string, lastSeen time.Time) error {
	query := db.rebind(`UPDATE specus_client_identity SET hostname = ?, last_seen_at = ? WHERE id = ?`)
	_, err := db.sql.ExecContext(ctx, query, hostname, formatTime(lastSeen), id)
	return err
}

// CountConnectionsSince counts connection records for a client at or after the given time
// (used for per-client login rate limiting).
func (db *DB) CountConnectionsSince(ctx context.Context, clientID int64, since time.Time) (int, error) {
	query := db.rebind(`SELECT COUNT(*) FROM specus_connection_record
		WHERE client_id = ? AND connected_at >= ?`)
	var count int
	err := db.sql.QueryRowContext(ctx, query, clientID, formatTime(since)).Scan(&count)
	return count, err
}

// InsertConnectionRecord persists a login audit row and returns its generated id.
func (db *DB) InsertConnectionRecord(ctx context.Context, record ConnectionRecord) (int64, error) {
	const cols = `(tenant_id, client_id, client_name, channel_id, remote_address, connected_at,
		disconnected_at, success, failure_reason, disconnect_reason)`
	const vals = `(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	args := []any{
		defaultTenant(record.TenantID), record.ClientID, record.ClientName, record.ChannelID, record.RemoteAddress,
		formatTime(record.ConnectedAt), nullableTime(record.DisconnectedAt),
		boolToInt(record.Success), record.FailureReason, record.DisconnectReason,
	}
	if db.dialect == DialectPostgres {
		query := db.rebind(`INSERT INTO specus_connection_record ` + cols + ` VALUES ` + vals + ` RETURNING id`)
		var id int64
		if err := db.sql.QueryRowContext(ctx, query, args...).Scan(&id); err != nil {
			return 0, err
		}
		return id, nil
	}
	result, err := db.sql.ExecContext(ctx, `INSERT INTO specus_connection_record `+cols+` VALUES `+vals, args...)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// MarkDisconnect stamps disconnected_at/disconnect_reason on a record if not already set.
func (db *DB) MarkDisconnect(ctx context.Context, recordID int64, reason string, when time.Time) error {
	query := db.rebind(`UPDATE specus_connection_record
		SET disconnected_at = COALESCE(disconnected_at, ?),
		    disconnect_reason = COALESCE(disconnect_reason, ?)
		WHERE id = ?`)
	_, err := db.sql.ExecContext(ctx, query, formatTime(when), reason, recordID)
	return err
}

// CloseStaleOpenConnections stamps disconnected_at/disconnect_reason on every connection
// record whose disconnected_at is still NULL. Used at startup (SERVER_RESTARTED) and graceful
// shutdown (SERVER_SHUTDOWN) to mirror Java ConnectionRecordService sweeps. Returns the
// number of rows updated.
func (db *DB) CloseStaleOpenConnections(ctx context.Context, reason string, when time.Time) (int64, error) {
	query := db.rebind(`UPDATE specus_connection_record
		SET disconnected_at = COALESCE(disconnected_at, ?),
		    disconnect_reason = COALESCE(disconnect_reason, ?)
		WHERE disconnected_at IS NULL`)
	result, err := db.sql.ExecContext(ctx, query, formatTime(when), reason)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// CountClients returns the number of client accounts.
func (db *DB) CountClients(ctx context.Context) (int64, error) {
	var count int64
	err := db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM specus_client_account`).Scan(&count)
	return count, err
}

// CountClientsByTenant returns the number of client accounts in a tenant.
func (db *DB) CountClientsByTenant(ctx context.Context, tenantID string) (int64, error) {
	var count int64
	err := db.sql.QueryRowContext(ctx,
		db.rebind(`SELECT COUNT(*) FROM specus_client_account WHERE COALESCE(tenant_id, 'default') = ?`),
		defaultTenant(tenantID)).Scan(&count)
	return count, err
}

// CountConnections counts a client's connection records, optionally only successful ones.
func (db *DB) CountConnections(ctx context.Context, clientName string, onlySuccess bool) (int, error) {
	query := `SELECT COUNT(*) FROM specus_connection_record WHERE client_name = ?`
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
		FROM specus_traffic_usage WHERE client_name = ?`)
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
	query := db.rebind(`INSERT INTO specus_client_account
		(id, tenant_id, owner_username, client_name, password_hash, enabled,
		 connection_rate_limit_per_minute, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err = db.sql.ExecContext(ctx, query, account.ID, defaultTenant(account.TenantID),
		defaultOwner(account.OwnerUsername), account.ClientName, account.PasswordHash,
		boolToInt(account.Enabled), account.ConnectionRateLimitPerMinute,
		formatTime(account.CreatedAt), formatTime(account.UpdatedAt))
	if err != nil {
		return false, err
	}
	return true, nil
}

func (db *DB) InsertCredentialIfAbsent(ctx context.Context, credential ClientCredential) (bool, error) {
	existing, err := db.FindCredentialByAPIKey(ctx, credential.APIKey)
	if err != nil {
		return false, err
	}
	if existing != nil {
		return false, nil
	}
	query := db.rebind(`INSERT INTO specus_client_credential
		(id, tenant_id, owner_username, api_key, secret_hash, enabled,
		 max_online_instances, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err = db.sql.ExecContext(ctx, query, credential.ID, defaultTenant(credential.TenantID),
		defaultOwner(credential.OwnerUsername), credential.APIKey, credential.SecretHash,
		boolToInt(credential.Enabled), credential.MaxOnlineInstances,
		formatTime(credential.CreatedAt), formatTime(credential.UpdatedAt))
	if err != nil {
		return false, err
	}
	return true, nil
}

// ListEnabledSpecusMappings returns enabled specus mappings for a client, ordered by id.
func (db *DB) ListEnabledSpecusMappings(ctx context.Context, clientID int64) ([]SpecusMapping, error) {
	query := db.rebind(`SELECT id, client_id, client_name, listen_port, target_address, target_port,
		enabled, detail_capture_enabled, created_at, updated_at FROM specus_mapping
		WHERE client_id = ? AND enabled = 1 ORDER BY id`)
	rows, err := db.sql.QueryContext(ctx, query, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var mappings []SpecusMapping
	for rows.Next() {
		var (
			mapping            SpecusMapping
			enabled            databaseBoolean
			detailCapture      databaseBoolean
			createdAt, updated string
		)
		if err := rows.Scan(&mapping.ID, &mapping.ClientID, &mapping.ClientName, &mapping.ListenPort,
			&mapping.TargetAddress, &mapping.TargetPort, &enabled, &detailCapture, &createdAt, &updated); err != nil {
			return nil, err
		}
		mapping.Enabled = bool(enabled)
		mapping.DetailCaptureEnabled = bool(detailCapture)
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
		detail_capture_enabled, path_rewrite_enabled, created_at, updated_at FROM http_route_mapping
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
			enabled            databaseBoolean
			detailCapture      databaseBoolean
			pathRewrite        databaseBoolean
			createdAt, updated string
		)
		if err := rows.Scan(&route.ID, &route.ClientID, &route.ClientName, &route.Route,
			&route.TargetBaseURL, &enabled, &detailCapture, &pathRewrite, &createdAt, &updated); err != nil {
			return nil, err
		}
		route.Enabled = bool(enabled)
		route.DetailCaptureEnabled = bool(detailCapture)
		route.PathRewriteEnabled = bool(pathRewrite)
		route.CreatedAt = parseTime(createdAt)
		route.UpdatedAt = parseTime(updated)
		routes = append(routes, route)
	}
	return routes, rows.Err()
}

// HTTPRoutePathRewriteEnabled reports whether a client route has server-side response path
// rewriting enabled. Missing client/route rows are treated as disabled.
func (db *DB) HTTPRoutePathRewriteEnabled(ctx context.Context, clientName, route string) (bool, error) {
	account, err := db.FindClientByName(ctx, clientName)
	if err != nil || account == nil {
		return false, err
	}
	query := db.rebind(`SELECT path_rewrite_enabled FROM http_route_mapping
		WHERE client_id = ? AND route = ?`)
	var enabled databaseBoolean
	err = db.sql.QueryRowContext(ctx, query, account.ID, route).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return bool(enabled), nil
}

// AddTraffic increments today's upload/download byte counters for a client, upserting the row.
func (db *DB) AddTraffic(ctx context.Context, account ClientAccount, usageDate string, upload, download int64) error {
	now := formatTime(time.Now())
	switch db.dialect {
	case DialectMySQL:
		query := `INSERT INTO specus_traffic_usage
			(tenant_id, client_id, client_name, usage_date, upload_bytes, download_bytes, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE upload_bytes = upload_bytes + VALUES(upload_bytes),
				tenant_id = VALUES(tenant_id),
				download_bytes = download_bytes + VALUES(download_bytes), updated_at = VALUES(updated_at)`
		_, err := db.sql.ExecContext(ctx, query, defaultTenant(account.TenantID), account.ID,
			account.ClientName, usageDate, upload, download, now)
		return err
	default:
		query := db.rebind(`INSERT INTO specus_traffic_usage
			(tenant_id, client_id, client_name, usage_date, upload_bytes, download_bytes, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (client_id, usage_date) DO UPDATE SET
				tenant_id = excluded.tenant_id,
				upload_bytes = specus_traffic_usage.upload_bytes + ?,
				download_bytes = specus_traffic_usage.download_bytes + ?,
				updated_at = ?`)
		_, err := db.sql.ExecContext(ctx, query, defaultTenant(account.TenantID), account.ID,
			account.ClientName, usageDate, upload, download, now, upload, download, now)
		return err
	}
}

// AddResourceTraffic increments one resource-level daily traffic row.
func (db *DB) AddResourceTraffic(ctx context.Context, account ClientAccount, resourceType, resourceKey,
	usageDate string, upload, download int64) error {
	now := formatTime(time.Now())
	resourceID, resourceName := db.resourceDescriptor(ctx, account.ID, resourceType, resourceKey)
	switch db.dialect {
	case DialectMySQL:
		query := `INSERT INTO specus_resource_traffic_usage
			(tenant_id, client_id, client_name, resource_type, resource_key, resource_id, resource_name,
			 usage_date, upload_bytes, download_bytes, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE resource_id = VALUES(resource_id), resource_name = VALUES(resource_name),
				upload_bytes = upload_bytes + VALUES(upload_bytes),
				download_bytes = download_bytes + VALUES(download_bytes), updated_at = VALUES(updated_at)`
		_, err := db.sql.ExecContext(ctx, query, defaultTenant(account.TenantID), account.ID, account.ClientName,
			resourceType, resourceKey, nullableInt64(resourceID), resourceName, usageDate, upload, download, now)
		return err
	default:
		query := db.rebind(`INSERT INTO specus_resource_traffic_usage
			(tenant_id, client_id, client_name, resource_type, resource_key, resource_id, resource_name,
			 usage_date, upload_bytes, download_bytes, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (tenant_id, client_id, resource_type, resource_key, usage_date) DO UPDATE SET
				resource_id = excluded.resource_id,
				resource_name = excluded.resource_name,
				upload_bytes = specus_resource_traffic_usage.upload_bytes + ?,
				download_bytes = specus_resource_traffic_usage.download_bytes + ?,
				updated_at = ?`)
		_, err := db.sql.ExecContext(ctx, query, defaultTenant(account.TenantID), account.ID, account.ClientName,
			resourceType, resourceKey, nullableInt64(resourceID), resourceName, usageDate, upload, download, now,
			upload, download, now)
		return err
	}
}

func (db *DB) resourceDescriptor(ctx context.Context, clientID int64, resourceType, resourceKey string) (*int64, string) {
	switch resourceType {
	case "TCP_SPECUS":
		listenPort := parseTCPResourceKey(resourceKey)
		var id int64
		var targetAddress string
		var targetPort int
		err := db.sql.QueryRowContext(ctx, db.rebind(`SELECT id, target_address, target_port
			FROM specus_mapping WHERE client_id = ? AND listen_port = ?`), clientID, listenPort).
			Scan(&id, &targetAddress, &targetPort)
		if err == nil {
			return &id, strconv.Itoa(listenPort) + " -> " + targetAddress + ":" + strconv.Itoa(targetPort)
		}
		return nil, "端口 " + strconv.Itoa(listenPort)
	case "HTTP_ROUTE":
		route := parseHTTPResourceKey(resourceKey)
		var id int64
		var targetBaseURL string
		err := db.sql.QueryRowContext(ctx, db.rebind(`SELECT id, target_base_url
			FROM http_route_mapping WHERE client_id = ? AND route = ?`), clientID, route).
			Scan(&id, &targetBaseURL)
		if err == nil {
			return &id, route + " -> " + targetBaseURL
		}
		return nil, route
	default:
		return nil, resourceKey
	}
}

func nullableInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func parseTCPResourceKey(resourceKey string) int {
	value := strings.TrimPrefix(resourceKey, "tcp:")
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return port
}

func parseHTTPResourceKey(resourceKey string) string {
	return strings.TrimPrefix(resourceKey, "http:")
}
