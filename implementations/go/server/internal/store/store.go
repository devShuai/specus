package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

//go:embed schema/*.sql
var schemaFS embed.FS

// isoLayout matches the C# server's "yyyy-MM-ddTHH:mm:ss.fffffffZ" so string ordering equals
// time ordering across SQLite TEXT and Postgres/MySQL VARCHAR columns.
const isoLayout = "2006-01-02T15:04:05.0000000Z"

// Dialect identifies the active SQL dialect.
type Dialect string

const (
	DialectSQLite   Dialect = "sqlite"
	DialectPostgres Dialect = "postgresql"
	DialectMySQL    Dialect = "mysql"
)

type clientAuthNonceLayout uint8

const (
	clientAuthNonceLayoutUnknown clientAuthNonceLayout = iota
	clientAuthNonceLayoutComposite
	clientAuthNonceLayoutJavaID
)

// DB is the persistence layer over a multi-dialect database/sql connection.
type DB struct {
	sql                   *sql.DB
	dialect               Dialect
	clientAuthNonceLayout clientAuthNonceLayout
	detailStore           trafficDetailBackend
	tcpCursorMu           sync.Mutex
	tcpCursors            map[string]*tcpStreamCursor
	detailMu              sync.Mutex
	detailDecisions       map[string]detailCaptureDecision
	pendingHTTPExchanges  []HTTPExchangeRecord
	pendingTCPFrames      []TCPFrameRecord
	detailMaxPending      int
	detailFlushBatchSize  int
	droppedHTTPDetails    int64
	droppedTCPDetails     int64
	lastDetailFlushedAt   time.Time
}

type trafficDetailBackend interface {
	InsertHTTPExchange(ctx context.Context, e HTTPTrafficExchange) error
	InsertTCPFrame(ctx context.Context, f TCPTrafficFrame) error
	ListHTTPExchanges(ctx context.Context, filter HTTPExchangeFilter) ([]HTTPTrafficExchange, int, error)
	GetHTTPExchange(ctx context.Context, tenantID string, id int64, clientIDs []int64) (*HTTPTrafficExchange, error)
	ListTCPFrames(ctx context.Context, filter TCPFrameFilter) ([]TCPTrafficFrame, int, error)
	GetTCPFrame(ctx context.Context, tenantID string, id int64, clientIDs []int64) (*TCPTrafficFrame, error)
	ListTCPStream(ctx context.Context, tenantID, channelID string, clientIDs []int64, limit int) ([]TCPTrafficFrame, error)
}

// Open connects using the given provider (sqlite|postgres|mysql) and connection string,
// then applies the embedded schema for that dialect.
func Open(provider, connectionString string) (*DB, error) {
	driver, dialect, err := resolveDriver(provider)
	if err != nil {
		return nil, err
	}
	handle, err := sql.Open(driver, connectionString)
	if err != nil {
		return nil, fmt.Errorf("open %s database: %w", dialect, err)
	}
	if dialect == DialectSQLite {
		// SQLite is single-writer; one connection avoids "database is locked".
		handle.SetMaxOpenConns(1)
	}
	if err := handle.Ping(); err != nil {
		handle.Close()
		return nil, fmt.Errorf("ping %s database: %w", dialect, err)
	}
	db := &DB{
		sql:                  handle,
		dialect:              dialect,
		tcpCursors:           make(map[string]*tcpStreamCursor),
		detailDecisions:      make(map[string]detailCaptureDecision),
		detailMaxPending:     20000,
		detailFlushBatchSize: 1000,
	}
	if err := db.migrate(); err != nil {
		handle.Close()
		return nil, err
	}
	return db, nil
}

// Dialect returns the active dialect (also surfaced as the API "dialect" field).
func (db *DB) Dialect() Dialect { return db.dialect }

// Close releases the underlying connection pool.
func (db *DB) Close() error { return db.sql.Close() }

func resolveDriver(provider string) (driver string, dialect Dialect, err error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", "sqlite", "sqlite3":
		return "sqlite", DialectSQLite, nil
	case "postgres", "postgresql", "npgsql", "pgx":
		return "pgx", DialectPostgres, nil
	case "mysql", "mariadb":
		return "mysql", DialectMySQL, nil
	default:
		return "", "", fmt.Errorf("unknown database provider %q (use sqlite, postgres, or mysql)", provider)
	}
}

func (db *DB) migrate() error {
	name := map[Dialect]string{
		DialectSQLite:   "schema/sqlite.sql",
		DialectPostgres: "schema/postgres.sql",
		DialectMySQL:    "schema/mysql.sql",
	}[db.dialect]
	data, err := schemaFS.ReadFile(name)
	if err != nil {
		return fmt.Errorf("read schema %s: %w", name, err)
	}
	for _, stmt := range splitStatements(string(data)) {
		if _, err := db.sql.Exec(stmt); err != nil {
			return fmt.Errorf("apply schema statement: %w\n%s", err, stmt)
		}
	}
	if err := db.ensureCompatibleColumns(); err != nil {
		return err
	}
	if err := db.detectClientAuthNonceLayout(); err != nil {
		return err
	}
	return nil
}

func (db *DB) detectClientAuthNonceLayout() error {
	hasID, err := db.columnExists("specus_client_auth_nonce", "id")
	if err != nil {
		return fmt.Errorf("inspect Java client nonce schema: %w", err)
	}
	if hasID {
		db.clientAuthNonceLayout = clientAuthNonceLayoutJavaID
		return nil
	}
	hasNonceHash, err := db.columnExists("specus_client_auth_nonce", "nonce_hash")
	if err != nil {
		return fmt.Errorf("inspect client nonce schema: %w", err)
	}
	if !hasNonceHash {
		return fmt.Errorf("unsupported specus_client_auth_nonce schema: expected id or nonce_hash")
	}
	db.clientAuthNonceLayout = clientAuthNonceLayoutComposite
	return nil
}

func (db *DB) ensureCompatibleColumns() error {
	boolType := "INTEGER NOT NULL DEFAULT 0"
	clientCapabilityBoolType := boolType
	ticketAttributesType := "TEXT"
	switch db.dialect {
	case DialectPostgres:
		boolType = "SMALLINT NOT NULL DEFAULT 0"
		clientCapabilityBoolType = "BOOLEAN NOT NULL DEFAULT FALSE"
	case DialectMySQL:
		boolType = "TINYINT(1) NOT NULL DEFAULT 0"
		clientCapabilityBoolType = boolType
		ticketAttributesType = "LONGTEXT"
	}
	columns := []struct {
		table      string
		name       string
		definition string
	}{
		{"specus_connection_record", "tenant_id", "VARCHAR(80)"},
		{"specus_management_user", "oidc_issuer", "VARCHAR(255)"},
		{"specus_management_user", "oidc_subject", "VARCHAR(255)"},
		{"specus_management_user", "oidc_identity_key", "VARCHAR(64)"},
		{"specus_connection_stat", "tenant_id", "VARCHAR(80)"},
		{"specus_traffic_usage", "tenant_id", "VARCHAR(80)"},
		{"specus_mapping", "detail_capture_enabled", boolType},
		{"specus_mapping", "tenant_id", "VARCHAR(80)"},
		{"http_route_mapping", "detail_capture_enabled", boolType},
		{"http_route_mapping", "media_capture_enabled", boolType},
		{"http_route_mapping", "path_rewrite_enabled", boolType},
		{"http_route_mapping", "auth_enabled", boolType},
		{"http_route_mapping", "auth_username", "VARCHAR(120) NOT NULL DEFAULT ''"},
		{"http_route_mapping", "auth_password_hash", "VARCHAR(64) NOT NULL DEFAULT ''"},
		{"http_route_mapping", "tenant_id", "VARCHAR(80)"},
		{"specus_client_session", "message_send_capable", clientCapabilityBoolType},
		{"specus_client_session", "message_receive_capable", clientCapabilityBoolType},
		{"specus_client_session", "message_attachments_capable", clientCapabilityBoolType},
		{"specus_client_session", "message_media_preview_capable", clientCapabilityBoolType},
		{"specus_client_session", "message_max_attachment_bytes", "BIGINT NOT NULL DEFAULT 0"},
		{"specus_client_session", "peer_service_discovery_version", "INTEGER NOT NULL DEFAULT 0"},
		{"specus_client_session", "peer_service_applications", "VARCHAR(160)"},
		{"peer_mesh_service_sharing", "mdns_import_enabled", boolType},
		{"peer_mesh_shared_service", "allowed_client_ids", "VARCHAR(512) NOT NULL DEFAULT ''"},
		{"client_download_link", "version", "VARCHAR(32)"},
		{"client_download_link", "sha256", "VARCHAR(64) NOT NULL DEFAULT ''"},
		{"client_download_link", "file_size", "BIGINT NOT NULL DEFAULT 0"},
		{"client_download_link", "is_latest", boolType},
		{"client_download_link", "latest_slot", "VARCHAR(160)"},
		{"client_download_link", "changelog_url", "VARCHAR(1024)"},
		{"client_download_link", "min_supported_version", "VARCHAR(32)"},
		{"transfer_attachment", "public_transfer_room_id", "BIGINT"},
		{"peer_mesh_device", "nat_mapping_behavior", "VARCHAR(80)"},
		{"peer_mesh_device", "nat_filtering_behavior", "VARCHAR(80)"},
		{"peer_mesh_device", "nat_behavior_discovery", "VARCHAR(40)"},
		{"peer_mesh_acl", "direction", "VARCHAR(16) NOT NULL DEFAULT 'OUTBOUND'"},
		{"specus_websocket_ticket", "attributes_json", ticketAttributesType},
		{"specus_websocket_ticket", "username", "VARCHAR(80)"},
		{"specus_websocket_ticket", "tenant_id", "VARCHAR(80)"},
		{"specus_websocket_ticket", "is_admin", boolType},
		{"specus_websocket_ticket", "room_id", "VARCHAR(120)"},
		{"specus_websocket_ticket", "room_key", "VARCHAR(80)"},
		{"specus_websocket_ticket", "room_role", "VARCHAR(16)"},
		{"specus_websocket_ticket", "peer_id", "VARCHAR(120)"},
		{"specus_websocket_ticket", "display_name", "VARCHAR(120)"},
		{"specus_websocket_ticket", "shared_room", boolType},
	}
	for _, column := range columns {
		if err := db.ensureColumn(column.table, column.name, column.definition); err != nil {
			return err
		}
	}
	if err := db.backfillClientDownloadVersions(); err != nil {
		return err
	}
	if err := db.backfillClientDownloadLatestSlots(); err != nil {
		return err
	}
	if err := db.ensureUniqueIndex("uq_client_download_target_version", "client_download_link",
		"implementation, platform, arch, version"); err != nil {
		return err
	}
	if err := db.ensureUniqueIndex("uq_client_download_latest_slot", "client_download_link", "latest_slot"); err != nil {
		return err
	}
	// This index must be created after ensureColumn. Embedded schema statements run before the
	// compatibility pass, so putting the index there would make an old table without the nullable
	// room column fail before it can be upgraded.
	if err := db.ensureIndex("idx_transfer_attachment_public_room", "transfer_attachment",
		"scope, public_transfer_room_id, id"); err != nil {
		return err
	}
	if err := db.ensureIndex("idx_transfer_attachment_public_room_status", "transfer_attachment",
		"scope, public_transfer_room_id, status"); err != nil {
		return err
	}
	if err := db.ensurePostgresClientMessageCapabilityTypes(); err != nil {
		return err
	}
	if err := db.ensureUniqueIndex("uq_management_user_oidc_identity_key",
		"specus_management_user", "oidc_identity_key"); err != nil {
		return err
	}
	if err := db.ensureIndex("idx_specus_connection_tenant", "specus_connection_record", "tenant_id"); err != nil {
		return err
	}
	if _, err := db.sql.Exec(db.rebind(`UPDATE specus_connection_stat
		SET tenant_id = COALESCE(
			(SELECT c.tenant_id FROM specus_client_account c WHERE c.id = specus_connection_stat.client_id LIMIT 1),
			(SELECT c.tenant_id FROM specus_client_account c WHERE specus_connection_stat.client_id IS NULL
				AND c.client_name = specus_connection_stat.client_name LIMIT 1),
			tenant_id,
			'default')
		WHERE tenant_id IS NULL OR tenant_id = '' OR tenant_id = 'default'`)); err != nil {
		return fmt.Errorf("backfill specus_connection_stat tenant_id: %w", err)
	}
	if err := db.ensureIndex("idx_specus_connection_stat_tenant", "specus_connection_stat", "tenant_id"); err != nil {
		return err
	}
	for _, table := range []string{"specus_mapping", "http_route_mapping"} {
		statement := fmt.Sprintf(`UPDATE %s SET tenant_id = COALESCE(
			(SELECT c.tenant_id FROM specus_client_account c WHERE c.id = %s.client_id LIMIT 1),
			tenant_id, 'default') WHERE tenant_id IS NULL OR tenant_id = ''`, table, table)
		if _, err := db.sql.Exec(db.rebind(statement)); err != nil {
			return fmt.Errorf("backfill %s tenant_id: %w", table, err)
		}
	}
	indexes := []struct{ name, table, columns string }{
		{"idx_specus_connection_tenant_id", "specus_connection_record", "tenant_id, id"},
		{"idx_specus_connection_tenant_client_id", "specus_connection_record", "tenant_id, client_id, id"},
		{"idx_specus_connection_tenant_success", "specus_connection_record", "tenant_id, success"},
		{"idx_specus_connection_tenant_client_time", "specus_connection_record", "tenant_id, client_id, connected_at"},
		{"idx_specus_mapping_tenant_client_id", "specus_mapping", "tenant_id, client_id, id"},
		{"idx_specus_mapping_tenant_client_enabled_id", "specus_mapping", "tenant_id, client_id, enabled, id"},
		{"idx_http_route_tenant_client_id", "http_route_mapping", "tenant_id, client_id, id"},
		{"idx_http_route_tenant_client_enabled_id", "http_route_mapping", "tenant_id, client_id, enabled, id"},
		{"idx_http_route_tenant_client_route", "http_route_mapping", "tenant_id, client_id, route"},
		{"idx_specus_traffic_tenant_date_id", "specus_traffic_usage", "tenant_id, usage_date, id"},
		{"idx_specus_traffic_tenant_client_date_id", "specus_traffic_usage", "tenant_id, client_id, usage_date, id"},
		{"idx_resource_traffic_tenant_date_id", "specus_resource_traffic_usage", "tenant_id, usage_date, id"},
		{"idx_resource_traffic_tenant_client_date_id", "specus_resource_traffic_usage", "tenant_id, client_id, usage_date, id"},
		{"idx_resource_traffic_tenant_type_date_id", "specus_resource_traffic_usage", "tenant_id, resource_type, usage_date, id"},
		{"idx_resource_traffic_tenant_client_type_date_id", "specus_resource_traffic_usage", "tenant_id, client_id, resource_type, usage_date, id"},
		{"idx_http_exchange_tenant_id", "specus_http_traffic_exchange", "tenant_id, id"},
		{"idx_http_exchange_tenant_client_id", "specus_http_traffic_exchange", "tenant_id, client_id, id"},
		{"idx_http_exchange_tenant_route_id", "specus_http_traffic_exchange", "tenant_id, route, id"},
		{"idx_http_exchange_tenant_client_route_id", "specus_http_traffic_exchange", "tenant_id, client_id, route, id"},
		{"idx_http_exchange_tenant_body_type_id", "specus_http_traffic_exchange", "tenant_id, response_body_type, id"},
		{"idx_tcp_frame_tenant_id", "specus_tcp_traffic_frame", "tenant_id, id"},
		{"idx_tcp_frame_tenant_client_id", "specus_tcp_traffic_frame", "tenant_id, client_id, id"},
		{"idx_tcp_frame_tenant_port_id", "specus_tcp_traffic_frame", "tenant_id, listen_port, id"},
		{"idx_tcp_frame_tenant_client_port_id", "specus_tcp_traffic_frame", "tenant_id, client_id, listen_port, id"},
		{"idx_tcp_frame_tenant_channel_id", "specus_tcp_traffic_frame", "tenant_id, channel_id, id"},
	}
	for _, index := range indexes {
		if err := db.ensureIndex(index.name, index.table, index.columns); err != nil {
			return err
		}
	}
	return nil
}

// backfillClientDownloadVersions upgrades both the original external-link-only catalog and the
// short-lived schema that stored invented 0.0.0-legacy.* versions. Only strict SemVer values are
// retained. A single lower-case v prefix is removed, and canonical duplicates are deterministically
// collapsed to one row so the unique target/version index can be recreated safely.
func (db *DB) backfillClientDownloadVersions() error {
	type row struct {
		id                             int64
		implementation, platform, arch string
		version                        sql.NullString
		latest, enabled                databaseBoolean
	}
	rows, err := db.sql.Query(`SELECT id, implementation, platform, arch, version, is_latest, enabled
		FROM client_download_link ORDER BY id DESC`)
	if err != nil {
		return fmt.Errorf("list client download versions for compatibility migration: %w", err)
	}
	var catalog []row
	for rows.Next() {
		var item row
		if err := rows.Scan(&item.id, &item.implementation, &item.platform, &item.arch, &item.version,
			&item.latest, &item.enabled); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan client download version for compatibility migration: %w", err)
		}
		catalog = append(catalog, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate client download versions for compatibility migration: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close client download compatibility rows: %w", err)
	}

	type normalizedRow struct {
		row
		version string
		valid   bool
	}
	normalized := make([]normalizedRow, 0, len(catalog))
	winners := make(map[string]int, len(catalog))
	for _, item := range catalog {
		version, valid := normalizeStoredClientDownloadVersion(item.version.String)
		entry := normalizedRow{row: item, version: version, valid: item.version.Valid && valid}
		normalized = append(normalized, entry)
		if !entry.valid {
			continue
		}
		keyPrefix := strings.ToLower(strings.TrimSpace(item.implementation)) + "\x00" +
			strings.ToLower(strings.TrimSpace(item.platform)) + "\x00" +
			strings.ToLower(strings.TrimSpace(item.arch)) + "\x00"
		key := keyPrefix + strings.ToLower(version)
		winnerIndex, exists := winners[key]
		if !exists || preferClientDownloadVersionWinner(
			bool(entry.enabled), bool(entry.latest), entry.id,
			bool(normalized[winnerIndex].enabled), bool(normalized[winnerIndex].latest), normalized[winnerIndex].id) {
			winners[key] = len(normalized) - 1
		}
	}

	desired := make(map[int64]sql.NullString, len(normalized))
	for _, entry := range normalized {
		desired[entry.id] = sql.NullString{}
	}
	for _, winnerIndex := range winners {
		winner := normalized[winnerIndex]
		desired[winner.id] = sql.NullString{String: winner.version, Valid: true}
	}
	needsUpdate := false
	for _, entry := range normalized {
		want := desired[entry.id]
		if entry.row.version.String != want.String || entry.row.version.Valid != want.Valid {
			needsUpdate = true
			break
		}
	}
	nullable, err := db.clientDownloadVersionColumnNullable()
	if err != nil {
		return err
	}
	if needsUpdate || !nullable {
		if err := db.dropIndexIfExists("uq_client_download_target_version", "client_download_link"); err != nil {
			return err
		}
	}
	if !nullable {
		if err := db.makeClientDownloadVersionNullable(); err != nil {
			return err
		}
	}
	if !needsUpdate {
		return nil
	}
	for _, entry := range normalized {
		want := desired[entry.id]
		if entry.row.version.String == want.String && entry.row.version.Valid == want.Valid {
			continue
		}
		var value any
		if want.Valid {
			value = want.String
		}
		if _, err := db.sql.Exec(db.rebind(`UPDATE client_download_link SET version = ? WHERE id = ?`),
			value, entry.id); err != nil {
			return fmt.Errorf("normalize client download version for id %d: %w", entry.id, err)
		}
	}
	return nil
}

func preferClientDownloadVersionWinner(candidateEnabled, candidateLatest bool, candidateID int64,
	currentEnabled, currentLatest bool, currentID int64) bool {
	candidatePublished := candidateEnabled && candidateLatest
	currentPublished := currentEnabled && currentLatest
	if candidatePublished != currentPublished {
		return candidatePublished
	}
	if candidateEnabled != currentEnabled {
		return candidateEnabled
	}
	return candidateID > currentID
}

func normalizeStoredClientDownloadVersion(value string) (string, bool) {
	version := strings.TrimSpace(value)
	version = strings.TrimPrefix(version, "v")
	if version == "" || len(version) > 32 ||
		strings.HasPrefix(strings.ToLower(version), "0.0.0-legacy.") {
		return "", false
	}
	withoutBuild := version
	if index := strings.IndexByte(withoutBuild, '+'); index >= 0 {
		if index == len(withoutBuild)-1 ||
			!validStoredSemanticIdentifiers(withoutBuild[index+1:], false) {
			return "", false
		}
		withoutBuild = withoutBuild[:index]
	}
	core := withoutBuild
	if index := strings.IndexByte(core, '-'); index >= 0 {
		if index == len(core)-1 || !validStoredSemanticIdentifiers(core[index+1:], true) {
			return "", false
		}
		core = core[:index]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return "", false
	}
	for _, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return "", false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return "", false
			}
		}
	}
	return version, true
}

func validStoredSemanticIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return false
		}
		numeric := true
		for _, char := range identifier {
			if (char < '0' || char > '9') && (char < 'A' || char > 'Z') &&
				(char < 'a' || char > 'z') && char != '-' {
				return false
			}
			if char < '0' || char > '9' {
				numeric = false
			}
		}
		if rejectNumericLeadingZero && numeric && len(identifier) > 1 && identifier[0] == '0' {
			return false
		}
	}
	return true
}

func (db *DB) clientDownloadVersionColumnNullable() (bool, error) {
	switch db.dialect {
	case DialectSQLite:
		rows, err := db.sql.Query(`PRAGMA table_info(client_download_link)`)
		if err != nil {
			return false, fmt.Errorf("inspect client download version nullability: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				cid, notNull, primaryKey int
				name, columnType         string
				defaultValue             sql.NullString
			)
			if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
				return false, fmt.Errorf("scan client download version nullability: %w", err)
			}
			if strings.EqualFold(name, "version") {
				return notNull == 0, nil
			}
		}
		if err := rows.Err(); err != nil {
			return false, err
		}
	case DialectPostgres:
		var nullable string
		err := db.sql.QueryRow(`SELECT is_nullable FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = 'client_download_link' AND column_name = 'version'`).Scan(&nullable)
		if err != nil {
			return false, fmt.Errorf("inspect client download version nullability: %w", err)
		}
		return strings.EqualFold(nullable, "YES"), nil
	case DialectMySQL:
		var nullable string
		err := db.sql.QueryRow(`SELECT is_nullable FROM information_schema.columns
			WHERE table_schema = DATABASE() AND table_name = 'client_download_link' AND column_name = 'version'`).Scan(&nullable)
		if err != nil {
			return false, fmt.Errorf("inspect client download version nullability: %w", err)
		}
		return strings.EqualFold(nullable, "YES"), nil
	}
	return false, fmt.Errorf("client_download_link.version column is missing")
}

func (db *DB) makeClientDownloadVersionNullable() error {
	switch db.dialect {
	case DialectSQLite:
		tx, err := db.sql.Begin()
		if err != nil {
			return fmt.Errorf("begin nullable client download version migration: %w", err)
		}
		defer func() { _ = tx.Rollback() }()
		for _, statement := range []string{
			`ALTER TABLE client_download_link RENAME COLUMN version TO version_legacy_not_null`,
			`ALTER TABLE client_download_link ADD COLUMN version VARCHAR(32)`,
			`UPDATE client_download_link SET version = version_legacy_not_null`,
			`ALTER TABLE client_download_link DROP COLUMN version_legacy_not_null`,
		} {
			if _, err := tx.Exec(statement); err != nil {
				return fmt.Errorf("make SQLite client download version nullable: %w", err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit nullable client download version migration: %w", err)
		}
		return nil
	case DialectPostgres:
		_, err := db.sql.Exec(`ALTER TABLE client_download_link ALTER COLUMN version DROP NOT NULL`)
		if err != nil {
			return fmt.Errorf("make PostgreSQL client download version nullable: %w", err)
		}
		return nil
	case DialectMySQL:
		_, err := db.sql.Exec(`ALTER TABLE client_download_link MODIFY COLUMN version VARCHAR(32) NULL`)
		if err != nil {
			return fmt.Errorf("make MySQL client download version nullable: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported database dialect %q", db.dialect)
	}
}

func (db *DB) dropIndexIfExists(indexName, table string) error {
	if db.dialect == DialectMySQL {
		var count int
		if err := db.sql.QueryRow(`SELECT COUNT(*) FROM information_schema.statistics
			WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?`, table, indexName).Scan(&count); err != nil {
			return fmt.Errorf("inspect index %s: %w", indexName, err)
		}
		if count == 0 {
			return nil
		}
		if _, err := db.sql.Exec(fmt.Sprintf("DROP INDEX %s ON %s", indexName, table)); err != nil {
			return fmt.Errorf("drop index %s: %w", indexName, err)
		}
		return nil
	}
	if _, err := db.sql.Exec(fmt.Sprintf("DROP INDEX IF EXISTS %s", indexName)); err != nil {
		return fmt.Errorf("drop index %s: %w", indexName, err)
	}
	return nil
}

// backfillClientDownloadLatestSlots converts the boolean marker into a nullable unique slot. The
// slot closes the race where two concurrent transactions could both clear and then mark different
// rows latest. If a pre-constraint database already contains duplicates, the oldest row keeps the
// marker and the remaining rows are safely demoted before the unique index is created.
func (db *DB) backfillClientDownloadLatestSlots() error {
	type row struct {
		id                             int64
		implementation, platform, arch string
		version                        sql.NullString
		latest, enabled                databaseBoolean
	}
	rows, err := db.sql.Query(`SELECT id, implementation, platform, arch, version, is_latest, enabled
		FROM client_download_link ORDER BY id`)
	if err != nil {
		return fmt.Errorf("list client download latest slots: %w", err)
	}
	var catalog []row
	for rows.Next() {
		var item row
		if err := rows.Scan(&item.id, &item.implementation, &item.platform, &item.arch, &item.version,
			&item.latest, &item.enabled); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan client download latest slot: %w", err)
		}
		catalog = append(catalog, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return fmt.Errorf("begin client download latest slot migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// Clear every persisted slot before rebuilding it from the in-memory snapshot. This prevents a
	// stale slot on a later invalid row from colliding with the valid winner while the unique index
	// from a partially upgraded schema is still present.
	if _, err := tx.Exec(`UPDATE client_download_link SET latest_slot = NULL`); err != nil {
		return fmt.Errorf("clear client download latest slots: %w", err)
	}
	seen := make(map[string]struct{})
	for _, item := range catalog {
		_, validVersion := normalizeStoredClientDownloadVersion(item.version.String)
		if !bool(item.latest) || !bool(item.enabled) || !item.version.Valid || !validVersion {
			if _, err := tx.Exec(db.rebind(`UPDATE client_download_link
				SET is_latest = ?, latest_slot = NULL WHERE id = ?`), 0, item.id); err != nil {
				return fmt.Errorf("clear client download latest slot %d: %w", item.id, err)
			}
			continue
		}
		slot := clientDownloadLatestSlot(item.implementation, item.platform, item.arch)
		if _, duplicate := seen[slot]; duplicate {
			if _, err := tx.Exec(db.rebind(`UPDATE client_download_link
				SET is_latest = ?, latest_slot = NULL WHERE id = ?`), 0, item.id); err != nil {
				return fmt.Errorf("demote duplicate latest client download %d: %w", item.id, err)
			}
			continue
		}
		seen[slot] = struct{}{}
		if _, err := tx.Exec(db.rebind(`UPDATE client_download_link SET latest_slot = ? WHERE id = ?`), slot, item.id); err != nil {
			return fmt.Errorf("backfill client download latest slot %d: %w", item.id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit client download latest slot migration: %w", err)
	}
	return nil
}

func clientDownloadLatestSlot(implementation, platform, arch string) string {
	return strings.ToLower(strings.TrimSpace(implementation)) + "|" +
		strings.ToLower(strings.TrimSpace(platform)) + "|" +
		strings.ToLower(strings.TrimSpace(arch))
}

var clientMessageCapabilityColumns = []string{
	"message_send_capable",
	"message_receive_capable",
	"message_attachments_capable",
	"message_media_preview_capable",
}

// ensurePostgresClientMessageCapabilityTypes upgrades the short-lived Go schema that used
// SMALLINT for these four Java boolean fields. All conversions run in one transaction so a
// startup failure cannot leave a partially converted client-session table.
func (db *DB) ensurePostgresClientMessageCapabilityTypes() error {
	if db.dialect != DialectPostgres {
		return nil
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return fmt.Errorf("begin PostgreSQL client capability migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, column := range clientMessageCapabilityColumns {
		var dataType string
		err := tx.QueryRow(`SELECT data_type FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2`,
			"specus_client_session", column).Scan(&dataType)
		if err != nil {
			return fmt.Errorf("inspect specus_client_session.%s type: %w", column, err)
		}
		switch strings.ToLower(strings.TrimSpace(dataType)) {
		case "boolean":
			continue
		case "smallint", "integer", "bigint":
			if _, err := tx.Exec(postgresClientCapabilityBooleanMigration(column)); err != nil {
				return fmt.Errorf("convert specus_client_session.%s to boolean: %w", column, err)
			}
		default:
			return fmt.Errorf("cannot safely convert specus_client_session.%s from PostgreSQL type %q to boolean", column, dataType)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit PostgreSQL client capability migration: %w", err)
	}
	return nil
}

func postgresClientCapabilityBooleanMigration(column string) string {
	return fmt.Sprintf(`ALTER TABLE specus_client_session
		ALTER COLUMN %s DROP DEFAULT,
		ALTER COLUMN %s TYPE BOOLEAN USING (%s <> 0),
		ALTER COLUMN %s SET DEFAULT FALSE,
		ALTER COLUMN %s SET NOT NULL`, column, column, column, column, column)
}

func (db *DB) ensureIndex(indexName, table, columns string) error {
	if db.dialect == DialectMySQL {
		var count int
		query := `SELECT COUNT(*) FROM information_schema.statistics
			WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?`
		if err := db.sql.QueryRow(query, table, indexName).Scan(&count); err != nil {
			return fmt.Errorf("inspect index %s: %w", indexName, err)
		}
		if count > 0 {
			return nil
		}
		if _, err := db.sql.Exec(fmt.Sprintf("CREATE INDEX %s ON %s (%s)", indexName, table, columns)); err != nil {
			return fmt.Errorf("create index %s: %w", indexName, err)
		}
		return nil
	}
	if _, err := db.sql.Exec(fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s (%s)", indexName, table, columns)); err != nil {
		return fmt.Errorf("create index %s: %w", indexName, err)
	}
	return nil
}

func (db *DB) ensureUniqueIndex(indexName, table, columns string) error {
	if db.dialect == DialectMySQL {
		var count int
		query := `SELECT COUNT(*) FROM information_schema.statistics
			WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?`
		if err := db.sql.QueryRow(query, table, indexName).Scan(&count); err != nil {
			return fmt.Errorf("inspect unique index %s: %w", indexName, err)
		}
		if count > 0 {
			return nil
		}
		if _, err := db.sql.Exec(fmt.Sprintf("CREATE UNIQUE INDEX %s ON %s (%s)", indexName, table, columns)); err != nil {
			return fmt.Errorf("create unique index %s: %w", indexName, err)
		}
		return nil
	}
	if _, err := db.sql.Exec(fmt.Sprintf("CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s (%s)", indexName, table, columns)); err != nil {
		return fmt.Errorf("create unique index %s: %w", indexName, err)
	}
	return nil
}

func (db *DB) ensureColumn(table, column, definition string) error {
	exists, err := db.columnExists(table, column)
	if err != nil {
		return fmt.Errorf("inspect column %s.%s: %w", table, column, err)
	}
	if exists {
		return nil
	}
	statement := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition)
	if _, err := db.sql.Exec(statement); err != nil {
		return fmt.Errorf("add column %s.%s: %w", table, column, err)
	}
	return nil
}

func (db *DB) columnExists(table, column string) (bool, error) {
	switch db.dialect {
	case DialectSQLite:
		rows, err := db.sql.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
		if err != nil {
			return false, err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				cid        int
				name       string
				columnType string
				notNull    int
				defaultVal sql.NullString
				pk         int
			)
			if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultVal, &pk); err != nil {
				return false, err
			}
			if strings.EqualFold(name, column) {
				return true, nil
			}
		}
		return false, rows.Err()
	case DialectPostgres:
		query := db.rebind(`SELECT COUNT(*) FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?`)
		var count int
		if err := db.sql.QueryRow(query, table, column).Scan(&count); err != nil {
			return false, err
		}
		return count > 0, nil
	case DialectMySQL:
		query := db.rebind(`SELECT COUNT(*) FROM information_schema.columns
			WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?`)
		var count int
		if err := db.sql.QueryRow(query, table, column).Scan(&count); err != nil {
			return false, err
		}
		return count > 0, nil
	default:
		return false, fmt.Errorf("unsupported database dialect %q", db.dialect)
	}
}

// splitStatements splits a schema file into individual statements on ';' boundaries,
// dropping comments and blank statements (safe for drivers that exec one statement at a time).
func splitStatements(script string) []string {
	var statements []string
	for _, raw := range strings.Split(script, ";") {
		var lines []string
		for _, line := range strings.Split(raw, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "--") {
				continue
			}
			lines = append(lines, line)
		}
		stmt := strings.TrimSpace(strings.Join(lines, "\n"))
		if stmt != "" {
			statements = append(statements, stmt)
		}
	}
	return statements
}

// rebind converts '?' placeholders to the dialect's positional form ($1.. for Postgres).
func (db *DB) rebind(query string) string {
	if db.dialect != DialectPostgres {
		return query
	}
	var builder strings.Builder
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			builder.WriteByte('$')
			builder.WriteString(strconv.Itoa(n))
			continue
		}
		builder.WriteByte(query[i])
	}
	return builder.String()
}

// formatTime renders a timestamp in the canonical ISO-8601 UTC string.
func formatTime(value time.Time) string {
	return value.UTC().Format(isoLayout)
}

// parseTime parses a stored ISO-8601 timestamp, tolerating fractional-width variants.
func parseTime(value string) time.Time {
	for _, layout := range []string{isoLayout, time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}
