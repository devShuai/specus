package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientAuthNonceSupportsLegacyJavaSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-java-nonce.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE specus_client_auth_nonce (
		id TEXT PRIMARY KEY,
		api_key_hash TEXT NOT NULL,
		expires_at TEXT NOT NULL
	)`)
	if closeErr := legacy.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("prepare Java nonce schema: %v", err)
	}

	db, err := Open("sqlite", path)
	if err != nil {
		t.Fatalf("open Java nonce schema: %v", err)
	}
	defer db.Close()
	if db.clientAuthNonceLayout != clientAuthNonceLayoutJavaID {
		t.Fatalf("nonce layout = %d, want Java ID", db.clientAuthNonceLayout)
	}

	ctx := context.Background()
	now := time.Date(2026, 7, 23, 8, 0, 0, 0, time.UTC)
	const apiKeyHash = "api-key-hash"
	const nonce = "client-nonce"
	consumed, err := db.ConsumeClientAuthNonce(ctx, apiKeyHash, nonce, now, now.Add(2*time.Minute))
	if err != nil || !consumed {
		t.Fatalf("first Java nonce consume: consumed=%v err=%v", consumed, err)
	}
	consumed, err = db.ConsumeClientAuthNonce(ctx, apiKeyHash, nonce, now, now.Add(2*time.Minute))
	if err != nil || consumed {
		t.Fatalf("duplicate Java nonce consume: consumed=%v err=%v", consumed, err)
	}

	digest := sha256.Sum256([]byte(apiKeyHash + "\n" + nonce))
	expectedID := hex.EncodeToString(digest[:])
	var storedID string
	if err := db.sql.QueryRow(`SELECT id FROM specus_client_auth_nonce WHERE api_key_hash = ?`,
		apiKeyHash).Scan(&storedID); err != nil {
		t.Fatalf("read Java nonce id: %v", err)
	}
	if storedID != expectedID {
		t.Fatalf("Java nonce id = %q, want %q", storedID, expectedID)
	}
}

func TestFreshSchemaUsesJavaClientAuthNonceLayout(t *testing.T) {
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "fresh-nonce.db"))
	if err != nil {
		t.Fatalf("open fresh nonce schema: %v", err)
	}
	defer db.Close()
	if db.clientAuthNonceLayout != clientAuthNonceLayoutJavaID {
		t.Fatalf("nonce layout = %d, want Java ID", db.clientAuthNonceLayout)
	}

	ctx := context.Background()
	now := time.Date(2026, 7, 23, 8, 0, 0, 0, time.UTC)
	consumed, err := db.ConsumeClientAuthNonce(ctx, "api-key-hash", "client-nonce", now, now.Add(2*time.Minute))
	if err != nil || !consumed {
		t.Fatalf("first fresh nonce consume: consumed=%v err=%v", consumed, err)
	}
	consumed, err = db.ConsumeClientAuthNonce(ctx, "api-key-hash", "client-nonce", now, now.Add(2*time.Minute))
	if err != nil || consumed {
		t.Fatalf("duplicate fresh nonce consume: consumed=%v err=%v", consumed, err)
	}
}

func TestClientAuthNonceStillSupportsLegacyCompositeSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "composite-nonce.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE specus_client_auth_nonce (
		api_key_hash TEXT NOT NULL,
		nonce_hash TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		created_at TEXT NOT NULL,
		PRIMARY KEY (api_key_hash, nonce_hash)
	)`)
	if closeErr := legacy.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("prepare composite nonce schema: %v", err)
	}

	db, err := Open("sqlite", path)
	if err != nil {
		t.Fatalf("open composite nonce schema: %v", err)
	}
	defer db.Close()
	if db.clientAuthNonceLayout != clientAuthNonceLayoutComposite {
		t.Fatalf("nonce layout = %d, want composite", db.clientAuthNonceLayout)
	}

	now := time.Date(2026, 7, 23, 8, 0, 0, 0, time.UTC)
	consumed, err := db.ConsumeClientAuthNonce(context.Background(), "api-key-hash", "client-nonce",
		now, now.Add(2*time.Minute))
	if err != nil || !consumed {
		t.Fatalf("first composite nonce consume: consumed=%v err=%v", consumed, err)
	}
}

func TestStartupMigrationAddsPeerMeshACLDirectionWithJavaDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-acl.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE peer_mesh_acl (
		id INTEGER PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		owner_username TEXT NOT NULL,
		source_client_id INTEGER NOT NULL,
		source_client_name TEXT NOT NULL,
		target_client_id INTEGER NOT NULL,
		target_client_name TEXT NOT NULL,
		allowed INTEGER NOT NULL DEFAULT 1,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		UNIQUE (tenant_id, source_client_id, target_client_id)
	)`)
	if err == nil {
		_, err = legacy.Exec(`INSERT INTO peer_mesh_acl
			(id, tenant_id, owner_username, source_client_id, source_client_name,
			 target_client_id, target_client_name, allowed, created_at, updated_at)
			VALUES (1, 'tenant-a', 'Alice', 10, 'source', 20, 'target', 1,
			 '2026-07-10T00:00:00.0000000Z', '2026-07-10T00:00:00.0000000Z')`)
	}
	if closeErr := legacy.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("prepare legacy schema: %v", err)
	}

	db, err := Open("sqlite", path)
	if err != nil {
		t.Fatalf("open and migrate legacy database: %v", err)
	}
	defer db.Close()
	acl, err := db.FindPeerMeshACL(context.Background(), "tenant-a", 10, 20)
	if err != nil || acl == nil {
		t.Fatalf("read migrated ACL: acl=%+v err=%v", acl, err)
	}
	if acl.Direction != "OUTBOUND" {
		t.Fatalf("legacy ACL direction = %q, want OUTBOUND", acl.Direction)
	}
}

func TestStartupMigrationExpandsJavaWebSocketTicketSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-java-ticket.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE specus_websocket_ticket (
		token_hash TEXT PRIMARY KEY,
		scope TEXT NOT NULL,
		attributes_json TEXT NOT NULL,
		remote_address_hash TEXT,
		created_at TEXT NOT NULL,
		expires_at TEXT NOT NULL
	)`)
	if closeErr := legacy.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("prepare Java websocket ticket schema: %v", err)
	}

	db, err := Open("sqlite", path)
	if err != nil {
		t.Fatalf("open and migrate Java websocket ticket schema: %v", err)
	}
	defer db.Close()

	now := time.Date(2026, 7, 23, 6, 0, 0, 0, time.UTC)
	ticket := WebSocketTicket{
		TokenHash: "go-ticket", Scope: "public-transfer", RoomID: "room-a", RoomKey: "room:7",
		RoomRole: "EDITOR", PeerID: "peer-a", DisplayName: "Go peer", SharedRoom: true,
		RemoteAddressHash: "address-hash", CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	if err := db.InsertWebSocketTicket(context.Background(), ticket); err != nil {
		t.Fatalf("insert ticket after Java schema migration: %v", err)
	}
	var attributesJSON string
	if err := db.sql.QueryRow(`SELECT attributes_json FROM specus_websocket_ticket
		WHERE token_hash = ?`, ticket.TokenHash).Scan(&attributesJSON); err != nil {
		t.Fatalf("read Java attributes_json: %v", err)
	}
	var attributes map[string]any
	if err := json.Unmarshal([]byte(attributesJSON), &attributes); err != nil {
		t.Fatalf("decode Java attributes_json: %v", err)
	}
	if attributes["roomId"] != ticket.RoomID || attributes["peerId"] != ticket.PeerID ||
		attributes["sharedRoom"] != true {
		t.Fatalf("unexpected Java attributes: %#v", attributes)
	}
	consumed, err := db.ConsumeWebSocketTicket(context.Background(), ticket.TokenHash,
		ticket.Scope, ticket.RemoteAddressHash, now)
	if err != nil || consumed == nil || consumed.RoomKey != ticket.RoomKey ||
		consumed.RoomRole != ticket.RoomRole {
		t.Fatalf("consume migrated Go ticket: ticket=%+v err=%v", consumed, err)
	}

	legacyAttributes := `{"roomId":"legacy-room","roomKey":"room:42","roomRole":"VIEWER",` +
		`"peerId":"legacy-peer","displayName":"Java peer","sharedRoom":true}`
	_, err = db.sql.Exec(`INSERT INTO specus_websocket_ticket
		(token_hash, scope, attributes_json, remote_address_hash, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		"java-ticket", "public-transfer", legacyAttributes, "java-address",
		formatTime(now), formatTime(now.Add(time.Minute)))
	if err != nil {
		t.Fatalf("insert legacy Java ticket: %v", err)
	}
	consumed, err = db.ConsumeWebSocketTicket(context.Background(), "java-ticket",
		"public-transfer", "java-address", now)
	if err != nil || consumed == nil || consumed.PeerID != "legacy-peer" ||
		consumed.RoomRole != "VIEWER" || !consumed.SharedRoom {
		t.Fatalf("consume legacy Java ticket: ticket=%+v err=%v", consumed, err)
	}
}

func TestPostgresClientMessageCapabilitySchemaUsesJavaBooleanColumns(t *testing.T) {
	data, err := schemaFS.ReadFile("schema/postgres.sql")
	if err != nil {
		t.Fatal(err)
	}
	schema := string(data)
	for _, column := range clientMessageCapabilityColumns {
		want := column + " BOOLEAN NOT NULL DEFAULT FALSE"
		if !strings.Contains(schema, want) {
			t.Errorf("PostgreSQL schema missing %q", want)
		}
		if strings.Contains(schema, column+" SMALLINT") {
			t.Errorf("PostgreSQL schema still defines %s as SMALLINT", column)
		}
		migration := postgresClientCapabilityBooleanMigration(column)
		for _, fragment := range []string{
			"ALTER COLUMN " + column + " DROP DEFAULT",
			"ALTER COLUMN " + column + " TYPE BOOLEAN USING (" + column + " <> 0)",
			"ALTER COLUMN " + column + " SET DEFAULT FALSE",
			"ALTER COLUMN " + column + " SET NOT NULL",
		} {
			if !strings.Contains(migration, fragment) {
				t.Errorf("migration for %s missing %q: %s", column, fragment, migration)
			}
		}
	}
}

func TestMySQLHTTPTrafficSchemaKeepsWideCaptureFieldsOffRow(t *testing.T) {
	data, err := schemaFS.ReadFile("schema/mysql.sql")
	if err != nil {
		t.Fatal(err)
	}
	schema := string(data)
	const tablePrefix = "CREATE TABLE IF NOT EXISTS specus_http_traffic_exchange ("
	tableStart := strings.Index(schema, tablePrefix)
	if tableStart < 0 {
		t.Fatal("MySQL schema is missing specus_http_traffic_exchange")
	}
	tableEnd := strings.Index(schema[tableStart:], "\n) ENGINE=InnoDB")
	if tableEnd < 0 {
		t.Fatal("MySQL specus_http_traffic_exchange definition is incomplete")
	}
	tableSchema := schema[tableStart : tableStart+tableEnd]
	for _, column := range []string{
		"relative_path",
		"raw_query",
		"error",
		"request_headers",
		"response_headers",
		"request_preview_hex",
		"response_preview_hex",
	} {
		if !strings.Contains(tableSchema, column+" TEXT") {
			t.Errorf("MySQL schema must define wide capture field %s as TEXT", column)
		}
		if strings.Contains(tableSchema, column+" VARCHAR") {
			t.Errorf("MySQL schema still defines wide capture field %s as VARCHAR", column)
		}
	}
}

func TestClientMessageCapabilitySQLUsesPostgresBooleanValuesAndPredicate(t *testing.T) {
	postgres := &DB{dialect: DialectPostgres}
	if value, ok := postgres.clientMessageCapabilityValue(true).(bool); !ok || !value {
		t.Fatalf("PostgreSQL capability value = %#v, want bool true", postgres.clientMessageCapabilityValue(true))
	}
	if got := postgres.clientMessageReceivePredicate(); got != "message_receive_capable" {
		t.Fatalf("PostgreSQL receive predicate = %q", got)
	}

	sqlite := &DB{dialect: DialectSQLite}
	if value, ok := sqlite.clientMessageCapabilityValue(true).(int); !ok || value != 1 {
		t.Fatalf("SQLite capability value = %#v, want integer 1", sqlite.clientMessageCapabilityValue(true))
	}
	if got := sqlite.clientMessageReceivePredicate(); got != "message_receive_capable <> 0" {
		t.Fatalf("SQLite receive predicate = %q", got)
	}
}
