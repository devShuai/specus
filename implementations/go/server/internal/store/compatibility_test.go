package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

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
