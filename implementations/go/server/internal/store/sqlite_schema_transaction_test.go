package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestSQLiteBaseSchemaRollsBackBeforeCompatibilityRepair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "failed-bootstrap.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	// A real incompatible existing table makes the embedded schema's tenant index
	// fail AFTER it has created the earlier client/session tables and indexes.
	if _, err := raw.Exec(`CREATE TABLE specus_management_user (sentinel TEXT NOT NULL);
		INSERT INTO specus_management_user VALUES ('keep-existing-data')`); err != nil {
		t.Fatal(err)
	}
	opened, err := Open("sqlite", path)
	if opened != nil {
		_ = opened.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "tenant_id") {
		t.Fatalf("expected actual embedded-schema index failure, got %v", err)
	}
	var count int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'specus_client_account'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed base schema left %d earlier client tables committed", count)
	}
	var sentinel string
	if err := raw.QueryRow(`SELECT sentinel FROM specus_management_user`).Scan(&sentinel); err != nil || sentinel != "keep-existing-data" {
		t.Fatalf("existing data changed after rollback: %q / %v", sentinel, err)
	}
	// Simulate an operator repairing the conflicting namespace without deleting
	// existing data. A new Open must not inherit a leaked transaction or pool.
	if _, err := raw.Exec(`ALTER TABLE specus_management_user RENAME TO preserved_legacy_user`); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open("sqlite", path)
	if err != nil {
		t.Fatalf("reopen after explicit repair: %v", err)
	}
	defer recovered.Close()
	if err := recovered.sql.QueryRow(`SELECT sentinel FROM preserved_legacy_user`).Scan(&sentinel); err != nil || sentinel != "keep-existing-data" {
		t.Fatalf("repair lost existing data: %q / %v", sentinel, err)
	}
}

func TestSQLiteBaseSchemaCommitsAndKeepsDurabilitySettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "committed-bootstrap.db")
	for attempt := 0; attempt < 2; attempt++ {
		db, err := Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer db.Close()
			for _, table := range []string{"specus_client_account", "specus_management_user", "specus_websocket_ticket", "peer_mesh_egress_policy", "client_owner_transfer_audit"} {
				var count int
				if err := db.sql.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&count); err != nil || count != 1 {
					t.Fatalf("committed table %s missing on open %d: %d / %v", table, attempt, count, err)
				}
			}
			var synchronous int
			var journal string
			if err := db.sql.QueryRow(`PRAGMA synchronous`).Scan(&synchronous); err != nil || synchronous != 2 {
				t.Fatalf("default FULL durability weakened: %d / %v", synchronous, err)
			}
			if err := db.sql.QueryRow(`PRAGMA journal_mode`).Scan(&journal); err != nil || journal != "delete" {
				t.Fatalf("default rollback journal changed: %q / %v", journal, err)
			}
		}()
	}
}

func BenchmarkOpenSQLiteBaseSchema(b *testing.B) {
	directory := b.TempDir()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		db, err := Open("sqlite", filepath.Join(directory, fmt.Sprintf("bootstrap-%d.db", index)))
		if err != nil {
			b.Fatal(err)
		}
		if err := db.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
