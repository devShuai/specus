package store

import (
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sqliteCompatibilityChangeCounter(t *testing.T, handle *sql.DB, path string) uint32 {
	t.Helper()
	var journal, locking string
	var synchronous int
	for _, item := range []struct {
		query string
		value any
	}{
		{"PRAGMA journal_mode", &journal}, {"PRAGMA locking_mode", &locking}, {"PRAGMA synchronous", &synchronous},
	} {
		if err := handle.QueryRow(item.query).Scan(item.value); err != nil {
			t.Fatal(err)
		}
	}
	if journal != "delete" || locking != "normal" || synchronous != 2 {
		t.Fatalf("SQLite durability changed: %s/%s/%d", journal, locking, synchronous)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var header [100]byte
	if _, err := file.ReadAt(header[:], 0); err != nil {
		t.Fatal(err)
	}
	if string(header[:16]) != "SQLite format 3\x00" || header[18] != 1 || header[19] != 1 {
		t.Fatal("expected ordinary rollback-journal SQLite file")
	}
	return binary.BigEndian.Uint32(header[24:28])
}

func TestSQLiteFreshOpenBoundsDurableCommitsAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.db")
	db, err := Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	changes := sqliteCompatibilityChangeCounter(t, db.sql, path)
	if changes == 0 || changes > 5 {
		t.Fatalf("fresh schema made %d durable change boundaries, want at most five without weakening durability", changes)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := sqliteCompatibilityChangeCounter(t, reopened.sql, path); got != changes {
		t.Fatalf("reopening an empty current schema changed its durable counter: %d -> %d", changes, got)
	}
}

func TestSQLiteUniqueIndexBatchRollsBackAndEnforcesBothConstraints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unique.db")
	db, err := Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.sql.Exec(`CREATE TABLE fixture_first (value TEXT);
		CREATE TABLE fixture_second (value TEXT);
		INSERT INTO fixture_first VALUES ('preserve-first');
		INSERT INTO fixture_second VALUES ('preserve-second')`); err != nil {
		t.Fatal(err)
	}
	indexes := []schemaIndex{{"fixture_unique_first", "fixture_first", "value"}, {"fixture_unique_second", "fixture_second", "missing_column"}}
	if err := db.ensureUniqueIndexes(indexes); err == nil || !strings.Contains(err.Error(), "missing_column") {
		t.Fatalf("expected real late CREATE failure, got %v", err)
	}
	var count int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('fixture_unique_first','fixture_unique_second')`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed unique batch retained %d indexes: %v", count, err)
	}
	before := sqliteCompatibilityChangeCounter(t, db.sql, path)
	indexes[1].columns = "value"
	if err := db.ensureUniqueIndexes(indexes); err != nil {
		t.Fatal(err)
	}
	if got := sqliteCompatibilityChangeCounter(t, db.sql, path) - before; got != 1 {
		t.Fatalf("unique batch made %d durable change boundaries, want one", got)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for _, item := range []struct{ table, value string }{{"fixture_first", "preserve-first"}, {"fixture_second", "preserve-second"}} {
		var value string
		if err := reopened.sql.QueryRow("SELECT value FROM " + item.table).Scan(&value); err != nil || value != item.value {
			t.Fatalf("existing row changed: %q / %v", value, err)
		}
		if _, err := reopened.sql.Exec("INSERT INTO "+item.table+" (value) VALUES (?)", item.value); err == nil {
			t.Fatalf("unique constraint not enforced after reopen: %s", item.table)
		}
	}
}

func TestSQLiteDeferredCompatibilityIndexesRollBackWithLaterFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deferred.db")
	db, err := Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.sql.Exec(`CREATE TABLE fixture_preserved (value TEXT);
		INSERT INTO fixture_preserved VALUES ('keep');
		DROP INDEX idx_transfer_attachment_public_room;
		DROP INDEX idx_transfer_attachment_public_room_status;
		DROP INDEX idx_specus_connection_stat_tenant;
		DROP INDEX idx_tcp_frame_tenant_channel_id;
		ALTER TABLE specus_tcp_traffic_frame RENAME COLUMN channel_id TO legacy_channel_id`); err != nil {
		t.Fatal(err)
	}
	if err := db.ensureCompatibleColumns(); err == nil || !strings.Contains(err.Error(), "channel_id") {
		t.Fatalf("expected real final compatibility CREATE failure: %v", err)
	}
	var count int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN
		('idx_transfer_attachment_public_room','idx_transfer_attachment_public_room_status','idx_specus_connection_stat_tenant','idx_tcp_frame_tenant_channel_id')`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("late failure retained %d earlier batch indexes: %v", count, err)
	}
	if _, err := db.sql.Exec(`ALTER TABLE specus_tcp_traffic_frame RENAME COLUMN legacy_channel_id TO channel_id`); err != nil {
		t.Fatal(err)
	}
	if err := db.ensureCompatibleColumns(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for _, item := range []schemaIndex{
		{"idx_transfer_attachment_public_room", "transfer_attachment", "scope,public_transfer_room_id,id"},
		{"idx_transfer_attachment_public_room_status", "transfer_attachment", "scope,public_transfer_room_id,status"},
		{"idx_specus_connection_stat_tenant", "specus_connection_stat", "tenant_id"},
		{"idx_tcp_frame_tenant_channel_id", "specus_tcp_traffic_frame", "tenant_id,channel_id,id"},
	} {
		unique, columns, err := reopened.indexDefinition(item.table, item.name)
		if err != nil || unique || strings.Join(columns, ",") != item.columns {
			t.Fatalf("repaired index %s differs: %v / %v / %v", item.name, unique, columns, err)
		}
	}
	var value string
	if err := reopened.sql.QueryRow("SELECT value FROM fixture_preserved").Scan(&value); err != nil || value != "keep" {
		t.Fatalf("existing row changed: %q / %v", value, err)
	}
}

func TestSQLiteConcurrentFreshOpenKeepsCompatibilityIndexes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared-bootstrap.db")
	start := make(chan struct{})
	type result struct {
		db  *DB
		err error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			db, err := Open("sqlite", path)
			results <- result{db, err}
		}()
	}
	close(start)
	for range 2 {
		opened := <-results
		if opened.err != nil {
			t.Errorf("concurrent fresh bootstrap: %v", opened.err)
			continue
		}
		for _, item := range []struct {
			table, index, columns string
			unique                bool
		}{
			{"client_download_link", "uq_client_download_target_version", "implementation,platform,arch,version", true},
			{"client_download_link", "uq_client_download_latest_slot", "latest_slot", true},
			{"transfer_attachment", "idx_transfer_attachment_public_room", "scope,public_transfer_room_id,id", false},
			{"transfer_attachment", "idx_transfer_attachment_public_room_status", "scope,public_transfer_room_id,status", false},
			{"specus_connection_stat", "idx_specus_connection_stat_tenant", "tenant_id", false},
		} {
			unique, columns, err := opened.db.indexDefinition(item.table, item.index)
			if err != nil || unique != item.unique || strings.Join(columns, ",") != item.columns {
				t.Errorf("concurrent bootstrap index %s: %v / %v / %v", item.index, unique, columns, err)
			}
		}
		if err := opened.db.Close(); err != nil {
			t.Error(err)
		}
	}
}
