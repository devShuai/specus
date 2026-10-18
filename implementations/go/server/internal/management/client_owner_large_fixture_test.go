package management

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// This is deterministic fixture construction, not the ownership operation under test.
// Keep every row and FULL/DELETE durability, but commit once before the real HTTP reads.
func seedLargeOwnerSnapshotFixture(t *testing.T, h *workbenchHarness, data store.OwnerTransferSnapshot) {
	t.Helper()
	if err := writeLargeOwnerSnapshotFixture(h.ctx, h.dbPath, data, time.Now()); err != nil {
		t.Fatal(err)
	}
}

type ownerFixtureExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func writeLargeOwnerSnapshotFixture(ctx context.Context, path string, data store.OwnerTransferSnapshot, now time.Time) error {
	connection, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer connection.Close()
	connection.SetMaxOpenConns(1)
	if _, err := connection.ExecContext(ctx, "PRAGMA busy_timeout = 5000"); err != nil {
		return err
	}
	tx, err := connection.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := writeLargeOwnerSnapshotRows(ctx, tx, data, now); err != nil {
		return err
	}
	return tx.Commit()
}

func writeLargeOwnerSnapshotRows(ctx context.Context, writer ownerFixtureExecutor, data store.OwnerTransferSnapshot, now time.Time) error {
	if len(data.Peers) != 0 {
		return fmt.Errorf("large preview fixture does not create peer rows")
	}
	text := func(value *string) string {
		if value == nil {
			return ""
		}
		return *value
	}
	bit := func(enabled bool) int {
		if enabled {
			return 1
		}
		return 0
	}
	stamp := now.UTC().Format("2006-01-02T15:04:05.0000000Z")
	for _, row := range data.Clients {
		if row.TenantID == "" || text(row.OwnerUsername) == "" {
			return fmt.Errorf("large fixture must explicitly bind each client tenant and owner")
		}
		if _, err := writer.ExecContext(ctx, `INSERT INTO specus_client_account
			(id, tenant_id, owner_username, client_name, password_hash, enabled,
			 connection_rate_limit_per_minute, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, row.ID, row.TenantID,
			text(row.OwnerUsername), text(row.ClientName), "secret-marker-password", bit(row.Enabled), 0, stamp, stamp); err != nil {
			return err
		}
	}
	for _, row := range data.Credentials {
		if row.TenantID == "" || text(row.OwnerUsername) == "" {
			return fmt.Errorf("large fixture must explicitly bind its credential tenant and owner")
		}
		if _, err := writer.ExecContext(ctx, `INSERT INTO specus_client_credential
			(id, tenant_id, owner_username, api_key, secret_hash, enabled,
			 max_online_instances, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, row.ID, row.TenantID,
			text(row.OwnerUsername), fmt.Sprint("secret-marker-key-", row.ID), "secret-marker-hash", bit(row.Enabled), 5, stamp, stamp); err != nil {
			return err
		}
	}
	for _, row := range data.Identities {
		if row.TenantID == "" {
			return fmt.Errorf("large fixture must explicitly bind each identity tenant")
		}
		if _, err := writer.ExecContext(ctx, `INSERT INTO specus_client_identity
			(id, tenant_id, credential_id, client_id, client_name, machine_fingerprint, os_user,
			 hostname, first_seen_at, last_seen_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, row.ID, row.TenantID,
			row.CredentialID, row.ClientID, fmt.Sprint("identity-", row.ID),
			fmt.Sprint("secret-marker-fingerprint-", row.ID), "test", "", stamp, stamp); err != nil {
			return err
		}
	}
	return nil
}

func ownerLargeFixtureRows(count int) store.OwnerTransferSnapshot {
	data := store.OwnerTransferSnapshot{Credentials: []store.OwnerTransferCredential{{ID: 501, TenantID: "t1", OwnerUsername: ownerText("alice"), Enabled: false}}}
	for n := 0; n < count; n++ {
		id := int64(1001 + n)
		data.Clients = append(data.Clients, store.OwnerTransferClient{ID: id, TenantID: "t1", ClientName: ownerText(fmt.Sprint("device-", n)), OwnerUsername: ownerText("alice"), Enabled: n%2 == 0})
		data.Identities = append(data.Identities, store.OwnerTransferIdentity{ID: int64(10001 + n), TenantID: "t1", CredentialID: 501, ClientID: id})
	}
	return data
}

// See SQLite fileformat2.html section 1.3.6. The counter is observed only in the
// existing rollback-journal mode, never in WAL and never after weakening durability.
func ownerFixtureChangeCounter(t *testing.T, connection *sql.DB, path string) uint32 {
	t.Helper()
	var journal, locking string
	var synchronous int
	for _, item := range []struct {
		query string
		value any
	}{{"PRAGMA journal_mode", &journal}, {"PRAGMA locking_mode", &locking}, {"PRAGMA synchronous", &synchronous}} {
		if err := connection.QueryRow(item.query).Scan(item.value); err != nil {
			t.Fatal(err)
		}
	}
	if journal != "delete" || locking != "normal" || synchronous != 2 {
		t.Fatalf("fixture durability changed: %s/%s/%d", journal, locking, synchronous)
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
		t.Fatal("expected ordinary rollback-journal SQLite fixture")
	}
	return binary.BigEndian.Uint32(header[24:28])
}

func TestOwnerLargeFixtureDurableAndComplete(t *testing.T) {
	h := newWorkbenchHTTPHarness(t)
	observer, err := sql.Open("sqlite", h.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	now := time.Date(2026, 10, 18, 0, 0, 0, 123456789, time.UTC)
	stamp := "2026-10-18T00:00:00.1234567Z"
	before := ownerFixtureChangeCounter(t, observer, h.dbPath)
	start := time.Now()
	if err := writeLargeOwnerSnapshotFixture(h.ctx, h.dbPath, ownerLargeFixtureRows(1050), now); err != nil {
		t.Fatal(err)
	}
	after := ownerFixtureChangeCounter(t, observer, h.dbPath)
	var clients, identities, credentials int
	if err := observer.QueryRow(`SELECT COUNT(*) FROM specus_client_account
		WHERE id BETWEEN 1001 AND 2050 AND tenant_id='t1' AND owner_username='alice'
		AND client_name='device-'||(id-1001) AND password_hash='secret-marker-password'
		AND enabled=((id-1001)%2=0) AND connection_rate_limit_per_minute=0
		AND created_at=? AND updated_at=?`, stamp, stamp).Scan(&clients); err != nil {
		t.Fatal(err)
	}
	if err := observer.QueryRow(`SELECT COUNT(*) FROM specus_client_identity
		WHERE id BETWEEN 10001 AND 11050 AND tenant_id='t1' AND credential_id=501
		AND client_id=id-9000 AND client_name='identity-'||id
		AND machine_fingerprint='secret-marker-fingerprint-'||id AND os_user='test'
		AND hostname='' AND first_seen_at=? AND last_seen_at=?`, stamp, stamp).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if err := observer.QueryRow(`SELECT COUNT(*) FROM specus_client_credential
		WHERE id=501 AND tenant_id='t1' AND owner_username='alice' AND api_key='secret-marker-key-501'
		AND secret_hash='secret-marker-hash' AND enabled=0 AND max_online_instances=5
		AND created_at=? AND updated_at=?`, stamp, stamp).Scan(&credentials); err != nil {
		t.Fatal(err)
	}
	if clients != 1050 || identities != 1050 || credentials != 1 {
		t.Fatalf("independent full-field readback differs: %d/%d/%d", clients, identities, credentials)
	}
	if after-before != 1 {
		t.Fatalf("fixture made %d durable change boundaries, want one for all2101 rows", after-before)
	}
	t.Logf("all2101 fixture rows independently verified after one durable transaction in %s", time.Since(start))
}

func TestOwnerLargeFixtureRollback(t *testing.T) {
	h := newWorkbenchHTTPHarness(t)
	data := ownerLargeFixtureRows(2)
	data.Identities[1].ID = data.Identities[0].ID
	if err := writeLargeOwnerSnapshotFixture(h.ctx, h.dbPath, data, time.Now()); err == nil {
		t.Fatal("duplicate identity did not fail fixture construction")
	}
	observer, err := sql.Open("sqlite", h.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	for _, query := range []string{
		"SELECT COUNT(*) FROM specus_client_account WHERE id IN (1001,1002)",
		"SELECT COUNT(*) FROM specus_client_credential WHERE id=501",
		"SELECT COUNT(*) FROM specus_client_identity WHERE id=10001",
	} {
		var count int
		if err := observer.QueryRow(query).Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed fixture left partial rows: %d / %v", count, err)
		}
	}
}
