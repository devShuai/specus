package store

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func requireOwnerSerialization(t *testing.T, err error) {
	t.Helper()
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "40001" {
		t.Fatalf("old PostgreSQL RR snapshot was not rejected: %v", err)
	}
}

func TestOwnerTransferCoreExternalProvider(t *testing.T) {
	db, ctx := openOwnedStartupProviderDB(t)
	actor := ownerWriteFixture(t, db, 2)
	if db.dialect == DialectMySQL {
		// Java/Hibernate BIT(1), not merely Go's fresh TINYINT shape. The union snapshot must
		// decode the actual driver values without treating the binary byte as text "true".
		for _, table := range []string{"specus_client_account", "specus_client_credential", "peer_mesh_device", "specus_management_user"} {
			if _, err := db.sql.ExecContext(ctx, `ALTER TABLE `+table+` MODIFY enabled BIT(1) NOT NULL`); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := db.sql.ExecContext(ctx, `UPDATE specus_client_credential SET enabled=1 WHERE id=501`); err != nil {
		t.Fatal(err)
	}
	credentialBefore, err := db.FindCredentialByAPIKey(ctx, "secret-marker-api-key")
	if err != nil || credentialBefore == nil {
		t.Fatal(err)
	}
	var oldTargetSnapshot *sql.Tx
	if db.dialect == DialectPostgres {
		oldTargetSnapshot, err = db.sql.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		defer oldTargetSnapshot.Rollback()
		var count int
		if err := oldTargetSnapshot.QueryRowContext(ctx, `SELECT COUNT(*) FROM specus_client_account WHERE owner_username='Bob'`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("prime target snapshot: %d / %v", count, err)
		}
	}
	request := ownerWriteRequest(t, db, actor, OwnerScopeGroup, 501, "bOB", 99001)
	out, err := db.TransferClientOwnership(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Response.Changed || out.Response.TargetUsername != "Bob" || len(out.Response.AffectedClientIDs) != 2 || ownerAuditCount(t, db) != 1 {
		t.Fatalf("native group transfer: %+v", out)
	}
	if oldTargetSnapshot != nil {
		target, err := db.FindManagementUserByLogin(ctx, "default", "Bob")
		if err != nil || target == nil {
			t.Fatal(err)
		}
		_, err = oldTargetSnapshot.ExecContext(ctx, db.rebind(`DELETE FROM specus_management_user WHERE username=?`), target.AccountKey)
		requireOwnerSerialization(t, err)
		_ = oldTargetSnapshot.Rollback()
	}
	noop := ownerWriteRequest(t, db, actor, OwnerScopeGroup, 501, "Bob", 99002)
	if out, err := db.TransferClientOwnership(ctx, noop); err != nil || out.Response.Changed || out.AuditID != nil || ownerAuditCount(t, db) != 1 {
		t.Fatalf("native noop: %+v / %v", out, err)
	}
	reverse := ownerWriteRequest(t, db, actor, OwnerScopeGroup, 501, "ADMIN", 99001) // Existing audit ID injects a real last-step constraint failure.
	if _, err := db.TransferClientOwnership(ctx, reverse); err == nil {
		t.Fatal("native duplicate audit unexpectedly committed")
	}
	client, err := db.GetClient(ctx, 1001)
	if err != nil || client.OwnerUsername != "Bob" || ownerAuditCount(t, db) != 1 {
		t.Fatalf("native audit failure left partial transfer: %+v / %v", client, err)
	}
	reverse.AuditID = 99003
	if out, err := db.TransferClientOwnership(ctx, reverse); err != nil || out.Response.TargetUsername != "admin" || !out.Response.Changed {
		t.Fatalf("native builtin target: %+v / %v", out, err)
	}
	var oldCredentialSnapshot *sql.Tx
	if db.dialect == DialectPostgres {
		oldCredentialSnapshot, err = db.sql.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		defer oldCredentialSnapshot.Rollback()
		var count int
		if err := oldCredentialSnapshot.QueryRowContext(ctx, `SELECT COUNT(*) FROM specus_client_identity WHERE credential_id=501`).Scan(&count); err != nil || count != 2 {
			t.Fatalf("prime identity snapshot: %d / %v", count, err)
		}
	}
	now := time.Now()
	_, created, _, err := db.ResolveClientStartup(ctx, *credentialBefore, ClientAccount{ID: 80001, ClientName: "late-device", PasswordHash: "fixture-hash", Enabled: true, CreatedAt: now, UpdatedAt: now}, ClientIdentity{ID: 81001, MachineFingerprint: "late-machine", OSUser: "fixture", Hostname: "late-host", FirstSeenAt: now, LastSeenAt: now})
	if err != nil || created.OwnerUsername != "admin" {
		t.Fatalf("old credential object resurrected old owner: %+v / %v", created, err)
	}
	if oldCredentialSnapshot != nil {
		_, err = oldCredentialSnapshot.ExecContext(ctx, `UPDATE specus_client_credential SET enabled=enabled WHERE id=501`)
		requireOwnerSerialization(t, err)
		_ = oldCredentialSnapshot.Rollback()
	}
	var oldParentSnapshot *sql.Tx
	if db.dialect == DialectPostgres {
		oldParentSnapshot, err = db.sql.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		defer oldParentSnapshot.Rollback()
		var count int
		if err := oldParentSnapshot.QueryRowContext(ctx, `SELECT COUNT(*) FROM peer_mesh_device WHERE client_id=80001`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("prime peer snapshot: %d / %v", count, err)
		}
	}
	seed := PeerDeviceSeed{ID: 82001, CIDR: "100.96.0.0/11", Now: now, CandidateIP: func(ClientAccount, uint64) (string, error) { return "100.96.10.1", nil }}
	device, err := db.ObservePeerMeshDevice(ctx, created.TenantID, created.ID, seed, func(*PeerMeshDevice) {})
	if err != nil || device.OwnerUsername != "admin" {
		t.Fatalf("native peer parent: %+v / %v", device, err)
	}
	if oldParentSnapshot != nil {
		_, err = oldParentSnapshot.ExecContext(ctx, `UPDATE specus_client_account SET enabled=enabled WHERE id=80001`)
		requireOwnerSerialization(t, err)
		_ = oldParentSnapshot.Rollback()
	}
	var detail string
	if err := db.sql.QueryRowContext(ctx, `SELECT detail_json FROM client_owner_transfer_audit WHERE id=99001`).Scan(&detail); err != nil || strings.Contains(detail, "secret-marker") {
		t.Fatalf("native audit detail missing/sensitive: %v", err)
	}
	t.Logf("native owner core PASS: dialect=%s group/canonical/noop/audit-rollback/builtin/stale-credential/current-peer/RR-publication", db.dialect)
}
