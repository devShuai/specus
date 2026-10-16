package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

// Observe an actual engine lock wait, not a goroutine-start signal or a timing assumption.
// The blocker connection is captured from this test's own transaction in the disposable DB.
func waitManagedNativeBlocker(t *testing.T, db *DB, ctx context.Context, blocker int64) int64 {
	t.Helper()
	query := `SELECT a.pid FROM pg_stat_activity a WHERE a.datname=current_database()
		AND a.wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(a.pid)) LIMIT 1`
	if db.dialect == DialectMySQL {
		query = `SELECT requesting.PROCESSLIST_ID FROM performance_schema.data_lock_waits w
		JOIN performance_schema.threads requesting ON requesting.THREAD_ID=w.REQUESTING_THREAD_ID
		JOIN performance_schema.threads blocking ON blocking.THREAD_ID=w.BLOCKING_THREAD_ID
		WHERE blocking.PROCESSLIST_ID=? LIMIT 1`
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiter int64
		err := db.sql.QueryRowContext(ctx, query, blocker).Scan(&waiter)
		if err == nil {
			return waiter
		}
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("owned backend %d never acquired an actual engine waiter: %v", blocker, ctx.Err())
		case <-ticker.C:
		}
	}
}

func TestManagedResourcesExternalProvider(t *testing.T) {
	db, ctx := openOwnedStartupProviderDB(t)
	now := time.Now()
	root := ManagementWriteActor{Username: "admin", TenantID: "default", Admin: true, BuiltIn: true}
	manager, err := db.InsertManagementUser(ctx, ManagementUser{Username: "native-managed-source", TenantID: "default", Role: ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	target, err := db.InsertManagementUser(ctx, ManagementUser{Username: "native-managed-target", TenantID: "default", Role: ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	actor := ManagementWriteActor{Username: manager.Username, TenantID: manager.TenantID, AccountKey: manager.AccountKey}
	credential, err := db.CreateManagedCredential(ctx, actor, ClientCredential{ID: 611001, TenantID: "foreign", OwnerUsername: "spoofed", APIKey: "native-managed-key", SecretHash: "native-managed-hash", Enabled: true, MaxOnlineInstances: 7, CreatedAt: now, UpdatedAt: now})
	if err != nil || credential.OwnerUsername != manager.Username || credential.TenantID != "default" {
		t.Fatalf("native create: %+v / %v", credential, err)
	}
	client, err := db.CreateManagedClient(ctx, actor, ClientAccount{ID: 611002, TenantID: "foreign", OwnerUsername: "spoofed", ClientName: "native-managed-device", PasswordHash: "native-managed-client-hash", Enabled: true, ConnectionRateLimitPerMinute: 23, CreatedAt: now, UpdatedAt: now})
	if err != nil || client.OwnerUsername != manager.Username || client.TenantID != "default" {
		t.Fatalf("native create: %+v / %v", client, err)
	}
	if err := db.InsertIdentity(ctx, ClientIdentity{ID: 611003, TenantID: "default", CredentialID: credential.ID, ClientID: client.ID, ClientName: client.ClientName, MachineFingerprint: "native-managed-machine", OSUser: "fixture", FirstSeenAt: now, LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	request := ownerWriteRequest(t, db, root, OwnerScopeGroup, credential.ID, target.Username, 990111)

	// Hold the credential; the ACTUAL transfer takes the target lock and waits behind it.
	// Only after observing that native wait do we start ACTUAL account deletion, which must
	// itself wait behind the transfer's target lock before checking current ownership counts.
	hold, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Rollback()
	if _, err := db.lockCredentialForOwnership(ctx, hold, "default", credential.ID); err != nil {
		t.Fatal(err)
	}
	var blocker int64
	pidQuery := `SELECT pg_backend_pid()`
	if db.dialect == DialectMySQL {
		pidQuery = `SELECT CONNECTION_ID()`
	}
	if err := hold.QueryRowContext(ctx, pidQuery).Scan(&blocker); err != nil {
		t.Fatal(err)
	}
	transferDone := make(chan error, 1)
	go func() { _, err := db.TransferClientOwnership(ctx, request); transferDone <- err }()
	transferBackend := waitManagedNativeBlocker(t, db, ctx, blocker)
	deleteDone := make(chan error, 1)
	go func() { _, err := db.DeleteManagedUser(ctx, root, target, now.Unix(), nil); deleteDone <- err }()
	deleteBackend := waitManagedNativeBlocker(t, db, ctx, transferBackend)
	if transferBackend == deleteBackend || transferBackend == blocker || deleteBackend == blocker {
		t.Fatal("native lock chain did not use independent DB connections")
	}
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-transferDone; err != nil {
		t.Fatal(err)
	}
	var owned *AccountStillOwnsError
	if err := <-deleteDone; !errors.As(err, &owned) || owned.Clients != 1 || owned.Credentials != 1 {
		t.Fatalf("native delayed delete missed transfer: %+v / %v", owned, err)
	}
	off := false
	if _, err := db.PatchManagedClient(ctx, actor, client.ID, ManagementClientPatch{Enabled: &off}, now, now.Unix()); !errors.Is(err, ErrManagementResourceForbidden) {
		t.Fatalf("native old owner patch: %v", err)
	}
	if err := db.DeleteManagedCredential(ctx, actor, credential.ID); !errors.Is(err, ErrManagementResourceForbidden) {
		t.Fatalf("native old owner delete: %v", err)
	}
	newActor := ManagementWriteActor{Username: target.Username, TenantID: target.TenantID, AccountKey: target.AccountKey}
	key, hash := "native-managed-rotated", "native-managed-rotated-hash"
	if _, err := db.PatchManagedCredential(ctx, newActor, credential.ID, ManagementCredentialPatch{APIKey: &key, SecretHash: &hash}, now); err != nil {
		t.Fatal(err)
	}
	current, err := db.PatchManagedCredential(ctx, newActor, credential.ID, ManagementCredentialPatch{Enabled: &off}, now)
	if err != nil || current.APIKey != key || current.SecretHash != hash || current.OwnerUsername != target.Username {
		t.Fatalf("native omitted-field edit overwrote rotation/owner: %+v / %v", current, err)
	}
	if _, err := db.TransferClientOwnership(ctx, ownerWriteRequest(t, db, root, OwnerScopeGroup, credential.ID, "admin", 990112)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DeleteManagedUser(ctx, root, target, now.Unix(), nil); err != nil {
		t.Fatalf("native transferred-away account could not be deleted: %v", err)
	}
	// Rename only after transfer checks: deliberately corrupt foreign identity edges
	// stay untouched and would correctly make a later transfer preview fail closed.
	for _, device := range []PeerMeshDevice{
		{ID: 611004, TenantID: "default", OwnerUsername: "admin", ClientID: client.ID, ClientName: client.ClientName, VirtualIP: "100.126.1.254", CIDR: "100.96.0.0/11", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: 611005, TenantID: "foreign", OwnerUsername: "foreign-owner", ClientID: client.ID, ClientName: "foreign-peer-keep", VirtualIP: "100.97.1.1", CIDR: "100.96.0.0/11", Enabled: true, CreatedAt: now, UpdatedAt: now},
	} {
		if err := db.InsertPeerMeshDevice(ctx, device); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.InsertIdentity(ctx, ClientIdentity{ID: 611006, TenantID: "foreign", CredentialID: credential.ID, ClientID: client.ID, ClientName: "foreign-identity-keep", MachineFingerprint: "native-foreign-machine", OSUser: "fixture", FirstSeenAt: now, LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, db.rebind(`INSERT INTO peer_mesh_acl(id,tenant_id,owner_username,source_client_id,source_client_name,target_client_id,target_client_name,allowed,created_at,updated_at) VALUES(611007,'foreign','foreign-owner',?,'foreign-acl-keep',9001,'other-foreign-client',1,?,?)`), client.ID, formatTime(now), formatTime(now)); err != nil {
		t.Fatal(err)
	}
	name := "native-managed-renamed"
	if _, err := db.PatchManagedClient(ctx, root, client.ID, ManagementClientPatch{ClientName: &name}, now, now.Unix()); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		table, column, expected string
		id                      int64
	}{
		{"peer_mesh_device", "client_name", "foreign-peer-keep", 611005},
		{"specus_client_identity", "client_name", "foreign-identity-keep", 611006},
		{"peer_mesh_acl", "source_client_name", "foreign-acl-keep", 611007},
		{"peer_mesh_device", "client_name", name, 611004},
		{"specus_client_identity", "client_name", name, 611003},
	} {
		var actual string
		if err := db.sql.QueryRowContext(ctx, db.rebind(`SELECT `+row.column+` FROM `+row.table+` WHERE id=?`), row.id).Scan(&actual); err != nil || actual != row.expected {
			t.Fatalf("native rename scope %s: got=%q want=%q err=%v", row.table, actual, row.expected, err)
		}
	}
	if _, err := db.PatchManagedUser(ctx, root, manager, ManagementUserPatch{Enabled: &off}, now, now.Unix(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateManagedClient(ctx, actor, ClientAccount{ID: 611004, ClientName: "native-revoked-new", PasswordHash: "hash", Enabled: true, CreatedAt: now, UpdatedAt: now}); !errors.Is(err, ErrManagementActorChanged) {
		t.Fatalf("native revoked create: %v", err)
	}
	t.Logf("native managed resources PASS: dialect=%s actual3connection-lock-chain/transfer-before-delete-current-counts/current-owner/explicit-rotation/disabled-actor/tenant-scoped-rename", db.dialect)
}
