package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func peerAdmissionFixture(t *testing.T, db *DB, base int64, tenant, owner string) (PeerClientReference, PeerClientReference) {
	t.Helper()
	now := time.Now()
	ctx := context.Background()
	for i, name := range []string{"admission-source", "admission-target"} {
		id := base + int64(i)
		client := ClientAccount{ID: id, TenantID: tenant, OwnerUsername: owner, ClientName: name + "-" + tenant, PasswordHash: "fixture-hash", Enabled: true, CreatedAt: now, UpdatedAt: now}
		if err := db.InsertClient(ctx, client); err != nil {
			t.Fatal(err)
		}
		if err := db.InsertPeerMeshDevice(ctx, PeerMeshDevice{ID: id + 10000, TenantID: tenant, OwnerUsername: owner, ClientID: id, ClientName: client.ClientName, VirtualIP: []string{"100.122.20.1", "100.122.20.2"}[i], CIDR: "100.96.0.0/11", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	return PeerClientReference{ID: base, TenantID: tenant, ClientName: "admission-source-" + tenant}, PeerClientReference{ID: base + 1, TenantID: tenant, ClientName: "admission-target-" + tenant}
}
func peerAdmissionSeed(id int64, hash string) PeerSessionSeed {
	return PeerSessionSeed{ID: id, TokenHash: hash, PathType: "DIRECT", TTL: time.Hour}
}

func TestPeerAdmissionReuseRequiresSQLHashAndRollbackKeepsExpiryState(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	source, target := peerAdmissionFixture(t, db, 7201, "default", "alice")
	seed := peerAdmissionSeed(7401, "first-hash")
	first, err := db.AdmitPeerMeshSession(ctx, source, target, seed)
	if err != nil || !first.Created {
		t.Fatalf("new admission: %+v / %v", first, err)
	}
	reuse := peerAdmissionSeed(7402, "unused-new-hash")
	reuse.ReusableTokenHashes = map[int64]string{first.Session.ID: "first-hash"}
	out, err := db.AdmitPeerMeshSession(ctx, source, target, reuse)
	if err != nil || out.Created || out.Session.ID != first.Session.ID {
		t.Fatalf("valid cached SQL hash not reused: %+v / %v", out, err)
	}
	reuse.ReusableTokenHashes[first.Session.ID] = "wrong-hash"
	second, err := db.AdmitPeerMeshSession(ctx, source, target, reuse)
	if err != nil || !second.Created || second.Session.ID != reuse.ID {
		t.Fatalf("wrong cached token hash was trusted: %+v / %v", second, err)
	}
	past := time.Now().Add(-time.Hour)
	if _, err := db.sql.Exec(`UPDATE peer_mesh_session SET expires_at=?,direct_bytes=123,relay_bytes=456 WHERE id IN (?,?)`, formatTime(past), first.Session.ID, second.Session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec(`CREATE TRIGGER reject_admission BEFORE INSERT ON peer_mesh_session WHEN NEW.id=7403 BEGIN SELECT RAISE(ABORT,'injected new grant failure'); END`); err != nil {
		t.Fatal(err)
	}
	out, err = db.AdmitPeerMeshSession(ctx, source, target, peerAdmissionSeed(7403, "third-hash"))
	if err == nil || out.Session.ID != 0 || len(out.ClosedIDs) != 0 {
		t.Fatalf("failed admission exposed effects: %+v / %v", out, err)
	}
	for _, id := range []int64{first.Session.ID, second.Session.ID} {
		row, err := db.GetPeerMeshSession(ctx, id)
		if err != nil || row.Status == "CLOSED" || row.ClosedAt != nil || row.DirectBytes != 123 || row.RelayBytes != 456 {
			t.Fatalf("failed insert partially closed/rewrote existing grant: %+v / %v", row, err)
		}
	}
	if _, err := db.sql.Exec(`DROP TRIGGER reject_admission`); err != nil {
		t.Fatal(err)
	}
	out, err = db.AdmitPeerMeshSession(ctx, source, target, peerAdmissionSeed(7403, "third-hash"))
	if err != nil || !out.Created || len(out.ClosedIDs) != 2 {
		t.Fatalf("expired grants not atomically replaced: %+v / %v", out, err)
	}
	for _, id := range []int64{first.Session.ID, second.Session.ID} {
		row, err := db.GetPeerMeshSession(ctx, id)
		if err != nil || row.Status != "CLOSED" || row.ClosedAt == nil || row.DirectBytes != 123 || row.RelayBytes != 456 {
			t.Fatalf("expiry closure lost counters/state: %+v / %v", row, err)
		}
	}
}

func TestPeerAdmissionCurrentDirectionAndExactParentIdentity(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	source, target := peerAdmissionFixture(t, db, 7201, "default", "Alice")
	if _, err := db.sql.Exec(`UPDATE specus_client_account SET owner_username='alice' WHERE id=?`, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AdmitPeerMeshSession(ctx, source, target, peerAdmissionSeed(7401, "hash")); !errors.Is(err, ErrPeerAccessDenied) {
		t.Fatalf("case-distinct owner bypassed current ACL: %v", err)
	}
	now := time.Now()
	acl := PeerMeshACL{ID: 7501, TenantID: "default", OwnerUsername: "admin", SourceClientID: source.ID, SourceClientName: source.ClientName, TargetClientID: target.ID, TargetClientName: target.ClientName, Direction: "INBOUND", Allowed: true, CreatedAt: now, UpdatedAt: now}
	if err := db.InsertPeerMeshACL(ctx, acl); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AdmitPeerMeshSession(ctx, source, target, peerAdmissionSeed(7401, "hash")); !errors.Is(err, ErrPeerAccessDenied) {
		t.Fatalf("INBOUND granted forward: %v", err)
	}
	if _, err := db.AdmitPeerMeshSession(ctx, target, source, peerAdmissionSeed(7402, "reverse-hash")); err != nil {
		t.Fatalf("INBOUND denied reverse: %v", err)
	}
	acl.Direction = "OUTBOUND"
	if err := db.UpdatePeerMeshACL(ctx, acl); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AdmitPeerMeshSession(ctx, source, target, peerAdmissionSeed(7403, "forward-hash")); err != nil {
		t.Fatal(err)
	}
	wrongTenant := target
	wrongTenant.TenantID = "DEFAULT"
	if _, err := db.AdmitPeerMeshSession(ctx, source, wrongTenant, peerAdmissionSeed(7404, "wrong-tenant-hash")); !errors.Is(err, ErrPeerAccessDenied) {
		t.Fatalf("case-distinct tenant authorized: %v", err)
	}
	root := ManagementWriteActor{Username: "admin", TenantID: "default", Admin: true, BuiltIn: true}
	name := "renamed-admission-source"
	if _, err := db.PatchManagedClient(ctx, root, source.ID, ManagementClientPatch{ClientName: &name}, now, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AdmitPeerMeshSession(ctx, source, target, peerAdmissionSeed(7404, "wrong-name-hash")); !errors.Is(err, ErrPeerAccessDenied) {
		t.Fatalf("renamed alias rebound: %v", err)
	}
	source.ClientName = name
	out, err := db.AdmitPeerMeshSession(ctx, source, target, peerAdmissionSeed(7404, "fresh-name-hash"))
	if err != nil || out.Session.SourceClientName != name || len(out.ClosedIDs) != 2 {
		t.Fatalf("fresh reference/stale name closure: %+v / %v", out, err)
	}
}

func TestDisabledPeerClosureRollsBackAndDoesNotCloseForeignScope(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	source, target := peerAdmissionFixture(t, db, 7201, "default", "alice")
	out, err := db.AdmitPeerMeshSession(ctx, source, target, peerAdmissionSeed(7401, "hash"))
	if err != nil {
		t.Fatal(err)
	}
	foreign := out.Session
	foreign.ID = 7402
	foreign.TenantID = "DEFAULT"
	foreign.TokenHash = nil
	if err := db.InsertPeerMeshSession(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	root := ManagementWriteActor{Username: "admin", TenantID: "default", Admin: true, BuiltIn: true}
	off := false
	if _, err := db.SetPeerMeshDeviceEnabled(ctx, root, source.ID, &off, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec(`CREATE TRIGGER reject_disabled_close BEFORE UPDATE ON peer_mesh_session WHEN NEW.status='CLOSED' BEGIN SELECT RAISE(ABORT,'injected closure failure'); END`); err != nil {
		t.Fatal(err)
	}
	if closed, err := db.CloseDisabledPeerMeshSessions(ctx, "default", source.ID); err == nil || len(closed) != 0 {
		t.Fatalf("failed closure exposed effects: %+v / %v", closed, err)
	}
	row, err := db.GetPeerMeshSession(ctx, out.Session.ID)
	if err != nil || row.Status == "CLOSED" {
		t.Fatalf("failed close persisted: %+v / %v", row, err)
	}
	if _, err := db.sql.Exec(`DROP TRIGGER reject_disabled_close`); err != nil {
		t.Fatal(err)
	}
	closed, err := db.CloseDisabledPeerMeshSessions(ctx, "default", source.ID)
	if err != nil || len(closed) != 1 || closed[0].ID != out.Session.ID {
		t.Fatalf("wrong scoped closure: %+v / %v", closed, err)
	}
	row, err = db.GetPeerMeshSession(ctx, foreign.ID)
	if err != nil || row.Status == "CLOSED" {
		t.Fatalf("foreign case scope changed: %+v / %v", row, err)
	}
	on := true
	if _, err := db.SetPeerMeshDeviceEnabled(ctx, root, source.ID, &on, time.Now()); err != nil {
		t.Fatal(err)
	}
	fresh, err := db.AdmitPeerMeshSession(ctx, source, target, peerAdmissionSeed(7403, "fresh-hash"))
	if err != nil {
		t.Fatal(err)
	}
	if closed, err := db.CloseDisabledPeerMeshSessions(ctx, "default", source.ID); err != nil || len(closed) != 0 {
		t.Fatalf("reenabled grants closed: %+v / %v", closed, err)
	}
	row, err = db.GetPeerMeshSession(ctx, fresh.Session.ID)
	if err != nil || row.Status == "CLOSED" {
		t.Fatalf("fresh valid grant closed: %+v / %v", row, err)
	}
}

func TestPeerAdmissionExternalProvider(t *testing.T) {
	db, ctx := openOwnedStartupProviderDB(t)
	source, target := peerAdmissionFixture(t, db, 721001, "default", "native-peer-owner")
	now := time.Now()
	owner, err := db.InsertManagementUser(ctx, ManagementUser{Username: "native-peer-new-owner", TenantID: "default", Role: ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	root := ManagementWriteActor{Username: "admin", TenantID: "default", Admin: true, BuiltIn: true}
	request := ownerWriteRequest(t, db, root, OwnerScopeSingle, target.ID, owner.Username, 990501)
	hold, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Rollback()
	if _, err := db.lockClientForOwnership(ctx, hold, "default", source.ID); err != nil {
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
	done := make(chan error, 1)
	go func() {
		_, err := db.AdmitPeerMeshSession(ctx, source, target, peerAdmissionSeed(751001, "native-peer-hash"))
		done <- err
	}()
	_ = waitManagedNativeBlocker(t, db, ctx, blocker)
	// A real transfer commits on a separate parent while the real admission is still
	// blocked at its first parent. Admission must observe the committed new owner afterwards.
	if _, err := db.TransferClientOwnership(ctx, request); err != nil {
		t.Fatal(err)
	}
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrPeerAccessDenied) {
		t.Fatalf("native admission used pre-transfer owner: %v", err)
	}
	if allowed, err := db.CheckPeerAccessCurrent(ctx, source, target); err != nil || allowed {
		t.Fatalf("native snapshot used stale owner: %v / %v", allowed, err)
	}
	if err := db.InsertPeerMeshACL(ctx, PeerMeshACL{ID: 741001, TenantID: "default", OwnerUsername: "admin", SourceClientID: source.ID, SourceClientName: source.ClientName, TargetClientID: target.ID, TargetClientName: target.ClientName, Allowed: true, Direction: "OUTBOUND", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	hash := "foreign-case-hash"
	foreign := PeerMeshSession{ID: 751099, TenantID: "DEFAULT", SourceClientID: source.ID, SourceClientName: source.ClientName, TargetClientID: target.ID, TargetClientName: target.ClientName, PathType: "DIRECT", Status: "ACTIVE", TokenHash: &hash, StartedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := db.InsertPeerMeshSession(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	seed := peerAdmissionSeed(751001, "native-peer-hash")
	seed.ReusableTokenHashes = map[int64]string{foreign.ID: hash}
	first, err := db.AdmitPeerMeshSession(ctx, source, target, seed)
	if err != nil || !first.Created || first.Session.ID != seed.ID {
		t.Fatalf("native valid ACL/foreign cache boundary: %+v / %v", first, err)
	}
	reuse := peerAdmissionSeed(751002, "unused-new-hash")
	reuse.ReusableTokenHashes = map[int64]string{first.Session.ID: seed.TokenHash}
	if out, err := db.AdmitPeerMeshSession(ctx, source, target, reuse); err != nil || out.Created || out.Session.ID != first.Session.ID {
		t.Fatalf("native SQL-bound reuse: %+v / %v", out, err)
	}
	if closed, err := db.CloseDisabledPeerMeshSessions(ctx, "default", source.ID); err != nil || len(closed) != 0 {
		t.Fatalf("native enabled close: %+v / %v", closed, err)
	}
	off := false
	if _, err := db.SetPeerMeshDeviceEnabled(ctx, root, source.ID, &off, time.Now()); err != nil {
		t.Fatal(err)
	}
	closed, err := db.CloseDisabledPeerMeshSessions(ctx, "default", source.ID)
	if err != nil || len(closed) != 1 || closed[0].ID != first.Session.ID {
		t.Fatalf("native disabled close wrong scope: %+v / %v", closed, err)
	}
	row, err := db.GetPeerMeshSession(ctx, foreign.ID)
	if err != nil || row.Status != "ACTIVE" {
		t.Fatalf("native case-distinct tenant mutated: %+v / %v", row, err)
	}
	if _, err := db.AdmitPeerMeshSession(ctx, source, target, peerAdmissionSeed(751003, "disabled-new-hash")); !errors.Is(err, ErrPeerAccessDenied) {
		t.Fatalf("native disabled admission: %v", err)
	}
	on := true
	if _, err := db.SetPeerMeshDeviceEnabled(ctx, root, source.ID, &on, time.Now()); err != nil {
		t.Fatal(err)
	}
	fresh, err := db.AdmitPeerMeshSession(ctx, source, target, peerAdmissionSeed(751003, "fresh-new-hash"))
	if err != nil || !fresh.Created {
		t.Fatalf("native reenable admission: %+v / %v", fresh, err)
	}
	if closed, err := db.CloseDisabledPeerMeshSessions(ctx, "default", source.ID); err != nil || len(closed) != 0 {
		t.Fatalf("native fresh grant closed: %+v / %v", closed, err)
	}
	roster, err := db.ListCurrentPeerRoster(ctx, source)
	if err != nil || len(roster) != 1 || roster[0].ClientID != target.ID {
		t.Fatalf("native current scoped directional roster: %+v / %v", roster, err)
	}
	t.Logf("native peer admission PASS: dialect=%s actual-parent-wait/real-owner-transfer/current-direction/SQL-hash-reuse/exact-tenant/disable-reenable", db.dialect)
}
