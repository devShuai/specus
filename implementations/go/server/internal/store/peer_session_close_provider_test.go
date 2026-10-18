package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestPeerCloseExternalProvider(t *testing.T) {
	db, ctx := openOwnedStartupProviderDB(t)
	now := time.Now()
	user := func(name string, role string) ManagementUser {
		u, err := db.InsertManagementUser(ctx, ManagementUser{Username: name, TenantID: "default", Role: role, Enabled: true, CreatedAt: now, UpdatedAt: now})
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	alice := user("native-close-alice", ManagementRoleUser)
	bob := user("native-close-bob", ManagementRoleUser)
	carol := user("native-close-carol", ManagementRoleUser)
	manager := user("native-close-manager", ManagementRoleAdmin)
	actor := func(u ManagementUser) ManagementWriteActor {
		return ManagementWriteActor{Username: u.Username, TenantID: u.TenantID, AccountKey: u.AccountKey, Admin: u.Role == ManagementRoleAdmin}
	}
	root := ManagementWriteActor{Username: "admin", TenantID: "default", Admin: true, BuiltIn: true}
	client := func(id int64, name, owner, ip string) PeerClientReference {
		if err := db.InsertClient(ctx, ClientAccount{ID: id, TenantID: "default", OwnerUsername: owner, ClientName: name, PasswordHash: "close-fixture", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
		if err := db.InsertPeerMeshDevice(ctx, PeerMeshDevice{ID: id + 10000, TenantID: "default", OwnerUsername: owner, ClientID: id, ClientName: name, VirtualIP: ip, CIDR: "100.96.0.0/11", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
		return PeerClientReference{ID: id, TenantID: "default", ClientName: name}
	}
	source := client(821001, "native-close-source", alice.Username, "100.122.30.1")
	target := client(821002, "native-close-target", alice.Username, "100.122.30.2")
	grant := func(id int64, from, to PeerClientReference) PeerMeshSession {
		out, err := db.AdmitPeerMeshSession(ctx, from, to, peerAdmissionSeed(id, "native-close-hash"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.sql.ExecContext(ctx, db.rebind(`UPDATE peer_mesh_session SET status='ACTIVE',direct_bytes=11,relay_bytes=22 WHERE id=?`), out.Session.ID); err != nil {
			t.Fatal(err)
		}
		row, err := db.GetPeerMeshSession(ctx, out.Session.ID)
		if err != nil {
			t.Fatal(err)
		}
		return *row
	}
	first := grant(851001, source, target)
	transfer := func(owner string, audit int64) {
		request := ownerWriteRequest(t, db, root, OwnerScopeSingle, target.ID, owner, audit)
		if _, err := db.TransferClientOwnership(ctx, request); err != nil {
			t.Fatal(err)
		}
	}
	transfer(bob.Username, 881091)
	holdParent := func(id int64) (*sql.Tx, int64) {
		tx, err := db.beginClientOwnershipWrite(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback() })
		if _, err := db.lockClientForOwnership(ctx, tx, "default", id); err != nil {
			t.Fatal(err)
		}
		query := `SELECT pg_backend_pid()`
		if db.dialect == DialectMySQL {
			query = `SELECT CONNECTION_ID()`
		}
		var backend int64
		if err := tx.QueryRowContext(ctx, query).Scan(&backend); err != nil {
			t.Fatal(err)
		}
		return tx, backend
	}
	hold, backend := holdParent(source.ID)
	closedOwner := make(chan error, 1)
	go func() {
		_, err := db.CloseManagedPeerMeshSessions(ctx, actor(bob), PeerSessionCloseSelection{SessionID: first.ID})
		closedOwner <- err
	}()
	_ = waitManagedNativeBlocker(t, db, ctx, backend)
	transfer(carol.Username, 881092)
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-closedOwner; !errors.Is(err, ErrNotFound) {
		t.Fatalf("native stale owner closed after actual transfer: %v", err)
	}
	if row, _ := db.GetPeerMeshSession(ctx, first.ID); row.Status == "CLOSED" {
		t.Fatal("rejected native owner changed SQL")
	}

	// A callback waiting for parents must observe a newly valid explicit ACL, not its old
	// discovery decision. This also proves the relevant parent wait in the actual engine.
	hold, backend = holdParent(source.ID)
	type result struct {
		rows []PeerMeshSession
		err  error
	}
	policyDone := make(chan result, 1)
	go func() {
		rows, err := db.CloseUnauthorizedPeerMeshSessions(ctx, "default", []int64{first.ID})
		policyDone <- result{rows, err}
	}()
	_ = waitManagedNativeBlocker(t, db, ctx, backend)
	acl := PeerMeshACL{ID: 841001, TenantID: "default", OwnerUsername: "admin", SourceClientID: source.ID, SourceClientName: source.ClientName, TargetClientID: target.ID, TargetClientName: target.ClientName, Allowed: true, Direction: "OUTBOUND", CreatedAt: now, UpdatedAt: now}
	if err := db.InsertPeerMeshACL(ctx, acl); err != nil {
		t.Fatal(err)
	}
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	if out := <-policyDone; out.err != nil || len(out.rows) != 0 {
		t.Fatalf("native delayed callback closed valid ACL grant: %+v / %v", out.rows, out.err)
	}
	acl.Allowed = false
	if err := db.UpdatePeerMeshACL(ctx, acl); err != nil {
		t.Fatal(err)
	}
	if rows, err := db.CloseUnauthorizedPeerMeshSessions(ctx, "default", []int64{first.ID}); err != nil || len(rows) != 1 {
		t.Fatalf("native current denial not closed: %+v / %v", rows, err)
	}
	acl.Allowed = true
	if err := db.UpdatePeerMeshACL(ctx, acl); err != nil {
		t.Fatal(err)
	}

	fresh := grant(851002, source, target)
	hold, backend = holdParent(source.ID)
	counterDone := make(chan result, 1)
	go func() {
		rows, err := db.CloseReportedPeerMeshSession(ctx, source, fresh.ID)
		counterDone <- result{rows, err}
	}()
	_ = waitManagedNativeBlocker(t, db, ctx, backend)
	if _, err := db.sql.ExecContext(ctx, db.rebind(`UPDATE peer_mesh_session SET direct_bytes=111,relay_bytes=222,rtt_millis=7 WHERE id=?`), fresh.ID); err != nil {
		t.Fatal(err)
	}
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	if out := <-counterDone; out.err != nil || len(out.rows) != 1 || out.rows[0].DirectBytes != 111 || out.rows[0].RelayBytes != 222 || out.rows[0].RTTMillis == nil || *out.rows[0].RTTMillis != 7 {
		t.Fatalf("native close overwrote preceding current counters: %+v / %v", out.rows, out.err)
	}

	foreign := fresh
	foreign.ID = 851099
	foreign.TenantID = "DEFAULT"
	foreign.Status = "ACTIVE"
	foreign.ClosedAt = nil
	if err := db.InsertPeerMeshSession(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CloseManagedPeerMeshSessions(ctx, root, PeerSessionCloseSelection{SessionID: foreign.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("native case-distinct tenant authorized: %v", err)
	}
	grant(851003, source, target)
	grant(851004, source, target)
	if _, err := db.sql.ExecContext(ctx, `ALTER TABLE peer_mesh_session ADD CONSTRAINT ck_native_peer_close CHECK (id<>851004 OR UPPER(status)<>'CLOSED')`); err != nil {
		t.Fatal(err)
	}
	if rows, err := db.CloseManagedPeerMeshSessions(ctx, root, PeerSessionCloseSelection{ClientID: source.ID}); err == nil || len(rows) != 0 {
		t.Fatalf("native second-row constraint failure exposed partial effects: %+v / %v", rows, err)
	}
	for _, id := range []int64{851003, 851004} {
		row, err := db.GetPeerMeshSession(ctx, id)
		if err != nil || row.Status == "CLOSED" || row.ClosedAt != nil {
			t.Fatalf("native batch partially committed: %+v / %v", row, err)
		}
	}
	drop := `ALTER TABLE peer_mesh_session DROP CONSTRAINT ck_native_peer_close`
	if db.dialect == DialectMySQL {
		drop = `ALTER TABLE peer_mesh_session DROP CHECK ck_native_peer_close`
	}
	if _, err := db.sql.ExecContext(ctx, drop); err != nil {
		t.Fatal(err)
	}
	if rows, err := db.CloseManagedPeerMeshSessions(ctx, root, PeerSessionCloseSelection{ClientID: source.ID}); err != nil || len(rows) != 2 {
		t.Fatalf("native batch close failed: %+v / %v", rows, err)
	}
	if row, _ := db.GetPeerMeshSession(ctx, foreign.ID); row.Status != "ACTIVE" {
		t.Fatal("native case-distinct tenant changed by batch")
	}

	current := grant(851005, source, target)
	actorHold, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer actorHold.Rollback()
	if _, err := db.lockManagementUserKey(ctx, actorHold, "default", manager.AccountKey); err != nil {
		t.Fatal(err)
	}
	query := `SELECT pg_backend_pid()`
	if db.dialect == DialectMySQL {
		query = `SELECT CONNECTION_ID()`
	}
	if err := actorHold.QueryRowContext(ctx, query).Scan(&backend); err != nil {
		t.Fatal(err)
	}
	actorDone := make(chan error, 1)
	go func() {
		_, err := db.CloseManagedPeerMeshSessions(ctx, actor(manager), PeerSessionCloseSelection{SessionID: current.ID})
		actorDone <- err
	}()
	_ = waitManagedNativeBlocker(t, db, ctx, backend)
	if _, err := actorHold.ExecContext(ctx, db.rebind(`UPDATE specus_management_user SET role='USER' WHERE username=?`), manager.AccountKey); err != nil {
		t.Fatal(err)
	}
	if err := actorHold.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-actorDone; !errors.Is(err, ErrNotFound) {
		t.Fatalf("native stale admin closed after committed demotion: %v", err)
	}

	otherSource := client(821003, "native-close-other-source", "native-close-other", "100.122.30.3")
	otherTarget := client(821004, "native-close-other-target", "native-close-other", "100.122.30.4")
	other := grant(851006, otherSource, otherTarget)
	unrelated, _ := holdParent(otherSource.ID)
	independent, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if rows, err := db.CloseManagedPeerMeshSessions(independent, actor(alice), PeerSessionCloseSelection{}); err != nil || len(rows) != 1 || rows[0].ID != current.ID {
		t.Fatalf("user close-all locked unrelated tenant graph: %+v / %v", rows, err)
	}
	if err := unrelated.Commit(); err != nil {
		t.Fatal(err)
	}
	if row, _ := db.GetPeerMeshSession(ctx, other.ID); row.Status != "ACTIVE" {
		t.Fatal("user close-all affected unrelated owner")
	}
	before, _ := db.GetPeerMeshSession(ctx, current.ID)
	if rows, err := db.CloseManagedPeerMeshSessions(ctx, root, PeerSessionCloseSelection{SessionID: current.ID}); err != nil || len(rows) != 1 || rows[0].ClosedAt == nil || before.ClosedAt == nil || !rows[0].ClosedAt.Equal(*before.ClosedAt) {
		t.Fatalf("native repeated close changed terminal time: %+v / %v", rows, err)
	}
	t.Logf("native peer close PASS: dialect=%s real-owner-transfer/current-role-parent-waits/ACL-reenable/counters/batch-rollback/exact-tenant/unrelated-parent/idempotence", db.dialect)
}
