package store

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestPeerRuntimePublicationExternalProvider(t *testing.T) {
	db, ctx := openOwnedIsolatedStartupProviderDB(t, "peer_publication")
	source, target := runtimePublicationFixture(t, db)
	grant, err := db.AdmitRuntimePeerMeshSession(ctx, source, target, peerAdmissionSeed(906001, "grant-hash"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"native-runtime-bob", "native-runtime-carol"} {
		now := time.Now()
		if _, err := db.InsertManagementUser(ctx, ManagementUser{Username: name, TenantID: "default", Role: ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	root := ManagementWriteActor{Username: "admin", TenantID: "default", Admin: true, BuiltIn: true}
	holdCredential := func(id int64) (*sql.Tx, int64) {
		tx, err := db.beginClientOwnershipWrite(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback() })
		if _, err := db.lockCredentialForOwnership(ctx, tx, "default", id); err != nil {
			t.Fatal(err)
		}
		query := "SELECT pg_backend_pid()"
		if db.dialect == DialectMySQL {
			query = "SELECT CONNECTION_ID()"
		}
		var backend int64
		if err := tx.QueryRowContext(ctx, query).Scan(&backend); err != nil {
			t.Fatal(err)
		}
		return tx, backend
	}
	transfer := func(owner string, audit int64) {
		if _, err := db.TransferClientOwnership(ctx, ownerWriteRequest(t, db, root, OwnerScopeSingle, target.ClientID, owner, audit)); err != nil {
			t.Fatal(err)
		}
	}
	// Publication waits on the source credential; an independent real target transfer
	// commits before it acquires the target. The callback must not publish its old default ACL.
	hold, backend := holdCredential(source.CredentialID)
	done := make(chan error, 1)
	called := make(chan struct{}, 1)
	go func() {
		done <- db.PublishPeerSignal(ctx, source, target, grant.Session.ID, "grant-hash", func(PeerSignalPublication) error { called <- struct{}{}; return nil })
	}()
	_ = waitManagedNativeBlocker(t, db, ctx, backend)
	transfer("native-runtime-bob", 907101)
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrPeerAccessDenied) {
		t.Fatalf("native old policy published after committed target transfer: %v", err)
	}
	select {
	case <-called:
		t.Fatal("revoked native publication reached callback")
	default:
	}
	now := time.Now()
	if err := db.InsertPeerMeshACL(ctx, PeerMeshACL{ID: 909001, TenantID: "default", OwnerUsername: "admin", SourceClientID: source.ClientID, SourceClientName: source.ClientName, TargetClientID: target.ClientID, TargetClientName: target.ClientName, Allowed: true, Direction: "OUTBOUND", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	// Observe the real waiting publication backend, then prove a second transfer remains
	// blocked on that same publication while the actual send callback is in progress.
	hold, backend = holdCredential(source.CredentialID)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	go func() {
		done <- db.PublishPeerSignal(ctx, source, target, grant.Session.ID, "grant-hash", func(current PeerSignalPublication) error {
			if current.Target.OwnerUsername != "native-runtime-bob" {
				return errors.New("stale publication material")
			}
			close(entered)
			<-release
			return nil
		})
	}()
	publicationBackend := waitManagedNativeBlocker(t, db, ctx, backend)
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	<-entered
	request := ownerWriteRequest(t, db, root, OwnerScopeSingle, target.ClientID, "native-runtime-carol", 907102)
	transferDone := make(chan error, 1)
	go func() { _, err := db.TransferClientOwnership(ctx, request); transferDone <- err }()
	_ = waitManagedNativeBlocker(t, db, ctx, publicationBackend)
	select {
	case err := <-transferDone:
		t.Fatalf("native transfer overtook active publication: %v", err)
	default:
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-transferDone; err != nil {
		t.Fatal(err)
	}
	// A retained explicit outbound grant permits the authenticated reply leg, not a new
	// reverse initiation. Both controls still use their original credential/identity/token.
	if err := db.PublishPeerSignal(ctx, target, source, grant.Session.ID, "grant-hash", func(PeerSignalPublication) error { return nil }); err != nil {
		t.Fatalf("valid native reply rejected: %v", err)
	}
	if _, err := db.AdmitRuntimePeerMeshSession(ctx, target, source, peerAdmissionSeed(906002, "reverse-hash")); !errors.Is(err, ErrPeerAccessDenied) {
		t.Fatalf("reply token widened reverse initiation: %v", err)
	}
	// Session-row rebinding while a grant writer waits must fail under the final locked read.
	hold, backend = holdCredential(source.CredentialID)
	go func() {
		_, err := db.AdmitRuntimePeerMeshSession(ctx, source, target, peerAdmissionSeed(906003, "new-hash"))
		done <- err
	}()
	_ = waitManagedNativeBlocker(t, db, ctx, backend)
	if _, err := db.sql.ExecContext(ctx, db.rebind("UPDATE specus_client_session SET channel_id='replacement-channel' WHERE id=?"), source.SessionID); err != nil {
		t.Fatal(err)
	}
	if err := hold.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrPeerRuntimeChanged) {
		t.Fatalf("native immutable source followed rebound SQL: %v", err)
	}
	check, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := db.CheckPeerRuntimeCurrent(check, source); !errors.Is(err, ErrPeerRuntimeChanged) {
		t.Fatal("rebound native runtime still valid")
	}
	t.Logf("native runtime publication PASS dialect=%s actual-row-waits/committed-owner-change/locks-through-send/original-CS-binding/explicit-reply-not-reverse-initiation", db.dialect)
}
