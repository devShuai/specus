package store

import (
	"errors"
	"testing"
	"time"
)

func TestPeerDeviceExternalProvider(t *testing.T) {
	db, ctx := openOwnedStartupProviderDB(t)
	parent, actor, seed := peerWriteFixture(t, db)
	user, err := db.FindManagementUserByAccountKey(ctx, actor.AccountKey)
	if err != nil || user == nil {
		t.Fatalf("actor: %v", err)
	}
	user.Role = ManagementRoleAdmin
	if err := db.UpdateManagementUser(ctx, *user); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ObservePeerMeshDevice(ctx, parent.TenantID, parent.ID, seed, func(device *PeerMeshDevice) {
		key := "current-key"
		device.PublicKey = &key
	}); err != nil {
		t.Fatal(err)
	}
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := db.startupClientOn(ctx, tx, parent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, db.rebind(`UPDATE specus_client_account SET owner_username = ?, client_name = ? WHERE id = ?`),
		"committed-owner", "committed-name", parent.ID); err != nil {
		t.Fatal(err)
	}
	type result struct {
		device *PeerMeshDevice
		err    error
	}
	done := make(chan result, 1)
	go func() {
		device, err := db.ObservePeerMeshDevice(ctx, parent.TenantID, parent.ID, seed, func(*PeerMeshDevice) {})
		done <- result{device, err}
	}()
	select {
	case got := <-done:
		t.Fatalf("native observation escaped parent lock: %v", got.err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if got.err != nil || got.device.OwnerUsername != "committed-owner" || got.device.ClientName != "committed-name" ||
		got.device.Enabled || got.device.PublicKey == nil || *got.device.PublicKey != "current-key" {
		t.Fatalf("native observation restored stale state: %+v / %v", got.device, got.err)
	}
	on := true
	// The captured Admin=false bit is not authoritative: current persisted role is ADMIN.
	if _, err := db.SetPeerMeshDeviceEnabled(ctx, actor, parent.ID, &on, time.Now()); err != nil {
		t.Fatal(err)
	}
	tx, err = db.beginClientOwnershipWrite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, db.rebind(`UPDATE specus_management_user SET enabled = 0 WHERE username = ?`), actor.AccountKey); err != nil {
		t.Fatal(err)
	}
	go func() {
		off := false
		device, err := db.SetPeerMeshDeviceEnabled(ctx, actor, parent.ID, &off, time.Now())
		done <- result{device, err}
	}()
	select {
	case got := <-done:
		t.Fatalf("native edit escaped actor lock: %v", got.err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := <-done; !errors.Is(got.err, ErrManagementActorChanged) {
		t.Fatalf("disabled native actor authorized: %v", got.err)
	}
	current, err := db.FindPeerMeshDeviceByClientID(ctx, parent.TenantID, parent.ID)
	if err != nil || current == nil || !current.Enabled || current.PublicKey == nil || *current.PublicKey != "current-key" {
		t.Fatalf("rejected native edit changed peer: %+v / %v", current, err)
	}
	now := time.Now().UTC()
	target := parent
	target.ID++
	target.ClientName = "peer-target"
	if err := db.InsertClient(ctx, target); err != nil {
		t.Fatal(err)
	}
	session := PeerMeshSession{ID: 93001, TenantID: parent.TenantID, SourceClientID: parent.ID,
		SourceClientName: "committed-name", TargetClientID: target.ID, TargetClientName: target.ClientName,
		PathType: "DIRECT", Status: "ACTIVE", StartedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := db.InsertPeerMeshSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	stale, err := db.GetPeerMeshSession(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpdatePeerMeshSession(ctx, *stale); err != nil {
		t.Fatalf("native no-op update treated as missing/closed: %v", err)
	}
	closed := *stale
	closed.Status, closed.ClosedAt = "CLOSED", &now
	if err := db.UpdatePeerMeshSession(ctx, closed); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdatePeerMeshSession(ctx, *stale); !errors.Is(err, ErrPeerMeshSessionClosed) {
		t.Fatalf("native stale write reopened closed grant: %v", err)
	}
	if err := db.UpdatePeerMeshSession(ctx, closed); err != nil {
		t.Fatalf("native repeated close not idempotent: %v", err)
	}
	durable, err := db.GetPeerMeshSession(ctx, session.ID)
	if err != nil || durable.Status != "CLOSED" || durable.ClosedAt == nil {
		t.Fatalf("native close not durable: %+v / %v", durable, err)
	}
	t.Logf("native peer write boundary PASS: dialect=%s parent-lock/current-owner/actor-lock/disabled-actor/noop/closed-monotonic", db.dialect)
}
