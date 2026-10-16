package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func peerWriteFixture(t *testing.T, db *DB) (ClientAccount, ManagementWriteActor, PeerDeviceSeed) {
	t.Helper()
	now := time.Now().UTC()
	parent := ClientAccount{ID: 91001, TenantID: "peer-write", OwnerUsername: "alice", ClientName: "current-client",
		PasswordHash: "hash", Enabled: true, ConnectionRateLimitPerMinute: 30, CreatedAt: now, UpdatedAt: now}
	if err := db.InsertClient(context.Background(), parent); err != nil {
		t.Fatal(err)
	}
	user, err := db.InsertManagementUser(context.Background(), ManagementUser{Username: "alice", TenantID: parent.TenantID,
		Role: ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	actor := ManagementWriteActor{Username: user.Username, TenantID: user.TenantID, AccountKey: user.AccountKey}
	seed := PeerDeviceSeed{ID: 92001, CIDR: "100.96.0.0/30", Now: now,
		CandidateIP: func(_ ClientAccount, probe uint64) (string, error) {
			if probe >= 2 {
				return "", errors.New("pool exhausted")
			}
			return fmt.Sprintf("100.96.0.%d", probe+1), nil
		}}
	return parent, actor, seed
}

func TestPeerObservationSealsScopeAndPreservesCurrentMetadata(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	parent, actor, seed := peerWriteFixture(t, db)
	created, err := db.ObservePeerMeshDevice(ctx, parent.TenantID, parent.ID, seed, func(device *PeerMeshDevice) {
		device.ID, device.ClientID, device.TenantID = 9, 8, "spoofed"
		device.Enabled, device.VirtualIP, device.CIDR = true, "127.0.0.1", "127.0.0.0/8"
		device.OwnerUsername, device.ClientName, device.CreatedAt = "spoofed", "spoofed", time.Time{}
		key, nat := "current-key", "SYMMETRIC"
		device.PublicKey, device.NatType = &key, &nat
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != seed.ID || created.ClientID != parent.ID || created.TenantID != parent.TenantID ||
		created.OwnerUsername != parent.OwnerUsername || created.ClientName != parent.ClientName ||
		created.Enabled || created.VirtualIP != "100.96.0.1" || created.CIDR != seed.CIDR || created.CreatedAt.IsZero() {
		t.Fatalf("runtime observer changed sealed scope: %+v", created)
	}
	on := true
	if _, err := db.SetPeerMeshDeviceEnabled(ctx, actor, parent.ID, &on, time.Now()); err != nil {
		t.Fatal(err)
	}
	current, err := db.ObservePeerMeshDevice(ctx, parent.TenantID, parent.ID, seed, func(device *PeerMeshDevice) {
		device.Enabled, device.PublicKey = false, created.PublicKey
		mode := "TUN"
		device.VirtualDeviceMode = &mode
	})
	if err != nil || !current.Enabled || current.PublicKey == nil || *current.PublicKey != "current-key" ||
		current.NatType == nil || *current.NatType != "SYMMETRIC" || current.VirtualDeviceMode == nil || *current.VirtualDeviceMode != "TUN" {
		t.Fatalf("observation lost current flag/key/metadata: %+v / %v", current, err)
	}
}

func TestPeerEnabledEditRevalidatesCurrentActor(t *testing.T) {
	for _, scenario := range []string{"disabled", "deleted-rebound", "renamed", "tenant", "downgraded", "oidc-rebound", "builtin-forged", "unbound"} {
		t.Run(scenario, func(t *testing.T) {
			db := provisionTestDB(t)
			ctx := context.Background()
			parent, actor, seed := peerWriteFixture(t, db)
			if _, err := db.ObservePeerMeshDevice(ctx, parent.TenantID, parent.ID, seed, func(*PeerMeshDevice) {}); err != nil {
				t.Fatal(err)
			}
			user, err := db.FindManagementUserByAccountKey(ctx, actor.AccountKey)
			if err != nil || user == nil {
				t.Fatalf("actor: %v", err)
			}
			switch scenario {
			case "disabled":
				user.Enabled = false
				if err := db.UpdateManagementUser(ctx, *user); err != nil {
					t.Fatal(err)
				}
			case "deleted-rebound":
				if _, err := db.sql.ExecContext(ctx, `DELETE FROM specus_management_user WHERE username = ?`, actor.AccountKey); err != nil {
					t.Fatal(err)
				}
				user.AccountKey = "different-account-key"
				if _, err := db.InsertManagementUser(ctx, *user); err != nil {
					t.Fatal(err)
				}
			case "renamed":
				if _, err := db.sql.ExecContext(ctx, `UPDATE specus_management_user SET login_name = 'renamed', login_name_normalized = 'renamed' WHERE username = ?`, actor.AccountKey); err != nil {
					t.Fatal(err)
				}
			case "tenant":
				if _, err := db.sql.ExecContext(ctx, `UPDATE specus_management_user SET tenant_id = 'other' WHERE username = ?`, actor.AccountKey); err != nil {
					t.Fatal(err)
				}
			case "downgraded":
				actor.Admin = true // Captured while admin; the locked current row is USER.
				parent.OwnerUsername = "different-owner"
				if err := db.UpdateClient(ctx, parent); err != nil {
					t.Fatal(err)
				}
			case "oidc-rebound":
				actor.OIDCIdentityKey, actor.OIDCIssuer, actor.OIDCSubject = "same-key", "https://issuer.example", "old-subject"
				user.OIDCIdentityKey, user.OIDCIssuer, user.OIDCSubject = actor.OIDCIdentityKey, actor.OIDCIssuer, "changed-subject"
				if err := db.UpdateManagementUser(ctx, *user); err != nil {
					t.Fatal(err)
				}
			case "builtin-forged":
				actor.BuiltIn, actor.Admin = true, true // DB identity must never masquerade as configured admin.
			case "unbound":
				actor.AccountKey = ""
			}
			on := true
			_, err = db.SetPeerMeshDeviceEnabled(ctx, actor, parent.ID, &on, time.Now())
			want := ErrManagementActorChanged
			if scenario == "downgraded" {
				want = ErrNotFound
			}
			if !errors.Is(err, want) {
				t.Fatalf("stale actor authorized %s: %v", scenario, err)
			}
			device, err := db.FindPeerMeshDeviceByClientID(ctx, parent.TenantID, parent.ID)
			if err != nil || device == nil || device.Enabled {
				t.Fatalf("rejected edit changed peer: %+v / %v", device, err)
			}
		})
	}
}

func TestPeerObservationWaitsForCurrentParentAcrossHandles(t *testing.T) {
	for _, scenario := range []string{"owner", "delete", "actor-disable"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "peer.db")
			writer, err := Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			reader, err := Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			parent, actor, seed := peerWriteFixture(t, writer)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := writer.ObservePeerMeshDevice(ctx, parent.TenantID, parent.ID, seed, func(device *PeerMeshDevice) {
				key := "preserved-key"
				device.PublicKey = &key
			}); err != nil {
				t.Fatal(err)
			}
			tx, err := writer.beginClientOwnershipWrite(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			switch scenario {
			case "owner":
				_, err = tx.ExecContext(ctx, `UPDATE specus_client_account SET owner_username = 'new-owner', client_name = 'new-name' WHERE id = ?`, parent.ID)
			case "delete":
				_, err = tx.ExecContext(ctx, `DELETE FROM specus_client_account WHERE id = ?`, parent.ID)
				if err == nil {
					_, err = tx.ExecContext(ctx, `DELETE FROM peer_mesh_device WHERE client_id = ?`, parent.ID)
				}
			case "actor-disable":
				_, err = tx.ExecContext(ctx, `UPDATE specus_management_user SET enabled = 0 WHERE username = ?`, actor.AccountKey)
			}
			if err != nil {
				t.Fatal(err)
			}
			type outcome struct {
				device *PeerMeshDevice
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				if scenario == "actor-disable" {
					on := true
					device, err := reader.SetPeerMeshDeviceEnabled(ctx, actor, parent.ID, &on, time.Now())
					done <- outcome{device, err}
				} else {
					device, err := reader.ObservePeerMeshDevice(ctx, parent.TenantID, parent.ID, seed, func(*PeerMeshDevice) {})
					done <- outcome{device, err}
				}
			}()
			select {
			case result := <-done:
				t.Fatalf("write escaped uncommitted parent/actor: %+v", result)
			case <-time.After(100 * time.Millisecond):
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			result := <-done
			if scenario == "owner" {
				if result.err != nil || result.device.OwnerUsername != "new-owner" || result.device.ClientName != "new-name" || result.device.Enabled || result.device.PublicKey == nil || *result.device.PublicKey != "preserved-key" {
					t.Fatalf("stale peer state after commit: %+v / %v", result.device, result.err)
				}
			} else {
				want := ErrNotFound
				if scenario == "actor-disable" {
					want = ErrManagementActorChanged
				}
				if !errors.Is(result.err, want) {
					t.Fatalf("post-commit write authorized: %v", result.err)
				}
			}
		})
	}
}

func TestPeerAddressPoolGuardsAndAtomicFailure(t *testing.T) {
	for _, scenario := range []string{"network", "broadcast", "outside", "invalid", "insert-failure"} {
		t.Run(scenario, func(t *testing.T) {
			db := provisionTestDB(t)
			ctx := context.Background()
			parent, _, seed := peerWriteFixture(t, db)
			if scenario == "insert-failure" {
				if _, err := db.sql.ExecContext(ctx, `CREATE TRIGGER fail_peer_insert BEFORE INSERT ON peer_mesh_device BEGIN SELECT RAISE(ABORT, 'injected peer insert failure'); END`); err != nil {
					t.Fatal(err)
				}
			} else {
				address := map[string]string{"network": "100.96.0.0", "broadcast": "100.96.0.3", "outside": "127.0.0.1", "invalid": "bad-ip"}[scenario]
				seed.CandidateIP = func(ClientAccount, uint64) (string, error) { return address, nil }
			}
			if _, err := db.ObservePeerMeshDevice(ctx, parent.TenantID, parent.ID, seed, func(*PeerMeshDevice) {}); err == nil {
				t.Fatal("invalid allocation/insertion accepted")
			}
			device, err := db.FindPeerMeshDeviceByClientID(ctx, parent.TenantID, parent.ID)
			if err != nil || device != nil {
				t.Fatalf("failed write left peer row: %+v / %v", device, err)
			}
		})
	}
}
