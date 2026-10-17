package store

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"
)

func managedResourceFixture(t *testing.T, db *DB) (ManagementWriteActor, ManagementWriteActor) {
	t.Helper()
	root := ownerWriteFixture(t, db, 1)
	now := time.Now()
	alice, err := db.InsertManagementUser(context.Background(), ManagementUser{Username: "alice", TenantID: "default", Role: ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec(`UPDATE specus_client_credential SET owner_username='alice' WHERE id=501`); err != nil {
		t.Fatal(err)
	}
	return ManagementWriteActor{Username: alice.Username, TenantID: alice.TenantID, AccountKey: alice.AccountKey}, root
}

func TestManagedWritesUseCurrentOwnershipAndPreserveOmittedFields(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	alice, root := managedResourceFixture(t, db)
	clientBefore, _ := db.GetClient(ctx, 1001)
	credentialBefore, _ := db.GetCredential(ctx, 501)
	if _, err := db.TransferClientOwnership(ctx, ownerWriteRequest(t, db, root, OwnerScopeGroup, 501, "Bob", 70001)); err != nil {
		t.Fatal(err)
	}
	off := false
	for _, op := range []struct {
		name string
		call func() error
	}{
		{"client-patch", func() error {
			_, err := db.PatchManagedClient(ctx, alice, 1001, ManagementClientPatch{Enabled: &off}, time.Now(), time.Now().Unix())
			return err
		}},
		{"client-delete", func() error {
			_, err := db.DeleteManagedClient(ctx, alice, 1001, time.Now(), time.Now().Unix(), func(HTTPRouteMapping) string { return "private" })
			return err
		}},
		{"credential-patch", func() error {
			_, err := db.PatchManagedCredential(ctx, alice, 501, ManagementCredentialPatch{Enabled: &off}, time.Now())
			return err
		}},
		{"credential-delete", func() error { return db.DeleteManagedCredential(ctx, alice, 501) }},
	} {
		t.Run(op.name, func(t *testing.T) {
			if err := op.call(); !errors.Is(err, ErrManagementResourceForbidden) {
				t.Fatalf("stale owner authorized: %v", err)
			}
		})
	}
	bob, err := db.FindManagementUserByLogin(ctx, "default", "Bob")
	if err != nil || bob == nil {
		t.Fatal(err)
	}
	actor := ManagementWriteActor{Username: bob.Username, TenantID: bob.TenantID, AccountKey: bob.AccountKey}
	rate := 71
	clientOut, err := db.PatchManagedClient(ctx, actor, 1001, ManagementClientPatch{ConnectionRateLimitPerMinute: &rate}, time.Now(), time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if clientOut.Before.OwnerUsername != "Bob" || clientOut.Before.ClientName != clientBefore.ClientName || clientOut.Client.PasswordHash != clientBefore.PasswordHash || clientOut.Client.ConnectionRateLimitPerMinute != rate {
		t.Fatalf("current client/omitted fields: %+v", clientOut)
	}
	limit := 13
	credential, err := db.PatchManagedCredential(ctx, actor, 501, ManagementCredentialPatch{MaxOnlineInstances: &limit}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if credential.OwnerUsername != "Bob" || credential.APIKey != credentialBefore.APIKey || credential.SecretHash != credentialBefore.SecretHash || credential.Enabled != credentialBefore.Enabled || credential.MaxOnlineInstances != limit {
		t.Fatalf("credential overwritten by old snapshot: %+v", credential)
	}
	key, hash := "rotated-key", "rotated-hash"
	if _, err := db.PatchManagedCredential(ctx, actor, 501, ManagementCredentialPatch{APIKey: &key, SecretHash: &hash}, time.Now()); err != nil {
		t.Fatal(err)
	}
	credential, err = db.PatchManagedCredential(ctx, actor, 501, ManagementCredentialPatch{Enabled: &off}, time.Now())
	if err != nil || credential.APIKey != key || credential.SecretHash != hash {
		t.Fatalf("unrelated edit lost explicit rotation: %+v / %v", credential, err)
	}
}

func TestManagedPatchesPreserveNullOwnersAndUnspecifiedIdentityMaterial(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	_, root := managedResourceFixture(t, db)
	for _, table := range []string{"specus_client_account", "specus_client_credential"} {
		if _, err := db.sql.Exec(`UPDATE ` + table + ` SET owner_username=NULL`); err != nil {
			t.Fatal(err)
		}
	}
	clientBefore, _ := db.GetClient(ctx, 1001)
	credentialBefore, _ := db.GetCredential(ctx, 501)
	rate, limit := 81, 17
	client, err := db.PatchManagedClient(ctx, root, 1001, ManagementClientPatch{ConnectionRateLimitPerMinute: &rate}, time.Now(), time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := db.PatchManagedCredential(ctx, root, 501, ManagementCredentialPatch{MaxOnlineInstances: &limit}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	clientBefore.ConnectionRateLimitPerMinute = rate
	clientBefore.UpdatedAt = client.Client.UpdatedAt
	credentialBefore.MaxOnlineInstances = limit
	credentialBefore.UpdatedAt = credential.UpdatedAt
	if !reflect.DeepEqual(*clientBefore, client.Client) || !reflect.DeepEqual(credentialBefore, credential) {
		t.Fatal("patch modified omitted name/key/hash/flags/creation/identity fields")
	}
	for _, row := range []struct {
		table string
		id    int64
	}{{"specus_client_account", 1001}, {"specus_client_credential", 501}} {
		var owner sql.NullString
		if err := db.sql.QueryRow(`SELECT owner_username FROM `+row.table+` WHERE id=?`, row.id).Scan(&owner); err != nil || owner.Valid {
			t.Fatalf("NULL owner normalized by unrelated edit: %+v / %v", owner, err)
		}
	}
}

func TestManagedResourceWritesRejectCurrentActorRevocation(t *testing.T) {
	for _, scenario := range []string{"disabled", "replacement", "oidc-rebound"} {
		t.Run(scenario, func(t *testing.T) {
			db := provisionTestDB(t)
			ctx := context.Background()
			actor, _ := managedResourceFixture(t, db)
			user, err := db.FindManagementUserByAccountKey(ctx, actor.AccountKey)
			if err != nil || user == nil {
				t.Fatal(err)
			}
			target, err := db.FindManagementUserByLogin(ctx, "default", "Bob")
			if err != nil || target == nil {
				t.Fatal(err)
			}
			switch scenario {
			case "disabled":
				user.Enabled = false
				if err := db.UpdateManagementUser(ctx, *user); err != nil {
					t.Fatal(err)
				}
			case "replacement":
				if _, err := db.sql.Exec(`DELETE FROM specus_management_user WHERE username=?`, user.AccountKey); err != nil {
					t.Fatal(err)
				}
				user.AccountKey = "recreated-alice"
				if _, err := db.InsertManagementUser(ctx, *user); err != nil {
					t.Fatal(err)
				}
			case "oidc-rebound":
				actor.OIDCIdentityKey, actor.OIDCIssuer, actor.OIDCSubject = "old-key", "issuer", "old-subject"
				user.OIDCIdentityKey, user.OIDCIssuer, user.OIDCSubject = "new-key", "issuer", "new-subject"
				if err := db.UpdateManagementUser(ctx, *user); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now()
			off := false
			for _, op := range []struct {
				name string
				call func() error
			}{
				{"client-create", func() error {
					_, err := db.CreateManagedClient(ctx, actor, ClientAccount{ID: 60001, ClientName: "late-new-client", Enabled: true, PasswordHash: "hash", CreatedAt: now, UpdatedAt: now})
					return err
				}},
				{"client-patch", func() error {
					_, err := db.PatchManagedClient(ctx, actor, 1001, ManagementClientPatch{Enabled: &off}, now, now.Unix())
					return err
				}},
				{"client-delete", func() error {
					_, err := db.DeleteManagedClient(ctx, actor, 1001, now, now.Unix(), func(HTTPRouteMapping) string { return "private" })
					return err
				}},
				{"credential-create", func() error {
					_, err := db.CreateManagedCredential(ctx, actor, ClientCredential{ID: 60002, APIKey: "late-api-key", SecretHash: "hash", Enabled: true, MaxOnlineInstances: 3, CreatedAt: now, UpdatedAt: now})
					return err
				}},
				{"credential-patch", func() error {
					_, err := db.PatchManagedCredential(ctx, actor, 501, ManagementCredentialPatch{Enabled: &off}, now)
					return err
				}},
				{"credential-delete", func() error { return db.DeleteManagedCredential(ctx, actor, 501) }},
				{"user-create", func() error {
					_, err := db.CreateManagedUser(ctx, actor, ManagementUser{Username: "late-user", Enabled: true, Role: ManagementRoleAdmin, CreatedAt: now, UpdatedAt: now})
					return err
				}},
				{"user-patch", func() error {
					_, err := db.PatchManagedUser(ctx, actor, *target, ManagementUserPatch{Enabled: &off}, now, now.Unix(), nil)
					return err
				}},
				{"user-delete", func() error { _, err := db.DeleteManagedUser(ctx, actor, *target, now.Unix(), nil); return err }},
			} {
				t.Run(op.name, func(t *testing.T) {
					if err := op.call(); !errors.Is(err, ErrManagementActorChanged) {
						t.Fatalf("revoked actor escaped current identity gate: %v", err)
					}
				})
			}
			client, err := db.GetClient(ctx, 1001)
			if err != nil || !client.Enabled {
				t.Fatalf("rejected operation changed client: %+v / %v", client, err)
			}
			credential, err := db.GetCredential(ctx, 501)
			if err != nil || credential.OwnerUsername != "alice" {
				t.Fatalf("rejected operation changed credential: %+v / %v", credential, err)
			}
			current, err := db.FindManagementUserByAccountKey(ctx, target.AccountKey)
			if err != nil || current == nil || !current.Enabled {
				t.Fatalf("rejected operation changed target: %+v / %v", current, err)
			}
		})
	}
}

func TestManagedCreateBindsCurrentActorAndTargetDeleteCounts(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	alice, root := managedResourceFixture(t, db)
	now := time.Now()
	created, err := db.CreateManagedClient(ctx, alice, ClientAccount{ID: 60001, TenantID: "foreign", OwnerUsername: "spoofed", ClientName: "bound-client", PasswordHash: "hash", Enabled: true, CreatedAt: now, UpdatedAt: now})
	if err != nil || created.TenantID != "default" || created.OwnerUsername != "alice" {
		t.Fatalf("create trusted candidate owner: %+v / %v", created, err)
	}
	credential, err := db.CreateManagedCredential(ctx, alice, ClientCredential{ID: 60002, TenantID: "foreign", OwnerUsername: "spoofed", APIKey: "bound-key", SecretHash: "hash", Enabled: true, MaxOnlineInstances: 3, CreatedAt: now, UpdatedAt: now})
	if err != nil || credential.TenantID != "default" || credential.OwnerUsername != "alice" {
		t.Fatalf("credential trusted candidate owner: %+v / %v", credential, err)
	}
	bob, _ := db.FindManagementUserByLogin(ctx, "default", "Bob")
	if _, err := db.TransferClientOwnership(ctx, ownerWriteRequest(t, db, root, OwnerScopeGroup, 501, "Bob", 70002)); err != nil {
		t.Fatal(err)
	}
	_, err = db.DeleteManagedUser(ctx, root, *bob, now.Unix(), nil)
	var owned *AccountStillOwnsError
	if !errors.As(err, &owned) || owned.Clients != 1 || owned.Credentials != 1 {
		t.Fatalf("delete missed current transferred rows: %+v / %v", owned, err)
	}
	if _, err := db.TransferClientOwnership(ctx, ownerWriteRequest(t, db, root, OwnerScopeGroup, 501, "admin", 70003)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DeleteManagedUser(ctx, root, *bob, now.Unix(), nil); err != nil {
		t.Fatal(err)
	}
	if current, err := db.FindManagementUserByAccountKey(ctx, bob.AccountKey); err != nil || current != nil {
		t.Fatalf("empty account not deleted: %+v / %v", current, err)
	}
}

func TestManagedUserPatchPreservesCurrentMaterialAndPinsTarget(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	_, root := managedResourceFixture(t, db)
	now := time.Now()
	target, _ := db.FindManagementUserByLogin(ctx, "default", "Bob")
	old := *target
	target.PasswordHash = "rotated-password"
	target.OIDCIdentityKey = "bound-key"
	target.OIDCIssuer = "issuer"
	target.OIDCSubject = "subject"
	target.Role = ManagementRoleAdmin
	if err := db.UpdateManagementUser(ctx, *target); err != nil {
		t.Fatal(err)
	}
	off := false
	out, err := db.PatchManagedUser(ctx, root, old, ManagementUserPatch{Enabled: &off}, now, now.Unix(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Disabled || out.RoleChanged || out.User.PasswordHash != target.PasswordHash || out.User.Role != target.Role || out.User.OIDCIdentityKey != target.OIDCIdentityKey || out.User.OIDCIssuer != target.OIDCIssuer || out.User.OIDCSubject != target.OIDCSubject {
		t.Fatalf("stale user object overwrote protected material: %+v", out)
	}
	if _, err := db.sql.Exec(`DELETE FROM specus_management_user WHERE username=?`, target.AccountKey); err != nil {
		t.Fatal(err)
	}
	target.AccountKey = "replacement-bob"
	target.Enabled = true
	if _, err := db.InsertManagementUser(ctx, *target); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DeleteManagedUser(ctx, root, old, now.Unix(), nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete rebound reusable login: %v", err)
	}
	if _, err := db.PatchManagedUser(ctx, root, old, ManagementUserPatch{Enabled: &off}, now, now.Unix(), nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("patch rebound reusable login: %v", err)
	}
	current, _ := db.FindManagementUserByAccountKey(ctx, target.AccountKey)
	if current == nil || !current.Enabled {
		t.Fatal("replacement account changed")
	}
}

func TestManagedDeleteRetainsAtomicPeerCleanupOnFailure(t *testing.T) {
	db, now := peerDeletionFixture(t)
	ctx := context.Background()
	actor := ManagementWriteActor{Username: "admin", TenantID: "tenant-a", Admin: true, BuiltIn: true}
	if _, err := db.sql.Exec(`CREATE TRIGGER reject_managed_delete BEFORE DELETE ON specus_client_account WHEN OLD.id=1001 BEGIN SELECT RAISE(ABORT,'injected managed delete failure'); END`); err != nil {
		t.Fatal(err)
	}
	out, err := db.DeleteManagedClient(ctx, actor, 1001, now, now.Unix(), func(HTTPRouteMapping) string { return "private" })
	if err == nil || out.ClosedPeerSessions != nil || out.RevokedShares != nil {
		t.Fatalf("failed delete exposed committed effects: %+v / %v", out, err)
	}
	device, err := db.FindPeerMeshDeviceByClientID(ctx, "tenant-a", 1001)
	if err != nil || device == nil {
		t.Fatalf("rollback lost peer: %+v / %v", device, err)
	}
	session, err := db.GetPeerMeshSession(ctx, 40)
	if err != nil || session.Status != "CONNECTED" || session.ClosedAt != nil {
		t.Fatalf("rollback closed peer session: %+v / %v", session, err)
	}
}

func TestManagedWritesUseCurrentAdminRoleAndEmptyCredentialCounts(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	_, root := managedResourceFixture(t, db)
	now := time.Now()
	manager, err := db.InsertManagementUser(ctx, ManagementUser{Username: "demoted-manager", TenantID: "default", Role: ManagementRoleAdmin, Enabled: true, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	actor := ManagementWriteActor{Username: manager.Username, TenantID: manager.TenantID, AccountKey: manager.AccountKey, Admin: true}
	manager.Role = ManagementRoleUser
	if err := db.UpdateManagementUser(ctx, manager); err != nil {
		t.Fatal(err)
	}
	bob, _ := db.FindManagementUserByLogin(ctx, "default", "Bob")
	off := false
	for _, op := range []func() error{
		func() error {
			_, err := db.CreateManagedUser(ctx, actor, ManagementUser{Username: "forbidden-user", Enabled: true, Role: ManagementRoleAdmin, CreatedAt: now, UpdatedAt: now})
			return err
		},
		func() error {
			_, err := db.PatchManagedUser(ctx, actor, *bob, ManagementUserPatch{Enabled: &off}, now, now.Unix(), nil)
			return err
		},
		func() error { _, err := db.DeleteManagedUser(ctx, actor, *bob, now.Unix(), nil); return err },
		func() error {
			_, err := db.PatchManagedClient(ctx, actor, 1001, ManagementClientPatch{Enabled: &off}, now, now.Unix())
			return err
		},
	} {
		if err := op(); !errors.Is(err, ErrManagementResourceForbidden) {
			t.Fatalf("cached admin bit granted authority: %v", err)
		}
	}
	// A zero-device credential is still an owned resource that must prevent account deletion.
	if err := db.InsertCredential(ctx, ClientCredential{ID: 60003, TenantID: "default", OwnerUsername: bob.Username, APIKey: "empty-owned-key", SecretHash: "hash", Enabled: false, MaxOnlineInstances: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	_, err = db.DeleteManagedUser(ctx, root, *bob, now.Unix(), nil)
	var owned *AccountStillOwnsError
	if !errors.As(err, &owned) || owned.Clients != 0 || owned.Credentials != 1 {
		t.Fatalf("empty owned credential omitted: %+v / %v", owned, err)
	}
	if _, err := db.TransferClientOwnership(ctx, ownerWriteRequest(t, db, root, OwnerScopeGroup, 60003, "admin", 70004)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DeleteManagedUser(ctx, root, *bob, now.Unix(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestManagedConflictRollsBackPatchAndPreservesOrdinaryScopeErrors(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	alice, root := managedResourceFixture(t, db)
	now := time.Now()
	name := "unrelated"
	off := false
	if _, err := db.PatchManagedClient(ctx, root, 1001, ManagementClientPatch{ClientName: &name, Enabled: &off}, now, now.Unix()); !errors.Is(err, ErrManagementResourceConflict) {
		t.Fatalf("name conflict: %v", err)
	}
	client, err := db.GetClient(ctx, 1001)
	if err != nil || client.ClientName == name || !client.Enabled || client.OwnerUsername != "alice" {
		t.Fatalf("failed client patch partially committed: %+v / %v", client, err)
	}
	if err := db.InsertCredential(ctx, ClientCredential{ID: 60004, TenantID: "foreign", OwnerUsername: "foreign-owner", APIKey: "occupied-key", SecretHash: "other-hash", Enabled: true, MaxOnlineInstances: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	key, hash, on := "occupied-key", "must-not-commit", true
	if _, err := db.PatchManagedCredential(ctx, root, 501, ManagementCredentialPatch{APIKey: &key, SecretHash: &hash, Enabled: &on}, now); !errors.Is(err, ErrManagementResourceConflict) {
		t.Fatalf("key conflict: %v", err)
	}
	credential, err := db.GetCredential(ctx, 501)
	if err != nil || credential.APIKey == key || credential.SecretHash == hash || credential.Enabled {
		t.Fatalf("failed credential patch partially committed: %+v / %v", credential, err)
	}
	if err := db.DeleteManagedCredential(ctx, alice, 60004); !errors.Is(err, ErrManagementResourceForbidden) {
		t.Fatalf("foreign ordinary resource no longer403: %v", err)
	}
	if err := db.DeleteManagedCredential(ctx, alice, 69999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing resource not404: %v", err)
	}
}
