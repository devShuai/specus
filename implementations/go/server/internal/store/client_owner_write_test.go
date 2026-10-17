package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func ownerWriteFixture(t *testing.T, db *DB, count int) ManagementWriteActor {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.InsertManagementUser(ctx, ManagementUser{Username: "Bob", TenantID: "default", Role: ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertCredential(ctx, ClientCredential{ID: 501, TenantID: "default", OwnerUsername: "credential-old", APIKey: "secret-marker-api-key", SecretHash: "secret-marker-hash", Enabled: false, MaxOnlineInstances: 7, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for index := 0; index < count; index++ {
		id := int64(1001 + index)
		owner := "alice"
		if index%2 != 0 {
			owner = "carol"
		}
		account := ClientAccount{ID: id, TenantID: "default", OwnerUsername: owner, ClientName: fmt.Sprintf("owner-client-%d", id), PasswordHash: "secret-marker-client-hash", Enabled: index%2 == 0, ConnectionRateLimitPerMinute: 43, CreatedAt: now, UpdatedAt: now}
		identity := ClientIdentity{ID: id + 10000, TenantID: "default", CredentialID: 501, ClientID: id, ClientName: account.ClientName, MachineFingerprint: fmt.Sprintf("secret-marker-machine-%d", id), OSUser: "fixture", Hostname: "fixture-host", FirstSeenAt: now, LastSeenAt: now}
		if err := db.insertClientWithIdentityOn(ctx, tx, account, identity); err != nil {
			t.Fatal(err)
		}
		key := "secret-marker-public-key"
		if err := db.insertPeerMeshDeviceOn(ctx, tx, PeerMeshDevice{ID: id + 20000, TenantID: "default", OwnerUsername: "peer-old", ClientID: id, ClientName: account.ClientName, VirtualIP: fmt.Sprintf("100.96.%d.%d", index/250, index%250+1), CIDR: "100.96.0.0/11", PublicKey: &key, Enabled: false, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertClient(ctx, ClientAccount{ID: 9001, TenantID: "default", OwnerUsername: "alice", ClientName: "unrelated", PasswordHash: "secret-marker-unrelated", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	return ManagementWriteActor{Username: "admin", TenantID: "default", Admin: true, BuiltIn: true}
}

func ownerWriteRequest(t *testing.T, db *DB, actor ManagementWriteActor, scope string, id int64, target string, auditID int64) OwnerTransferWrite {
	t.Helper()
	data, err := db.LoadOwnerTransferSnapshot(context.Background(), actor.TenantID, scope, id)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := PreviewOwnerTransfer(actor, scope, id, data)
	if err != nil {
		t.Fatal(err)
	}
	revision := "missing"
	if preview.Revision != nil {
		revision = *preview.Revision
	}
	request := OwnerTransferWrite{Actor: actor, Scope: scope, PathID: id, AuditID: auditID, Body: map[string]any{"scope": scope, "targetUsername": target, "expectedRevision": revision}}
	request.BuiltInTarget.Username = "admin"
	request.BuiltInTarget.TenantID = "default"
	request.BuiltInTarget.Enabled = true
	return request
}

func assertOwnerWriteError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var problem *OwnerTransferError
	if !errors.As(err, &problem) || problem.Status != status || problem.Code != code {
		t.Fatalf("error=%v, want %d/%s", err, status, code)
	}
}

func ownerAuditCount(t *testing.T, db *DB) int {
	t.Helper()
	var count int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM client_owner_transfer_audit`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestOwnerWriteAtomicGroupRetentionAndNoop(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	actor := ownerWriteFixture(t, db, 2)
	beforeClient, _ := db.GetClient(ctx, 1001)
	beforeCredential, _ := db.FindCredentialByAPIKey(ctx, "secret-marker-api-key")
	beforePeer, _ := db.FindPeerMeshDeviceByClientID(ctx, "default", 1001)
	request := ownerWriteRequest(t, db, actor, OwnerScopeGroup, 501, "  bOB  ", 50001)
	out, err := db.TransferClientOwnership(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Response.Changed || !out.Response.AccessRetained || out.Response.TargetUsername != "Bob" || out.AuditID == nil || *out.AuditID != 50001 || !reflect.DeepEqual(out.Response.AffectedClientIDs, []int64{1001, 1002}) {
		t.Fatalf("outcome=%+v", out)
	}
	afterClient, _ := db.GetClient(ctx, 1001)
	afterCredential, _ := db.FindCredentialByAPIKey(ctx, "secret-marker-api-key")
	afterPeer, _ := db.FindPeerMeshDeviceByClientID(ctx, "default", 1001)
	beforeClient.OwnerUsername = "Bob"
	beforeClient.UpdatedAt = afterClient.UpdatedAt
	beforeCredential.OwnerUsername = "Bob"
	beforeCredential.UpdatedAt = afterCredential.UpdatedAt
	beforePeer.OwnerUsername = "Bob"
	beforePeer.UpdatedAt = afterPeer.UpdatedAt
	if !reflect.DeepEqual(beforeClient, afterClient) || !reflect.DeepEqual(beforeCredential, afterCredential) || !reflect.DeepEqual(beforePeer, afterPeer) {
		t.Fatal("transfer changed keys/IDs/name/flags/limits/address or other preserved fields")
	}
	unrelated, err := db.GetClient(ctx, 9001)
	if err != nil || unrelated.OwnerUsername != "alice" {
		t.Fatalf("unrelated scope changed: %+v / %v", unrelated, err)
	}
	var detail, actorName, scope, target string
	var path int64
	if err := db.sql.QueryRow(`SELECT actor,scope,path_id,target_username,detail_json FROM client_owner_transfer_audit WHERE id=50001`).Scan(&actorName, &scope, &path, &target, &detail); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(detail, "secret-marker") || actorName != "admin" || scope != OwnerScopeGroup || path != 501 || target != "Bob" {
		t.Fatalf("incorrect/sensitive audit metadata: %s", detail)
	}
	var audit struct {
		AffectedClientIDs []int64                   `json:"affectedClientIds"`
		Clients           []OwnerTransferClient     `json:"clients"`
		Credentials       []OwnerTransferCredential `json:"credentials"`
		Peers             []OwnerTransferPeer       `json:"peerDevices"`
	}
	if err := json.Unmarshal([]byte(detail), &audit); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(audit.AffectedClientIDs, []int64{1001, 1002}) || len(audit.Clients) != 2 || len(audit.Credentials) != 1 || len(audit.Peers) != 2 || *audit.Credentials[0].OwnerUsername != "credential-old" {
		t.Fatalf("incomplete old-owner audit: %s", detail)
	}
	_, err = db.TransferClientOwnership(ctx, request)
	assertOwnerWriteError(t, err, 409, "TRANSFER_PREVIEW_CHANGED")
	noop := ownerWriteRequest(t, db, actor, OwnerScopeGroup, 501, "Bob", 50002)
	out, err = db.TransferClientOwnership(ctx, noop)
	if err != nil || out.Response.Changed || out.AuditID != nil || ownerAuditCount(t, db) != 1 {
		t.Fatalf("repeated success not noop: %+v / %v", out, err)
	}
}

func TestOwnerWriteLegacyUniqueEmptyAndBuiltin(t *testing.T) {
	for _, scenario := range []string{"legacy", "unique", "empty", "builtin"} {
		t.Run(scenario, func(t *testing.T) {
			db := provisionTestDB(t)
			ctx := context.Background()
			count := 1
			if scenario == "empty" {
				count = 0
			}
			actor := ownerWriteFixture(t, db, count)
			scope, id, target := OwnerScopeSingle, int64(1001), "Bob"
			if scenario == "legacy" {
				if _, err := db.sql.Exec(`DELETE FROM specus_client_identity WHERE client_id=1001`); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "empty" {
				scope, id = OwnerScopeGroup, 501
			}
			if scenario == "builtin" {
				target = "ADMIN"
			}
			out, err := db.TransferClientOwnership(ctx, ownerWriteRequest(t, db, actor, scope, id, target, 50003))
			if err != nil {
				t.Fatal(err)
			}
			if !out.Response.Changed || out.AuditID == nil {
				t.Fatalf("missing committed change: %+v", out)
			}
			if scenario == "legacy" {
				if out.Response.CredentialID != nil {
					t.Fatal("legacy acquired credential")
				}
				credential, _ := db.FindCredentialByAPIKey(ctx, "secret-marker-api-key")
				if credential.OwnerUsername != "credential-old" {
					t.Fatal("legacy transferred unrelated credential")
				}
			} else if out.Response.CredentialID == nil || *out.Response.CredentialID != 501 {
				t.Fatal("wrong credential")
			}
			if scenario == "empty" && len(out.Response.AffectedClientIDs) != 0 {
				t.Fatal("empty credential transferred clients")
			}
			if scenario == "builtin" && out.Response.TargetUsername != "admin" {
				t.Fatal("builtin target not canonical")
			}
		})
	}
}

func TestOwnerWriteValidationOrderAndRollback(t *testing.T) {
	for _, scenario := range []string{"nonadmin", "object", "path", "scope", "shared", "stale-target", "disabled-target", "damaged", "audit-failure", "credential-failure", "postcondition"} {
		t.Run(scenario, func(t *testing.T) {
			db := provisionTestDB(t)
			ctx := context.Background()
			actor := ownerWriteFixture(t, db, 2)
			request := ownerWriteRequest(t, db, actor, OwnerScopeGroup, 501, "Bob", 50004)
			status, code := 400, "INVALID_TRANSFER_REQUEST"
			switch scenario {
			case "nonadmin":
				request.Actor.Admin = false
				request.Body = nil
				status, code = 403, "FORBIDDEN"
			case "object":
				request.Body = []any{}
			case "path":
				request.PathID = 9999
				request.Body = map[string]any{}
				status, code = 404, "RESOURCE_NOT_FOUND"
			case "scope":
				request.Body = map[string]any{"scope": OwnerScopeSingle}
			case "shared":
				request.Scope, request.PathID = OwnerScopeSingle, 1001
				request.Body = map[string]any{"scope": OwnerScopeSingle}
				status, code = 409, "CREDENTIAL_SHARED"
			case "stale-target":
				request.Body.(map[string]any)["expectedRevision"] = "stale"
				fallthrough
			case "disabled-target":
				user, err := db.FindManagementUserByLogin(ctx, "default", "Bob")
				if err != nil || user == nil {
					t.Fatal(err)
				}
				user.Enabled = false
				if err := db.UpdateManagementUser(ctx, *user); err != nil {
					t.Fatal(err)
				}
				status, code = 400, "INVALID_TARGET_OWNER"
				if scenario == "stale-target" {
					status, code = 409, "TRANSFER_PREVIEW_CHANGED"
				}
			case "damaged":
				if err := db.InsertIdentity(ctx, ClientIdentity{ID: 40001, TenantID: "foreign", CredentialID: 501, ClientID: 1001, ClientName: "owner-client-1001", MachineFingerprint: "foreign-edge", OSUser: "fixture", FirstSeenAt: time.Now(), LastSeenAt: time.Now()}); err != nil {
					t.Fatal(err)
				}
				status, code = 409, "INCONSISTENT_CREDENTIAL_GROUP"
			case "audit-failure":
				if _, err := db.sql.Exec(`CREATE TRIGGER reject_owner_audit BEFORE INSERT ON client_owner_transfer_audit BEGIN SELECT RAISE(ABORT,'injected audit failure'); END`); err != nil {
					t.Fatal(err)
				}
			case "credential-failure":
				if _, err := db.sql.Exec(`CREATE TRIGGER reject_owner_credential BEFORE UPDATE ON specus_client_credential WHEN NEW.owner_username='Bob' BEGIN SELECT RAISE(ABORT,'injected credential write failure'); END`); err != nil {
					t.Fatal(err)
				}
			case "postcondition":
				if _, err := db.sql.Exec(`CREATE TRIGGER rewrite_owner AFTER UPDATE ON specus_client_account WHEN NEW.owner_username='Bob' BEGIN UPDATE specus_client_account SET owner_username='wrong' WHERE id=NEW.id; END`); err != nil {
					t.Fatal(err)
				}
			}
			_, err := db.TransferClientOwnership(ctx, request)
			if strings.HasSuffix(scenario, "failure") || scenario == "postcondition" {
				if err == nil {
					t.Fatal("injected failure committed")
				}
			} else {
				assertOwnerWriteError(t, err, status, code)
			}
			client, _ := db.GetClient(ctx, 1001)
			credential, _ := db.FindCredentialByAPIKey(ctx, "secret-marker-api-key")
			peer, _ := db.FindPeerMeshDeviceByClientID(ctx, "default", 1001)
			if client.OwnerUsername != "alice" || credential.OwnerUsername != "credential-old" || peer.OwnerUsername != "peer-old" || ownerAuditCount(t, db) != 0 {
				t.Fatal("failed transfer partially changed ownership/audit")
			}
		})
	}
}

func TestOwnerWriteCompleteLargeGroup(t *testing.T) {
	db := provisionTestDB(t)
	actor := ownerWriteFixture(t, db, 1050)
	out, err := db.TransferClientOwnership(context.Background(), ownerWriteRequest(t, db, actor, OwnerScopeGroup, 501, "Bob", 50005))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Response.AffectedClientIDs) != 1050 || out.Response.AffectedClientIDs[0] != 1001 || out.Response.AffectedClientIDs[1049] != 2050 {
		t.Fatal("large group truncated or unsorted")
	}
	var count int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM peer_mesh_device WHERE owner_username='Bob'`).Scan(&count); err != nil || count != 1050 {
		t.Fatalf("large peer group changed=%d / %v", count, err)
	}
}

func TestOwnerWriteCurrentActorPrecedesBodyAndTarget(t *testing.T) {
	for _, scenario := range []string{"disabled", "deleted-rebound", "downgraded", "oidc-rebound"} {
		t.Run(scenario, func(t *testing.T) {
			db := provisionTestDB(t)
			ctx := context.Background()
			root := ownerWriteFixture(t, db, 1)
			now := time.Now()
			user, err := db.InsertManagementUser(ctx, ManagementUser{Username: "manager", TenantID: "default", Role: ManagementRoleAdmin, Enabled: true, CreatedAt: now, UpdatedAt: now})
			if err != nil {
				t.Fatal(err)
			}
			request := ownerWriteRequest(t, db, root, OwnerScopeGroup, 501, "missing-target", 50006)
			request.Actor = ManagementWriteActor{Username: user.Username, TenantID: user.TenantID, AccountKey: user.AccountKey, Admin: true}
			request.Body = []any{} // Actor rejection must precede the invalid body.
			switch scenario {
			case "disabled":
				user.Enabled = false
			case "downgraded":
				user.Role = ManagementRoleUser
			case "deleted-rebound":
				if _, err := db.sql.Exec(`DELETE FROM specus_management_user WHERE username=?`, user.AccountKey); err != nil {
					t.Fatal(err)
				}
				user.AccountKey = "replacement-manager"
				if _, err := db.InsertManagementUser(ctx, user); err != nil {
					t.Fatal(err)
				}
			case "oidc-rebound":
				request.Actor.OIDCIdentityKey, request.Actor.OIDCIssuer, request.Actor.OIDCSubject = "bound-key", "https://issuer.example", "old-subject"
				user.OIDCIdentityKey, user.OIDCIssuer, user.OIDCSubject = "bound-key", "https://issuer.example", "new-subject"
			}
			if scenario != "deleted-rebound" {
				if err := db.UpdateManagementUser(ctx, user); err != nil {
					t.Fatal(err)
				}
			}
			_, err = db.TransferClientOwnership(ctx, request)
			if scenario == "downgraded" {
				assertOwnerWriteError(t, err, 403, "FORBIDDEN")
			} else if !errors.Is(err, ErrManagementActorChanged) {
				t.Fatalf("actor rejection lost precedence: %v", err)
			}
			if ownerAuditCount(t, db) != 0 {
				t.Fatal("rejected actor created audit")
			}
		})
	}
}

func TestOwnerWritePinsTargetAccountAcrossInternalRetry(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	actor := ownerWriteFixture(t, db, 1)
	binding := &ownerTargetBinding{}
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, target, err := db.lockOwnerTransferActors(ctx, tx, actor, "Bob", false, binding)
	if err != nil || target == nil {
		t.Fatalf("first target: %+v / %v", target, err)
	}
	oldKey := target.AccountKey
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec(`DELETE FROM specus_management_user WHERE username=?`, oldKey); err != nil {
		t.Fatal(err)
	}
	target.AccountKey = "replacement-bob"
	if _, err := db.InsertManagementUser(ctx, *target); err != nil {
		t.Fatal(err)
	}
	tx, err = db.beginClientOwnershipWrite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	_, target, err = db.lockOwnerTransferActors(ctx, tx, actor, "Bob", false, binding)
	if err != nil || target != nil || binding.key != oldKey {
		t.Fatalf("retry rebound reusable target name: %+v / %v", target, err)
	}
}

func TestOwnerWriteBuiltinActorMustStillMatchServerConfiguration(t *testing.T) {
	for _, scenario := range []string{"disabled", "name", "tenant"} {
		t.Run(scenario, func(t *testing.T) {
			db := provisionTestDB(t)
			actor := ownerWriteFixture(t, db, 1)
			request := ownerWriteRequest(t, db, actor, OwnerScopeGroup, 501, "Bob", 50007)
			switch scenario {
			case "disabled":
				request.BuiltInTarget.Enabled = false
			case "name":
				request.BuiltInTarget.Username = "different"
			case "tenant":
				request.BuiltInTarget.TenantID = "other"
			}
			if _, err := db.TransferClientOwnership(context.Background(), request); !errors.Is(err, ErrManagementActorChanged) {
				t.Fatalf("invalid configured actor accepted: %v", err)
			}
			if ownerAuditCount(t, db) != 0 {
				t.Fatal("invalid configured actor wrote audit")
			}
		})
	}
}
