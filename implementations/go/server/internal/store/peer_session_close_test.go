package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func closeStoreFixture(t *testing.T) (*DB, PeerClientReference, PeerClientReference, int64) {
	t.Helper()
	db := provisionTestDB(t)
	source, target := peerAdmissionFixture(t, db, 8301, "default", "alice")
	out, err := db.AdmitPeerMeshSession(context.Background(), source, target, peerAdmissionSeed(8401, "close-store-hash"))
	if err != nil {
		t.Fatal(err)
	}
	return db, source, target, out.Session.ID
}

func TestPeerManagedCloseUsesCurrentActorAndRole(t *testing.T) {
	for _, scenario := range []string{"disabled", "renamed", "deleted", "oidc-rebound", "demoted-single", "demoted-all", "promoted"} {
		t.Run(scenario, func(t *testing.T) {
			db, _, _, id := closeStoreFixture(t)
			ctx := context.Background()
			now := time.Now()
			role := ManagementRoleAdmin
			if scenario == "promoted" {
				role = ManagementRoleUser
			}
			user, err := db.InsertManagementUser(ctx, ManagementUser{Username: "closer", TenantID: "default", Role: role, Enabled: true, OIDCIdentityKey: "close-oidc-a", OIDCIssuer: "issuer", OIDCSubject: "subject-a", CreatedAt: now, UpdatedAt: now})
			if err != nil {
				t.Fatal(err)
			}
			actor := ManagementWriteActor{Username: user.Username, TenantID: user.TenantID, AccountKey: user.AccountKey, Admin: role == ManagementRoleAdmin, OIDCIdentityKey: user.OIDCIdentityKey, OIDCIssuer: user.OIDCIssuer, OIDCSubject: user.OIDCSubject}
			query := `UPDATE specus_management_user SET enabled=0 WHERE username=?`
			switch scenario {
			case "renamed":
				query = `UPDATE specus_management_user SET login_name='renamed-closer',login_name_normalized='renamed-closer' WHERE username=?`
			case "deleted":
				query = `DELETE FROM specus_management_user WHERE username=?`
			case "oidc-rebound":
				query = `UPDATE specus_management_user SET oidc_identity_key='close-oidc-b',oidc_subject='subject-b' WHERE username=?`
			case "demoted-single", "demoted-all":
				query = `UPDATE specus_management_user SET role='USER' WHERE username=?`
			case "promoted":
				query = `UPDATE specus_management_user SET role='ADMIN' WHERE username=?`
			}
			if _, err := db.sql.Exec(query, user.AccountKey); err != nil {
				t.Fatal(err)
			}
			selection := PeerSessionCloseSelection{SessionID: id}
			if scenario == "demoted-all" {
				selection = PeerSessionCloseSelection{}
			}
			rows, err := db.CloseManagedPeerMeshSessions(ctx, actor, selection)
			if scenario == "promoted" {
				if err != nil || len(rows) != 1 || rows[0].Status != "CLOSED" {
					t.Fatalf("current promotion ignored: %+v / %v", rows, err)
				}
				return
			}
			if scenario == "demoted-all" {
				if err != nil || len(rows) != 0 {
					t.Fatalf("current user all-selection wrong: %+v / %v", rows, err)
				}
			} else if scenario == "demoted-single" {
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("stale admin permission accepted: %v", err)
				}
			} else if !errors.Is(err, ErrManagementActorChanged) {
				t.Fatalf("changed actor accepted: %+v / %v", rows, err)
			}
			row, err := db.GetPeerMeshSession(ctx, id)
			if err != nil || row.Status == "CLOSED" {
				t.Fatalf("rejected actor changed session: %+v / %v", row, err)
			}
		})
	}
}

func TestPeerCloseCurrentParentAndConditionalPredicates(t *testing.T) {
	db, source, target, id := closeStoreFixture(t)
	ctx := context.Background()
	now := time.Now()
	user, err := db.InsertManagementUser(ctx, ManagementUser{Username: "alice", TenantID: "default", Role: ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	actor := ManagementWriteActor{Username: user.Username, TenantID: user.TenantID, AccountKey: user.AccountKey}
	// Leave stale device ownership intentionally: parent ownership is authoritative.
	if _, err := db.sql.Exec(`UPDATE specus_client_account SET owner_username='bob' WHERE id IN (?,?)`, source.ID, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CloseManagedPeerMeshSessions(ctx, actor, PeerSessionCloseSelection{SessionID: id}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale child owner authorized close: %v", err)
	}
	if rows, err := db.CloseExpiredPeerMeshSessions(ctx, "default", []int64{id}); err != nil || len(rows) != 0 {
		t.Fatalf("stale expiry callback closed future grant: %+v / %v", rows, err)
	}
	if rows, err := db.CloseUnauthorizedPeerMeshSessions(ctx, "default", []int64{id}); err != nil || len(rows) != 0 {
		t.Fatalf("same current owner callback closed valid grant: %+v / %v", rows, err)
	}
	root := ManagementWriteActor{Username: "admin", TenantID: "default", Admin: true, BuiltIn: true}
	rename := "renamed-close-source"
	if _, err := db.PatchManagedClient(ctx, root, source.ID, ManagementClientPatch{ClientName: &rename}, now, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CloseReportedPeerMeshSession(ctx, source, id); !errors.Is(err, ErrPeerAccessDenied) {
		t.Fatalf("stale reporting alias accepted: %v", err)
	}
	source.ClientName = rename
	if rows, err := db.CloseReportedPeerMeshSession(ctx, source, id); err != nil || len(rows) != 1 || rows[0].Status != "CLOSED" {
		t.Fatalf("current participant close failed: %+v / %v", rows, err)
	}
}

func TestPeerExpiredClosureCleansLegacyOrphanEndpoints(t *testing.T) {
	db, source, _, id := closeStoreFixture(t)
	if _, err := db.sql.Exec(`UPDATE peer_mesh_session SET source_client_id=0,target_client_id=-1,expires_at=? WHERE id=?`, formatTime(time.Now().Add(-time.Hour)), id); err != nil {
		t.Fatal(err)
	}
	rows, err := db.CloseExpiredPeerMeshSessions(context.Background(), "default", []int64{id})
	if err != nil || len(rows) != 1 || rows[0].Status != "CLOSED" {
		t.Fatalf("legacy bad endpoints poisoned expiry cleanup: %+v / %v", rows, err)
	}
	if _, err := db.CloseReportedPeerMeshSession(context.Background(), source, id); !errors.Is(err, ErrPeerAccessDenied) {
		t.Fatalf("orphan cleanup granted reporting authority: %v", err)
	}
}

func TestPeerClosingPathReportMergesTelemetryNotTrafficSnapshot(t *testing.T) {
	for _, scenario := range []struct {
		name            string
		direct, relay   int64
		requested, want string
	}{
		{"new-path", 0, 0, "RELAY", "RELAY"},
		{"relay-wins", 11, 22, "DIRECT", "RELAY"},
		{"direct-wins", 22, 11, "RELAY", "DIRECT"},
		{"equal-keeps-current", 11, 11, "DIRECT", "RELAY"},
		{"omitted-keeps-current", 22, 11, "", "RELAY"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			db, source, _, id := closeStoreFixture(t)
			if _, err := db.sql.Exec(`UPDATE peer_mesh_session SET path_type='RELAY',direct_bytes=?,relay_bytes=? WHERE id=?`, scenario.direct, scenario.relay, id); err != nil {
				t.Fatal(err)
			}
			rtt := int64(9)
			endpoint := "127.0.0.1:1234"
			rows, err := db.CloseReportedPeerMeshSessionWithPath(context.Background(), source, id, PeerSessionClosePath{PathType: scenario.requested, RTTMillis: &rtt, LocalEndpoint: &endpoint})
			if err != nil || len(rows) != 1 {
				t.Fatalf("closing path report failed: %+v / %v", rows, err)
			}
			row := rows[0]
			if row.PathType != scenario.want || row.DirectBytes != scenario.direct || row.RelayBytes != scenario.relay || row.RTTMillis == nil || *row.RTTMillis != rtt || row.LocalEndpoint == nil || *row.LocalEndpoint != endpoint || row.Status != "CLOSED" {
				t.Fatalf("closing telemetry/current traffic mismatch: %+v", row)
			}
		})
	}
}
