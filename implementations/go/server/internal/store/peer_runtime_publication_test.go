package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func runtimePublicationFixture(t *testing.T, db *DB) (RuntimeClientReference, RuntimeClientReference) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	refs := []RuntimeClientReference{}
	for i, name := range []string{"runtime-source", "runtime-target"} {
		n := int64(i)
		credential := ClientCredential{ID: 901001 + n, TenantID: "default", OwnerUsername: "alice", APIKey: name + "-key", SecretHash: "fixture-hash", Enabled: true, MaxOnlineInstances: 9, CreatedAt: now, UpdatedAt: now}
		if err := db.InsertCredential(ctx, credential); err != nil {
			t.Fatal(err)
		}
		account := ClientAccount{ID: 902001 + n, TenantID: "default", OwnerUsername: "alice", ClientName: name, PasswordHash: "fixture-hash", Enabled: true, CreatedAt: now, UpdatedAt: now}
		identity := ClientIdentity{ID: 903001 + n, TenantID: "default", CredentialID: credential.ID, ClientID: account.ID, ClientName: name, MachineFingerprint: name + "-machine", OSUser: "fixture", Hostname: "fixture", FirstSeenAt: now, LastSeenAt: now}
		if err := db.InsertClientWithIdentity(ctx, account, identity); err != nil {
			t.Fatal(err)
		}
		ref := RuntimeClientReference{SessionID: 904001 + n, CredentialID: credential.ID, IdentityID: identity.ID, ClientID: account.ID, TenantID: "default", ClientName: name, TokenHash: strings.Repeat(string(rune('a'+i)), 64), ChannelID: name + "-channel", MachineFingerprint: identity.MachineFingerprint, OSUser: identity.OSUser, ExpiresAt: now.Add(time.Hour)}
		if err := db.InsertClientSession(ctx, ClientSession{ID: ref.SessionID, TenantID: ref.TenantID, CredentialID: ref.CredentialID, IdentityID: ref.IdentityID, ClientID: ref.ClientID, ClientName: ref.ClientName, TokenHash: ref.TokenHash, Status: "NETTY_ONLINE", MachineFingerprint: ref.MachineFingerprint, OSUser: ref.OSUser, HTTPLoginAt: now, NettyConnectedAt: &now, ExpiresAt: ref.ExpiresAt, ChannelID: &ref.ChannelID}); err != nil {
			t.Fatal(err)
		}
		key := name + "-public"
		if err := db.InsertPeerMeshDevice(ctx, PeerMeshDevice{ID: 905001 + n, TenantID: "default", OwnerUsername: "alice", ClientID: ref.ClientID, ClientName: name, VirtualIP: []string{"100.123.40.1", "100.123.40.2"}[i], CIDR: "100.96.0.0/11", PublicKey: &key, Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
		refs = append(refs, ref)
	}
	return refs[0], refs[1]
}

func TestPeerRuntimeOriginalBindingCannotFollowMutableSQL(t *testing.T) {
	for _, mutation := range []string{"source-channel", "target-channel", "source-client", "target-client", "credential-binding", "identity-binding", "token-hash", "fingerprint", "os-user", "status", "expiry", "case-tenant", "parent-disabled", "parent-renamed", "credential-disabled", "identity-client", "identity-credential", "identity-fingerprint"} {
		t.Run(mutation, func(t *testing.T) {
			db := provisionTestDB(t)
			ctx := context.Background()
			source, target := runtimePublicationFixture(t, db)
			query := ""
			switch mutation {
			case "source-channel":
				query = "UPDATE specus_client_session SET channel_id='replacement' WHERE id=904001"
			case "target-channel":
				query = "UPDATE specus_client_session SET channel_id='replacement' WHERE id=904002"
			case "source-client":
				query = "UPDATE specus_client_session SET client_id=902002 WHERE id=904001"
			case "target-client":
				query = "UPDATE specus_client_session SET client_id=902001 WHERE id=904002"
			case "credential-binding":
				query = "UPDATE specus_client_session SET credential_id=901002 WHERE id=904001"
			case "identity-binding":
				query = "UPDATE specus_client_session SET identity_id=903002 WHERE id=904001"
			case "token-hash":
				query = "UPDATE specus_client_session SET token_hash='replacement' WHERE id=904001"
			case "fingerprint":
				query = "UPDATE specus_client_session SET machine_fingerprint='replacement' WHERE id=904001"
			case "os-user":
				query = "UPDATE specus_client_session SET os_user='replacement' WHERE id=904001"
			case "status":
				query = "UPDATE specus_client_session SET status='DISCONNECTED' WHERE id=904001"
			case "expiry":
				query = "UPDATE specus_client_session SET expires_at='2000-01-01T00:00:00Z' WHERE id=904001"
			case "case-tenant":
				query = "UPDATE specus_client_session SET tenant_id='DEFAULT' WHERE id=904001"
			case "parent-disabled":
				query = "UPDATE specus_client_account SET enabled=0 WHERE id=902001"
			case "parent-renamed":
				query = "UPDATE specus_client_account SET client_name='replacement' WHERE id=902001"
			case "credential-disabled":
				query = "UPDATE specus_client_credential SET enabled=0 WHERE id=901001"
			case "identity-client":
				query = "UPDATE specus_client_identity SET client_id=902002 WHERE id=903001"
			case "identity-credential":
				query = "UPDATE specus_client_identity SET credential_id=901002 WHERE id=903001"
			case "identity-fingerprint":
				query = "UPDATE specus_client_identity SET machine_fingerprint='replacement' WHERE id=903001"
			}
			if _, err := db.sql.Exec(query); err != nil {
				t.Fatal(err)
			}
			out, err := db.AdmitRuntimePeerMeshSession(ctx, source, target, peerAdmissionSeed(906001, "grant-hash"))
			if !errors.Is(err, ErrPeerRuntimeChanged) || out.Session.ID != 0 {
				t.Fatalf("stale original binding admitted: %v", err)
			}
			called := false
			if err := db.PublishPeerSignal(ctx, source, target, 0, "", func(PeerSignalPublication) error { called = true; return nil }); !errors.Is(err, ErrPeerRuntimeChanged) || called {
				t.Fatalf("stale original binding published: %v called=%v", err, called)
			}
			var count int
			if err := db.sql.QueryRow("SELECT COUNT(*) FROM peer_mesh_session").Scan(&count); err != nil || count != 0 {
				t.Fatal("failed runtime admission left SQL authority")
			}
		})
	}
}

func TestPeerRuntimePublicationUsesCurrentMaterialAndCommittedGrant(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	source, target := runtimePublicationFixture(t, db)
	grant, err := db.AdmitRuntimePeerMeshSession(ctx, source, target, peerAdmissionSeed(906001, "grant-hash"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec("UPDATE peer_mesh_device SET public_key='current-key' WHERE client_id=902002"); err != nil {
		t.Fatal(err)
	}
	called := 0
	if err := db.PublishPeerSignal(ctx, source, target, grant.Session.ID, "grant-hash", func(current PeerSignalPublication) error {
		called++
		if current.Session == nil || current.TargetDevice.PublicKey == nil || *current.TargetDevice.PublicKey != "current-key" {
			t.Fatal("publication used pre-lock material")
		}
		return errors.New("injected wire failure")
	}); err == nil || called != 1 {
		t.Fatal("wire failure hidden")
	}
	if row, err := db.GetPeerMeshSession(ctx, grant.Session.ID); err != nil || row.Status == "CLOSED" {
		t.Fatal("publication rollback revoked already committed grant")
	}
	for _, hash := range []string{"", "wrong-hash"} {
		if err := db.PublishPeerSignal(ctx, source, target, grant.Session.ID, hash, func(PeerSignalPublication) error { t.Fatal("wrong token published"); return nil }); err == nil {
			t.Fatal("wrong token accepted")
		}
	}
	if _, err := db.CloseReportedPeerMeshSession(ctx, source.PeerClient(), grant.Session.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.PublishPeerSignal(ctx, source, target, grant.Session.ID, "grant-hash", func(PeerSignalPublication) error { t.Fatal("closed grant published"); return nil }); err == nil {
		t.Fatal("closed authority accepted")
	}
}

func TestPeerRuntimeOwnerIsNotAnImmutableAccessBinding(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	source, target := runtimePublicationFixture(t, db)
	now := time.Now()
	if _, err := db.InsertManagementUser(ctx, ManagementUser{Username: "bob", TenantID: "default", Role: ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	root := ManagementWriteActor{Username: "admin", TenantID: "default", Admin: true, BuiltIn: true}
	for i, ref := range []RuntimeClientReference{source, target} {
		if _, err := db.TransferClientOwnership(ctx, ownerWriteRequest(t, db, root, OwnerScopeSingle, ref.ClientID, "bob", 907001+int64(i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.CheckPeerRuntimeCurrent(ctx, source); err != nil {
		t.Fatalf("management transfer revoked original access: %v", err)
	}
	grant, err := db.AdmitRuntimePeerMeshSession(ctx, source, target, peerAdmissionSeed(906001, "grant-hash"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PublishPeerSignal(ctx, source, target, grant.Session.ID, "grant-hash", func(current PeerSignalPublication) error {
		if current.Source.OwnerUsername != "bob" || current.Target.OwnerUsername != "bob" {
			t.Fatal("historical owner replayed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPeerRuntimeExplicitGrantReplyDoesNotWidenReverseInitiation(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	source, target := runtimePublicationFixture(t, db)
	now := time.Now()
	if _, err := db.sql.Exec("UPDATE specus_client_account SET owner_username='bob' WHERE id=902002"); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertPeerMeshACL(ctx, PeerMeshACL{ID: 909001, TenantID: "default", OwnerUsername: "admin", SourceClientID: source.ClientID, SourceClientName: source.ClientName, TargetClientID: target.ClientID, TargetClientName: target.ClientName, Allowed: true, Direction: "OUTBOUND", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	grant, err := db.AdmitRuntimePeerMeshSession(ctx, source, target, peerAdmissionSeed(906001, "grant-hash"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PublishPeerSignal(ctx, target, source, grant.Session.ID, "grant-hash", func(PeerSignalPublication) error { return nil }); err != nil {
		t.Fatalf("valid reply leg denied: %v", err)
	}
	if err := db.PublishPeerSignal(ctx, target, source, 0, "", func(PeerSignalPublication) error { t.Fatal("new reverse initiation published"); return nil }); !errors.Is(err, ErrPeerAccessDenied) {
		t.Fatalf("existing grant widened initiation: %v", err)
	}
	if _, err := db.AdmitRuntimePeerMeshSession(ctx, target, source, peerAdmissionSeed(906002, "reverse")); !errors.Is(err, ErrPeerAccessDenied) {
		t.Fatal("reverse direction created SQL authority")
	}
}
