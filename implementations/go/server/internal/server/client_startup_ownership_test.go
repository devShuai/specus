package server

import (
	"context"
	"testing"
)

// Authentication can finish before an administrator's transaction commits. Identity creation
// must not use that earlier owner snapshot, even though the unchanged secret remains valid.
func TestStartupIdentityUsesCommittedCredentialOwner(t *testing.T) {
	app, _ := newAPIServer(t)
	ctx := context.Background()
	insertCredentialForTest(t, app, "owner-race", "before", "owner-race-key", "secret", 2)
	before, err := app.DB().FindCredentialByAPIKey(ctx, "owner-race-key")
	if err != nil || before == nil {
		t.Fatalf("credential: %v", err)
	}
	after := *before
	after.OwnerUsername = "after"
	after.MaxOnlineInstances = 7
	if err := app.DB().UpdateCredential(ctx, after); err != nil {
		t.Fatal(err)
	}
	account, _, err := app.findOrCreateClientIdentity(ctx, before, clientEnvironmentInfo{
		MachineFingerprint: "new-machine", OSUser: "user", Hostname: "host",
	})
	if err != nil {
		t.Fatal(err)
	}
	if account.OwnerUsername != "after" {
		t.Fatalf("new client owner = %q, want committed owner after", account.OwnerUsername)
	}
	if before.MaxOnlineInstances != 7 {
		t.Fatalf("response limit = %d, want current limit 7", before.MaxOnlineInstances)
	}
}

func TestStartupIdentityRejectsChangedAuthenticationMaterial(t *testing.T) {
	for _, change := range []string{"disabled", "rotated", "api-key", "deleted", "tenant"} {
		t.Run(change, func(t *testing.T) {
			app, _ := newAPIServer(t)
			ctx := context.Background()
			insertCredentialForTest(t, app, "auth-race", "owner", "auth-race-key", "secret", 2)
			before, err := app.DB().FindCredentialByAPIKey(ctx, "auth-race-key")
			if err != nil || before == nil {
				t.Fatalf("credential: %v", err)
			}
			after := *before
			switch change {
			case "disabled":
				after.Enabled = false
			case "rotated":
				after.SecretHash = "new-secret-hash"
			case "api-key":
				after.APIKey = "new-api-key"
			case "tenant":
				// Ordinary editing cannot retarget a tenant; simulate a separate committed writer.
				if err := app.DB().DeleteCredential(ctx, before.ID); err != nil {
					t.Fatal(err)
				}
				after.TenantID = "other-tenant"
				if err := app.DB().InsertCredential(ctx, after); err != nil {
					t.Fatal(err)
				}
			case "deleted":
				if err := app.DB().DeleteCredential(ctx, before.ID); err != nil {
					t.Fatal(err)
				}
			}
			if change == "disabled" || change == "rotated" || change == "api-key" {
				if err := app.DB().UpdateCredential(ctx, after); err != nil {
					t.Fatal(err)
				}
			}
			_, _, err = app.findOrCreateClientIdentity(ctx, before, clientEnvironmentInfo{
				MachineFingerprint: "new-machine", OSUser: "user", Hostname: "host",
			})
			if err == nil {
				t.Fatal("stale authentication must not create an identity")
			}
			clients, err := app.DB().ListClients(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, client := range clients {
				if client.TenantID == "auth-race" || client.TenantID == "other-tenant" {
					t.Fatalf("rejected authentication created client %+v", client)
				}
			}
		})
	}
}

// A shared credential can have identities with different owners. A reconnect is not a transfer.
func TestStartupIdentityPreservesExistingClientOwner(t *testing.T) {
	app, ts := newAPIServer(t)
	ctx := context.Background()
	insertCredentialForTest(t, app, "mixed-owner", "credential-owner", "mixed-key", "secret", 2)
	clientAuthLoginForTest(t, ts.URL, "mixed-key", "secret", "machine", "user")
	identity, err := app.DB().FindIdentity(ctx, credentialIDForTest(t, app, "mixed-key"), "machine", "user")
	if err != nil || identity == nil {
		t.Fatalf("identity: %v", err)
	}
	account, err := app.DB().GetClient(ctx, identity.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	account.OwnerUsername = "different-client-owner"
	if err := app.DB().UpdateClient(ctx, *account); err != nil {
		t.Fatal(err)
	}
	clientAuthLoginForTest(t, ts.URL, "mixed-key", "secret", "machine", "user")
	current, err := app.DB().GetClient(ctx, identity.ClientID)
	if err != nil || current.OwnerUsername != "different-client-owner" || current.ID != identity.ClientID {
		t.Fatalf("reconnect must preserve owner and id: %+v, %v", current, err)
	}
}
