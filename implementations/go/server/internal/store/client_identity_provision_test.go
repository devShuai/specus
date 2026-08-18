package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func provisionTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "provision.db"))
	if err != nil {
		t.Fatalf("open temp db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestInsertClientWithIdentityCommitsBothRows(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	account := ClientAccount{
		ID: 7001, TenantID: "default", OwnerUsername: "admin", ClientName: "machine-a",
		PasswordHash: "hash", Enabled: true, ConnectionRateLimitPerMinute: 30,
		CreatedAt: now, UpdatedAt: now,
	}
	identity := ClientIdentity{
		ID: 7101, TenantID: "default", CredentialID: 11, ClientID: account.ID,
		ClientName: account.ClientName, MachineFingerprint: "machine", OSUser: "alice",
		Hostname: "host-a", FirstSeenAt: now, LastSeenAt: now,
	}
	if err := db.InsertClientWithIdentity(ctx, account, identity); err != nil {
		t.Fatalf("insert account with identity: %v", err)
	}

	stored, err := db.GetClient(ctx, account.ID)
	if err != nil || stored == nil {
		t.Fatalf("account not persisted: %v", err)
	}
	found, err := db.FindIdentity(ctx, identity.CredentialID, identity.MachineFingerprint, identity.OSUser)
	if err != nil || found == nil {
		t.Fatalf("identity not persisted: %v", err)
	}
	if found.ClientID != account.ID {
		t.Fatalf("identity points at client %d, want %d", found.ClientID, account.ID)
	}
}

// An account inserted without its identity row could never be matched on the next login, while its
// name stayed reserved. A failing identity insert must roll the account back too.
func TestInsertClientWithIdentityRollsBackTheAccountWhenTheIdentityFails(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	first := ClientIdentity{
		ID: 7201, TenantID: "default", CredentialID: 21, ClientID: 7002,
		ClientName: "machine-b", MachineFingerprint: "machine-b", OSUser: "bob",
		Hostname: "host-b", FirstSeenAt: now, LastSeenAt: now,
	}
	if err := db.InsertClientWithIdentity(ctx, ClientAccount{
		ID: 7002, TenantID: "default", OwnerUsername: "admin", ClientName: "machine-b",
		PasswordHash: "hash", Enabled: true, ConnectionRateLimitPerMinute: 30,
		CreatedAt: now, UpdatedAt: now,
	}, first); err != nil {
		t.Fatalf("seed first client: %v", err)
	}

	// Reusing the identity primary key makes the second insert of the transaction fail.
	orphan := ClientAccount{
		ID: 7003, TenantID: "default", OwnerUsername: "admin", ClientName: "machine-c",
		PasswordHash: "hash", Enabled: true, ConnectionRateLimitPerMinute: 30,
		CreatedAt: now, UpdatedAt: now,
	}
	conflicting := ClientIdentity{
		ID: first.ID, TenantID: "default", CredentialID: 31, ClientID: orphan.ID,
		ClientName: orphan.ClientName, MachineFingerprint: "machine-c", OSUser: "carol",
		Hostname: "host-c", FirstSeenAt: now, LastSeenAt: now,
	}
	if err := db.InsertClientWithIdentity(ctx, orphan, conflicting); err == nil {
		t.Fatal("a duplicate identity id must fail the insert")
	}

	// No orphan account, and the name is still free for a later attempt.
	if _, err := db.GetClient(ctx, orphan.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get client err = %v, want ErrNotFound (the account must be rolled back)", err)
	}
	byName, err := db.FindClientByName(ctx, orphan.ClientName)
	if err != nil {
		t.Fatalf("find client by name: %v", err)
	}
	if byName != nil {
		t.Fatal("the rolled-back account must not keep its name reserved")
	}
}
