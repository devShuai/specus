package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func startupFixture(t *testing.T, db *DB) (ClientCredential, ClientAccount, ClientIdentity) {
	t.Helper()
	now := time.Now().UTC()
	credential := ClientCredential{ID: 8101, TenantID: "startup", OwnerUsername: "owner",
		APIKey: "startup-key", SecretHash: "hash", Enabled: true, MaxOnlineInstances: 2,
		CreatedAt: now, UpdatedAt: now}
	if err := db.InsertCredential(context.Background(), credential); err != nil {
		t.Fatal(err)
	}
	account := ClientAccount{ID: 8201, ClientName: "startup-host", TenantID: "untrusted",
		OwnerUsername: "untrusted", PasswordHash: "client-hash", Enabled: true,
		ConnectionRateLimitPerMinute: 30, CreatedAt: now, UpdatedAt: now}
	identity := ClientIdentity{ID: 8301, ClientID: 9999, TenantID: "untrusted", CredentialID: 9999,
		ClientName: "untrusted", MachineFingerprint: "machine", OSUser: "user", Hostname: "host",
		FirstSeenAt: now, LastSeenAt: now}
	return credential, account, identity
}

func TestResolveClientStartupConcurrentSeparateDatabaseHandles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	first, err := Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	credential, candidate, identity := startupFixture(t, first)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const workers = 12
	start := make(chan struct{})
	results := make(chan error, workers)
	var wg sync.WaitGroup
	for index := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			db := first
			if index%2 != 0 {
				db = second
			}
			account, id := candidate, identity
			account.ID += int64(index)
			id.ID += int64(index)
			current, resolved, binding, err := db.ResolveClientStartup(ctx, credential, account, id)
			if err == nil && (current.ID != credential.ID || resolved.OwnerUsername != "owner" ||
				resolved.TenantID != "startup" || binding.ClientID != resolved.ID || binding.ClientName != resolved.ClientName) {
				err = fmt.Errorf("inconsistent startup resolution: credential=%+v client=%+v identity=%+v", current, resolved, binding)
			}
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	var clients, identities int
	if err := first.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM specus_client_account`).Scan(&clients); err != nil {
		t.Fatal(err)
	}
	if err := first.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM specus_client_identity`).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if clients != 1 || identities != 1 {
		t.Fatalf("concurrent reconnect created %d accounts / %d identities, want 1 / 1", clients, identities)
	}
}

func TestResolveClientStartupWaitsForCommittedCredential(t *testing.T) {
	for _, outcome := range []string{"owner", "disabled", "rollback"} {
		t.Run(outcome, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "shared.db")
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
			credential, account, identity := startupFixture(t, writer)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			tx, err := writer.beginClientOwnershipWrite(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			enabled := 1
			if outcome == "disabled" {
				enabled = 0
			}
			if _, err := tx.ExecContext(ctx, `UPDATE specus_client_credential SET owner_username = ?,
				max_online_instances = 7, enabled = ? WHERE id = ?`, "new-owner", enabled, credential.ID); err != nil {
				t.Fatal(err)
			}
			type startupResult struct {
				credential *ClientCredential
				account    *ClientAccount
				err        error
			}
			started := make(chan struct{})
			done := make(chan startupResult, 1)
			go func() {
				close(started)
				current, resolved, _, err := reader.ResolveClientStartup(ctx, credential, account, identity)
				done <- startupResult{current, resolved, err}
			}()
			<-started
			// The writer already owns SQLite's reservation. A second handle must not create a
			// client before its decision. This bounded wait does not act as a transaction gate.
			select {
			case result := <-done:
				t.Fatalf("startup completed while credential write was uncommitted: %+v", result)
			case <-time.After(100 * time.Millisecond):
			}
			if outcome == "rollback" {
				err = tx.Rollback()
			} else {
				err = tx.Commit()
			}
			if err != nil {
				t.Fatal(err)
			}
			result := <-done
			if outcome == "disabled" {
				if !errors.Is(result.err, ErrClientStartupChanged) {
					t.Fatalf("disabled credential result: %v", result.err)
				}
				if _, err := reader.GetClient(ctx, account.ID); !errors.Is(err, ErrNotFound) {
					t.Fatalf("disabled credential created a client: %v", err)
				}
				return
			}
			if result.err != nil {
				t.Fatal(result.err)
			}
			owner, limit := "new-owner", 7
			if outcome == "rollback" {
				owner, limit = "owner", 2
			}
			if result.account.OwnerUsername != owner || result.credential.MaxOnlineInstances != limit {
				t.Fatalf("stale/uncommitted result: %+v / %+v", result.account, result.credential)
			}
		})
	}
}

func TestResolveClientStartupCurrentBindingAndAtomicFailure(t *testing.T) {
	for _, scenario := range []string{"collision", "rename", "disabled-client", "missing-client", "cross-tenant", "observation-failure", "identity-insert-failure"} {
		t.Run(scenario, func(t *testing.T) {
			db := provisionTestDB(t)
			ctx := context.Background()
			credential, account, identity := startupFixture(t, db)
			if scenario == "collision" {
				other := account
				other.ID++
				if err := db.InsertClient(ctx, other); err != nil {
					t.Fatal(err)
				}
				_, result, _, err := db.ResolveClientStartup(ctx, credential, account, identity)
				if err != nil || result.ClientName != account.ClientName+"-2" {
					t.Fatalf("name collision: %+v / %v", result, err)
				}
				return
			}
			if scenario == "identity-insert-failure" {
				if _, err := db.sql.ExecContext(ctx, `CREATE TRIGGER fail_startup_insert BEFORE INSERT ON specus_client_identity
					BEGIN SELECT RAISE(ABORT, 'injected identity insertion failure'); END`); err != nil {
					t.Fatal(err)
				}
				if _, _, _, err := db.ResolveClientStartup(ctx, credential, account, identity); err == nil {
					t.Fatal("identity insert failure must abort")
				}
				if _, err := db.GetClient(ctx, account.ID); !errors.Is(err, ErrNotFound) {
					t.Fatalf("identity insertion left orphan account: %v", err)
				}
				return
			}
			_, current, binding, err := db.ResolveClientStartup(ctx, credential, account, identity)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "rename":
				current.ClientName = "renamed"
				current.OwnerUsername = "independent-owner"
				if err := db.UpdateClientAndRenameReferences(ctx, *current, account.ClientName); err != nil {
					t.Fatal(err)
				}
			case "disabled-client":
				current.Enabled = false
				if err := db.UpdateClient(ctx, *current); err != nil {
					t.Fatal(err)
				}
			case "missing-client":
				if _, err := db.sql.ExecContext(ctx, `DELETE FROM specus_client_account WHERE id = ?`, current.ID); err != nil {
					t.Fatal(err)
				}
			case "cross-tenant":
				if _, err := db.sql.ExecContext(ctx, `UPDATE specus_client_identity SET tenant_id = 'other' WHERE id = ?`, binding.ID); err != nil {
					t.Fatal(err)
				}
			case "observation-failure":
				if _, err := db.sql.ExecContext(ctx, `CREATE TRIGGER fail_startup_observation BEFORE UPDATE ON specus_client_identity
					BEGIN SELECT RAISE(ABORT, 'injected last seen failure'); END`); err != nil {
					t.Fatal(err)
				}
			}
			identity.Hostname = "new-host"
			_, resolved, observed, err := db.ResolveClientStartup(ctx, credential, account, identity)
			if scenario == "missing-client" || scenario == "cross-tenant" {
				if !errors.Is(err, ErrClientStartupChanged) {
					t.Fatalf("inconsistent binding must fail closed: %v", err)
				}
				return
			}
			if scenario == "observation-failure" {
				if err == nil {
					t.Fatal("observation write failure must not be ignored")
				}
				unchanged, err := db.FindIdentity(ctx, credential.ID, identity.MachineFingerprint, identity.OSUser)
				if err != nil || unchanged.Hostname != "host" {
					t.Fatalf("failed observation mutated identity: %+v / %v", unchanged, err)
				}
				return
			}
			if err != nil || resolved.ID != current.ID || resolved.ClientName != current.ClientName ||
				resolved.OwnerUsername != current.OwnerUsername || resolved.Enabled != current.Enabled ||
				observed.ID != binding.ID || observed.ClientName != current.ClientName || observed.Hostname != "new-host" {
				t.Fatalf("reconnect overwrote current identity: %+v / %+v / %v", resolved, observed, err)
			}
		})
	}
}
