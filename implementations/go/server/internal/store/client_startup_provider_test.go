package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// Explicitly opt in with an owned, disposable database. Validate its name before Open runs
// migrations; never point this at a deployment database. Ordinary tests exercise SQLite.
func openOwnedStartupProviderDB(t *testing.T) (*DB, context.Context) {
	t.Helper()
	provider, dsn := os.Getenv("SPECUS_TEST_STARTUP_PROVIDER"), os.Getenv("SPECUS_TEST_STARTUP_DSN")
	if provider == "" && dsn == "" {
		t.Skip("requires an explicitly owned MySQL/PostgreSQL startup fixture")
	}
	if os.Getenv("SPECUS_TEST_STARTUP_DATABASE_OWNED") != "1" || dsn == "" {
		t.Fatal("external startup fixture requires explicit ownership and DSN")
	}
	driver, dialect, err := resolveDriver(provider)
	if err != nil || (dialect != DialectMySQL && dialect != DialectPostgres) {
		t.Fatal("external startup fixture must be MySQL or PostgreSQL")
	}
	raw, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	query := "SELECT DATABASE()"
	if dialect == DialectPostgres {
		query = "SELECT current_database()"
	}
	var name string
	if err := raw.QueryRowContext(ctx, query).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, "specus_startup_237_") {
		t.Fatal("refusing to migrate a database outside specus_startup_237_ fixture namespace")
	}
	db, err := Open(provider, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, ctx
}

func TestResolveClientStartupExternalProvider(t *testing.T) {
	db, ctx := openOwnedStartupProviderDB(t)
	credential, candidate, identity := startupFixture(t, db)
	// A concurrent transaction changes the owner after authentication has already read the
	// credential. Native FOR UPDATE must wait, then return the committed row, not an RR snapshot.
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := scanCredential(tx.QueryRowContext(ctx, db.rebind(`SELECT id, tenant_id,
		COALESCE(owner_username, ''), api_key, secret_hash, enabled, max_online_instances,
		created_at, updated_at FROM specus_client_credential WHERE id = ?`+db.ownershipLockSuffix()), credential.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, db.rebind(`UPDATE specus_client_credential SET
		owner_username = ?, max_online_instances = 7 WHERE id = ?`), "committed-owner", credential.ID); err != nil {
		t.Fatal(err)
	}
	type resolution struct {
		credential *ClientCredential
		account    *ClientAccount
		identity   *ClientIdentity
		err        error
	}
	done := make(chan resolution, 1)
	go func() {
		current, account, binding, err := db.ResolveClientStartup(ctx, credential, candidate, identity)
		done <- resolution{current, account, binding, err}
	}()
	select {
	case result := <-done:
		t.Fatalf("native lock did not wait for the current credential: %v", result.err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	result := <-done
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.account.OwnerUsername != "committed-owner" || result.credential.MaxOnlineInstances != 7 ||
		result.identity.ClientID != result.account.ID || result.account.TenantID != credential.TenantID {
		t.Fatal("native lock returned stale credential/binding")
	}
	// Repeated no-op current-row locks must not mistake MySQL changed-rows=0 for a missing row.
	for range 3 {
		_, account, binding, err := db.ResolveClientStartup(ctx, credential, candidate, identity)
		if err != nil || account.ID != result.account.ID || binding.ID != result.identity.ID {
			t.Fatalf("native reconnect: %v", err)
		}
	}
	current := *result.credential
	current.SecretHash = "rotated"
	if err := db.UpdateCredential(ctx, current); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := db.ResolveClientStartup(ctx, credential, candidate, identity); !errors.Is(err, ErrClientStartupChanged) {
		t.Fatalf("native stale secret was not rejected: %v", err)
	}
	t.Logf("native startup boundary PASS: dialect=%s owner/current-limit/reconnect/stale-secret", db.dialect)
}
