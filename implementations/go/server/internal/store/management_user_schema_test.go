package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// legacyManagementUserTable is specus_management_user as releases before tenant-scoped login
// names created it: the username is the global primary key and there is no login name.
const legacyManagementUserTable = `CREATE TABLE specus_management_user (
  username TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  oidc_issuer TEXT,
  oidc_subject TEXT,
  oidc_identity_key TEXT,
  role TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
)`

func legacyManagementUserDatabase(t *testing.T, statements ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, statement := range append([]string{legacyManagementUserTable}, statements...) {
		if _, err := raw.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	return path
}

func legacyUserRow(username, tenantID string) string {
	return `INSERT INTO specus_management_user (username, tenant_id, password_hash, role, enabled,
		created_at, updated_at) VALUES ('` + username + `', '` + tenantID + `', 'hash', 'USER', 1,
		'2026-07-31T00:00:00Z', '2026-07-31T00:00:00Z')`
}

// Java ManagementUserSchemaMigratorTests.backfillsLegacyRowsAndEnforcesTenantScopedUniqueness.
func TestLoginNameMigrationBackfillsLegacyRowsAndEnforcesTenantScopedUniqueness(t *testing.T) {
	path := legacyManagementUserDatabase(t, legacyUserRow("Alice", "tenant-a"), legacyUserRow("alice", "tenant-b"))
	for i := 0; i < 2; i++ { // the migration runs on every start
		db, err := Open("sqlite", path)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		db.Close()
	}
	db, err := Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var loginName, normalized string
	if err := db.sql.QueryRow(`SELECT login_name, login_name_normalized FROM specus_management_user
		WHERE username = 'Alice'`).Scan(&loginName, &normalized); err != nil {
		t.Fatal(err)
	}
	if loginName != "Alice" || normalized != "alice" {
		t.Fatalf("backfill = %q/%q, want Alice/alice", loginName, normalized)
	}
	_, err = db.sql.Exec(`INSERT INTO specus_management_user (username, tenant_id, login_name,
		login_name_normalized, password_hash, role, enabled, created_at, updated_at)
		VALUES ('new-key', 'tenant-a', 'ALICE', 'alice', 'hash', 'USER', 1, 'x', 'x')`)
	if err == nil || !isUniqueConstraintError(err) {
		t.Fatalf("a second alice of tenant-a was stored: %v", err)
	}
	// Both accounts keep their key and are found in their own tenant only.
	for tenant, key := range map[string]string{"tenant-a": "Alice", "tenant-b": "alice"} {
		user, err := db.FindManagementUserByLogin(context.Background(), tenant, "ALICE")
		if err != nil || user == nil || user.AccountKey != key || user.TenantID != tenant {
			t.Fatalf("%s: user=%+v err=%v", tenant, user, err)
		}
	}
	if user, err := db.FindManagementUserByLogin(context.Background(), "default", "alice"); err != nil || user != nil {
		t.Fatalf("default tenant found user=%+v err=%v", user, err)
	}
}

// Java ManagementUserSchemaMigratorTests.failsBeforeBackfillWhenLegacyRowsCollideInsideTenant.
func TestLoginNameMigrationFailsBeforeBackfillWhenLegacyRowsCollideInsideTenant(t *testing.T) {
	path := legacyManagementUserDatabase(t, legacyUserRow("Alice", "tenant-a"), legacyUserRow("alice", "tenant-a"))
	db, err := Open("sqlite", path)
	if err == nil {
		db.Close()
		t.Fatal("the store opened with two alices in one tenant")
	}
	if !strings.Contains(err.Error(), "duplicate management login name") || !strings.Contains(err.Error(), "tenant-a") {
		t.Fatalf("error = %v", err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var backfilled int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM specus_management_user WHERE login_name IS NOT NULL`).
		Scan(&backfilled); err != nil {
		t.Fatal(err)
	}
	if backfilled != 0 {
		t.Fatalf("%d rows were backfilled before the failure", backfilled)
	}
}

// Java ManagementUserSchemaMigratorTests.rejectsAnExistingIndexWithTheExpectedNameButWrongDefinition.
func TestLoginNameMigrationRejectsAnIndexWithTheExpectedNameButWrongDefinition(t *testing.T) {
	path := legacyManagementUserDatabase(t,
		`CREATE UNIQUE INDEX uq_management_user_tenant_login_name ON specus_management_user (username)`)
	db, err := Open("sqlite", path)
	if err == nil {
		db.Close()
		t.Fatal("the store opened with a wrong login-name index")
	}
	if !strings.Contains(err.Error(), "must be unique on (tenant_id, login_name_normalized)") {
		t.Fatalf("error = %v", err)
	}
}

var accountKeyPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Java ManagementUserServiceTests.createsSameLoginNameInDifferentTenantWithoutGlobalLookup, at the
// store: a new account gets a random key, not its login name, so tenants can share a login name.
func TestNewAccountsGetRandomKeysAndShareLoginNamesAcrossTenants(t *testing.T) {
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now()
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		user, err := db.InsertManagementUser(ctx, ManagementUser{Username: "Bob", TenantID: tenant,
			PasswordHash: "hash", Role: ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now})
		if err != nil {
			t.Fatalf("%s: %v", tenant, err)
		}
		if !accountKeyPattern.MatchString(user.AccountKey) {
			t.Fatalf("%s: account key %q is not a UUID", tenant, user.AccountKey)
		}
	}
	if _, err := db.InsertManagementUser(ctx, ManagementUser{Username: "BOB", TenantID: "tenant-a",
		PasswordHash: "hash", Role: ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now}); !isUniqueConstraintError(err) {
		t.Fatalf("a second bob of tenant-a: %v", err)
	}
	a, _ := db.FindManagementUserByLogin(ctx, "tenant-a", "bob")
	b, _ := db.FindManagementUserByLogin(ctx, "tenant-b", "bob")
	if a == nil || b == nil || a.AccountKey == b.AccountKey || a.Username != "Bob" || b.TenantID != "tenant-b" {
		t.Fatalf("tenant-a=%+v tenant-b=%+v", a, b)
	}
	if legacy, err := db.FindLegacyManagementUser(ctx, "bob"); err != nil || legacy != nil {
		t.Fatalf("a new account was found by its login name as a legacy key: %+v %v", legacy, err)
	}
}

// Java ManagementUserServiceTests.bareLegacyLoginFailsClosedWhenCaseInsensitiveAccountKeyIsAmbiguous.
func TestLegacyAccountKeyLookupFailsClosedWhenAmbiguous(t *testing.T) {
	path := legacyManagementUserDatabase(t, legacyUserRow("Alice", "tenant-a"), legacyUserRow("alice", "tenant-b"),
		legacyUserRow("carol", "tenant-c"))
	db, err := Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if user, err := db.FindLegacyManagementUser(context.Background(), "ALICE"); err != nil || user != nil {
		t.Fatalf("ambiguous key resolved: user=%+v err=%v", user, err)
	}
	if user, err := db.FindLegacyManagementUser(context.Background(), "Carol"); err != nil || user == nil ||
		user.AccountKey != "carol" || user.TenantID != "tenant-c" {
		t.Fatalf("unique legacy key: user=%+v err=%v", user, err)
	}
}

func insertManagementEmail(t *testing.T, db *DB, accountKey, email string) {
	t.Helper()
	if _, err := db.sql.Exec(`INSERT INTO specus_management_user_email (username, email, verified_at, created_at,
		updated_at) VALUES (?, ?, '2026-07-31T00:00:00Z', '2026-07-31T00:00:00Z', '2026-07-31T00:00:00Z')`,
		accountKey, email); err != nil {
		t.Fatal(err)
	}
}

// Java ManagementAccountsHttpTests.deletingAnAccountReleasesItsEmail: the email row is keyed by the
// account key and goes in the delete's transaction; other accounts keep theirs.
func TestDeletingAnAccountReleasesItsEmail(t *testing.T) {
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "emails.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now()
	var accounts []ManagementUser
	for _, name := range []string{"frank", "grace"} {
		user, err := db.InsertManagementUser(ctx, ManagementUser{Username: name, TenantID: "default",
			PasswordHash: "hash", Role: ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now})
		if err != nil {
			t.Fatal(err)
		}
		insertManagementEmail(t, db, user.AccountKey, name+"@example.com")
		accounts = append(accounts, user)
	}
	if _, err := db.DeleteManagementUserAudited(ctx, accounts[0], "admin", now.UnixMilli(),
		func(HTTPShareSnapshot) string { return "" }); err != nil {
		t.Fatal(err)
	}
	if exists, err := db.ManagementEmailExists(ctx, "FRANK@example.com"); err != nil || exists {
		t.Fatalf("frank's email after the delete: exists=%v err=%v", exists, err)
	}
	if exists, err := db.ManagementEmailExists(ctx, "grace@example.com"); err != nil || !exists {
		t.Fatalf("grace's email: exists=%v err=%v", exists, err)
	}
}

// Java ManagementUserSchemaMigratorTests.removesEmailRecordsOfAccountsThatNoLongerExist.
func TestLoginNameMigrationRemovesEmailRecordsOfDeletedAccounts(t *testing.T) {
	path := legacyManagementUserDatabase(t, legacyUserRow("kept-key", "default"))
	db, err := Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	insertManagementEmail(t, db, "kept-key", "kept@example.com")
	insertManagementEmail(t, db, "deleted-key", "released@example.com")
	db.Close()
	for i := 0; i < 2; i++ { // the migration runs on every start
		db, err = Open("sqlite", path)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		db.Close()
	}
	db, err = Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if exists, err := db.ManagementEmailExists(ctx, "released@example.com"); err != nil || exists {
		t.Fatalf("orphaned email: exists=%v err=%v", exists, err)
	}
	if exists, err := db.ManagementEmailExists(ctx, "kept@example.com"); err != nil || !exists {
		t.Fatalf("kept email: exists=%v err=%v", exists, err)
	}
}
