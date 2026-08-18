package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openLegacyDemoTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "legacy-demo.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func insertLegacyDemoTestRows(t *testing.T, db *DB, passwordHash, secretHash string) {
	t.Helper()
	now := time.Now().UTC()
	if err := db.InsertClient(context.Background(), ClientAccount{
		ID: 1, TenantID: "default", OwnerUsername: "admin",
		ClientName: legacyDemoClientName, PasswordHash: passwordHash, Enabled: true,
		ConnectionRateLimitPerMinute: 30, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("insert demo client: %v", err)
	}
	if err := db.InsertCredential(context.Background(), ClientCredential{
		ID: 2, TenantID: "default", OwnerUsername: "admin",
		APIKey: legacyDemoCredential, SecretHash: secretHash, Enabled: true,
		MaxOnlineInstances: 2, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("insert demo credential: %v", err)
	}
}

func TestDisableLegacyDemoCredentialsIsExactAndIdempotent(t *testing.T) {
	db := openLegacyDemoTestDB(t)
	insertLegacyDemoTestRows(t, db, legacyDemoSecretSHA256, legacyDemoSecretSHA256)
	now := time.Now().UTC()
	if err := db.InsertClient(context.Background(), ClientAccount{
		ID: 3, TenantID: "default", OwnerUsername: "admin",
		ClientName: "custom-client", PasswordHash: legacyDemoSecretSHA256, Enabled: true,
		ConnectionRateLimitPerMinute: 30, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("insert custom client: %v", err)
	}
	if err := db.InsertCredential(context.Background(), ClientCredential{
		ID: 4, TenantID: "default", OwnerUsername: "admin",
		APIKey: "custom-key", SecretHash: legacyDemoSecretSHA256, Enabled: true,
		MaxOnlineInstances: 2, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("insert custom credential: %v", err)
	}

	result, err := db.DisableLegacyDemoCredentials(context.Background())
	if err != nil {
		t.Fatalf("disable legacy demo credentials: %v", err)
	}
	if result.ClientAccounts != 1 || result.ClientCredentials != 1 {
		t.Fatalf("unexpected cleanup result: %+v", result)
	}
	legacyClient, err := db.FindClientByName(context.Background(), legacyDemoClientName)
	if err != nil || legacyClient == nil || legacyClient.Enabled {
		t.Fatalf("legacy client was not disabled: client=%+v err=%v", legacyClient, err)
	}
	legacyCredential, err := db.FindCredentialByAPIKey(context.Background(), legacyDemoCredential)
	if err != nil || legacyCredential == nil || legacyCredential.Enabled {
		t.Fatalf("legacy credential was not disabled: credential=%+v err=%v", legacyCredential, err)
	}
	customClient, err := db.FindClientByName(context.Background(), "custom-client")
	if err != nil || customClient == nil || !customClient.Enabled {
		t.Fatalf("custom client was changed: client=%+v err=%v", customClient, err)
	}
	customCredential, err := db.FindCredentialByAPIKey(context.Background(), "custom-key")
	if err != nil || customCredential == nil || !customCredential.Enabled {
		t.Fatalf("custom credential was changed: credential=%+v err=%v", customCredential, err)
	}

	second, err := db.DisableLegacyDemoCredentials(context.Background())
	if err != nil {
		t.Fatalf("repeat cleanup: %v", err)
	}
	if second.ClientAccounts != 0 || second.ClientCredentials != 0 {
		t.Fatalf("repeat cleanup must be idempotent: %+v", second)
	}
}

func TestDisableLegacyDemoCredentialsPreservesRotatedValues(t *testing.T) {
	db := openLegacyDemoTestDB(t)
	rotatedHash := strings.Repeat("a", 64)
	insertLegacyDemoTestRows(t, db, rotatedHash, rotatedHash)

	result, err := db.DisableLegacyDemoCredentials(context.Background())
	if err != nil {
		t.Fatalf("disable legacy demo credentials: %v", err)
	}
	if result.ClientAccounts != 0 || result.ClientCredentials != 0 {
		t.Fatalf("rotated credentials must be preserved: %+v", result)
	}
	client, _ := db.FindClientByName(context.Background(), legacyDemoClientName)
	credential, _ := db.FindCredentialByAPIKey(context.Background(), legacyDemoCredential)
	if client == nil || !client.Enabled || credential == nil || !credential.Enabled {
		t.Fatalf("rotated credentials were disabled: client=%+v credential=%+v", client, credential)
	}
}

func TestDisableLegacyDemoCredentialsPreservesCaseInsensitiveNearMatches(t *testing.T) {
	db := openLegacyDemoTestDB(t)
	if _, err := db.sql.Exec(`DROP TABLE specus_client_credential; DROP TABLE specus_client_account;
		CREATE TABLE specus_client_account (
			id INTEGER PRIMARY KEY, client_name TEXT COLLATE NOCASE NOT NULL UNIQUE,
			password_hash TEXT COLLATE NOCASE NOT NULL, enabled INTEGER NOT NULL,
			updated_at TEXT NOT NULL
		);
		CREATE TABLE specus_client_credential (
			id INTEGER PRIMARY KEY, api_key TEXT COLLATE NOCASE NOT NULL UNIQUE,
			secret_hash TEXT COLLATE NOCASE NOT NULL, enabled INTEGER NOT NULL,
			updated_at TEXT NOT NULL
		)`); err != nil {
		t.Fatalf("recreate case-insensitive legacy tables: %v", err)
	}
	now := formatTime(time.Now())
	if _, err := db.sql.Exec(`INSERT INTO specus_client_account
		(id, client_name, password_hash, enabled, updated_at) VALUES (?, ?, ?, 1, ?)`,
		1, "DEMO CLIENT", strings.ToUpper(legacyDemoSecretSHA256), now); err != nil {
		t.Fatalf("insert near-match client: %v", err)
	}
	if _, err := db.sql.Exec(`INSERT INTO specus_client_credential
		(id, api_key, secret_hash, enabled, updated_at) VALUES (?, ?, ?, 1, ?)`,
		2, "Demo-Client", strings.ToUpper(legacyDemoSecretSHA256), now); err != nil {
		t.Fatalf("insert near-match credential: %v", err)
	}

	result, err := db.DisableLegacyDemoCredentials(context.Background())
	if err != nil {
		t.Fatalf("disable legacy demo credentials: %v", err)
	}
	if result.ClientAccounts != 0 || result.ClientCredentials != 0 {
		t.Fatalf("case-insensitive near matches must be preserved: %+v", result)
	}
	var accountEnabled, credentialEnabled int
	if err := db.sql.QueryRow(`SELECT enabled FROM specus_client_account WHERE id = 1`).Scan(&accountEnabled); err != nil {
		t.Fatalf("read near-match client: %v", err)
	}
	if err := db.sql.QueryRow(`SELECT enabled FROM specus_client_credential WHERE id = 2`).Scan(&credentialEnabled); err != nil {
		t.Fatalf("read near-match credential: %v", err)
	}
	if accountEnabled != 1 || credentialEnabled != 1 {
		t.Fatalf("near matches were disabled: account=%d credential=%d", accountEnabled, credentialEnabled)
	}
}

func TestDisableLegacyDemoCredentialsRollsBackBothUpdates(t *testing.T) {
	db := openLegacyDemoTestDB(t)
	insertLegacyDemoTestRows(t, db, legacyDemoSecretSHA256, legacyDemoSecretSHA256)
	_, err := db.sql.Exec(`CREATE TRIGGER reject_legacy_demo_credential_update
		BEFORE UPDATE ON specus_client_credential
		WHEN OLD.api_key = 'demo-client'
		BEGIN
			SELECT RAISE(ABORT, 'forced credential update failure');
		END`)
	if err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}

	if _, err := db.DisableLegacyDemoCredentials(context.Background()); err == nil {
		t.Fatal("cleanup must report the credential update failure")
	}
	client, err := db.FindClientByName(context.Background(), legacyDemoClientName)
	if err != nil || client == nil || !client.Enabled {
		t.Fatalf("client update was not rolled back: client=%+v err=%v", client, err)
	}
}
