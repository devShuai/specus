package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const (
	legacyDemoClientName   = "Demo client"
	legacyDemoCredential   = "demo-client"
	legacyDemoSecretSHA256 = "937e8d5fbb48bd4949536cd65b8d35c426b80d2f830c5c308e2cdec422ae2244"
)

// LegacyDemoCredentialsDisableResult reports which published demo credentials were changed.
// Zero counts mean either that the rows did not exist, were already disabled, or had been rotated.
type LegacyDemoCredentialsDisableResult struct {
	ClientAccounts    int64
	ClientCredentials int64
}

// DisableLegacyDemoCredentials atomically disables only the exact demo account and startup
// credential shipped by older releases. Matching both the public identifier and the SHA-256
// digest preserves operators' rotated credentials and unrelated rows that happen to reuse one
// half of the old default.
func (db *DB) DisableLegacyDemoCredentials(ctx context.Context) (LegacyDemoCredentialsDisableResult, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return LegacyDemoCredentialsDisableResult{}, fmt.Errorf("begin legacy demo credential cleanup: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	accountIDs, err := exactLegacyAccountIDs(ctx, db, tx)
	if err != nil {
		return LegacyDemoCredentialsDisableResult{}, err
	}
	credentialIDs, err := exactLegacyCredentialIDs(ctx, db, tx)
	if err != nil {
		return LegacyDemoCredentialsDisableResult{}, err
	}

	updatedAt := formatTime(time.Now())
	var accounts int64
	for _, id := range accountIDs {
		result, updateErr := tx.ExecContext(ctx, db.rebind(`UPDATE specus_client_account
			SET enabled = ?, updated_at = ?
			WHERE id = ? AND client_name = ? AND password_hash = ? AND enabled <> 0`),
			boolToInt(false), updatedAt, id, legacyDemoClientName, legacyDemoSecretSHA256)
		if updateErr != nil {
			return LegacyDemoCredentialsDisableResult{}, fmt.Errorf(
				"disable legacy demo client account: %w", updateErr)
		}
		changed, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return LegacyDemoCredentialsDisableResult{}, fmt.Errorf(
				"count disabled legacy demo client accounts: %w", rowsErr)
		}
		accounts += changed
	}
	var credentials int64
	for _, id := range credentialIDs {
		result, updateErr := tx.ExecContext(ctx, db.rebind(`UPDATE specus_client_credential
			SET enabled = ?, updated_at = ?
			WHERE id = ? AND api_key = ? AND secret_hash = ? AND enabled <> 0`),
			boolToInt(false), updatedAt, id, legacyDemoCredential, legacyDemoSecretSHA256)
		if updateErr != nil {
			return LegacyDemoCredentialsDisableResult{}, fmt.Errorf(
				"disable legacy demo client credential: %w", updateErr)
		}
		changed, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return LegacyDemoCredentialsDisableResult{}, fmt.Errorf(
				"count disabled legacy demo client credentials: %w", rowsErr)
		}
		credentials += changed
	}
	if err := tx.Commit(); err != nil {
		return LegacyDemoCredentialsDisableResult{}, fmt.Errorf("commit legacy demo credential cleanup: %w", err)
	}
	return LegacyDemoCredentialsDisableResult{
		ClientAccounts:    accounts,
		ClientCredentials: credentials,
	}, nil
}

// The SQL predicate intentionally remains narrow for index use, but it is not the trust boundary:
// common MySQL collations compare identifiers case-insensitively. Go's == supplies the same ordinal
// second check used by the Java and .NET implementations before any row is updated.
func exactLegacyAccountIDs(ctx context.Context, db *DB, tx *sql.Tx) ([]int64, error) {
	query := `SELECT id, client_name, password_hash
		FROM specus_client_account
		WHERE client_name = ? AND password_hash = ? AND enabled <> 0`
	if db.dialect != DialectSQLite {
		query += " FOR UPDATE"
	}
	rows, err := tx.QueryContext(ctx, db.rebind(query),
		legacyDemoClientName, legacyDemoSecretSHA256)
	if err != nil {
		return nil, fmt.Errorf("query legacy demo client accounts: %w", err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		var clientName, passwordHash string
		if err := rows.Scan(&id, &clientName, &passwordHash); err != nil {
			return nil, fmt.Errorf("scan legacy demo client account: %w", err)
		}
		if clientName == legacyDemoClientName && passwordHash == legacyDemoSecretSHA256 {
			ids = append(ids, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read legacy demo client accounts: %w", err)
	}
	return ids, nil
}

func exactLegacyCredentialIDs(ctx context.Context, db *DB, tx *sql.Tx) ([]int64, error) {
	query := `SELECT id, api_key, secret_hash
		FROM specus_client_credential
		WHERE api_key = ? AND secret_hash = ? AND enabled <> 0`
	if db.dialect != DialectSQLite {
		query += " FOR UPDATE"
	}
	rows, err := tx.QueryContext(ctx, db.rebind(query),
		legacyDemoCredential, legacyDemoSecretSHA256)
	if err != nil {
		return nil, fmt.Errorf("query legacy demo client credentials: %w", err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		var apiKey, secretHash string
		if err := rows.Scan(&id, &apiKey, &secretHash); err != nil {
			return nil, fmt.Errorf("scan legacy demo client credential: %w", err)
		}
		if apiKey == legacyDemoCredential && secretHash == legacyDemoSecretSHA256 {
			ids = append(ids, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read legacy demo client credentials: %w", err)
	}
	return ids, nil
}
