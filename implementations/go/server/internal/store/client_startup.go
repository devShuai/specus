package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"strconv"
)

// ErrClientStartupChanged rejects authentication material invalidated between signature
// verification and identity provisioning. Ownership and online limits are deliberately not
// authentication material: management-only transfers retain the credential's access capability.
var ErrClientStartupChanged = errors.New("client startup credential changed or is disabled")

// beginClientOwnershipWrite acquires SQLite's writer reservation before any read snapshot.
// Row-locking databases use READ COMMITTED plus explicit, ordered current-row locks. Future
// ownership writers must use the same credential -> client -> identity/device order after
// their management actor/target locks; this is
// not a process mutex, so separate server processes coordinate through the database as well.
func (db *DB) beginClientOwnershipWrite(ctx context.Context) (*sql.Tx, error) {
	var options *sql.TxOptions
	if db.dialect != DialectSQLite {
		options = &sql.TxOptions{Isolation: sql.LevelReadCommitted}
	}
	tx, err := db.sql.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	if db.dialect == DialectSQLite {
		if _, err := tx.ExecContext(ctx, `UPDATE specus_client_credential SET id = id WHERE 1 = 0`); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
	}
	return tx, nil
}

func (db *DB) ownershipLockSuffix() string {
	if db.dialect == DialectSQLite {
		return ""
	}
	return " FOR UPDATE"
}

// ResolveClientStartup validates the previously authenticated credential against its locked,
// current row, then reuses or creates the identity atomically. Candidate rows contain generated
// IDs/name/password only; their owner/tenant are never trusted. There is no network I/O or
// caller callback inside the transaction. Returns the current credential for response limits.
func (db *DB) ResolveClientStartup(ctx context.Context, expected ClientCredential,
	candidate ClientAccount, candidateIdentity ClientIdentity) (*ClientCredential, *ClientAccount, *ClientIdentity, error) {
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	defer tx.Rollback()
	currentCredential, err := db.lockCredentialForOwnership(ctx, tx, expected.TenantID, expected.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil, ErrClientStartupChanged
	}
	if err != nil {
		return nil, nil, nil, err
	}
	credential := *currentCredential
	if !credential.Enabled || credential.APIKey != expected.APIKey ||
		defaultTenant(credential.TenantID) != defaultTenant(expected.TenantID) ||
		subtle.ConstantTimeCompare([]byte(credential.SecretHash), []byte(expected.SecretHash)) != 1 {
		return nil, nil, nil, ErrClientStartupChanged
	}
	identity, err := db.startupIdentityOn(ctx, tx, credential.ID, candidateIdentity, false)
	if err != nil {
		return nil, nil, nil, err
	}
	var account *ClientAccount
	if identity != nil {
		// Read the binding without a child lock, then lock the parent first. Renames/deletions
		// also lock the client before its identity, so taking the identity first would deadlock.
		account, err = db.lockClientForOwnership(ctx, tx, credential.TenantID, identity.ClientID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, nil, ErrClientStartupChanged
		}
		if err != nil {
			return nil, nil, nil, err
		}
		identity, err = db.startupIdentityOn(ctx, tx, credential.ID, candidateIdentity, true)
		if err != nil {
			return nil, nil, nil, err
		}
		if identity == nil || identity.ClientID != account.ID ||
			defaultTenant(identity.TenantID) != defaultTenant(credential.TenantID) ||
			defaultTenant(account.TenantID) != defaultTenant(credential.TenantID) {
			return nil, nil, nil, ErrClientStartupChanged
		}
		// An existing client may intentionally have an owner different from its credential.
		// Preserve current owner/name/enabled/key; only explicit observation fields change.
		identity.Hostname = candidateIdentity.Hostname
		identity.LastSeenAt = candidateIdentity.LastSeenAt
		if _, err := tx.ExecContext(ctx, db.rebind(`UPDATE specus_client_identity SET hostname = ?,
			last_seen_at = ? WHERE id = ?`), identity.Hostname, formatTime(identity.LastSeenAt), identity.ID); err != nil {
			return nil, nil, nil, err
		}
	} else {
		if candidate.ID <= 0 || candidateIdentity.ID <= 0 || candidate.ClientName == "" ||
			candidateIdentity.MachineFingerprint == "" || candidateIdentity.OSUser == "" {
			return nil, nil, nil, errors.New("invalid startup identity candidate")
		}
		candidate.TenantID = defaultTenant(credential.TenantID)
		candidate.OwnerUsername = credential.OwnerUsername
		// Resolve a committed name collision inside the same write boundary, including the
		// normal reconnect race where another process inserted the identity before our lock.
		base := candidate.ClientName
		for suffix := 2; ; suffix++ {
			var id int64
			err := tx.QueryRowContext(ctx, db.rebind(`SELECT id FROM specus_client_account WHERE client_name = ?`), candidate.ClientName).Scan(&id)
			if errors.Is(err, sql.ErrNoRows) {
				break
			}
			if err != nil {
				return nil, nil, nil, err
			}
			extra := "-" + strconv.Itoa(suffix)
			prefix := base
			if len(prefix)+len(extra) > 120 {
				prefix = prefix[:120-len(extra)]
			}
			candidate.ClientName = prefix + extra
		}
		candidateIdentity.TenantID = candidate.TenantID
		candidateIdentity.CredentialID = credential.ID
		candidateIdentity.ClientID = candidate.ID
		candidateIdentity.ClientName = candidate.ClientName
		if err := db.insertClientWithIdentityOn(ctx, tx, candidate, candidateIdentity); err != nil {
			return nil, nil, nil, err
		}
		account, identity = &candidate, &candidateIdentity
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, nil, err
	}
	return &credential, account, identity, nil
}

func (db *DB) startupIdentityOn(ctx context.Context, tx *sql.Tx, credentialID int64,
	key ClientIdentity, lock bool) (*ClientIdentity, error) {
	query := `SELECT id, tenant_id, credential_id, client_id, client_name, machine_fingerprint,
		os_user, COALESCE(hostname, ''), first_seen_at, last_seen_at FROM specus_client_identity
		WHERE credential_id = ? AND machine_fingerprint = ? AND os_user = ?`
	if lock {
		query += db.ownershipLockSuffix()
	}
	var identity ClientIdentity
	var firstSeen, lastSeen string
	err := tx.QueryRowContext(ctx, db.rebind(query), credentialID, key.MachineFingerprint, key.OSUser).Scan(
		&identity.ID, &identity.TenantID, &identity.CredentialID, &identity.ClientID, &identity.ClientName,
		&identity.MachineFingerprint, &identity.OSUser, &identity.Hostname, &firstSeen, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	identity.FirstSeenAt, identity.LastSeenAt = parseTime(firstSeen), parseTime(lastSeen)
	return &identity, nil
}

func (db *DB) lockClientForOwnership(ctx context.Context, tx *sql.Tx, tenant string, id int64) (*ClientAccount, error) {
	// Runtime device creation must invalidate older PostgreSQL RR snapshots of the parent
	// just as credential-derived identity creation invalidates its credential snapshot.
	if _, err := tx.ExecContext(ctx, db.rebind(`UPDATE specus_client_account SET enabled = enabled
		WHERE id = ? AND COALESCE(tenant_id, 'default') = ?`), id, defaultTenant(tenant)); err != nil {
		return nil, err
	}
	var account ClientAccount
	var enabled databaseBoolean
	var created, updated string
	err := tx.QueryRowContext(ctx, db.rebind(`SELECT id, COALESCE(tenant_id, 'default'),
		COALESCE(owner_username, ''), client_name, password_hash, enabled,
		connection_rate_limit_per_minute, created_at, updated_at FROM specus_client_account
		WHERE id = ? AND COALESCE(tenant_id, 'default') = ?`+db.ownershipLockSuffix()), id, defaultTenant(tenant)).Scan(&account.ID, &account.TenantID,
		&account.OwnerUsername, &account.ClientName, &account.PasswordHash, &enabled,
		&account.ConnectionRateLimitPerMinute, &created, &updated)
	if err != nil {
		return nil, err
	}
	account.Enabled = bool(enabled)
	account.CreatedAt, account.UpdatedAt = parseTime(created), parseTime(updated)
	return &account, nil
}

func (db *DB) lockCredentialForOwnership(ctx context.Context, tx *sql.Tx, tenant string, id int64) (*ClientCredential, error) {
	if _, err := tx.ExecContext(ctx, db.rebind(`UPDATE specus_client_credential SET enabled = enabled
		WHERE id = ? AND tenant_id = ?`), id, defaultTenant(tenant)); err != nil {
		return nil, err
	}
	credential, err := scanCredential(tx.QueryRowContext(ctx, db.rebind(`SELECT id, tenant_id,
		COALESCE(owner_username, ''), api_key, secret_hash, enabled, max_online_instances,
		created_at, updated_at FROM specus_client_credential WHERE id = ? AND tenant_id = ?`+db.ownershipLockSuffix()), id, defaultTenant(tenant)))
	if err != nil {
		return nil, err
	}
	return &credential, nil
}
