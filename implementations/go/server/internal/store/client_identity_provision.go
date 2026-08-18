package store

import (
	"context"
)

// InsertClientWithIdentity creates a machine client account and its identity row together.
//
// Inserting the account first and the identity afterwards leaves an orphan account whenever the
// second insert fails: the client cannot be recognised on its next login (no identity to match),
// yet the account name is taken and shows up in the management UI forever. Both rows now commit
// together or not at all.
func (db *DB) InsertClientWithIdentity(ctx context.Context, account ClientAccount,
	identity ClientIdentity) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	accountQuery := db.rebind(`INSERT INTO specus_client_account
		(id, tenant_id, owner_username, client_name, password_hash, enabled,
		 connection_rate_limit_per_minute, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if _, err := tx.ExecContext(ctx, accountQuery, account.ID, defaultTenant(account.TenantID),
		defaultOwner(account.OwnerUsername), account.ClientName, account.PasswordHash,
		boolToInt(account.Enabled), account.ConnectionRateLimitPerMinute,
		formatTime(account.CreatedAt), formatTime(account.UpdatedAt)); err != nil {
		return err
	}

	identityQuery := db.rebind(`INSERT INTO specus_client_identity
		(id, tenant_id, credential_id, client_id, client_name, machine_fingerprint, os_user,
		 hostname, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if _, err := tx.ExecContext(ctx, identityQuery, identity.ID, defaultTenant(identity.TenantID),
		identity.CredentialID, identity.ClientID, identity.ClientName,
		identity.MachineFingerprint, identity.OSUser, identity.Hostname,
		formatTime(identity.FirstSeenAt), formatTime(identity.LastSeenAt)); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}
