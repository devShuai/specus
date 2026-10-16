package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	ErrManagementResourceForbidden = errors.New("current management identity cannot access resource")
	ErrManagementResourceConflict  = errors.New("resource name or key already exists")
)

// Patches contain ONLY fields the management API permits. Owner, tenant, password, creation
// time and IDs cannot accidentally be copied back from an earlier HTTP/database snapshot.
type ManagementClientPatch struct {
	ClientName                   *string
	Enabled                      *bool
	ConnectionRateLimitPerMinute *int
}
type ManagementCredentialPatch struct {
	APIKey, SecretHash *string
	Enabled            *bool
	MaxOnlineInstances *int
}
type ManagementClientWriteResult struct {
	Before, Client     ClientAccount
	RevokedShares      []string
	ClosedPeerSessions []PeerMeshSession
}

func resourceWriteError(err error) error {
	if isUniqueConstraintError(err) {
		return ErrManagementResourceConflict
	}
	return err
}
func currentResourceAccess(actor ManagementWriteActor, tenant, owner string) error {
	if defaultTenant(actor.TenantID) != defaultTenant(tenant) || (!actor.Admin && actor.Username != owner) {
		return ErrManagementResourceForbidden
	}
	return nil
}

func (db *DB) missingManagedResource(ctx context.Context, tx *sql.Tx, table string, id int64) error {
	// Preserve the existing ordinary CRUD 403/404 distinction without taking a foreign tenant
	// row lock. Ownership-transfer endpoints deliberately have their separate hidden-404 rule.
	var found int64
	err := tx.QueryRowContext(ctx, db.rebind(`SELECT id FROM `+table+` WHERE id=?`), id).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return ErrManagementResourceForbidden
}

// Create operations lock the current management row before assigning ownership. Account
// deletion uses that same row before checking owned-resource counts, including empty credentials.
func (db *DB) CreateManagedClient(ctx context.Context, actor ManagementWriteActor, candidate ClientAccount) (*ClientAccount, error) {
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	actor, err = db.lockManagementWriteActor(ctx, tx, actor)
	if err != nil {
		return nil, err
	}
	candidate.TenantID, candidate.OwnerUsername = defaultTenant(actor.TenantID), actor.Username
	if err := db.insertClientOn(ctx, tx, candidate); err != nil {
		return nil, resourceWriteError(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &candidate, nil
}
func (db *DB) CreateManagedCredential(ctx context.Context, actor ManagementWriteActor, candidate ClientCredential) (*ClientCredential, error) {
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	actor, err = db.lockManagementWriteActor(ctx, tx, actor)
	if err != nil {
		return nil, err
	}
	candidate.TenantID, candidate.OwnerUsername = defaultTenant(actor.TenantID), actor.Username
	if err := db.insertCredentialOn(ctx, tx, candidate); err != nil {
		return nil, resourceWriteError(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &candidate, nil
}

// Lock every discovered credential before the parent, then verify the discovery is still
// complete. A concurrent association change is retried in a NEW transaction, never with a
// late credential lock after the parent. Identity rows aren't needed for the access decision.
func (db *DB) lockManagedClient(ctx context.Context, tx *sql.Tx, actor ManagementWriteActor, id int64) (*ClientAccount, error) {
	ids, err := db.clientCredentialIDsOn(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	locked := make(map[int64]bool)
	for _, credentialID := range ids {
		if _, err := db.lockCredentialForOwnership(ctx, tx, actor.TenantID, credentialID); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		locked[credentialID] = true
	}
	client, err := db.lockClientForOwnership(ctx, tx, actor.TenantID, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, db.missingManagedResource(ctx, tx, "specus_client_account", id)
	}
	if err != nil {
		return nil, err
	}
	if err := currentResourceAccess(actor, client.TenantID, client.OwnerUsername); err != nil {
		return nil, err
	}
	current, err := db.clientCredentialIDsOn(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	for _, credentialID := range current {
		if !locked[credentialID] {
			return nil, errOwnerRangeChanged
		}
	}
	return client, nil
}
func (db *DB) clientCredentialIDsOn(ctx context.Context, runner sqlRunner, id int64) ([]int64, error) {
	rows, err := runner.QueryContext(ctx, db.rebind(`SELECT DISTINCT credential_id FROM specus_client_identity WHERE client_id=? ORDER BY credential_id`), id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (db *DB) PatchManagedClient(ctx context.Context, actor ManagementWriteActor, id int64, patch ManagementClientPatch, now time.Time, shareNow int64) (ManagementClientWriteResult, error) {
	for range 4 {
		out, err := db.writeManagedClientOnce(ctx, actor, id, &patch, now, shareNow, nil)
		if !errors.Is(err, errOwnerRangeChanged) || ctx.Err() != nil {
			return out, err
		}
	}
	return ManagementClientWriteResult{}, errOwnerRangeChanged
}
func (db *DB) DeleteManagedClient(ctx context.Context, actor ManagementWriteActor, id int64, now time.Time, shareNow int64, exposure func(HTTPRouteMapping) string) (ManagementClientWriteResult, error) {
	for range 4 {
		out, err := db.writeManagedClientOnce(ctx, actor, id, nil, now, shareNow, exposure)
		if !errors.Is(err, errOwnerRangeChanged) || ctx.Err() != nil {
			return out, err
		}
	}
	return ManagementClientWriteResult{}, errOwnerRangeChanged
}
func (db *DB) writeManagedClientOnce(ctx context.Context, actor ManagementWriteActor, id int64, patch *ManagementClientPatch, now time.Time, shareNow int64, exposure func(HTTPRouteMapping) string) (ManagementClientWriteResult, error) {
	var empty ManagementClientWriteResult
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	actor, err = db.lockManagementWriteActor(ctx, tx, actor)
	if err != nil {
		return empty, err
	}
	client, err := db.lockManagedClient(ctx, tx, actor, id)
	if err != nil {
		return empty, err
	}
	out := ManagementClientWriteResult{Before: *client, Client: *client}
	if patch == nil {
		out.RevokedShares, err = db.deleteClientAuditedOn(ctx, tx, id, actor.Username, shareNow, exposure, &out.ClosedPeerSessions)
		if err != nil {
			return empty, err
		}
	} else {
		if patch.ClientName != nil {
			out.Client.ClientName = *patch.ClientName
		}
		if patch.Enabled != nil {
			out.Client.Enabled = *patch.Enabled
		}
		if patch.ConnectionRateLimitPerMinute != nil {
			out.Client.ConnectionRateLimitPerMinute = *patch.ConnectionRateLimitPerMinute
		}
		out.Client.UpdatedAt = now
		// Never write owner/password even when NULL/empty in legacy storage. The other values
		// below all originate from the locked current row, not an old full-row API object.
		query := `UPDATE specus_client_account SET updated_at=?`
		args := []any{formatTime(now)}
		if patch.ClientName != nil {
			query += `,client_name=?`
			args = append(args, *patch.ClientName)
		}
		if patch.Enabled != nil {
			query += `,enabled=?`
			args = append(args, boolToInt(*patch.Enabled))
		}
		if patch.ConnectionRateLimitPerMinute != nil {
			query += `,connection_rate_limit_per_minute=?`
			args = append(args, *patch.ConnectionRateLimitPerMinute)
		}
		args = append(args, id, defaultTenant(actor.TenantID))
		_, err = tx.ExecContext(ctx, db.rebind(query+` WHERE id=? AND COALESCE(tenant_id,'default')=?`), args...)
		if err != nil {
			return empty, resourceWriteError(err)
		}
		if err := db.renameClientReferencesOn(ctx, tx, out.Client, out.Before.ClientName); err != nil {
			return empty, err
		}
		if out.Before.Enabled && !out.Client.Enabled {
			out.RevokedShares, err = db.revokeActiveShares(ctx, tx, `route_id IN (SELECT id FROM http_route_mapping WHERE client_id=?)`, []any{id}, shareNow, nullableActor(actor.Username), "client-disabled", nil)
			if err != nil {
				return empty, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return out, nil
}

func (db *DB) PatchManagedCredential(ctx context.Context, actor ManagementWriteActor, id int64, patch ManagementCredentialPatch, now time.Time) (*ClientCredential, error) {
	return db.writeManagedCredential(ctx, actor, id, &patch, now)
}
func (db *DB) DeleteManagedCredential(ctx context.Context, actor ManagementWriteActor, id int64) error {
	_, err := db.writeManagedCredential(ctx, actor, id, nil, time.Time{})
	return err
}
func (db *DB) writeManagedCredential(ctx context.Context, actor ManagementWriteActor, id int64, patch *ManagementCredentialPatch, now time.Time) (*ClientCredential, error) {
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	actor, err = db.lockManagementWriteActor(ctx, tx, actor)
	if err != nil {
		return nil, err
	}
	credential, err := db.lockCredentialForOwnership(ctx, tx, actor.TenantID, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, db.missingManagedResource(ctx, tx, "specus_client_credential", id)
	}
	if err != nil {
		return nil, err
	}
	if err := currentResourceAccess(actor, credential.TenantID, credential.OwnerUsername); err != nil {
		return nil, err
	}
	if patch == nil {
		_, err = tx.ExecContext(ctx, db.rebind(`DELETE FROM specus_client_credential WHERE id=? AND tenant_id=?`), id, defaultTenant(actor.TenantID))
	} else {
		// Build the update from provided fields only. In particular an unrelated enabled edit
		// cannot roll back a concurrent key rotation or overwrite owner, even a nullable owner.
		query := `UPDATE specus_client_credential SET updated_at=?`
		args := []any{formatTime(now)}
		if patch.APIKey != nil {
			credential.APIKey = *patch.APIKey
			query += `,api_key=?`
			args = append(args, *patch.APIKey)
		}
		if patch.SecretHash != nil {
			credential.SecretHash = *patch.SecretHash
			query += `,secret_hash=?`
			args = append(args, *patch.SecretHash)
		}
		if patch.Enabled != nil {
			credential.Enabled = *patch.Enabled
			query += `,enabled=?`
			args = append(args, boolToInt(*patch.Enabled))
		}
		if patch.MaxOnlineInstances != nil {
			credential.MaxOnlineInstances = *patch.MaxOnlineInstances
			query += `,max_online_instances=?`
			args = append(args, *patch.MaxOnlineInstances)
		}
		args = append(args, id, defaultTenant(actor.TenantID))
		_, err = tx.ExecContext(ctx, db.rebind(query+` WHERE id=? AND tenant_id=?`), args...)
		credential.UpdatedAt = now
	}
	if err != nil {
		return nil, resourceWriteError(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return credential, nil
}
