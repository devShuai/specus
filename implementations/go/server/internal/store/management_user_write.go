package store

import (
	"context"
	"database/sql"
	"sort"
	"time"
)

type ManagementUserPatch struct {
	PasswordHash, Role *string
	Enabled            *bool
}
type ManagementUserWriteResult struct {
	Before, User          ManagementUser
	RevokedShares         []string
	Disabled, RoleChanged bool
}

func (db *DB) CreateManagedUser(ctx context.Context, actor ManagementWriteActor, candidate ManagementUser) (ManagementUser, error) {
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return ManagementUser{}, err
	}
	defer tx.Rollback()
	actor, err = db.lockManagementWriteActor(ctx, tx, actor)
	if err != nil {
		return ManagementUser{}, err
	}
	if !actor.Admin {
		return ManagementUser{}, ErrManagementResourceForbidden
	}
	candidate.TenantID = defaultTenant(actor.TenantID)
	if err := db.insertManagementUserOn(ctx, tx, &candidate); err != nil {
		return ManagementUser{}, err
	}
	if err := tx.Commit(); err != nil {
		return ManagementUser{}, err
	}
	return candidate, nil
}

func (db *DB) lockManagedUserTarget(ctx context.Context, tx *sql.Tx, actor ManagementWriteActor, expected ManagementUser) (ManagementWriteActor, *ManagementUser, error) {
	keys := map[string]bool{}
	if !actor.BuiltIn && actor.AccountKey != "" {
		keys[actor.AccountKey] = true
	}
	if expected.AccountKey != "" {
		keys[expected.AccountKey] = true
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	locked := make(map[string]*ManagementUser)
	for _, key := range ordered {
		user, err := db.lockManagementUserKey(ctx, tx, actor.TenantID, key)
		if err != nil {
			return actor, nil, err
		}
		locked[key] = user
	}
	currentActor, err := currentManagementWriteActor(actor, locked[actor.AccountKey])
	if err != nil {
		return actor, nil, err
	}
	if !currentActor.Admin {
		return actor, nil, ErrManagementResourceForbidden
	}
	target := locked[expected.AccountKey]
	if target == nil || target.AccountKey != expected.AccountKey || target.Username != expected.Username || defaultTenant(target.TenantID) != defaultTenant(expected.TenantID) {
		return actor, nil, ErrNotFound
	}
	return currentActor, target, nil
}

// A server-resolved immutable target key, not a reusable public login lookup, is carried through
// the boundary. Target and actor locks share transfer's total key order (including self-edits).
func (db *DB) PatchManagedUser(ctx context.Context, actor ManagementWriteActor, expected ManagementUser, patch ManagementUserPatch, now time.Time, shareNow int64, lapse ShareLapseFunc) (ManagementUserWriteResult, error) {
	var empty ManagementUserWriteResult
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	actor, current, err := db.lockManagedUserTarget(ctx, tx, actor, expected)
	if err != nil {
		return empty, err
	}
	out := ManagementUserWriteResult{Before: *current, User: *current}
	query := `UPDATE specus_management_user SET updated_at=?`
	args := []any{formatTime(now)}
	if patch.PasswordHash != nil {
		out.User.PasswordHash = *patch.PasswordHash
		query += `,password_hash=?`
		args = append(args, *patch.PasswordHash)
	}
	if patch.Role != nil {
		out.User.Role = normalizeManagementRole(*patch.Role)
		query += `,role=?`
		args = append(args, out.User.Role)
	}
	if patch.Enabled != nil {
		out.User.Enabled = *patch.Enabled
		query += `,enabled=?`
		args = append(args, boolToInt(*patch.Enabled))
	}
	args = append(args, current.AccountKey, defaultTenant(current.TenantID))
	if _, err := tx.ExecContext(ctx, db.rebind(query+` WHERE username=? AND tenant_id=?`), args...); err != nil {
		return empty, err
	}
	out.User.UpdatedAt = now
	out.Disabled = out.Before.Enabled && !out.User.Enabled
	out.RoleChanged = out.Before.Enabled && normalizeManagementRole(out.Before.Role) != normalizeManagementRole(out.User.Role)
	if out.Disabled || out.RoleChanged {
		if err := db.revokeWebSocketTicketsOn(ctx, tx, defaultTenant(current.TenantID), current.Username); err != nil {
			return empty, err
		}
	}
	out.RevokedShares, err = db.revokeActiveShares(ctx, tx, `tenant_id = ? AND LOWER(created_by) = LOWER(?)`, []any{defaultTenant(current.TenantID), current.Username}, shareNow, nullableActor(actor.Username), "creator-lost-access", lapse)
	if err != nil {
		return empty, err
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return out, nil
}

func (db *DB) DeleteManagedUser(ctx context.Context, actor ManagementWriteActor, expected ManagementUser, shareNow int64, lapse ShareLapseFunc) (ManagementUserWriteResult, error) {
	var empty ManagementUserWriteResult
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	actor, current, err := db.lockManagedUserTarget(ctx, tx, actor, expected)
	if err != nil {
		return empty, err
	}
	out := ManagementUserWriteResult{Before: *current, User: *current}
	// READ COMMITTED plus the target account lock makes subsequent ownership counts current.
	// A concurrent create/transfer either commits first and is counted, or cannot target the
	// deleted immutable key. PostgreSQL row-version publication also rejects older RR writers.
	out.RevokedShares, err = db.deleteManagementUserAuditedOn(ctx, tx, *current, actor.Username, shareNow, lapse)
	if err != nil {
		return empty, err
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return out, nil
}
