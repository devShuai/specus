package store

import (
	"context"
	"crypto/subtle"
	"errors"
)

var (
	ErrManagementPasswordLoginChanged = errors.New("password login identity changed or is disabled")
	ErrManagementPasswordHashChanged  = errors.New("password login hash changed; reverify outside transaction")
)

// CompleteManagementPasswordLogin validates a server-read, successfully verified password
// snapshot against its current immutable account row. Password KDF work NEVER runs under this
// lock. Current role/OIDC/other metadata are returned, not copied back from the old snapshot.
// A changed hash alone returns a current snapshot for bounded OUTSIDE-transaction reverification;
// a deleted/replaced/renamed/disabled identity is never rebound by its reusable login name.
func (db *DB) CompleteManagementPasswordLogin(ctx context.Context, expected ManagementUser) (*ManagementUser, error) {
	if expected.AccountKey == "" {
		return nil, ErrManagementPasswordLoginChanged
	}
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	current, err := db.lockManagementUserKey(ctx, tx, expected.TenantID, expected.AccountKey)
	if err != nil {
		return nil, err
	}
	if current == nil || !current.Enabled || current.AccountKey != expected.AccountKey || current.Username != expected.Username || defaultTenant(current.TenantID) != defaultTenant(expected.TenantID) {
		return nil, ErrManagementPasswordLoginChanged
	}
	if subtle.ConstantTimeCompare([]byte(current.PasswordHash), []byte(expected.PasswordHash)) != 1 {
		return current, ErrManagementPasswordHashChanged
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return current, nil
}

// UpgradeManagementPasswordHash is best-effort maintenance after current authentication.
// Its single conditional write cannot restore enabled/role/OIDC/updated_at, or an older password
// after a concurrent rotation. Zero affected rows are harmless (another upgrade, disable/delete,
// rename or rotation won); MySQL's changed-row convention is not an authentication decision.
func (db *DB) UpgradeManagementPasswordHash(ctx context.Context, expected ManagementUser, upgradedHash string) error {
	if expected.AccountKey == "" || upgradedHash == "" {
		return ErrManagementPasswordLoginChanged
	}
	keyMatch, tenantMatch, hashMatch, nameMatch := `username=?`, `tenant_id=?`, `password_hash=?`, `COALESCE(NULLIF(login_name,''),username)=?`
	if db.dialect == DialectMySQL {
		// MySQL's default VARCHAR collation is commonly case-insensitive. Authentication
		// preimages are bytes: even a case-only replacement must defeat this stale CAS.
		keyMatch = `CAST(username AS BINARY)=CAST(? AS BINARY)`
		tenantMatch = `CAST(tenant_id AS BINARY)=CAST(? AS BINARY)`
		hashMatch = `CAST(password_hash AS BINARY)=CAST(? AS BINARY)`
		nameMatch = `CAST(COALESCE(NULLIF(login_name,''),username) AS BINARY)=CAST(? AS BINARY)`
	}
	_, err := db.sql.ExecContext(ctx, db.rebind(`UPDATE specus_management_user SET password_hash=?
		WHERE `+keyMatch+` AND `+tenantMatch+` AND `+hashMatch+` AND enabled=? AND `+nameMatch), upgradedHash, expected.AccountKey, defaultTenant(expected.TenantID), expected.PasswordHash, boolToInt(true), expected.Username)
	return err
}
