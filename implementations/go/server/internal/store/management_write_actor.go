package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

var ErrManagementActorChanged = errors.New("management actor changed or is disabled")

// ManagementWriteActor carries a server-resolved identity, never request JSON. BuiltIn is the
// existing configured-admin capability; DB-backed users must carry their immutable account key.
type ManagementWriteActor struct {
	Username, TenantID, AccountKey string
	Admin, BuiltIn                 bool
	OIDCIdentityKey                string
	OIDCIssuer, OIDCSubject        string
}

// Actor locks precede credential/client/Peer locks. Authorization uses the current role, not
// the cached Admin bit. A renamed/deleted/rebound identity cannot authorize a delayed write.
func (db *DB) lockManagementWriteActor(ctx context.Context, tx *sql.Tx, actor ManagementWriteActor) (ManagementWriteActor, error) {
	if actor.BuiltIn {
		return currentManagementWriteActor(actor, nil)
	}
	if strings.TrimSpace(actor.AccountKey) == "" {
		return ManagementWriteActor{}, ErrManagementActorChanged
	}
	user, err := db.lockManagementUserKey(ctx, tx, actor.TenantID, actor.AccountKey)
	if err != nil {
		return ManagementWriteActor{}, err
	}
	return currentManagementWriteActor(actor, user)
}

func currentManagementWriteActor(actor ManagementWriteActor, user *ManagementUser) (ManagementWriteActor, error) {
	if actor.BuiltIn {
		if !actor.Admin || actor.AccountKey != "" || actor.Username == "" || actor.OIDCIdentityKey != "" || actor.OIDCIssuer != "" || actor.OIDCSubject != "" {
			return ManagementWriteActor{}, ErrManagementActorChanged
		}
		return actor, nil
	}
	if user == nil || !user.Enabled || user.AccountKey != actor.AccountKey || user.Username != actor.Username || defaultTenant(user.TenantID) != defaultTenant(actor.TenantID) ||
		(actor.OIDCIdentityKey != "" && (user.OIDCIdentityKey != actor.OIDCIdentityKey || user.OIDCIssuer != actor.OIDCIssuer || user.OIDCSubject != actor.OIDCSubject)) {
		return ManagementWriteActor{}, ErrManagementActorChanged
	}
	actor.Admin = normalizeManagementRole(user.Role) == ManagementRoleAdmin
	return actor, nil
}

func (db *DB) lockManagementUserKey(ctx context.Context, tx *sql.Tx, tenant, key string) (*ManagementUser, error) {
	// Publish a row version as well as acquiring the lock. A PostgreSQL RR caller that already
	// read an older ownership snapshot must abort rather than delete a now-owning account.
	if _, err := tx.ExecContext(ctx, db.rebind(`UPDATE specus_management_user SET enabled = enabled
		WHERE username = ? AND tenant_id = ?`), key, defaultTenant(tenant)); err != nil {
		return nil, err
	}
	user, err := scanManagementUser(tx.QueryRowContext(ctx, db.rebind(`SELECT `+managementUserColumns+
		` FROM specus_management_user WHERE username = ? AND tenant_id = ?`+db.ownershipLockSuffix()), key, defaultTenant(tenant)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}
