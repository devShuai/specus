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
		if !actor.Admin || actor.AccountKey != "" || actor.Username == "" || actor.OIDCIdentityKey != "" || actor.OIDCIssuer != "" || actor.OIDCSubject != "" {
			return ManagementWriteActor{}, ErrManagementActorChanged
		}
		return actor, nil
	}
	if strings.TrimSpace(actor.AccountKey) == "" {
		return ManagementWriteActor{}, ErrManagementActorChanged
	}
	user, err := scanManagementUser(tx.QueryRowContext(ctx, db.rebind(`SELECT `+managementUserColumns+
		` FROM specus_management_user WHERE username = ?`+db.ownershipLockSuffix()), actor.AccountKey))
	if errors.Is(err, sql.ErrNoRows) {
		return ManagementWriteActor{}, ErrManagementActorChanged
	}
	if err != nil {
		return ManagementWriteActor{}, err
	}
	if !user.Enabled || user.Username != actor.Username || defaultTenant(user.TenantID) != defaultTenant(actor.TenantID) ||
		(actor.OIDCIdentityKey != "" && (user.OIDCIdentityKey != actor.OIDCIdentityKey || user.OIDCIssuer != actor.OIDCIssuer || user.OIDCSubject != actor.OIDCSubject)) {
		return ManagementWriteActor{}, ErrManagementActorChanged
	}
	actor.Admin = normalizeManagementRole(user.Role) == ManagementRoleAdmin
	return actor, nil
}
