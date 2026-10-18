package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"
)

// RuntimeClientReference is captured from the authenticated login, never reconstructed
// from a mutable client name or a later SQL session lookup. Owner is deliberately absent:
// management-only transfer retains access, while publication checks CURRENT peer policy.
type RuntimeClientReference struct {
	SessionID, CredentialID, IdentityID, ClientID int64
	TenantID, ClientName, TokenHash, ChannelID    string
	MachineFingerprint, OSUser                    string
	ExpiresAt                                     time.Time
}

func (r RuntimeClientReference) PeerClient() PeerClientReference {
	return PeerClientReference{ID: r.ClientID, TenantID: r.TenantID, ClientName: r.ClientName}
}

var ErrPeerRuntimeChanged = errors.New("authenticated peer runtime changed")

func (db *DB) lockPeerRuntimes(ctx context.Context, tx *sql.Tx, refs []RuntimeClientReference) error {
	if len(refs) == 0 {
		return ErrPeerRuntimeChanged
	}
	tenant := refs[0].TenantID
	credentials, clients, identities, sessions := []int64{}, []int64{}, []int64{}, []int64{}
	for _, ref := range refs {
		if tenant == "" || ref.TenantID != tenant || ref.ClientID <= 0 || ref.SessionID <= 0 || ref.ClientName == "" || ref.ChannelID == "" || ref.TokenHash == "" || ref.CredentialID < 0 || ref.IdentityID < 0 || !ref.ExpiresAt.After(time.Now()) || (ref.CredentialID > 0) != (ref.IdentityID > 0) {
			return ErrPeerRuntimeChanged
		}
		if ref.CredentialID > 0 {
			credentials = append(credentials, ref.CredentialID)
			identities = append(identities, ref.IdentityID)
		}
		clients = append(clients, ref.ClientID)
		sessions = append(sessions, ref.SessionID)
	}
	// Same order as startup/ownership writers: credentials, parents, identities, sessions.
	for _, id := range sortedOwnerIDs(credentials) {
		row, err := db.lockCredentialForOwnership(ctx, tx, tenant, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPeerRuntimeChanged
		}
		if err != nil {
			return err
		}
		if row.TenantID != tenant || !row.Enabled {
			return ErrPeerRuntimeChanged
		}
	}
	parents := map[int64]*ClientAccount{}
	for _, id := range sortedOwnerIDs(clients) {
		row, err := db.lockClientForOwnership(ctx, tx, tenant, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPeerRuntimeChanged
		}
		if err != nil {
			return err
		}
		if row.TenantID != tenant || !row.Enabled {
			return ErrPeerRuntimeChanged
		}
		parents[id] = row
	}
	type identity struct {
		id, credential, client          int64
		tenant, name, fingerprint, user string
	}
	identityRows := map[int64]identity{}
	for _, id := range sortedOwnerIDs(identities) {
		var row identity
		err := tx.QueryRowContext(ctx, db.rebind(`SELECT id,tenant_id,credential_id,client_id,client_name,machine_fingerprint,os_user FROM specus_client_identity WHERE id=?`)+db.ownershipLockSuffix(), id).Scan(&row.id, &row.tenant, &row.credential, &row.client, &row.name, &row.fingerprint, &row.user)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPeerRuntimeChanged
		}
		if err != nil {
			return err
		}
		identityRows[id] = row
	}
	type runtime struct {
		credential, identity, client                           int64
		tenant, name, hash, status, fingerprint, user, expires string
		channel                                                sql.NullString
	}
	runtimes := map[int64]runtime{}
	for _, id := range sortedOwnerIDs(sessions) {
		var row runtime
		err := tx.QueryRowContext(ctx, db.rebind(`SELECT tenant_id,credential_id,identity_id,client_id,client_name,token_hash,status,machine_fingerprint,os_user,expires_at,channel_id FROM specus_client_session WHERE id=?`)+db.ownershipLockSuffix(), id).Scan(&row.tenant, &row.credential, &row.identity, &row.client, &row.name, &row.hash, &row.status, &row.fingerprint, &row.user, &row.expires, &row.channel)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPeerRuntimeChanged
		}
		if err != nil {
			return err
		}
		runtimes[id] = row
	}
	for _, ref := range refs {
		parent, row := parents[ref.ClientID], runtimes[ref.SessionID]
		if parent.ClientName != ref.ClientName || row.tenant != tenant || row.client != ref.ClientID || row.name != ref.ClientName || row.credential != ref.CredentialID || row.identity != ref.IdentityID || row.status != "NETTY_ONLINE" || !row.channel.Valid || row.channel.String != ref.ChannelID || row.fingerprint != ref.MachineFingerprint || row.user != ref.OSUser || subtle.ConstantTimeCompare([]byte(row.hash), []byte(ref.TokenHash)) != 1 || !parseTime(row.expires).After(time.Now()) || formatTime(parseTime(row.expires)) != formatTime(ref.ExpiresAt) {
			return ErrPeerRuntimeChanged
		}
		if ref.IdentityID > 0 {
			identity := identityRows[ref.IdentityID]
			if identity.tenant != tenant || identity.credential != ref.CredentialID || identity.client != ref.ClientID || identity.name != ref.ClientName || identity.fingerprint != ref.MachineFingerprint || identity.user != ref.OSUser {
				return ErrPeerRuntimeChanged
			}
		}
	}
	return nil
}

func (db *DB) CheckPeerRuntimeCurrent(ctx context.Context, ref RuntimeClientReference) error {
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := db.lockPeerRuntimes(ctx, tx, []RuntimeClientReference{ref}); err != nil {
		return err
	}
	return tx.Commit()
}
