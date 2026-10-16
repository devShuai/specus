package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"
)

var ErrPeerAccessDenied = errors.New("peer access denied")

// References come from server-resolved clients, not client-supplied owner or enabled fields.
// Names fence a delayed request for a renamed/reused alias; owner-only transfer retains identity.
type PeerClientReference struct {
	ID                   int64
	TenantID, ClientName string
}
type PeerSessionSeed struct {
	ID                  int64
	PathType, TokenHash string
	TTL                 time.Duration
	ReusableTokenHashes map[int64]string // hashes of this process's cached tokens, never plaintext
}
type PeerSessionAdmission struct {
	Session   PeerMeshSession
	Created   bool
	ClosedIDs []int64
}

type peerAccessState struct {
	source, target             *ClientAccount
	sourceDevice, targetDevice *PeerMeshDevice
	forward, reverse           *PeerMeshACL
}

func peerOwner(value string) string { return defaultOwner(strings.TrimSpace(value)) }
func (p peerAccessState) valid(source, target PeerClientReference) bool {
	return p.source != nil && p.target != nil && p.sourceDevice != nil && p.targetDevice != nil &&
		p.source.ID == source.ID && p.target.ID == target.ID && p.source.TenantID == source.TenantID && p.target.TenantID == target.TenantID && source.TenantID == target.TenantID &&
		p.source.ClientName == source.ClientName && p.target.ClientName == target.ClientName && p.source.Enabled && p.target.Enabled &&
		p.sourceDevice.TenantID == source.TenantID && p.targetDevice.TenantID == target.TenantID && p.sourceDevice.ClientID == source.ID && p.targetDevice.ClientID == target.ID && p.sourceDevice.Enabled && p.targetDevice.Enabled && p.sourceDevice.ClientName == source.ClientName && p.targetDevice.ClientName == target.ClientName
}
func (p peerAccessState) allowed(lockedACLs map[int64]bool) bool {
	if peerOwner(p.source.OwnerUsername) == peerOwner(p.target.OwnerUsername) {
		return true
	}
	valid := func(row *PeerMeshACL, direction string) bool {
		return row != nil && row.TenantID == p.source.TenantID && row.Allowed && (row.Direction == direction || row.Direction == "BOTH") && (lockedACLs == nil || lockedACLs[row.ID])
	}
	return valid(p.forward, "OUTBOUND") || valid(p.reverse, "INBOUND")
}

func (db *DB) peerDeviceOn(ctx context.Context, runner sqlRunner, tenant string, id int64) (*PeerMeshDevice, error) {
	row, err := scanPeerMeshDevice(runner.QueryRowContext(ctx, db.rebind(`SELECT `+peerDeviceWriteColumns+` FROM peer_mesh_device WHERE tenant_id=? AND client_id=?`), tenant, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}
func (db *DB) peerACLOn(ctx context.Context, runner sqlRunner, tenant string, source, target int64) (*PeerMeshACL, error) {
	row, err := scanPeerMeshACL(runner.QueryRowContext(ctx, db.rebind(`SELECT id,tenant_id,owner_username,source_client_id,source_client_name,target_client_id,target_client_name,allowed,direction,created_at,updated_at FROM peer_mesh_acl WHERE tenant_id=? AND source_client_id=? AND target_client_id=?`), tenant, source, target))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}
func (db *DB) peerAccessOn(ctx context.Context, runner sqlRunner, source, target PeerClientReference) (peerAccessState, error) {
	var p peerAccessState
	var err error
	if p.source, err = db.getClientByID(ctx, runner, source.ID); err != nil {
		return p, err
	}
	if p.target, err = db.getClientByID(ctx, runner, target.ID); err != nil {
		return p, err
	}
	if p.source == nil || p.target == nil {
		return p, nil
	}
	if p.sourceDevice, err = db.peerDeviceOn(ctx, runner, source.TenantID, source.ID); err != nil {
		return p, err
	}
	if p.targetDevice, err = db.peerDeviceOn(ctx, runner, target.TenantID, target.ID); err != nil {
		return p, err
	}
	if p.forward, err = db.peerACLOn(ctx, runner, source.TenantID, source.ID, target.ID); err != nil {
		return p, err
	}
	if p.reverse, err = db.peerACLOn(ctx, runner, source.TenantID, target.ID, source.ID); err != nil {
		return p, err
	}
	return p, nil
}
func (db *DB) beginPeerAccessRead(ctx context.Context) (*sql.Tx, error) {
	options := &sql.TxOptions{ReadOnly: true}
	if db.dialect != DialectSQLite {
		options.Isolation = sql.LevelRepeatableRead
	}
	return db.sql.BeginTx(ctx, options)
}

// CheckPeerAccessCurrent reads one database snapshot. It is not a grant-creation boundary:
// admission below revalidates under ordered parent/device/ACL locks in its writing transaction.
func (db *DB) CheckPeerAccessCurrent(ctx context.Context, source, target PeerClientReference) (bool, error) {
	if source.TenantID != target.TenantID {
		return false, nil
	}
	source.TenantID = defaultTenant(source.TenantID)
	target.TenantID = defaultTenant(target.TenantID)
	tx, err := db.beginPeerAccessRead(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	p, err := db.peerAccessOn(ctx, tx, source, target)
	if err != nil {
		return false, err
	}
	allowed := p.valid(source, target) && p.allowed(nil)
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return allowed, nil
}

// ListCurrentPeerRoster uses three bulk collections in one repeatable snapshot, not a page or
// per-device current-owner lookup. Parent ownership is authoritative even if a legacy device's
// denormalized owner is wrong. The same directional predicate used by grant admission applies.
func (db *DB) ListCurrentPeerRoster(ctx context.Context, source PeerClientReference) ([]PeerMeshDevice, error) {
	source.TenantID = defaultTenant(source.TenantID)
	tx, err := db.beginPeerAccessRead(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, db.rebind(`SELECT id,COALESCE(tenant_id,'default'),COALESCE(owner_username,''),client_name,enabled FROM specus_client_account WHERE COALESCE(tenant_id,'default')=? ORDER BY id`), source.TenantID)
	if err != nil {
		return nil, err
	}
	clients := map[int64]*ClientAccount{}
	for rows.Next() {
		var client ClientAccount
		var enabled databaseBoolean
		if err := rows.Scan(&client.ID, &client.TenantID, &client.OwnerUsername, &client.ClientName, &enabled); err != nil {
			rows.Close()
			return nil, err
		}
		client.Enabled = bool(enabled)
		if client.TenantID == source.TenantID {
			clients[client.ID] = &client
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	current := clients[source.ID]
	if current == nil || current.ClientName != source.ClientName {
		return nil, ErrNotFound
	}
	rows, err = tx.QueryContext(ctx, db.rebind(`SELECT `+peerDeviceWriteColumns+` FROM peer_mesh_device WHERE tenant_id=? ORDER BY id`), source.TenantID)
	if err != nil {
		return nil, err
	}
	devices := map[int64]*PeerMeshDevice{}
	for rows.Next() {
		device, err := scanPeerMeshDevice(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if device.TenantID == source.TenantID {
			devices[device.ClientID] = &device
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, db.rebind(`SELECT id,tenant_id,owner_username,source_client_id,source_client_name,target_client_id,target_client_name,allowed,direction,created_at,updated_at FROM peer_mesh_acl WHERE tenant_id=? ORDER BY id`), source.TenantID)
	if err != nil {
		return nil, err
	}
	type edge struct{ source, target int64 }
	acls := map[edge]*PeerMeshACL{}
	for rows.Next() {
		acl, err := scanPeerMeshACL(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if acl.TenantID == source.TenantID {
			acls[edge{acl.SourceClientID, acl.TargetClientID}] = &acl
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]PeerMeshDevice, 0)
	ids := make([]int64, 0, len(devices))
	for id := range devices {
		ids = append(ids, id)
	}
	for _, id := range sortedOwnerIDs(ids) {
		if id == source.ID {
			continue
		}
		target := clients[id]
		if target == nil {
			continue
		}
		ref := PeerClientReference{ID: id, TenantID: source.TenantID, ClientName: target.ClientName}
		p := peerAccessState{source: current, target: target, sourceDevice: devices[source.ID], targetDevice: devices[id], forward: acls[edge{source.ID, id}], reverse: acls[edge{id, source.ID}]}
		if p.valid(source, ref) && p.allowed(nil) {
			out = append(out, *devices[id])
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func (db *DB) lockPeerIDsOn(ctx context.Context, tx *sql.Tx, query string, args ...any) (map[int64]bool, error) {
	rows, err := tx.QueryContext(ctx, db.rebind(query+db.ownershipLockSuffix()), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids[id] = true
	}
	return ids, rows.Err()
}

const peerAdmissionSessionColumns = `id,tenant_id,source_client_id,source_client_name,target_client_id,target_client_name,path_type,status,token_hash,started_at,updated_at,expires_at,closed_at,rtt_millis,local_endpoint,remote_endpoint,direct_bytes,relay_bytes,last_traffic_at`

func (db *DB) AdmitPeerMeshSession(ctx context.Context, source, target PeerClientReference, seed PeerSessionSeed) (PeerSessionAdmission, error) {
	if source.TenantID != target.TenantID {
		return PeerSessionAdmission{}, ErrPeerAccessDenied
	}
	source.TenantID = defaultTenant(source.TenantID)
	target.TenantID = defaultTenant(target.TenantID)
	for range 4 {
		out, err := db.admitPeerMeshSessionOnce(ctx, source, target, seed)
		if !errors.Is(err, errOwnerRangeChanged) || ctx.Err() != nil {
			return out, err
		}
	}
	return PeerSessionAdmission{}, errOwnerRangeChanged
}
func (db *DB) admitPeerMeshSessionOnce(ctx context.Context, source, target PeerClientReference, seed PeerSessionSeed) (PeerSessionAdmission, error) {
	var empty PeerSessionAdmission
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	out, err := db.admitPeerMeshSessionOn(ctx, tx, source, target, seed)
	if err != nil {
		return empty, err
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return out, nil
}

func (db *DB) admitPeerMeshSessionOn(ctx context.Context, tx *sql.Tx, source, target PeerClientReference, seed PeerSessionSeed) (PeerSessionAdmission, error) {
	var empty PeerSessionAdmission
	for _, id := range sortedOwnerIDs([]int64{source.ID, target.ID}) {
		parent, err := db.lockClientForOwnership(ctx, tx, source.TenantID, id)
		if errors.Is(err, sql.ErrNoRows) {
			return empty, ErrPeerAccessDenied
		}
		if err != nil {
			return empty, err
		}
		if parent.TenantID != source.TenantID {
			return empty, ErrPeerAccessDenied
		}
	}
	devices, err := db.lockPeerIDsOn(ctx, tx, `SELECT id FROM peer_mesh_device WHERE tenant_id=? AND client_id IN (?,?) ORDER BY id`, source.TenantID, source.ID, target.ID)
	if err != nil {
		return empty, err
	}
	acls, err := db.lockPeerIDsOn(ctx, tx, `SELECT id FROM peer_mesh_acl WHERE tenant_id=? AND ((source_client_id=? AND target_client_id=?) OR (source_client_id=? AND target_client_id=?)) ORDER BY id`, source.TenantID, source.ID, target.ID, target.ID, source.ID)
	if err != nil {
		return empty, err
	}
	p, err := db.peerAccessOn(ctx, tx, source, target)
	if err != nil {
		return empty, err
	}
	if !p.valid(source, target) || !p.allowed(nil) {
		return empty, ErrPeerAccessDenied
	}
	// An ACL inserted after an absent-row discovery isn't a locked proof. Retry rather than
	// allowing it to be deleted again between this read and the grant insert. Same-owner
	// authorization depends only on the parents we already hold, not an unrelated ACL.
	if !devices[p.sourceDevice.ID] || !devices[p.targetDevice.ID] || !p.allowed(acls) {
		return empty, errOwnerRangeChanged
	}
	rows, err := tx.QueryContext(ctx, db.rebind(`SELECT `+peerAdmissionSessionColumns+` FROM peer_mesh_session WHERE tenant_id=? AND UPPER(status)<>'CLOSED' AND ((source_client_id=? AND target_client_id=?) OR (source_client_id=? AND target_client_id=?)) ORDER BY id`+db.ownershipLockSuffix()), source.TenantID, source.ID, target.ID, target.ID, source.ID)
	if err != nil {
		return empty, err
	}
	var existing []PeerMeshSession
	for rows.Next() {
		row, err := scanPeerMeshSession(rows)
		if err != nil {
			rows.Close()
			return empty, err
		}
		existing = append(existing, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return empty, err
	}
	now := time.Now().UTC()
	out := PeerSessionAdmission{}
	// SQL locks are acquired in ID order; reuse preference stays most-recent as before.
	sort.Slice(existing, func(i, j int) bool {
		if existing[i].UpdatedAt.Equal(existing[j].UpdatedAt) {
			return existing[i].ID > existing[j].ID
		}
		return existing[i].UpdatedAt.After(existing[j].UpdatedAt)
	})
	for _, row := range existing {
		if row.TenantID != source.TenantID {
			continue
		}
		forward := row.SourceClientID == source.ID
		nameMatches := (forward && row.SourceClientName == source.ClientName && row.TargetClientName == target.ClientName) || (!forward && row.SourceClientName == target.ClientName && row.TargetClientName == source.ClientName)
		if row.ClosedAt != nil || !row.ExpiresAt.After(now) || !nameMatches {
			if err := db.closePeerSessionOn(ctx, tx, source.TenantID, row.ID, now); err != nil {
				return empty, err
			}
			out.ClosedIDs = append(out.ClosedIDs, row.ID)
			continue
		}
		hash, has := seed.ReusableTokenHashes[row.ID]
		if out.Session.ID == 0 && has && hash != "" && row.TokenHash != nil && subtle.ConstantTimeCompare([]byte(hash), []byte(*row.TokenHash)) == 1 {
			out.Session = row
		}
	}
	if out.Session.ID == 0 {
		if seed.ID <= 0 || seed.TokenHash == "" || seed.TTL <= 0 {
			return empty, errors.New("invalid server peer grant seed")
		}
		hash := seed.TokenHash
		out.Session = PeerMeshSession{ID: seed.ID, TenantID: source.TenantID, SourceClientID: source.ID, SourceClientName: source.ClientName, TargetClientID: target.ID, TargetClientName: target.ClientName, PathType: seed.PathType, Status: "NEGOTIATING", TokenHash: &hash, StartedAt: now, UpdatedAt: now, ExpiresAt: now.Add(seed.TTL)}
		if err := db.insertPeerMeshSessionOn(ctx, tx, out.Session); err != nil {
			return empty, err
		}
		out.Created = true
	}
	return out, nil
}

func (db *DB) closePeerSessionOn(ctx context.Context, tx *sql.Tx, tenant string, id int64, now time.Time) error {
	_, err := tx.ExecContext(ctx, db.rebind(`UPDATE peer_mesh_session SET status='CLOSED',updated_at=?,closed_at=COALESCE(closed_at,?) WHERE id=? AND tenant_id=? AND UPPER(status)<>'CLOSED'`), formatTime(now), formatTime(now), id, tenant)
	return err
}

// Recheck persistent state under the SAME parent/device boundary as new admission. A delayed
// "disabled" callback cannot close sessions created after re-enable. No network/cache effect
// runs before commit, and only the returned old IDs are eligible for local cache eviction.
func (db *DB) CloseDisabledPeerMeshSessions(ctx context.Context, tenant string, clientID int64) ([]PeerMeshSession, error) {
	tenant = defaultTenant(tenant)
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	parent, err := db.lockClientForOwnership(ctx, tx, tenant, clientID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	device, err := db.peerDeviceForWrite(ctx, tx, tenant, clientID)
	if err != nil {
		return nil, err
	}
	if parent.TenantID != tenant {
		return nil, ErrNotFound
	}
	if parent.Enabled && device != nil && device.TenantID == tenant && device.Enabled {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	rows, err := tx.QueryContext(ctx, db.rebind(`SELECT `+peerAdmissionSessionColumns+` FROM peer_mesh_session WHERE tenant_id=? AND UPPER(status)<>'CLOSED' AND (source_client_id=? OR target_client_id=?) ORDER BY id`+db.ownershipLockSuffix()), tenant, clientID, clientID)
	if err != nil {
		return nil, err
	}
	var closed []PeerMeshSession
	for rows.Next() {
		row, err := scanPeerMeshSession(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if row.TenantID == tenant {
			closed = append(closed, row)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	for i := range closed {
		if err := db.closePeerSessionOn(ctx, tx, tenant, closed[i].ID, now); err != nil {
			return nil, err
		}
		closed[i].Status = "CLOSED"
		closed[i].UpdatedAt = now
		if closed[i].ClosedAt == nil {
			closed[i].ClosedAt = &now
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return closed, nil
}
