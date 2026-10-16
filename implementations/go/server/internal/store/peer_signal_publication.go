package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Bound admission checks the ORIGINAL authenticated runtime and the CURRENT peer policy in
// the same transaction that creates/reuses SQL authority. A name lookup is not an auth proof.
func (db *DB) AdmitRuntimePeerMeshSession(ctx context.Context, source, target RuntimeClientReference, seed PeerSessionSeed) (PeerSessionAdmission, error) {
	if source.ClientID == target.ClientID || source.TenantID != target.TenantID {
		return PeerSessionAdmission{}, ErrPeerRuntimeChanged
	}
	for range 4 {
		out, err := db.admitRuntimePeerMeshSessionOnce(ctx, source, target, seed)
		if !errors.Is(err, errOwnerRangeChanged) || ctx.Err() != nil {
			return out, err
		}
	}
	return PeerSessionAdmission{}, errOwnerRangeChanged
}

func (db *DB) admitRuntimePeerMeshSessionOnce(ctx context.Context, source, target RuntimeClientReference, seed PeerSessionSeed) (PeerSessionAdmission, error) {
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return PeerSessionAdmission{}, err
	}
	defer tx.Rollback()
	if err := db.lockPeerRuntimes(ctx, tx, []RuntimeClientReference{source, target}); err != nil {
		return PeerSessionAdmission{}, err
	}
	out, err := db.admitPeerMeshSessionOn(ctx, tx, source.PeerClient(), target.PeerClient(), seed)
	if err != nil {
		return PeerSessionAdmission{}, err
	}
	if err := tx.Commit(); err != nil {
		return PeerSessionAdmission{}, err
	}
	return out, nil
}

type PeerSignalPublication struct {
	Source, Target             ClientAccount
	SourceDevice, TargetDevice PeerMeshDevice
	Session                    *PeerMeshSession
}

// The grant, if any, has ALREADY committed. This second, bounded publication lease only
// revalidates current identity/policy/material and keeps their SQL locks through the actual
// send callback. It never exposes a newly uncommitted grant. Do not run further DB queries
// inside deliver (SQLite pool1), and do not use an unbounded transport writer there.
func (db *DB) PublishPeerSignal(ctx context.Context, source, target RuntimeClientReference, sessionID int64, tokenHash string, deliver func(PeerSignalPublication) error) error {
	if source.ClientID == target.ClientID || source.TenantID != target.TenantID || deliver == nil || sessionID < 0 || (sessionID > 0 && tokenHash == "") {
		return ErrPeerAccessDenied
	}
	for range 4 {
		err := db.publishPeerSignalOnce(ctx, source, target, sessionID, tokenHash, deliver)
		if !errors.Is(err, errOwnerRangeChanged) || ctx.Err() != nil {
			return err
		}
	}
	return errOwnerRangeChanged
}

func (db *DB) publishPeerSignalOnce(ctx context.Context, source, target RuntimeClientReference, sessionID int64, tokenHash string, deliver func(PeerSignalPublication) error) error {
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := db.lockPeerRuntimes(ctx, tx, []RuntimeClientReference{source, target}); err != nil {
		return err
	}
	a, b := source.PeerClient(), target.PeerClient()
	devices, err := db.lockPeerIDsOn(ctx, tx, `SELECT id FROM peer_mesh_device WHERE tenant_id=? AND client_id IN (?,?) ORDER BY id`, a.TenantID, a.ID, b.ID)
	if err != nil {
		return err
	}
	acls, err := db.lockPeerIDsOn(ctx, tx, `SELECT id FROM peer_mesh_acl WHERE tenant_id=? AND ((source_client_id=? AND target_client_id=?) OR (source_client_id=? AND target_client_id=?)) ORDER BY id`, a.TenantID, a.ID, b.ID, b.ID, a.ID)
	if err != nil {
		return err
	}
	p, err := db.peerAccessOn(ctx, tx, a, b)
	if err != nil {
		return err
	}
	if !p.valid(a, b) {
		return ErrPeerAccessDenied
	}
	if !devices[p.sourceDevice.ID] || !devices[p.targetDevice.ID] {
		return errOwnerRangeChanged
	}
	publication := PeerSignalPublication{Source: *p.source, Target: *p.target, SourceDevice: *p.sourceDevice, TargetDevice: *p.targetDevice}
	policy := p
	if sessionID > 0 {
		row, err := scanPeerMeshSession(tx.QueryRowContext(ctx, db.rebind(`SELECT `+peerAdmissionSessionColumns+` FROM peer_mesh_session WHERE id=?`)+db.ownershipLockSuffix(), sessionID))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPeerAccessDenied
		}
		if err != nil {
			return err
		}
		forward := row.SourceClientID == a.ID && row.SourceClientName == a.ClientName && row.TargetClientID == b.ID && row.TargetClientName == b.ClientName
		reverse := row.SourceClientID == b.ID && row.SourceClientName == b.ClientName && row.TargetClientID == a.ID && row.TargetClientName == a.ClientName
		if row.TenantID != a.TenantID || (!forward && !reverse) || row.ClosedAt != nil || (!strings.EqualFold(row.Status, "ACTIVE") && !strings.EqualFold(row.Status, "NEGOTIATING")) || !row.ExpiresAt.After(time.Now()) || row.TokenHash == nil || subtle.ConstantTimeCompare([]byte(*row.TokenHash), []byte(tokenHash)) != 1 {
			return ErrPeerAccessDenied
		}
		// Replies retain the original grant direction; they do not authorize a new reverse
		// initiation merely because both authenticated participants know its valid token.
		if reverse {
			policy = peerAccessState{source: p.target, target: p.source, sourceDevice: p.targetDevice, targetDevice: p.sourceDevice, forward: p.reverse, reverse: p.forward}
		}
		publication.Session = &row
	}
	if !policy.allowed(nil) {
		return ErrPeerAccessDenied
	}
	if !policy.allowed(acls) {
		return errOwnerRangeChanged
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := deliver(publication); err != nil {
		return err
	}
	return tx.Commit()
}
