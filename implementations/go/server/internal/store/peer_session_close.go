package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// A managed selection is resolved by storage using the current actor, not a cached list of
// visible IDs. Zero/zero selects the open sessions visible at transaction selection time;
// it is not a promise to close future sessions created after that selection.
type PeerSessionCloseSelection struct{ SessionID, ClientID int64 }

// A closing path report may update its telemetry, but never counters, expiry or identity.
type PeerSessionClosePath struct {
	PathType                      string
	RTTMillis                     *int64
	LocalEndpoint, RemoteEndpoint *string
}

type peerCloseMode uint8

const (
	peerCloseManaged peerCloseMode = iota
	peerCloseReported
	peerCloseExpired
	peerCloseUnauthorized
)

type peerCloseRequest struct {
	mode      peerCloseMode
	tenant    string
	actor     ManagementWriteActor
	reporter  PeerClientReference
	selection PeerSessionCloseSelection
	ids       []int64
	path      *PeerSessionClosePath
}

func (db *DB) CloseManagedPeerMeshSessions(ctx context.Context, actor ManagementWriteActor, selection PeerSessionCloseSelection) ([]PeerMeshSession, error) {
	return db.closeCurrentPeerSessions(ctx, peerCloseRequest{mode: peerCloseManaged, tenant: defaultTenant(actor.TenantID), actor: actor, selection: selection})
}
func (db *DB) CloseReportedPeerMeshSession(ctx context.Context, reporter PeerClientReference, id int64) ([]PeerMeshSession, error) {
	return db.closeCurrentPeerSessions(ctx, peerCloseRequest{mode: peerCloseReported, tenant: defaultTenant(reporter.TenantID), reporter: reporter, ids: []int64{id}})
}
func (db *DB) CloseReportedPeerMeshSessionWithPath(ctx context.Context, reporter PeerClientReference, id int64, path PeerSessionClosePath) ([]PeerMeshSession, error) {
	return db.closeCurrentPeerSessions(ctx, peerCloseRequest{mode: peerCloseReported, tenant: defaultTenant(reporter.TenantID), reporter: reporter, ids: []int64{id}, path: &path})
}
func (db *DB) CloseExpiredPeerMeshSessions(ctx context.Context, tenant string, ids []int64) ([]PeerMeshSession, error) {
	return db.closeCurrentPeerSessions(ctx, peerCloseRequest{mode: peerCloseExpired, tenant: defaultTenant(tenant), ids: ids})
}
func (db *DB) CloseUnauthorizedPeerMeshSessions(ctx context.Context, tenant string, ids []int64) ([]PeerMeshSession, error) {
	return db.closeCurrentPeerSessions(ctx, peerCloseRequest{mode: peerCloseUnauthorized, tenant: defaultTenant(tenant), ids: ids})
}

// Closures are atomic for the selected batch. They never write counters, expiry or identity;
// only an explicit path report may also merge path telemetry. No cache/socket callback runs
// under the transaction or before commit.
func (db *DB) closeCurrentPeerSessions(ctx context.Context, request peerCloseRequest) ([]PeerMeshSession, error) {
	for range 4 {
		rows, err := db.closeCurrentPeerSessionsOnce(ctx, request)
		if !errors.Is(err, errOwnerRangeChanged) || ctx.Err() != nil {
			return rows, err
		}
	}
	return nil, errOwnerRangeChanged
}

func (db *DB) closeCurrentPeerSessionsOnce(ctx context.Context, request peerCloseRequest) ([]PeerMeshSession, error) {
	if request.mode == peerCloseReported && request.reporter.ID <= 0 {
		return nil, ErrPeerAccessDenied
	}
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if request.mode == peerCloseManaged {
		request.actor, err = db.lockManagementWriteActor(ctx, tx, request.actor)
		if err != nil {
			return nil, err
		}
	}
	var hints []PeerMeshSession
	if request.mode == peerCloseManaged {
		if request.selection.SessionID < 0 || request.selection.ClientID < 0 || (request.selection.SessionID > 0 && request.selection.ClientID > 0) {
			return nil, ErrNotFound
		}
		query := `SELECT ` + peerAdmissionSessionColumns + ` FROM peer_mesh_session WHERE tenant_id=?`
		args := []any{request.tenant}
		if request.selection.SessionID > 0 {
			query += ` AND id=?`
			args = append(args, request.selection.SessionID)
		} else {
			query += ` AND UPPER(status)<>'CLOSED'`
			if request.selection.ClientID > 0 {
				query += ` AND (source_client_id=? OR target_client_id=?)`
				args = append(args, request.selection.ClientID, request.selection.ClientID)
			}
		}
		if request.selection.SessionID == 0 && request.selection.ClientID == 0 && !request.actor.Admin {
			hints, err = db.managedPeerCloseCandidates(ctx, tx, request.tenant, request.actor.Username)
		} else {
			hints, err = db.readPeerCloseRows(ctx, tx, query+` ORDER BY id`, args...)
		}
	} else {
		hints, err = db.peerCloseRowsByIDs(ctx, tx, request.ids, false)
	}
	if err != nil {
		return nil, err
	}
	// Permission discovery is a hint only. Acquire locks only for the selected resource
	// graph, then recheck every current owner; do not lock all unrelated tenant parents.
	selected := make([]PeerMeshSession, 0, len(hints))
	parentIDs := []int64{}
	for _, row := range hints {
		if row.TenantID != request.tenant {
			continue
		}
		selected = append(selected, row)
		parentIDs = append(parentIDs, row.SourceClientID, row.TargetClientID)
	}
	if request.mode == peerCloseManaged && request.selection.ClientID > 0 {
		parentIDs = append(parentIDs, request.selection.ClientID)
	}
	if request.mode == peerCloseReported {
		parentIDs = append(parentIDs, request.reporter.ID)
	}
	parents := map[int64]*ClientAccount{}
	covered := map[int64]bool{}
	for _, id := range sortedOwnerIDs(parentIDs) {
		if id <= 0 {
			// Terminal cleanup must not be poisoned by a legacy orphan endpoint. It
			// grants no ownership: users still need a real owned parent, reporters a
			// current positive ID, and administrative cleanup is tenant-bound.
			covered[id] = true
			continue
		}
		parent, err := db.lockClientForOwnership(ctx, tx, request.tenant, id)
		if errors.Is(err, sql.ErrNoRows) {
			parent = nil
			err = nil
		}
		if err != nil {
			return nil, err
		}
		if parent != nil && parent.TenantID != request.tenant {
			return nil, ErrNotFound
		}
		parents[id], covered[id] = parent, true
	}
	if request.mode == peerCloseManaged && request.selection.ClientID > 0 {
		parent := parents[request.selection.ClientID]
		if parent == nil || (!request.actor.Admin && !peerCloseOwner(parent, request.tenant, request.actor.Username)) {
			return nil, ErrNotFound
		}
		device, err := db.peerDeviceOn(ctx, tx, request.tenant, parent.ID)
		if err != nil {
			return nil, err
		}
		if device == nil || device.TenantID != request.tenant {
			return nil, ErrNotFound
		}
	}
	if request.mode == peerCloseReported {
		parent := parents[request.reporter.ID]
		// Closing one's existing session is cleanup; a disabled parent may still close it.
		if parent == nil || parent.TenantID != request.reporter.TenantID || parent.ClientName != request.reporter.ClientName {
			return nil, ErrPeerAccessDenied
		}
	}
	ids := make([]int64, 0, len(selected))
	for _, row := range selected {
		ids = append(ids, row.ID)
	}
	current, err := db.peerCloseRowsByIDs(ctx, tx, ids, true)
	if err != nil {
		return nil, err
	}
	if (request.mode == peerCloseReported || (request.mode == peerCloseManaged && request.selection.SessionID > 0)) && len(current) != 1 {
		return nil, ErrNotFound
	}
	closed := make([]PeerMeshSession, 0, len(current))
	now := time.Now().UTC()
	for _, row := range current {
		if row.TenantID != request.tenant {
			return nil, ErrNotFound
		}
		if !covered[row.SourceClientID] || !covered[row.TargetClientID] {
			return nil, errOwnerRangeChanged
		}
		switch request.mode {
		case peerCloseManaged:
			if !request.actor.Admin && !peerCloseOwner(parents[row.SourceClientID], request.tenant, request.actor.Username) && !peerCloseOwner(parents[row.TargetClientID], request.tenant, request.actor.Username) {
				return nil, ErrNotFound
			}
		case peerCloseReported:
			if row.SourceClientID != request.reporter.ID && row.TargetClientID != request.reporter.ID {
				return nil, ErrPeerAccessDenied
			}
		case peerCloseExpired:
			if !strings.EqualFold(row.Status, "CLOSED") && (row.ExpiresAt.IsZero() || row.ExpiresAt.After(now)) {
				continue
			}
		case peerCloseUnauthorized:
			if !strings.EqualFold(row.Status, "CLOSED") {
				source := PeerClientReference{ID: row.SourceClientID, TenantID: request.tenant, ClientName: row.SourceClientName}
				target := PeerClientReference{ID: row.TargetClientID, TenantID: request.tenant, ClientName: row.TargetClientName}
				policy, err := db.peerAccessOn(ctx, tx, source, target)
				if err != nil {
					return nil, err
				}
				if policy.valid(source, target) && policy.allowed(nil) {
					continue
				}
			}
		}
		if !strings.EqualFold(row.Status, "CLOSED") {
			if request.path == nil {
				if err := db.closePeerSessionOn(ctx, tx, request.tenant, row.ID, now); err != nil {
					return nil, err
				}
			} else {
				pathType := row.PathType
				if request.path.PathType != "" {
					switch {
					case row.DirectBytes <= 0 && row.RelayBytes <= 0:
						pathType = request.path.PathType
					case row.RelayBytes > row.DirectBytes:
						pathType = "RELAY"
					case row.DirectBytes > row.RelayBytes:
						pathType = "DIRECT"
					case strings.TrimSpace(pathType) == "":
						pathType = "DIRECT"
					}
				}
				if _, err := tx.ExecContext(ctx, db.rebind(`UPDATE peer_mesh_session SET status='CLOSED',updated_at=?,closed_at=COALESCE(closed_at,?),path_type=?,rtt_millis=?,local_endpoint=?,remote_endpoint=? WHERE id=? AND tenant_id=? AND UPPER(status)<>'CLOSED'`), formatTime(now), formatTime(now), pathType, request.path.RTTMillis, request.path.LocalEndpoint, request.path.RemoteEndpoint, row.ID, request.tenant); err != nil {
					return nil, err
				}
			}
			// Read the committed candidate again: triggers/concurrent traffic preceding the
			// row lock may have advanced counters. The response must not be a stale hint.
			updated, err := db.peerCloseRowsByIDs(ctx, tx, []int64{row.ID}, false)
			if err != nil {
				return nil, err
			}
			if len(updated) != 1 {
				return nil, ErrNotFound
			}
			row = updated[0]
			if !strings.EqualFold(row.Status, "CLOSED") || row.ClosedAt == nil {
				return nil, errors.New("peer session close was not persisted")
			}
		}
		row.Status = "CLOSED"
		closed = append(closed, row)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return closed, nil
}

func peerCloseOwner(parent *ClientAccount, tenant, owner string) bool {
	return parent != nil && parent.TenantID == tenant && peerOwner(parent.OwnerUsername) == owner
}

type peerCloseOwnerScanner struct {
	base   scanner
	values *[4]string
}

func (s peerCloseOwnerScanner) Scan(dest ...any) error {
	for i := range s.values {
		dest = append(dest, &s.values[i])
	}
	return s.base.Scan(dest...)
}

// One statement captures session/parent ownership together, with Go's exact Unicode trim
// and case-sensitive identity semantics. No N+1 snapshots or native collation broadening.
func (db *DB) managedPeerCloseCandidates(ctx context.Context, tx *sql.Tx, tenant, owner string) ([]PeerMeshSession, error) {
	columns := "s." + strings.ReplaceAll(peerAdmissionSessionColumns, ",", ",s.")
	query := `SELECT ` + columns + `,CASE WHEN src.id IS NULL THEN '' ELSE COALESCE(src.tenant_id,'default') END,COALESCE(src.owner_username,''),CASE WHEN dst.id IS NULL THEN '' ELSE COALESCE(dst.tenant_id,'default') END,COALESCE(dst.owner_username,'') FROM peer_mesh_session s LEFT JOIN specus_client_account src ON src.id=s.source_client_id LEFT JOIN specus_client_account dst ON dst.id=s.target_client_id WHERE s.tenant_id=? AND UPPER(s.status)<>'CLOSED' ORDER BY s.id`
	rows, err := tx.QueryContext(ctx, db.rebind(query), tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []PeerMeshSession{}
	for rows.Next() {
		var values [4]string
		row, err := scanPeerMeshSession(peerCloseOwnerScanner{base: rows, values: &values})
		if err != nil {
			return nil, err
		}
		if row.TenantID == tenant && ((values[0] == tenant && peerOwner(values[1]) == owner) || (values[2] == tenant && peerOwner(values[3]) == owner)) {
			result = append(result, row)
		}
	}
	return result, rows.Err()
}

func (db *DB) peerCloseRowsByIDs(ctx context.Context, tx *sql.Tx, ids []int64, lock bool) ([]PeerMeshSession, error) {
	ids = sortedOwnerIDs(ids)
	result := []PeerMeshSession{}
	for start := 0; start < len(ids); start += 500 {
		end := start + 500
		if end > len(ids) {
			end = len(ids)
		}
		args := make([]any, 0, end-start)
		for _, id := range ids[start:end] {
			if id <= 0 {
				return nil, ErrNotFound
			}
			args = append(args, id)
		}
		query := `SELECT ` + peerAdmissionSessionColumns + ` FROM peer_mesh_session WHERE id IN (` + placeholders(len(args)) + `) ORDER BY id`
		if lock {
			query += db.ownershipLockSuffix()
		}
		rows, err := db.readPeerCloseRows(ctx, tx, query, args...)
		if err != nil {
			return nil, err
		}
		result = append(result, rows...)
	}
	return result, nil
}
func (db *DB) readPeerCloseRows(ctx context.Context, runner sqlRunner, query string, args ...any) ([]PeerMeshSession, error) {
	rows, err := runner.QueryContext(ctx, db.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []PeerMeshSession{}
	for rows.Next() {
		row, err := scanPeerMeshSession(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}
