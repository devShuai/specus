package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"
)

// The audit and ownership changes commit together. Receipts are per process incarnation,
// not delivery acknowledgements or a durable ID/time watermark: a lower ID can commit late.
type OwnerTransferEvent struct {
	ID                   int64
	TenantID, DetailJSON string
}

func validOwnerReceiptNode(node string) bool {
	if len(node) != 32 {
		return false
	}
	for _, c := range node {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (db *DB) PendingOwnerTransferEvents(ctx context.Context, node string, after int64) ([]OwnerTransferEvent, error) {
	if !validOwnerReceiptNode(node) || after < 0 {
		return nil, errors.New("invalid ownership journal cursor")
	}
	rows, err := db.sql.QueryContext(ctx, db.rebind(`SELECT a.id,a.tenant_id,a.detail_json FROM client_owner_transfer_audit a
	 WHERE a.id>? AND NOT EXISTS (SELECT 1 FROM client_owner_transfer_receipt r WHERE r.node_id=? AND r.event_id=a.id)
	 ORDER BY a.id LIMIT 32`), after, node)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OwnerTransferEvent{}
	for rows.Next() {
		var event OwnerTransferEvent
		if err := rows.Scan(&event.ID, &event.TenantID, &event.DetailJSON); err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

func (db *DB) FindPendingOwnerTransferEvent(ctx context.Context, node string, id int64) (*OwnerTransferEvent, error) {
	if !validOwnerReceiptNode(node) || id <= 0 {
		return nil, errors.New("invalid ownership journal identity")
	}
	var event OwnerTransferEvent
	err := db.sql.QueryRowContext(ctx, db.rebind(`SELECT a.id,a.tenant_id,a.detail_json FROM client_owner_transfer_audit a
	 WHERE a.id=? AND NOT EXISTS (SELECT 1 FROM client_owner_transfer_receipt r WHERE r.node_id=? AND r.event_id=a.id)`), id, node).Scan(&event.ID, &event.TenantID, &event.DetailJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &event, err
}

// Call only after successful current-state reconciliation, outside its network work. On an
// acknowledgement failure the event remains pending; retries and duplicate sends are expected.
func (db *DB) AcknowledgeOwnerTransferEvent(ctx context.Context, node string, event OwnerTransferEvent) error {
	if !validOwnerReceiptNode(node) || event.ID <= 0 || event.TenantID == "" {
		return errors.New("invalid ownership receipt")
	}
	tx, err := db.beginClientOwnershipWrite(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var tenant, detail string
	if err := tx.QueryRowContext(ctx, db.rebind(`SELECT tenant_id,detail_json FROM client_owner_transfer_audit WHERE id=?`)+db.ownershipLockSuffix(), event.ID).Scan(&tenant, &detail); err != nil {
		return err
	}
	if tenant != event.TenantID || detail != event.DetailJSON {
		return errors.New("ownership journal event changed")
	}
	id := node + ":" + strconv.FormatInt(event.ID, 10)
	query := `INSERT INTO client_owner_transfer_receipt(id,node_id,event_id,processed_at) VALUES (?,?,?,?) ON CONFLICT(id) DO NOTHING`
	if db.dialect == DialectMySQL {
		query = `INSERT INTO client_owner_transfer_receipt(id,node_id,event_id,processed_at) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE id=id`
	}
	if _, err := tx.ExecContext(ctx, db.rebind(query), id, node, event.ID, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	var actualNode string
	var actualEvent int64
	if err := tx.QueryRowContext(ctx, db.rebind(`SELECT node_id,event_id FROM client_owner_transfer_receipt WHERE id=?`), id).Scan(&actualNode, &actualEvent); err != nil {
		return err
	}
	if actualNode != node || actualEvent != event.ID {
		return errors.New("ownership receipt identity differs")
	}
	return tx.Commit()
}

// Includes already-CLOSED rows: another process may have closed SQL while this node still
// holds an old active relay cache, or a previous close notification may have failed.
func (db *DB) PeerSessionsAffectedByOwnership(ctx context.Context, tenant string, clientIDs []int64) ([]PeerMeshSession, error) {
	ids := sortedOwnerIDs(clientIDs)
	byID := map[int64]PeerMeshSession{}
	for start := 0; start < len(ids); start += 250 {
		end := min(start+250, len(ids))
		args := []any{tenant}
		for _, id := range ids[start:end] {
			if id <= 0 {
				return nil, ErrNotFound
			}
			args = append(args, id)
		}
		for _, id := range ids[start:end] {
			args = append(args, id)
		}
		in := placeholders(end - start)
		rows, err := db.sql.QueryContext(ctx, db.rebind(`SELECT `+peerAdmissionSessionColumns+` FROM peer_mesh_session WHERE tenant_id=? AND (source_client_id IN (`+in+`) OR target_client_id IN (`+in+`)) ORDER BY id`), args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			row, err := scanPeerMeshSession(rows)
			if err != nil {
				rows.Close()
				return nil, err
			}
			if row.TenantID == tenant {
				byID[row.ID] = row
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	keys := []int64{}
	for id := range byID {
		keys = append(keys, id)
	}
	out := []PeerMeshSession{}
	for _, id := range sortedOwnerIDs(keys) {
		out = append(out, byID[id])
	}
	return out, nil
}
