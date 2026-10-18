package store

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"
)

// deleteClientPeerReferences runs inside the account deletion transaction. Session and usage
// history survive, but operational permissions and advertisements cannot outlive their client.
// Returned sessions are for runtime eviction only after the caller commits successfully.
func (db *DB) deleteClientPeerReferences(ctx context.Context, tx *sql.Tx, id int64, now time.Time) ([]PeerMeshSession, error) {
	account, err := db.getClientByID(ctx, tx, id)
	if err != nil || account == nil {
		return nil, err
	}
	tenant := account.TenantID
	rows, err := tx.QueryContext(ctx, db.rebind(`SELECT id, tenant_id, source_client_id, source_client_name,
		target_client_id, target_client_name, path_type, status, token_hash, started_at, updated_at, expires_at,
		closed_at, rtt_millis, local_endpoint, remote_endpoint, direct_bytes, relay_bytes, last_traffic_at
		FROM peer_mesh_session WHERE tenant_id = ? AND status <> 'CLOSED'
		AND (source_client_id = ? OR target_client_id = ?)`), tenant, id, id)
	if err != nil {
		return nil, err
	}
	var closed []PeerMeshSession
	for rows.Next() {
		item, err := scanPeerMeshSession(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		item.Status = "CLOSED"
		item.UpdatedAt = now
		if item.ClosedAt == nil {
			item.ClosedAt = &now
		}
		closed = append(closed, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, db.rebind(`UPDATE peer_mesh_session
		SET status = 'CLOSED', updated_at = ?, closed_at = COALESCE(closed_at, ?)
		WHERE tenant_id = ? AND status <> 'CLOSED' AND (source_client_id = ? OR target_client_id = ?)`),
		formatTime(now), formatTime(now), tenant, id, id); err != nil {
		return nil, err
	}
	for _, source := range []struct{ table, predicate string }{
		{"peer_mesh_acl", "(source_client_id = ? OR target_client_id = ?)"},
		{"peer_mesh_device", "client_id = ?"},
		{"peer_mesh_egress_policy", "egress_client_id = ?"},
		{"peer_mesh_shared_service", "client_id = ?"},
	} {
		args := []any{tenant, id}
		if source.table == "peer_mesh_acl" {
			args = append(args, id)
		}
		if _, err := tx.ExecContext(ctx, db.rebind(`DELETE FROM `+source.table+` WHERE tenant_id = ? AND `+source.predicate), args...); err != nil {
			return nil, err
		}
	}
	for _, source := range []struct{ table, column string }{
		{"peer_mesh_egress_policy", "allowed_consumer_client_ids"},
		{"peer_mesh_shared_service", "allowed_client_ids"},
	} {
		query := `SELECT id, ` + source.column
		if source.table == "peer_mesh_shared_service" {
			query += `, visibility`
		}
		rows, err := tx.QueryContext(ctx, db.rebind(query+` FROM `+source.table+` WHERE tenant_id = ?`), tenant)
		if err != nil {
			return nil, err
		}
		type changedList struct {
			id      int64
			value   string
			disable bool
		}
		var updates []changedList
		for rows.Next() {
			var rowID int64
			var raw sql.NullString
			var visibility string
			args := []any{&rowID, &raw}
			if source.table == "peer_mesh_shared_service" {
				args = append(args, &visibility)
			}
			if err := rows.Scan(args...); err != nil {
				rows.Close()
				return nil, err
			}
			value, changed := removePeerClientID(raw.String, id)
			if changed {
				updates = append(updates, changedList{rowID, value,
					source.table == "peer_mesh_shared_service" && visibility != "OWNER" && value == ""})
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		for _, update := range updates {
			query := `UPDATE ` + source.table + ` SET ` + source.column + ` = ?, updated_at = ?`
			args := []any{update.value, formatTime(now)}
			if update.disable {
				// Shared-service empty lists allow all eligible peers; never widen a grant
				// when its last explicit recipient is deleted. Egress empty lists deny all.
				query += `, enabled = ?`
				args = append(args, db.clientMessageCapabilityValue(false))
			}
			args = append(args, tenant, update.id)
			if _, err := tx.ExecContext(ctx, db.rebind(query+` WHERE tenant_id = ? AND id = ?`), args...); err != nil {
				return nil, err
			}
		}
	}
	return closed, nil
}

func removePeerClientID(raw string, id int64) (string, bool) {
	var remaining []string
	changed := false
	for _, part := range strings.Split(raw, ",") {
		value, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
		if err == nil && value == id {
			changed = true
			continue
		}
		// Match the existing permission decoder: only positive IDs confer access.
		if err == nil && value > 0 {
			remaining = append(remaining, strconv.FormatInt(value, 10))
		}
	}
	return strings.Join(remaining, ","), changed
}
