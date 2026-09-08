package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// PeerMeshEgressPolicy mirrors peer_mesh_egress_policy.
//
// Stored apart from PeerMeshACL on purpose: mesh ACLs decide whether two devices may reach each
// other, this decides whether one may be used as a way out to the wider network. Effective
// permission is the intersection of the two.
type PeerMeshEgressPolicy struct {
	ID                       int64
	TenantID                 string
	OwnerUsername            string
	EgressClientID           int64
	EgressClientName         string
	Enabled                  bool
	Scope                    string
	AllowedConsumerClientIDs string
	// DestinationRules is a canonical JSON array. Empty denies everything; there is no
	// unconfigured-therefore-open state.
	DestinationRules    string
	MaxConcurrentFlows  int
	MaxFlowsPerConsumer int
	IdleTimeoutSeconds  int
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

const peerEgressPolicyColumns = `id, tenant_id, owner_username, egress_client_id, egress_client_name, enabled,
	scope, allowed_consumer_client_ids, destination_rules, max_concurrent_flows, max_flows_per_consumer,
	idle_timeout_seconds, created_at, updated_at`

type egressPolicyScanner interface {
	Scan(dest ...any) error
}

func scanPeerMeshEgressPolicy(scanner egressPolicyScanner) (PeerMeshEgressPolicy, error) {
	var (
		row                  PeerMeshEgressPolicy
		consumers, rules     sql.NullString
		enabled              databaseBoolean
		createdAt, updatedAt string
	)
	err := scanner.Scan(&row.ID, &row.TenantID, &row.OwnerUsername, &row.EgressClientID, &row.EgressClientName,
		&enabled, &row.Scope, &consumers, &rules, &row.MaxConcurrentFlows, &row.MaxFlowsPerConsumer,
		&row.IdleTimeoutSeconds, &createdAt, &updatedAt)
	if err != nil {
		return PeerMeshEgressPolicy{}, err
	}
	if consumers.Valid {
		row.AllowedConsumerClientIDs = consumers.String
	}
	if rules.Valid {
		row.DestinationRules = rules.String
	}
	row.Enabled = bool(enabled)
	row.CreatedAt = parseTime(createdAt)
	row.UpdatedAt = parseTime(updatedAt)
	return row, nil
}

// ListPeerMeshEgressPolicies returns every policy in the tenant. When enabledOnly is set only
// policies currently switched on are returned, which is what catalogue building needs.
func (db *DB) ListPeerMeshEgressPolicies(ctx context.Context, tenantID string, enabledOnly bool) ([]PeerMeshEgressPolicy, error) {
	query := `SELECT ` + peerEgressPolicyColumns + ` FROM peer_mesh_egress_policy WHERE tenant_id = ?`
	if enabledOnly {
		query += ` AND enabled = ?`
	}
	query += ` ORDER BY egress_client_name ASC`
	args := []any{defaultTenant(tenantID)}
	if enabledOnly {
		args = append(args, db.clientMessageCapabilityValue(true))
	}
	rows, err := db.sql.QueryContext(ctx, db.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []PeerMeshEgressPolicy
	for rows.Next() {
		item, err := scanPeerMeshEgressPolicy(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// GetPeerMeshEgressPolicy returns the policy with this row id, or nil when absent.
func (db *DB) GetPeerMeshEgressPolicy(ctx context.Context, tenantID string, id int64) (*PeerMeshEgressPolicy, error) {
	query := db.rebind(`SELECT ` + peerEgressPolicyColumns +
		` FROM peer_mesh_egress_policy WHERE tenant_id = ? AND id = ?`)
	item, err := scanPeerMeshEgressPolicy(db.sql.QueryRowContext(ctx, query, defaultTenant(tenantID), id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

// FindPeerMeshEgressPolicyByClient returns the policy owned by an egress device, or nil when the
// device has never been configured as one.
func (db *DB) FindPeerMeshEgressPolicyByClient(ctx context.Context, tenantID string, egressClientID int64) (*PeerMeshEgressPolicy, error) {
	query := db.rebind(`SELECT ` + peerEgressPolicyColumns +
		` FROM peer_mesh_egress_policy WHERE tenant_id = ? AND egress_client_id = ?`)
	item, err := scanPeerMeshEgressPolicy(db.sql.QueryRowContext(ctx, query, defaultTenant(tenantID), egressClientID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

// InsertPeerMeshEgressPolicy stores a new policy.
func (db *DB) InsertPeerMeshEgressPolicy(ctx context.Context, row PeerMeshEgressPolicy) error {
	query := db.rebind(`INSERT INTO peer_mesh_egress_policy
		(id, tenant_id, owner_username, egress_client_id, egress_client_name, enabled, scope,
		 allowed_consumer_client_ids, destination_rules, max_concurrent_flows, max_flows_per_consumer,
		 idle_timeout_seconds, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, row.ID, defaultTenant(row.TenantID), row.OwnerUsername,
		row.EgressClientID, row.EgressClientName, db.clientMessageCapabilityValue(row.Enabled), row.Scope,
		row.AllowedConsumerClientIDs, row.DestinationRules, row.MaxConcurrentFlows, row.MaxFlowsPerConsumer,
		row.IdleTimeoutSeconds, formatTime(row.CreatedAt), formatTime(row.UpdatedAt))
	return err
}

// UpdatePeerMeshEgressPolicy replaces the mutable fields of an existing policy.
func (db *DB) UpdatePeerMeshEgressPolicy(ctx context.Context, row PeerMeshEgressPolicy) error {
	query := db.rebind(`UPDATE peer_mesh_egress_policy SET owner_username = ?, egress_client_name = ?, enabled = ?,
		scope = ?, allowed_consumer_client_ids = ?, destination_rules = ?, max_concurrent_flows = ?,
		max_flows_per_consumer = ?, idle_timeout_seconds = ?, updated_at = ?
		WHERE tenant_id = ? AND id = ?`)
	_, err := db.sql.ExecContext(ctx, query, row.OwnerUsername, row.EgressClientName,
		db.clientMessageCapabilityValue(row.Enabled), row.Scope, row.AllowedConsumerClientIDs, row.DestinationRules,
		row.MaxConcurrentFlows, row.MaxFlowsPerConsumer, row.IdleTimeoutSeconds, formatTime(row.UpdatedAt),
		defaultTenant(row.TenantID), row.ID)
	return err
}

// DeletePeerMeshEgressPolicy removes a policy. New flows stop being authorised immediately; callers
// are responsible for tearing down flows already established under it.
func (db *DB) DeletePeerMeshEgressPolicy(ctx context.Context, tenantID string, id int64) error {
	query := db.rebind(`DELETE FROM peer_mesh_egress_policy WHERE tenant_id = ? AND id = ?`)
	_, err := db.sql.ExecContext(ctx, query, defaultTenant(tenantID), id)
	return err
}
