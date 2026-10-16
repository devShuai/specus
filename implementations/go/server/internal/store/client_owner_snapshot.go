package store

import (
	"context"
	"database/sql"
	"fmt"
)

// These deliberately minimal rows never load credentials, tokens or device fingerprints.
type OwnerTransferClient struct {
	ID            int64   `json:"id"`
	TenantID      string  `json:"tenantId"`
	ClientName    *string `json:"clientName"`
	OwnerUsername *string `json:"ownerUsername"`
	Enabled       bool    `json:"enabled"`
}

type OwnerTransferCredential struct {
	ID            int64   `json:"id"`
	TenantID      string  `json:"tenantId"`
	OwnerUsername *string `json:"ownerUsername"`
	Enabled       bool    `json:"enabled"`
}

type OwnerTransferIdentity struct {
	ID           int64  `json:"id"`
	TenantID     string `json:"tenantId"`
	CredentialID int64  `json:"credentialId"`
	ClientID     int64  `json:"clientId"`
}

type OwnerTransferPeer struct {
	ID            int64   `json:"id"`
	TenantID      string  `json:"tenantId"`
	ClientID      int64   `json:"clientId"`
	ClientName    *string `json:"clientName"`
	OwnerUsername *string `json:"ownerUsername"`
	Enabled       bool    `json:"enabled"`
}

// Include every forward/reverse identity edge, even a corrupt foreign edge. Filtering those
// before validation could turn an incomplete group into a successful preview.
type OwnerTransferSnapshot struct {
	Clients     []OwnerTransferClient     `json:"clients"`
	Credentials []OwnerTransferCredential `json:"credentials"`
	Identities  []OwnerTransferIdentity   `json:"identities"`
	Peers       []OwnerTransferPeer       `json:"peers"`
}

// LoadOwnerTransferSnapshot is read-only. One statement gives one database snapshot even on
// PostgreSQL READ COMMITTED. There is no page/IN-parameter limit or per-client follow-up query.
// This is NOT a write coordination boundary; a future writer must reload under database locks.
func (db *DB) LoadOwnerTransferSnapshot(ctx context.Context, tenant, scope string, id int64) (OwnerTransferSnapshot, error) {
	return db.loadOwnerTransferSnapshotOn(ctx, db.sql, tenant, scope, id)
}

func (db *DB) loadOwnerTransferSnapshotOn(ctx context.Context, runner sqlRunner, tenant, scope string, id int64) (OwnerTransferSnapshot, error) {
	var result OwnerTransferSnapshot
	rows, err := runner.QueryContext(ctx, db.rebind(ownerTransferSnapshotSQL), id, tenant, scope, id, tenant, scope, tenant)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, tenantID string
		var rowID int64
		var name, owner sql.NullString
		var rawEnabled any
		var enabled databaseBoolean
		var credentialID, clientID sql.NullInt64
		if err := rows.Scan(&kind, &rowID, &tenantID, &name, &owner, &rawEnabled, &credentialID, &clientID); err != nil {
			return OwnerTransferSnapshot{}, err
		}
		if rawEnabled != nil {
			if err := enabled.Scan(rawEnabled); err != nil {
				return OwnerTransferSnapshot{}, err
			}
		}
		var nameValue, ownerValue *string
		if name.Valid {
			nameValue = &name.String
		}
		if owner.Valid {
			ownerValue = &owner.String
		}
		switch kind {
		case "client":
			result.Clients = append(result.Clients, OwnerTransferClient{rowID, tenantID, nameValue, ownerValue, bool(enabled)})
		case "credential":
			result.Credentials = append(result.Credentials, OwnerTransferCredential{rowID, tenantID, ownerValue, bool(enabled)})
		case "identity":
			result.Identities = append(result.Identities, OwnerTransferIdentity{rowID, tenantID, credentialID.Int64, clientID.Int64})
		case "peer":
			result.Peers = append(result.Peers, OwnerTransferPeer{rowID, tenantID, clientID.Int64, nameValue, ownerValue, bool(enabled)})
		default:
			return OwnerTransferSnapshot{}, fmt.Errorf("unknown ownership snapshot row type")
		}
	}
	return result, rows.Err()
}

const ownerTransferSnapshotSQL = `
WITH path_client AS (
    SELECT id FROM specus_client_account WHERE id = ? AND tenant_id = ? AND ? = 'single'
), selected_credentials AS (
    SELECT id FROM specus_client_credential WHERE id = ? AND tenant_id = ? AND ? = 'credential-group'
    UNION
    SELECT i.credential_id FROM specus_client_identity i WHERE i.client_id IN (SELECT id FROM path_client)
), affected_clients AS (
    SELECT id FROM path_client
    UNION
    SELECT i.client_id FROM specus_client_identity i WHERE i.credential_id IN (SELECT id FROM selected_credentials)
)
SELECT 'client' AS kind, c.id AS row_id, c.tenant_id, c.client_name, c.owner_username, c.enabled,
       CAST(NULL AS DECIMAL(19,0)) AS credential_id, CAST(NULL AS DECIMAL(19,0)) AS client_id
FROM specus_client_account c WHERE c.id IN (SELECT id FROM affected_clients)
UNION ALL
SELECT 'credential', c.id, c.tenant_id, NULL, c.owner_username, c.enabled, NULL, NULL
FROM specus_client_credential c WHERE c.id IN (SELECT id FROM selected_credentials)
UNION ALL
SELECT 'identity', i.id, i.tenant_id, NULL, NULL, NULL, i.credential_id, i.client_id
FROM specus_client_identity i WHERE i.credential_id IN (SELECT id FROM selected_credentials)
   OR i.client_id IN (SELECT id FROM affected_clients)
UNION ALL
SELECT 'peer', p.id, p.tenant_id, p.client_name, p.owner_username, p.enabled, NULL, p.client_id
FROM peer_mesh_device p WHERE p.tenant_id = ? AND p.client_id IN (SELECT id FROM affected_clients)
`
