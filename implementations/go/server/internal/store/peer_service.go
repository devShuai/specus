package store

import (
	"context"
	"database/sql"
	"errors"
)

func (db *DB) GetPeerMeshServiceSharing(ctx context.Context, tenantID string) (*PeerMeshServiceSharing, error) {
	query := db.rebind(`SELECT tenant_id, enabled, mdns_import_enabled, updated_by, updated_at FROM peer_mesh_service_sharing WHERE tenant_id = ?`)
	var (
		row       PeerMeshServiceSharing
		enabled   databaseBoolean
		mdns      databaseBoolean
		updatedBy sql.NullString
		updatedAt string
	)
	err := db.sql.QueryRowContext(ctx, query, defaultTenant(tenantID)).Scan(&row.TenantID, &enabled, &mdns, &updatedBy, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	row.Enabled = bool(enabled)
	row.MdnsImportEnabled = bool(mdns)
	if updatedBy.Valid {
		row.UpdatedBy = &updatedBy.String
	}
	row.UpdatedAt = parseTime(updatedAt)
	return &row, nil
}

func (db *DB) UpsertPeerMeshServiceSharing(ctx context.Context, row PeerMeshServiceSharing) error {
	query := db.rebind(`INSERT INTO peer_mesh_service_sharing (tenant_id, enabled, mdns_import_enabled, updated_by, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id) DO UPDATE SET enabled = excluded.enabled, mdns_import_enabled = excluded.mdns_import_enabled, updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
	if db.dialect == DialectMySQL {
		query = `INSERT INTO peer_mesh_service_sharing (tenant_id, enabled, mdns_import_enabled, updated_by, updated_at)
			VALUES (?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE enabled = VALUES(enabled), mdns_import_enabled = VALUES(mdns_import_enabled), updated_by = VALUES(updated_by), updated_at = VALUES(updated_at)`
	}
	_, err := db.sql.ExecContext(ctx, query, defaultTenant(row.TenantID), db.clientMessageCapabilityValue(row.Enabled),
		db.clientMessageCapabilityValue(row.MdnsImportEnabled), nullableSessionText(ptrText(row.UpdatedBy)), formatTime(row.UpdatedAt))
	return err
}

func (db *DB) ListPeerMeshSharedServices(ctx context.Context, tenantID string, clientIDs []int64) ([]PeerMeshSharedService, error) {
	query := `SELECT id, tenant_id, client_id, client_name, service_id, name, description, transport, application,
		target_host, target_port, published_port, path, enabled, visibility, allowed_client_ids, created_at, updated_at
		FROM peer_mesh_shared_service WHERE tenant_id = ?`
	args := []any{defaultTenant(tenantID)}
	if len(clientIDs) > 0 {
		query += ` AND client_id IN (` + placeholders(len(clientIDs)) + `)`
		for _, id := range clientIDs {
			args = append(args, id)
		}
	}
	query += ` ORDER BY client_name ASC, name ASC`
	rows, err := db.sql.QueryContext(ctx, db.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []PeerMeshSharedService
	for rows.Next() {
		item, err := scanPeerMeshSharedService(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) GetPeerMeshSharedService(ctx context.Context, tenantID string, id int64) (*PeerMeshSharedService, error) {
	query := db.rebind(`SELECT id, tenant_id, client_id, client_name, service_id, name, description, transport, application,
		target_host, target_port, published_port, path, enabled, visibility, allowed_client_ids, created_at, updated_at
		FROM peer_mesh_shared_service WHERE tenant_id = ? AND id = ?`)
	item, err := scanPeerMeshSharedService(db.sql.QueryRowContext(ctx, query, defaultTenant(tenantID), id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) FindPeerMeshSharedServiceByServiceID(ctx context.Context, tenantID string, clientID int64, serviceID string) (*PeerMeshSharedService, error) {
	query := db.rebind(`SELECT id, tenant_id, client_id, client_name, service_id, name, description, transport, application,
		target_host, target_port, published_port, path, enabled, visibility, allowed_client_ids, created_at, updated_at
		FROM peer_mesh_shared_service WHERE tenant_id = ? AND client_id = ? AND service_id = ?`)
	item, err := scanPeerMeshSharedService(db.sql.QueryRowContext(ctx, query, defaultTenant(tenantID), clientID, serviceID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) InsertPeerMeshSharedService(ctx context.Context, row PeerMeshSharedService) error {
	query := db.rebind(`INSERT INTO peer_mesh_shared_service
		(id, tenant_id, client_id, client_name, service_id, name, description, transport, application,
		 target_host, target_port, published_port, path, enabled, visibility, allowed_client_ids, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, row.ID, defaultTenant(row.TenantID), row.ClientID, row.ClientName,
		row.ServiceID, row.Name, row.Description, row.Transport, row.Application, row.TargetHost, row.TargetPort,
		row.PublishedPort, row.Path, db.clientMessageCapabilityValue(row.Enabled), row.Visibility, row.AllowedClientIDs,
		formatTime(row.CreatedAt), formatTime(row.UpdatedAt))
	return err
}

func (db *DB) UpdatePeerMeshSharedService(ctx context.Context, row PeerMeshSharedService) error {
	query := db.rebind(`UPDATE peer_mesh_shared_service SET name = ?, description = ?, transport = ?, application = ?,
		target_host = ?, target_port = ?, published_port = ?, path = ?, enabled = ?, visibility = ?, allowed_client_ids = ?, updated_at = ?
		WHERE tenant_id = ? AND id = ?`)
	_, err := db.sql.ExecContext(ctx, query, row.Name, row.Description, row.Transport, row.Application, row.TargetHost,
		row.TargetPort, row.PublishedPort, row.Path, db.clientMessageCapabilityValue(row.Enabled), row.Visibility,
		row.AllowedClientIDs, formatTime(row.UpdatedAt), defaultTenant(row.TenantID), row.ID)
	return err
}

func (db *DB) DeletePeerMeshSharedService(ctx context.Context, tenantID string, id int64) error {
	query := db.rebind(`DELETE FROM peer_mesh_shared_service WHERE tenant_id = ? AND id = ?`)
	_, err := db.sql.ExecContext(ctx, query, defaultTenant(tenantID), id)
	return err
}

func (db *DB) CountEnabledPeerMeshSharedServices(ctx context.Context, tenantID string) (int64, error) {
	query := db.rebind(`SELECT COUNT(*) FROM peer_mesh_shared_service WHERE tenant_id = ? AND ` + db.boolTrue("enabled"))
	var count int64
	err := db.sql.QueryRowContext(ctx, query, defaultTenant(tenantID)).Scan(&count)
	return count, err
}

func (db *DB) boolTrue(column string) string {
	if db.dialect == DialectPostgres {
		return column
	}
	return column + " <> 0"
}

func ptrText(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

type sharedServiceScanner interface {
	Scan(dest ...any) error
}

func scanPeerMeshSharedService(scanner sharedServiceScanner) (PeerMeshSharedService, error) {
	var (
		row                         PeerMeshSharedService
		description, path, allowed  sql.NullString
		enabled                     databaseBoolean
		createdAt, updatedAt        string
	)
	err := scanner.Scan(&row.ID, &row.TenantID, &row.ClientID, &row.ClientName, &row.ServiceID, &row.Name,
		&description, &row.Transport, &row.Application, &row.TargetHost, &row.TargetPort, &row.PublishedPort,
		&path, &enabled, &row.Visibility, &allowed, &createdAt, &updatedAt)
	if err != nil {
		return PeerMeshSharedService{}, err
	}
	if description.Valid {
		row.Description = description.String
	}
	if path.Valid {
		row.Path = path.String
	}
	if allowed.Valid {
		row.AllowedClientIDs = allowed.String
	}
	row.Enabled = bool(enabled)
	row.CreatedAt = parseTime(createdAt)
	row.UpdatedAt = parseTime(updatedAt)
	return row, nil
}
