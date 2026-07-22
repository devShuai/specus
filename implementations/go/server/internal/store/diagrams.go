package store

import (
	"context"
	"database/sql"
	"errors"
)

// ---- user_diagram_document --------------------------------------------------------------

func (db *DB) InsertUserDiagramDocument(ctx context.Context, document UserDiagramDocument) error {
	query := db.rebind(`INSERT INTO user_diagram_document
		(id, tenant_id, owner_username, name, snapshot_data, size_bytes, revision, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, document.ID, document.TenantID, document.OwnerUsername,
		document.Name, document.SnapshotData, document.SizeBytes, document.Revision,
		formatTime(document.CreatedAt), formatTime(document.UpdatedAt))
	return err
}

// ListUserDiagramDocumentSummaries returns document metadata (no snapshot blob) for one owner,
// newest update first.
func (db *DB) ListUserDiagramDocumentSummaries(ctx context.Context,
	tenantID, ownerUsername string) ([]UserDiagramDocument, error) {
	query := db.rebind(`SELECT id, tenant_id, owner_username, name, size_bytes, revision, created_at, updated_at
		FROM user_diagram_document WHERE tenant_id = ? AND owner_username = ? ORDER BY updated_at DESC`)
	rows, err := db.sql.QueryContext(ctx, query, tenantID, ownerUsername)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]UserDiagramDocument, 0)
	for rows.Next() {
		var item UserDiagramDocument
		var createdAt, updatedAt string
		if err := rows.Scan(&item.ID, &item.TenantID, &item.OwnerUsername, &item.Name,
			&item.SizeBytes, &item.Revision, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		item.CreatedAt = parseTime(createdAt)
		item.UpdatedAt = parseTime(updatedAt)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) GetUserDiagramDocument(ctx context.Context,
	id int64, tenantID, ownerUsername string) (*UserDiagramDocument, error) {
	query := db.rebind(`SELECT id, tenant_id, owner_username, name, snapshot_data, size_bytes,
		revision, created_at, updated_at
		FROM user_diagram_document WHERE id = ? AND tenant_id = ? AND owner_username = ?`)
	var item UserDiagramDocument
	var createdAt, updatedAt string
	err := db.sql.QueryRowContext(ctx, query, id, tenantID, ownerUsername).Scan(&item.ID, &item.TenantID,
		&item.OwnerUsername, &item.Name, &item.SnapshotData, &item.SizeBytes, &item.Revision,
		&createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	item.CreatedAt = parseTime(createdAt)
	item.UpdatedAt = parseTime(updatedAt)
	return &item, nil
}

func (db *DB) CountUserDiagramDocuments(ctx context.Context, tenantID, ownerUsername string) (int64, error) {
	query := db.rebind(`SELECT COUNT(*) FROM user_diagram_document WHERE tenant_id = ? AND owner_username = ?`)
	var count int64
	err := db.sql.QueryRowContext(ctx, query, tenantID, ownerUsername).Scan(&count)
	return count, err
}

// UpdateUserDiagramDocument applies the mutation only while the stored revision still equals
// expectedRevision (optimistic locking, aligned with the Java @Version column).
func (db *DB) UpdateUserDiagramDocument(ctx context.Context, document UserDiagramDocument,
	expectedRevision int64) (bool, error) {
	query := db.rebind(`UPDATE user_diagram_document
		SET name = ?, snapshot_data = ?, size_bytes = ?, revision = revision + 1, updated_at = ?
		WHERE id = ? AND tenant_id = ? AND owner_username = ? AND revision = ?`)
	result, err := db.sql.ExecContext(ctx, query, document.Name, document.SnapshotData,
		document.SizeBytes, formatTime(document.UpdatedAt), document.ID, document.TenantID,
		document.OwnerUsername, expectedRevision)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}

func (db *DB) DeleteUserDiagramDocument(ctx context.Context, id int64, tenantID, ownerUsername string) error {
	_, err := db.sql.ExecContext(ctx, db.rebind(`DELETE FROM user_diagram_document
		WHERE id = ? AND tenant_id = ? AND owner_username = ?`), id, tenantID, ownerUsername)
	return err
}

func (db *DB) UserDiagramDocumentExists(ctx context.Context, id int64) (bool, error) {
	return db.rowExists(ctx, `SELECT COUNT(*) FROM user_diagram_document WHERE id = ?`, id)
}
