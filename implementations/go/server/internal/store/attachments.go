package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

func (db *DB) InsertTransferAttachment(ctx context.Context, item TransferAttachment) error {
	query := db.rebind(`INSERT INTO transfer_attachment
		(id, tenant_id, scope, room_id, room_token_hash, owner_username, target_client_id,
		 object_key, file_name, mime_type, size_bytes, sha256, status, created_at, updated_at,
		 upload_expires_at, expires_at, uploaded_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, item.ID, item.TenantID, item.Scope, item.RoomID,
		item.RoomTokenHash, item.OwnerUsername, item.TargetClientID, item.ObjectKey, item.FileName,
		item.MimeType, item.SizeBytes, item.SHA256, item.Status, formatTime(item.CreatedAt),
		formatTime(item.UpdatedAt), formatTime(item.UploadExpiresAt), formatTime(item.ExpiresAt),
		nullableTime(item.UploadedAt))
	return err
}

func (db *DB) UpdateTransferAttachment(ctx context.Context, item TransferAttachment) error {
	query := db.rebind(`UPDATE transfer_attachment SET size_bytes = ?, status = ?, updated_at = ?, uploaded_at = ? WHERE id = ?`)
	result, err := db.sql.ExecContext(ctx, query, item.SizeBytes, item.Status, formatTime(item.UpdatedAt),
		nullableTime(item.UploadedAt), item.ID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (db *DB) GetTransferAttachment(ctx context.Context, id int64, scope string) (*TransferAttachment, error) {
	query := db.rebind(transferAttachmentSelect + ` WHERE id = ? AND scope = ?`)
	return scanTransferAttachmentOrNil(db.sql.QueryRowContext(ctx, query, id, scope))
}

func (db *DB) GetTenantTransferAttachment(ctx context.Context, id int64, tenantID, scope string) (*TransferAttachment, error) {
	query := db.rebind(transferAttachmentSelect + ` WHERE id = ? AND tenant_id = ? AND scope = ?`)
	return scanTransferAttachmentOrNil(db.sql.QueryRowContext(ctx, query, id, defaultTenant(tenantID), scope))
}

func (db *DB) CountPendingTransferAttachments(ctx context.Context, scope, roomTokenHash, status string) (int64, error) {
	query := db.rebind(`SELECT COUNT(*) FROM transfer_attachment WHERE scope = ? AND room_token_hash = ? AND status = ?`)
	var count int64
	err := db.sql.QueryRowContext(ctx, query, scope, roomTokenHash, status).Scan(&count)
	return count, err
}

func (db *DB) SumActiveTransferStorageBytes(ctx context.Context, tenantID, ownerUsername string,
	excludedAttachmentID int64, now time.Time) (int64, error) {
	query := db.rebind(`SELECT COALESCE(SUM(size_bytes), 0) FROM transfer_attachment
		WHERE tenant_id = ? AND owner_username = ? AND id <> ?
		AND ((status = ? AND upload_expires_at > ?) OR (status = ? AND expires_at > ?))`)
	var total int64
	nowValue := formatTime(now)
	err := db.sql.QueryRowContext(ctx, query, defaultTenant(tenantID), strings.TrimSpace(ownerUsername),
		excludedAttachmentID, "PENDING", nowValue, "UPLOADED", nowValue).Scan(&total)
	return total, err
}

func (db *DB) SumTransferDownloadUsageBytes(ctx context.Context, tenantID, username,
	usageMonth string) (int64, error) {
	query := db.rebind(`SELECT COALESCE(SUM(size_bytes), 0) FROM transfer_attachment_download_usage
		WHERE tenant_id = ? AND username = ? AND usage_month = ?`)
	var total int64
	err := db.sql.QueryRowContext(ctx, query, defaultTenant(tenantID), strings.TrimSpace(username),
		usageMonth).Scan(&total)
	return total, err
}

func (db *DB) InsertTransferDownloadUsage(ctx context.Context, id int64, tenantID, username string,
	attachmentID, sizeBytes int64, usageMonth string, createdAt time.Time) error {
	query := db.rebind(`INSERT INTO transfer_attachment_download_usage
		(id, tenant_id, username, attachment_id, size_bytes, usage_month, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, id, defaultTenant(tenantID), strings.TrimSpace(username),
		attachmentID, sizeBytes, usageMonth, formatTime(createdAt))
	return err
}

func (db *DB) ListExpiredTransferAttachments(ctx context.Context, before time.Time, expiredStatus string, limit int) ([]TransferAttachment, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := db.rebind(transferAttachmentSelect + ` WHERE expires_at < ? AND status <> ? ORDER BY expires_at ASC LIMIT ?`)
	rows, err := db.sql.QueryContext(ctx, query, formatTime(before), expiredStatus, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]TransferAttachment, 0)
	for rows.Next() {
		item, err := scanTransferAttachment(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

const transferAttachmentSelect = `SELECT id, tenant_id, scope, room_id, room_token_hash,
	owner_username, target_client_id, object_key, file_name, mime_type, size_bytes, sha256,
	status, created_at, updated_at, upload_expires_at, expires_at, uploaded_at
	FROM transfer_attachment`

type transferAttachmentScanner interface{ Scan(...any) error }

func scanTransferAttachmentOrNil(scanner transferAttachmentScanner) (*TransferAttachment, error) {
	item, err := scanTransferAttachment(scanner)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func scanTransferAttachment(scanner transferAttachmentScanner) (TransferAttachment, error) {
	var item TransferAttachment
	var tenantID, roomID, roomTokenHash, ownerUsername, sha256Value, uploadedAt sql.NullString
	var targetClientID sql.NullInt64
	var createdAt, updatedAt, uploadExpiresAt, expiresAt string
	err := scanner.Scan(&item.ID, &tenantID, &item.Scope, &roomID, &roomTokenHash, &ownerUsername,
		&targetClientID, &item.ObjectKey, &item.FileName, &item.MimeType, &item.SizeBytes,
		&sha256Value, &item.Status, &createdAt, &updatedAt, &uploadExpiresAt, &expiresAt, &uploadedAt)
	if err != nil {
		return TransferAttachment{}, err
	}
	item.TenantID = nullStringPtr(tenantID)
	item.RoomID = nullStringPtr(roomID)
	item.RoomTokenHash = nullStringPtr(roomTokenHash)
	item.OwnerUsername = nullStringPtr(ownerUsername)
	item.SHA256 = nullStringPtr(sha256Value)
	if targetClientID.Valid {
		value := targetClientID.Int64
		item.TargetClientID = &value
	}
	item.CreatedAt = parseTime(createdAt)
	item.UpdatedAt = parseTime(updatedAt)
	item.UploadExpiresAt = parseTime(uploadExpiresAt)
	item.ExpiresAt = parseTime(expiresAt)
	item.UploadedAt = nullTimePtr(uploadedAt)
	return item, nil
}
