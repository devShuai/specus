package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	moderncsqlite "modernc.org/sqlite"
)

func (db *DB) InsertTransferAttachment(ctx context.Context, item TransferAttachment) error {
	return db.insertTransferAttachment(ctx, db.sql, item)
}

type transferAttachmentExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func (db *DB) insertTransferAttachment(ctx context.Context, exec transferAttachmentExecer,
	item TransferAttachment) error {
	query := db.rebind(`INSERT INTO transfer_attachment
		(id, tenant_id, scope, room_id, room_token_hash, public_transfer_room_id, owner_username,
		 target_client_id, object_key, file_name, mime_type, size_bytes, sha256, status, created_at,
		 updated_at, upload_expires_at, expires_at, uploaded_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := exec.ExecContext(ctx, query, item.ID, item.TenantID, item.Scope, item.RoomID,
		item.RoomTokenHash, item.PublicTransferRoomID, item.OwnerUsername, item.TargetClientID,
		item.ObjectKey, item.FileName,
		item.MimeType, item.SizeBytes, item.SHA256, item.Status, formatTime(item.CreatedAt),
		formatTime(item.UpdatedAt), formatTime(item.UploadExpiresAt), formatTime(item.ExpiresAt),
		nullableTime(item.UploadedAt))
	return err
}

// InsertTransferAttachmentWithinRoomPendingLimit serializes the room-level pending quota in the
// database. SQLite uses a no-op UPDATE to take its write lock; MySQL/PostgreSQL lock the persistent
// room row with SELECT ... FOR UPDATE. Another server instance therefore cannot count the same
// pre-insert state and exceed the configured limit. A false result is a quota rejection; no
// attachment row was inserted.
func (db *DB) InsertTransferAttachmentWithinRoomPendingLimit(ctx context.Context,
	item TransferAttachment, maxPending int, pendingStatus string) (bool, error) {
	if item.PublicTransferRoomID == nil {
		return false, errors.New("persistent public transfer room id is required")
	}
	if maxPending < 1 {
		maxPending = 1
	}

	const maxSQLiteAttempts = 6
	attempts := 1
	if db.dialect == DialectSQLite {
		attempts = maxSQLiteAttempts
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		inserted, err := db.insertTransferAttachmentWithinRoomPendingLimitOnce(ctx, item,
			maxPending, pendingStatus)
		if err == nil || db.dialect != DialectSQLite || !isSQLiteBusy(err) {
			return inserted, err
		}
		lastErr = err
		if attempt+1 == attempts {
			break
		}
		delay := time.Duration(5*(1<<attempt)) * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return false, ctx.Err()
		case <-timer.C:
		}
	}
	return false, lastErr
}

func (db *DB) insertTransferAttachmentWithinRoomPendingLimitOnce(ctx context.Context,
	item TransferAttachment, maxPending int, pendingStatus string) (inserted bool, err error) {
	var options *sql.TxOptions
	if db.dialect != DialectSQLite {
		// A fresh snapshot after the room-row lock is acquired must observe the previous
		// transaction's insert. This is also the common default used by PostgreSQL deployments.
		options = &sql.TxOptions{Isolation: sql.LevelReadCommitted}
	}
	tx, err := db.sql.BeginTx(ctx, options)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	if db.dialect == DialectSQLite {
		// SQLite does not support SELECT ... FOR UPDATE. A write, even one that leaves the value
		// unchanged, obtains its single-writer lock before the count is evaluated.
		lockQuery := db.rebind(`UPDATE public_transfer_room SET updated_at = updated_at WHERE id = ?`)
		if _, err := tx.ExecContext(ctx, lockQuery, *item.PublicTransferRoomID); err != nil {
			return false, err
		}
	}
	roomQuery := `SELECT id FROM public_transfer_room WHERE id = ?`
	if db.dialect != DialectSQLite {
		roomQuery += ` FOR UPDATE`
	}
	var lockedRoomID int64
	if err := tx.QueryRowContext(ctx, db.rebind(roomQuery), *item.PublicTransferRoomID).
		Scan(&lockedRoomID); errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	} else if err != nil {
		return false, err
	}

	countQuery := db.rebind(`SELECT COUNT(*) FROM transfer_attachment
		WHERE scope = ? AND public_transfer_room_id = ? AND status = ?`)
	var count int64
	if err := tx.QueryRowContext(ctx, countQuery, item.Scope, *item.PublicTransferRoomID,
		pendingStatus).Scan(&count); err != nil {
		return false, err
	}
	if count >= int64(maxPending) {
		return false, nil
	}
	if err := db.insertTransferAttachment(ctx, tx, item); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func isSQLiteBusy(err error) bool {
	var sqliteErr *moderncsqlite.Error
	return errors.As(err, &sqliteErr) && sqliteErr.Code()&0xff == 5
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

func (db *DB) GetTransferAttachmentByID(ctx context.Context, id int64) (*TransferAttachment, error) {
	query := db.rebind(transferAttachmentSelect + ` WHERE id = ?`)
	return scanTransferAttachmentOrNil(db.sql.QueryRowContext(ctx, query, id))
}

func (db *DB) GetTransferAttachmentByObjectKey(ctx context.Context,
	objectKey string) (*TransferAttachment, error) {
	query := db.rebind(transferAttachmentSelect + ` WHERE object_key = ?`)
	return scanTransferAttachmentOrNil(db.sql.QueryRowContext(ctx, query, strings.TrimSpace(objectKey)))
}

func (db *DB) GetTenantTransferAttachment(ctx context.Context, id int64, tenantID, scope string) (*TransferAttachment, error) {
	query := db.rebind(transferAttachmentSelect + ` WHERE id = ? AND tenant_id = ? AND scope = ?`)
	return scanTransferAttachmentOrNil(db.sql.QueryRowContext(ctx, query, id, defaultTenant(tenantID), scope))
}

// CountPendingTransferAttachmentsByRoom counts a persistent room's pending uploads, so the quota
// follows room membership instead of a single room token.
func (db *DB) CountPendingTransferAttachmentsByRoom(ctx context.Context, scope string,
	publicTransferRoomID int64, status string) (int64, error) {
	query := db.rebind(`SELECT COUNT(*) FROM transfer_attachment
		WHERE scope = ? AND public_transfer_room_id = ? AND status = ?`)
	var count int64
	err := db.sql.QueryRowContext(ctx, query, scope, publicTransferRoomID, status).Scan(&count)
	return count, err
}

// CountPendingTransferAttachments keeps the token-hash based count for rows created before the
// persistent room binding existed.
func (db *DB) CountPendingTransferAttachments(ctx context.Context, scope, roomTokenHash, status string) (int64, error) {
	query := db.rebind(`SELECT COUNT(*) FROM transfer_attachment
		WHERE scope = ? AND room_token_hash = ? AND status = ? AND public_transfer_room_id IS NULL`)
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

func (db *DB) InsertTransferDownloadGrant(ctx context.Context, grant TransferAttachmentDownloadGrant) error {
	query := db.rebind(`INSERT INTO transfer_attachment_download_grant
		(id, token_hash, tenant_id, username, attachment_id, created_at, expires_at, consumed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, grant.ID, grant.TokenHash, defaultTenant(grant.TenantID),
		strings.TrimSpace(grant.Username), grant.AttachmentID, formatTime(grant.CreatedAt),
		formatTime(grant.ExpiresAt), nullableTime(grant.ConsumedAt))
	return err
}

func (db *DB) GetTransferDownloadGrantByTokenHash(ctx context.Context,
	tokenHash string) (*TransferAttachmentDownloadGrant, error) {
	query := db.rebind(`SELECT id, token_hash, tenant_id, username, attachment_id,
		created_at, expires_at, consumed_at
		FROM transfer_attachment_download_grant WHERE token_hash = ?`)
	var grant TransferAttachmentDownloadGrant
	var createdAt, expiresAt string
	var consumedAt sql.NullString
	err := db.sql.QueryRowContext(ctx, query, tokenHash).Scan(&grant.ID, &grant.TokenHash,
		&grant.TenantID, &grant.Username, &grant.AttachmentID, &createdAt, &expiresAt, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	grant.CreatedAt = parseTime(createdAt)
	grant.ExpiresAt = parseTime(expiresAt)
	grant.ConsumedAt = nullTimePtr(consumedAt)
	return &grant, nil
}

func (db *DB) ConsumeTransferDownloadGrant(ctx context.Context, id int64, tokenHash string,
	now time.Time) (bool, error) {
	query := db.rebind(`UPDATE transfer_attachment_download_grant SET consumed_at = ?
		WHERE id = ? AND token_hash = ? AND consumed_at IS NULL AND expires_at > ?`)
	result, err := db.sql.ExecContext(ctx, query, formatTime(now), id, tokenHash, formatTime(now))
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}

func (db *DB) ConsumeTransferDownloadGrantAndInsertUsage(ctx context.Context, grantID int64,
	tokenHash string, consumedAt time.Time, usageID int64, tenantID, username string,
	attachmentID, sizeBytes int64, usageMonth string) (bool, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	update := db.rebind(`UPDATE transfer_attachment_download_grant SET consumed_at = ?
		WHERE id = ? AND token_hash = ? AND consumed_at IS NULL AND expires_at > ?`)
	result, err := tx.ExecContext(ctx, update, formatTime(consumedAt), grantID, tokenHash,
		formatTime(consumedAt))
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return false, err
	}
	insert := db.rebind(`INSERT INTO transfer_attachment_download_usage
		(id, tenant_id, username, attachment_id, size_bytes, usage_month, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if _, err = tx.ExecContext(ctx, insert, usageID, defaultTenant(tenantID), strings.TrimSpace(username),
		attachmentID, sizeBytes, usageMonth, formatTime(consumedAt)); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (db *DB) DeleteTransferDownloadGrant(ctx context.Context, id int64) error {
	_, err := db.sql.ExecContext(ctx,
		db.rebind(`DELETE FROM transfer_attachment_download_grant WHERE id = ?`), id)
	return err
}

func (db *DB) DeleteExpiredTransferDownloadGrants(ctx context.Context, before time.Time) error {
	_, err := db.sql.ExecContext(ctx,
		db.rebind(`DELETE FROM transfer_attachment_download_grant WHERE expires_at < ?`), formatTime(before))
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
	public_transfer_room_id, owner_username, target_client_id, object_key, file_name, mime_type,
	size_bytes, sha256, status, created_at, updated_at, upload_expires_at, expires_at, uploaded_at
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
	var targetClientID, publicTransferRoomID sql.NullInt64
	var createdAt, updatedAt, uploadExpiresAt, expiresAt string
	err := scanner.Scan(&item.ID, &tenantID, &item.Scope, &roomID, &roomTokenHash,
		&publicTransferRoomID, &ownerUsername,
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
	if publicTransferRoomID.Valid {
		roomRowID := publicTransferRoomID.Int64
		item.PublicTransferRoomID = &roomRowID
	}
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
