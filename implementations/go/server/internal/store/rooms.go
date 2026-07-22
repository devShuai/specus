package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ---- public_transfer_room ---------------------------------------------------------------

func (db *DB) InsertPublicTransferRoom(ctx context.Context, room PublicTransferRoom) error {
	query := db.rebind(`INSERT INTO public_transfer_room
		(id, room_name, owner_token_hash, created_by_peer_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, room.ID, room.RoomName, room.OwnerTokenHash,
		room.CreatedByPeerID, formatTime(room.CreatedAt), formatTime(room.UpdatedAt))
	return err
}

func (db *DB) GetPublicTransferRoomByNameAndOwnerTokenHash(ctx context.Context,
	roomName, ownerTokenHash string) (*PublicTransferRoom, error) {
	query := db.rebind(`SELECT id, room_name, owner_token_hash, created_by_peer_id, created_at, updated_at
		FROM public_transfer_room WHERE room_name = ? AND owner_token_hash = ?`)
	return scanPublicTransferRoomOrNil(db.sql.QueryRowContext(ctx, query, roomName, ownerTokenHash))
}

func (db *DB) GetPublicTransferRoomByID(ctx context.Context, id int64) (*PublicTransferRoom, error) {
	query := db.rebind(`SELECT id, room_name, owner_token_hash, created_by_peer_id, created_at, updated_at
		FROM public_transfer_room WHERE id = ?`)
	return scanPublicTransferRoomOrNil(db.sql.QueryRowContext(ctx, query, id))
}

func (db *DB) PublicTransferRoomExists(ctx context.Context, id int64) (bool, error) {
	return db.rowExists(ctx, `SELECT COUNT(*) FROM public_transfer_room WHERE id = ?`, id)
}

func scanPublicTransferRoomOrNil(scanner transferAttachmentScanner) (*PublicTransferRoom, error) {
	var room PublicTransferRoom
	var createdAt, updatedAt string
	err := scanner.Scan(&room.ID, &room.RoomName, &room.OwnerTokenHash, &room.CreatedByPeerID,
		&createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	room.CreatedAt = parseTime(createdAt)
	room.UpdatedAt = parseTime(updatedAt)
	return &room, nil
}

// ---- public_transfer_room_access --------------------------------------------------------

func (db *DB) InsertPublicTransferRoomAccess(ctx context.Context, access PublicTransferRoomAccess) error {
	query := db.rebind(`INSERT INTO public_transfer_room_access
		(id, room_id, token_hash, role, label, created_at, expires_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, access.ID, access.RoomID, access.TokenHash, access.Role,
		access.Label, formatTime(access.CreatedAt), nullableTime(access.ExpiresAt), nullableTime(access.RevokedAt))
	return err
}

func (db *DB) GetPublicTransferRoomAccessByTokenHash(ctx context.Context,
	tokenHash string) (*PublicTransferRoomAccess, error) {
	query := db.rebind(publicTransferRoomAccessSelect + ` WHERE token_hash = ?`)
	return scanPublicTransferRoomAccessOrNil(db.sql.QueryRowContext(ctx, query, tokenHash))
}

func (db *DB) GetPublicTransferRoomAccessByIDAndRoom(ctx context.Context,
	id, roomID int64) (*PublicTransferRoomAccess, error) {
	query := db.rebind(publicTransferRoomAccessSelect + ` WHERE id = ? AND room_id = ?`)
	return scanPublicTransferRoomAccessOrNil(db.sql.QueryRowContext(ctx, query, id, roomID))
}

func (db *DB) ListPublicTransferRoomAccessByRoom(ctx context.Context,
	roomID int64) ([]PublicTransferRoomAccess, error) {
	query := db.rebind(publicTransferRoomAccessSelect + ` WHERE room_id = ? ORDER BY created_at DESC`)
	rows, err := db.sql.QueryContext(ctx, query, roomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PublicTransferRoomAccess, 0)
	for rows.Next() {
		item, err := scanPublicTransferRoomAccess(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) RevokePublicTransferRoomAccess(ctx context.Context, id int64, revokedAt time.Time) error {
	query := db.rebind(`UPDATE public_transfer_room_access SET revoked_at = ? WHERE id = ?`)
	_, err := db.sql.ExecContext(ctx, query, formatTime(revokedAt), id)
	return err
}

func (db *DB) PublicTransferRoomAccessExists(ctx context.Context, id int64) (bool, error) {
	return db.rowExists(ctx, `SELECT COUNT(*) FROM public_transfer_room_access WHERE id = ?`, id)
}

const publicTransferRoomAccessSelect = `SELECT id, room_id, token_hash, role, label,
	created_at, expires_at, revoked_at FROM public_transfer_room_access`

func scanPublicTransferRoomAccessOrNil(scanner transferAttachmentScanner) (*PublicTransferRoomAccess, error) {
	item, err := scanPublicTransferRoomAccess(scanner)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func scanPublicTransferRoomAccess(scanner transferAttachmentScanner) (PublicTransferRoomAccess, error) {
	var item PublicTransferRoomAccess
	var createdAt string
	var expiresAt, revokedAt sql.NullString
	err := scanner.Scan(&item.ID, &item.RoomID, &item.TokenHash, &item.Role, &item.Label,
		&createdAt, &expiresAt, &revokedAt)
	if err != nil {
		return PublicTransferRoomAccess{}, err
	}
	item.CreatedAt = parseTime(createdAt)
	item.ExpiresAt = nullTimePtr(expiresAt)
	item.RevokedAt = nullTimePtr(revokedAt)
	return item, nil
}

// ---- public_transfer_room_pairing_code --------------------------------------------------

func (db *DB) InsertPublicTransferPairingCode(ctx context.Context, code PublicTransferRoomPairingCode) error {
	query := db.rebind(`INSERT INTO public_transfer_room_pairing_code
		(id, room_id, code_hash, role, label, created_at, expires_at, max_uses, used_count, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, code.ID, code.RoomID, code.CodeHash, code.Role, code.Label,
		formatTime(code.CreatedAt), formatTime(code.ExpiresAt), code.MaxUses, code.UsedCount,
		nullableTime(code.RevokedAt))
	return err
}

func (db *DB) GetPublicTransferPairingCodeByHash(ctx context.Context,
	codeHash string) (*PublicTransferRoomPairingCode, error) {
	query := db.rebind(`SELECT id, room_id, code_hash, role, label, created_at, expires_at,
		max_uses, used_count, revoked_at FROM public_transfer_room_pairing_code WHERE code_hash = ?`)
	var item PublicTransferRoomPairingCode
	var createdAt, expiresAt string
	var revokedAt sql.NullString
	err := db.sql.QueryRowContext(ctx, query, codeHash).Scan(&item.ID, &item.RoomID, &item.CodeHash,
		&item.Role, &item.Label, &createdAt, &expiresAt, &item.MaxUses, &item.UsedCount, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	item.CreatedAt = parseTime(createdAt)
	item.ExpiresAt = parseTime(expiresAt)
	item.RevokedAt = nullTimePtr(revokedAt)
	return &item, nil
}

// ConsumePublicTransferPairingCode atomically reserves one redemption, avoiding the
// check-then-update race that could let a one-time code mint more than one access token.
func (db *DB) ConsumePublicTransferPairingCode(ctx context.Context, codeHash string, now time.Time) (bool, error) {
	query := db.rebind(`UPDATE public_transfer_room_pairing_code SET used_count = used_count + 1
		WHERE code_hash = ? AND revoked_at IS NULL AND expires_at > ? AND used_count < max_uses`)
	result, err := db.sql.ExecContext(ctx, query, codeHash, formatTime(now))
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}

func (db *DB) PublicTransferPairingCodeHashExists(ctx context.Context, codeHash string) (bool, error) {
	return db.rowExists(ctx, `SELECT COUNT(*) FROM public_transfer_room_pairing_code WHERE code_hash = ?`, codeHash)
}

func (db *DB) PublicTransferPairingCodeExists(ctx context.Context, id int64) (bool, error) {
	return db.rowExists(ctx, `SELECT COUNT(*) FROM public_transfer_room_pairing_code WHERE id = ?`, id)
}

// ---- public_transfer_diagram_version ----------------------------------------------------

func (db *DB) InsertPublicTransferDiagramVersion(ctx context.Context, version PublicTransferDiagramVersion) error {
	query := db.rebind(`INSERT INTO public_transfer_diagram_version
		(id, room_id, name, author_peer_id, snapshot_data, size_bytes, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, version.ID, version.RoomID, version.Name,
		version.AuthorPeerID, version.SnapshotData, version.SizeBytes, formatTime(version.CreatedAt))
	return err
}

// ListPublicTransferDiagramVersionsByRoom returns version metadata (no snapshot blob),
// newest first.
func (db *DB) ListPublicTransferDiagramVersionsByRoom(ctx context.Context,
	roomID int64) ([]PublicTransferDiagramVersion, error) {
	query := db.rebind(`SELECT id, room_id, name, author_peer_id, size_bytes, created_at
		FROM public_transfer_diagram_version WHERE room_id = ? ORDER BY created_at DESC`)
	rows, err := db.sql.QueryContext(ctx, query, roomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PublicTransferDiagramVersion, 0)
	for rows.Next() {
		var item PublicTransferDiagramVersion
		var createdAt string
		if err := rows.Scan(&item.ID, &item.RoomID, &item.Name, &item.AuthorPeerID,
			&item.SizeBytes, &createdAt); err != nil {
			return nil, err
		}
		item.CreatedAt = parseTime(createdAt)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) GetPublicTransferDiagramVersion(ctx context.Context,
	id, roomID int64) (*PublicTransferDiagramVersion, error) {
	query := db.rebind(`SELECT id, room_id, name, author_peer_id, snapshot_data, size_bytes, created_at
		FROM public_transfer_diagram_version WHERE id = ? AND room_id = ?`)
	var item PublicTransferDiagramVersion
	var createdAt string
	err := db.sql.QueryRowContext(ctx, query, id, roomID).Scan(&item.ID, &item.RoomID, &item.Name,
		&item.AuthorPeerID, &item.SnapshotData, &item.SizeBytes, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	item.CreatedAt = parseTime(createdAt)
	return &item, nil
}

func (db *DB) DeletePublicTransferDiagramVersion(ctx context.Context, id int64) error {
	_, err := db.sql.ExecContext(ctx,
		db.rebind(`DELETE FROM public_transfer_diagram_version WHERE id = ?`), id)
	return err
}

func (db *DB) PublicTransferDiagramVersionExists(ctx context.Context, id int64) (bool, error) {
	return db.rowExists(ctx, `SELECT COUNT(*) FROM public_transfer_diagram_version WHERE id = ?`, id)
}

func (db *DB) rowExists(ctx context.Context, query string, args ...any) (bool, error) {
	var count int
	if err := db.sql.QueryRowContext(ctx, db.rebind(query), args...).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}
