package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// RedeemPairingCodeRequest carries everything needed to consume a pairing code and hand back an
// access token inside one transaction.
type RedeemPairingCodeRequest struct {
	CodeHash string
	Now      time.Time
	// MaxAccessTokensPerRoom bounds live invitations per room; 0 disables the check.
	MaxAccessTokensPerRoom int
	// NewAccess is called with the resolved room and pairing code to build the row to insert.
	//
	// It runs while the transaction holds the write lock, so it must be a pure computation: any
	// query it issues would wait for that same lock and deadlock on SQLite. Allocate identifiers and
	// read anything else you need before calling RedeemPairingCode.
	NewAccess func(room PublicTransferRoom, code PublicTransferRoomPairingCode) (PublicTransferRoomAccess, error)
}

// ErrPairingCodeUnusable reports a code that is unknown, revoked, expired or already exhausted.
var ErrPairingCodeUnusable = errors.New("pairing code is not usable")

// ErrAccessTokenCapacity reports that the room already holds its maximum live invitations.
var ErrAccessTokenCapacity = errors.New("room already holds the maximum number of access tokens")

// RedeemPairingCode consumes one use of a pairing code and inserts the resulting access token in a
// single transaction.
//
// Consuming the code first and issuing the token afterwards would permanently burn a use whenever a
// later step failed: the caller would have spent the code and received nothing. Both effects now
// commit together or not at all.
func (db *DB) RedeemPairingCode(ctx context.Context, request RedeemPairingCodeRequest) (
	PublicTransferRoom, PublicTransferRoomPairingCode, PublicTransferRoomAccess, error) {
	var (
		room   PublicTransferRoom
		code   PublicTransferRoomPairingCode
		access PublicTransferRoomAccess
	)
	if request.NewAccess == nil {
		return room, code, access, errors.New("NewAccess is required")
	}

	var options *sql.TxOptions
	if db.dialect != DialectSQLite {
		// The capacity count must observe rows committed by a concurrent redemption.
		options = &sql.TxOptions{Isolation: sql.LevelReadCommitted}
	}
	tx, err := db.sql.BeginTx(ctx, options)
	if err != nil {
		return room, code, access, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// The conditional UPDATE is the atomic gate: exactly one concurrent caller can take the use.
	consume := db.rebind(`UPDATE public_transfer_room_pairing_code SET used_count = used_count + 1
		WHERE code_hash = ? AND revoked_at IS NULL AND expires_at > ? AND used_count < max_uses`)
	result, err := tx.ExecContext(ctx, consume, request.CodeHash, formatTime(request.Now))
	if err != nil {
		return room, code, access, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return room, code, access, err
	}
	if affected != 1 {
		return room, code, access, ErrPairingCodeUnusable
	}

	code, err = scanPairingCodeByHashTx(ctx, db, tx, request.CodeHash)
	if err != nil {
		return room, code, access, err
	}
	room, err = scanRoomByIDTx(ctx, db, tx, code.RoomID)
	if err != nil {
		return room, code, access, err
	}

	if request.MaxAccessTokensPerRoom > 0 {
		countQuery := db.rebind(`SELECT COUNT(*) FROM public_transfer_room_access
			WHERE room_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`)
		var live int
		if err := tx.QueryRowContext(ctx, countQuery, room.ID, formatTime(request.Now)).Scan(&live); err != nil {
			return room, code, access, err
		}
		if live >= request.MaxAccessTokensPerRoom {
			return room, code, access, ErrAccessTokenCapacity
		}
	}

	access, err = request.NewAccess(room, code)
	if err != nil {
		return room, code, access, err
	}
	insert := db.rebind(`INSERT INTO public_transfer_room_access
		(id, room_id, token_hash, role, label, created_at, expires_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`)
	if _, err := tx.ExecContext(ctx, insert, access.ID, access.RoomID, access.TokenHash,
		access.Role, access.Label, formatTime(access.CreatedAt),
		nullableTime(access.ExpiresAt)); err != nil {
		return room, code, access, err
	}

	if err := tx.Commit(); err != nil {
		return room, code, access, err
	}
	committed = true
	return room, code, access, nil
}

func scanPairingCodeByHashTx(ctx context.Context, db *DB, tx *sql.Tx,
	codeHash string) (PublicTransferRoomPairingCode, error) {
	query := db.rebind(`SELECT id, room_id, code_hash, role, label, created_at, expires_at,
		max_uses, used_count, revoked_at
		FROM public_transfer_room_pairing_code WHERE code_hash = ?`)
	var (
		item      PublicTransferRoomPairingCode
		createdAt string
		expiresAt string
		revokedAt sql.NullString
		label     sql.NullString
	)
	err := tx.QueryRowContext(ctx, query, codeHash).Scan(&item.ID, &item.RoomID, &item.CodeHash,
		&item.Role, &label, &createdAt, &expiresAt, &item.MaxUses, &item.UsedCount, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return item, ErrPairingCodeUnusable
	}
	if err != nil {
		return item, err
	}
	item.Label = label.String
	item.CreatedAt = parseTime(createdAt)
	item.ExpiresAt = parseTime(expiresAt)
	if revokedAt.Valid {
		value := parseTime(revokedAt.String)
		item.RevokedAt = &value
	}
	return item, nil
}

func scanRoomByIDTx(ctx context.Context, db *DB, tx *sql.Tx, roomID int64) (PublicTransferRoom, error) {
	query := db.rebind(`SELECT id, room_name, owner_token_hash, created_at, updated_at
		FROM public_transfer_room WHERE id = ?`)
	var (
		item      PublicTransferRoom
		createdAt string
		updatedAt string
	)
	err := tx.QueryRowContext(ctx, query, roomID).Scan(&item.ID, &item.RoomName,
		&item.OwnerTokenHash, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return item, ErrPairingCodeUnusable
	}
	if err != nil {
		return item, err
	}
	item.CreatedAt = parseTime(createdAt)
	item.UpdatedAt = parseTime(updatedAt)
	return item, nil
}
