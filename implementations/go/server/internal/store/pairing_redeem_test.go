package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func seedPairingCode(t *testing.T, db *DB, codeHash string, maxUses int,
	expiresAt time.Time) (roomID int64) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	roomID = 9001
	if err := db.InsertPublicTransferRoom(ctx, PublicTransferRoom{
		ID: roomID, RoomName: "room-atomic", OwnerTokenHash: "owner-hash",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("insert room: %v", err)
	}
	if err := db.InsertPublicTransferPairingCode(ctx, PublicTransferRoomPairingCode{
		ID: 9101, RoomID: roomID, CodeHash: codeHash, Role: "EDITOR", Label: "invite",
		CreatedAt: now, ExpiresAt: expiresAt, MaxUses: maxUses,
	}); err != nil {
		t.Fatalf("insert pairing code: %v", err)
	}
	return roomID
}

func openPairingDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "pairing.db"))
	if err != nil {
		t.Fatalf("open temp db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestRedeemPairingCodeCommitsConsumptionAndTokenTogether(t *testing.T) {
	db := openPairingDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	roomID := seedPairingCode(t, db, "hash-ok", 1, now.Add(time.Hour))

	room, code, access, err := db.RedeemPairingCode(ctx, RedeemPairingCodeRequest{
		CodeHash: "hash-ok", Now: now,
		NewAccess: func(room PublicTransferRoom, code PublicTransferRoomPairingCode) (PublicTransferRoomAccess, error) {
			return PublicTransferRoomAccess{
				ID: 9201, RoomID: room.ID, TokenHash: "token-hash",
				Role: code.Role, Label: code.Label, CreatedAt: now,
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if room.ID != roomID || code.UsedCount != 1 || access.ID != 9201 {
		t.Fatalf("unexpected redeem result: room=%d used=%d access=%d", room.ID, code.UsedCount, access.ID)
	}

	stored, err := db.ListPublicTransferRoomAccessByRoom(ctx, roomID)
	if err != nil || len(stored) != 1 {
		t.Fatalf("access token was not persisted: %v (%d rows)", err, len(stored))
	}

	// The single use is now spent.
	if _, _, _, err := db.RedeemPairingCode(ctx, RedeemPairingCodeRequest{
		CodeHash: "hash-ok", Now: now,
		NewAccess: func(PublicTransferRoom, PublicTransferRoomPairingCode) (PublicTransferRoomAccess, error) {
			return PublicTransferRoomAccess{ID: 9202, RoomID: roomID, TokenHash: "second", CreatedAt: now}, nil
		},
	}); !errors.Is(err, ErrPairingCodeUnusable) {
		t.Fatalf("second redeem err = %v, want ErrPairingCodeUnusable", err)
	}
}

// Consuming the code first and issuing the token afterwards would permanently burn one use whenever
// a later step failed. The whole redemption must roll back instead.
func TestRedeemPairingCodeRollsBackTheConsumedUseWhenIssuingFails(t *testing.T) {
	db := openPairingDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	roomID := seedPairingCode(t, db, "hash-fail", 1, now.Add(time.Hour))

	issueErr := errors.New("token generation failed")
	if _, _, _, err := db.RedeemPairingCode(ctx, RedeemPairingCodeRequest{
		CodeHash: "hash-fail", Now: now,
		NewAccess: func(PublicTransferRoom, PublicTransferRoomPairingCode) (PublicTransferRoomAccess, error) {
			return PublicTransferRoomAccess{}, issueErr
		},
	}); !errors.Is(err, issueErr) {
		t.Fatalf("redeem err = %v, want the issuing failure", err)
	}

	// No token was stored and the use was returned, so the code still works.
	stored, err := db.ListPublicTransferRoomAccessByRoom(ctx, roomID)
	if err != nil {
		t.Fatalf("list access: %v", err)
	}
	if len(stored) != 0 {
		t.Fatalf("a failed redemption must not leave an access token: %d rows", len(stored))
	}
	code, err := db.GetPublicTransferPairingCodeByHash(ctx, "hash-fail")
	if err != nil || code == nil {
		t.Fatalf("load pairing code: %v", err)
	}
	if code.UsedCount != 0 {
		t.Fatalf("usedCount = %d, want the consumed use rolled back", code.UsedCount)
	}

	// Proof the code is still redeemable.
	if _, _, _, err := db.RedeemPairingCode(ctx, RedeemPairingCodeRequest{
		CodeHash: "hash-fail", Now: now,
		NewAccess: func(room PublicTransferRoom, code PublicTransferRoomPairingCode) (PublicTransferRoomAccess, error) {
			return PublicTransferRoomAccess{
				ID: 9301, RoomID: room.ID, TokenHash: "retry-hash", Role: code.Role, CreatedAt: now,
			}, nil
		},
	}); err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}
}

func TestRedeemPairingCodeRejectsExpiredAndOverCapacityRooms(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	expired := openPairingDB(t)
	seedPairingCode(t, expired, "hash-expired", 1, now.Add(-time.Minute))
	if _, _, _, err := expired.RedeemPairingCode(ctx, RedeemPairingCodeRequest{
		CodeHash: "hash-expired", Now: now,
		NewAccess: func(PublicTransferRoom, PublicTransferRoomPairingCode) (PublicTransferRoomAccess, error) {
			return PublicTransferRoomAccess{ID: 1, CreatedAt: now}, nil
		},
	}); !errors.Is(err, ErrPairingCodeUnusable) {
		t.Fatalf("expired code err = %v, want ErrPairingCodeUnusable", err)
	}

	full := openPairingDB(t)
	roomID := seedPairingCode(t, full, "hash-full", 5, now.Add(time.Hour))
	if err := full.InsertPublicTransferRoomAccess(ctx, PublicTransferRoomAccess{
		ID: 9401, RoomID: roomID, TokenHash: "existing", Role: "EDITOR", CreatedAt: now,
	}); err != nil {
		t.Fatalf("insert existing access: %v", err)
	}
	if _, _, _, err := full.RedeemPairingCode(ctx, RedeemPairingCodeRequest{
		CodeHash: "hash-full", Now: now, MaxAccessTokensPerRoom: 1,
		NewAccess: func(PublicTransferRoom, PublicTransferRoomPairingCode) (PublicTransferRoomAccess, error) {
			return PublicTransferRoomAccess{ID: 9402, RoomID: roomID, TokenHash: "new", CreatedAt: now}, nil
		},
	}); !errors.Is(err, ErrAccessTokenCapacity) {
		t.Fatalf("capacity err = %v, want ErrAccessTokenCapacity", err)
	}
	// The rejected redemption must not have spent a use either.
	code, err := full.GetPublicTransferPairingCodeByHash(ctx, "hash-full")
	if err != nil || code == nil {
		t.Fatalf("load pairing code: %v", err)
	}
	if code.UsedCount != 0 {
		t.Fatalf("usedCount = %d, want 0 after a capacity rejection", code.UsedCount)
	}
}
