package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// ConsumeClientAuthNonce atomically reserves an API-key nonce until expiresAt.
func (db *DB) ConsumeClientAuthNonce(ctx context.Context, apiKeyHash, nonceHash string, now, expiresAt time.Time) (bool, error) {
	_, _ = db.sql.ExecContext(ctx, db.rebind(`DELETE FROM tunnel_client_auth_nonce WHERE expires_at <= ?`), formatTime(now))
	_, err := db.sql.ExecContext(ctx, db.rebind(`INSERT INTO tunnel_client_auth_nonce
		(api_key_hash, nonce_hash, expires_at, created_at) VALUES (?, ?, ?, ?)`),
		apiKeyHash, nonceHash, formatTime(expiresAt), formatTime(now))
	if err == nil {
		return true, nil
	}
	var count int
	lookupErr := db.sql.QueryRowContext(ctx, db.rebind(`SELECT COUNT(*) FROM tunnel_client_auth_nonce
		WHERE api_key_hash = ? AND nonce_hash = ?`), apiKeyHash, nonceHash).Scan(&count)
	if lookupErr == nil && count > 0 {
		return false, nil
	}
	return false, fmt.Errorf("reserve client authentication nonce: %w", err)
}

func (db *DB) InsertWebSocketTicket(ctx context.Context, ticket WebSocketTicket) error {
	_, err := db.sql.ExecContext(ctx, db.rebind(`INSERT INTO tunnel_websocket_ticket
		(token_hash, scope, username, tenant_id, is_admin, room_id, room_key, room_role, peer_id, display_name,
		 shared_room, remote_address_hash, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		ticket.TokenHash, ticket.Scope, nullableText(ticket.Username), nullableText(ticket.TenantID), databaseBool(ticket.Admin),
		nullableText(ticket.RoomID), nullableText(ticket.RoomKey), nullableText(ticket.RoomRole), nullableText(ticket.PeerID), nullableText(ticket.DisplayName),
		databaseBool(ticket.SharedRoom), ticket.RemoteAddressHash, formatTime(ticket.CreatedAt), formatTime(ticket.ExpiresAt))
	if err != nil {
		return fmt.Errorf("insert websocket ticket: %w", err)
	}
	return nil
}

// ConsumeWebSocketTicket returns a ticket exactly once. Scope, expiry and address binding are
// checked before the atomic delete, so a request on the wrong endpoint cannot burn the ticket.
func (db *DB) ConsumeWebSocketTicket(ctx context.Context, tokenHash, scope, remoteAddressHash string, now time.Time) (*WebSocketTicket, error) {
	_, _ = db.sql.ExecContext(ctx, db.rebind(`DELETE FROM tunnel_websocket_ticket WHERE expires_at <= ?`), formatTime(now))
	var (
		ticket                              WebSocketTicket
		username, tenantID, roomID, roomKey sql.NullString
		roomRole, peerID, displayName       sql.NullString
		admin, sharedRoom                   int
		createdAt, expiresAt                string
	)
	err := db.sql.QueryRowContext(ctx, db.rebind(`SELECT token_hash, scope, username, tenant_id, is_admin,
		room_id, room_key, room_role, peer_id, display_name, shared_room, remote_address_hash, created_at, expires_at
		FROM tunnel_websocket_ticket WHERE token_hash = ?`), tokenHash).Scan(
		&ticket.TokenHash, &ticket.Scope, &username, &tenantID, &admin, &roomID, &roomKey, &roomRole, &peerID,
		&displayName, &sharedRoom, &ticket.RemoteAddressHash, &createdAt, &expiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("select websocket ticket: %w", err)
	}
	ticket.Username = username.String
	ticket.TenantID = tenantID.String
	ticket.Admin = admin != 0
	ticket.RoomID = roomID.String
	ticket.RoomKey = roomKey.String
	ticket.RoomRole = roomRole.String
	ticket.PeerID = peerID.String
	ticket.DisplayName = displayName.String
	ticket.SharedRoom = sharedRoom != 0
	ticket.CreatedAt = parseTime(createdAt)
	ticket.ExpiresAt = parseTime(expiresAt)
	if ticket.Scope != scope || ticket.RemoteAddressHash != remoteAddressHash || !ticket.ExpiresAt.After(now) {
		return nil, nil
	}
	result, err := db.sql.ExecContext(ctx, db.rebind(`DELETE FROM tunnel_websocket_ticket
		WHERE token_hash = ? AND scope = ? AND remote_address_hash = ? AND expires_at > ?`),
		tokenHash, scope, remoteAddressHash, formatTime(now))
	if err != nil {
		return nil, fmt.Errorf("consume websocket ticket: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("inspect consumed websocket ticket: %w", err)
	}
	if affected != 1 {
		return nil, nil
	}
	return &ticket, nil
}

func nullableText(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func databaseBool(value bool) int {
	if value {
		return 1
	}
	return 0
}
