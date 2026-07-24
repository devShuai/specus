package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ConsumeClientAuthNonce atomically reserves an API-key nonce until expiresAt.
func (db *DB) ConsumeClientAuthNonce(ctx context.Context, apiKeyHash, nonce string, now, expiresAt time.Time) (bool, error) {
	_, _ = db.sql.ExecContext(ctx, db.rebind(`DELETE FROM tunnel_client_auth_nonce WHERE expires_at <= ?`), formatTime(now))

	var insertQuery, lookupQuery string
	var insertArgs, lookupArgs []any
	switch db.clientAuthNonceLayout {
	case clientAuthNonceLayoutJavaID:
		nonceID := hashClientAuthNonce(apiKeyHash + "\n" + nonce)
		insertQuery = `INSERT INTO tunnel_client_auth_nonce (id, api_key_hash, expires_at) VALUES (?, ?, ?)`
		insertArgs = []any{nonceID, apiKeyHash, formatTime(expiresAt)}
		lookupQuery = `SELECT COUNT(*) FROM tunnel_client_auth_nonce WHERE id = ?`
		lookupArgs = []any{nonceID}
	case clientAuthNonceLayoutComposite:
		nonceHash := hashClientAuthNonce(nonce)
		insertQuery = `INSERT INTO tunnel_client_auth_nonce
			(api_key_hash, nonce_hash, expires_at, created_at) VALUES (?, ?, ?, ?)`
		insertArgs = []any{apiKeyHash, nonceHash, formatTime(expiresAt), formatTime(now)}
		lookupQuery = `SELECT COUNT(*) FROM tunnel_client_auth_nonce
			WHERE api_key_hash = ? AND nonce_hash = ?`
		lookupArgs = []any{apiKeyHash, nonceHash}
	default:
		return false, fmt.Errorf("reserve client authentication nonce: database nonce schema is not initialized")
	}

	_, err := db.sql.ExecContext(ctx, db.rebind(insertQuery), insertArgs...)
	if err == nil {
		return true, nil
	}
	var count int
	lookupErr := db.sql.QueryRowContext(ctx, db.rebind(lookupQuery), lookupArgs...).Scan(&count)
	if lookupErr == nil && count > 0 {
		return false, nil
	}
	return false, fmt.Errorf("reserve client authentication nonce: %w", err)
}

func hashClientAuthNonce(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func (db *DB) InsertWebSocketTicket(ctx context.Context, ticket WebSocketTicket) error {
	attributesJSON, err := encodeWebSocketTicketAttributes(ticket)
	if err != nil {
		return fmt.Errorf("encode websocket ticket attributes: %w", err)
	}
	_, err = db.sql.ExecContext(ctx, db.rebind(`INSERT INTO tunnel_websocket_ticket
		(token_hash, scope, attributes_json, username, tenant_id, is_admin, room_id, room_key, room_role, peer_id, display_name,
		 shared_room, remote_address_hash, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		ticket.TokenHash, ticket.Scope, attributesJSON, nullableText(ticket.Username), nullableText(ticket.TenantID), boolToInt(ticket.Admin),
		nullableText(ticket.RoomID), nullableText(ticket.RoomKey), nullableText(ticket.RoomRole), nullableText(ticket.PeerID), nullableText(ticket.DisplayName),
		boolToInt(ticket.SharedRoom), ticket.RemoteAddressHash, formatTime(ticket.CreatedAt), formatTime(ticket.ExpiresAt))
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
		attributesJSON, storedAddressHash   sql.NullString
		admin, sharedRoom                   databaseBoolean
		createdAt, expiresAt                string
	)
	err := db.sql.QueryRowContext(ctx, db.rebind(`SELECT token_hash, scope, attributes_json, username, tenant_id, is_admin,
		room_id, room_key, room_role, peer_id, display_name, shared_room, remote_address_hash, created_at, expires_at
		FROM tunnel_websocket_ticket WHERE token_hash = ?`), tokenHash).Scan(
		&ticket.TokenHash, &ticket.Scope, &attributesJSON, &username, &tenantID, &admin, &roomID, &roomKey, &roomRole, &peerID,
		&displayName, &sharedRoom, &storedAddressHash, &createdAt, &expiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("select websocket ticket: %w", err)
	}
	if attributesJSON.Valid && strings.TrimSpace(attributesJSON.String) != "" {
		if err := decodeWebSocketTicketAttributes(attributesJSON.String, &ticket); err != nil {
			return nil, fmt.Errorf("decode websocket ticket attributes: %w", err)
		}
	} else {
		ticket.Username = username.String
		ticket.TenantID = tenantID.String
		ticket.Admin = bool(admin)
		ticket.RoomID = roomID.String
		ticket.RoomKey = roomKey.String
		ticket.RoomRole = roomRole.String
		ticket.PeerID = peerID.String
		ticket.DisplayName = displayName.String
		ticket.SharedRoom = bool(sharedRoom)
	}
	ticket.RemoteAddressHash = storedAddressHash.String
	ticket.CreatedAt = parseTime(createdAt)
	ticket.ExpiresAt = parseTime(expiresAt)
	if ticket.Scope != scope ||
		(ticket.RemoteAddressHash != "" && ticket.RemoteAddressHash != remoteAddressHash) ||
		!ticket.ExpiresAt.After(now) {
		return nil, nil
	}
	deleteQuery := `DELETE FROM tunnel_websocket_ticket
		WHERE token_hash = ? AND scope = ? AND expires_at > ?`
	deleteArgs := []any{tokenHash, scope, formatTime(now)}
	if ticket.RemoteAddressHash != "" {
		deleteQuery = `DELETE FROM tunnel_websocket_ticket
			WHERE token_hash = ? AND scope = ? AND remote_address_hash = ? AND expires_at > ?`
		deleteArgs = []any{tokenHash, scope, remoteAddressHash, formatTime(now)}
	}
	result, err := db.sql.ExecContext(ctx, db.rebind(deleteQuery), deleteArgs...)
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

type webSocketTicketAttributes struct {
	Username    string `json:"wsUser,omitempty"`
	TenantID    string `json:"tenantId,omitempty"`
	Admin       bool   `json:"admin"`
	RoomID      string `json:"roomId,omitempty"`
	RoomKey     string `json:"roomKey,omitempty"`
	RoomRole    string `json:"roomRole,omitempty"`
	PeerID      string `json:"peerId,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	SharedRoom  bool   `json:"sharedRoom"`
}

func encodeWebSocketTicketAttributes(ticket WebSocketTicket) (string, error) {
	payload, err := json.Marshal(webSocketTicketAttributes{
		Username: ticket.Username, TenantID: ticket.TenantID, Admin: ticket.Admin,
		RoomID: ticket.RoomID, RoomKey: ticket.RoomKey, RoomRole: ticket.RoomRole,
		PeerID: ticket.PeerID, DisplayName: ticket.DisplayName, SharedRoom: ticket.SharedRoom,
	})
	return string(payload), err
}

func decodeWebSocketTicketAttributes(payload string, ticket *WebSocketTicket) error {
	var attributes webSocketTicketAttributes
	if err := json.Unmarshal([]byte(payload), &attributes); err != nil {
		return err
	}
	ticket.Username = attributes.Username
	ticket.TenantID = attributes.TenantID
	ticket.Admin = attributes.Admin
	ticket.RoomID = attributes.RoomID
	ticket.RoomKey = attributes.RoomKey
	ticket.RoomRole = attributes.RoomRole
	ticket.PeerID = attributes.PeerID
	ticket.DisplayName = attributes.DisplayName
	ticket.SharedRoom = attributes.SharedRoom
	return nil
}

func nullableText(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
