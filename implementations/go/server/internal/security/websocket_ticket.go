package security

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

const (
	WebSocketScopeConnections    = "connections"
	WebSocketScopeClientMessages = "client-messages"
	WebSocketScopePublicTransfer = "public-transfer"
	webSocketTicketTTL           = 45 * time.Second
)

type WebSocketTicketService struct {
	db  *store.DB
	now func() time.Time
}

type WebSocketTicketClaims struct {
	Username    string
	TenantID    string
	Admin       bool
	RoomID      string
	RoomKey     string
	RoomRole    string
	PeerID      string
	DisplayName string
	// PublicAddress is the issuer-visible client address (same chain as the discovery
	// upgrade's trustedClientIP), persisted so Java nodes consuming Go tickets derive
	// the same netId/roomKey (aligned with the Java WebSocketTicketResource).
	PublicAddress string
	SharedRoom    bool
	// Discoverable defaults to true for tickets minted before the field existed
	// (aligned with the Java discoverable attribute semantics).
	Discoverable bool
}

// ExtractWebSocketTicket accepts only the v2 single-ticket query shape.
func ExtractWebSocketTicket(r *http.Request) (string, bool) {
	query := r.URL.Query()
	values, ok := query["ticket"]
	if !ok || len(query) != 1 || len(values) != 1 {
		return "", false
	}
	ticket := strings.TrimSpace(values[0])
	return ticket, ticket != ""
}

// WebSocketRequestAddress must produce the same binding for the ticket POST and upgrade. Both go
// through the shared trusted-proxy boundary so a forged header cannot rebind someone else's ticket.
func WebSocketRequestAddress(resolver *ClientAddressResolver, r *http.Request) string {
	return resolver.Resolve(r)
}

type IssuedWebSocketTicket struct {
	Ticket    string    `json:"ticket"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func NewWebSocketTicketService(db *store.DB) *WebSocketTicketService {
	return &WebSocketTicketService{db: db, now: time.Now}
}

func (s *WebSocketTicketService) Issue(ctx context.Context, scope, remoteAddress string, claims WebSocketTicketClaims) (IssuedWebSocketTicket, error) {
	if !validWebSocketScope(scope) {
		return IssuedWebSocketTicket{}, fmt.Errorf("unsupported websocket ticket scope %q", scope)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return IssuedWebSocketTicket{}, fmt.Errorf("generate websocket ticket: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	now := s.now().UTC()
	expiresAt := now.Add(webSocketTicketTTL)
	err := s.db.InsertWebSocketTicket(ctx, store.WebSocketTicket{
		TokenHash:         digestText(token),
		Scope:             scope,
		Username:          strings.TrimSpace(claims.Username),
		TenantID:          strings.TrimSpace(claims.TenantID),
		Admin:             claims.Admin,
		RoomID:            strings.TrimSpace(claims.RoomID),
		RoomKey:           strings.TrimSpace(claims.RoomKey),
		RoomRole:          strings.TrimSpace(claims.RoomRole),
		PeerID:            strings.TrimSpace(claims.PeerID),
		DisplayName:       strings.TrimSpace(claims.DisplayName),
		PublicAddress:     strings.TrimSpace(claims.PublicAddress),
		SharedRoom:        claims.SharedRoom,
		Discoverable:      claims.Discoverable,
		RemoteAddressHash: digestText(remoteAddress),
		CreatedAt:         now,
		ExpiresAt:         expiresAt,
	})
	if err != nil {
		return IssuedWebSocketTicket{}, err
	}
	return IssuedWebSocketTicket{Ticket: token, ExpiresAt: expiresAt}, nil
}

func (s *WebSocketTicketService) Consume(ctx context.Context, ticket, scope, remoteAddress string) (*WebSocketTicketClaims, error) {
	if len(ticket) < 32 || len(ticket) > 128 || !validWebSocketScope(scope) {
		return nil, nil
	}
	record, err := s.db.ConsumeWebSocketTicket(ctx, digestText(ticket), scope, digestText(remoteAddress), s.now().UTC())
	if err != nil || record == nil {
		return nil, err
	}
	return &WebSocketTicketClaims{
		Username: record.Username, TenantID: record.TenantID, Admin: record.Admin,
		RoomID: record.RoomID, RoomKey: record.RoomKey, RoomRole: record.RoomRole, PeerID: record.PeerID,
		DisplayName: record.DisplayName, PublicAddress: record.PublicAddress,
		SharedRoom: record.SharedRoom, Discoverable: record.Discoverable,
	}, nil
}

func validWebSocketScope(scope string) bool {
	switch scope {
	case WebSocketScopeConnections, WebSocketScopeClientMessages, WebSocketScopePublicTransfer:
		return true
	default:
		return false
	}
}

func digestText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
