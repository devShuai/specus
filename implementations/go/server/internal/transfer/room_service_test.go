package transfer

import (
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/config"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/security"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/store"
)

func newRoomService(t *testing.T, publicCfg config.PublicTransferConfig) *RoomService {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "rooms.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	tokens := security.NewLocalTokenService(config.AuthConfig{JwtSecret: "room-service-test-secret"})
	return NewRoomService(db, publicCfg, tokens)
}

func ownerCredential(roomID, token string) RoomCredential {
	return RoomCredential{RoomID: roomID, RoomToken: token, PeerID: "peer-owner"}
}

func TestRoomResolveCreatesOwnerRoomOnce(t *testing.T) {
	service := newRoomService(t, config.PublicTransferConfig{})
	ctx := context.Background()

	first, err := service.Resolve(ctx, "room-a", "owner-token", "peer-1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if first.Role != RoleOwner || first.RoomName != "room-a" {
		t.Fatalf("unexpected access: %+v", first)
	}
	again, err := service.Resolve(ctx, "room-a", "owner-token", "peer-1")
	if err != nil {
		t.Fatalf("resolve again: %v", err)
	}
	if again.RoomID != first.RoomID {
		t.Fatalf("room id changed across resolves: %d != %d", again.RoomID, first.RoomID)
	}
	other, err := service.Resolve(ctx, "room-a", "another-token", "peer-2")
	if err != nil {
		t.Fatalf("resolve other owner: %v", err)
	}
	if other.RoomID == first.RoomID {
		t.Fatal("distinct owner tokens must not share a room")
	}
	if _, err := service.Resolve(ctx, "room-a", "st-editor-bogus", "peer-3"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("invite-shaped unknown token: err = %v, want forbidden", err)
	}
	if _, err := service.Resolve(ctx, "", "owner-token", "peer-1"); !errors.Is(err, ErrValidation) {
		t.Fatalf("blank roomId: err = %v, want validation", err)
	}
}

func TestRoomAccessTokenLifecycle(t *testing.T) {
	service := newRoomService(t, config.PublicTransferConfig{})
	ctx := context.Background()
	credential := ownerCredential("room-a", "owner-token")

	created, err := service.CreateAccessToken(ctx, CreateAccessTokenRequest{
		RoomID: credential.RoomID, RoomToken: credential.RoomToken, PeerID: credential.PeerID,
		Role: "editor",
	})
	if err != nil {
		t.Fatalf("create access token: %v", err)
	}
	if !strings.HasPrefix(created.Token, "st-editor-") {
		t.Fatalf("token = %q, want st-editor- prefix", created.Token)
	}
	if created.Access.Role != RoleEditor || created.Access.Label != "编辑者邀请" {
		t.Fatalf("unexpected access view: %+v", created.Access)
	}
	if created.Access.ExpiresAt != nil || created.Access.RevokedAt != nil {
		t.Fatalf("unexpected expiry/revocation: %+v", created.Access)
	}

	views, err := service.ListAccessTokens(ctx, credential)
	if err != nil {
		t.Fatalf("list access tokens: %v", err)
	}
	if len(views) != 1 || views[0].ID != created.Access.ID {
		t.Fatalf("unexpected token list: %+v", views)
	}

	invited, err := service.Resolve(ctx, credential.RoomID, created.Token, "peer-2")
	if err != nil {
		t.Fatalf("resolve invite: %v", err)
	}
	if invited.Role != RoleEditor {
		t.Fatalf("invite role = %q, want EDITOR", invited.Role)
	}
	if _, err := service.ListAccessTokens(ctx,
		RoomCredential{RoomID: credential.RoomID, RoomToken: created.Token, PeerID: "peer-2"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-owner list: err = %v, want forbidden", err)
	}
	if _, err := service.CreateAccessToken(ctx, CreateAccessTokenRequest{
		RoomID: credential.RoomID, RoomToken: credential.RoomToken, Role: "owner",
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("owner invite role: err = %v, want validation", err)
	}

	revoked, err := service.RevokeAccessToken(ctx, created.Access.ID, credential)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.RevokedAt == nil {
		t.Fatal("revokedAt must be set after revoke")
	}
	if _, err := service.Resolve(ctx, credential.RoomID, created.Token, "peer-2"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("resolve revoked token: err = %v, want forbidden", err)
	}
	if _, err := service.RevokeAccessToken(ctx, created.Access.ID+1, credential); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke unknown token: err = %v, want not found", err)
	}
}

func TestRoomAccessTokenExpiryWindow(t *testing.T) {
	service := newRoomService(t, config.PublicTransferConfig{})
	ctx := context.Background()
	credential := ownerCredential("room-a", "owner-token")

	tooShort := int64(10)
	if _, err := service.CreateAccessToken(ctx, CreateAccessTokenRequest{
		RoomID: credential.RoomID, RoomToken: credential.RoomToken, Role: "viewer",
		ExpiresInSeconds: &tooShort,
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("short ttl: err = %v, want validation", err)
	}
	ttl := int64(300)
	created, err := service.CreateAccessToken(ctx, CreateAccessTokenRequest{
		RoomID: credential.RoomID, RoomToken: credential.RoomToken, Role: "viewer",
		ExpiresInSeconds: &ttl,
	})
	if err != nil {
		t.Fatalf("create expiring token: %v", err)
	}
	if created.Access.ExpiresAt == nil {
		t.Fatal("expiresAt must be set for a ttl-bound token")
	}
}

func TestRoomPairingCodeRedeemFlow(t *testing.T) {
	service := newRoomService(t, config.PublicTransferConfig{PairingCodeTtlSeconds: 300})
	ctx := context.Background()
	credential := ownerCredential("room-a", "owner-token")

	maxUses := 2
	pairing, err := service.CreatePairingCode(ctx, CreatePairingCodeRequest{
		RoomID: credential.RoomID, RoomToken: credential.RoomToken, PeerID: credential.PeerID,
		Role: "viewer", MaxUses: &maxUses,
	})
	if err != nil {
		t.Fatalf("create pairing code: %v", err)
	}
	if len(pairing.Code) != 8 {
		t.Fatalf("pairing code = %q, want 8 digits", pairing.Code)
	}
	if pairing.Role != RoleViewer || pairing.MaxUses != 2 || pairing.UsedCount != 0 ||
		pairing.Label != "访客配对" || pairing.ExpiresAt == "" {
		t.Fatalf("unexpected pairing response: %+v", pairing)
	}

	var redeemed RedeemPairingCodeResponse
	for attempt := 0; attempt < 2; attempt++ {
		redeemed, err = service.RedeemPairingCode(ctx, RedeemPairingCodeRequest{Code: pairing.Code, PeerID: "peer-9"})
		if err != nil {
			t.Fatalf("redeem attempt %d: %v", attempt, err)
		}
	}
	if redeemed.RoomID != "room-a" || redeemed.Role != RoleViewer ||
		!strings.HasPrefix(redeemed.RoomToken, "st-viewer-") || redeemed.ExpiresAt == "" {
		t.Fatalf("unexpected redeem response: %+v", redeemed)
	}
	if _, err := service.RedeemPairingCode(ctx,
		RedeemPairingCodeRequest{Code: pairing.Code}); !errors.Is(err, ErrValidation) {
		t.Fatalf("third redeem: err = %v, want validation (exhausted)", err)
	}
	if _, err := service.RedeemPairingCode(ctx,
		RedeemPairingCodeRequest{Code: "12345"}); !errors.Is(err, ErrValidation) {
		t.Fatalf("malformed code: err = %v, want validation", err)
	}

	access, err := service.Resolve(ctx, "room-a", redeemed.RoomToken, "peer-9")
	if err != nil {
		t.Fatalf("resolve redeemed token: %v", err)
	}
	if access.Role != RoleViewer {
		t.Fatalf("redeemed role = %q, want VIEWER", access.Role)
	}

	overLimit := 6
	if _, err := service.CreatePairingCode(ctx, CreatePairingCodeRequest{
		RoomID: credential.RoomID, RoomToken: credential.RoomToken, Role: "editor", MaxUses: &overLimit,
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("maxUses 6: err = %v, want validation", err)
	}
}

func TestRoomPairingRedeemRateLimit(t *testing.T) {
	service := newRoomService(t, config.PublicTransferConfig{
		PairingCodeRedeemRateLimitPerIP:         2,
		PairingCodeRedeemRateLimitWindowSeconds: 300,
	})
	ctx := context.Background()
	for attempt := 0; attempt < 2; attempt++ {
		if err := service.CheckPairingCodeRedeem(ctx, "203.0.113.7"); err != nil {
			t.Fatalf("attempt %d unexpectedly limited: %v", attempt, err)
		}
	}
	if err := service.CheckPairingCodeRedeem(ctx, "203.0.113.7"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("third attempt: err = %v, want rate limited", err)
	}
	if err := service.CheckPairingCodeRedeem(ctx, "203.0.113.8"); err != nil {
		t.Fatalf("distinct source unexpectedly limited: %v", err)
	}
}

func TestRoomDiagramVersions(t *testing.T) {
	service := newRoomService(t, config.PublicTransferConfig{})
	ctx := context.Background()
	credential := ownerCredential("room-a", "owner-token")

	viewer, err := service.CreateAccessToken(ctx, CreateAccessTokenRequest{
		RoomID: credential.RoomID, RoomToken: credential.RoomToken, Role: "viewer",
	})
	if err != nil {
		t.Fatalf("create viewer token: %v", err)
	}
	viewerCredential := RoomCredential{RoomID: "room-a", RoomToken: viewer.Token, PeerID: "peer-viewer"}

	created, err := service.CreateVersion(ctx, CreateDiagramVersionRequest{
		RoomID: credential.RoomID, RoomToken: credential.RoomToken, PeerID: credential.PeerID,
		Name: "版本一", Update: base64.StdEncoding.EncodeToString([]byte("payload-1")),
	})
	if err != nil {
		t.Fatalf("create version: %v", err)
	}
	if created.Name != "版本一" || created.SizeBytes != int64(len("payload-1")) ||
		created.AuthorPeerID != "peer-owner" {
		t.Fatalf("unexpected version view: %+v", created)
	}
	if _, err := service.CreateVersion(ctx, CreateDiagramVersionRequest{
		RoomID: viewerCredential.RoomID, RoomToken: viewerCredential.RoomToken, PeerID: viewerCredential.PeerID,
		Name: "访客版本", Update: base64.StdEncoding.EncodeToString([]byte("payload-2")),
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer create: err = %v, want forbidden", err)
	}

	views, err := service.ListVersions(ctx, viewerCredential)
	if err != nil {
		t.Fatalf("list versions: %v", err)
	}
	if len(views) != 1 || views[0].ID != created.ID {
		t.Fatalf("unexpected version list: %+v", views)
	}
	detail, err := service.GetVersion(ctx, created.ID, viewerCredential)
	if err != nil {
		t.Fatalf("get version: %v", err)
	}
	if detail.Update != base64.StdEncoding.EncodeToString([]byte("payload-1")) {
		t.Fatalf("unexpected snapshot payload: %q", detail.Update)
	}
	if err := service.DeleteVersion(ctx, created.ID, viewerCredential); !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer delete: err = %v, want forbidden", err)
	}
	if err := service.DeleteVersion(ctx, created.ID, credential); err != nil {
		t.Fatalf("owner delete: %v", err)
	}
	if _, err := service.GetVersion(ctx, created.ID, credential); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get deleted version: err = %v, want not found", err)
	}
	if _, err := service.CreateVersion(ctx, CreateDiagramVersionRequest{
		RoomID: credential.RoomID, RoomToken: credential.RoomToken, Name: "bad", Update: "not-base64!!",
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid base64: err = %v, want validation", err)
	}
}

func TestRoomDiagramVersionPruningKeepsNewestFifty(t *testing.T) {
	service := newRoomService(t, config.PublicTransferConfig{})
	ctx := context.Background()
	credential := ownerCredential("room-a", "owner-token")
	for index := 0; index < maxVersionsPerRoom+5; index++ {
		if _, err := service.CreateVersion(ctx, CreateDiagramVersionRequest{
			RoomID: credential.RoomID, RoomToken: credential.RoomToken,
			Name:   "v" + strings.Repeat("x", index%3),
			Update: base64.StdEncoding.EncodeToString([]byte{byte(index)}),
		}); err != nil {
			t.Fatalf("create version %d: %v", index, err)
		}
	}
	views, err := service.ListVersions(ctx, credential)
	if err != nil {
		t.Fatalf("list versions: %v", err)
	}
	if len(views) != maxVersionsPerRoom {
		t.Fatalf("versions = %d, want %d after pruning", len(views), maxVersionsPerRoom)
	}
}
