package transfer

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// newRoomBoundAttachmentService wires the attachment service to the persistent room subsystem the
// same way the server does, so these cases exercise the real authorization path.
func newRoomBoundAttachmentService(t *testing.T,
	publicCfg config.PublicTransferConfig) (*Service, *RoomService, *store.DB) {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "attachments.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	objectCfg := config.ObjectStorageConfig{
		Provider: "aliyun-oss", Endpoint: "https://oss.example.com", Region: "cn-hangzhou",
		Bucket: "private", AccessKeyID: "key", AccessKeySecret: "secret",
		ObjectPrefix: "specus/attachments", UploadURLTTLSeconds: 900,
		DownloadURLTTLSeconds: 600, RetentionHours: 72, MaxAttachmentBytes: 4096,
	}
	rooms := NewRoomService(db, publicCfg,
		security.NewLocalTokenService(config.AuthConfig{JwtSecret: "attachment-room-test-secret"}))
	service := NewService(db, objectCfg, publicCfg)
	service.SetRoomService(rooms)
	return service, rooms, db
}

func uploadRequest(fileName, roomToken string) PresignUploadRequest {
	size := int64(16)
	return PresignUploadRequest{RoomID: "room-att", RoomToken: roomToken, FileName: fileName,
		MimeType: "text/plain", SizeBytes: &size}
}

func inviteToken(t *testing.T, rooms *RoomService, ownerToken, role string) string {
	t.Helper()
	created, err := rooms.CreateAccessToken(context.Background(), CreateAccessTokenRequest{
		RoomID: "room-att", RoomToken: ownerToken, PeerID: "peer-owner", Role: role,
	})
	if err != nil {
		t.Fatalf("create %s invite: %v", role, err)
	}
	return created.Token
}

func TestPublicUploadRequiresEditorRole(t *testing.T) {
	service, rooms, _ := newRoomBoundAttachmentService(t,
		config.PublicTransferConfig{MaxPendingUploadsPerRoom: 8})
	ctx := context.Background()
	const ownerToken = "owner-token"
	if _, err := rooms.Resolve(ctx, "room-att", ownerToken, "peer-owner"); err != nil {
		t.Fatalf("create owner room: %v", err)
	}

	// OWNER and EDITOR may upload.
	if _, err := service.CreatePublicUpload(ctx, "tenant-a", "alice",
		uploadRequest("owner.txt", ownerToken)); err != nil {
		t.Fatalf("owner upload: %v", err)
	}
	editorToken := inviteToken(t, rooms, ownerToken, "editor")
	if _, err := service.CreatePublicUpload(ctx, "tenant-a", "alice",
		uploadRequest("editor.txt", editorToken)); err != nil {
		t.Fatalf("editor upload: %v", err)
	}

	// VIEWER may not.
	viewerToken := inviteToken(t, rooms, ownerToken, "viewer")
	_, err := service.CreatePublicUpload(ctx, "tenant-a", "alice",
		uploadRequest("viewer.txt", viewerToken))
	if err == nil {
		t.Fatal("viewer upload should be rejected")
	}
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer upload err = %v, want forbidden", err)
	}
}

func TestPublicUploadBindsAttachmentToPersistentRoom(t *testing.T) {
	service, rooms, db := newRoomBoundAttachmentService(t, config.PublicTransferConfig{})
	ctx := context.Background()
	const ownerToken = "owner-token"
	access, err := rooms.Resolve(ctx, "room-att", ownerToken, "peer-owner")
	if err != nil {
		t.Fatalf("create owner room: %v", err)
	}

	response, err := service.CreatePublicUpload(ctx, "tenant-a", "alice",
		uploadRequest("a.txt", ownerToken))
	if err != nil {
		t.Fatalf("owner upload: %v", err)
	}
	item, err := db.GetTransferAttachment(ctx, response.AttachmentID, ScopePublicTransfer)
	if err != nil || item == nil {
		t.Fatalf("load attachment: %v", err)
	}
	if item.PublicTransferRoomID == nil || *item.PublicTransferRoomID != access.RoomID {
		t.Fatalf("publicTransferRoomId = %v, want %d", item.PublicTransferRoomID, access.RoomID)
	}
}

func TestPublicAttachmentAccessFollowsRoomMembershipNotOneToken(t *testing.T) {
	service, rooms, _ := newRoomBoundAttachmentService(t,
		config.PublicTransferConfig{MaxPendingUploadsPerRoom: 8})
	ctx := context.Background()
	const ownerToken = "owner-token"
	if _, err := rooms.Resolve(ctx, "room-att", ownerToken, "peer-owner"); err != nil {
		t.Fatalf("create owner room: %v", err)
	}
	uploaded, err := service.CreatePublicUpload(ctx, "tenant-a", "alice",
		uploadRequest("a.txt", ownerToken))
	if err != nil {
		t.Fatalf("owner upload: %v", err)
	}

	// A different valid member of the same room passes authorization, even though the attachment
	// was created under the owner token. The upload itself is still pending here, so the request
	// stops at that check rather than at the room gate.
	viewerToken := inviteToken(t, rooms, ownerToken, "viewer")
	_, err = service.CreatePublicDownload(ctx, uploaded.AttachmentID, viewerToken, "tenant-a", "bob")
	if errors.Is(err, ErrForbidden) || errors.Is(err, ErrValidation) {
		t.Fatalf("a room member must pass the room gate, got %v", err)
	}
	// A VIEWER still cannot complete (mutate) it.
	if _, err := service.CompletePublic(ctx, uploaded.AttachmentID, viewerToken,
		"tenant-a", "bob"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer complete err = %v, want forbidden", err)
	}
	// A token for another room is rejected outright.
	if _, err := rooms.Resolve(ctx, "room-other", "other-owner-token", "peer-x"); err != nil {
		t.Fatalf("create other room: %v", err)
	}
	_, err = service.CreatePublicDownload(ctx, uploaded.AttachmentID, "other-owner-token",
		"tenant-a", "mallory")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("a token from another room must be rejected, got %v", err)
	}
}

func TestPublicPendingQuotaCountsPerRoomAcrossTokens(t *testing.T) {
	service, rooms, _ := newRoomBoundAttachmentService(t,
		config.PublicTransferConfig{MaxPendingUploadsPerRoom: 2})
	ctx := context.Background()
	const ownerToken = "owner-token"
	if _, err := rooms.Resolve(ctx, "room-att", ownerToken, "peer-owner"); err != nil {
		t.Fatalf("create owner room: %v", err)
	}
	editorToken := inviteToken(t, rooms, ownerToken, "editor")

	if _, err := service.CreatePublicUpload(ctx, "tenant-a", "alice",
		uploadRequest("one.txt", ownerToken)); err != nil {
		t.Fatalf("first upload: %v", err)
	}
	if _, err := service.CreatePublicUpload(ctx, "tenant-a", "bob",
		uploadRequest("two.txt", editorToken)); err != nil {
		t.Fatalf("second upload: %v", err)
	}
	// The quota belongs to the room, so a second token cannot start a fresh budget.
	_, err := service.CreatePublicUpload(ctx, "tenant-a", "bob",
		uploadRequest("three.txt", editorToken))
	if err == nil {
		t.Fatal("third pending upload should exceed the room quota")
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("quota err = %v, want rate limited", err)
	}
}
