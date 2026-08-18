package transfer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// Public-transfer room service, aligned with the Java PublicTransferRoomService (S-3).
const (
	maxRoomSnapshotBytes         = 3 * 1024 * 1024
	maxVersionsPerRoom           = 50
	maxAccessTokensPerRoom       = 20
	minAccessTokenTTLSeconds     = 300
	maxAccessTokenTTLSeconds     = 7 * 24 * 60 * 60
	pairingAccessTokenTTLSeconds = 24 * 60 * 60
	maxPairingCodeUses           = 5
	maxPairingCodeGenAttempts    = 16
	pairingRedeemRateLimitBucket = "pairing-code-redeem"
)

// roomISOLayout matches store.formatTime so stored timestamps and comparisons stay compatible.
const roomISOLayout = "2006-01-02T15:04:05.0000000Z"

var (
	ErrValidation = errors.New("validation")
	ErrNotFound   = errors.New("not found")
)

func validation(message string) error {
	return &categorizedError{category: ErrValidation, message: message}
}

func notFound(message string) error {
	return &categorizedError{category: ErrNotFound, message: message}
}

// Role mirrors the Java PublicTransferRoomService.Role enum.
type Role string

const (
	RoleOwner  Role = "OWNER"
	RoleEditor Role = "EDITOR"
	RoleViewer Role = "VIEWER"
)

func (r Role) CanEdit() bool { return r == RoleOwner || r == RoleEditor }

type RoomAccess struct {
	RoomID   int64
	Role     Role
	RoomName string
}

type RoomCredential struct {
	RoomID    string `json:"roomId"`
	RoomToken string `json:"roomToken"`
	PeerID    string `json:"peerId"`
}

type CreateAccessTokenRequest struct {
	RoomID           string `json:"roomId"`
	RoomToken        string `json:"roomToken"`
	PeerID           string `json:"peerId"`
	Role             string `json:"role"`
	Label            string `json:"label"`
	ExpiresInSeconds *int64 `json:"expiresInSeconds"`
}

func (r CreateAccessTokenRequest) Credential() RoomCredential {
	return RoomCredential{RoomID: r.RoomID, RoomToken: r.RoomToken, PeerID: r.PeerID}
}

type AccessTokenView struct {
	ID        int64   `json:"id"`
	Role      Role    `json:"role"`
	Label     string  `json:"label"`
	CreatedAt string  `json:"createdAt"`
	ExpiresAt *string `json:"expiresAt"`
	RevokedAt *string `json:"revokedAt"`
}

type CreatedAccessToken struct {
	Access AccessTokenView `json:"access"`
	Token  string          `json:"token"`
}

type CreatePairingCodeRequest struct {
	RoomID    string `json:"roomId"`
	RoomToken string `json:"roomToken"`
	PeerID    string `json:"peerId"`
	Role      string `json:"role"`
	Label     string `json:"label"`
	MaxUses   *int   `json:"maxUses"`
}

func (r CreatePairingCodeRequest) Credential() RoomCredential {
	return RoomCredential{RoomID: r.RoomID, RoomToken: r.RoomToken, PeerID: r.PeerID}
}

type CreatePairingCodeResponse struct {
	ID        int64  `json:"id"`
	Code      string `json:"code"`
	Role      Role   `json:"role"`
	Label     string `json:"label"`
	CreatedAt string `json:"createdAt"`
	ExpiresAt string `json:"expiresAt"`
	MaxUses   int    `json:"maxUses"`
	UsedCount int    `json:"usedCount"`
}

type RedeemPairingCodeRequest struct {
	Code   string `json:"code"`
	PeerID string `json:"peerId"`
}

type RedeemPairingCodeResponse struct {
	RoomID    string `json:"roomId"`
	Role      Role   `json:"role"`
	RoomToken string `json:"roomToken"`
	ExpiresAt string `json:"expiresAt"`
}

type CreateDiagramVersionRequest struct {
	RoomID    string `json:"roomId"`
	RoomToken string `json:"roomToken"`
	PeerID    string `json:"peerId"`
	Name      string `json:"name"`
	Update    string `json:"update"`
}

func (r CreateDiagramVersionRequest) Credential() RoomCredential {
	return RoomCredential{RoomID: r.RoomID, RoomToken: r.RoomToken, PeerID: r.PeerID}
}

type DiagramVersionView struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	AuthorPeerID string `json:"authorPeerId"`
	SizeBytes    int64  `json:"sizeBytes"`
	CreatedAt    string `json:"createdAt"`
}

type DiagramVersionDetail struct {
	Version DiagramVersionView `json:"version"`
	Update  string             `json:"update"`
}

// RoomService implements the public-transfer room access-token, pairing-code, and diagram
// version flows. Aligned with the Java PublicTransferRoomService.
type RoomService struct {
	db                *store.DB
	publicCfg         config.PublicTransferConfig
	tokens            *security.LocalTokenService
	sharedRateLimiter SharedRateLimiter
	redeemMu          sync.Mutex
	redeemWindows     map[string]rateWindow
}

func NewRoomService(db *store.DB, publicCfg config.PublicTransferConfig,
	tokens *security.LocalTokenService, sharedRateLimiter ...SharedRateLimiter) *RoomService {
	service := &RoomService{db: db, publicCfg: publicCfg, tokens: tokens,
		redeemWindows: make(map[string]rateWindow)}
	if len(sharedRateLimiter) > 0 {
		service.sharedRateLimiter = sharedRateLimiter[0]
	}
	return service
}

// Resolve authenticates a room credential, creating the owner room on first use (aligned with
// the Java resolve()).
func (s *RoomService) Resolve(ctx context.Context, roomNameValue, tokenValue, peerIDValue string) (RoomAccess, error) {
	roomName, err := roomRequireText(roomNameValue, "roomId", 120)
	if err != nil {
		return RoomAccess{}, err
	}
	token, err := roomRequireText(tokenValue, "roomToken", 512)
	if err != nil {
		return RoomAccess{}, err
	}
	peerID, err := roomNormalizeText(peerIDValue, "web", 120)
	if err != nil {
		return RoomAccess{}, err
	}
	hash := tokenHash(token)
	access, found, err := s.resolveStoredCredential(ctx, roomName, hash)
	if err != nil {
		return RoomAccess{}, err
	}
	if found {
		return access, nil
	}
	if isInviteToken(token) {
		return RoomAccess{}, forbidden("房间凭证无效")
	}

	roomID, err := s.newUniqueID(ctx, s.db.PublicTransferRoomExists)
	if err != nil {
		return RoomAccess{}, err
	}
	now := time.Now().UTC()
	room := store.PublicTransferRoom{
		ID: roomID, RoomName: roomName, OwnerTokenHash: hash, CreatedByPeerID: peerID,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.db.InsertPublicTransferRoom(ctx, room); err != nil {
		// Unique-key race with a concurrent owner login: fall back to the existing row.
		existing, lookupErr := s.db.GetPublicTransferRoomByNameAndOwnerTokenHash(ctx, roomName, hash)
		if lookupErr == nil && existing != nil {
			return RoomAccess{RoomID: existing.ID, Role: RoleOwner, RoomName: roomName}, nil
		}
		return RoomAccess{}, internalError(err)
	}
	return RoomAccess{RoomID: room.ID, Role: RoleOwner, RoomName: roomName}, nil
}

// ResolveExisting authenticates an existing owner or invitation without creating an owner room.
// Existing attachments must use this path so a typo or hostile token cannot leave shadow rooms as
// a side effect of a completion or download authorization check.
func (s *RoomService) ResolveExisting(ctx context.Context, roomNameValue, tokenValue,
	peerIDValue string) (RoomAccess, error) {
	roomName, err := roomRequireText(roomNameValue, "roomId", 120)
	if err != nil {
		return RoomAccess{}, err
	}
	token, err := roomRequireText(tokenValue, "roomToken", 512)
	if err != nil {
		return RoomAccess{}, err
	}
	if _, err := roomNormalizeText(peerIDValue, "web", 120); err != nil {
		return RoomAccess{}, err
	}
	access, found, err := s.resolveStoredCredential(ctx, roomName, tokenHash(token))
	if err != nil {
		return RoomAccess{}, err
	}
	if !found {
		return RoomAccess{}, forbidden("房间凭证无效")
	}
	return access, nil
}

func (s *RoomService) resolveStoredCredential(ctx context.Context, roomName,
	hash string) (RoomAccess, bool, error) {

	ownerRoom, err := s.db.GetPublicTransferRoomByNameAndOwnerTokenHash(ctx, roomName, hash)
	if err != nil {
		return RoomAccess{}, false, internalError(err)
	}
	if ownerRoom != nil {
		return RoomAccess{RoomID: ownerRoom.ID, Role: RoleOwner, RoomName: roomName}, true, nil
	}
	invited, err := s.db.GetPublicTransferRoomAccessByTokenHash(ctx, hash)
	if err != nil {
		return RoomAccess{}, false, internalError(err)
	}
	if invited != nil {
		access, err := s.requireUsableInvite(ctx, roomName, invited)
		return access, true, err
	}
	return RoomAccess{}, false, nil
}

// CheckPairingCodeRedeem enforces the per-IP fixed-window limit for pairing-code redemption
// (aligned with the Java PublicTransferRateLimiter.checkPairingCodeRedeem).
func (s *RoomService) CheckPairingCodeRedeem(ctx context.Context, ip string) error {
	limit := s.publicCfg.PairingCodeRedeemRateLimitPerIP
	if limit < 1 {
		limit = 1
	}
	windowDuration := time.Duration(s.publicCfg.PairingCodeRedeemRateLimitWindowSeconds) * time.Second
	if windowDuration <= 0 {
		windowDuration = time.Second
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		ip = "unknown"
	}
	if s.publicCfg.ClusterEnabled {
		if s.sharedRateLimiter == nil {
			return rateLimited("服务暂时不可用,请稍后再试")
		}
		allowed, err := s.sharedRateLimiter.AllowRate(ctx, pairingRedeemRateLimitBucket, ip, limit, windowDuration)
		if err != nil {
			return rateLimited("服务暂时不可用,请稍后再试")
		}
		if !allowed {
			return rateLimited("请求过于频繁,请稍后再试")
		}
		return nil
	}
	now := time.Now()
	s.redeemMu.Lock()
	defer s.redeemMu.Unlock()
	if _, exists := s.redeemWindows[ip]; !exists && len(s.redeemWindows) >= maxTrackedRateSources {
		return rateLimited("请求过于频繁,请稍后再试")
	}
	window := s.redeemWindows[ip]
	if window.started.IsZero() || now.Sub(window.started) >= windowDuration {
		window = rateWindow{started: now}
	}
	window.count++
	s.redeemWindows[ip] = window
	if window.count > limit {
		return rateLimited("请求过于频繁,请稍后再试")
	}
	return nil
}

func (s *RoomService) ListAccessTokens(ctx context.Context, credential RoomCredential) ([]AccessTokenView, error) {
	owner, err := s.requireRole(ctx, credential, RoleOwner)
	if err != nil {
		return nil, err
	}
	items, err := s.db.ListPublicTransferRoomAccessByRoom(ctx, owner.RoomID)
	if err != nil {
		return nil, internalError(err)
	}
	views := make([]AccessTokenView, 0, len(items))
	for _, item := range items {
		views = append(views, accessTokenView(item))
	}
	return views, nil
}

func (s *RoomService) CreateAccessToken(ctx context.Context,
	request CreateAccessTokenRequest) (CreatedAccessToken, error) {
	owner, err := s.requireRole(ctx, request.Credential(), RoleOwner)
	if err != nil {
		return CreatedAccessToken{}, err
	}
	role, err := parseInviteRole(request.Role)
	if err != nil {
		return CreatedAccessToken{}, err
	}
	room, err := s.db.GetPublicTransferRoomByID(ctx, owner.RoomID)
	if err != nil {
		return CreatedAccessToken{}, internalError(err)
	}
	if room == nil {
		return CreatedAccessToken{}, notFound("房间不存在")
	}
	if err := s.requireAccessTokenCapacity(ctx, owner.RoomID); err != nil {
		return CreatedAccessToken{}, err
	}
	now := time.Now().UTC()
	expiresAt, err := accessTokenExpiry(request.ExpiresInSeconds, now)
	if err != nil {
		return CreatedAccessToken{}, err
	}
	defaultLabel := "访客邀请"
	if role == RoleEditor {
		defaultLabel = "编辑者邀请"
	}
	label, err := roomNormalizeText(request.Label, defaultLabel, 80)
	if err != nil {
		return CreatedAccessToken{}, err
	}
	return s.issueAccessToken(ctx, *room, role, label, now, expiresAt)
}

func (s *RoomService) RevokeAccessToken(ctx context.Context, accessID int64,
	credential RoomCredential) (AccessTokenView, error) {
	owner, err := s.requireRole(ctx, credential, RoleOwner)
	if err != nil {
		return AccessTokenView{}, err
	}
	access, err := s.db.GetPublicTransferRoomAccessByIDAndRoom(ctx, accessID, owner.RoomID)
	if err != nil {
		return AccessTokenView{}, internalError(err)
	}
	if access == nil {
		return AccessTokenView{}, notFound("邀请 Token 不存在")
	}
	if access.RevokedAt == nil {
		now := time.Now().UTC()
		if err := s.db.RevokePublicTransferRoomAccess(ctx, access.ID, now); err != nil {
			return AccessTokenView{}, internalError(err)
		}
		access.RevokedAt = &now
	}
	return accessTokenView(*access), nil
}

func (s *RoomService) CreatePairingCode(ctx context.Context,
	request CreatePairingCodeRequest) (CreatePairingCodeResponse, error) {
	owner, err := s.requireRole(ctx, request.Credential(), RoleOwner)
	if err != nil {
		return CreatePairingCodeResponse{}, err
	}
	role, err := parseInviteRole(request.Role)
	if err != nil {
		return CreatePairingCodeResponse{}, err
	}
	maxUses, err := normalizePairingCodeUses(request.MaxUses)
	if err != nil {
		return CreatePairingCodeResponse{}, err
	}
	room, err := s.db.GetPublicTransferRoomByID(ctx, owner.RoomID)
	if err != nil {
		return CreatePairingCodeResponse{}, internalError(err)
	}
	if room == nil {
		return CreatePairingCodeResponse{}, notFound("房间不存在")
	}
	defaultLabel := "访客配对"
	if role == RoleEditor {
		defaultLabel = "编辑者配对"
	}
	label, err := roomNormalizeText(request.Label, defaultLabel, 80)
	if err != nil {
		return CreatePairingCodeResponse{}, err
	}
	ttlSeconds := s.publicCfg.PairingCodeTtlSeconds
	if ttlSeconds < 60 {
		ttlSeconds = 60
	}
	if ttlSeconds > 900 {
		ttlSeconds = 900
	}
	plainCode, err := s.newUniquePairingCode(ctx)
	if err != nil {
		return CreatePairingCodeResponse{}, err
	}
	codeID, err := s.newUniqueID(ctx, s.db.PublicTransferPairingCodeExists)
	if err != nil {
		return CreatePairingCodeResponse{}, err
	}
	createdAt := time.Now().UTC()
	pairingCode := store.PublicTransferRoomPairingCode{
		ID: codeID, RoomID: room.ID, CodeHash: s.tokens.PairingCodeHash(plainCode),
		Role: string(role), Label: label, CreatedAt: createdAt,
		ExpiresAt: createdAt.Add(time.Duration(ttlSeconds) * time.Second),
		MaxUses:   maxUses,
	}
	if err := s.db.InsertPublicTransferPairingCode(ctx, pairingCode); err != nil {
		return CreatePairingCodeResponse{}, internalError(err)
	}
	return CreatePairingCodeResponse{
		ID: pairingCode.ID, Code: plainCode, Role: role, Label: pairingCode.Label,
		CreatedAt: roomFormatTime(pairingCode.CreatedAt), ExpiresAt: roomFormatTime(pairingCode.ExpiresAt),
		MaxUses: pairingCode.MaxUses, UsedCount: pairingCode.UsedCount,
	}, nil
}

func (s *RoomService) RedeemPairingCode(ctx context.Context,
	request RedeemPairingCodeRequest) (RedeemPairingCodeResponse, error) {
	if _, err := roomNormalizeText(request.PeerID, "web", 120); err != nil {
		return RedeemPairingCodeResponse{}, err
	}
	plainCode, err := normalizePairingCode(request.Code)
	if err != nil {
		return RedeemPairingCodeResponse{}, err
	}
	codeHash := s.tokens.PairingCodeHash(plainCode)
	now := time.Now().UTC()
	expiresAt := now.Add(pairingAccessTokenTTLSeconds * time.Second)

	// Read the code first to learn its role, then allocate the id and token, and only then open the
	// transaction. Everything the callback needs is precomputed: a query inside the transaction
	// would wait on the write lock the transaction itself holds.
	pending, err := s.db.GetPublicTransferPairingCodeByHash(ctx, codeHash)
	if err != nil {
		return RedeemPairingCodeResponse{}, internalError(err)
	}
	if pending == nil {
		return RedeemPairingCodeResponse{}, invalidPairingCode()
	}
	role, err := parseInviteRole(pending.Role)
	if err != nil {
		return RedeemPairingCodeResponse{}, err
	}
	accessID, err := s.newUniqueID(ctx, s.db.PublicTransferRoomAccessExists)
	if err != nil {
		return RedeemPairingCodeResponse{}, err
	}
	plainToken := newAccessToken(role)

	// Consuming the code and issuing the token must commit together. Consuming first and failing
	// later would permanently burn one use and hand the caller nothing back.
	room, _, _, err := s.db.RedeemPairingCode(ctx, store.RedeemPairingCodeRequest{
		CodeHash:               codeHash,
		Now:                    now,
		MaxAccessTokensPerRoom: maxAccessTokensPerRoom,
		NewAccess: func(room store.PublicTransferRoom,
			code store.PublicTransferRoomPairingCode) (store.PublicTransferRoomAccess, error) {
			// The role is re-checked against the committed row: a code edited between the read and
			// the transaction must not hand out a token for the wrong role.
			if code.Role != string(role) {
				return store.PublicTransferRoomAccess{}, store.ErrPairingCodeUnusable
			}
			return store.PublicTransferRoomAccess{
				ID: accessID, RoomID: room.ID, TokenHash: tokenHash(plainToken),
				Role: string(role), Label: code.Label, CreatedAt: now, ExpiresAt: &expiresAt,
			}, nil
		},
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrPairingCodeUnusable):
			return RedeemPairingCodeResponse{}, invalidPairingCode()
		case errors.Is(err, store.ErrAccessTokenCapacity):
			return RedeemPairingCodeResponse{}, conflict("房间有效邀请 Token 已达到 20 个上限")
		case errors.Is(err, ErrValidation), errors.Is(err, ErrConflict):
			return RedeemPairingCodeResponse{}, err
		default:
			return RedeemPairingCodeResponse{}, internalError(err)
		}
	}
	return RedeemPairingCodeResponse{
		RoomID: room.RoomName, Role: role, RoomToken: plainToken,
		ExpiresAt: roomFormatTime(expiresAt),
	}, nil
}

func (s *RoomService) ListVersions(ctx context.Context,
	credential RoomCredential) ([]DiagramVersionView, error) {
	access, err := s.Resolve(ctx, credential.RoomID, credential.RoomToken, credential.PeerID)
	if err != nil {
		return nil, err
	}
	versions, err := s.db.ListPublicTransferDiagramVersionsByRoom(ctx, access.RoomID)
	if err != nil {
		return nil, internalError(err)
	}
	views := make([]DiagramVersionView, 0, len(versions))
	for _, version := range versions {
		views = append(views, diagramVersionView(version))
	}
	return views, nil
}

func (s *RoomService) CreateVersion(ctx context.Context,
	request CreateDiagramVersionRequest) (DiagramVersionView, error) {
	access, err := s.Resolve(ctx, request.RoomID, request.RoomToken, request.PeerID)
	if err != nil {
		return DiagramVersionView{}, err
	}
	if !access.Role.CanEdit() {
		return DiagramVersionView{}, forbidden("访客不能创建流程图版本")
	}
	snapshot, err := decodeVersionSnapshot(request.Update)
	if err != nil {
		return DiagramVersionView{}, err
	}
	room, err := s.db.GetPublicTransferRoomByID(ctx, access.RoomID)
	if err != nil {
		return DiagramVersionView{}, internalError(err)
	}
	if room == nil {
		return DiagramVersionView{}, notFound("房间不存在")
	}
	name, err := roomRequireText(request.Name, "name", 80)
	if err != nil {
		return DiagramVersionView{}, err
	}
	authorPeerID, err := roomNormalizeText(request.PeerID, "web", 120)
	if err != nil {
		return DiagramVersionView{}, err
	}
	versionID, err := s.newUniqueID(ctx, s.db.PublicTransferDiagramVersionExists)
	if err != nil {
		return DiagramVersionView{}, err
	}
	version := store.PublicTransferDiagramVersion{
		ID: versionID, RoomID: room.ID, Name: name, AuthorPeerID: authorPeerID,
		SnapshotData: snapshot, SizeBytes: int64(len(snapshot)), CreatedAt: time.Now().UTC(),
	}
	if err := s.db.InsertPublicTransferDiagramVersion(ctx, version); err != nil {
		return DiagramVersionView{}, internalError(err)
	}
	versions, err := s.db.ListPublicTransferDiagramVersionsByRoom(ctx, access.RoomID)
	if err != nil {
		return DiagramVersionView{}, internalError(err)
	}
	for _, stale := range versions[min(len(versions), maxVersionsPerRoom):] {
		if err := s.db.DeletePublicTransferDiagramVersion(ctx, stale.ID); err != nil {
			return DiagramVersionView{}, internalError(err)
		}
	}
	return diagramVersionView(version), nil
}

func (s *RoomService) GetVersion(ctx context.Context, versionID int64,
	credential RoomCredential) (DiagramVersionDetail, error) {
	access, err := s.Resolve(ctx, credential.RoomID, credential.RoomToken, credential.PeerID)
	if err != nil {
		return DiagramVersionDetail{}, err
	}
	version, err := s.db.GetPublicTransferDiagramVersion(ctx, versionID, access.RoomID)
	if err != nil {
		return DiagramVersionDetail{}, internalError(err)
	}
	if version == nil {
		return DiagramVersionDetail{}, notFound("流程图版本不存在")
	}
	return DiagramVersionDetail{
		Version: diagramVersionView(*version),
		Update:  base64.StdEncoding.EncodeToString(version.SnapshotData),
	}, nil
}

func (s *RoomService) DeleteVersion(ctx context.Context, versionID int64,
	credential RoomCredential) error {
	owner, err := s.requireRole(ctx, credential, RoleOwner)
	if err != nil {
		return err
	}
	version, err := s.db.GetPublicTransferDiagramVersion(ctx, versionID, owner.RoomID)
	if err != nil {
		return internalError(err)
	}
	if version == nil {
		return notFound("流程图版本不存在")
	}
	return internalError(s.db.DeletePublicTransferDiagramVersion(ctx, version.ID))
}

func (s *RoomService) requireRole(ctx context.Context, credential RoomCredential,
	required Role) (RoomAccess, error) {
	access, err := s.Resolve(ctx, credential.RoomID, credential.RoomToken, credential.PeerID)
	if err != nil {
		return RoomAccess{}, err
	}
	if access.Role != required {
		return RoomAccess{}, forbidden("需要房主权限")
	}
	return access, nil
}

func (s *RoomService) requireUsableInvite(ctx context.Context, roomName string,
	access *store.PublicTransferRoomAccess) (RoomAccess, error) {
	room, err := s.db.GetPublicTransferRoomByID(ctx, access.RoomID)
	if err != nil {
		return RoomAccess{}, internalError(err)
	}
	// Keep all known-but-unusable invite states indistinguishable and, critically, prevent
	// Resolve from falling through to legacy owner-room creation.
	if room == nil || room.RoomName != roomName || !isUsableAccess(access, time.Now().UTC()) {
		return RoomAccess{}, forbidden("房间凭证无效")
	}
	role := Role(access.Role)
	if role != RoleEditor && role != RoleViewer {
		return RoomAccess{}, forbidden("房间凭证无效")
	}
	return RoomAccess{RoomID: room.ID, Role: role, RoomName: roomName}, nil
}

func (s *RoomService) requireAccessTokenCapacity(ctx context.Context, roomID int64) error {
	items, err := s.db.ListPublicTransferRoomAccessByRoom(ctx, roomID)
	if err != nil {
		return internalError(err)
	}
	now := time.Now().UTC()
	active := 0
	for i := range items {
		if isUsableAccess(&items[i], now) {
			active++
		}
	}
	if active >= maxAccessTokensPerRoom {
		return conflict("房间有效邀请 Token 已达到 20 个上限")
	}
	return nil
}

func isUsableAccess(access *store.PublicTransferRoomAccess, now time.Time) bool {
	if access.RevokedAt != nil {
		return false
	}
	if access.ExpiresAt == nil {
		return true
	}
	return access.ExpiresAt.After(now)
}

func accessTokenExpiry(expiresInSeconds *int64, now time.Time) (*time.Time, error) {
	if expiresInSeconds == nil {
		return nil, nil
	}
	if *expiresInSeconds < minAccessTokenTTLSeconds || *expiresInSeconds > maxAccessTokenTTLSeconds {
		return nil, validation("邀请有效期必须在 300 到 604800 秒之间")
	}
	expiresAt := now.Add(time.Duration(*expiresInSeconds) * time.Second)
	return &expiresAt, nil
}

func (s *RoomService) issueAccessToken(ctx context.Context, room store.PublicTransferRoom,
	role Role, label string, createdAt time.Time, expiresAt *time.Time) (CreatedAccessToken, error) {
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		plainToken := newAccessToken(role)
		accessID, err := s.newUniqueID(ctx, s.db.PublicTransferRoomAccessExists)
		if err != nil {
			return CreatedAccessToken{}, err
		}
		access := store.PublicTransferRoomAccess{
			ID: accessID, RoomID: room.ID, TokenHash: tokenHash(plainToken),
			Role: string(role), Label: label, CreatedAt: createdAt, ExpiresAt: expiresAt,
		}
		if err := s.db.InsertPublicTransferRoomAccess(ctx, access); err != nil {
			lastErr = err
			continue
		}
		return CreatedAccessToken{Access: accessTokenView(access), Token: plainToken}, nil
	}
	if lastErr != nil {
		return CreatedAccessToken{}, internalError(lastErr)
	}
	return CreatedAccessToken{}, conflict("无法生成邀请 Token")
}

func newAccessToken(role Role) string {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		panic("transfer: secure random source unavailable: " + err.Error())
	}
	return "st-" + strings.ToLower(string(role)) + "-" + base64.RawURLEncoding.EncodeToString(random)
}

func isInviteToken(token string) bool {
	return strings.HasPrefix(token, "st-editor-") || strings.HasPrefix(token, "st-viewer-")
}

func parseInviteRole(value string) (Role, error) {
	normalized, err := roomNormalizeText(value, "", 16)
	if err == nil {
		switch Role(strings.ToUpper(normalized)) {
		case RoleEditor:
			return RoleEditor, nil
		case RoleViewer:
			return RoleViewer, nil
		}
	}
	return "", validation("邀请角色必须是 EDITOR 或 VIEWER")
}

func normalizePairingCodeUses(value *int) (int, error) {
	normalized := 1
	if value != nil {
		normalized = *value
	}
	if normalized < 1 || normalized > maxPairingCodeUses {
		return 0, validation("配对码可用次数必须在 1 到 5 之间")
	}
	return normalized, nil
}

func normalizePairingCode(value string) (string, error) {
	code := strings.TrimSpace(value)
	if len(code) != 8 {
		return "", invalidPairingCode()
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return "", invalidPairingCode()
		}
	}
	return code, nil
}

func (s *RoomService) newUniquePairingCode(ctx context.Context) (string, error) {
	for attempt := 0; attempt < maxPairingCodeGenAttempts; attempt++ {
		n, err := rand.Int(rand.Reader, big.NewInt(100_000_000))
		if err != nil {
			return "", internalError(err)
		}
		code := fmt.Sprintf("%08d", n.Int64())
		exists, err := s.db.PublicTransferPairingCodeHashExists(ctx, s.tokens.PairingCodeHash(code))
		if err != nil {
			return "", internalError(err)
		}
		if !exists {
			return code, nil
		}
	}
	return "", conflict("无法生成唯一配对码")
}

func invalidPairingCode() error {
	return validation("配对码无效或已过期")
}

func decodeVersionSnapshot(encoded string) ([]byte, error) {
	if strings.TrimSpace(encoded) == "" || len(encoded) > 4*1024*1024+16 {
		return nil, validation("流程图版本数据无效或超过限制")
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, validation("流程图版本数据不是有效的 Base64")
	}
	if len(decoded) == 0 || len(decoded) > maxRoomSnapshotBytes {
		return nil, validation("流程图版本数据无效或超过 3 MB")
	}
	return decoded, nil
}

func accessTokenView(access store.PublicTransferRoomAccess) AccessTokenView {
	return AccessTokenView{
		ID: access.ID, Role: Role(access.Role), Label: access.Label,
		CreatedAt: roomFormatTime(access.CreatedAt),
		ExpiresAt: roomFormatTimePtr(access.ExpiresAt), RevokedAt: roomFormatTimePtr(access.RevokedAt),
	}
}

func diagramVersionView(version store.PublicTransferDiagramVersion) DiagramVersionView {
	return DiagramVersionView{
		ID: version.ID, Name: version.Name, AuthorPeerID: version.AuthorPeerID,
		SizeBytes: version.SizeBytes, CreatedAt: roomFormatTime(version.CreatedAt),
	}
}

func (s *RoomService) newUniqueID(ctx context.Context,
	exists func(context.Context, int64) (bool, error)) (int64, error) {
	for attempt := 0; attempt < 8; attempt++ {
		id := auth.NewClientID()
		taken, err := exists(ctx, id)
		if err != nil {
			return 0, internalError(err)
		}
		if !taken {
			return id, nil
		}
	}
	return 0, conflict("无法生成唯一 ID")
}

func roomFormatTime(value time.Time) string { return value.UTC().Format(roomISOLayout) }

func roomFormatTimePtr(value *time.Time) *string {
	if value == nil {
		return nil
	}
	formatted := roomFormatTime(*value)
	return &formatted
}

func roomRequireText(value, field string, maxLength int) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", validation(field + " 不能为空")
	}
	return roomNormalizeText(value, "", maxLength)
}

func roomNormalizeText(value, fallback string, maxLength int) (string, error) {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		normalized = fallback
	}
	if utf16Length(normalized) > maxLength {
		return "", validation("字段长度不能超过 " + strconv.Itoa(maxLength))
	}
	if strings.ContainsAny(normalized, "\r\n") {
		return "", validation("字段不能包含换行")
	}
	return normalized, nil
}
