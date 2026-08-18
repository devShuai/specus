package transfer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

const (
	ScopePublicTransfer            = "PUBLIC_TRANSFER"
	ScopeAdminClientMessage        = "ADMIN_CLIENT_MESSAGE"
	StatusPending                  = "PENDING"
	StatusUploaded                 = "UPLOADED"
	StatusExpired                  = "EXPIRED"
	maxTrackedRateSources          = 100_000
	defaultPerUserQuotaBytes int64 = 1024 * 1024 * 1024
)

var (
	ErrRateLimited = errors.New("rate limited")
	ErrConflict    = errors.New("conflict")
	ErrForbidden   = errors.New("forbidden")
	ErrGone        = errors.New("gone")
	ErrInternal    = errors.New("internal")
	sha256Pattern  = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

type categorizedError struct {
	category error
	message  string
}

func (e *categorizedError) Error() string { return e.message }
func (e *categorizedError) Unwrap() error { return e.category }

func rateLimited(message string) error {
	return &categorizedError{category: ErrRateLimited, message: message}
}

func conflict(message string) error {
	return &categorizedError{category: ErrConflict, message: message}
}

func forbidden(message string) error {
	return &categorizedError{category: ErrForbidden, message: message}
}

func gone(message string) error {
	return &categorizedError{category: ErrGone, message: message}
}

func internalError(err error) error {
	if err == nil {
		return nil
	}
	return &categorizedError{category: ErrInternal, message: err.Error()}
}

type AttachmentView struct {
	AttachmentID int64   `json:"attachmentId"`
	ObjectID     string  `json:"objectId"`
	FileName     string  `json:"fileName"`
	MimeType     string  `json:"mimeType"`
	SizeBytes    int64   `json:"sizeBytes"`
	SHA256       *string `json:"sha256"`
	Status       string  `json:"status"`
	ExpiresAt    string  `json:"expiresAt"`
}

type PresignUploadRequest struct {
	FileName       string `json:"fileName"`
	MimeType       string `json:"mimeType"`
	SizeBytes      *int64 `json:"sizeBytes"`
	SHA256         string `json:"sha256"`
	RoomID         string `json:"roomId"`
	RoomToken      string `json:"roomToken"`
	TargetClientID *int64 `json:"targetClientId"`
}

type CompleteAttachmentRequest struct {
	RoomToken string `json:"roomToken"`
}
type PresignDownloadRequest struct {
	RoomToken string `json:"roomToken"`
}

type OSSUploadCallback struct {
	Bucket   string `json:"bucket"`
	Object   string `json:"object"`
	Size     *int64 `json:"size"`
	MimeType string `json:"mimeType"`
	ETag     string `json:"etag"`
}

type PresignUploadResponse struct {
	AttachmentID  int64             `json:"attachmentId"`
	ObjectID      string            `json:"objectId"`
	ObjectKey     string            `json:"objectKey"`
	UploadURL     string            `json:"uploadUrl"`
	UploadHeaders map[string]string `json:"uploadHeaders"`
	ExpiresAt     string            `json:"expiresAt"`
	Attachment    AttachmentView    `json:"attachment"`
}

type PresignDownloadResponse struct {
	AttachmentID    int64             `json:"attachmentId"`
	ObjectID        string            `json:"objectId"`
	DownloadURL     string            `json:"downloadUrl"`
	DownloadHeaders map[string]string `json:"downloadHeaders"`
	ExpiresAt       string            `json:"expiresAt"`
	Attachment      AttachmentView    `json:"attachment"`
}

type rateWindow struct {
	started time.Time
	count   int
}

// SharedRateLimiter is implemented by the server Redis coordination layer without
// coupling the attachment package to a concrete Redis client.
type SharedRateLimiter interface {
	AllowRate(context.Context, string, string, int, time.Duration) (bool, error)
}

type SharedRateLimiterFunc func(context.Context, string, string, int, time.Duration) (bool, error)

func (limiter SharedRateLimiterFunc) AllowRate(ctx context.Context, bucket, identity string,
	limit int, window time.Duration) (bool, error) {
	return limiter(ctx, bucket, identity, limit, window)
}

type Service struct {
	db                *store.DB
	storage           *ObjectStorage
	objectCfg         config.ObjectStorageConfig
	publicCfg         config.PublicTransferConfig
	rateMu            sync.Mutex
	rateByIP          map[string]rateWindow
	maxTrackedSources int
	sharedRateLimiter SharedRateLimiter
	quotaLocks        [64]sync.Mutex
	roomQuotaLocks    [64]sync.Mutex
	// rooms resolves the persistent public-transfer room and the caller's role. Admin-only
	// deployments may omit it, but new public uploads and bound attachments fail closed without it.
	rooms *RoomService
}

// SetRoomService attaches the persistent room resolver used to authorize public attachments.
func (s *Service) SetRoomService(rooms *RoomService) { s.rooms = rooms }

func NewService(db *store.DB, objectCfg config.ObjectStorageConfig, publicCfg config.PublicTransferConfig,
	sharedRateLimiter ...SharedRateLimiter) *Service {
	service := &Service{db: db, storage: NewObjectStorage(objectCfg), objectCfg: objectCfg,
		publicCfg: publicCfg, rateByIP: make(map[string]rateWindow), maxTrackedSources: maxTrackedRateSources}
	if len(sharedRateLimiter) > 0 {
		service.sharedRateLimiter = sharedRateLimiter[0]
	}
	return service
}

func (s *Service) CheckPresignIP(ip string) error {
	return s.CheckPresignIPContext(context.Background(), ip)
}

func (s *Service) CheckPresignIPContext(ctx context.Context, ip string) error {
	limit := s.publicCfg.PresignRateLimitPerIP
	if limit < 1 {
		limit = 1
	}
	windowDuration := time.Duration(s.publicCfg.PresignRateLimitWindowSeconds) * time.Second
	if windowDuration <= 0 {
		windowDuration = time.Second
	}
	now := time.Now()
	ip = strings.TrimSpace(ip)
	if ip == "" {
		ip = "unknown"
	}
	if s.publicCfg.ClusterEnabled {
		if s.sharedRateLimiter == nil {
			return rateLimited("服务暂时不可用,请稍后再试")
		}
		allowed, err := s.sharedRateLimiter.AllowRate(ctx, "presign-upload", ip, limit, windowDuration)
		if err != nil {
			return rateLimited("服务暂时不可用,请稍后再试")
		}
		if !allowed {
			return rateLimited("请求过于频繁,请稍后再试")
		}
		return nil
	}
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	if _, exists := s.rateByIP[ip]; !exists && len(s.rateByIP) >= s.maxTrackedSources {
		return rateLimited("请求过于频繁,请稍后再试")
	}
	window := s.rateByIP[ip]
	if window.started.IsZero() || now.Sub(window.started) >= windowDuration {
		window = rateWindow{started: now}
	}
	window.count++
	s.rateByIP[ip] = window
	if window.count > limit {
		return rateLimited("请求过于频繁,请稍后再试")
	}
	return nil
}

func (s *Service) CreatePublicUpload(ctx context.Context, tenantID, username string,
	request PresignUploadRequest) (PresignUploadResponse, error) {
	tenantID, username, err := normalizeAccount(tenantID, username)
	if err != nil {
		return PresignUploadResponse{}, err
	}
	roomToken, err := requireText(request.RoomToken, "roomToken")
	if err != nil {
		return PresignUploadResponse{}, err
	}
	hash := tokenHash(roomToken)
	roomID, err := normalizeRoomID(request.RoomID)
	if err != nil {
		return PresignUploadResponse{}, err
	}
	// Resolve the persistent room first: VIEWER invitations must not be able to upload, and the
	// pending quota is a property of the room rather than of one room token.
	access, err := s.resolveRoomAccess(ctx, roomID, roomToken, "attachment-upload")
	if err != nil {
		return PresignUploadResponse{}, err
	}
	if access == nil {
		return PresignUploadResponse{}, internalError(errors.New("public transfer room service is unavailable"))
	}
	maxPending := s.publicCfg.MaxPendingUploadsPerRoom
	if maxPending < 1 {
		maxPending = 1
	}
	if !access.Role.CanEdit() {
		return PresignUploadResponse{}, forbidden("访客不能上传文件")
	}
	// This lock only reduces same-process contention. The transactional store operation remains
	// the authoritative quota gate across server instances.
	roomLock := s.roomQuotaLock(access.RoomID)
	roomLock.Lock()
	defer roomLock.Unlock()
	lock := s.quotaLock(tenantID, username)
	lock.Lock()
	defer lock.Unlock()
	roomRowID := access.RoomID
	publicRoomID := &roomRowID
	return s.createUpload(ctx, ScopePublicTransfer, &tenantID, &roomID, &hash, &username, nil,
		publicRoomID, maxPending, request)
}

func (s *Service) CreateAdminUpload(ctx context.Context, tenantID, username string, targetClientID int64,
	request PresignUploadRequest) (PresignUploadResponse, error) {
	request.TargetClientID = &targetClientID
	var err error
	tenantID, username, err = normalizeAccount(tenantID, username)
	if err != nil {
		return PresignUploadResponse{}, err
	}
	lock := s.quotaLock(tenantID, username)
	lock.Lock()
	defer lock.Unlock()
	return s.createUpload(ctx, ScopeAdminClientMessage, &tenantID, nil, nil, &username,
		&targetClientID, nil, 0, request)
}

func (s *Service) CompletePublic(ctx context.Context, id int64, roomToken, tenantID,
	username string) (AttachmentView, error) {
	item, err := s.db.GetTransferAttachment(ctx, id, ScopePublicTransfer)
	if err != nil || item == nil {
		return AttachmentView{}, attachmentNotFound(id, err)
	}
	if err := s.requireRoomAccess(ctx, *item, roomToken, true); err != nil {
		return AttachmentView{}, err
	}
	tenantID, username, err = normalizeAccount(tenantID, username)
	if err != nil {
		return AttachmentView{}, err
	}
	if item.TenantID == nil || strings.TrimSpace(*item.TenantID) == "" {
		item.TenantID = &tenantID
	}
	if item.OwnerUsername == nil || strings.TrimSpace(*item.OwnerUsername) == "" {
		item.OwnerUsername = &username
	}
	return s.complete(ctx, *item, false)
}

func (s *Service) CompleteAdmin(ctx context.Context, id int64, tenantID, username string) (AttachmentView, error) {
	item, err := s.db.GetTenantTransferAttachment(ctx, id, tenantID, ScopeAdminClientMessage)
	if err != nil || item == nil {
		return AttachmentView{}, attachmentNotFound(id, err)
	}
	if item.OwnerUsername == nil || strings.TrimSpace(*item.OwnerUsername) == "" {
		username = strings.TrimSpace(username)
		item.OwnerUsername = &username
	}
	return s.complete(ctx, *item, false)
}

func (s *Service) CreatePublicDownload(ctx context.Context, id int64, roomToken, tenantID,
	username string) (PresignDownloadResponse, error) {
	item, err := s.db.GetTransferAttachment(ctx, id, ScopePublicTransfer)
	if err != nil || item == nil {
		return PresignDownloadResponse{}, attachmentNotFound(id, err)
	}
	if err := s.requireRoomAccess(ctx, *item, roomToken, false); err != nil {
		return PresignDownloadResponse{}, err
	}
	return s.createDownload(ctx, *item, tenantID, username)
}

func (s *Service) CreateAdminDownload(ctx context.Context, id int64, tenantID,
	username string) (PresignDownloadResponse, error) {
	item, err := s.db.GetTenantTransferAttachment(ctx, id, tenantID, ScopeAdminClientMessage)
	if err != nil || item == nil {
		return PresignDownloadResponse{}, attachmentNotFound(id, err)
	}
	return s.createDownload(ctx, *item, tenantID, username)
}

func (s *Service) GetAdminAttachment(ctx context.Context, id int64, tenantID string) (*store.TransferAttachment, error) {
	item, err := s.db.GetTenantTransferAttachment(ctx, id, tenantID, ScopeAdminClientMessage)
	if err != nil {
		return nil, internalError(err)
	}
	return item, nil
}

func (s *Service) RunExpiration(ctx context.Context) {
	interval := time.Duration(s.objectCfg.ExpirationScanIntervalMs) * time.Millisecond
	if interval <= 0 {
		interval = time.Hour
	}
	expirationTicker := time.NewTicker(interval)
	purgeTicker := time.NewTicker(10 * time.Minute)
	defer expirationTicker.Stop()
	defer purgeTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-expirationTicker.C:
			_ = s.expire(ctx)
		case now := <-purgeTicker.C:
			s.PurgeExpiredRateWindows(now)
			_ = s.db.DeleteExpiredTransferDownloadGrants(ctx, now.UTC())
		}
	}
}

func (s *Service) PurgeExpiredRateWindows(now time.Time) int {
	windowDuration := time.Duration(s.publicCfg.PresignRateLimitWindowSeconds) * time.Second
	if windowDuration <= 0 {
		windowDuration = time.Second
	}
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	return s.purgeExpiredRateWindowsLocked(now, windowDuration)
}

func (s *Service) purgeExpiredRateWindowsLocked(now time.Time, windowDuration time.Duration) int {
	removed := 0
	for key, window := range s.rateByIP {
		if now.Sub(window.started) >= windowDuration {
			delete(s.rateByIP, key)
			removed++
		}
	}
	return removed
}

func (s *Service) expire(ctx context.Context) error {
	for {
		items, err := s.db.ListExpiredTransferAttachments(ctx, time.Now(), StatusExpired, 100)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			return nil
		}
		for _, item := range items {
			if s.storage.Enabled() {
				if err := s.storage.Delete(ctx, item.ObjectKey); err != nil {
					return err
				}
			}
			item.Status = StatusExpired
			item.UpdatedAt = time.Now()
			if err := s.db.UpdateTransferAttachment(ctx, item); err != nil {
				return err
			}
		}
	}
}

func (s *Service) createUpload(ctx context.Context, scope string, tenantID, roomID, roomTokenHash,
	ownerUsername *string, targetClientID *int64, publicTransferRoomID *int64,
	maxPending int, request PresignUploadRequest) (PresignUploadResponse, error) {
	if !s.storage.Enabled() {
		return PresignUploadResponse{}, conflict("object storage is not configured")
	}
	fileName, err := normalizeFileName(request.FileName)
	if err != nil {
		return PresignUploadResponse{}, err
	}
	mimeType, err := normalizeMimeType(request.MimeType)
	if err != nil {
		return PresignUploadResponse{}, err
	}
	sizeBytes, err := s.normalizeSize(request.SizeBytes)
	if err != nil {
		return PresignUploadResponse{}, err
	}
	if tenantID == nil || ownerUsername == nil {
		return PresignUploadResponse{}, internalError(errors.New("authenticated account is missing"))
	}
	if err := s.ensureStorageQuota(ctx, *tenantID, *ownerUsername, sizeBytes, -1); err != nil {
		return PresignUploadResponse{}, err
	}
	shaValue, err := normalizeSHA256(request.SHA256)
	if err != nil {
		return PresignUploadResponse{}, err
	}
	now := time.Now().UTC()
	uploadTTL := time.Duration(s.objectCfg.UploadURLTTLSeconds) * time.Second
	retention := time.Duration(s.objectCfg.RetentionHours) * time.Hour
	if retention <= 0 {
		retention = time.Hour
	}
	var lastErr error
	for attempt := 0; attempt < 8; attempt++ {
		id := auth.NewClientID()
		objectKey := s.objectKey(scope, id, fileName, now)
		presigned, err := s.storage.PresignUpload(objectKey, mimeType, uploadTTL)
		if err != nil {
			return PresignUploadResponse{}, conflict(err.Error())
		}
		item := store.TransferAttachment{ID: id, TenantID: tenantID, Scope: scope, RoomID: roomID,
			RoomTokenHash: roomTokenHash, PublicTransferRoomID: publicTransferRoomID,
			OwnerUsername: ownerUsername, TargetClientID: targetClientID,
			ObjectKey: objectKey, FileName: fileName, MimeType: mimeType, SizeBytes: sizeBytes,
			SHA256: shaValue, Status: StatusPending, CreatedAt: now, UpdatedAt: now,
			UploadExpiresAt: presigned.ExpiresAt, ExpiresAt: now.Add(retention)}
		inserted := true
		var insertErr error
		if publicTransferRoomID != nil {
			inserted, insertErr = s.db.InsertTransferAttachmentWithinRoomPendingLimit(ctx, item,
				maxPending, StatusPending)
		} else {
			insertErr = s.db.InsertTransferAttachment(ctx, item)
		}
		if insertErr != nil {
			lastErr = insertErr
			continue
		}
		if !inserted {
			return PresignUploadResponse{}, rateLimited("当前房间待上传文件过多,请稍后再试")
		}
		return PresignUploadResponse{AttachmentID: id, ObjectID: fmt.Sprint(id), ObjectKey: objectKey,
			UploadURL: presigned.URL, UploadHeaders: presigned.Headers,
			ExpiresAt: presigned.ExpiresAt.Format(time.RFC3339Nano), Attachment: attachmentView(item)}, nil
	}
	return PresignUploadResponse{}, internalError(fmt.Errorf("failed to allocate attachment id: %w", lastErr))
}

func (s *Service) CompleteUploadCallback(ctx context.Context, requestTarget string, body []byte,
	authorization, publicKeyURL string) (AttachmentView, error) {
	if !s.storage.VerifyUploadCallback(ctx, requestTarget, body, authorization, publicKeyURL) {
		return AttachmentView{}, forbidden("invalid OSS upload callback signature")
	}
	var callback OSSUploadCallback
	if err := json.Unmarshal(body, &callback); err != nil || strings.TrimSpace(callback.Bucket) == "" ||
		strings.TrimSpace(callback.Object) == "" || callback.Size == nil || *callback.Size < 0 {
		return AttachmentView{}, errors.New("invalid OSS upload callback body")
	}
	if callback.Bucket != strings.TrimSpace(s.objectCfg.Bucket) {
		return AttachmentView{}, forbidden("OSS callback bucket mismatch")
	}
	objectKey := strings.TrimSpace(callback.Object)
	if err := s.storage.validateObjectKey(objectKey); err != nil {
		return AttachmentView{}, err
	}
	item, err := s.db.GetTransferAttachmentByObjectKey(ctx, objectKey)
	if err != nil {
		return AttachmentView{}, internalError(err)
	}
	if item == nil {
		return AttachmentView{}, errors.New("attachment object was not allocated")
	}
	if item.ObjectKey != objectKey {
		return AttachmentView{}, forbidden("OSS callback object mismatch")
	}
	if item.Status == StatusUploaded {
		return attachmentView(*item), nil
	}
	if item.Status != StatusPending {
		return AttachmentView{}, conflict("attachment is not pending")
	}
	if *callback.Size > s.objectCfg.MaxAttachmentBytes {
		if err := s.storage.Delete(ctx, objectKey); err != nil {
			return AttachmentView{}, conflict(err.Error())
		}
		return AttachmentView{}, errors.New("attachment is too large")
	}
	item.SizeBytes = *callback.Size
	return s.complete(ctx, *item, true)
}

func (s *Service) complete(ctx context.Context, item store.TransferAttachment,
	objectVerifiedByCallback bool) (AttachmentView, error) {
	if item.TenantID == nil || item.OwnerUsername == nil {
		return AttachmentView{}, internalError(errors.New("attachment owner is missing"))
	}
	lock := s.quotaLock(*item.TenantID, *item.OwnerUsername)
	lock.Lock()
	defer lock.Unlock()
	now := time.Now().UTC()
	if item.Status == StatusUploaded {
		return attachmentView(item), nil
	}
	if item.Status != StatusPending {
		return AttachmentView{}, conflict("attachment is not pending")
	}
	if item.UploadExpiresAt.Before(now) {
		return AttachmentView{}, conflict("attachment upload URL is expired")
	}
	if s.storage.Enabled() && !objectVerifiedByCallback {
		stat, err := s.storage.Stat(ctx, item.ObjectKey)
		if err != nil {
			return AttachmentView{}, conflict(err.Error())
		}
		if !stat.Exists {
			return AttachmentView{}, conflict("attachment object was not uploaded")
		}
		maxBytes := s.objectCfg.MaxAttachmentBytes
		if stat.ContentLength > maxBytes {
			if err := s.storage.Delete(ctx, item.ObjectKey); err != nil {
				return AttachmentView{}, conflict(err.Error())
			}
			return AttachmentView{}, errors.New("attachment is too large")
		}
		if stat.ContentLength >= 0 {
			item.SizeBytes = stat.ContentLength
		}
	}
	if err := s.ensureStorageQuota(ctx, *item.TenantID, *item.OwnerUsername, item.SizeBytes, item.ID); err != nil {
		if s.storage.Enabled() {
			if deleteErr := s.storage.Delete(ctx, item.ObjectKey); deleteErr != nil {
				return AttachmentView{}, conflict(deleteErr.Error())
			}
		}
		return AttachmentView{}, err
	}
	item.Status = StatusUploaded
	item.UpdatedAt = now
	item.UploadedAt = &now
	if err := s.db.UpdateTransferAttachment(ctx, item); err != nil {
		return AttachmentView{}, internalError(err)
	}
	return attachmentView(item), nil
}

func (s *Service) createDownload(ctx context.Context, item store.TransferAttachment, tenantID,
	username string) (PresignDownloadResponse, error) {
	now := time.Now()
	if item.Status != StatusUploaded {
		return PresignDownloadResponse{}, conflict("attachment is not uploaded")
	}
	if item.ExpiresAt.Before(now) {
		return PresignDownloadResponse{}, conflict("attachment is expired")
	}
	if !s.storage.Enabled() {
		return PresignDownloadResponse{}, conflict("object storage is not configured")
	}
	tenantID, username, err := normalizeAccount(tenantID, username)
	if err != nil {
		return PresignDownloadResponse{}, err
	}
	lock := s.quotaLock(tenantID, username)
	lock.Lock()
	defer lock.Unlock()
	usageMonth := time.Now().UTC().Format("2006-01")
	usedBytes, err := s.db.SumTransferDownloadUsageBytes(ctx, tenantID, username, usageMonth)
	if err != nil {
		return PresignDownloadResponse{}, internalError(err)
	}
	if err := ensureWithinQuota(usedBytes, item.SizeBytes,
		s.objectCfg.PerUserMonthlyDownloadQuotaBytes,
		"本月 OSS 下载流量额度不足"); err != nil {
		return PresignDownloadResponse{}, err
	}
	grant, token, err := s.createDownloadGrant(ctx, tenantID, username, item.ID, now.UTC())
	if err != nil {
		return PresignDownloadResponse{}, err
	}
	return PresignDownloadResponse{AttachmentID: item.ID, ObjectID: fmt.Sprint(item.ID),
		DownloadURL: "/api/public/transfer/downloads/" + token, DownloadHeaders: map[string]string{},
		ExpiresAt: grant.ExpiresAt.Format(time.RFC3339Nano), Attachment: attachmentView(item)}, nil
}

func (s *Service) createDownloadGrant(ctx context.Context, tenantID, username string,
	attachmentID int64, now time.Time) (store.TransferAttachmentDownloadGrant, string, error) {
	ttlSeconds := s.objectCfg.DownloadURLTTLSeconds
	if ttlSeconds < 1 {
		ttlSeconds = 1
	}
	var lastErr error
	for attempt := 0; attempt < 8; attempt++ {
		rawToken := make([]byte, 32)
		if _, err := rand.Read(rawToken); err != nil {
			return store.TransferAttachmentDownloadGrant{}, "", internalError(err)
		}
		token := base64.RawURLEncoding.EncodeToString(rawToken)
		grant := store.TransferAttachmentDownloadGrant{
			ID: auth.NewClientID(), TokenHash: tokenHash(token), TenantID: tenantID,
			Username: username, AttachmentID: attachmentID, CreatedAt: now,
			ExpiresAt: now.Add(time.Duration(ttlSeconds) * time.Second),
		}
		if err := s.db.InsertTransferDownloadGrant(ctx, grant); err == nil {
			return grant, token, nil
		} else {
			lastErr = err
		}
	}
	return store.TransferAttachmentDownloadGrant{}, "",
		internalError(fmt.Errorf("failed to allocate download grant: %w", lastErr))
}

// ConsumeDownloadGrant atomically consumes a bearer grant and returns a very short-lived
// direct OSS URL. The grant itself can never produce a second redirect.
func (s *Service) ConsumeDownloadGrant(ctx context.Context, token string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 512 {
		return "", gone("download link is expired or already used")
	}
	hash := tokenHash(token)
	grant, err := s.db.GetTransferDownloadGrantByTokenHash(ctx, hash)
	if err != nil {
		return "", internalError(err)
	}
	now := time.Now().UTC()
	if grant == nil || grant.ConsumedAt != nil || !grant.ExpiresAt.After(now) {
		return "", gone("download link is expired or already used")
	}
	item, err := s.db.GetTransferAttachmentByID(ctx, grant.AttachmentID)
	if err != nil {
		return "", internalError(err)
	}
	if item == nil || item.Status != StatusUploaded || !item.ExpiresAt.After(now) || !s.storage.Enabled() {
		return "", gone("download link is no longer available")
	}
	lock := s.quotaLock(grant.TenantID, grant.Username)
	lock.Lock()
	defer lock.Unlock()
	usageMonth := now.Format("2006-01")
	usedBytes, err := s.db.SumTransferDownloadUsageBytes(ctx, grant.TenantID, grant.Username, usageMonth)
	if err != nil {
		return "", internalError(err)
	}
	if err := ensureWithinQuota(usedBytes, item.SizeBytes,
		s.objectCfg.PerUserMonthlyDownloadQuotaBytes,
		"本月 OSS 下载流量额度不足"); err != nil {
		return "", err
	}
	directTTL := time.Duration(s.objectCfg.DownloadObjectURLTTLSeconds) * time.Second
	presigned, err := s.storage.PresignDownload(item.ObjectKey, directTTL, fmt.Sprint(grant.ID))
	if err != nil {
		return "", conflict(err.Error())
	}
	var lastErr error
	for attempt := 0; attempt < 8; attempt++ {
		consumed, consumeErr := s.db.ConsumeTransferDownloadGrantAndInsertUsage(
			ctx, grant.ID, hash, now, auth.NewClientID(), grant.TenantID, grant.Username,
			item.ID, item.SizeBytes, usageMonth)
		if consumeErr == nil {
			if !consumed {
				return "", gone("download link is expired or already used")
			}
			return presigned.URL, nil
		}
		lastErr = consumeErr
	}
	return "", internalError(fmt.Errorf("failed to consume download grant and record usage: %w", lastErr))
}

func (s *Service) ensureStorageQuota(ctx context.Context, tenantID, username string,
	requestedBytes, excludedAttachmentID int64) error {
	usedBytes, err := s.db.SumActiveTransferStorageBytes(ctx, tenantID, username,
		excludedAttachmentID, time.Now().UTC())
	if err != nil {
		return internalError(err)
	}
	return ensureWithinQuota(usedBytes, requestedBytes, s.objectCfg.PerUserStorageQuotaBytes,
		"OSS 存储额度不足")
}

func ensureWithinQuota(usedBytes, requestedBytes, limitBytes int64, message string) error {
	if limitBytes < 1 {
		limitBytes = defaultPerUserQuotaBytes
	}
	if requestedBytes < 0 || usedBytes > limitBytes-requestedBytes {
		return rateLimited(message)
	}
	return nil
}

func (s *Service) quotaLock(tenantID, username string) *sync.Mutex {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(strings.TrimSpace(tenantID)))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(strings.TrimSpace(username)))
	return &s.quotaLocks[int(hash.Sum32())%len(s.quotaLocks)]
}

func (s *Service) roomQuotaLock(roomID int64) *sync.Mutex {
	value := uint64(roomID)
	value ^= value >> 32
	return &s.roomQuotaLocks[int(value%uint64(len(s.roomQuotaLocks)))]
}

func normalizeAccount(tenantID, username string) (string, string, error) {
	tenantID = strings.TrimSpace(tenantID)
	username = strings.TrimSpace(username)
	if tenantID == "" || username == "" {
		return "", "", internalError(errors.New("authenticated account is missing"))
	}
	return tenantID, username, nil
}

func (s *Service) normalizeSize(value *int64) (int64, error) {
	if value == nil || *value <= 0 {
		return 0, errors.New("sizeBytes must be positive")
	}
	maxBytes := s.objectCfg.MaxAttachmentBytes
	if *value > maxBytes {
		return 0, errors.New("attachment is too large")
	}
	return *value, nil
}

func (s *Service) objectKey(scope string, id int64, fileName string, now time.Time) string {
	prefix := strings.Trim(strings.TrimSpace(s.objectCfg.ObjectPrefix), "/")
	if prefix != "" {
		prefix += "/"
	}
	scopeSegment := strings.ToLower(strings.ReplaceAll(scope, "_", "-"))
	return fmt.Sprintf("%s%s/%s/%d/%s", prefix, scopeSegment, now.UTC().Format("20060102"), id, fileName)
}

func attachmentView(item store.TransferAttachment) AttachmentView {
	return AttachmentView{AttachmentID: item.ID, ObjectID: fmt.Sprint(item.ID), FileName: item.FileName,
		MimeType: item.MimeType, SizeBytes: item.SizeBytes, SHA256: item.SHA256, Status: item.Status,
		ExpiresAt: item.ExpiresAt.Format(time.RFC3339Nano)}
}

// resolveRoomAccess resolves the persistent room and role for a new public attachment. A nil
// result means the room subsystem is unavailable and the caller must fail closed. Legacy fallback
// applies only when authorizing an existing row whose PublicTransferRoomID is nil.
func (s *Service) resolveRoomAccess(ctx context.Context, roomID, roomToken,
	peerID string) (*RoomAccess, error) {
	if s.rooms == nil {
		return nil, nil
	}
	access, err := s.rooms.Resolve(ctx, roomID, roomToken, peerID)
	if err != nil {
		return nil, err
	}
	return &access, nil
}

// requireRoomAccess authorizes an operation on an existing attachment. Attachments bound to a
// persistent room are checked against room membership (and role, for mutations); rows predating the
// binding keep the legacy room-token comparison.
func (s *Service) requireRoomAccess(ctx context.Context, item store.TransferAttachment,
	roomToken string, requireEdit bool) error {
	if item.PublicTransferRoomID == nil {
		return matchingRoomToken(item, roomToken)
	}
	if s.rooms == nil {
		return internalError(errors.New("public transfer room service is unavailable"))
	}
	roomName := ""
	if item.RoomID != nil {
		roomName = *item.RoomID
	}
	access, err := s.rooms.ResolveExisting(ctx, roomName, roomToken, "attachment-access")
	if err != nil {
		return err
	}
	if access.RoomID != *item.PublicTransferRoomID || (requireEdit && !access.Role.CanEdit()) {
		return forbidden("房间凭证无效")
	}
	return nil
}

func matchingRoomToken(item store.TransferAttachment, roomToken string) error {
	value, err := requireText(roomToken, "roomToken")
	if err != nil {
		return err
	}
	if item.RoomTokenHash == nil || *item.RoomTokenHash != tokenHash(value) {
		return errors.New("roomToken is invalid")
	}
	return nil
}

func tokenHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func normalizeRoomID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "default", nil
	}
	if utf16Length(value) > 120 || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("roomId is invalid")
	}
	return value, nil
}

func normalizeFileName(value string) (string, error) {
	if value == "" {
		return "", errors.New("fileName cannot be blank")
	}
	if slash := strings.LastIndexAny(value, `/\`); slash >= 0 {
		value = value[slash+1:]
	}

	normalized := make([]rune, 0, len(value))
	previousWasInvalid := false
	previousWasDot := false
	for _, codePoint := range value {
		asciiAlphaNumeric := codePoint >= 'A' && codePoint <= 'Z' ||
			codePoint >= 'a' && codePoint <= 'z' ||
			codePoint >= '0' && codePoint <= '9'
		allowed := asciiAlphaNumeric || codePoint == '.' || codePoint == '_' || codePoint == '-'
		if !allowed {
			if !previousWasInvalid {
				normalized = append(normalized, '_')
			}
			previousWasInvalid = true
			previousWasDot = false
			continue
		}
		previousWasInvalid = false
		if codePoint == '.' {
			if !previousWasDot {
				normalized = append(normalized, codePoint)
			}
			previousWasDot = true
		} else {
			normalized = append(normalized, codePoint)
			previousWasDot = false
		}
	}

	if len(normalized) == 0 || len(normalized) == 1 && normalized[0] == '.' {
		return "attachment", nil
	}
	if len(normalized) <= 180 {
		return string(normalized), nil
	}

	dot := -1
	for index := len(normalized) - 1; index >= 0; index-- {
		if normalized[index] == '.' {
			dot = index
			break
		}
	}
	if dot > 0 && dot < len(normalized)-1 {
		extension := normalized[dot:]
		if len(extension) < 180 {
			return string(normalized[:180-len(extension)]) + string(extension), nil
		}
	}
	return string(normalized[:180]), nil
}

func normalizeMimeType(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "application/octet-stream", nil
	}
	if utf16Length(value) > 120 || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("mimeType is invalid")
	}
	return value, nil
}

func normalizeSHA256(value string) (*string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return nil, nil
	}
	if !sha256Pattern.MatchString(value) {
		return nil, errors.New("sha256 is invalid")
	}
	return &value, nil
}

func requireText(value, field string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s cannot be blank", field)
	}
	return value, nil
}

func attachmentNotFound(id int64, err error) error {
	if err != nil {
		return internalError(err)
	}
	return fmt.Errorf("attachment not found: %d", id)
}

func utf16Length(value string) int { return len(utf16.Encode([]rune(value))) }
