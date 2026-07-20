package transfer

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/config"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/store"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestPublicAttachmentLifecycleValidatesObjectWithHead(t *testing.T) {
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "attachments.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	objectCfg := config.ObjectStorageConfig{
		Provider: "aliyun-oss", Endpoint: "https://oss.example.com", Bucket: "private",
		AccessKeyID: "key", AccessKeySecret: "secret", ObjectPrefix: "shuai-tunnel/attachments",
		UploadURLTTLSeconds: 900, DownloadURLTTLSeconds: 600, RetentionHours: 72,
		MaxAttachmentBytes: 20,
	}
	service := NewService(db, objectCfg, config.PublicTransferConfig{MaxPendingUploadsPerRoom: 2})
	var mu sync.Mutex
	methods := make([]string, 0)
	service.storage.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		methods = append(methods, request.Method)
		mu.Unlock()
		header := make(http.Header)
		if request.Method == http.MethodHead {
			header.Set("Content-Length", "13")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: header,
			Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})}

	size := int64(10)
	upload, err := service.CreatePublicUpload(context.Background(), "default", "alice", PresignUploadRequest{
		FileName: "../my 图片.png", MimeType: "image/png", SizeBytes: &size,
		SHA256: strings.Repeat("A", 64), RoomID: "room-a", RoomToken: "secret-room-token",
	})
	if err != nil {
		t.Fatalf("create upload: %v", err)
	}
	if upload.Attachment.Status != StatusPending || upload.Attachment.SHA256 == nil ||
		*upload.Attachment.SHA256 != strings.Repeat("a", 64) {
		t.Fatalf("unexpected upload response: %+v", upload)
	}
	if upload.Attachment.FileName != "my_.png" {
		t.Fatalf("Java-compatible ASCII filename sanitization mismatch: %q", upload.Attachment.FileName)
	}
	if !strings.Contains(upload.UploadURL, "private.oss.example.com/") ||
		upload.UploadHeaders["Content-Type"] != "image/png" {
		t.Fatalf("unexpected presign response: %+v", upload)
	}
	if _, err := service.CompletePublic(context.Background(), upload.AttachmentID, "wrong-token", "default", "alice"); err == nil {
		t.Fatal("completion accepted a mismatched room token")
	}
	completed, err := service.CompletePublic(context.Background(), upload.AttachmentID, "secret-room-token", "default", "alice")
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if completed.Status != StatusUploaded || completed.SizeBytes != 13 {
		t.Fatalf("HEAD content length was not persisted: %+v", completed)
	}
	download, err := service.CreatePublicDownload(context.Background(), upload.AttachmentID, "secret-room-token", "default", "alice")
	if err != nil {
		t.Fatalf("presign download: %v", err)
	}
	if !strings.Contains(download.DownloadURL, "OSSAccessKeyId=key") || download.Attachment.SizeBytes != 13 {
		t.Fatalf("unexpected download response: %+v", download)
	}
	mu.Lock()
	gotMethods := strings.Join(methods, ",")
	mu.Unlock()
	if gotMethods != http.MethodHead {
		t.Fatalf("object verification methods = %q", gotMethods)
	}
}

func TestNormalizeFileNameUsesUnicodeCodePointsAndSafeLengthBoundaries(t *testing.T) {
	cases := map[string]string{
		`mixed/path\photo😀  中文.png`: "photo_.png",
		"😀😀.txt":                    "_.txt",
		"folder/":                   "attachment",
		`folder\`:                   "attachment",
		"folder/...":                "attachment",
		"archive..tar...gz":         "archive.tar.gz",
		".env":                      ".env",
		"file.":                     "file.",
		"   ":                       "_",
		"  photo .png  ":            "_photo_.png_",
	}
	for input, expected := range cases {
		actual, err := normalizeFileName(input)
		if err != nil {
			t.Fatalf("normalizeFileName(%q): %v", input, err)
		}
		if actual != expected {
			t.Errorf("normalizeFileName(%q) = %q, want %q", input, actual, expected)
		}
		if strings.Contains(actual, "..") {
			t.Errorf("normalizeFileName(%q) produced unsafe dot run %q", input, actual)
		}
	}

	shortExtension := "." + strings.Repeat("b", 178)
	longCases := map[string]string{
		strings.Repeat("a", 200) + ".txt": strings.Repeat("a", 176) + ".txt",
		"abcdefghij" + shortExtension:     "a" + shortExtension,
		"a." + strings.Repeat("b", 180):   "a." + strings.Repeat("b", 178),
		strings.Repeat("x", 181):          strings.Repeat("x", 180),
	}
	for input, expected := range longCases {
		actual, err := normalizeFileName(input)
		if err != nil {
			t.Fatalf("normalizeFileName(long input): %v", err)
		}
		if actual != expected || len(actual) != 180 {
			t.Errorf("long filename normalized to length %d value %q, want %q", len(actual), actual, expected)
		}
	}
}

func TestPublicAttachmentRateAndPendingLimits(t *testing.T) {
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "limits.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service := NewService(db, config.ObjectStorageConfig{
		Provider: "aliyun-oss", Endpoint: "oss.example.com", Bucket: "private",
		AccessKeyID: "key", AccessKeySecret: "secret", ObjectPrefix: "prefix",
		UploadURLTTLSeconds: 60, RetentionHours: 1, MaxAttachmentBytes: 100,
	}, config.PublicTransferConfig{
		PresignRateLimitPerIP: 1, PresignRateLimitWindowSeconds: 60, MaxPendingUploadsPerRoom: 1,
	})
	if err := service.CheckPresignIP("203.0.113.8"); err != nil {
		t.Fatal(err)
	}
	if err := service.CheckPresignIP("203.0.113.8"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("second request was not rate limited: %v", err)
	}
	size := int64(1)
	request := PresignUploadRequest{FileName: "a.txt", SizeBytes: &size, RoomToken: "same-room"}
	if _, err := service.CreatePublicUpload(context.Background(), "default", "alice", request); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreatePublicUpload(context.Background(), "default", "alice", request); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("second pending upload was not limited: %v", err)
	}
}

func TestAttachmentStorageQuotaIsScopedToAuthenticatedAccount(t *testing.T) {
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "storage-quota.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service := NewService(db, config.ObjectStorageConfig{
		Provider: "aliyun-oss", Endpoint: "oss.example.com", Bucket: "private",
		AccessKeyID: "key", AccessKeySecret: "secret", ObjectPrefix: "prefix",
		UploadURLTTLSeconds: 60, RetentionHours: 1, MaxAttachmentBytes: 100,
		PerUserStorageQuotaBytes: 10,
	}, config.PublicTransferConfig{MaxPendingUploadsPerRoom: 10})
	firstSize := int64(5)
	if _, err := service.CreatePublicUpload(context.Background(), "default", "alice",
		PresignUploadRequest{FileName: "first.bin", SizeBytes: &firstSize, RoomToken: "room"}); err != nil {
		t.Fatal(err)
	}
	secondSize := int64(6)
	if _, err := service.CreatePublicUpload(context.Background(), "default", "alice",
		PresignUploadRequest{FileName: "second.bin", SizeBytes: &secondSize, RoomToken: "room"}); !errors.Is(err, ErrRateLimited) || !strings.Contains(err.Error(), "存储额度不足") {
		t.Fatalf("storage quota was not enforced: %v", err)
	}
	if _, err := service.CreatePublicUpload(context.Background(), "default", "bob",
		PresignUploadRequest{FileName: "second.bin", SizeBytes: &secondSize, RoomToken: "other-room"}); err != nil {
		t.Fatalf("another account incorrectly shared alice's quota: %v", err)
	}
}

func TestAttachmentDownloadQuotaCountsEachPresignedFileSize(t *testing.T) {
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "download-quota.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service := NewService(db, config.ObjectStorageConfig{
		Provider: "aliyun-oss", Endpoint: "oss.example.com", Bucket: "private",
		AccessKeyID: "key", AccessKeySecret: "secret", ObjectPrefix: "prefix",
		UploadURLTTLSeconds: 60, DownloadURLTTLSeconds: 60, RetentionHours: 1,
		MaxAttachmentBytes: 100, PerUserStorageQuotaBytes: 100,
		PerUserMonthlyDownloadQuotaBytes: 10,
	}, config.PublicTransferConfig{MaxPendingUploadsPerRoom: 10})
	service.storage.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		header := make(http.Header)
		if request.Method == http.MethodHead {
			header.Set("Content-Length", "6")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: header,
			Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})}
	size := int64(6)
	upload, err := service.CreatePublicUpload(context.Background(), "default", "alice",
		PresignUploadRequest{FileName: "file.bin", SizeBytes: &size, RoomToken: "room"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CompletePublic(context.Background(), upload.AttachmentID, "room",
		"default", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreatePublicDownload(context.Background(), upload.AttachmentID, "room",
		"default", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreatePublicDownload(context.Background(), upload.AttachmentID, "room",
		"default", "alice"); !errors.Is(err, ErrRateLimited) ||
		!strings.Contains(err.Error(), "下载流量额度不足") {
		t.Fatalf("download quota was not enforced: %v", err)
	}
}

func TestCompleteRejectsAndDeletesObjectWhoseActualSizeExceedsLimit(t *testing.T) {
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "oversize.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service := NewService(db, config.ObjectStorageConfig{
		Provider: "aliyun-oss", Endpoint: "oss.example.com", Bucket: "private",
		AccessKeyID: "key", AccessKeySecret: "secret", ObjectPrefix: "prefix",
		UploadURLTTLSeconds: 60, RetentionHours: 1, MaxAttachmentBytes: 5,
	}, config.PublicTransferConfig{MaxPendingUploadsPerRoom: 2})
	deleted := false
	service.storage.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		header := make(http.Header)
		if request.Method == http.MethodHead {
			header.Set("Content-Length", "13")
		}
		if request.Method == http.MethodDelete {
			deleted = true
		}
		return &http.Response{StatusCode: http.StatusOK, Header: header,
			Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})}
	size := int64(4)
	upload, err := service.CreatePublicUpload(context.Background(), "default", "alice", PresignUploadRequest{
		FileName: "large.bin", SizeBytes: &size, RoomToken: "room-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CompletePublic(context.Background(), upload.AttachmentID, "room-token", "default", "alice"); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized object was accepted: %v", err)
	}
	if !deleted {
		t.Fatal("oversized object was not deleted")
	}
}

func TestRateLimiterBoundsTrackedSourcesAndPurgesExpiredWindows(t *testing.T) {
	service := NewService(nil, config.ObjectStorageConfig{}, config.PublicTransferConfig{
		PresignRateLimitPerIP: 10, PresignRateLimitWindowSeconds: 60,
	})
	service.maxTrackedSources = 2
	if err := service.CheckPresignIP("192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := service.CheckPresignIP("192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	if err := service.CheckPresignIP("192.0.2.3"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("new source was accepted after capacity: %v", err)
	}
	service.rateMu.Lock()
	for key, window := range service.rateByIP {
		window.started = time.Now().Add(-2 * time.Minute)
		service.rateByIP[key] = window
	}
	service.rateMu.Unlock()
	if err := service.CheckPresignIP("192.0.2.3"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("full source table was cleaned inline instead of rejecting until the scheduled purge: %v", err)
	}
	if removed := service.PurgeExpiredRateWindows(time.Now()); removed != 2 {
		t.Fatalf("purged %d windows, want 2", removed)
	}
	if err := service.CheckPresignIP("192.0.2.3"); err != nil {
		t.Fatalf("new source rejected after purge: %v", err)
	}
}

func TestRoomIDValidationUsesJavaUTF16LengthWithoutBreakingUTF8(t *testing.T) {
	valid := strings.Repeat("中", 120)
	if got, err := normalizeRoomID(valid); err != nil || got != valid {
		t.Fatalf("120 BMP characters rejected: len=%d err=%v", len([]rune(got)), err)
	}
	if _, err := normalizeRoomID(strings.Repeat("中", 121)); err == nil {
		t.Fatal("121 BMP characters were accepted")
	}
	if got, err := normalizeRoomID(strings.Repeat("😀", 60)); err != nil || got == "" {
		t.Fatalf("60 surrogate-pair characters should fit Java length 120: %v", err)
	}
	if _, err := normalizeRoomID(strings.Repeat("😀", 61)); err == nil {
		t.Fatal("61 surrogate-pair characters exceeded Java length but were accepted")
	}
}

func TestExplicitZeroStorageLimitsAreNotSilentlyReplacedByDefaults(t *testing.T) {
	service := NewService(nil, config.ObjectStorageConfig{
		Provider: "aliyun-oss", Endpoint: "oss.example.com", Bucket: "private",
		AccessKeyID: "key", AccessKeySecret: "secret", ObjectPrefix: "prefix",
		UploadURLTTLSeconds: 0, DownloadURLTTLSeconds: 0, RetentionHours: 0,
		MaxAttachmentBytes: 0,
	}, config.PublicTransferConfig{})
	size := int64(1)
	if _, err := service.normalizeSize(&size); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("maxAttachmentBytes=0 should reject every positive file: %v", err)
	}
	now := time.Now()
	upload, err := service.storage.PresignUpload("prefix/a.txt", "text/plain", 0)
	if err != nil {
		t.Fatal(err)
	}
	if upload.ExpiresAt.After(now.Add(time.Second)) {
		t.Fatalf("zero upload TTL was replaced by a positive default: %s", upload.ExpiresAt.Sub(now))
	}
	download, err := service.storage.PresignDownload("prefix/a.txt", 0)
	if err != nil {
		t.Fatal(err)
	}
	if download.ExpiresAt.After(now.Add(time.Second)) {
		t.Fatalf("zero download TTL was replaced by a positive default: %s", download.ExpiresAt.Sub(now))
	}
}

func TestRetentionHoursKeepsJavaMinimumOfOneHour(t *testing.T) {
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "retention.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service := NewService(db, config.ObjectStorageConfig{
		Provider: "aliyun-oss", Endpoint: "oss.example.com", Bucket: "private",
		AccessKeyID: "key", AccessKeySecret: "secret", ObjectPrefix: "prefix",
		UploadURLTTLSeconds: 60, RetentionHours: 0, MaxAttachmentBytes: 10,
	}, config.PublicTransferConfig{MaxPendingUploadsPerRoom: 2})
	size := int64(1)
	before := time.Now().Add(59 * time.Minute)
	upload, err := service.CreatePublicUpload(context.Background(), "default", "alice", PresignUploadRequest{
		FileName: "a.txt", SizeBytes: &size, RoomToken: "token",
	})
	if err != nil {
		t.Fatal(err)
	}
	expires, err := time.Parse(time.RFC3339Nano, upload.Attachment.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if expires.Before(before) || expires.After(time.Now().Add(61*time.Minute)) {
		t.Fatalf("retentionHours=0 did not clamp to one hour: %s", expires)
	}
}

func TestExpirationAdvancesDatabaseStateWhenObjectStorageIsDisabled(t *testing.T) {
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "expiration-disabled.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	item := store.TransferAttachment{
		ID:              12345,
		Scope:           ScopePublicTransfer,
		ObjectKey:       "prefix/public-transfer/expired.txt",
		FileName:        "expired.txt",
		MimeType:        "text/plain",
		SizeBytes:       1,
		Status:          StatusUploaded,
		CreatedAt:       now.Add(-2 * time.Hour),
		UpdatedAt:       now.Add(-2 * time.Hour),
		UploadExpiresAt: now.Add(-time.Hour),
		ExpiresAt:       now.Add(-time.Minute),
	}
	if err := db.InsertTransferAttachment(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	service := NewService(db, config.ObjectStorageConfig{Provider: "disabled"}, config.PublicTransferConfig{})
	if err := service.expire(context.Background()); err != nil {
		t.Fatalf("expire with disabled storage: %v", err)
	}
	got, err := db.GetTransferAttachment(context.Background(), item.ID, ScopePublicTransfer)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Status != StatusExpired {
		t.Fatalf("expired attachment = %+v, want status %s", got, StatusExpired)
	}
}

func TestCompleteSkipsHeadWhenObjectStorageIsDisabledLikeJava(t *testing.T) {
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "complete-disabled.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	hash := tokenHash("room-token")
	item := store.TransferAttachment{
		ID: 23456, Scope: ScopePublicTransfer, RoomTokenHash: &hash,
		ObjectKey: "prefix/public-transfer/pending.txt", FileName: "pending.txt",
		MimeType: "text/plain", SizeBytes: 7, Status: StatusPending,
		CreatedAt: now, UpdatedAt: now, UploadExpiresAt: now.Add(time.Hour),
		ExpiresAt: now.Add(2 * time.Hour),
	}
	if err := db.InsertTransferAttachment(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	service := NewService(db, config.ObjectStorageConfig{Provider: "disabled"}, config.PublicTransferConfig{})
	completed, err := service.CompletePublic(context.Background(), item.ID, "room-token", "default", "alice")
	if err != nil {
		t.Fatalf("complete with disabled storage: %v", err)
	}
	if completed.Status != StatusUploaded || completed.SizeBytes != item.SizeBytes {
		t.Fatalf("completed attachment = %+v", completed)
	}
}
