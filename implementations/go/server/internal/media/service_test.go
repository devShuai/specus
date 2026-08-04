package media

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

type memoryMediaStorage struct {
	mu      sync.Mutex
	nextID  int
	parts   map[string]map[int][]byte
	objects map[string][]byte
}

func newMemoryMediaStorage() *memoryMediaStorage {
	return &memoryMediaStorage{parts: make(map[string]map[int][]byte), objects: make(map[string][]byte)}
}

func (*memoryMediaStorage) Ready() bool { return true }

func (s *memoryMediaStorage) BeginMultipart(_ context.Context, objectKey, _, _ string) (MultipartUpload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	id := fmt.Sprintf("upload-%d", s.nextID)
	s.parts[id] = make(map[int][]byte)
	return MultipartUpload{ObjectKey: objectKey, UploadID: id}, nil
}

func (s *memoryMediaStorage) UploadPart(_ context.Context, upload MultipartUpload,
	partNumber int, data []byte) (CompletedPart, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.parts[upload.UploadID][partNumber] = append([]byte(nil), data...)
	return CompletedPart{PartNumber: partNumber, ETag: fmt.Sprintf("part-%d", partNumber)}, nil
}

func (s *memoryMediaStorage) CompleteMultipart(_ context.Context, upload MultipartUpload,
	parts []CompletedPart) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sorted := append([]CompletedPart(nil), parts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PartNumber < sorted[j].PartNumber })
	var object []byte
	for _, part := range sorted {
		object = append(object, s.parts[upload.UploadID][part.PartNumber]...)
	}
	s.objects[upload.ObjectKey] = object
	delete(s.parts, upload.UploadID)
	return "object-etag", nil
}

func (s *memoryMediaStorage) AbortMultipart(_ context.Context, upload MultipartUpload) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.parts, upload.UploadID)
	return nil
}

func (s *memoryMediaStorage) Open(_ context.Context, objectKey string, start, end int64) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	object, ok := s.objects[objectKey]
	if !ok {
		return nil, errors.New("object not found")
	}
	if start >= 0 && end >= start {
		if start >= int64(len(object)) {
			return nil, errors.New("range outside object")
		}
		end = minInt64(end, int64(len(object))-1)
		object = object[start : end+1]
	}
	return io.NopCloser(bytes.NewReader(append([]byte(nil), object...))), nil
}

func (s *memoryMediaStorage) ReadAll(_ context.Context, objectKey string, maxBytes int64) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	object, ok := s.objects[objectKey]
	if !ok {
		return nil, errors.New("object not found")
	}
	if int64(len(object)) > maxBytes {
		return nil, errors.New("object too large")
	}
	return append([]byte(nil), object...), nil
}

func (s *memoryMediaStorage) Delete(_ context.Context, objectKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.objects, objectKey)
	return nil
}

func TestCaptureStreamsMultipartAndDeduplicatesCompletedRange(t *testing.T) {
	db := openMediaTestDB(t)
	storage := newMemoryMediaStorage()
	cfg := config.Default().MediaCapture
	cfg.Enabled = true
	cfg.RetentionSeconds = 60
	service := NewService(db, cfg, storage, slog.New(slog.NewTextHandler(io.Discard, nil)))
	body := bytes.Repeat([]byte{0x5a}, int(cfg.NormalizedPartSizeBytes())+31)
	headers := []string{
		"Content-Type: video/mp4",
		fmt.Sprintf("Content-Length: %d", len(body)),
		`ETag: "version-1"`,
	}
	session := service.Open(context.Background(), "client-a", "media", "GET", "/movie.mp4",
		200, headers)
	if !session.Active() || !session.Externalized() {
		t.Fatalf("capture session active=%t externalized=%t", session.Active(), session.Externalized())
	}
	session.Append(body[:1024])
	session.Append(body[1024:])
	session.Complete()
	waitForMediaFinalizers(t, service)

	items, total, err := db.ListHTTPMediaCaptures(context.Background(), store.HTTPMediaCaptureFilter{
		TenantID: "tenant-a", Page: 0, Size: 10,
	})
	if err != nil {
		t.Fatalf("ListHTTPMediaCaptures: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].State != StateComplete || items[0].CapturedBytes != int64(len(body)) {
		t.Fatalf("captures total=%d items=%#v", total, items)
	}
	storage.mu.Lock()
	stored := append([]byte(nil), storage.objects[items[0].ObjectKey]...)
	storage.mu.Unlock()
	if !bytes.Equal(stored, body) {
		t.Fatalf("stored object length=%d want=%d", len(stored), len(body))
	}

	duplicate := service.Open(context.Background(), "client-a", "media", "GET", "/movie.mp4", 200, headers)
	if duplicate.Active() || !duplicate.Externalized() {
		t.Fatalf("duplicate active=%t externalized=%t", duplicate.Active(), duplicate.Externalized())
	}
	_, total, err = db.ListHTTPMediaCaptures(context.Background(), store.HTTPMediaCaptureFilter{
		TenantID: "tenant-a", Page: 0, Size: 10,
	})
	if err != nil || total != 1 {
		t.Fatalf("deduplicated total=%d err=%v", total, err)
	}
}

func TestCaptureRetainsReceivedRangeWhenResponseIsCancelled(t *testing.T) {
	db := openMediaTestDB(t)
	storage := newMemoryMediaStorage()
	cfg := config.Default().MediaCapture
	cfg.Enabled = true
	service := NewService(db, cfg, storage, slog.New(slog.NewTextHandler(io.Discard, nil)))
	session := service.Open(context.Background(), "client-a", "media", "GET", "/movie.mp4", 206,
		[]string{"Content-Type: video/mp4", "Content-Range: bytes 100-199/1000", "Content-Length: 100"})
	session.Append(bytes.Repeat([]byte{1}, 40))
	session.Fail("player cancelled")
	waitForMediaFinalizers(t, service)
	items, total, err := db.ListHTTPMediaCaptures(context.Background(), store.HTTPMediaCaptureFilter{
		TenantID: "tenant-a", Page: 0, Size: 10,
	})
	if err != nil || total != 1 {
		t.Fatalf("list total=%d err=%v", total, err)
	}
	capture := items[0]
	if capture.State != StateComplete || capture.CapturedBytes != 40 || capture.ContentRangeEnd == nil ||
		*capture.ContentRangeEnd != 139 || capture.DeduplicationKey != nil {
		t.Fatalf("retained capture = %#v", capture)
	}
}

func TestCaptureRequiresPerRouteMediaFlag(t *testing.T) {
	db := openMediaTestDB(t)
	route, err := db.GetHTTPRoute(context.Background(), 201)
	if err != nil {
		t.Fatal(err)
	}
	route.MediaCaptureEnabled = false
	if err := db.UpdateHTTPRoute(context.Background(), *route); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default().MediaCapture
	cfg.Enabled = true
	service := NewService(db, cfg, newMemoryMediaStorage(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	session := service.Open(context.Background(), "client-a", "media", "GET", "/movie.mp4", 200,
		[]string{"Content-Type: video/mp4", "Content-Length: 5"})
	if session.Active() || session.Externalized() {
		t.Fatalf("disabled route capture active=%t externalized=%t", session.Active(), session.Externalized())
	}
	_, total, err := db.ListHTTPMediaCaptures(context.Background(), store.HTTPMediaCaptureFilter{
		TenantID: "tenant-a", Page: 0, Size: 10,
	})
	if err != nil || total != 0 {
		t.Fatalf("disabled route persisted %d captures: %v", total, err)
	}
}

func TestCaptureRequiresGlobalMediaFlag(t *testing.T) {
	db := openMediaTestDB(t)
	cfg := config.Default().MediaCapture
	service := NewService(db, cfg, newMemoryMediaStorage(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	session := service.Open(context.Background(), "client-a", "media", "GET", "/movie.mp4", 200,
		[]string{"Content-Type: video/mp4", "Content-Length: 5"})
	if session.Active() || session.Externalized() {
		t.Fatalf("globally disabled capture active=%t externalized=%t", session.Active(), session.Externalized())
	}
	_, total, err := db.ListHTTPMediaCaptures(context.Background(), store.HTTPMediaCaptureFilter{
		TenantID: "tenant-a", Page: 0, Size: 10,
	})
	if err != nil || total != 0 {
		t.Fatalf("globally disabled capture persisted %d rows: %v", total, err)
	}
}

func TestCloseWaitsForActiveCaptureSession(t *testing.T) {
	db := openMediaTestDB(t)
	cfg := config.Default().MediaCapture
	cfg.Enabled = true
	service := NewService(db, cfg, newMemoryMediaStorage(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	session := service.Open(context.Background(), "client-a", "media", "GET", "/movie.mp4", 200,
		[]string{"Content-Type: video/mp4", "Content-Length: 5"})
	if !session.Active() {
		t.Fatal("capture session did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := service.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close while capture active = %v, want deadline exceeded", err)
	}
	session.Append([]byte("abcde"))
	session.Complete()
	waitForMediaFinalizers(t, service)
}

func TestPlaybackAssemblesRangeAcrossObjectsAndReportsHoles(t *testing.T) {
	db := openMediaTestDB(t)
	storage := newMemoryMediaStorage()
	cfg := config.Default().MediaCapture
	service := NewService(db, cfg, storage, slog.New(slog.NewTextHandler(io.Discard, nil)))
	first := insertPlaybackCapture(t, db, storage, "resource-a", "part-a", 0, 4, 10, []byte("abcde"))
	_ = insertPlaybackCapture(t, db, storage, "resource-a", "part-b", 5, 9, 10, []byte("fghij"))
	plan, err := service.Plan(context.Background(), first, "bytes=3-7")
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !plan.Partial || plan.Start != 3 || plan.End != 7 || len(plan.Slices) != 2 {
		t.Fatalf("plan = %#v", plan)
	}
	var output bytes.Buffer
	if err := service.Stream(context.Background(), plan, &output); err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if output.String() != "defgh" {
		t.Fatalf("streamed = %q", output.String())
	}
	if coverage := EvaluateCoverage([]store.HTTPMediaCapture{first}); coverage.Playable || coverage.Reason != "采集数据不完整，缺少字节 5" {
		t.Fatalf("sparse coverage = %#v", coverage)
	}
}

func TestPlaybackTicketExpiresAndCannotCrossTenantBoundary(t *testing.T) {
	db := openMediaTestDB(t)
	storage := newMemoryMediaStorage()
	cfg := config.Default().MediaCapture
	service := NewService(db, cfg, storage, slog.New(slog.NewTextHandler(io.Discard, nil)))
	capture := insertPlaybackCapture(t, db, storage, "ticket-resource", "ticket-object", 0, 4, 5, []byte("abcde"))
	ticket, err := service.CreateTicket(context.Background(), capture, true)
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	resolved, err := service.ResolveTicket(context.Background(), ticket.Ticket)
	if err != nil || resolved.Capture.ID != capture.ID || !resolved.BackfillMissing {
		t.Fatalf("ResolveTicket=%#v err=%v", resolved, err)
	}
	service.ticketsMu.Lock()
	service.tickets["cross-tenant"] = playbackTicket{
		CaptureID: capture.ID, TenantID: "tenant-b", ExpiresAt: time.Now().Add(time.Minute),
	}
	service.ticketsMu.Unlock()
	if _, err := service.ResolveTicket(context.Background(), "cross-tenant"); err == nil {
		t.Fatal("tenant-bound ticket resolved a capture from another tenant")
	}
	service.now = func() time.Time { return resolved.ExpiresAt.Add(time.Second) }
	if _, err := service.ResolveTicket(context.Background(), ticket.Ticket); err == nil {
		t.Fatal("expired playback ticket still resolved")
	}
}

func TestCleanupDeletesExpiredObjectAndRowButRetainsUnexpiredFailure(t *testing.T) {
	db := openMediaTestDB(t)
	storage := newMemoryMediaStorage()
	cfg := config.Default().MediaCapture
	cfg.Enabled = true
	cfg.RetentionSeconds = 60
	service := NewService(db, cfg, storage, slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := time.Now().UTC()
	service.now = func() time.Time { return now }
	expired := store.HTTPMediaCapture{
		TenantID: "tenant-a", ClientID: 101, ClientName: "client-a", Route: "media",
		SourceURL: "/expired.mp4", ResourceKey: "expired-resource", Method: "GET", StatusCode: 200,
		MediaKind: KindProgressive, CapturedBytes: 5, ObjectKey: "expired-object", State: StateComplete,
		CapturedAt: now.Add(-2 * time.Hour), CompletedAt: timePtr(now.Add(-2 * time.Hour)),
		ExpiresAt: now.Add(-time.Minute),
	}
	if err := db.InsertHTTPMediaCapture(context.Background(), &expired); err != nil {
		t.Fatal(err)
	}
	failure := store.HTTPMediaCapture{
		TenantID: "tenant-a", ClientID: 101, ClientName: "client-a", Route: "media",
		SourceURL: "/failed.mp4", ResourceKey: "failed-resource", Method: "GET", StatusCode: 200,
		MediaKind: KindProgressive, ObjectKey: "failed-object", State: StateFailed,
		FailureReason: stringPtr("upload failed"), CapturedAt: now, CompletedAt: &now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := db.InsertHTTPMediaCapture(context.Background(), &failure); err != nil {
		t.Fatal(err)
	}
	storage.mu.Lock()
	storage.objects[expired.ObjectKey] = []byte("abcde")
	storage.mu.Unlock()

	service.CleanupExpired(context.Background())

	if _, err := db.GetHTTPMediaCapture(context.Background(), expired.TenantID, expired.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired capture row still exists: %v", err)
	}
	storage.mu.Lock()
	_, objectExists := storage.objects[expired.ObjectKey]
	storage.mu.Unlock()
	if objectExists {
		t.Fatal("expired RustFS object was not deleted")
	}
	retained, err := db.GetHTTPMediaCapture(context.Background(), failure.TenantID, failure.ID)
	if err != nil || retained.State != StateFailed || retained.FailureReason == nil {
		t.Fatalf("unexpired failure was not retained: %#v err=%v", retained, err)
	}
}

func openMediaTestDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "media.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC()
	account := store.ClientAccount{ID: 101, TenantID: "tenant-a", OwnerUsername: "owner-a",
		ClientName: "client-a", PasswordHash: "hash", Enabled: true,
		ConnectionRateLimitPerMinute: 60, CreatedAt: now, UpdatedAt: now}
	if err := db.InsertClient(context.Background(), account); err != nil {
		t.Fatalf("insert client: %v", err)
	}
	if err := db.InsertHTTPRoute(context.Background(), store.HTTPRouteMapping{
		ID: 201, TenantID: account.TenantID, ClientID: account.ID, ClientName: account.ClientName,
		Route: "media", TargetBaseURL: "http://127.0.0.1:8096", Enabled: true,
		MediaCaptureEnabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("insert route: %v", err)
	}
	return db
}

func waitForMediaFinalizers(t *testing.T, service *Service) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := service.Close(ctx); err != nil {
		t.Fatalf("wait media finalizers: %v", err)
	}
}

func insertPlaybackCapture(t *testing.T, db *store.DB, storage *memoryMediaStorage,
	resourceKey, objectKey string, start, end, total int64, data []byte) store.HTTPMediaCapture {
	t.Helper()
	now := time.Now().UTC()
	capture := store.HTTPMediaCapture{
		TenantID: "tenant-a", ClientID: 101, ClientName: "client-a", Route: "media",
		SourceURL: "/movie.mp4", ResourceKey: resourceKey, Method: "GET", StatusCode: 206,
		ContentType: stringPtr("video/mp4"), MediaKind: KindProgressive,
		ContentRangeStart: &start, ContentRangeEnd: &end, TotalBytes: &total,
		CapturedBytes: int64(len(data)), ObjectKey: objectKey, State: StateComplete,
		CapturedAt: now, CompletedAt: &now, ExpiresAt: now.Add(time.Hour),
	}
	if err := db.InsertHTTPMediaCapture(context.Background(), &capture); err != nil {
		t.Fatalf("insert media capture: %v", err)
	}
	storage.mu.Lock()
	storage.objects[objectKey] = append([]byte(nil), data...)
	storage.mu.Unlock()
	return capture
}

func timePtr(value time.Time) *time.Time { return &value }
