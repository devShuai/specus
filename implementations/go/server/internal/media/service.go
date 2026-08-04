package media

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

const (
	StateStarting   = "STARTING"
	StateCapturing  = "CAPTURING"
	StateComplete   = "COMPLETE"
	StateIncomplete = "INCOMPLETE"
	StateFailed     = "FAILED"
)

var sensitiveQueryParameter = regexp.MustCompile(`(?i)([?&](?:api_?key|access_token|auth_token|token|x-emby-token)=)[^&#]*`)

type CaptureSession interface {
	Append([]byte)
	Complete()
	Fail(string)
	Active() bool
	Externalized() bool
}

type Service struct {
	db          *store.DB
	cfg         config.MediaCaptureConfig
	storage     Storage
	logger      *slog.Logger
	uploadSlots chan struct{}
	finalizers  sync.WaitGroup
	ticketsMu   sync.Mutex
	tickets     map[string]playbackTicket
	now         func() time.Time
}

func NewService(db *store.DB, cfg config.MediaCaptureConfig, storage Storage,
	logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		db: db, cfg: cfg, storage: storage, logger: logger,
		uploadSlots: make(chan struct{}, cfg.NormalizedUploadThreads()),
		tickets:     make(map[string]playbackTicket), now: time.Now,
	}
}

func (s *Service) Ready() bool {
	return s != nil && s.storage != nil && s.storage.Ready()
}

func (s *Service) Open(ctx context.Context, clientName, route, method, sourceURL string,
	statusCode int, responseHeaders []string) CaptureSession {
	if s == nil || !s.cfg.Enabled || !s.Ready() || strings.EqualFold(method, "HEAD") {
		return noopCapture{}
	}
	normalizedSource := NormalizeSourceURL(sourceURL)
	contentType := headerValue(responseHeaders, "content-type")
	contentEncoding := headerValue(responseHeaders, "content-encoding")
	contentRangeValue := headerValue(responseHeaders, "content-range")
	kind := Classify(normalizedSource, contentType, statusCode, contentRangeValue)
	if kind == "" {
		return noopCapture{}
	}
	policy, err := s.db.HTTPRouteAccessPolicy(ctx, clientName, route)
	if err != nil || policy == nil || !policy.MediaCaptureEnabled {
		if err != nil {
			s.logger.Warn("media capture route lookup failed", "client", clientName, "route", route, "err", err)
		}
		return noopCapture{}
	}

	now := s.now().UTC()
	entityTag := headerValue(responseHeaders, "etag")
	lastModified := headerValue(responseHeaders, "last-modified")
	parsedRange := ParseContentRange(contentRangeValue)
	contentLength := nonNegativeInt64(headerValue(responseHeaders, "content-length"))
	var rangeStart, rangeEnd, totalBytes *int64
	expectedBytes := int64(-1)
	if parsedRange == nil {
		zero := int64(0)
		rangeStart = &zero
		if contentLength != nil {
			end := *contentLength - 1
			rangeEnd = &end
			total := *contentLength
			totalBytes = &total
			expectedBytes = *contentLength
		}
	} else {
		start, end := parsedRange.Start, parsedRange.End
		rangeStart, rangeEnd, totalBytes = &start, &end, parsedRange.Total
		expectedBytes = end - start + 1
	}
	normalizedMethod := strings.ToUpper(strings.TrimSpace(method))
	if normalizedMethod == "" {
		normalizedMethod = "GET"
	}
	normalizedMethod = capText(normalizedMethod, 16)
	storedEncoding := nullableCapped(contentEncoding, 128)
	resourceKey := mediaResourceKey(policy.TenantID, policy.ClientID, route, normalizedSource,
		entityTag, lastModified)
	dedup := mediaDeduplicationKey(resourceKey, normalizedMethod, kind, rangeStart, rangeEnd,
		totalBytes, stringValue(storedEncoding))
	if dedup != nil && s.hasReusableCapture(ctx, policy.TenantID, *dedup, resourceKey, kind,
		rangeStart, rangeEnd, totalBytes, expectedBytes, storedEncoding, now) {
		return externalizedNoopCapture{}
	}

	resourceID := policy.ResourceID
	capture := store.HTTPMediaCapture{
		TenantID: policy.TenantID, ClientID: policy.ClientID, ClientName: clientName,
		Route: route, ResourceID: &resourceID, SourceURL: normalizedSource,
		ResourceKey: resourceKey, DeduplicationKey: dedup, Method: normalizedMethod,
		StatusCode: statusCode, ContentType: nullableCapped(contentType, 255),
		ContentEncoding: storedEncoding, MediaKind: kind,
		EntityTag: nullableCapped(entityTag, 512), LastModified: nullableCapped(lastModified, 128),
		ContentRangeStart: rangeStart, ContentRangeEnd: rangeEnd, TotalBytes: totalBytes,
		SegmentSequence:       InferSequence(normalizedSource),
		InitializationSegment: IsInitializationSegment(normalizedSource),
		ObjectKey:             s.objectKey(policy.TenantID, route, normalizedSource), State: StateStarting,
		ResponseHeaders: strings.Join(responseHeaders, "\n"), CapturedAt: now,
		ExpiresAt: now.Add(time.Duration(maxInt64(60, s.cfg.RetentionSeconds)) * time.Second),
	}
	if err := s.db.InsertHTTPMediaCapture(ctx, &capture); err != nil {
		if dedup != nil {
			if concurrent, lookupErr := s.db.FindHTTPMediaCaptureByDedup(ctx, policy.TenantID, *dedup); lookupErr == nil && concurrent != nil && reusableCapture(*concurrent, rangeStart, rangeEnd, expectedBytes, now) {
				return externalizedNoopCapture{}
			}
		}
		s.logger.Warn("media capture row creation failed", "client", clientName, "route", route, "err", err)
		return noopCapture{}
	}
	upload, err := s.storage.BeginMultipart(ctx, capture.ObjectKey,
		stringValue(capture.ContentType), stringValue(capture.ContentEncoding))
	if err != nil {
		s.markFailed(capture.ID, capture.TenantID, err)
		return noopCapture{}
	}
	capture.UploadID = stringPtr(upload.UploadID)
	capture.State = StateCapturing
	if err := s.db.UpdateHTTPMediaCapture(ctx, capture); err != nil {
		abortErr := s.storage.AbortMultipart(context.Background(), upload)
		if abortErr != nil {
			err = fmt.Errorf("%w; abort multipart: %v", err, abortErr)
		}
		s.markFailed(capture.ID, capture.TenantID, err)
		s.logger.Warn("media capture state update failed", "id", capture.ID, "err", err)
		return noopCapture{}
	}
	return newActiveCapture(s, capture, upload, expectedBytes)
}

func (s *Service) hasReusableCapture(ctx context.Context, tenantID, deduplicationKey,
	resourceKey, mediaKind string, rangeStart, rangeEnd, totalBytes *int64,
	expectedBytes int64, contentEncoding *string, now time.Time) bool {
	keyed, err := s.db.FindHTTPMediaCaptureByDedup(ctx, tenantID, deduplicationKey)
	if err == nil && keyed != nil {
		if reusableCapture(*keyed, rangeStart, rangeEnd, expectedBytes, now) {
			return true
		}
		keyed.DeduplicationKey = nil
		_ = s.db.UpdateHTTPMediaCapture(ctx, *keyed)
	}
	captures, err := s.db.ListCompleteHTTPMediaCapturesByResource(ctx, tenantID, resourceKey)
	if err != nil {
		return false
	}
	for _, candidate := range captures {
		if candidate.MediaKind == mediaKind && equalInt64Ptr(candidate.ContentRangeStart, rangeStart) &&
			equalInt64Ptr(candidate.ContentRangeEnd, rangeEnd) && equalInt64Ptr(candidate.TotalBytes, totalBytes) &&
			candidate.CapturedBytes == expectedBytes && equalStringPtr(candidate.ContentEncoding, contentEncoding) &&
			candidate.ExpiresAt.After(now) {
			return true
		}
	}
	return false
}

func reusableCapture(capture store.HTTPMediaCapture, rangeStart, rangeEnd *int64,
	expectedBytes int64, now time.Time) bool {
	if capture.State == StateStarting || capture.State == StateCapturing {
		return true
	}
	return capture.State == StateComplete && capture.CapturedBytes == expectedBytes &&
		equalInt64Ptr(capture.ContentRangeStart, rangeStart) &&
		equalInt64Ptr(capture.ContentRangeEnd, rangeEnd) && capture.ExpiresAt.After(now)
}

func (s *Service) markFailed(id int64, tenantID string, cause error) {
	capture, err := s.db.GetHTTPMediaCapture(context.Background(), tenantID, id)
	if err != nil {
		return
	}
	now := s.now().UTC()
	message := "媒体采集失败"
	if cause != nil && strings.TrimSpace(cause.Error()) != "" {
		message = cause.Error()
	}
	capture.State = StateFailed
	capture.DeduplicationKey = nil
	capture.FailureReason = stringPtr(capText(message, 2048))
	capture.CompletedAt = &now
	if err := s.db.UpdateHTTPMediaCapture(context.Background(), *capture); err != nil {
		s.logger.Warn("mark media capture failed", "id", id, "err", err)
	}
}

func (s *Service) markComplete(id int64, tenantID, objectETag string, capturedBytes,
	expectedBytes int64, manifestBytes []byte, acceptPartial bool, completionReason string) {
	capture, err := s.db.GetHTTPMediaCapture(context.Background(), tenantID, id)
	if err != nil {
		return
	}
	now := s.now().UTC()
	retainedPartial := acceptPartial && capturedBytes > 0 && expectedBytes >= 0 && expectedBytes != capturedBytes
	complete := retainedPartial || expectedBytes < 0 || expectedBytes == capturedBytes
	if complete {
		capture.State = StateComplete
		capture.FailureReason = nil
	} else {
		capture.State = StateIncomplete
		capture.FailureReason = stringPtr(fmt.Sprintf("响应正文长度不完整，预期 %d 字节，实际 %d 字节", expectedBytes, capturedBytes))
	}
	if !complete || retainedPartial {
		capture.DeduplicationKey = nil
	}
	capture.ObjectETag = nullableCapped(objectETag, 512)
	capture.UploadID = nil
	capture.CapturedBytes = capturedBytes
	if retainedPartial && capture.ContentRangeStart != nil {
		end := *capture.ContentRangeStart + capturedBytes - 1
		capture.ContentRangeEnd = &end
	} else if capture.ContentRangeEnd == nil && capturedBytes > 0 && capture.ContentRangeStart != nil {
		end := *capture.ContentRangeStart + capturedBytes - 1
		capture.ContentRangeEnd = &end
	}
	if capture.TotalBytes == nil && capture.ContentRangeStart != nil && *capture.ContentRangeStart == 0 && complete {
		total := capturedBytes
		capture.TotalBytes = &total
	}
	capture.CompletedAt = &now
	if complete && manifestBytes != nil && isManifest(capture.MediaKind) {
		text, decodeErr := DecodeManifestBody(manifestBytes, stringValue(capture.ContentEncoding), s.cfg.ManifestMaxBytes)
		if decodeErr != nil {
			s.logger.Warn("decode captured manifest failed", "id", id, "err", decodeErr)
		} else {
			parsed := ParseManifest(capture.MediaKind, capture.SourceURL, text)
			capture.LiveStream = parsed.Live
			if parsed.Live {
				capture.ExpiresAt = now.Add(time.Duration(maxInt64(60, s.cfg.LiveWindowSeconds)) * time.Second)
				s.markLiveWindow(*capture, parsed, now)
			}
			s.saveManifestReferences(*capture, parsed, now)
		}
	}
	if err := s.db.UpdateHTTPMediaCapture(context.Background(), *capture); err != nil {
		s.logger.Warn("complete media capture row failed", "id", id, "reason", completionReason, "err", err)
	}
}

func (s *Service) markLiveWindow(manifest store.HTTPMediaCapture, parsed ParsedManifest, now time.Time) {
	expiresAt := now.Add(time.Duration(maxInt64(60, s.cfg.LiveWindowSeconds)) * time.Second)
	cutoff := now.Add(-time.Duration(maxInt64(60, s.cfg.LiveWindowSeconds)) * time.Second)
	related := make(map[int64]store.HTTPMediaCapture)
	for _, reference := range parsed.References {
		if reference.RelationType != "SEGMENT" && reference.RelationType != "INITIALIZATION" {
			continue
		}
		capture, err := s.db.LatestCompleteHTTPMediaCaptureForSource(context.Background(),
			manifest.TenantID, manifest.ClientID, manifest.Route, reference.ResolvedSourceURL)
		if err == nil {
			related[capture.ID] = *capture
		}
	}
	segments, _ := s.db.ListRecentCompleteHTTPMediaSegments(context.Background(), manifest.TenantID,
		manifest.ClientID, manifest.Route, 1000)
	for _, segment := range segments {
		if segment.CapturedAt.After(cutoff) {
			related[segment.ID] = segment
		}
	}
	for _, capture := range related {
		capture.LiveStream = true
		capture.ExpiresAt = expiresAt
		_ = s.db.UpdateHTTPMediaCapture(context.Background(), capture)
	}
}

func (s *Service) saveManifestReferences(capture store.HTTPMediaCapture, parsed ParsedManifest,
	now time.Time) {
	references := make([]store.HTTPMediaReference, 0, len(parsed.References))
	for _, reference := range parsed.References {
		references = append(references, store.HTTPMediaReference{
			TenantID: capture.TenantID, ManifestCaptureID: capture.ID,
			RelationType: reference.RelationType, SequenceIndex: reference.Sequence,
			OriginalURI:       capText(reference.OriginalURI, 2048),
			ResolvedSourceURL: capText(reference.ResolvedSourceURL, 3072), CreatedAt: now,
		})
	}
	if err := s.db.ReplaceHTTPMediaReferences(context.Background(), capture.TenantID, capture.ID, references); err != nil {
		s.logger.Warn("save media manifest references failed", "id", capture.ID, "err", err)
	}
}

func (s *Service) objectKey(tenantID, route, sourceURL string) string {
	prefix := strings.Trim(strings.TrimSpace(s.cfg.ObjectPrefix), "/")
	date := s.now().UTC().Format("2006/01/02")
	var random [16]byte
	_, _ = rand.Read(random[:])
	parts := make([]string, 0, 5)
	if prefix != "" {
		parts = append(parts, prefix)
	}
	parts = append(parts, safeObjectSegment(tenantID), date, safeObjectSegment(route),
		hex.EncodeToString(random[:])+mediaExtension(sourceURL))
	return strings.Join(parts, "/")
}

func (s *Service) Run(ctx context.Context) {
	interval := time.Duration(s.cfg.CleanupIntervalMs) * time.Millisecond
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.CleanupExpired(ctx)
			s.cleanupTickets()
		}
	}
}

func (s *Service) CleanupExpired(ctx context.Context) {
	if s == nil || !s.cfg.Enabled {
		return
	}
	now := s.now().UTC()
	captures, err := s.db.ListExpiredHTTPMediaCaptures(ctx, now, 200)
	if err != nil {
		s.logger.Warn("list expired media captures failed", "err", err)
		return
	}
	for _, capture := range captures {
		if !capture.LiveStream && (capture.State == StateComplete || capture.State == StateIncomplete) {
			configuredExpiry := capture.CapturedAt.Add(time.Duration(maxInt64(60, s.cfg.RetentionSeconds)) * time.Second)
			if configuredExpiry.After(now) && configuredExpiry.After(capture.ExpiresAt) {
				capture.ExpiresAt = configuredExpiry
				_ = s.db.UpdateHTTPMediaCapture(ctx, capture)
				continue
			}
		}
		var storageErr error
		if s.Ready() {
			switch {
			case (capture.State == StateStarting || capture.State == StateCapturing) && capture.UploadID != nil:
				storageErr = s.storage.AbortMultipart(ctx, MultipartUpload{ObjectKey: capture.ObjectKey, UploadID: *capture.UploadID})
			case capture.State == StateComplete || capture.State == StateIncomplete:
				storageErr = s.storage.Delete(ctx, capture.ObjectKey)
			}
		}
		if storageErr != nil {
			s.logger.Warn("delete expired media capture object failed", "id", capture.ID, "err", storageErr)
			continue
		}
		if err := s.db.DeleteHTTPMediaCapture(ctx, capture.TenantID, capture.ID); err != nil {
			s.logger.Warn("delete expired media capture failed", "id", capture.ID, "err", err)
		}
	}
}

func (s *Service) Close(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		s.finalizers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type noopCapture struct{}

func (noopCapture) Append([]byte)      {}
func (noopCapture) Complete()          {}
func (noopCapture) Fail(string)        {}
func (noopCapture) Active() bool       { return false }
func (noopCapture) Externalized() bool { return false }

type externalizedNoopCapture struct{ noopCapture }

func (externalizedNoopCapture) Externalized() bool { return true }

type capturePart struct {
	number int
	data   []byte
}

type activeCapture struct {
	service         *Service
	capture         store.HTTPMediaCapture
	upload          MultipartUpload
	expectedBytes   int64
	partialUsable   bool
	partSize        int
	jobs            chan capturePart
	workers         sync.WaitGroup
	mu              sync.Mutex
	resultMu        sync.Mutex
	terminal        bool
	partBuffer      bytes.Buffer
	manifestBuffer  *bytes.Buffer
	manifestDropped bool
	nextPart        int
	capturedBytes   int64
	parts           []CompletedPart
	uploadErr       error
}

func newActiveCapture(service *Service, capture store.HTTPMediaCapture,
	upload MultipartUpload, expectedBytes int64) *activeCapture {
	// Count the session before exposing it to the caller. Adding only when finalization
	// starts allows Close to observe a zero counter while a response is still active.
	service.finalizers.Add(1)
	partSize := service.cfg.NormalizedPartSizeBytes()
	if partSize > 512*1024*1024 {
		partSize = 512 * 1024 * 1024
	}
	result := &activeCapture{
		service: service, capture: capture, upload: upload, expectedBytes: expectedBytes,
		partialUsable: !isManifest(capture.MediaKind), partSize: int(partSize),
		jobs: make(chan capturePart, service.cfg.NormalizedMaxInflightParts()), nextPart: 1,
	}
	result.partBuffer.Grow(result.partSize)
	if isManifest(capture.MediaKind) {
		result.manifestBuffer = &bytes.Buffer{}
	}
	for index := 0; index < service.cfg.NormalizedMaxInflightParts(); index++ {
		result.workers.Add(1)
		go result.uploadWorker()
	}
	return result
}

func (c *activeCapture) Append(data []byte) {
	if len(data) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal || c.hasUploadError() {
		return
	}
	if c.manifestBuffer != nil && !c.manifestDropped {
		if c.service.cfg.ManifestMaxBytes > 0 && int64(c.manifestBuffer.Len()+len(data)) <= c.service.cfg.ManifestMaxBytes {
			_, _ = c.manifestBuffer.Write(data)
		} else {
			c.manifestBuffer.Reset()
			c.manifestDropped = true
		}
	}
	for len(data) > 0 {
		remaining := c.partSize - c.partBuffer.Len()
		length := minInt(len(data), remaining)
		_, _ = c.partBuffer.Write(data[:length])
		c.capturedBytes += int64(length)
		data = data[length:]
		if c.partBuffer.Len() == c.partSize {
			c.submitPartLocked()
		}
	}
}

func (c *activeCapture) Complete() { c.finish(false, "") }

func (c *activeCapture) Fail(reason string) {
	c.mu.Lock()
	hasPartial := c.partialUsable && c.capturedBytes > 0
	c.mu.Unlock()
	if hasPartial {
		c.finish(true, reason)
		return
	}
	c.abort(errors.New(firstText(strings.TrimSpace(reason), "媒体响应中断")))
}

func (c *activeCapture) Active() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.terminal
}

func (c *activeCapture) Externalized() bool { return true }

func (c *activeCapture) finish(acceptPartial bool, reason string) {
	c.mu.Lock()
	if c.terminal {
		c.mu.Unlock()
		return
	}
	c.terminal = true
	if c.partBuffer.Len() > 0 {
		c.submitPartLocked()
	}
	close(c.jobs)
	capturedBytes := c.capturedBytes
	var manifest []byte
	if c.manifestBuffer != nil && !c.manifestDropped {
		manifest = append([]byte(nil), c.manifestBuffer.Bytes()...)
	}
	c.mu.Unlock()
	go func() {
		defer c.service.finalizers.Done()
		c.workers.Wait()
		c.resultMu.Lock()
		parts := append([]CompletedPart(nil), c.parts...)
		uploadErr := c.uploadErr
		c.resultMu.Unlock()
		if capturedBytes == 0 {
			_ = c.service.storage.AbortMultipart(context.Background(), c.upload)
			c.service.markFailed(c.capture.ID, c.capture.TenantID, errors.New("媒体响应正文为空"))
			return
		}
		if uploadErr != nil {
			c.abortAndFail(uploadErr)
			return
		}
		sort.Slice(parts, func(i, j int) bool { return parts[i].PartNumber < parts[j].PartNumber })
		etag, err := c.service.storage.CompleteMultipart(context.Background(), c.upload, parts)
		if err != nil {
			c.abortAndFail(err)
			return
		}
		c.service.markComplete(c.capture.ID, c.capture.TenantID, etag, capturedBytes,
			c.expectedBytes, manifest, acceptPartial, reason)
	}()
}

func (c *activeCapture) abort(cause error) {
	c.mu.Lock()
	if c.terminal {
		c.mu.Unlock()
		return
	}
	c.terminal = true
	close(c.jobs)
	c.mu.Unlock()
	go func() {
		defer c.service.finalizers.Done()
		c.workers.Wait()
		c.abortAndFail(cause)
	}()
}

func (c *activeCapture) abortAndFail(cause error) {
	if abortErr := c.service.storage.AbortMultipart(context.Background(), c.upload); abortErr != nil {
		cause = fmt.Errorf("%w; abort multipart: %v", cause, abortErr)
	}
	c.service.markFailed(c.capture.ID, c.capture.TenantID, cause)
}

func (c *activeCapture) submitPartLocked() {
	data := append([]byte(nil), c.partBuffer.Bytes()...)
	c.partBuffer.Reset()
	part := capturePart{number: c.nextPart, data: data}
	c.nextPart++
	c.jobs <- part
}

func (c *activeCapture) uploadWorker() {
	defer c.workers.Done()
	for part := range c.jobs {
		c.service.uploadSlots <- struct{}{}
		completed, err := c.service.storage.UploadPart(context.Background(), c.upload, part.number, part.data)
		<-c.service.uploadSlots
		c.resultMu.Lock()
		if err != nil {
			if c.uploadErr == nil {
				c.uploadErr = err
			}
		} else {
			c.parts = append(c.parts, completed)
		}
		c.resultMu.Unlock()
	}
}

func (c *activeCapture) hasUploadError() bool {
	c.resultMu.Lock()
	defer c.resultMu.Unlock()
	return c.uploadErr != nil
}

func mediaResourceKey(tenantID string, clientID int64, route, sourceURL,
	entityTag, lastModified string) string {
	version := strings.TrimSpace(entityTag)
	if version == "" {
		version = strings.TrimSpace(lastModified)
	}
	value := tenantID + "\n" + strconv.FormatInt(clientID, 10) + "\n" + route + "\n" + sourceURL + "\n" + version
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func mediaDeduplicationKey(resourceKey, method, kind string, start, end, total *int64,
	contentEncoding string) *string {
	if isManifest(kind) || start == nil || end == nil || *end < *start {
		return nil
	}
	totalText := ""
	if total != nil {
		totalText = strconv.FormatInt(*total, 10)
	}
	value := resourceKey + "\n" + method + "\n" + kind + "\n" + strconv.FormatInt(*start, 10) +
		"\n" + strconv.FormatInt(*end, 10) + "\n" + totalText + "\n" + strings.ToLower(contentEncoding)
	digest := sha256.Sum256([]byte(value))
	result := hex.EncodeToString(digest[:])
	return &result
}

func mediaExtension(sourceURL string) string {
	extension := strings.ToLower(filepath.Ext(pathOnly(sourceURL)))
	if matched, _ := regexp.MatchString(`^\.[a-z0-9]{1,10}$`, extension); matched {
		return extension
	}
	return ".bin"
}

func safeObjectSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "default"
	}
	value = regexp.MustCompile(`[^A-Za-z0-9._-]`).ReplaceAllString(value, "_")
	return capText(value, 80)
}

func RedactSourceURL(sourceURL string) string {
	return sensitiveQueryParameter.ReplaceAllString(sourceURL, `${1}***`)
}

func headerValue(headers []string, name string) string {
	for _, header := range headers {
		if separator := strings.IndexByte(header, ':'); separator > 0 &&
			strings.EqualFold(strings.TrimSpace(header[:separator]), name) {
			return strings.TrimSpace(header[separator+1:])
		}
	}
	return ""
}

func nonNegativeInt64(value string) *int64 {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || parsed < 0 {
		return nil
	}
	return &parsed
}

func isManifest(kind string) bool { return kind == KindHLSManifest || kind == KindDASHManifest }

func capText(value string, maxLength int) string {
	if maxLength <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= maxLength {
		return value
	}
	return string(runes[:maxLength])
}

func nullableCapped(value string, maxLength int) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	result := capText(value, maxLength)
	return &result
}

func stringPtr(value string) *string { return &value }
func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func equalInt64Ptr(first, second *int64) bool {
	return first == nil && second == nil || first != nil && second != nil && *first == *second
}

func equalStringPtr(first, second *string) bool {
	return first == nil && second == nil || first != nil && second != nil && *first == *second
}

func maxInt64(first, second int64) int64 {
	if first > second {
		return first
	}
	return second
}

func minInt(first, second int) int {
	if first < second {
		return first
	}
	return second
}

func firstText(first, second string) string {
	if strings.TrimSpace(first) != "" {
		return first
	}
	return second
}
