package media

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

type CaptureView struct {
	ID                    int64   `json:"id"`
	ClientID              int64   `json:"clientId"`
	ClientName            string  `json:"clientName"`
	Route                 string  `json:"route"`
	ResourceID            *int64  `json:"resourceId"`
	SourceURL             string  `json:"sourceUrl"`
	Method                string  `json:"method"`
	StatusCode            int     `json:"statusCode"`
	ContentType           *string `json:"contentType"`
	MediaKind             string  `json:"mediaKind"`
	EntityTag             *string `json:"entityTag"`
	ContentRangeStart     *int64  `json:"contentRangeStart"`
	ContentRangeEnd       *int64  `json:"contentRangeEnd"`
	TotalBytes            *int64  `json:"totalBytes"`
	CapturedBytes         int64   `json:"capturedBytes"`
	SegmentSequence       *int64  `json:"segmentSequence"`
	InitializationSegment bool    `json:"initializationSegment"`
	LiveStream            bool    `json:"liveStream"`
	State                 string  `json:"state"`
	FailureReason         *string `json:"failureReason"`
	Playable              bool    `json:"playable"`
	OfflineReady          bool    `json:"offlineReady"`
	PlaybackMessage       *string `json:"playbackMessage"`
	CapturedAt            string  `json:"capturedAt"`
	CompletedAt           *string `json:"completedAt"`
	ExpiresAt             string  `json:"expiresAt"`
}

type CapturePage struct {
	Items      []CaptureView `json:"items"`
	Total      int           `json:"total"`
	Page       int           `json:"page"`
	Size       int           `json:"size"`
	TotalPages int           `json:"totalPages"`
}

func (s *Service) ListViews(ctx context.Context, filter store.HTTPMediaCaptureFilter) (CapturePage, error) {
	items, total, err := s.db.ListHTTPMediaCaptures(ctx, filter)
	if err != nil {
		return CapturePage{}, err
	}
	views := make([]CaptureView, 0, len(items))
	for _, item := range items {
		views = append(views, s.captureView(ctx, item))
	}
	size := filter.Size
	if size < 1 {
		size = 50
	}
	if size > 200 {
		size = 200
	}
	pages := 0
	if total > 0 {
		pages = (total + size - 1) / size
	}
	return CapturePage{Items: views, Total: total, Page: maxInt(filter.Page, 0), Size: size, TotalPages: pages}, nil
}

func (s *Service) captureView(ctx context.Context, capture store.HTTPMediaCapture) CaptureView {
	playable, offlineReady, message := s.playbackStatus(ctx, capture)
	var completedAt *string
	if capture.CompletedAt != nil {
		formatted := capture.CompletedAt.Format(time.RFC3339Nano)
		completedAt = &formatted
	}
	return CaptureView{
		ID: capture.ID, ClientID: capture.ClientID, ClientName: capture.ClientName,
		Route: capture.Route, ResourceID: capture.ResourceID, SourceURL: RedactSourceURL(capture.SourceURL),
		Method: capture.Method, StatusCode: capture.StatusCode, ContentType: capture.ContentType,
		MediaKind: capture.MediaKind, EntityTag: capture.EntityTag,
		ContentRangeStart: capture.ContentRangeStart, ContentRangeEnd: capture.ContentRangeEnd,
		TotalBytes: capture.TotalBytes, CapturedBytes: capture.CapturedBytes,
		SegmentSequence: capture.SegmentSequence, InitializationSegment: capture.InitializationSegment,
		LiveStream: capture.LiveStream, State: capture.State, FailureReason: capture.FailureReason,
		Playable: playable, OfflineReady: offlineReady, PlaybackMessage: message,
		CapturedAt: capture.CapturedAt.Format(time.RFC3339Nano), CompletedAt: completedAt,
		ExpiresAt: capture.ExpiresAt.Format(time.RFC3339Nano),
	}
}

func (s *Service) playbackStatus(ctx context.Context, capture store.HTTPMediaCapture) (bool, bool, *string) {
	if capture.State != StateComplete {
		return false, false, stringPtr("媒体采集尚未完成")
	}
	if capture.MediaKind == KindMediaSegment || capture.InitializationSegment {
		return false, true, stringPtr("媒体分段由 HLS/DASH 清单播放器按需加载")
	}
	if isManifest(capture.MediaKind) {
		if capture.CapturedBytes > 0 {
			return true, false, stringPtr("仅播放已缓存的媒体分段")
		}
		return false, false, stringPtr("媒体清单正文为空")
	}
	captures, err := s.db.ListCompleteHTTPMediaCapturesByResource(ctx, capture.TenantID, capture.ResourceKey)
	if err != nil {
		return false, false, stringPtr("媒体缓存状态不可用")
	}
	availability := EvaluateCoverage(captures)
	if availability.Playable {
		return true, true, nil
	}
	if capture.CapturedBytes > 0 {
		return true, false, stringPtr(availability.Reason + "；仅可播放已缓存区间")
	}
	return false, false, stringPtr(availability.Reason)
}

type PlaybackByteRange struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

type PlaybackAvailability struct {
	Playable   bool
	TotalBytes int64
	Reason     string
}

type PlaybackSlice struct {
	Capture      store.HTTPMediaCapture
	LogicalStart int64
	LogicalEnd   int64
	ObjectStart  int64
	ObjectEnd    int64
}

type PlaybackPlan struct {
	Anchor          store.HTTPMediaCapture
	ContentType     string
	ContentEncoding string
	ETag            string
	TotalBytes      int64
	Start           int64
	End             int64
	Partial         bool
	Slices          []PlaybackSlice
}

func (p PlaybackPlan) ContentLength() int64 { return p.End - p.Start + 1 }

type RangeError struct {
	Message    string
	TotalBytes int64
}

func (e *RangeError) Error() string { return e.Message }

func (s *Service) Plan(ctx context.Context, anchor store.HTTPMediaCapture,
	rangeHeader string) (PlaybackPlan, error) {
	if anchor.State != StateComplete {
		return PlaybackPlan{}, errors.New("媒体采集尚未完成")
	}
	captures, err := s.db.ListCompleteHTTPMediaCapturesByResource(ctx, anchor.TenantID, anchor.ResourceKey)
	if err != nil {
		return PlaybackPlan{}, err
	}
	captures = usableCaptures(captures)
	if len(captures) == 0 {
		return PlaybackPlan{}, errors.New("媒体采集没有可回放的数据")
	}
	totalBytes := playbackTotalBytes(captures)
	rangeRequested := strings.TrimSpace(rangeHeader) != ""
	coverage := EvaluateCoverage(captures)
	var requested PlaybackByteRange
	if !rangeRequested && !coverage.Playable {
		requested, err = initialSparseRange(anchor, captures, totalBytes)
	} else {
		requested, err = parsePlaybackRange(rangeHeader, totalBytes)
	}
	if err != nil {
		return PlaybackPlan{}, err
	}
	availableEnd, err := contiguousAvailableEnd(captures, requested.Start, requested.End, totalBytes)
	if err != nil {
		return PlaybackPlan{}, err
	}
	slices, err := playbackSlices(captures, requested.Start, availableEnd, totalBytes)
	if err != nil {
		return PlaybackPlan{}, err
	}
	contentType := stringValue(anchor.ContentType)
	if strings.TrimSpace(contentType) == "" {
		contentType = "application/octet-stream"
	}
	etag := stringValue(anchor.EntityTag)
	if strings.TrimSpace(etag) == "" {
		etag = stringValue(anchor.ObjectETag)
	}
	return PlaybackPlan{
		Anchor: anchor, ContentType: contentType, ContentEncoding: stringValue(anchor.ContentEncoding),
		ETag: etag, TotalBytes: totalBytes, Start: requested.Start, End: availableEnd,
		Partial: rangeRequested || requested.Start > 0 || availableEnd < totalBytes-1, Slices: slices,
	}, nil
}

func (s *Service) Stream(ctx context.Context, plan PlaybackPlan, output io.Writer) error {
	buffer := make([]byte, 64*1024)
	for _, slice := range plan.Slices {
		remaining := slice.ObjectEnd - slice.ObjectStart + 1
		input, err := s.storage.Open(ctx, slice.Capture.ObjectKey, slice.ObjectStart, slice.ObjectEnd)
		if err != nil {
			return err
		}
		for remaining > 0 {
			read, readErr := input.Read(buffer[:minInt64(int64(len(buffer)), remaining)])
			if read > 0 {
				written, writeErr := output.Write(buffer[:read])
				remaining -= int64(written)
				if writeErr != nil {
					input.Close()
					return writeErr
				}
				if written != read {
					input.Close()
					return io.ErrShortWrite
				}
			}
			if remaining == 0 {
				break
			}
			if readErr != nil {
				input.Close()
				if errors.Is(readErr, io.EOF) {
					return fmt.Errorf("RustFS 对象提前结束: %s", slice.Capture.ObjectKey)
				}
				return readErr
			}
		}
		if err := input.Close(); err != nil {
			return err
		}
	}
	return nil
}

func EvaluateCoverage(captures []store.HTTPMediaCapture) PlaybackAvailability {
	usable := usableCaptures(captures)
	if len(usable) == 0 {
		return PlaybackAvailability{Reason: "媒体采集没有可回放的数据"}
	}
	totalBytes := playbackTotalBytes(usable)
	if totalBytes <= 0 {
		return PlaybackAvailability{Reason: "媒体总长度未知"}
	}
	cursor := int64(0)
	for cursor < totalBytes {
		selectedEnd := int64(-1)
		for _, capture := range usable {
			start, end := normalizedStart(capture), normalizedEnd(capture)
			if start <= cursor && end >= cursor && end > selectedEnd {
				selectedEnd = end
			}
		}
		if selectedEnd < cursor {
			return PlaybackAvailability{TotalBytes: totalBytes,
				Reason: "采集数据不完整，缺少字节 " + strconv.FormatInt(cursor, 10)}
		}
		if selectedEnd >= totalBytes-1 {
			return PlaybackAvailability{Playable: true, TotalBytes: totalBytes}
		}
		cursor = selectedEnd + 1
	}
	return PlaybackAvailability{Playable: true, TotalBytes: totalBytes}
}

func (s *Service) CacheLayout(ctx context.Context, anchor store.HTTPMediaCapture) (int64, []PlaybackByteRange, error) {
	if anchor.State != StateComplete {
		return 0, nil, errors.New("媒体采集尚未完成")
	}
	captures, err := s.db.ListCompleteHTTPMediaCapturesByResource(ctx, anchor.TenantID, anchor.ResourceKey)
	if err != nil {
		return 0, nil, err
	}
	total := playbackTotalBytes(usableCaptures(captures))
	return total, mergeAvailableRanges(captures, total), nil
}

func contiguousAvailableEnd(captures []store.HTTPMediaCapture, start, requestedEnd,
	totalBytes int64) (int64, error) {
	cursor, availableEnd := start, start-1
	for cursor <= requestedEnd {
		selectedEnd := int64(-1)
		for _, capture := range captures {
			captureStart, captureEnd := normalizedStart(capture), normalizedEnd(capture)
			if captureStart <= cursor && captureEnd >= cursor && captureEnd > selectedEnd {
				selectedEnd = captureEnd
			}
		}
		if selectedEnd < cursor {
			if availableEnd < start {
				return 0, &RangeError{Message: "请求位置尚未缓存，缺少字节 " + strconv.FormatInt(cursor, 10), TotalBytes: totalBytes}
			}
			break
		}
		availableEnd = minInt64(requestedEnd, selectedEnd)
		cursor = availableEnd + 1
	}
	return availableEnd, nil
}

func initialSparseRange(anchor store.HTTPMediaCapture, captures []store.HTTPMediaCapture,
	totalBytes int64) (PlaybackByteRange, error) {
	if totalBytes <= 0 {
		return PlaybackByteRange{}, &RangeError{Message: "媒体总长度未知", TotalBytes: totalBytes}
	}
	anchorStart, anchorEnd := normalizedStart(anchor), normalizedEnd(anchor)
	if anchorStart >= 0 && anchorStart < totalBytes && anchorEnd >= anchorStart {
		for _, capture := range captures {
			if normalizedStart(capture) <= anchorStart && normalizedEnd(capture) >= anchorStart {
				return PlaybackByteRange{Start: anchorStart, End: minInt64(anchorEnd, totalBytes-1)}, nil
			}
		}
	}
	ranges := mergeAvailableRanges(captures, totalBytes)
	if len(ranges) == 0 {
		return PlaybackByteRange{}, &RangeError{Message: "媒体采集没有可回放的数据", TotalBytes: totalBytes}
	}
	return ranges[0], nil
}

func parsePlaybackRange(header string, totalBytes int64) (PlaybackByteRange, error) {
	if totalBytes <= 0 {
		return PlaybackByteRange{}, &RangeError{Message: "媒体总长度未知", TotalBytes: totalBytes}
	}
	normalized := strings.ToLower(strings.TrimSpace(header))
	if normalized == "" {
		return PlaybackByteRange{Start: 0, End: totalBytes - 1}, nil
	}
	if !strings.HasPrefix(normalized, "bytes=") || strings.Contains(normalized, ",") {
		return PlaybackByteRange{}, &RangeError{Message: "仅支持单一 bytes Range", TotalBytes: totalBytes}
	}
	value := strings.TrimSpace(strings.TrimPrefix(normalized, "bytes="))
	parts := strings.SplitN(value, "-", 2)
	if len(parts) != 2 {
		return PlaybackByteRange{}, &RangeError{Message: "Range 格式无效", TotalBytes: totalBytes}
	}
	var start, end int64
	var err error
	if strings.TrimSpace(parts[0]) == "" {
		var suffix int64
		suffix, err = strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		if err == nil && suffix > 0 {
			start, end = maxInt64(0, totalBytes-suffix), totalBytes-1
		} else {
			return PlaybackByteRange{}, &RangeError{Message: "Range 后缀长度无效", TotalBytes: totalBytes}
		}
	} else {
		start, err = strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
		if err == nil {
			if strings.TrimSpace(parts[1]) == "" {
				end = totalBytes - 1
			} else {
				end, err = strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
			}
		}
		if err != nil {
			return PlaybackByteRange{}, &RangeError{Message: "Range 格式无效", TotalBytes: totalBytes}
		}
	}
	if start < 0 || start >= totalBytes || end < start {
		return PlaybackByteRange{}, &RangeError{Message: "Range 超出媒体范围", TotalBytes: totalBytes}
	}
	return PlaybackByteRange{Start: start, End: minInt64(end, totalBytes-1)}, nil
}

func playbackSlices(captures []store.HTTPMediaCapture, start, end,
	totalBytes int64) ([]PlaybackSlice, error) {
	result := make([]PlaybackSlice, 0)
	for cursor := start; cursor <= end; {
		var selected *store.HTTPMediaCapture
		selectedEnd := int64(-1)
		for index := range captures {
			captureStart, captureEnd := normalizedStart(captures[index]), normalizedEnd(captures[index])
			if captureStart <= cursor && captureEnd >= cursor && captureEnd > selectedEnd {
				selected, selectedEnd = &captures[index], captureEnd
			}
		}
		if selected == nil {
			return nil, &RangeError{Message: "采集数据存在空洞，缺少字节 " + strconv.FormatInt(cursor, 10), TotalBytes: totalBytes}
		}
		logicalEnd := minInt64(end, selectedEnd)
		captureStart := normalizedStart(*selected)
		result = append(result, PlaybackSlice{Capture: *selected, LogicalStart: cursor,
			LogicalEnd: logicalEnd, ObjectStart: cursor - captureStart, ObjectEnd: logicalEnd - captureStart})
		cursor = logicalEnd + 1
	}
	return result, nil
}

func usableCaptures(captures []store.HTTPMediaCapture) []store.HTTPMediaCapture {
	result := make([]store.HTTPMediaCapture, 0, len(captures))
	for _, capture := range captures {
		if capture.CapturedBytes > 0 && normalizedEnd(capture) >= normalizedStart(capture) {
			result = append(result, capture)
		}
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].ID > result[j].ID })
	return result
}

func playbackTotalBytes(captures []store.HTTPMediaCapture) int64 {
	total := int64(0)
	for _, capture := range captures {
		if capture.TotalBytes != nil && *capture.TotalBytes > total {
			total = *capture.TotalBytes
		}
	}
	if total > 0 {
		return total
	}
	for _, capture := range captures {
		total = maxInt64(total, normalizedEnd(capture)+1)
	}
	return total
}

func mergeAvailableRanges(captures []store.HTTPMediaCapture, totalBytes int64) []PlaybackByteRange {
	if totalBytes <= 0 {
		return nil
	}
	ranges := make([]PlaybackByteRange, 0, len(captures))
	for _, capture := range captures {
		start, end := maxInt64(0, normalizedStart(capture)), minInt64(totalBytes-1, normalizedEnd(capture))
		if end >= start {
			ranges = append(ranges, PlaybackByteRange{Start: start, End: end})
		}
	}
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].Start < ranges[j].Start || ranges[i].Start == ranges[j].Start && ranges[i].End < ranges[j].End
	})
	if len(ranges) == 0 {
		return nil
	}
	merged := []PlaybackByteRange{ranges[0]}
	for _, next := range ranges[1:] {
		current := &merged[len(merged)-1]
		if next.Start <= current.End+1 {
			current.End = maxInt64(current.End, next.End)
		} else {
			merged = append(merged, next)
		}
	}
	return merged
}

func normalizedStart(capture store.HTTPMediaCapture) int64 {
	if capture.ContentRangeStart == nil {
		return 0
	}
	return *capture.ContentRangeStart
}

func normalizedEnd(capture store.HTTPMediaCapture) int64 {
	if capture.ContentRangeEnd != nil {
		return *capture.ContentRangeEnd
	}
	return normalizedStart(capture) + capture.CapturedBytes - 1
}

func (s *Service) LatestForSource(ctx context.Context, anchor store.HTTPMediaCapture,
	sourceURL string) (*store.HTTPMediaCapture, error) {
	return s.db.LatestCompleteHTTPMediaCaptureForSource(ctx, anchor.TenantID, anchor.ClientID,
		anchor.Route, NormalizeSourceURL(sourceURL))
}

func (s *Service) RewrittenManifest(ctx context.Context, anchor store.HTTPMediaCapture,
	assetBasePath string) (string, error) {
	latest, err := s.db.LatestCompleteHTTPMediaManifestForSource(ctx, anchor.TenantID,
		anchor.ClientID, anchor.Route, anchor.SourceURL)
	if errors.Is(err, store.ErrNotFound) && isManifest(anchor.MediaKind) {
		latest = &anchor
		err = nil
	}
	if err != nil {
		return "", err
	}
	if latest.State != StateComplete || !isManifest(latest.MediaKind) {
		return "", errors.New("媒体清单尚未采集完成")
	}
	data, err := s.storage.ReadAll(ctx, latest.ObjectKey, s.cfg.ManifestMaxBytes)
	if err != nil {
		return "", err
	}
	text, err := DecodeManifestBody(data, stringValue(latest.ContentEncoding), s.cfg.ManifestMaxBytes)
	if err != nil {
		return "", err
	}
	return RewriteManifest(latest.MediaKind, latest.SourceURL, text, assetBasePath), nil
}

type playbackTicket struct {
	CaptureID       int64
	TenantID        string
	ExpiresAt       time.Time
	BackfillMissing bool
}

type PlaybackTicketView struct {
	Ticket            string              `json:"ticket"`
	MediaKind         string              `json:"mediaKind"`
	PlayURL           string              `json:"playUrl"`
	ManifestURL       string              `json:"manifestUrl"`
	TotalBytes        int64               `json:"totalBytes"`
	InitialRangeStart *int64              `json:"initialRangeStart"`
	InitialRangeEnd   *int64              `json:"initialRangeEnd"`
	CachedRanges      []PlaybackByteRange `json:"cachedRanges"`
	BackfillMissing   bool                `json:"backfillMissing"`
	ExpiresAt         string              `json:"expiresAt"`
}

type ResolvedTicket struct {
	Token           string
	Capture         store.HTTPMediaCapture
	ExpiresAt       time.Time
	BackfillMissing bool
}

func (ticket ResolvedTicket) AssetBasePath() string {
	return "/api/public/media-playback/" + ticket.Token + "/asset"
}

func (s *Service) CreateTicket(ctx context.Context, capture store.HTTPMediaCapture,
	backfillMissing bool) (PlaybackTicketView, error) {
	if capture.State != StateComplete {
		return PlaybackTicketView{}, errors.New("媒体采集尚未完成")
	}
	if capture.MediaKind == KindMediaSegment || capture.InitializationSegment {
		return PlaybackTicketView{}, errors.New("媒体分段不能独立创建播放会话")
	}
	totalBytes := int64(0)
	cachedRanges := []PlaybackByteRange{}
	var initialStart, initialEnd *int64
	if !isManifest(capture.MediaKind) {
		captures, err := s.db.ListCompleteHTTPMediaCapturesByResource(ctx, capture.TenantID, capture.ResourceKey)
		if err != nil {
			return PlaybackTicketView{}, err
		}
		availability := EvaluateCoverage(captures)
		if !availability.Playable && capture.CapturedBytes <= 0 {
			return PlaybackTicketView{}, errors.New(availability.Reason)
		}
		totalBytes = playbackTotalBytes(usableCaptures(captures))
		cachedRanges = mergeAvailableRanges(captures, totalBytes)
		if capture.CapturedBytes > 0 && totalBytes > 0 {
			start, end := normalizedStart(capture), normalizedEnd(capture)
			start = maxInt64(0, minInt64(start, totalBytes-1))
			end = maxInt64(start, minInt64(end, totalBytes-1))
			initialStart, initialEnd = &start, &end
		}
	}
	var randomBytes [32]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return PlaybackTicketView{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(randomBytes[:])
	expiresAt := s.now().UTC().Add(time.Duration(maxInt64(60, s.cfg.PlaybackTicketTTLSeconds)) * time.Second)
	s.ticketsMu.Lock()
	s.tickets[token] = playbackTicket{CaptureID: capture.ID, TenantID: capture.TenantID,
		ExpiresAt: expiresAt, BackfillMissing: backfillMissing}
	s.ticketsMu.Unlock()
	base := "/api/public/media-playback/" + token
	return PlaybackTicketView{
		Ticket: token, MediaKind: capture.MediaKind, PlayURL: base + "/play",
		ManifestURL: base + "/manifest", TotalBytes: totalBytes,
		InitialRangeStart: initialStart, InitialRangeEnd: initialEnd, CachedRanges: cachedRanges,
		BackfillMissing: backfillMissing, ExpiresAt: expiresAt.Format(time.RFC3339Nano),
	}, nil
}

func (s *Service) ResolveTicket(ctx context.Context, token string) (ResolvedTicket, error) {
	s.ticketsMu.Lock()
	ticket, ok := s.tickets[token]
	if ok && ticket.ExpiresAt.Before(s.now()) {
		delete(s.tickets, token)
		ok = false
	}
	s.ticketsMu.Unlock()
	if !ok {
		return ResolvedTicket{}, errors.New("媒体播放票据无效或已过期")
	}
	capture, err := s.db.GetHTTPMediaCapture(ctx, ticket.TenantID, ticket.CaptureID)
	if err != nil {
		return ResolvedTicket{}, errors.New("媒体采集记录不存在")
	}
	return ResolvedTicket{Token: token, Capture: *capture, ExpiresAt: ticket.ExpiresAt,
		BackfillMissing: ticket.BackfillMissing}, nil
}

func (s *Service) cleanupTickets() {
	now := s.now()
	s.ticketsMu.Lock()
	defer s.ticketsMu.Unlock()
	for token, ticket := range s.tickets {
		if ticket.ExpiresAt.Before(now) {
			delete(s.tickets, token)
		}
	}
}

func minInt64(first, second int64) int64 {
	if first < second {
		return first
	}
	return second
}

func maxInt(first, second int) int {
	if first > second {
		return first
	}
	return second
}
