package management

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/devShuai/specus/implementations/go/server/internal/media"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func (a *API) handleListMediaCaptures(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	if a.mediaCapture == nil {
		writeError(w, http.StatusServiceUnavailable, "媒体采集服务不可用")
		return
	}
	clientID := queryInt64Ptr(r, "clientId")
	visibleIDs, err := a.visibleClientIDs(r.Context(), principal)
	if err != nil {
		a.fail(w, err)
		return
	}
	if clientID != nil && !containsInt64(visibleIDs, *clientID) {
		writeJSON(w, http.StatusOK, media.CapturePage{
			Items: []media.CaptureView{}, Page: maxInt(queryInt(r, "page", 0), 0),
			Size: normalizedMediaPageSize(queryInt(r, "size", 50)),
		})
		return
	}
	filter := store.HTTPMediaCaptureFilter{
		TenantID: principal.TenantID, ClientID: clientID, Route: r.URL.Query().Get("route"),
		Page: queryInt(r, "page", 0), Size: normalizedMediaPageSize(queryInt(r, "size", 50)),
	}
	if !principal.Admin {
		filter.ClientIDs = visibleIDs
	}
	page, err := a.mediaCapture.ListViews(r.Context(), filter)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (a *API) handleCreateMediaPlaybackTicket(w http.ResponseWriter, r *http.Request) {
	capture, ok := a.requireAccessibleMediaCapture(w, r)
	if !ok {
		return
	}
	ticket, err := a.mediaCapture.CreateTicket(r.Context(), *capture,
		queryBool(r, "backfillMissing", false))
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ticket)
}

func (a *API) handleAdminMediaPlay(w http.ResponseWriter, r *http.Request) {
	capture, ok := a.requireAccessibleMediaCapture(w, r)
	if !ok {
		return
	}
	a.writeMediaPlayback(w, r, *capture, false, "")
}

func (a *API) handleAdminMediaManifest(w http.ResponseWriter, r *http.Request) {
	capture, ok := a.requireAccessibleMediaCapture(w, r)
	if !ok {
		return
	}
	base := "/api/admin/traffic/media-captures/" + strconv.FormatInt(capture.ID, 10) + "/asset"
	a.writeMediaManifest(w, r, *capture, base)
}

func (a *API) handleAdminMediaAsset(w http.ResponseWriter, r *http.Request) {
	anchor, ok := a.requireAccessibleMediaCapture(w, r)
	if !ok {
		return
	}
	target, err := a.mediaCapture.LatestForSource(r.Context(), *anchor, r.URL.Query().Get("url"))
	if err != nil {
		writeError(w, http.StatusNotFound, "对应媒体分段尚未采集完成")
		return
	}
	if isMediaManifest(target.MediaKind) {
		base := "/api/admin/traffic/media-captures/" + strconv.FormatInt(target.ID, 10) + "/asset"
		a.writeMediaManifest(w, r, *target, base)
		return
	}
	a.writeMediaPlayback(w, r, *target, false, "")
}

func (a *API) handlePublicMediaPlay(w http.ResponseWriter, r *http.Request) {
	resolved, ok := a.resolveMediaTicket(w, r)
	if !ok {
		return
	}
	a.writeMediaPlayback(w, r, resolved.Capture, resolved.BackfillMissing,
		resolved.Capture.SourceURL)
}

func (a *API) handlePublicMediaManifest(w http.ResponseWriter, r *http.Request) {
	resolved, ok := a.resolveMediaTicket(w, r)
	if !ok {
		return
	}
	a.writeMediaManifest(w, r, resolved.Capture, resolved.AssetBasePath())
}

func (a *API) handlePublicMediaAsset(w http.ResponseWriter, r *http.Request) {
	resolved, ok := a.resolveMediaTicket(w, r)
	if !ok {
		return
	}
	sourceURL := r.URL.Query().Get("url")
	target, err := a.mediaCapture.LatestForSource(r.Context(), resolved.Capture, sourceURL)
	if err != nil {
		if resolved.BackfillMissing {
			redirectMediaToOrigin(w, resolved.Capture, sourceURL)
		} else {
			writeMediaCacheMiss(w, r, http.StatusNotFound, "媒体资源尚未缓存", 0)
		}
		return
	}
	if isMediaManifest(target.MediaKind) {
		a.writeMediaManifest(w, r, *target, resolved.AssetBasePath())
		return
	}
	a.writeMediaPlayback(w, r, *target, resolved.BackfillMissing, sourceURL)
}

func (a *API) requireAccessibleMediaCapture(w http.ResponseWriter,
	r *http.Request) (*store.HTTPMediaCapture, bool) {
	if a.mediaCapture == nil {
		writeError(w, http.StatusServiceUnavailable, "媒体采集服务不可用")
		return nil, false
	}
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return nil, false
	}
	id, err := pathInt(r, "id")
	if err != nil {
		a.fail(w, err)
		return nil, false
	}
	capture, err := a.db.GetHTTPMediaCapture(r.Context(), principal.TenantID, id)
	if err != nil {
		a.fail(w, store.ErrNotFound)
		return nil, false
	}
	account, err := a.db.GetClient(r.Context(), capture.ClientID)
	if err != nil || !principal.canAccessClient(*account) {
		a.fail(w, store.ErrNotFound)
		return nil, false
	}
	return capture, true
}

func (a *API) resolveMediaTicket(w http.ResponseWriter, r *http.Request) (media.ResolvedTicket, bool) {
	if a.mediaCapture == nil {
		writeMediaCacheMiss(w, r, http.StatusServiceUnavailable, "媒体播放服务不可用", 0)
		return media.ResolvedTicket{}, false
	}
	resolved, err := a.mediaCapture.ResolveTicket(r.Context(), r.PathValue("ticket"))
	if err != nil {
		writeMediaCacheMiss(w, r, http.StatusNotFound, err.Error(), 0)
		return media.ResolvedTicket{}, false
	}
	return resolved, true
}

func (a *API) writeMediaManifest(w http.ResponseWriter, r *http.Request,
	capture store.HTTPMediaCapture, assetBasePath string) {
	manifest, err := a.mediaCapture.RewrittenManifest(r.Context(), capture, assetBasePath)
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeMediaCacheMiss(w, r, status, err.Error(), 0)
		return
	}
	body := []byte(manifest)
	contentType := "application/dash+xml"
	if capture.MediaKind == media.KindHLSManifest {
		contentType = "application/vnd.apple.mpegurl"
	}
	w.Header().Set("Content-Type", contentType+"; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func (a *API) writeMediaPlayback(w http.ResponseWriter, r *http.Request,
	capture store.HTTPMediaCapture, backfillMissing bool, originSourceURL string) {
	plan, err := a.mediaCapture.Plan(r.Context(), capture, r.Header.Get("Range"))
	if err != nil {
		var rangeErr *media.RangeError
		if errors.As(err, &rangeErr) {
			if backfillMissing {
				redirectMediaToOrigin(w, capture, originSourceURL)
			} else {
				writeMediaCacheMiss(w, r, http.StatusRequestedRangeNotSatisfiable,
					rangeErr.Message, rangeErr.TotalBytes)
			}
			return
		}
		writeMediaCacheMiss(w, r, http.StatusConflict, err.Error(), 0)
		return
	}
	status := http.StatusOK
	if plan.Partial {
		status = http.StatusPartialContent
	}
	w.Header().Set("Content-Type", plan.ContentType)
	if strings.TrimSpace(plan.ContentEncoding) != "" {
		w.Header().Set("Content-Encoding", plan.ContentEncoding)
	}
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Cache-Control", "private, no-store")
	if strings.TrimSpace(plan.ETag) != "" {
		w.Header().Set("ETag", plan.ETag)
	}
	if plan.Partial {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", plan.Start, plan.End, plan.TotalBytes))
	}
	w.Header().Set("Content-Length", strconv.FormatInt(plan.ContentLength(), 10))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		if err := a.mediaCapture.Stream(r.Context(), plan, w); err != nil {
			a.logger.Warn("stream cached media failed", "captureId", capture.ID, "err", err)
		}
	}
}

func writeMediaCacheMiss(w http.ResponseWriter, r *http.Request, status int,
	message string, totalBytes int64) {
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Cache-Control", "private, no-store")
	if status == http.StatusRequestedRangeNotSatisfiable && totalBytes > 0 {
		w.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(totalBytes, 10))
	}
	body := []byte(message)
	w.Header().Set("Content-Type", "text/plain;charset=UTF-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if r.Method != http.MethodHead && len(body) > 0 {
		_, _ = w.Write(body)
	}
}

func redirectMediaToOrigin(w http.ResponseWriter, capture store.HTTPMediaCapture,
	sourceURL string) {
	location := "/http/" + url.PathEscape(capture.ClientName) + "/" + url.PathEscape(capture.Route) +
		safeMediaSourceURL(sourceURL)
	w.Header().Set("Location", location)
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusTemporaryRedirect)
}

func safeMediaSourceURL(sourceURL string) string {
	normalized := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(sourceURL, "\r", ""), "\n", ""))
	if normalized == "" {
		normalized = "/"
	}
	if !strings.HasPrefix(normalized, "/") {
		normalized = "/" + normalized
	}
	parsed, err := url.Parse(normalized)
	if err == nil {
		path := parsed.EscapedPath()
		if path == "" {
			path = "/"
		}
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
		return path
	}
	path, query, _ := strings.Cut(normalized, "?")
	segments := strings.Split(path, "/")
	for index, segment := range segments {
		segments[index] = url.PathEscape(segment)
	}
	result := strings.Join(segments, "/")
	if query != "" {
		result += "?" + query
	}
	return result
}

func isMediaManifest(kind string) bool {
	return kind == media.KindHLSManifest || kind == media.KindDASHManifest
}

func normalizedMediaPageSize(size int) int {
	if size < 1 {
		return 1
	}
	if size > 200 {
		return 200
	}
	return size
}
