package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

const httpMediaCaptureColumns = `id, tenant_id, client_id, client_name, route, resource_id,
	source_url, resource_key, deduplication_key, method, status_code, content_type,
	content_encoding, media_kind, entity_tag, last_modified, content_range_start,
	content_range_end, total_bytes, captured_bytes, segment_sequence, initialization_segment,
	live_stream, object_key, upload_id, object_etag, state, failure_reason, response_headers,
	captured_at, completed_at, expires_at`

type mediaRowScanner interface {
	Scan(dest ...any) error
}

func scanHTTPMediaCapture(scanner mediaRowScanner) (HTTPMediaCapture, error) {
	var (
		capture                       HTTPMediaCapture
		resourceID, rangeStart        sql.NullInt64
		rangeEnd, totalBytes          sql.NullInt64
		segmentSequence               sql.NullInt64
		deduplicationKey, contentType sql.NullString
		contentEncoding, entityTag    sql.NullString
		lastModified, uploadID        sql.NullString
		objectETag, failureReason     sql.NullString
		responseHeaders               sql.NullString
		capturedAt, completedAt       sql.NullString
		expiresAt                     string
		initializationSegment         databaseBoolean
		liveStream                    databaseBoolean
	)
	err := scanner.Scan(
		&capture.ID, &capture.TenantID, &capture.ClientID, &capture.ClientName, &capture.Route,
		&resourceID, &capture.SourceURL, &capture.ResourceKey, &deduplicationKey, &capture.Method,
		&capture.StatusCode, &contentType, &contentEncoding, &capture.MediaKind, &entityTag,
		&lastModified, &rangeStart, &rangeEnd, &totalBytes, &capture.CapturedBytes,
		&segmentSequence, &initializationSegment, &liveStream, &capture.ObjectKey, &uploadID,
		&objectETag, &capture.State, &failureReason, &responseHeaders, &capturedAt, &completedAt,
		&expiresAt)
	if err != nil {
		return HTTPMediaCapture{}, err
	}
	capture.ResourceID = nullInt64Ptr(resourceID)
	capture.ContentRangeStart = nullInt64Ptr(rangeStart)
	capture.ContentRangeEnd = nullInt64Ptr(rangeEnd)
	capture.TotalBytes = nullInt64Ptr(totalBytes)
	capture.SegmentSequence = nullInt64Ptr(segmentSequence)
	capture.DeduplicationKey = mediaNullStringPtr(deduplicationKey)
	capture.ContentType = mediaNullStringPtr(contentType)
	capture.ContentEncoding = mediaNullStringPtr(contentEncoding)
	capture.EntityTag = mediaNullStringPtr(entityTag)
	capture.LastModified = mediaNullStringPtr(lastModified)
	capture.UploadID = mediaNullStringPtr(uploadID)
	capture.ObjectETag = mediaNullStringPtr(objectETag)
	capture.FailureReason = mediaNullStringPtr(failureReason)
	capture.ResponseHeaders = responseHeaders.String
	capture.InitializationSegment = bool(initializationSegment)
	capture.LiveStream = bool(liveStream)
	capture.CapturedAt = parseTime(capturedAt.String)
	if completedAt.Valid {
		value := parseTime(completedAt.String)
		capture.CompletedAt = &value
	}
	capture.ExpiresAt = parseTime(expiresAt)
	return capture, nil
}

func nullInt64Ptr(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	result := value.Int64
	return &result
}

func mediaNullStringPtr(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	result := value.String
	return &result
}

// InsertHTTPMediaCapture persists a capture and assigns its database identity.
func (db *DB) InsertHTTPMediaCapture(ctx context.Context, capture *HTTPMediaCapture) error {
	if capture == nil {
		return errors.New("media capture is nil")
	}
	columns := `tenant_id, client_id, client_name, route, resource_id, source_url, resource_key,
		deduplication_key, method, status_code, content_type, content_encoding, media_kind,
		entity_tag, last_modified, content_range_start, content_range_end, total_bytes,
		captured_bytes, segment_sequence, initialization_segment, live_stream, object_key,
		upload_id, object_etag, state, failure_reason, response_headers, captured_at, completed_at,
		expires_at`
	values := []any{
		defaultTenant(capture.TenantID), capture.ClientID, capture.ClientName, capture.Route,
		capture.ResourceID, capture.SourceURL, capture.ResourceKey, capture.DeduplicationKey,
		capture.Method, capture.StatusCode, capture.ContentType, capture.ContentEncoding,
		capture.MediaKind, capture.EntityTag, capture.LastModified, capture.ContentRangeStart,
		capture.ContentRangeEnd, capture.TotalBytes, capture.CapturedBytes, capture.SegmentSequence,
		capture.InitializationSegment, capture.LiveStream, capture.ObjectKey, capture.UploadID,
		capture.ObjectETag, capture.State, capture.FailureReason, capture.ResponseHeaders,
		formatTime(capture.CapturedAt), mediaNullableTime(capture.CompletedAt), formatTime(capture.ExpiresAt),
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(values)), ",")
	base := `INSERT INTO specus_http_media_capture (` + columns + `) VALUES (` + placeholders + `)`
	if db.dialect == DialectMySQL {
		result, err := db.sql.ExecContext(ctx, base, values...)
		if err != nil {
			return err
		}
		capture.ID, err = result.LastInsertId()
		return err
	}
	return db.sql.QueryRowContext(ctx, db.rebind(base+` RETURNING id`), values...).Scan(&capture.ID)
}

// UpdateHTTPMediaCapture writes mutable capture state and metadata.
func (db *DB) UpdateHTTPMediaCapture(ctx context.Context, capture HTTPMediaCapture) error {
	query := db.rebind(`UPDATE specus_http_media_capture SET deduplication_key = ?,
		content_range_start = ?, content_range_end = ?, total_bytes = ?, captured_bytes = ?,
		segment_sequence = ?, initialization_segment = ?, live_stream = ?, upload_id = ?,
		object_etag = ?, state = ?, failure_reason = ?, response_headers = ?, completed_at = ?,
		expires_at = ? WHERE id = ? AND tenant_id = ?`)
	_, err := db.sql.ExecContext(ctx, query,
		capture.DeduplicationKey, capture.ContentRangeStart, capture.ContentRangeEnd,
		capture.TotalBytes, capture.CapturedBytes, capture.SegmentSequence,
		capture.InitializationSegment, capture.LiveStream, capture.UploadID, capture.ObjectETag,
		capture.State, capture.FailureReason, capture.ResponseHeaders, mediaNullableTime(capture.CompletedAt),
		formatTime(capture.ExpiresAt), capture.ID, defaultTenant(capture.TenantID))
	return err
}

func mediaNullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return formatTime(*value)
}

// GetHTTPMediaCapture returns a tenant-bound capture by id.
func (db *DB) GetHTTPMediaCapture(ctx context.Context, tenantID string, id int64) (*HTTPMediaCapture, error) {
	query := db.rebind(`SELECT ` + httpMediaCaptureColumns + ` FROM specus_http_media_capture
		WHERE id = ? AND tenant_id = ?`)
	capture, err := scanHTTPMediaCapture(db.sql.QueryRowContext(ctx, query, id, defaultTenant(tenantID)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &capture, nil
}

func (db *DB) FindHTTPMediaCaptureByDedup(ctx context.Context, tenantID, key string) (*HTTPMediaCapture, error) {
	query := db.rebind(`SELECT ` + httpMediaCaptureColumns + ` FROM specus_http_media_capture
		WHERE tenant_id = ? AND deduplication_key = ?`)
	capture, err := scanHTTPMediaCapture(db.sql.QueryRowContext(ctx, query, defaultTenant(tenantID), key))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &capture, nil
}

func (db *DB) ListCompleteHTTPMediaCapturesByResource(ctx context.Context, tenantID, resourceKey string) ([]HTTPMediaCapture, error) {
	return db.listHTTPMediaCapturesQuery(ctx,
		`tenant_id = ? AND resource_key = ? AND state = 'COMPLETE' ORDER BY id DESC`,
		defaultTenant(tenantID), resourceKey)
}

func (db *DB) LatestCompleteHTTPMediaCaptureForSource(ctx context.Context, tenantID string,
	clientID int64, route, sourceURL string) (*HTTPMediaCapture, error) {
	query := db.rebind(`SELECT ` + httpMediaCaptureColumns + ` FROM specus_http_media_capture
		WHERE tenant_id = ? AND client_id = ? AND route = ? AND source_url = ? AND state = 'COMPLETE'
		ORDER BY id DESC LIMIT 1`)
	capture, err := scanHTTPMediaCapture(db.sql.QueryRowContext(ctx, query,
		defaultTenant(tenantID), clientID, route, sourceURL))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &capture, nil
}

func (db *DB) LatestCompleteHTTPMediaManifestForSource(ctx context.Context, tenantID string,
	clientID int64, route, sourceURL string) (*HTTPMediaCapture, error) {
	query := db.rebind(`SELECT ` + httpMediaCaptureColumns + ` FROM specus_http_media_capture
		WHERE tenant_id = ? AND client_id = ? AND route = ? AND source_url = ? AND state = 'COMPLETE'
		AND media_kind IN ('HLS_MANIFEST', 'DASH_MANIFEST') ORDER BY id DESC LIMIT 1`)
	capture, err := scanHTTPMediaCapture(db.sql.QueryRowContext(ctx, query,
		defaultTenant(tenantID), clientID, route, sourceURL))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &capture, nil
}

func (db *DB) ListRecentCompleteHTTPMediaSegments(ctx context.Context, tenantID string,
	clientID int64, route string, limit int) ([]HTTPMediaCapture, error) {
	if limit < 1 {
		limit = 1000
	}
	return db.listHTTPMediaCapturesQuery(ctx,
		`tenant_id = ? AND client_id = ? AND route = ? AND media_kind = 'MEDIA_SEGMENT' AND state = 'COMPLETE' ORDER BY id DESC LIMIT ?`,
		defaultTenant(tenantID), clientID, route, limit)
}

func (db *DB) listHTTPMediaCapturesQuery(ctx context.Context, where string, args ...any) ([]HTTPMediaCapture, error) {
	rows, err := db.sql.QueryContext(ctx, db.rebind(`SELECT `+httpMediaCaptureColumns+
		` FROM specus_http_media_capture WHERE `+where), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]HTTPMediaCapture, 0)
	for rows.Next() {
		capture, scanErr := scanHTTPMediaCapture(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, capture)
	}
	return result, rows.Err()
}

// ListHTTPMediaCaptures returns one newest-first page with tenant/ownership filters applied
// in SQL. An explicitly empty ClientIDs slice means no clients are visible.
func (db *DB) ListHTTPMediaCaptures(ctx context.Context, filter HTTPMediaCaptureFilter) ([]HTTPMediaCapture, int, error) {
	if filter.Size < 1 {
		filter.Size = 50
	}
	if filter.Size > 200 {
		filter.Size = 200
	}
	if filter.Page < 0 {
		filter.Page = 0
	}
	where := []string{"tenant_id = ?"}
	args := []any{defaultTenant(filter.TenantID)}
	if filter.ClientID != nil {
		where = append(where, "client_id = ?")
		args = append(args, *filter.ClientID)
	} else if filter.ClientIDs != nil {
		if len(filter.ClientIDs) == 0 {
			return []HTTPMediaCapture{}, 0, nil
		}
		where = append(where, "client_id IN ("+strings.TrimSuffix(strings.Repeat("?,", len(filter.ClientIDs)), ",")+")")
		for _, id := range filter.ClientIDs {
			args = append(args, id)
		}
	}
	if route := strings.TrimSpace(filter.Route); route != "" {
		where = append(where, "route = ?")
		args = append(args, route)
	}
	whereSQL := strings.Join(where, " AND ")
	var total int
	if err := db.sql.QueryRowContext(ctx, db.rebind(`SELECT COUNT(*) FROM specus_http_media_capture WHERE `+whereSQL), args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	pageArgs := append(append([]any(nil), args...), filter.Size, filter.Page*filter.Size)
	rows, err := db.sql.QueryContext(ctx, db.rebind(`SELECT `+httpMediaCaptureColumns+
		` FROM specus_http_media_capture WHERE `+whereSQL+` ORDER BY id DESC LIMIT ? OFFSET ?`), pageArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]HTTPMediaCapture, 0, filter.Size)
	for rows.Next() {
		capture, scanErr := scanHTTPMediaCapture(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		items = append(items, capture)
	}
	return items, total, rows.Err()
}

func (db *DB) ReplaceHTTPMediaReferences(ctx context.Context, tenantID string, manifestID int64,
	references []HTTPMediaReference) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, db.rebind(`DELETE FROM specus_http_media_reference
		WHERE tenant_id = ? AND manifest_capture_id = ?`), defaultTenant(tenantID), manifestID); err != nil {
		return err
	}
	query := db.rebind(`INSERT INTO specus_http_media_reference
		(tenant_id, manifest_capture_id, relation_type, sequence_index, original_uri,
		 resolved_source_url, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	for _, reference := range references {
		if _, err := tx.ExecContext(ctx, query, defaultTenant(tenantID), manifestID,
			reference.RelationType, reference.SequenceIndex, reference.OriginalURI,
			reference.ResolvedSourceURL, formatTime(reference.CreatedAt)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) ListExpiredHTTPMediaCaptures(ctx context.Context, now time.Time, limit int) ([]HTTPMediaCapture, error) {
	if limit < 1 || limit > 200 {
		limit = 200
	}
	return db.listHTTPMediaCapturesQuery(ctx,
		`state IN ('STARTING','CAPTURING','COMPLETE','INCOMPLETE','FAILED') AND expires_at < ? ORDER BY id ASC LIMIT ?`,
		formatTime(now), limit)
}

func (db *DB) DeleteHTTPMediaCapture(ctx context.Context, tenantID string, id int64) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, db.rebind(`DELETE FROM specus_http_media_reference
		WHERE tenant_id = ? AND manifest_capture_id = ?`), defaultTenant(tenantID), id); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, db.rebind(`DELETE FROM specus_http_media_capture
		WHERE tenant_id = ? AND id = ?`), defaultTenant(tenantID), id)
	if err != nil {
		return err
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr == nil && rows == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}
