package store

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/rand"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
)

const (
	TCPDirectionPublicToClient = "PUBLIC_TO_CLIENT"
	TCPDirectionClientToPublic = "CLIENT_TO_PUBLIC"
	defaultPreviewBytes        = 256
	defaultHeaderChars         = 8192
	defaultDecodeMaxBytes      = 1024 * 1024
	detailCaptureDecisionTTL   = 2 * time.Second
)

// TrafficDetailOptions controls the optional detailed traffic capture path.
type TrafficDetailOptions struct {
	Enabled        bool
	PreviewBytes   int
	HeaderChars    int
	DecodeMaxBytes int
	SampleRate     float64
}

type detailCaptureDecision struct {
	enabled   bool
	expiresAt time.Time
}

// HTTPExchangeRecord is the hot-path input for a direct HTTP exchange.
type HTTPExchangeRecord struct {
	ClientName      string
	Route           string
	Method          string
	RelativePath    string
	RawQuery        string
	RequestHeaders  []string
	RequestBody     []byte
	StatusCode      int
	ResponseHeaders []string
	ResponseBody    []byte
	StartedAt       time.Time
	RemoteAddress   string
	Error           string
	Options         TrafficDetailOptions
}

// TCPFrameRecord is the hot-path input for one TCP payload frame.
type TCPFrameRecord struct {
	ClientName         string
	ListenPort         int
	ChannelID          string
	Direction          string
	SourceAddress      string
	SourcePort         *int
	DestinationAddress string
	DestinationPort    *int
	Payload            []byte
	Options            TrafficDetailOptions
	StreamOffset       int64
	StreamEndOffset    int64
	FrameIndex         int64
	HasStreamPosition  bool
}

// HTTPExchangeFilter narrows the paged HTTP detail query.
type HTTPExchangeFilter struct {
	TenantID         string
	ClientID         *int64
	ClientIDs        []int64
	Route            string
	ResponseBodyType string
	Field            string
	Query            string
	Page             int
	Size             int
}

// TCPFrameFilter narrows the paged TCP detail query.
type TCPFrameFilter struct {
	TenantID   string
	ClientID   *int64
	ClientIDs  []int64
	ListenPort *int
	Page       int
	Size       int
}

type tcpStreamCursor struct {
	offset atomic.Int64
	index  atomic.Int64
}

// ConfigureTrafficDetailQueue sets Java-compatible capture queue limits. Values below 1 keep
// the default protective limits.
func (db *DB) ConfigureTrafficDetailQueue(maxPending, flushBatchSize int) {
	db.detailMu.Lock()
	defer db.detailMu.Unlock()
	if maxPending > 0 {
		db.detailMaxPending = maxPending
	}
	if flushBatchSize > 0 {
		db.detailFlushBatchSize = flushBatchSize
	}
}

// RunTrafficDetailFlush periodically persists queued HTTP/TCP detail rows until ctx stops.
func (db *DB) RunTrafficDetailFlush(ctx context.Context, interval time.Duration, onError func(error)) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := db.FlushTrafficDetails(context.Background()); err != nil && onError != nil {
				onError(err)
			}
			return
		case <-ticker.C:
			if err := db.FlushTrafficDetails(ctx); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

// FlushTrafficDetails drains one configured batch of queued detail rows.
func (db *DB) FlushTrafficDetails(ctx context.Context) error {
	httpItems, tcpItems := db.drainTrafficDetails()
	for _, item := range httpItems {
		if err := db.persistHTTPExchange(ctx, item); err != nil {
			return err
		}
	}
	for _, item := range tcpItems {
		if err := db.persistTCPFrame(ctx, item); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) drainTrafficDetails() ([]HTTPExchangeRecord, []TCPFrameRecord) {
	db.detailMu.Lock()
	defer db.detailMu.Unlock()
	batchSize := db.detailFlushBatchSize
	if batchSize <= 0 {
		batchSize = 1000
	}
	httpCount := min(batchSize, len(db.pendingHTTPExchanges))
	tcpCount := min(batchSize, len(db.pendingTCPFrames))
	httpItems := append([]HTTPExchangeRecord(nil), db.pendingHTTPExchanges[:httpCount]...)
	tcpItems := append([]TCPFrameRecord(nil), db.pendingTCPFrames[:tcpCount]...)
	db.pendingHTTPExchanges = append(db.pendingHTTPExchanges[:0], db.pendingHTTPExchanges[httpCount:]...)
	db.pendingTCPFrames = append(db.pendingTCPFrames[:0], db.pendingTCPFrames[tcpCount:]...)
	return httpItems, tcpItems
}

func (db *DB) HTTPRouteDetailCaptureEnabled(ctx context.Context, clientName, route string) (bool, error) {
	account, err := db.FindClientByName(ctx, clientName)
	if err != nil || account == nil {
		return false, err
	}
	query := db.rebind(`SELECT detail_capture_enabled FROM http_route_mapping
		WHERE client_id = ? AND route = ?`)
	var enabled int
	err = db.sql.QueryRowContext(ctx, query, account.ID, route).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return enabled != 0, err
}

func (db *DB) TunnelDetailCaptureEnabled(ctx context.Context, clientName string, listenPort int) (bool, error) {
	query := db.rebind(`SELECT detail_capture_enabled FROM tunnel_mapping
		WHERE client_name = ? AND listen_port = ?`)
	var enabled int
	err := db.sql.QueryRowContext(ctx, query, clientName, listenPort).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return enabled != 0, err
}

func (db *DB) RecordHTTPExchange(ctx context.Context, record HTTPExchangeRecord) error {
	if !record.Options.Enabled || strings.TrimSpace(record.ClientName) == "" {
		return nil
	}
	route := blank(record.Route)
	if route == "" {
		return nil
	}
	enabled, err := db.cachedDetailCaptureDecision(ctx, "http:"+record.ClientName+":"+route, func() (bool, error) {
		return db.HTTPRouteDetailCaptureEnabled(ctx, record.ClientName, route)
	})
	if err != nil || !enabled {
		return err
	}
	record.Route = route
	db.enqueueHTTPExchange(record)
	return nil
}

func (db *DB) persistHTTPExchange(ctx context.Context, record HTTPExchangeRecord) error {
	route := blank(record.Route)
	account, err := db.FindClientByName(ctx, record.ClientName)
	if err != nil || account == nil {
		return err
	}
	resourceID, resourceName := db.httpResource(ctx, account, route)
	requestContentType := headerValue(record.RequestHeaders, "content-type")
	responseContentType := headerValue(record.ResponseHeaders, "content-type")
	requestPreview := bodyPreview(record.RequestBody, requestContentType, headerValue(record.RequestHeaders, "content-encoding"), decodeMaxBytes(record.Options))
	responsePreview := bodyPreview(record.ResponseBody, responseContentType, headerValue(record.ResponseHeaders, "content-encoding"), decodeMaxBytes(record.Options))
	startedAt := record.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	exchange := HTTPTrafficExchange{
		TenantID:            defaultTenant(account.TenantID),
		ClientID:            account.ID,
		ClientName:          account.ClientName,
		Route:               route,
		ResourceID:          resourceID,
		ResourceName:        resourceName,
		Method:              capString(record.Method, 16),
		RelativePath:        capString(defaultString(record.RelativePath, "/"), 1024),
		RawQuery:            capString(record.RawQuery, 2048),
		StatusCode:          record.StatusCode,
		Success:             record.Error == "",
		Error:               nullableString(capString(record.Error, 2048)),
		RemoteAddress:       nullableString(capString(record.RemoteAddress, 255)),
		RequestBytes:        int64(len(record.RequestBody)),
		ResponseBytes:       int64(len(record.ResponseBody)),
		ElapsedMs:           maxInt64(0, time.Since(startedAt).Milliseconds()),
		RequestContentType:  nullableString(capString(requestContentType, 255)),
		ResponseContentType: nullableString(capString(responseContentType, 255)),
		ResponseBodyType:    classifyHTTPBody(responseContentType, len(record.ResponseBody)),
		RequestHeaders:      capString(joinHeaders(record.RequestHeaders), headerChars(record.Options)),
		ResponseHeaders:     capString(joinHeaders(record.ResponseHeaders), headerChars(record.Options)),
		RequestPreviewText:  requestPreview.text,
		ResponsePreviewText: responsePreview.text,
		RequestTruncated:    requestPreview.truncated,
		ResponseTruncated:   responsePreview.truncated,
		CapturedAt:          time.Now(),
	}
	return db.InsertHTTPExchange(ctx, exchange)
}

func (db *DB) RecordTCPFrame(ctx context.Context, record TCPFrameRecord) error {
	if !record.Options.Enabled || strings.TrimSpace(record.ClientName) == "" || record.ListenPort <= 0 {
		return nil
	}
	enabled, err := db.cachedDetailCaptureDecision(ctx,
		"tcp:"+record.ClientName+":"+strconv.Itoa(record.ListenPort),
		func() (bool, error) {
			return db.TunnelDetailCaptureEnabled(ctx, record.ClientName, record.ListenPort)
		})
	if err != nil || !enabled {
		return err
	}
	offset, endOffset, frameIndex := db.nextTCPFramePosition(record.ClientName, record.ListenPort,
		record.ChannelID, record.Direction, int64(len(record.Payload)))
	if frameIndex > 0 && !sampleAllowed(record.Options.SampleRate) {
		return nil
	}
	record.StreamOffset = offset
	record.StreamEndOffset = endOffset
	record.FrameIndex = frameIndex
	record.HasStreamPosition = true
	db.enqueueTCPFrame(record)
	return nil
}

func (db *DB) persistTCPFrame(ctx context.Context, record TCPFrameRecord) error {
	account, err := db.FindClientByName(ctx, record.ClientName)
	if err != nil || account == nil {
		return err
	}
	resourceID, resourceName := db.tcpResource(ctx, account, record.ListenPort)
	offset, endOffset, frameIndex := record.StreamOffset, record.StreamEndOffset, record.FrameIndex
	if !record.HasStreamPosition {
		offset, endOffset, frameIndex = db.nextTCPFramePosition(record.ClientName, record.ListenPort,
			record.ChannelID, record.Direction, int64(len(record.Payload)))
	}
	previewHex, previewText, truncated := tcpPreview(record.Payload, previewBytes(record.Options))
	frame := TCPTrafficFrame{
		TenantID:           defaultTenant(account.TenantID),
		ClientID:           account.ID,
		ClientName:         account.ClientName,
		ListenPort:         record.ListenPort,
		ResourceID:         resourceID,
		ResourceName:       resourceName,
		ChannelID:          capString(blank(record.ChannelID), 120),
		Direction:          capString(blank(record.Direction), 32),
		RemoteAddress:      nullableString(peerAddress(record.Direction, record.SourceAddress, record.SourcePort, record.DestinationAddress, record.DestinationPort)),
		SourceAddress:      nullableString(capString(record.SourceAddress, 255)),
		SourcePort:         record.SourcePort,
		DestinationAddress: nullableString(capString(record.DestinationAddress, 255)),
		DestinationPort:    record.DestinationPort,
		StreamOffset:       offset,
		StreamEndOffset:    endOffset,
		FrameIndex:         frameIndex,
		PayloadBytes:       int64(len(record.Payload)),
		PayloadData:        append([]byte(nil), record.Payload...),
		PayloadPreviewHex:  previewHex,
		PayloadPreviewText: previewText,
		Truncated:          truncated,
		FrameTime:          time.Now(),
	}
	return db.InsertTCPFrame(ctx, frame)
}

func (db *DB) cachedDetailCaptureDecision(ctx context.Context, key string, loader func() (bool, error)) (bool, error) {
	now := time.Now()
	db.detailMu.Lock()
	if decision, ok := db.detailDecisions[key]; ok && decision.expiresAt.After(now) {
		db.detailMu.Unlock()
		return decision.enabled, nil
	}
	db.detailMu.Unlock()

	enabled, err := loader()
	if err != nil {
		return false, err
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	db.detailMu.Lock()
	db.detailDecisions[key] = detailCaptureDecision{enabled: enabled, expiresAt: now.Add(detailCaptureDecisionTTL)}
	db.detailMu.Unlock()
	return enabled, nil
}

func (db *DB) enqueueHTTPExchange(record HTTPExchangeRecord) {
	db.detailMu.Lock()
	defer db.detailMu.Unlock()
	if db.detailMaxPending <= 0 || len(db.pendingHTTPExchanges) >= db.detailMaxPending {
		return
	}
	db.pendingHTTPExchanges = append(db.pendingHTTPExchanges, cloneHTTPExchangeRecord(record))
}

func (db *DB) enqueueTCPFrame(record TCPFrameRecord) {
	db.detailMu.Lock()
	defer db.detailMu.Unlock()
	if db.detailMaxPending <= 0 || len(db.pendingTCPFrames) >= db.detailMaxPending {
		return
	}
	db.pendingTCPFrames = append(db.pendingTCPFrames, cloneTCPFrameRecord(record))
}

func cloneHTTPExchangeRecord(record HTTPExchangeRecord) HTTPExchangeRecord {
	record.RequestHeaders = append([]string(nil), record.RequestHeaders...)
	record.ResponseHeaders = append([]string(nil), record.ResponseHeaders...)
	record.RequestBody = append([]byte(nil), record.RequestBody...)
	record.ResponseBody = append([]byte(nil), record.ResponseBody...)
	return record
}

func cloneTCPFrameRecord(record TCPFrameRecord) TCPFrameRecord {
	record.Payload = append([]byte(nil), record.Payload...)
	return record
}

func (db *DB) ReleaseTCPStream(channelID string) {
	if strings.TrimSpace(channelID) == "" {
		return
	}
	token := "|" + channelID + "|"
	db.tcpCursorMu.Lock()
	defer db.tcpCursorMu.Unlock()
	for key := range db.tcpCursors {
		if strings.Contains(key, token) {
			delete(db.tcpCursors, key)
		}
	}
}

func (db *DB) InsertHTTPExchange(ctx context.Context, e HTTPTrafficExchange) error {
	if db.detailStore != nil {
		return db.detailStore.InsertHTTPExchange(ctx, e)
	}
	return db.insertHTTPExchangeDB(ctx, e)
}

func (db *DB) insertHTTPExchangeDB(ctx context.Context, e HTTPTrafficExchange) error {
	query := db.rebind(`INSERT INTO tunnel_http_traffic_exchange
		(tenant_id, client_id, client_name, route, resource_id, resource_name, method,
		 relative_path, raw_query, status_code, success, error, remote_address, request_bytes,
		 response_bytes, elapsed_ms, request_content_type, response_content_type, response_body_type,
		 request_headers, response_headers, request_preview_hex, request_preview_text,
		 response_preview_hex, response_preview_text, request_truncated, response_truncated, captured_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query,
		e.TenantID, e.ClientID, e.ClientName, e.Route, e.ResourceID, e.ResourceName, e.Method,
		e.RelativePath, e.RawQuery, e.StatusCode, boolToInt(e.Success), e.Error, e.RemoteAddress,
		e.RequestBytes, e.ResponseBytes, e.ElapsedMs, e.RequestContentType, e.ResponseContentType,
		e.ResponseBodyType, e.RequestHeaders, e.ResponseHeaders, e.RequestPreviewHex, e.RequestPreviewText,
		e.ResponsePreviewHex, e.ResponsePreviewText, boolToInt(e.RequestTruncated),
		boolToInt(e.ResponseTruncated), formatTime(e.CapturedAt))
	return err
}

func (db *DB) InsertTCPFrame(ctx context.Context, f TCPTrafficFrame) error {
	if db.detailStore != nil {
		return db.detailStore.InsertTCPFrame(ctx, f)
	}
	return db.insertTCPFrameDB(ctx, f)
}

func (db *DB) insertTCPFrameDB(ctx context.Context, f TCPTrafficFrame) error {
	query := db.rebind(`INSERT INTO tunnel_tcp_traffic_frame
		(tenant_id, client_id, client_name, listen_port, resource_id, resource_name, channel_id,
		 frame_direction, remote_address, source_address, source_port, destination_address,
		 destination_port, stream_offset, stream_end_offset, frame_index, payload_bytes,
		 payload_data, payload_preview_hex, payload_preview_text, truncated, frame_time)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query,
		f.TenantID, f.ClientID, f.ClientName, f.ListenPort, f.ResourceID, f.ResourceName,
		f.ChannelID, f.Direction, f.RemoteAddress, f.SourceAddress, f.SourcePort,
		f.DestinationAddress, f.DestinationPort, f.StreamOffset, f.StreamEndOffset,
		f.FrameIndex, f.PayloadBytes, f.PayloadData, f.PayloadPreviewHex, f.PayloadPreviewText,
		boolToInt(f.Truncated), formatTime(f.FrameTime))
	return err
}

func (db *DB) ListHTTPExchanges(ctx context.Context, filter HTTPExchangeFilter) ([]HTTPTrafficExchange, int, error) {
	if db.detailStore != nil {
		return db.detailStore.ListHTTPExchanges(ctx, filter)
	}
	where, args := httpExchangeWhere(filter)
	var total int
	if err := db.sql.QueryRowContext(ctx, db.rebind(`SELECT COUNT(*) FROM tunnel_http_traffic_exchange`+where), args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	size, page := normalizeTrafficPage(filter.Size, filter.Page)
	listArgs := append(append([]any{}, args...), size, page*size)
	query := db.rebind(`SELECT id, tenant_id, client_id, client_name, route, resource_id, resource_name,
		method, relative_path, raw_query, status_code, success, error, remote_address, request_bytes,
		response_bytes, elapsed_ms, request_content_type, response_content_type, response_body_type,
		request_headers, response_headers, request_preview_hex, request_preview_text, response_preview_hex,
		response_preview_text, request_truncated, response_truncated, captured_at
		FROM tunnel_http_traffic_exchange` + where + ` ORDER BY id DESC LIMIT ? OFFSET ?`)
	rows, err := db.sql.QueryContext(ctx, query, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]HTTPTrafficExchange, 0)
	for rows.Next() {
		item, err := scanHTTPExchange(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

func (db *DB) ListTCPFrames(ctx context.Context, filter TCPFrameFilter) ([]TCPTrafficFrame, int, error) {
	if db.detailStore != nil {
		return db.detailStore.ListTCPFrames(ctx, filter)
	}
	where, args := tcpFrameWhere(filter)
	var total int
	if err := db.sql.QueryRowContext(ctx, db.rebind(`SELECT COUNT(*) FROM tunnel_tcp_traffic_frame`+where), args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	size, page := normalizeTrafficPage(filter.Size, filter.Page)
	listArgs := append(append([]any{}, args...), size, page*size)
	query := db.rebind(`SELECT id, tenant_id, client_id, client_name, listen_port, resource_id, resource_name,
		channel_id, frame_direction, remote_address, source_address, source_port, destination_address,
		destination_port, stream_offset, stream_end_offset, frame_index, payload_bytes, payload_data,
		payload_preview_hex, payload_preview_text, truncated, frame_time
		FROM tunnel_tcp_traffic_frame` + where + ` ORDER BY id DESC LIMIT ? OFFSET ?`)
	rows, err := db.sql.QueryContext(ctx, query, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]TCPTrafficFrame, 0)
	for rows.Next() {
		item, err := scanTCPFrame(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

func (db *DB) GetTCPFrame(ctx context.Context, tenantID string, id int64, clientIDs []int64) (*TCPTrafficFrame, error) {
	if db.detailStore != nil {
		return db.detailStore.GetTCPFrame(ctx, tenantID, id, clientIDs)
	}
	filter := TCPFrameFilter{TenantID: tenantID, ClientIDs: clientIDs, Page: 0, Size: 1}
	where, args := tcpFrameWhere(filter)
	where += ` AND id = ?`
	args = append(args, id)
	query := db.rebind(`SELECT id, tenant_id, client_id, client_name, listen_port, resource_id, resource_name,
		channel_id, frame_direction, remote_address, source_address, source_port, destination_address,
		destination_port, stream_offset, stream_end_offset, frame_index, payload_bytes, payload_data,
		payload_preview_hex, payload_preview_text, truncated, frame_time
		FROM tunnel_tcp_traffic_frame` + where + ` ORDER BY id DESC LIMIT 1`)
	frame, err := scanTCPFrame(db.sql.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &frame, err
}

func (db *DB) ListTCPStream(ctx context.Context, tenantID, channelID string, clientIDs []int64, limit int) ([]TCPTrafficFrame, error) {
	if db.detailStore != nil {
		return db.detailStore.ListTCPStream(ctx, tenantID, channelID, clientIDs, limit)
	}
	filter := TCPFrameFilter{TenantID: tenantID, ClientIDs: clientIDs}
	where, args := tcpFrameWhere(filter)
	where += ` AND channel_id = ?`
	args = append(args, channelID)
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	args = append(args, limit)
	query := db.rebind(`SELECT id, tenant_id, client_id, client_name, listen_port, resource_id, resource_name,
		channel_id, frame_direction, remote_address, source_address, source_port, destination_address,
		destination_port, stream_offset, stream_end_offset, frame_index, payload_bytes, payload_data,
		payload_preview_hex, payload_preview_text, truncated, frame_time
		FROM tunnel_tcp_traffic_frame` + where + ` ORDER BY id ASC LIMIT ?`)
	rows, err := db.sql.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]TCPTrafficFrame, 0)
	for rows.Next() {
		item, err := scanTCPFrame(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) httpResource(ctx context.Context, account *ClientAccount, route string) (*int64, *string) {
	query := db.rebind(`SELECT id, route, target_base_url FROM http_route_mapping
		WHERE client_id = ? AND route = ?`)
	var id int64
	var routeName, target string
	if err := db.sql.QueryRowContext(ctx, query, account.ID, route).Scan(&id, &routeName, &target); err != nil {
		return nil, nullableString(route)
	}
	name := routeName + " -> " + target
	return &id, &name
}

func (db *DB) tcpResource(ctx context.Context, account *ClientAccount, listenPort int) (*int64, *string) {
	query := db.rebind(`SELECT id, listen_port, target_address, target_port FROM tunnel_mapping
		WHERE client_id = ? AND listen_port = ?`)
	var id int64
	var port, targetPort int
	var target string
	if err := db.sql.QueryRowContext(ctx, query, account.ID, listenPort).Scan(&id, &port, &target, &targetPort); err != nil {
		name := "端口 " + strconv.Itoa(listenPort)
		return nil, &name
	}
	name := strconv.Itoa(port) + " -> " + target + ":" + strconv.Itoa(targetPort)
	return &id, &name
}

func (db *DB) nextTCPFramePosition(clientName string, listenPort int, channelID, direction string, payloadBytes int64) (int64, int64, int64) {
	key := clientName + "|" + strconv.Itoa(listenPort) + "|" + channelID + "|" + direction
	db.tcpCursorMu.Lock()
	cursor := db.tcpCursors[key]
	if cursor == nil {
		cursor = &tcpStreamCursor{}
		db.tcpCursors[key] = cursor
	}
	db.tcpCursorMu.Unlock()
	offset := cursor.offset.Add(payloadBytes) - payloadBytes
	index := cursor.index.Add(1) - 1
	return offset, offset + payloadBytes, index
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanHTTPExchange(scanner rowScanner) (HTTPTrafficExchange, error) {
	var (
		item                                     HTTPTrafficExchange
		resourceID                               sql.NullInt64
		resourceName, errText, remote            sql.NullString
		requestCT, responseCT                    sql.NullString
		success, requestTruncated, responseTrunc int
		capturedAt                               string
	)
	err := scanner.Scan(&item.ID, &item.TenantID, &item.ClientID, &item.ClientName, &item.Route,
		&resourceID, &resourceName, &item.Method, &item.RelativePath, &item.RawQuery,
		&item.StatusCode, &success, &errText, &remote, &item.RequestBytes, &item.ResponseBytes,
		&item.ElapsedMs, &requestCT, &responseCT, &item.ResponseBodyType, &item.RequestHeaders,
		&item.ResponseHeaders, &item.RequestPreviewHex, &item.RequestPreviewText,
		&item.ResponsePreviewHex, &item.ResponsePreviewText, &requestTruncated, &responseTrunc,
		&capturedAt)
	if err != nil {
		return HTTPTrafficExchange{}, err
	}
	item.Success = success != 0
	item.RequestTruncated = requestTruncated != 0
	item.ResponseTruncated = responseTrunc != 0
	item.CapturedAt = parseTime(capturedAt)
	if resourceID.Valid {
		item.ResourceID = &resourceID.Int64
	}
	item.ResourceName = nullStringPtr(resourceName)
	item.Error = nullStringPtr(errText)
	item.RemoteAddress = nullStringPtr(remote)
	item.RequestContentType = nullStringPtr(requestCT)
	item.ResponseContentType = nullStringPtr(responseCT)
	item.ResponseBodyType = classifyOrNormalizeHTTPBody(item.ResponseBodyType, item.ResponseContentType, item.ResponseBytes)
	return item, nil
}

func scanTCPFrame(scanner rowScanner) (TCPTrafficFrame, error) {
	var (
		item                        TCPTrafficFrame
		resourceID                  sql.NullInt64
		resourceName, remote        sql.NullString
		source, destination         sql.NullString
		sourcePort, destinationPort sql.NullInt64
		truncated                   int
		frameTime                   string
	)
	err := scanner.Scan(&item.ID, &item.TenantID, &item.ClientID, &item.ClientName,
		&item.ListenPort, &resourceID, &resourceName, &item.ChannelID, &item.Direction,
		&remote, &source, &sourcePort, &destination, &destinationPort, &item.StreamOffset,
		&item.StreamEndOffset, &item.FrameIndex, &item.PayloadBytes, &item.PayloadData,
		&item.PayloadPreviewHex, &item.PayloadPreviewText, &truncated, &frameTime)
	if err != nil {
		return TCPTrafficFrame{}, err
	}
	if resourceID.Valid {
		item.ResourceID = &resourceID.Int64
	}
	item.ResourceName = nullStringPtr(resourceName)
	item.RemoteAddress = nullStringPtr(remote)
	item.SourceAddress = nullStringPtr(source)
	item.DestinationAddress = nullStringPtr(destination)
	if sourcePort.Valid {
		v := int(sourcePort.Int64)
		item.SourcePort = &v
	}
	if destinationPort.Valid {
		v := int(destinationPort.Int64)
		item.DestinationPort = &v
	}
	item.Truncated = truncated != 0
	item.FrameTime = parseTime(frameTime)
	return item, nil
}

func httpExchangeWhere(filter HTTPExchangeFilter) (string, []any) {
	where := ` WHERE tenant_id = ?`
	args := []any{defaultTenant(filter.TenantID)}
	if filter.ClientID != nil {
		where += ` AND client_id = ?`
		args = append(args, *filter.ClientID)
	} else if len(filter.ClientIDs) > 0 {
		where += ` AND client_id IN (` + placeholders(len(filter.ClientIDs)) + `)`
		for _, id := range filter.ClientIDs {
			args = append(args, id)
		}
	}
	if filter.Route != "" {
		where += ` AND route = ?`
		args = append(args, filter.Route)
	}
	if bodyType := normalizeHTTPBodyType(filter.ResponseBodyType); bodyType != "" {
		clause, clauseArgs := responseBodyTypeClause(bodyType)
		where += ` AND (` + clause + `)`
		args = append(args, clauseArgs...)
	}
	if strings.TrimSpace(filter.Query) != "" {
		where, args = appendHTTPSearch(where, args, filter.Field, filter.Query)
	}
	return where, args
}

func normalizeHTTPBodyType(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "empty", "json", "html", "xml", "image", "video", "audio", "form", "script", "text", "binary":
		return normalized
	default:
		return ""
	}
}

func responseBodyTypeClause(bodyType string) (string, []any) {
	clause := `LOWER(COALESCE(response_body_type, '')) = ?`
	args := []any{bodyType}
	if bodyType == "empty" {
		return clause + ` OR response_bytes = 0`, args
	}
	for _, pattern := range responseContentTypeSQLPatterns(bodyType) {
		clause += ` OR LOWER(COALESCE(response_content_type, '')) LIKE ?`
		args = append(args, pattern)
	}
	return clause, args
}

func responseContentTypeSQLPatterns(bodyType string) []string {
	switch bodyType {
	case "json":
		return []string{"%application/json%", "%+json%"}
	case "html":
		return []string{"%text/html%"}
	case "xml":
		return []string{"%application/xml%", "%text/xml%", "%+xml%"}
	case "image":
		return []string{"image/%"}
	case "video":
		return []string{"video/%"}
	case "audio":
		return []string{"audio/%"}
	case "form":
		return []string{"%application/x-www-form-urlencoded%", "%multipart/form-data%"}
	case "script":
		return []string{"%javascript%", "%ecmascript%"}
	case "text":
		return []string{"text/%"}
	case "binary":
		return []string{"%application/octet-stream%", "%application/pdf%", "%application/zip%", "%application/x-%", "%application/vnd.%"}
	default:
		return nil
	}
}

func appendHTTPSearch(where string, args []any, field, q string) (string, []any) {
	field = normalizeHTTPSearchField(field)
	for _, token := range strings.Fields(q) {
		clause, clauseArgs := httpSearchTokenClause(field, token)
		where += ` AND (` + clause + `)`
		args = append(args, clauseArgs...)
	}
	return where, args
}

func normalizeHTTPSearchField(field string) string {
	field = strings.ToLower(strings.TrimSpace(field))
	field = strings.ReplaceAll(field, "_", "")
	field = strings.ReplaceAll(field, "-", "")
	return field
}

func httpSearchTokenClause(field, token string) (string, []any) {
	token = strings.TrimSpace(token)
	lower := strings.ToLower(token)
	like := "%" + lower + "%"
	numeric, numericErr := strconv.ParseInt(token, 10, 64)
	numericOK := numericErr == nil
	switch field {
	case "method":
		return `LOWER(COALESCE(method, '')) = ?`, []any{lower}
	case "id":
		if numericOK {
			return `id = ?`, []any{numeric}
		}
		return `1=0`, nil
	case "status", "statuscode":
		if numericOK {
			return `status_code = ?`, []any{numeric}
		}
		return `1=0`, nil
	case "route":
		return `LOWER(COALESCE(route, '')) LIKE ?`, []any{like}
	case "path", "relativepath":
		return `(LOWER(COALESCE(relative_path, '')) LIKE ? OR LOWER(COALESCE(raw_query, '')) LIKE ?)`, []any{like, like}
	case "query", "rawquery":
		return `LOWER(COALESCE(raw_query, '')) LIKE ?`, []any{like}
	case "client", "clientid", "clientname":
		clause := `LOWER(COALESCE(client_name, '')) LIKE ?`
		clauseArgs := []any{like}
		if numericOK {
			clause += ` OR client_id = ?`
			clauseArgs = append(clauseArgs, numeric)
		}
		return clause, clauseArgs
	case "resource", "resourceid", "resourcename":
		clause := `LOWER(COALESCE(resource_name, '')) LIKE ?`
		clauseArgs := []any{like}
		if numericOK {
			clause += ` OR resource_id = ?`
			clauseArgs = append(clauseArgs, numeric)
		}
		return clause, clauseArgs
	case "remote", "remoteaddress":
		return `LOWER(COALESCE(remote_address, '')) LIKE ?`, []any{like}
	case "contenttype":
		return `(LOWER(COALESCE(request_content_type, '')) LIKE ? OR LOWER(COALESCE(response_content_type, '')) LIKE ? OR LOWER(COALESCE(response_body_type, '')) = ?)`, []any{like, like, lower}
	case "error":
		return `LOWER(COALESCE(error, '')) LIKE ?`, []any{like}
	case "responsebodytype", "responsedatatype":
		return `LOWER(COALESCE(response_body_type, '')) = ?`, []any{lower}
	case "requestheaders":
		return `LOWER(COALESCE(request_headers, '')) LIKE ?`, []any{like}
	case "responseheaders":
		return `LOWER(COALESCE(response_headers, '')) LIKE ?`, []any{like}
	case "headers":
		return `(LOWER(COALESCE(request_headers, '')) LIKE ? OR LOWER(COALESCE(response_headers, '')) LIKE ?)`, []any{like, like}
	case "requestbody":
		return `LOWER(COALESCE(request_preview_text, '')) LIKE ?`, []any{like}
	case "responsebody":
		return `LOWER(COALESCE(response_preview_text, '')) LIKE ?`, []any{like}
	case "body":
		return `(LOWER(COALESCE(request_preview_text, '')) LIKE ? OR LOWER(COALESCE(response_preview_text, '')) LIKE ?)`, []any{like, like}
	case "all":
		predicates := []string{
			`LOWER(COALESCE(client_name, '')) LIKE ?`,
			`LOWER(COALESCE(route, '')) LIKE ?`,
			`LOWER(COALESCE(resource_name, '')) LIKE ?`,
			`LOWER(COALESCE(method, '')) LIKE ?`,
			`LOWER(COALESCE(relative_path, '')) LIKE ?`,
			`LOWER(COALESCE(raw_query, '')) LIKE ?`,
			`LOWER(COALESCE(error, '')) LIKE ?`,
			`LOWER(COALESCE(remote_address, '')) LIKE ?`,
			`LOWER(COALESCE(request_content_type, '')) LIKE ?`,
			`LOWER(COALESCE(response_content_type, '')) LIKE ?`,
			`LOWER(COALESCE(response_body_type, '')) LIKE ?`,
			`LOWER(COALESCE(request_headers, '')) LIKE ?`,
			`LOWER(COALESCE(response_headers, '')) LIKE ?`,
			`LOWER(COALESCE(request_preview_text, '')) LIKE ?`,
			`LOWER(COALESCE(response_preview_text, '')) LIKE ?`,
			`LOWER(CAST(captured_at AS TEXT)) LIKE ?`,
		}
		clauseArgs := []any{
			like, like, like, like, like, like, like, like,
			like, like, like, like, like, like, like, like,
		}
		if numericOK {
			predicates = append(predicates, `id = ?`, `client_id = ?`, `status_code = ?`, `resource_id = ?`)
			clauseArgs = append(clauseArgs, numeric, numeric, numeric, numeric)
		}
		return strings.Join(predicates, ` OR `), clauseArgs
	default:
		predicates := []string{
			`LOWER(COALESCE(client_name, '')) LIKE ?`,
			`LOWER(COALESCE(route, '')) LIKE ?`,
			`LOWER(COALESCE(resource_name, '')) LIKE ?`,
			`LOWER(COALESCE(method, '')) LIKE ?`,
			`LOWER(COALESCE(relative_path, '')) LIKE ?`,
			`LOWER(COALESCE(raw_query, '')) LIKE ?`,
			`LOWER(COALESCE(error, '')) LIKE ?`,
			`LOWER(COALESCE(remote_address, '')) LIKE ?`,
			`LOWER(COALESCE(request_content_type, '')) LIKE ?`,
			`LOWER(COALESCE(response_content_type, '')) LIKE ?`,
			`LOWER(COALESCE(response_body_type, '')) LIKE ?`,
			`LOWER(CAST(captured_at AS TEXT)) LIKE ?`,
		}
		clauseArgs := []any{
			like, like, like, like, like, like,
			like, like, like, like, like, like,
		}
		if numericOK {
			predicates = append(predicates, `id = ?`, `client_id = ?`, `status_code = ?`, `resource_id = ?`)
			clauseArgs = append(clauseArgs, numeric, numeric, numeric, numeric)
		}
		return strings.Join(predicates, ` OR `), clauseArgs
	}
}

func tcpFrameWhere(filter TCPFrameFilter) (string, []any) {
	where := ` WHERE tenant_id = ?`
	args := []any{defaultTenant(filter.TenantID)}
	if filter.ClientID != nil {
		where += ` AND client_id = ?`
		args = append(args, *filter.ClientID)
	} else if len(filter.ClientIDs) > 0 {
		where += ` AND client_id IN (` + placeholders(len(filter.ClientIDs)) + `)`
		for _, id := range filter.ClientIDs {
			args = append(args, id)
		}
	}
	if filter.ListenPort != nil {
		where += ` AND listen_port = ?`
		args = append(args, *filter.ListenPort)
	}
	return where, args
}

func normalizeTrafficPage(size, page int) (int, int) {
	if size <= 0 || size > 500 {
		size = 50
	}
	if page < 0 {
		page = 0
	}
	return size, page
}

type bodyPreviewResult struct {
	text      string
	truncated bool
}

func bodyPreview(data []byte, contentType, contentEncoding string, maxBytes int) bodyPreviewResult {
	if len(data) == 0 {
		return bodyPreviewResult{}
	}
	displayData, truncated := decodeBody(data, contentEncoding, maxBytes)
	if !isTextBody(contentType) && !looksLikeText(displayData) {
		mediaType := contentMediaType(contentType)
		return bodyPreviewResult{
			text:      "data:" + mediaType + ";base64," + base64.StdEncoding.EncodeToString(displayData),
			truncated: truncated,
		}
	}
	return bodyPreviewResult{text: sanitizeText(string(displayData)), truncated: truncated}
}

func decodeBody(data []byte, contentEncoding string, maxBytes int) ([]byte, bool) {
	tokens := strings.Split(contentEncoding, ",")
	current := data
	decoded := false
	truncated := false
	for i := len(tokens) - 1; i >= 0; i-- {
		token := strings.ToLower(strings.TrimSpace(tokens[i]))
		if token == "" || token == "identity" {
			continue
		}
		next, itemTruncated, ok := decodeOne(current, token, maxBytes)
		if !ok {
			if decoded {
				return current, truncated
			}
			return data, false
		}
		current = next
		truncated = truncated || itemTruncated
		decoded = true
		if truncated {
			return current, true
		}
	}
	if !decoded && len(current) > maxBytes && maxBytes > 0 {
		return append([]byte(nil), current[:maxBytes]...), true
	}
	return current, truncated
}

func decodeOne(data []byte, token string, maxBytes int) ([]byte, bool, bool) {
	var reader io.ReadCloser
	var err error
	switch token {
	case "gzip", "x-gzip":
		reader, err = gzip.NewReader(bytes.NewReader(data))
	case "deflate", "x-deflate":
		reader, err = zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			reader = flate.NewReader(bytes.NewReader(data))
			err = nil
		}
	case "br":
		reader = io.NopCloser(brotli.NewReader(bytes.NewReader(data)))
	default:
		return nil, false, false
	}
	if err != nil {
		return nil, false, false
	}
	defer reader.Close()
	out, truncated, err := readLimited(reader, maxBytes)
	return out, truncated, err == nil
}

func tcpPreview(data []byte, maxBytes int) (string, string, bool) {
	if maxBytes < 0 {
		maxBytes = 0
	}
	if len(data) == 0 || maxBytes == 0 {
		return "", "", len(data) > 0
	}
	n := len(data)
	if n > maxBytes {
		n = maxBytes
	}
	encoded := strings.ToUpper(hex.EncodeToString(data[:n]))
	var spaced strings.Builder
	for i := 0; i < len(encoded); i += 2 {
		if i > 0 {
			spaced.WriteByte(' ')
		}
		spaced.WriteString(encoded[i : i+2])
	}
	return spaced.String(), sanitizeText(string(data[:n])), len(data) > n
}

func joinHeaders(headers []string) string {
	if len(headers) == 0 {
		return ""
	}
	out := make([]string, 0, len(headers))
	for _, header := range headers {
		if header = strings.TrimSpace(header); header != "" {
			out = append(out, maskHeader(header))
		}
	}
	return strings.Join(out, "\n")
}

func maskHeader(header string) string {
	idx := strings.IndexByte(header, ':')
	if idx <= 0 {
		return header
	}
	name := strings.ToLower(strings.TrimSpace(header[:idx]))
	switch name {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "x-csrf-token":
		return header[:idx+1] + "***"
	default:
		return header
	}
}

func headerValue(headers []string, name string) string {
	for _, header := range headers {
		idx := strings.IndexByte(header, ':')
		if idx > 0 && strings.EqualFold(strings.TrimSpace(header[:idx]), name) {
			return strings.TrimSpace(header[idx+1:])
		}
	}
	return ""
}

func classifyHTTPBody(contentType string, bytes int) string {
	if bytes <= 0 {
		return "empty"
	}
	media := contentMediaType(contentType)
	switch {
	case media == "application/json" || strings.HasSuffix(media, "+json"):
		return "json"
	case media == "text/html":
		return "html"
	case media == "application/xml" || media == "text/xml" || strings.HasSuffix(media, "+xml"):
		return "xml"
	case strings.HasPrefix(media, "image/"):
		return "image"
	case strings.HasPrefix(media, "video/"):
		return "video"
	case strings.HasPrefix(media, "audio/"):
		return "audio"
	case media == "application/x-www-form-urlencoded" || media == "multipart/form-data":
		return "form"
	case strings.Contains(media, "javascript") || strings.Contains(media, "ecmascript"):
		return "script"
	case strings.HasPrefix(media, "text/"):
		return "text"
	default:
		return "binary"
	}
}

func isTextBody(contentType string) bool {
	media := contentMediaType(contentType)
	return strings.HasPrefix(media, "text/") ||
		media == "application/json" || strings.HasSuffix(media, "+json") ||
		media == "application/xml" || strings.HasSuffix(media, "+xml") ||
		media == "application/x-www-form-urlencoded" ||
		media == "application/graphql" ||
		media == "application/javascript" ||
		media == "application/ecmascript" ||
		media == "application/x-yaml" ||
		media == "application/yaml"
}

func contentMediaType(contentType string) string {
	media := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if strings.Contains(media, "/") {
		return media
	}
	return "application/octet-stream"
}

func looksLikeText(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	inspected := len(data)
	if inspected > 512 {
		inspected = 512
	}
	controls := 0
	for _, b := range data[:inspected] {
		if b == 0 {
			return false
		}
		if b < 0x20 && b != '\r' && b != '\n' && b != '\t' {
			controls++
		}
	}
	return inspected == 0 || controls*10 <= inspected
}

func sanitizeText(text string) string {
	var builder strings.Builder
	builder.Grow(len(text))
	for _, r := range text {
		if (r < 0x20 || r == utf8.RuneError) && r != '\r' && r != '\n' && r != '\t' {
			builder.WriteByte('.')
		} else {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func peerAddress(direction, source string, sourcePort *int, destination string, destinationPort *int) string {
	if direction == TCPDirectionPublicToClient {
		return endpoint(source, sourcePort)
	}
	if direction == TCPDirectionClientToPublic {
		return endpoint(destination, destinationPort)
	}
	if value := endpoint(source, sourcePort); value != "" {
		return value
	}
	return endpoint(destination, destinationPort)
}

func endpoint(address string, port *int) string {
	if strings.TrimSpace(address) == "" {
		if port == nil {
			return ""
		}
		return ":" + strconv.Itoa(*port)
	}
	if port == nil {
		return address
	}
	return address + ":" + strconv.Itoa(*port)
}

func nullStringPtr(value sql.NullString) *string {
	if value.Valid {
		return &value.String
	}
	return nil
}

func nullableString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func capString(value string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func blank(value string) string {
	return strings.TrimSpace(value)
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func previewBytes(options TrafficDetailOptions) int {
	if options.PreviewBytes <= 0 {
		return defaultPreviewBytes
	}
	return options.PreviewBytes
}

func headerChars(options TrafficDetailOptions) int {
	if options.HeaderChars <= 0 {
		return defaultHeaderChars
	}
	return options.HeaderChars
}

func decodeMaxBytes(options TrafficDetailOptions) int {
	if options.DecodeMaxBytes < 1024 {
		return defaultDecodeMaxBytes
	}
	return options.DecodeMaxBytes
}

func sampleAllowed(rate float64) bool {
	if rate >= 1 {
		return true
	}
	if rate <= 0 {
		return false
	}
	return rand.Float64() < rate
}

func readLimited(reader io.Reader, maxBytes int) ([]byte, bool, error) {
	if maxBytes < 1024 {
		maxBytes = defaultDecodeMaxBytes
	}
	var out bytes.Buffer
	if maxBytes < 8192 {
		out.Grow(maxBytes)
	} else {
		out.Grow(8192)
	}
	limited := io.LimitReader(reader, int64(maxBytes)+1)
	_, err := out.ReadFrom(limited)
	if err != nil {
		return nil, false, err
	}
	data := out.Bytes()
	if len(data) > maxBytes {
		return append([]byte(nil), data[:maxBytes]...), true, nil
	}
	return append([]byte(nil), data...), false, nil
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
