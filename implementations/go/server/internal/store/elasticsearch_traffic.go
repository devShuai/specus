package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultHTTPESIndex = "specus-http-traffic"
	defaultTCPESIndex  = "specus-tcp-traffic"
	esTrimBatchSize    = 500
	esMaxTrimBatches   = 20
	esTrimInterval     = time.Minute
)

// ElasticsearchTrafficOptions configures Java-compatible HTTP/TCP detail storage.
type ElasticsearchTrafficOptions struct {
	URIs                 []string
	Username             string
	Password             string
	APIKey               string
	HTTPIndex            string
	TCPIndex             string
	HTTPMaxStoreBytes    int64
	TCPMaxStoreBytes     int64
	HTTPClient           *http.Client
	RetentionCheckPeriod time.Duration
}

// UseElasticsearchTraffic switches detailed HTTP/TCP traffic storage from DB to Elasticsearch.
func (db *DB) UseElasticsearchTraffic(ctx context.Context, options ElasticsearchTrafficOptions) error {
	backend, err := newElasticsearchTrafficStore(options)
	if err != nil {
		return err
	}
	if err := backend.ensureHTTPIndex(ctx); err != nil {
		return err
	}
	if err := backend.ensureTCPIndex(ctx); err != nil {
		return err
	}
	db.detailStore = backend
	return nil
}

type elasticsearchTrafficStore struct {
	endpoints            []string
	username             string
	password             string
	apiKey               string
	httpIndex            string
	tcpIndex             string
	httpMaxStoreBytes    int64
	tcpMaxStoreBytes     int64
	retentionCheckPeriod time.Duration
	client               *http.Client
	idSequence           atomic.Int64
	httpLastTrim         atomic.Int64
	tcpLastTrim          atomic.Int64
	mu                   sync.Mutex
	httpIndexReady       bool
	tcpIndexReady        bool
}

func newElasticsearchTrafficStore(options ElasticsearchTrafficOptions) (*elasticsearchTrafficStore, error) {
	endpoints := make([]string, 0, len(options.URIs))
	for _, raw := range options.URIs {
		normalized := strings.TrimRight(strings.TrimSpace(raw), "/")
		if normalized != "" {
			endpoints = append(endpoints, normalized)
		}
	}
	if len(endpoints) == 0 {
		return nil, errors.New("elasticsearch uris cannot be blank")
	}
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	period := options.RetentionCheckPeriod
	if period <= 0 {
		period = esTrimInterval
	}
	httpIndex := strings.TrimSpace(options.HTTPIndex)
	if httpIndex == "" {
		httpIndex = defaultHTTPESIndex
	}
	tcpIndex := strings.TrimSpace(options.TCPIndex)
	if tcpIndex == "" {
		tcpIndex = defaultTCPESIndex
	}
	return &elasticsearchTrafficStore{
		endpoints:            endpoints,
		username:             options.Username,
		password:             options.Password,
		apiKey:               options.APIKey,
		httpIndex:            httpIndex,
		tcpIndex:             tcpIndex,
		httpMaxStoreBytes:    options.HTTPMaxStoreBytes,
		tcpMaxStoreBytes:     options.TCPMaxStoreBytes,
		retentionCheckPeriod: period,
		client:               client,
	}, nil
}

func (s *elasticsearchTrafficStore) InsertHTTPExchange(ctx context.Context, e HTTPTrafficExchange) error {
	if err := s.ensureHTTPIndex(ctx); err != nil {
		return err
	}
	id := s.documentID(e.ID)
	doc := httpTrafficDocument{
		DocumentID:          formatESID(id),
		ID:                  id,
		TenantID:            defaultTenant(e.TenantID),
		ClientID:            e.ClientID,
		ClientName:          e.ClientName,
		Route:               e.Route,
		ResourceID:          e.ResourceID,
		ResourceName:        e.ResourceName,
		Method:              e.Method,
		RelativePath:        e.RelativePath,
		RawQuery:            e.RawQuery,
		StatusCode:          e.StatusCode,
		Success:             e.Success,
		Error:               e.Error,
		RemoteAddress:       e.RemoteAddress,
		RequestBytes:        e.RequestBytes,
		ResponseBytes:       e.ResponseBytes,
		ElapsedMs:           e.ElapsedMs,
		RequestContentType:  e.RequestContentType,
		ResponseContentType: e.ResponseContentType,
		ResponseBodyType:    classifyOrNormalizeHTTPBody(e.ResponseBodyType, e.ResponseContentType, e.ResponseBytes),
		RequestHeaders:      e.RequestHeaders,
		ResponseHeaders:     e.ResponseHeaders,
		RequestPreviewHex:   e.RequestPreviewHex,
		RequestPreviewText:  e.RequestPreviewText,
		ResponsePreviewHex:  e.ResponsePreviewHex,
		ResponsePreviewText: e.ResponsePreviewText,
		RequestTruncated:    e.RequestTruncated,
		ResponseTruncated:   e.ResponseTruncated,
		CapturedAt:          formatTime(e.CapturedAt),
	}
	if err := s.indexDocument(ctx, s.httpIndex, doc.DocumentID, doc); err != nil {
		return err
	}
	s.trimIfNecessary(ctx, s.httpIndex, s.httpMaxStoreBytes, &s.httpLastTrim)
	return nil
}

func (s *elasticsearchTrafficStore) InsertTCPFrame(ctx context.Context, f TCPTrafficFrame) error {
	if err := s.ensureTCPIndex(ctx); err != nil {
		return err
	}
	id := s.documentID(f.ID)
	payloadBase64 := ""
	if len(f.PayloadData) > 0 {
		payloadBase64 = base64.StdEncoding.EncodeToString(f.PayloadData)
	}
	doc := tcpTrafficDocument{
		DocumentID:         formatESID(id),
		ID:                 id,
		TenantID:           defaultTenant(f.TenantID),
		ClientID:           f.ClientID,
		ClientName:         f.ClientName,
		ListenPort:         f.ListenPort,
		ResourceID:         f.ResourceID,
		ResourceName:       f.ResourceName,
		ChannelID:          f.ChannelID,
		Direction:          f.Direction,
		RemoteAddress:      f.RemoteAddress,
		SourceAddress:      f.SourceAddress,
		SourcePort:         f.SourcePort,
		DestinationAddress: f.DestinationAddress,
		DestinationPort:    f.DestinationPort,
		StreamOffset:       f.StreamOffset,
		StreamEndOffset:    f.StreamEndOffset,
		FrameIndex:         f.FrameIndex,
		PayloadBytes:       f.PayloadBytes,
		PayloadData:        payloadBase64,
		PayloadPreviewHex:  f.PayloadPreviewHex,
		PayloadPreviewText: f.PayloadPreviewText,
		Truncated:          f.Truncated,
		FrameTime:          formatTime(f.FrameTime),
	}
	if err := s.indexDocument(ctx, s.tcpIndex, doc.DocumentID, doc); err != nil {
		return err
	}
	s.trimIfNecessary(ctx, s.tcpIndex, s.tcpMaxStoreBytes, &s.tcpLastTrim)
	return nil
}

func (s *elasticsearchTrafficStore) ListHTTPExchanges(ctx context.Context, filter HTTPExchangeFilter) ([]HTTPTrafficExchange, int, error) {
	if isDenied(filter.ClientID, filter.ClientIDs) {
		return []HTTPTrafficExchange{}, 0, nil
	}
	if err := s.ensureHTTPIndex(ctx); err != nil {
		return nil, 0, err
	}
	size, page := normalizeTrafficPage(filter.Size, filter.Page)
	query := map[string]any{
		"query": buildHTTPESQuery(filter),
		"from":  page * size,
		"size":  size,
		"sort":  []any{map[string]any{"id": map[string]any{"order": "desc"}}},
		"_source": map[string]any{"excludes": []string{
			"requestHeaders",
			"responseHeaders",
			"requestPreviewHex",
			"requestPreviewText",
			"responsePreviewHex",
			"responsePreviewText",
		}},
	}
	var response esSearchResponse[httpTrafficDocument]
	if err := s.doJSON(ctx, http.MethodPost, "/"+url.PathEscape(s.httpIndex)+"/_search", query, &response); err != nil {
		return nil, 0, err
	}
	items := make([]HTTPTrafficExchange, 0, len(response.Hits.Hits))
	for _, hit := range response.Hits.Hits {
		items = append(items, hit.Source.toEntity())
	}
	return items, response.Hits.Total.Value, nil
}

func (s *elasticsearchTrafficStore) GetHTTPExchange(
	ctx context.Context,
	tenantID string,
	id int64,
	clientIDs []int64,
) (*HTTPTrafficExchange, error) {
	if len(clientIDs) == 0 {
		return nil, ErrNotFound
	}
	if err := s.ensureHTTPIndex(ctx); err != nil {
		return nil, err
	}
	filter := HTTPExchangeFilter{TenantID: tenantID, ClientIDs: clientIDs}
	query := buildHTTPESQuery(filter)
	queryBool := query["bool"].(map[string]any)
	queryBool["filter"] = append(queryBool["filter"].([]any), esTerm("id", id))
	request := map[string]any{"query": query, "size": 1}
	var response esSearchResponse[httpTrafficDocument]
	if err := s.doJSON(
		ctx,
		http.MethodPost,
		"/"+url.PathEscape(s.httpIndex)+"/_search",
		request,
		&response,
	); err != nil {
		return nil, err
	}
	if len(response.Hits.Hits) == 0 {
		return nil, ErrNotFound
	}
	item := response.Hits.Hits[0].Source.toEntity()
	return &item, nil
}

func (s *elasticsearchTrafficStore) ListTCPFrames(ctx context.Context, filter TCPFrameFilter) ([]TCPTrafficFrame, int, error) {
	if isDenied(filter.ClientID, filter.ClientIDs) {
		return []TCPTrafficFrame{}, 0, nil
	}
	if err := s.ensureTCPIndex(ctx); err != nil {
		return nil, 0, err
	}
	size, page := normalizeTrafficPage(filter.Size, filter.Page)
	query := map[string]any{
		"query": buildTCPESQuery(filter, ""),
		"from":  page * size,
		"size":  size,
		"sort":  []any{map[string]any{"id": map[string]any{"order": "desc"}}},
	}
	var response esSearchResponse[tcpTrafficDocument]
	if err := s.doJSON(ctx, http.MethodPost, "/"+url.PathEscape(s.tcpIndex)+"/_search", query, &response); err != nil {
		return nil, 0, err
	}
	items := make([]TCPTrafficFrame, 0, len(response.Hits.Hits))
	for _, hit := range response.Hits.Hits {
		items = append(items, hit.Source.toEntity())
	}
	return items, response.Hits.Total.Value, nil
}

func (s *elasticsearchTrafficStore) GetTCPFrame(ctx context.Context, tenantID string, id int64, clientIDs []int64) (*TCPTrafficFrame, error) {
	if len(clientIDs) == 0 {
		return nil, ErrNotFound
	}
	if err := s.ensureTCPIndex(ctx); err != nil {
		return nil, err
	}
	filter := TCPFrameFilter{TenantID: tenantID, ClientIDs: clientIDs}
	query := buildTCPESQuery(filter, "")
	queryBool := query["bool"].(map[string]any)
	queryBool["filter"] = append(queryBool["filter"].([]any), esTerm("id", id))
	request := map[string]any{"query": query, "size": 1}
	var response esSearchResponse[tcpTrafficDocument]
	if err := s.doJSON(ctx, http.MethodPost, "/"+url.PathEscape(s.tcpIndex)+"/_search", request, &response); err != nil {
		return nil, err
	}
	if len(response.Hits.Hits) == 0 {
		return nil, ErrNotFound
	}
	item := response.Hits.Hits[0].Source.toEntity()
	return &item, nil
}

func (s *elasticsearchTrafficStore) ListTCPStream(ctx context.Context, tenantID, channelID string, clientIDs []int64, limit int) ([]TCPTrafficFrame, error) {
	if strings.TrimSpace(channelID) == "" || len(clientIDs) == 0 {
		return []TCPTrafficFrame{}, nil
	}
	if err := s.ensureTCPIndex(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	filter := TCPFrameFilter{TenantID: tenantID, ClientIDs: clientIDs}
	query := map[string]any{
		"query": buildTCPESQuery(filter, strings.TrimSpace(channelID)),
		"size":  limit,
		"sort":  []any{map[string]any{"id": map[string]any{"order": "asc"}}},
	}
	var response esSearchResponse[tcpTrafficDocument]
	if err := s.doJSON(ctx, http.MethodPost, "/"+url.PathEscape(s.tcpIndex)+"/_search", query, &response); err != nil {
		return nil, err
	}
	items := make([]TCPTrafficFrame, 0, len(response.Hits.Hits))
	for _, hit := range response.Hits.Hits {
		items = append(items, hit.Source.toEntity())
	}
	return items, nil
}

func (s *elasticsearchTrafficStore) ensureHTTPIndex(ctx context.Context) error {
	mapping := map[string]any{"mappings": map[string]any{"properties": httpESProperties()}}
	return s.ensureIndex(ctx, s.httpIndex, mapping, &s.httpIndexReady)
}

func (s *elasticsearchTrafficStore) ensureTCPIndex(ctx context.Context) error {
	mapping := map[string]any{"mappings": map[string]any{"properties": tcpESProperties()}}
	return s.ensureIndex(ctx, s.tcpIndex, mapping, &s.tcpIndexReady)
}

func (s *elasticsearchTrafficStore) ensureIndex(ctx context.Context, index string, mapping map[string]any, ready *bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if *ready {
		return nil
	}
	status, _, err := s.doRaw(ctx, http.MethodHead, "/"+url.PathEscape(index), nil)
	if err != nil {
		return err
	}
	if status == http.StatusOK {
		*ready = true
		return nil
	}
	if status != http.StatusNotFound {
		return fmt.Errorf("elasticsearch inspect index %s returned HTTP %d", index, status)
	}
	if err := s.doJSON(ctx, http.MethodPut, "/"+url.PathEscape(index), mapping, nil); err != nil {
		return err
	}
	*ready = true
	return nil
}

func (s *elasticsearchTrafficStore) indexDocument(ctx context.Context, index, id string, doc any) error {
	path := "/" + url.PathEscape(index) + "/_doc/" + url.PathEscape(id)
	return s.doJSON(ctx, http.MethodPut, path, doc, nil)
}

func (s *elasticsearchTrafficStore) doJSON(ctx context.Context, method, path string, input any, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	status, data, err := s.doRaw(ctx, method, path, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("elasticsearch %s %s returned HTTP %d: %s", method, path, status, string(data))
	}
	if output == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, output)
}

func (s *elasticsearchTrafficStore) doRaw(ctx context.Context, method, path string, body io.Reader) (int, []byte, error) {
	endpoint := s.endpoints[0]
	req, err := http.NewRequestWithContext(ctx, method, endpoint+path, body)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(s.apiKey) != "" {
		req.Header.Set("Authorization", "ApiKey "+strings.TrimSpace(s.apiKey))
	} else if s.username != "" || s.password != "" {
		req.SetBasicAuth(s.username, s.password)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, data, nil
}

func (s *elasticsearchTrafficStore) trimIfNecessary(ctx context.Context, index string, maxBytes int64, lastTrim *atomic.Int64) {
	if maxBytes <= 0 {
		return
	}
	now := time.Now().UnixNano()
	last := lastTrim.Load()
	if last != 0 && time.Duration(now-last) < s.retentionCheckPeriod {
		return
	}
	if !lastTrim.CompareAndSwap(last, now) {
		return
	}
	storeBytes, err := s.currentStoreBytes(ctx, index)
	if err != nil || storeBytes <= maxBytes {
		return
	}
	for batch := 0; storeBytes > maxBytes && batch < esMaxTrimBatches; batch++ {
		ids, err := s.oldestDocumentIDs(ctx, index)
		if err != nil || len(ids) == 0 {
			return
		}
		if err := s.bulkDelete(ctx, index, ids); err != nil {
			return
		}
		storeBytes, err = s.currentStoreBytes(ctx, index)
		if err != nil {
			return
		}
	}
}

func (s *elasticsearchTrafficStore) currentStoreBytes(ctx context.Context, index string) (int64, error) {
	var response esStatsResponse
	err := s.doJSON(ctx, http.MethodGet, "/"+url.PathEscape(index)+"/_stats/store", nil, &response)
	if err != nil {
		return 0, err
	}
	stats := response.Indices[index]
	if stats.Total.Store.TotalDataSetSizeInBytes > 0 {
		return stats.Total.Store.TotalDataSetSizeInBytes, nil
	}
	return stats.Total.Store.SizeInBytes, nil
}

func (s *elasticsearchTrafficStore) oldestDocumentIDs(ctx context.Context, index string) ([]string, error) {
	query := map[string]any{
		"query": map[string]any{"match_all": map[string]any{}},
		"size":  esTrimBatchSize,
		"sort":  []any{map[string]any{"id": map[string]any{"order": "asc"}}},
	}
	var response esSearchResponse[map[string]any]
	if err := s.doJSON(ctx, http.MethodPost, "/"+url.PathEscape(index)+"/_search", query, &response); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(response.Hits.Hits))
	for _, hit := range response.Hits.Hits {
		if hit.ID != "" {
			ids = append(ids, hit.ID)
		}
	}
	return ids, nil
}

func (s *elasticsearchTrafficStore) bulkDelete(ctx context.Context, index string, ids []string) error {
	var body strings.Builder
	for _, id := range ids {
		line, _ := json.Marshal(map[string]any{"delete": map[string]any{"_index": index, "_id": id}})
		body.Write(line)
		body.WriteByte('\n')
	}
	status, data, err := s.doRaw(ctx, http.MethodPost, "/_bulk", strings.NewReader(body.String()))
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("elasticsearch bulk delete returned HTTP %d: %s", status, string(data))
	}
	return nil
}

func (s *elasticsearchTrafficStore) documentID(existing int64) int64 {
	if existing > 0 {
		return existing
	}
	millis := time.Now().UnixMilli()
	seq := s.idSequence.Add(1) & 0xfffff
	return (millis << 20) | seq
}

type httpTrafficDocument struct {
	DocumentID          string  `json:"documentId,omitempty"`
	ID                  int64   `json:"id"`
	TenantID            string  `json:"tenantId"`
	ClientID            int64   `json:"clientId"`
	ClientName          string  `json:"clientName"`
	Route               string  `json:"route"`
	ResourceID          *int64  `json:"resourceId,omitempty"`
	ResourceName        *string `json:"resourceName,omitempty"`
	Method              string  `json:"method"`
	RelativePath        string  `json:"relativePath"`
	RawQuery            string  `json:"rawQuery"`
	StatusCode          int     `json:"statusCode"`
	Success             bool    `json:"success"`
	Error               *string `json:"error,omitempty"`
	RemoteAddress       *string `json:"remoteAddress,omitempty"`
	RequestBytes        int64   `json:"requestBytes"`
	ResponseBytes       int64   `json:"responseBytes"`
	ElapsedMs           int64   `json:"elapsedMs"`
	RequestContentType  *string `json:"requestContentType,omitempty"`
	ResponseContentType *string `json:"responseContentType,omitempty"`
	ResponseBodyType    string  `json:"responseBodyType"`
	RequestHeaders      string  `json:"requestHeaders"`
	ResponseHeaders     string  `json:"responseHeaders"`
	RequestPreviewHex   string  `json:"requestPreviewHex"`
	RequestPreviewText  string  `json:"requestPreviewText"`
	ResponsePreviewHex  string  `json:"responsePreviewHex"`
	ResponsePreviewText string  `json:"responsePreviewText"`
	RequestTruncated    bool    `json:"requestTruncated"`
	ResponseTruncated   bool    `json:"responseTruncated"`
	CapturedAt          string  `json:"capturedAt"`
}

type tcpTrafficDocument struct {
	DocumentID         string  `json:"documentId,omitempty"`
	ID                 int64   `json:"id"`
	TenantID           string  `json:"tenantId"`
	ClientID           int64   `json:"clientId"`
	ClientName         string  `json:"clientName"`
	ListenPort         int     `json:"listenPort"`
	ResourceID         *int64  `json:"resourceId,omitempty"`
	ResourceName       *string `json:"resourceName,omitempty"`
	ChannelID          string  `json:"channelId"`
	Direction          string  `json:"direction"`
	RemoteAddress      *string `json:"remoteAddress,omitempty"`
	SourceAddress      *string `json:"sourceAddress,omitempty"`
	SourcePort         *int    `json:"sourcePort,omitempty"`
	DestinationAddress *string `json:"destinationAddress,omitempty"`
	DestinationPort    *int    `json:"destinationPort,omitempty"`
	StreamOffset       int64   `json:"streamOffset"`
	StreamEndOffset    int64   `json:"streamEndOffset"`
	FrameIndex         int64   `json:"frameIndex"`
	PayloadBytes       int64   `json:"payloadBytes"`
	PayloadData        string  `json:"payloadData"`
	PayloadPreviewHex  string  `json:"payloadPreviewHex"`
	PayloadPreviewText string  `json:"payloadPreviewText"`
	Truncated          bool    `json:"truncated"`
	FrameTime          string  `json:"frameTime"`
}

func (d httpTrafficDocument) toEntity() HTTPTrafficExchange {
	return HTTPTrafficExchange{
		ID:                  d.ID,
		TenantID:            d.TenantID,
		ClientID:            d.ClientID,
		ClientName:          d.ClientName,
		Route:               d.Route,
		ResourceID:          d.ResourceID,
		ResourceName:        d.ResourceName,
		Method:              d.Method,
		RelativePath:        d.RelativePath,
		RawQuery:            d.RawQuery,
		StatusCode:          d.StatusCode,
		Success:             d.Success,
		Error:               d.Error,
		RemoteAddress:       d.RemoteAddress,
		RequestBytes:        d.RequestBytes,
		ResponseBytes:       d.ResponseBytes,
		ElapsedMs:           d.ElapsedMs,
		RequestContentType:  d.RequestContentType,
		ResponseContentType: d.ResponseContentType,
		ResponseBodyType:    classifyOrNormalizeHTTPBody(d.ResponseBodyType, d.ResponseContentType, d.ResponseBytes),
		RequestHeaders:      d.RequestHeaders,
		ResponseHeaders:     d.ResponseHeaders,
		RequestPreviewHex:   d.RequestPreviewHex,
		RequestPreviewText:  d.RequestPreviewText,
		ResponsePreviewHex:  d.ResponsePreviewHex,
		ResponsePreviewText: d.ResponsePreviewText,
		RequestTruncated:    d.RequestTruncated,
		ResponseTruncated:   d.ResponseTruncated,
		CapturedAt:          parseTime(d.CapturedAt),
	}
}

func (d tcpTrafficDocument) toEntity() TCPTrafficFrame {
	payload, _ := base64.StdEncoding.DecodeString(d.PayloadData)
	return TCPTrafficFrame{
		ID:                 d.ID,
		TenantID:           d.TenantID,
		ClientID:           d.ClientID,
		ClientName:         d.ClientName,
		ListenPort:         d.ListenPort,
		ResourceID:         d.ResourceID,
		ResourceName:       d.ResourceName,
		ChannelID:          d.ChannelID,
		Direction:          d.Direction,
		RemoteAddress:      d.RemoteAddress,
		SourceAddress:      d.SourceAddress,
		SourcePort:         d.SourcePort,
		DestinationAddress: d.DestinationAddress,
		DestinationPort:    d.DestinationPort,
		StreamOffset:       d.StreamOffset,
		StreamEndOffset:    d.StreamEndOffset,
		FrameIndex:         d.FrameIndex,
		PayloadBytes:       d.PayloadBytes,
		PayloadData:        payload,
		PayloadPreviewHex:  d.PayloadPreviewHex,
		PayloadPreviewText: d.PayloadPreviewText,
		Truncated:          d.Truncated,
		FrameTime:          parseTime(d.FrameTime),
	}
}

type esSearchResponse[T any] struct {
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Hits []struct {
			ID     string `json:"_id"`
			Source T      `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type esStatsResponse struct {
	Indices map[string]struct {
		Total struct {
			Store struct {
				SizeInBytes             int64 `json:"size_in_bytes"`
				TotalDataSetSizeInBytes int64 `json:"total_data_set_size_in_bytes"`
			} `json:"store"`
		} `json:"total"`
	} `json:"indices"`
}

func buildHTTPESQuery(filter HTTPExchangeFilter) map[string]any {
	filters := []any{esTerm("tenantId", defaultTenant(filter.TenantID))}
	if filter.ClientID != nil {
		filters = append(filters, esTerm("clientId", *filter.ClientID))
	} else if len(filter.ClientIDs) > 0 {
		filters = append(filters, esTerms("clientId", int64Terms(filter.ClientIDs)))
	}
	if filter.Route != "" {
		filters = append(filters, esTerm("route", filter.Route))
	}
	if bodyType := normalizeHTTPBodyType(filter.ResponseBodyType); bodyType != "" {
		filters = append(filters, esResponseBodyTypeQuery(bodyType))
	}
	must := []any{}
	for _, token := range strings.Fields(strings.TrimSpace(filter.Query)) {
		must = append(must, esHTTPSearchToken(filter.Field, token))
	}
	return map[string]any{"bool": map[string]any{"filter": filters, "must": must}}
}

func buildTCPESQuery(filter TCPFrameFilter, channelID string) map[string]any {
	filters := []any{esTerm("tenantId", defaultTenant(filter.TenantID))}
	if filter.ClientID != nil {
		filters = append(filters, esTerm("clientId", *filter.ClientID))
	} else if len(filter.ClientIDs) > 0 {
		filters = append(filters, esTerms("clientId", int64Terms(filter.ClientIDs)))
	}
	if filter.ListenPort != nil {
		filters = append(filters, esTerm("listenPort", *filter.ListenPort))
	}
	if channelID != "" {
		filters = append(filters, esTerm("channelId", channelID))
	}
	return map[string]any{"bool": map[string]any{"filter": filters}}
}

func esHTTPSearchToken(field, token string) map[string]any {
	field = normalizeHTTPSearchField(field)
	lower := strings.ToLower(strings.TrimSpace(token))
	switch field {
	case "id":
		if id, ok := parseInt64Token(lower); ok {
			return esTerm("id", id)
		}
		return esNoMatch()
	case "method":
		return esTerm("method", strings.ToUpper(lower))
	case "status", "statuscode", "status_code":
		if status, ok := parseInt64Token(lower); ok {
			return esTerm("statusCode", status)
		}
		return esNoMatch()
	case "route":
		return esAny(esWildcard("route", lower))
	case "path", "relativepath":
		return esAny(esMultiMatch(lower, []string{"relativePath", "rawQuery"}), esWildcard("relativePath", lower), esWildcard("rawQuery", lower))
	case "query", "rawquery":
		return esAny(esMultiMatch(lower, []string{"rawQuery"}), esWildcard("rawQuery", lower))
	case "client", "clientid", "clientname":
		queries := []any{esWildcard("clientName", lower)}
		if id, ok := parseInt64Token(lower); ok {
			queries = append(queries, esTerm("clientId", id))
		}
		return esAny(queries...)
	case "resource", "resourceid", "resourcename":
		queries := []any{esMultiMatch(lower, []string{"resourceName"}), esWildcard("resourceName", lower)}
		if id, ok := parseInt64Token(lower); ok {
			queries = append(queries, esTerm("resourceId", id))
		}
		return esAny(queries...)
	case "remote", "remoteaddress":
		return esAny(esWildcard("remoteAddress", lower))
	case "contenttype":
		return esAny(esWildcard("requestContentType", lower), esWildcard("responseContentType", lower), esTerm("responseBodyType", lower))
	case "responsebodytype", "responsedatatype":
		return esTerm("responseBodyType", lower)
	case "error":
		return esAny(esMultiMatch(lower, []string{"error"}), esWildcard("error", lower))
	case "requestheaders":
		return esAny(esMultiMatch(lower, []string{"requestHeaders"}), esWildcard("requestHeaders", lower))
	case "responseheaders":
		return esAny(esMultiMatch(lower, []string{"responseHeaders"}), esWildcard("responseHeaders", lower))
	case "headers":
		return esAny(esMultiMatch(lower, []string{"requestHeaders", "responseHeaders"}), esWildcard("requestHeaders", lower), esWildcard("responseHeaders", lower))
	case "requestbody":
		return esAny(esMultiMatch(lower, []string{"requestPreviewText"}), esWildcard("requestPreviewText", lower))
	case "responsebody":
		return esAny(esMultiMatch(lower, []string{"responsePreviewText"}), esWildcard("responsePreviewText", lower))
	case "body":
		return esAny(esMultiMatch(lower, []string{"requestPreviewText", "responsePreviewText"}), esWildcard("requestPreviewText", lower), esWildcard("responsePreviewText", lower))
	case "all":
		return esAny(esSummaryQuery(lower),
			esMultiMatch(lower, []string{"requestHeaders", "responseHeaders", "requestPreviewText", "responsePreviewText"}),
			esWildcard("requestHeaders", lower), esWildcard("responseHeaders", lower),
			esWildcard("requestPreviewText", lower), esWildcard("responsePreviewText", lower))
	default:
		return esSummaryQuery(lower)
	}
}

func esSummaryQuery(token string) map[string]any {
	should := []any{
		esMultiMatch(token, []string{"resourceName", "relativePath", "rawQuery", "error"}),
		esWildcard("clientName", token),
		esWildcard("route", token),
		esWildcard("method", token),
		esWildcard("remoteAddress", token),
		esWildcard("requestContentType", token),
		esWildcard("responseContentType", token),
		esWildcard("responseBodyType", token),
		esWildcard("capturedAt", token),
	}
	if value, ok := parseInt64Token(token); ok {
		should = append(should, esTerm("id", value), esTerm("clientId", value), esTerm("statusCode", value), esTerm("resourceId", value))
	}
	return esAny(should...)
}

func esResponseBodyTypeQuery(value string) map[string]any {
	should := []any{esTerm("responseBodyType", value)}
	if value == "empty" {
		should = append(should, esTerm("responseBytes", 0))
	} else {
		for _, pattern := range responseContentTypePatterns(value) {
			should = append(should, esWildcard("responseContentType", pattern))
		}
	}
	return esAny(should...)
}

func responseContentTypePatterns(bodyType string) []string {
	switch bodyType {
	case "json":
		return []string{"application/json", "+json"}
	case "html":
		return []string{"text/html"}
	case "xml":
		return []string{"application/xml", "text/xml", "+xml"}
	case "image":
		return []string{"image/"}
	case "video":
		return []string{"video/"}
	case "audio":
		return []string{"audio/"}
	case "form":
		return []string{"application/x-www-form-urlencoded", "multipart/form-data"}
	case "script":
		return []string{"javascript", "ecmascript"}
	case "text":
		return []string{"text/"}
	case "binary":
		return []string{"application/octet-stream", "application/pdf", "application/zip", "application/x-", "application/vnd."}
	default:
		return nil
	}
}

func esTerm(field string, value any) map[string]any {
	return map[string]any{"term": map[string]any{field: value}}
}

func esTerms(field string, values []any) map[string]any {
	return map[string]any{"terms": map[string]any{field: values}}
}

func esWildcard(field, value string) map[string]any {
	return map[string]any{"wildcard": map[string]any{field: map[string]any{
		"value":            "*" + escapeESWildcard(value) + "*",
		"case_insensitive": true,
	}}}
}

func esMultiMatch(query string, fields []string) map[string]any {
	return map[string]any{"multi_match": map[string]any{"query": query, "fields": fields}}
}

func esAny(queries ...any) map[string]any {
	should := make([]any, 0, len(queries))
	for _, query := range queries {
		if query != nil {
			should = append(should, query)
		}
	}
	if len(should) == 0 {
		return esNoMatch()
	}
	return map[string]any{"bool": map[string]any{"should": should, "minimum_should_match": 1}}
}

func esNoMatch() map[string]any {
	return esTerm("_id", "__specus_no_match__")
}

func int64Terms(values []int64) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func isDenied(clientID *int64, visibleIDs []int64) bool {
	if len(visibleIDs) == 0 {
		return false
	}
	if clientID == nil {
		return false
	}
	for _, id := range visibleIDs {
		if id == *clientID {
			return false
		}
	}
	return true
}

func classifyOrNormalizeHTTPBody(bodyType string, contentType *string, responseBytes int64) string {
	normalized := strings.ToLower(strings.TrimSpace(bodyType))
	switch normalized {
	case "empty", "json", "html", "xml", "image", "video", "audio", "form", "script", "text", "binary":
		return normalized
	}
	ct := ""
	if contentType != nil {
		ct = *contentType
	}
	return classifyHTTPBody(ct, int(responseBytes))
}

func parseInt64Token(value string) (int64, bool) {
	if value == "" {
		return 0, false
	}
	var result int64
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, false
		}
		result = result*10 + int64(r-'0')
	}
	return result, true
}

func escapeESWildcard(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `*`, `\*`)
	value = strings.ReplaceAll(value, `?`, `\?`)
	return value
}

func formatESID(id int64) string {
	return fmt.Sprintf("%d", id)
}

func httpESProperties() map[string]any {
	return map[string]any{
		"id":                  esType("long"),
		"tenantId":            esType("keyword"),
		"clientId":            esType("long"),
		"clientName":          esType("keyword"),
		"route":               esType("keyword"),
		"resourceId":          esType("long"),
		"resourceName":        esType("text"),
		"method":              esType("keyword"),
		"relativePath":        esType("text"),
		"rawQuery":            esType("text"),
		"statusCode":          esType("integer"),
		"success":             esType("boolean"),
		"error":               esType("text"),
		"remoteAddress":       esType("keyword"),
		"requestBytes":        esType("long"),
		"responseBytes":       esType("long"),
		"elapsedMs":           esType("long"),
		"requestContentType":  esType("keyword"),
		"responseContentType": esType("keyword"),
		"responseBodyType":    esType("keyword"),
		"requestHeaders":      esType("text"),
		"responseHeaders":     esType("text"),
		"requestPreviewHex":   esType("text"),
		"requestPreviewText":  esType("text"),
		"responsePreviewHex":  esType("text"),
		"responsePreviewText": esType("text"),
		"requestTruncated":    esType("boolean"),
		"responseTruncated":   esType("boolean"),
		"capturedAt":          esType("keyword"),
	}
}

func tcpESProperties() map[string]any {
	return map[string]any{
		"id":                 esType("long"),
		"tenantId":           esType("keyword"),
		"clientId":           esType("long"),
		"clientName":         esType("keyword"),
		"listenPort":         esType("integer"),
		"resourceId":         esType("long"),
		"resourceName":       esType("text"),
		"channelId":          esType("keyword"),
		"direction":          esType("keyword"),
		"remoteAddress":      esType("keyword"),
		"sourceAddress":      esType("keyword"),
		"sourcePort":         esType("integer"),
		"destinationAddress": esType("keyword"),
		"destinationPort":    esType("integer"),
		"streamOffset":       esType("long"),
		"streamEndOffset":    esType("long"),
		"frameIndex":         esType("long"),
		"payloadBytes":       esType("long"),
		"payloadData":        esType("binary"),
		"payloadPreviewHex":  esType("text"),
		"payloadPreviewText": esType("text"),
		"truncated":          esType("boolean"),
		"frameTime":          esType("keyword"),
	}
}

func esType(kind string) map[string]any {
	return map[string]any{"type": kind}
}
