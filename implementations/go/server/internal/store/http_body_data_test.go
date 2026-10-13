package store

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var pngBody = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0, 0, 13, 'I', 'H', 'D', 'R'}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	if _, err := writer.Write(data); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return out.Bytes()
}

// bodyCaptureDB is a client with a capturing route "bodies" and a queue to flush by hand.
func bodyCaptureDB(t *testing.T, path string) *DB {
	t.Helper()
	db, err := Open("sqlite", path)
	if err != nil {
		t.Fatalf("open temp db: %v", err)
	}
	db.ConfigureTrafficDetailQueue(10, 10)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.InsertClientIfAbsent(ctx, ClientAccount{
		ID: 1001, TenantID: "default", OwnerUsername: "admin", ClientName: "body-client",
		PasswordHash: "hash", Enabled: true, ConnectionRateLimitPerMinute: 30, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("insert client: %v", err)
	}
	if err := db.InsertHTTPRoute(ctx, HTTPRouteMapping{
		ID: 2001, ClientID: 1001, ClientName: "body-client", Route: "bodies",
		TargetBaseURL: "http://127.0.0.1:8080", Enabled: true, DetailCaptureEnabled: true,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("insert route: %v", err)
	}
	return db
}

func recordBody(t *testing.T, db *DB, path string, responseHeaders []string, body []byte) {
	t.Helper()
	if err := db.RecordHTTPExchange(context.Background(), HTTPExchangeRecord{
		ClientName:      "body-client",
		Route:           "bodies",
		Method:          "GET",
		RelativePath:    path,
		StatusCode:      200,
		ResponseHeaders: responseHeaders,
		ResponseBody:    body,
		StartedAt:       time.Now(),
		Options:         TrafficDetailOptions{Enabled: true},
	}); err != nil {
		t.Fatalf("record %s: %v", path, err)
	}
}

func detailByPath(t *testing.T, db *DB, path string) *HTTPTrafficExchange {
	t.Helper()
	ctx := context.Background()
	items, _, err := db.ListHTTPExchanges(ctx, HTTPExchangeFilter{TenantID: "default", Field: "path", Query: path, Size: 20})
	if err != nil || len(items) != 1 {
		t.Fatalf("list %s: %d items, %v", path, len(items), err)
	}
	if items[0].ResponsePreviewText != "" || items[0].ResponseBodyData != nil {
		t.Fatalf("summary of %s carried the body: %q", path, items[0].ResponsePreviewText)
	}
	detail, err := db.GetHTTPExchange(ctx, "default", items[0].ID, nil)
	if err != nil {
		t.Fatalf("detail %s: %v", path, err)
	}
	return detail
}

// TrafficInspectionServiceTests and HttpBodyDataCodec in Java: the body is kept as received, the
// preview is the first capture-preview-bytes, and the detail shows the decoded body.
func TestHTTPBodiesAreStoredAndShownAsJava(t *testing.T) {
	db := bodyCaptureDB(t, filepath.Join(t.TempDir(), "bodies.db"))
	defer db.Close()
	longText := strings.Repeat("a", 300) + " needle-deep"
	jsonBody := []byte(`{"items":[1,2,3]}`)
	recordBody(t, db, "/long", []string{"Content-Type: text/plain"}, []byte(longText))
	recordBody(t, db, "/gzip", []string{"Content-Type: application/json", "Content-Encoding: gzip"}, gzipBytes(t, jsonBody))
	recordBody(t, db, "/png", []string{"Content-Type: image/png"}, pngBody)
	recordBody(t, db, "/broken", []string{"Content-Type: application/json", "Content-Encoding: gzip"}, []byte("not gzip"))
	if err := db.FlushTrafficDetails(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	long := detailByPath(t, db, "/long")
	if long.ResponsePreviewText != longText || long.ResponseTruncated {
		t.Fatalf("long text detail = %q truncated=%v, want the whole body", long.ResponsePreviewText, long.ResponseTruncated)
	}
	if want := strings.TrimSuffix(strings.Repeat("61 ", 256), " "); long.ResponsePreviewHex != want {
		t.Fatalf("long text preview hex = %q", long.ResponsePreviewHex)
	}
	if got := detailByPath(t, db, "/gzip").ResponsePreviewText; got != string(jsonBody) {
		t.Fatalf("gzip detail = %q, want the decoded JSON", got)
	}
	if got, want := detailByPath(t, db, "/png").ResponsePreviewText,
		"data:image/png;base64,"+base64.StdEncoding.EncodeToString(pngBody); got != want {
		t.Fatalf("png detail = %q, want %q", got, want)
	}
	if got, want := detailByPath(t, db, "/broken").ResponsePreviewText,
		"data:application/octet-stream;base64,"+base64.StdEncoding.EncodeToString([]byte("not gzip")); got != want {
		t.Fatalf("undecodable detail = %q, want %q", got, want)
	}

	// A body search looks at the first capture-preview-bytes characters only, as Java's does.
	ctx := context.Background()
	if _, total, err := db.ListHTTPExchanges(ctx, HTTPExchangeFilter{TenantID: "default", Field: "responseBody", Query: "needle", Size: 20}); err != nil || total != 0 {
		t.Fatalf("search past the preview: total=%d err=%v, want none", total, err)
	}
	if _, total, err := db.ListHTTPExchanges(ctx, HTTPExchangeFilter{TenantID: "default", Field: "responseBody", Query: "items", Size: 20}); err != nil || total != 1 {
		t.Fatalf("search the decoded JSON: total=%d err=%v, want one", total, err)
	}
}

// A database from before the body columns gets them added; its exchanges keep their preview text.
func TestHTTPBodyColumnsAreAddedToAnOlderDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "older.db")
	db := bodyCaptureDB(t, path)
	ctx := context.Background()
	for _, column := range []string{"request_body_data", "response_body_data"} {
		if _, err := db.sql.ExecContext(ctx, "ALTER TABLE specus_http_traffic_exchange DROP COLUMN "+column); err != nil {
			t.Fatalf("drop %s: %v", column, err)
		}
	}
	textType := "text/plain"
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO specus_http_traffic_exchange
		(tenant_id, client_id, client_name, route, method, relative_path, raw_query, status_code, success,
		 request_bytes, response_bytes, elapsed_ms, response_content_type, response_body_type,
		 request_headers, response_headers, request_preview_hex, request_preview_text,
		 response_preview_hex, response_preview_text, request_truncated, response_truncated, captured_at)
		VALUES ('default', 1001, 'body-client', 'bodies', 'GET', '/before', '', 200, 1, 0, 5, 1, ?, 'text',
		 '', 'Content-Type: text/plain', '', '', '68 65 6C 6C 6F', 'hello', 0, 0, ?)`,
		textType, formatTime(time.Now())); err != nil {
		t.Fatalf("insert an exchange of the older layout: %v", err)
	}
	db.Close()

	db, err := Open("sqlite", path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db.Close()
	for _, column := range []string{"request_body_data", "response_body_data"} {
		if exists, err := db.columnExists("specus_http_traffic_exchange", column); err != nil || !exists {
			t.Fatalf("column %s after reopening: exists=%v err=%v", column, exists, err)
		}
	}
	if got := detailByPath(t, db, "/before").ResponsePreviewText; got != "hello" {
		t.Fatalf("older exchange detail = %q, want its preview text", got)
	}
}

// fakeElasticsearch keeps documents by id and records what the store asked for.
type fakeElasticsearch struct {
	mu           sync.Mutex
	indexExists  bool
	mappingPuts  []string
	docs         map[string]json.RawMessage
	listExcludes []string
}

func (f *fakeElasticsearch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.Method == http.MethodHead:
		if f.indexExists {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/_mapping"):
		f.mappingPuts = append(f.mappingPuts, string(body))
		_, _ = w.Write([]byte(`{"acknowledged":true}`))
	case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/_doc/"):
		f.docs[r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]] = append(json.RawMessage(nil), body...)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"result":"created"}`))
	case r.Method == http.MethodPut:
		f.indexExists = true
		_, _ = w.Write([]byte(`{"acknowledged":true}`))
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/_search"):
		var request struct {
			Source struct {
				Excludes []string `json:"excludes"`
			} `json:"_source"`
		}
		_ = json.Unmarshal(body, &request)
		hits := make([]map[string]any, 0, len(f.docs))
		for _, doc := range f.docs {
			var source map[string]any
			_ = json.Unmarshal(doc, &source)
			if len(request.Source.Excludes) > 0 {
				f.listExcludes = request.Source.Excludes
				for _, field := range request.Source.Excludes {
					delete(source, field)
				}
			}
			hits = append(hits, map[string]any{"_source": source})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{
			"total": map[string]any{"value": len(hits)}, "hits": hits}})
	default:
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}
}

// SpringDataElasticsearchHttpTrafficExchangeStore: an existing index gets the binary body fields,
// the list leaves the bodies out, and the detail shows them.
func TestElasticsearchHTTPBodiesAsJava(t *testing.T) {
	fake := &fakeElasticsearch{indexExists: true, docs: map[string]json.RawMessage{}}
	server := httptest.NewServer(fake)
	defer server.Close()
	db := bodyCaptureDB(t, filepath.Join(t.TempDir(), "es.db"))
	defer db.Close()
	ctx := context.Background()
	if err := db.UseElasticsearchTraffic(ctx, ElasticsearchTrafficOptions{URIs: []string{server.URL}}); err != nil {
		t.Fatalf("use elasticsearch: %v", err)
	}
	fake.mu.Lock()
	puts := append([]string(nil), fake.mappingPuts...)
	fake.mu.Unlock()
	// The HTTP index gets the two fields; the TCP index has nothing to add.
	if len(puts) != 1 || !strings.Contains(puts[0], `"requestBodyData":{"type":"binary"}`) ||
		!strings.Contains(puts[0], `"responseBodyData":{"type":"binary"}`) {
		t.Fatalf("mapping updates of the existing indices = %q", puts)
	}

	recordBody(t, db, "/png", []string{"Content-Type: image/png"}, pngBody)
	if err := db.FlushTrafficDetails(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	items, total, err := db.ListHTTPExchanges(ctx, HTTPExchangeFilter{TenantID: "default", Size: 20})
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("list: total=%d len=%d err=%v", total, len(items), err)
	}
	fake.mu.Lock()
	excludes := strings.Join(fake.listExcludes, ",")
	fake.mu.Unlock()
	if !strings.Contains(excludes, "requestBodyData") || !strings.Contains(excludes, "responseBodyData") {
		t.Fatalf("list excludes = %q, want the body fields", excludes)
	}
	if items[0].ResponseBodyData != nil {
		t.Fatal("summary carried the body")
	}
	detail, err := db.GetHTTPExchange(ctx, "default", items[0].ID, []int64{1001})
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if want := "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBody); detail.ResponsePreviewText != want {
		t.Fatalf("detail = %q, want %q", detail.ResponsePreviewText, want)
	}
}
