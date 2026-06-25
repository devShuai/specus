package store

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
)

func TestListHTTPExchangesSearchMatchesJavaFieldSemantics(t *testing.T) {
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatalf("open temp db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	resourceName := "api -> https://example.com/base"
	remoteAddress := "127.0.0.1:62000"
	jsonType := "application/json"
	now := time.Date(2026, 6, 25, 10, 0, 0, 0, time.UTC)
	if err := db.InsertHTTPExchange(ctx, HTTPTrafficExchange{
		TenantID:            "default",
		ClientID:            1,
		ClientName:          "Demo client",
		Route:               "api",
		ResourceName:        &resourceName,
		Method:              "POST",
		RelativePath:        "/items",
		RawQuery:            "page=1",
		StatusCode:          201,
		Success:             true,
		RemoteAddress:       &remoteAddress,
		RequestBytes:        14,
		ResponseBytes:       11,
		ElapsedMs:           12,
		RequestContentType:  &jsonType,
		ResponseContentType: &jsonType,
		ResponseBodyType:    "json",
		RequestHeaders:      "Content-Type: application/json",
		ResponseHeaders:     "Content-Type: application/json",
		RequestPreviewText:  `{"hello":true}`,
		ResponsePreviewText: `{"ok":true}`,
		CapturedAt:          now,
	}); err != nil {
		t.Fatalf("insert POST exchange: %v", err)
	}
	if err := db.InsertHTTPExchange(ctx, HTTPTrafficExchange{
		TenantID:            "default",
		ClientID:            2,
		ClientName:          "Other client",
		Route:               "assets",
		Method:              "GET",
		RelativePath:        "/vendor.js",
		StatusCode:          200,
		Success:             true,
		RequestBytes:        0,
		ResponseBytes:       1024,
		ElapsedMs:           6,
		ResponseBodyType:    "script",
		RequestHeaders:      "X-Debug-Method: POST",
		ResponseHeaders:     "Content-Type: text/javascript",
		ResponsePreviewText: "console.log('ready')",
		CapturedAt:          now.Add(time.Second),
	}); err != nil {
		t.Fatalf("insert GET exchange: %v", err)
	}
	imageType := "image/png;charset=UTF-8"
	if err := db.InsertHTTPExchange(ctx, HTTPTrafficExchange{
		TenantID:            "default",
		ClientID:            1,
		ClientName:          "Demo client",
		Route:               "legacy-image",
		Method:              "GET",
		RelativePath:        "/logo.png",
		StatusCode:          200,
		Success:             true,
		ResponseBytes:       42,
		ResponseContentType: &imageType,
		ResponseBodyType:    "",
		CapturedAt:          now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("insert legacy image exchange: %v", err)
	}
	if err := db.InsertHTTPExchange(ctx, HTTPTrafficExchange{
		TenantID:         "default",
		ClientID:         1,
		ClientName:       "Demo client",
		Route:            "legacy-empty",
		Method:           "GET",
		RelativePath:     "/empty",
		StatusCode:       204,
		Success:          true,
		ResponseBytes:    0,
		ResponseBodyType: "",
		CapturedAt:       now.Add(3 * time.Second),
	}); err != nil {
		t.Fatalf("insert legacy empty exchange: %v", err)
	}

	assertSinglePOST := func(name string, filter HTTPExchangeFilter) {
		t.Helper()
		items, total, err := db.ListHTTPExchanges(ctx, filter)
		if err != nil {
			t.Fatalf("%s query failed: %v", name, err)
		}
		if total != 1 || len(items) != 1 || items[0].Method != "POST" {
			t.Fatalf("%s returned total=%d len=%d method=%q, want one POST", name, total, len(items), firstMethod(items))
		}
	}

	assertSinglePOST("tokenized summary", HTTPExchangeFilter{TenantID: "default", Query: "POST api", Size: 20})
	assertSinglePOST("method exact", HTTPExchangeFilter{TenantID: "default", Field: "method", Query: "POST", Size: 20})
	assertSinglePOST("status exact", HTTPExchangeFilter{TenantID: "default", Field: "status", Query: "201", Size: 20})
	assertSinglePOST("response data type alias", HTTPExchangeFilter{TenantID: "default", Field: "responseDataType", Query: "json", Size: 20})

	imageItems, imageTotal, err := db.ListHTTPExchanges(ctx, HTTPExchangeFilter{
		TenantID: "default", Route: "legacy-image", ResponseBodyType: "image", Size: 20,
	})
	if err != nil {
		t.Fatalf("image body type query failed: %v", err)
	}
	if imageTotal != 1 || len(imageItems) != 1 || imageItems[0].ResponseBodyType != "image" {
		t.Fatalf("image body type fallback returned total=%d len=%d type=%q",
			imageTotal, len(imageItems), firstResponseBodyType(imageItems))
	}

	emptyItems, emptyTotal, err := db.ListHTTPExchanges(ctx, HTTPExchangeFilter{
		TenantID: "default", Route: "legacy-empty", ResponseBodyType: "empty", Size: 20,
	})
	if err != nil {
		t.Fatalf("empty body type query failed: %v", err)
	}
	if emptyTotal != 1 || len(emptyItems) != 1 || emptyItems[0].ResponseBodyType != "empty" {
		t.Fatalf("empty body type fallback returned total=%d len=%d type=%q",
			emptyTotal, len(emptyItems), firstResponseBodyType(emptyItems))
	}

	unsupportedItems, unsupportedTotal, err := db.ListHTTPExchanges(ctx, HTTPExchangeFilter{
		TenantID: "default", Route: "legacy-image", ResponseBodyType: "unknown", Size: 20,
	})
	if err != nil {
		t.Fatalf("unsupported body type query failed: %v", err)
	}
	if unsupportedTotal != 1 || len(unsupportedItems) != 1 {
		t.Fatalf("unsupported response body type should be ignored like Java, got total=%d len=%d",
			unsupportedTotal, len(unsupportedItems))
	}
}

func TestRecordHTTPExchangeQueuesAndFlushesLikeJava(t *testing.T) {
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "traffic-queue.db"))
	if err != nil {
		t.Fatalf("open temp db: %v", err)
	}
	defer db.Close()
	db.ConfigureTrafficDetailQueue(10, 10)

	ctx := context.Background()
	now := time.Now().UTC()
	inserted, err := db.InsertClientIfAbsent(ctx, ClientAccount{
		ID:                           1001,
		TenantID:                     "default",
		OwnerUsername:                "admin",
		ClientName:                   "queued-client",
		PasswordHash:                 "hash",
		Enabled:                      true,
		ConnectionRateLimitPerMinute: 30,
		CreatedAt:                    now,
		UpdatedAt:                    now,
	})
	if err != nil {
		t.Fatalf("insert client: %v", err)
	}
	if !inserted {
		t.Fatal("client should be inserted")
	}
	if err := db.InsertHTTPRoute(ctx, HTTPRouteMapping{
		ID:                   2001,
		ClientID:             1001,
		ClientName:           "queued-client",
		Route:                "queued",
		TargetBaseURL:        "http://127.0.0.1:8080",
		Enabled:              true,
		DetailCaptureEnabled: true,
		CreatedAt:            now,
		UpdatedAt:            now,
	}); err != nil {
		t.Fatalf("insert route: %v", err)
	}

	if err := db.RecordHTTPExchange(ctx, HTTPExchangeRecord{
		ClientName:      "queued-client",
		Route:           "queued",
		Method:          "GET",
		RelativePath:    "/health",
		RawQuery:        "ok=true",
		RequestHeaders:  []string{"Accept: application/json"},
		StatusCode:      200,
		ResponseHeaders: []string{"Content-Type: application/json"},
		ResponseBody:    []byte(`{"ok":true}`),
		StartedAt:       now,
		RemoteAddress:   "127.0.0.1:61000",
		Options:         TrafficDetailOptions{Enabled: true},
	}); err != nil {
		t.Fatalf("record queued exchange: %v", err)
	}

	items, total, err := db.ListHTTPExchanges(ctx, HTTPExchangeFilter{TenantID: "default", Route: "queued", Size: 20})
	if err != nil {
		t.Fatalf("list before flush: %v", err)
	}
	if total != 0 || len(items) != 0 {
		t.Fatalf("before flush total=%d len=%d, want zero", total, len(items))
	}

	if err := db.FlushTrafficDetails(ctx); err != nil {
		t.Fatalf("flush details: %v", err)
	}
	items, total, err = db.ListHTTPExchanges(ctx, HTTPExchangeFilter{TenantID: "default", Route: "queued", Size: 20})
	if err != nil {
		t.Fatalf("list after flush: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("after flush total=%d len=%d, want one", total, len(items))
	}
	if got := items[0].ResponseBodyType; got != "json" {
		t.Fatalf("response body type = %q, want json", got)
	}
	if got := items[0].ResponsePreviewText; got != `{"ok":true}` {
		t.Fatalf("response preview = %q", got)
	}
}

func TestDecodeBodySupportsZlibAndRawDeflate(t *testing.T) {
	plain := []byte(`{"ok":true,"message":"hello"}`)

	if got := decodeBody(zlibDeflate(t, plain), "deflate"); !bytes.Equal(got, plain) {
		t.Fatalf("zlib deflate decoded to %q, want %q", got, plain)
	}

	if got := decodeBody(rawDeflate(t, plain), "deflate"); !bytes.Equal(got, plain) {
		t.Fatalf("raw deflate decoded to %q, want %q", got, plain)
	}
}

func TestDecodeBodySupportsBrotli(t *testing.T) {
	plain := []byte(`<html><body>hello</body></html>`)
	if got := decodeBody(brotliCompress(t, plain), "br"); !bytes.Equal(got, plain) {
		t.Fatalf("brotli decoded to %q, want %q", got, plain)
	}
}

func firstMethod(items []HTTPTrafficExchange) string {
	if len(items) == 0 {
		return ""
	}
	return items[0].Method
}

func firstResponseBodyType(items []HTTPTrafficExchange) string {
	if len(items) == 0 {
		return ""
	}
	return items[0].ResponseBodyType
}

func zlibDeflate(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)
	if _, err := writer.Write(data); err != nil {
		t.Fatalf("write zlib: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zlib: %v", err)
	}
	return buf.Bytes()
}

func rawDeflate(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("new flate writer: %v", err)
	}
	if _, err := writer.Write(data); err != nil {
		t.Fatalf("write raw deflate: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close raw deflate: %v", err)
	}
	return buf.Bytes()
}

func brotliCompress(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := brotli.NewWriter(&buf)
	if _, err := writer.Write(data); err != nil {
		t.Fatalf("write brotli: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close brotli: %v", err)
	}
	return buf.Bytes()
}
