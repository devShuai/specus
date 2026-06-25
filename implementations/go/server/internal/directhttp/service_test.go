package directhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/protocol"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/session"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/store"
)

func TestServeHTTPRecordsOversizedRequestDetailLikeJava(t *testing.T) {
	recorder := &capturingDetailRecorder{}
	service := NewService(nil, time.Second, 4, 1024, nil, nil, recorder, store.TrafficDetailOptions{Enabled: true})

	request := httptest.NewRequest(http.MethodPost, "/http/Demo%20client/api/upload?debug=true",
		strings.NewReader("12345"))
	request.SetPathValue("clientName", "Demo client")
	request.SetPathValue("route", "api")
	request.SetPathValue("rest", "upload")
	request.Header.Set("Content-Type", "text/plain")
	response := httptest.NewRecorder()

	service.ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", response.Code)
	}
	if recorder.record.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("record status = %d, want 413", recorder.record.StatusCode)
	}
	if recorder.record.ClientName != "Demo client" ||
		recorder.record.Route != "api" ||
		recorder.record.Method != http.MethodPost ||
		recorder.record.RelativePath != "/upload" ||
		recorder.record.RawQuery != "debug=true" {
		t.Fatalf("unexpected record metadata: %+v", recorder.record)
	}
	if recorder.record.Error != "HTTP 请求体超过限制" ||
		string(recorder.record.ResponseBody) != "HTTP 请求体超过限制" {
		t.Fatalf("unexpected error record: %+v", recorder.record)
	}
	if len(recorder.record.RequestBody) != 5 {
		t.Fatalf("recorded request body length = %d, want max+1 bytes", len(recorder.record.RequestBody))
	}
}

func TestServeHTTPRecordsOfflineErrorDetailLikeJava(t *testing.T) {
	recorder := &capturingDetailRecorder{}
	service := NewService(session.NewRegistry(), time.Second, 1024, 1024, nil, nil, recorder,
		store.TrafficDetailOptions{Enabled: true})

	request := httptest.NewRequest(http.MethodGet, "/http/Demo%20client/api/ping", nil)
	request.SetPathValue("clientName", "Demo client")
	request.SetPathValue("route", "api")
	request.SetPathValue("rest", "ping")
	response := httptest.NewRecorder()

	service.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
	if recorder.record.StatusCode != http.StatusServiceUnavailable ||
		recorder.record.Error != "客户端不在线: Demo client" ||
		string(recorder.record.ResponseBody) != "客户端不在线: Demo client" {
		t.Fatalf("unexpected offline record: %+v", recorder.record)
	}
	if got := strings.Join(recorder.record.ResponseHeaders, "\n"); !strings.Contains(got, "Content-Type:text/plain;charset=UTF-8") {
		t.Fatalf("error headers = %q, want plain text content type", got)
	}
}

func TestServeHTTPRecordsClientErrorResponseDetailLikeJava(t *testing.T) {
	recorder := &capturingDetailRecorder{}
	registry := session.NewRegistry()
	service := NewService(registry, time.Second, 1024, 1024, nil, nil, recorder,
		store.TrafficDetailOptions{Enabled: true})
	registry.Replace(&fakeDirectHTTPSession{clientName: "Demo client", send: func(packet protocol.Packet) error {
		request := packet.(protocol.DirectHTTPRequest)
		service.Ack(protocol.DirectHTTPResponse{
			RequestID:  request.RequestID,
			StatusCode: http.StatusBadGateway,
			Headers:    []string{"X-Upstream:ignored"},
			Body:       []byte("ignored upstream body"),
			Error:      stringPtr("upstream failed"),
		})
		return nil
	}})

	request := httptest.NewRequest(http.MethodGet, "/http/Demo%20client/api/ping", nil)
	request.SetPathValue("clientName", "Demo client")
	request.SetPathValue("route", "api")
	request.SetPathValue("rest", "ping")
	response := httptest.NewRecorder()

	service.ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", response.Code)
	}
	if recorder.record.StatusCode != http.StatusBadGateway ||
		recorder.record.Error != "upstream failed" ||
		string(recorder.record.ResponseBody) != "upstream failed" {
		t.Fatalf("unexpected client error record: %+v", recorder.record)
	}
	if got := strings.Join(recorder.record.ResponseHeaders, "\n"); got != "Content-Type:text/plain;charset=UTF-8" {
		t.Fatalf("recorded response headers = %q, want Java plain error headers", got)
	}
}

func TestServeHTTPRecordsWriteFailureDetailLikeJava(t *testing.T) {
	recorder := &capturingDetailRecorder{}
	traffic := &capturingTrafficRecorder{}
	registry := session.NewRegistry()
	service := NewService(registry, time.Second, 1024, 1024, traffic, nil, recorder,
		store.TrafficDetailOptions{Enabled: true})
	registry.Replace(&fakeDirectHTTPSession{clientName: "Demo client", send: func(protocol.Packet) error {
		return errors.New("socket closed")
	}})

	request := httptest.NewRequest(http.MethodPost, "/http/Demo%20client/api/ping", strings.NewReader("abc"))
	request.SetPathValue("clientName", "Demo client")
	request.SetPathValue("route", "api")
	request.SetPathValue("rest", "ping")
	response := httptest.NewRecorder()

	service.ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", response.Code)
	}
	if recorder.record.StatusCode != http.StatusBadGateway ||
		recorder.record.Method != http.MethodPost ||
		recorder.record.Error != "HTTP 转发请求发送失败" ||
		string(recorder.record.ResponseBody) != "HTTP 转发请求发送失败" {
		t.Fatalf("unexpected write failure record: %+v", recorder.record)
	}
	if got := strings.Join(recorder.record.ResponseHeaders, "\n"); got != "Content-Type:text/plain;charset=UTF-8" {
		t.Fatalf("recorded response headers = %q, want Java plain error headers", got)
	}
	if traffic.upload != 3 || traffic.download != 0 {
		t.Fatalf("traffic upload/download = %d/%d, want Java write-failure accounting 3/0",
			traffic.upload, traffic.download)
	}
}

func TestServeHTTPPreservesEncodedRelativePathLikeJava(t *testing.T) {
	recorder := &capturingDetailRecorder{}
	registry := session.NewRegistry()
	service := NewService(registry, time.Second, 1024, 1024, nil, nil, recorder,
		store.TrafficDetailOptions{Enabled: true})
	var captured protocol.DirectHTTPRequest
	registry.Replace(&fakeDirectHTTPSession{clientName: "Demo client", send: func(packet protocol.Packet) error {
		captured = packet.(protocol.DirectHTTPRequest)
		service.Ack(protocol.DirectHTTPResponse{
			RequestID:  captured.RequestID,
			StatusCode: http.StatusOK,
			Headers:    []string{"Content-Type:text/plain"},
			Body:       []byte("ok"),
		})
		return nil
	}})

	request := httptest.NewRequest(http.MethodGet,
		"/http/Demo%20client/api/%E4%BD%A0%2Fok/%252F?x=%2F", nil)
	request.SetPathValue("clientName", "Demo client")
	request.SetPathValue("route", "api")
	request.SetPathValue("rest", "你/ok/%2F")
	response := httptest.NewRecorder()

	service.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if captured.RelativePath != "/%E4%BD%A0%2Fok/%252F" {
		t.Fatalf("relativePath = %q, want Java raw encoded path", captured.RelativePath)
	}
	if recorder.record.RelativePath != "/%E4%BD%A0%2Fok/%252F" || recorder.record.RawQuery != "x=%2F" {
		t.Fatalf("record path/query = %q/%q, want encoded Java shape",
			recorder.record.RelativePath, recorder.record.RawQuery)
	}
}

type capturingDetailRecorder struct {
	record store.HTTPExchangeRecord
}

func (r *capturingDetailRecorder) RecordHTTPExchange(_ context.Context, record store.HTTPExchangeRecord) error {
	r.record = record
	return nil
}

type capturingTrafficRecorder struct {
	upload   int64
	download int64
}

func (r *capturingTrafficRecorder) RecordHTTPUpload(_, _ string, bytes int64) {
	r.upload += bytes
}

func (r *capturingTrafficRecorder) RecordHTTPDownload(_, _ string, bytes int64) {
	r.download += bytes
}

type fakeDirectHTTPSession struct {
	clientName string
	send       func(protocol.Packet) error
}

func (s *fakeDirectHTTPSession) ClientName() string { return s.clientName }

func (s *fakeDirectHTTPSession) LoginTimeMs() int64 { return 0 }

func (s *fakeDirectHTTPSession) Send(packet protocol.Packet) error { return s.send(packet) }

func (s *fakeDirectHTTPSession) Close(string) {}
