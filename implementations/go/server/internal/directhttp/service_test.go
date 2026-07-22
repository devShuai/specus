package directhttp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/protocol"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/session"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/store"
)

func TestServeHTTPRejectsKnownOversizedRequestBeforeOpeningStream(t *testing.T) {
	recorder := &capturingDetailRecorder{}
	opened := false
	service := NewService(nil, func(string, map[string]any) (Stream, error) {
		opened = true
		return nil, nil
	}, nil, time.Second, 4, 1024, nil, nil, recorder, store.TrafficDetailOptions{Enabled: true})
	request := tunnelRequest(http.MethodPost, "/http/Demo%20client/api/upload?debug=true", "12345")
	response := httptest.NewRecorder()

	service.ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge || opened {
		t.Fatalf("status/opened = %d/%t, want 413/false", response.Code, opened)
	}
	if recorder.record.Error != errRequestTooLarge.Error() || string(recorder.record.RequestBody) != "12345" {
		t.Fatalf("unexpected detail: %+v", recorder.record)
	}
}

func TestServeHTTPRecordsOfflineError(t *testing.T) {
	recorder := &capturingDetailRecorder{}
	service := NewService(session.NewRegistry(), nil, nil, time.Second, 1024, 1024,
		nil, nil, recorder, store.TrafficDetailOptions{Enabled: true})
	request := tunnelRequest(http.MethodGet, "/http/Demo%20client/api/ping", "")
	response := httptest.NewRecorder()

	service.ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway || recorder.record.Error != "客户端不在线: Demo client" {
		t.Fatalf("unexpected offline response/detail: %d %+v", response.Code, recorder.record)
	}
}

func TestServeHTTPStreamsRequestAndResponseWithCredit(t *testing.T) {
	recorder := &capturingDetailRecorder{}
	traffic := &capturingTrafficRecorder{}
	registry := onlineRegistry("Demo client")
	stream := newFakeStream()
	stream.head = map[string]any{
		"statusCode": 201,
		"headers":    []string{"Content-Type:text/plain", "X-Upstream:ok"},
	}
	stream.responses = []fakeResponse{
		{data: []byte("first-")}, {data: []byte("second")}, {end: true},
	}
	var opened map[string]any
	service := NewService(registry, func(_ string, metadata map[string]any) (Stream, error) {
		opened = metadata
		return stream, nil
	}, nil, time.Second, 1024, 1024, traffic, nil, recorder, store.TrafficDetailOptions{Enabled: true})
	request := tunnelRequest(http.MethodPatch, "/http/Demo%20client/api/items?x=%2F", "request-body")
	request.Header.Set("X-Request", "yes")
	response := httptest.NewRecorder()

	service.ServeHTTP(response, request)

	if response.Code != 201 || response.Body.String() != "first-second" {
		t.Fatalf("response = %d/%q", response.Code, response.Body.String())
	}
	if string(stream.requestBody()) != "request-body" || stream.consumed != len("first-second") {
		t.Fatalf("stream request/credit = %q/%d", stream.requestBody(), stream.consumed)
	}
	if opened["method"] != http.MethodPatch || opened["relativePath"] != "/items" || opened["rawQuery"] != "x=%2F" {
		t.Fatalf("unexpected OPEN metadata: %+v", opened)
	}
	if traffic.upload != int64(len("request-body")) || traffic.download != int64(len("first-second")) {
		t.Fatalf("traffic = %d/%d", traffic.upload, traffic.download)
	}
}

func TestServeHTTPPreservesEncodedRelativePath(t *testing.T) {
	registry := onlineRegistry("Demo client")
	stream := newFakeStream()
	stream.head = map[string]any{"statusCode": 200, "headers": []string{"Content-Type:text/plain"}}
	stream.responses = []fakeResponse{{data: []byte("ok")}, {end: true}}
	var opened map[string]any
	service := NewService(registry, func(_ string, metadata map[string]any) (Stream, error) {
		opened = metadata
		return stream, nil
	}, nil, time.Second, 1024, 1024, nil, nil, nil, store.TrafficDetailOptions{})
	request := tunnelRequest(http.MethodGet, "/http/Demo%20client/api/%E4%BD%A0%2Fok/%252F?x=%2F", "")
	response := httptest.NewRecorder()

	service.ServeHTTP(response, request)

	if opened["relativePath"] != "/%E4%BD%A0%2Fok/%252F" || opened["rawQuery"] != "x=%2F" {
		t.Fatalf("unexpected path/query: %+v", opened)
	}
}

func TestServeHTTPPropagatesHeaderTimeoutAsReset(t *testing.T) {
	registry := onlineRegistry("Demo client")
	stream := newFakeStream()
	stream.blockHead = true
	service := NewService(registry, func(string, map[string]any) (Stream, error) { return stream, nil },
		nil, 10*time.Millisecond, 1024, 1024, nil, nil, nil, store.TrafficDetailOptions{})
	response := httptest.NewRecorder()

	service.ServeHTTP(response, tunnelRequest(http.MethodGet, "/http/Demo%20client/api/ping", ""))

	if response.Code != http.StatusGatewayTimeout || stream.resetReason == "" {
		t.Fatalf("timeout response/reset = %d/%q", response.Code, stream.resetReason)
	}
}

func tunnelRequest(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.SetPathValue("clientName", "Demo client")
	request.SetPathValue("route", "api")
	if index := strings.Index(target, "/api/"); index >= 0 {
		rest := target[index+len("/api/"):]
		if query := strings.IndexByte(rest, '?'); query >= 0 {
			rest = rest[:query]
		}
		request.SetPathValue("rest", rest)
	}
	return request
}

func onlineRegistry(name string) *session.Registry {
	registry := session.NewRegistry()
	registry.Replace(&fakeOnlineSession{name: name})
	return registry
}

type fakeOnlineSession struct{ name string }

func (s *fakeOnlineSession) ClientName() string       { return s.name }
func (*fakeOnlineSession) LoginTimeMs() int64         { return 0 }
func (*fakeOnlineSession) Send(protocol.Packet) error { return nil }
func (*fakeOnlineSession) Close(string)               {}

type fakeResponse struct {
	data     []byte
	metadata map[string]any
	end      bool
	err      error
}

type fakeStream struct {
	mu            sync.Mutex
	request       bytes.Buffer
	finished      chan struct{}
	finishOnce    sync.Once
	head          map[string]any
	responses     []fakeResponse
	responseIndex int
	consumed      int
	resetReason   string
	blockHead     bool
}

func newFakeStream() *fakeStream { return &fakeStream{finished: make(chan struct{})} }
func (s *fakeStream) SendData(_ context.Context, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.request.Write(data)
	return nil
}
func (s *fakeStream) FinishRequest(map[string]any) error {
	s.finishOnce.Do(func() { close(s.finished) })
	return nil
}
func (s *fakeStream) WaitResponseHead(ctx context.Context) (map[string]any, error) {
	if s.blockHead {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	select {
	case <-s.finished:
		return s.head, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (s *fakeStream) ReadResponse(context.Context) ([]byte, map[string]any, bool, error) {
	if s.responseIndex >= len(s.responses) {
		return nil, nil, false, errors.New("missing response event")
	}
	event := s.responses[s.responseIndex]
	s.responseIndex++
	return event.data, event.metadata, event.end, event.err
}
func (s *fakeStream) Consume(bytes int) error       { s.consumed += bytes; return nil }
func (s *fakeStream) Reset(_ uint32, reason string) { s.resetReason = reason }
func (*fakeStream) Close()                          {}
func (s *fakeStream) requestBody() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.request.Bytes()...)
}

type capturingDetailRecorder struct{ record store.HTTPExchangeRecord }

func (r *capturingDetailRecorder) RecordHTTPExchange(_ context.Context, record store.HTTPExchangeRecord) error {
	r.record = record
	return nil
}

type capturingTrafficRecorder struct{ upload, download int64 }

func (r *capturingTrafficRecorder) RecordHTTPUpload(_, _ string, bytes int64)   { r.upload += bytes }
func (r *capturingTrafficRecorder) RecordHTTPDownload(_, _ string, bytes int64) { r.download += bytes }
