package directhttp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestServeHTTPRejectsKnownOversizedRequestBeforeOpeningStream(t *testing.T) {
	recorder := &capturingDetailRecorder{}
	opened := false
	service := NewService(nil, func(string, map[string]any) (Stream, error) {
		opened = true
		return nil, nil
	}, nil, time.Second, 4, 1024, nil, nil, recorder, store.TrafficDetailOptions{Enabled: true})
	request := specusRequest(http.MethodPost, "/http/Demo%20client/api/upload?debug=true", "12345")
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
	request := specusRequest(http.MethodGet, "/http/Demo%20client/api/ping", "")
	response := httptest.NewRecorder()

	service.ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway || recorder.record.Error != "客户端不在线: Demo client" {
		t.Fatalf("unexpected offline response/detail: %d %+v", response.Code, recorder.record)
	}
}

func TestServeHTTPWaitsForDataReconnect(t *testing.T) {
	registry := session.NewRegistry()
	control := &fakeOnlineSession{name: "Demo client"}
	data := &fakeOnlineSession{name: "Demo client"}
	registry.Replace(control)
	registry.ReplaceData(data)
	registry.Unbind("Demo client", data)
	stream := newFakeStream()
	stream.head = map[string]any{"statusCode": 200, "headers": []string{"Content-Type:text/plain"}}
	stream.responses = []fakeResponse{{data: []byte("ok")}, {end: true}}
	service := NewService(registry, func(string, map[string]any) (Stream, error) {
		return stream, nil
	}, nil, time.Second, 1024, 1024, nil, nil, nil, store.TrafficDetailOptions{})
	service.SetReconnectGrace(500 * time.Millisecond)

	reconnected := make(chan struct{})
	go func() {
		time.Sleep(20 * time.Millisecond)
		registry.ReplaceData(&fakeOnlineSession{name: "Demo client"})
		close(reconnected)
	}()

	response := httptest.NewRecorder()
	service.ServeHTTP(response, specusRequest(http.MethodGet, "/http/Demo%20client/api/ping", ""))
	<-reconnected

	if response.Code != http.StatusOK || response.Body.String() != "ok" {
		t.Fatalf("response = %d/%q, want 200/ok", response.Code, response.Body.String())
	}
}

func TestServeHTTPUsesDataChannelAsOnlineAuthority(t *testing.T) {
	t.Run("data channel is sufficient", func(t *testing.T) {
		registry := session.NewRegistry()
		registry.ReplaceData(&fakeOnlineSession{name: "Demo client"})
		stream := newFakeStream()
		stream.head = map[string]any{"statusCode": 200}
		stream.responses = []fakeResponse{{end: true}}
		service := NewService(registry, func(string, map[string]any) (Stream, error) {
			return stream, nil
		}, nil, time.Second, 1024, 1024, nil, nil, nil, store.TrafficDetailOptions{})

		response := httptest.NewRecorder()
		service.ServeHTTP(response, specusRequest(http.MethodGet, "/http/Demo%20client/api/ping", ""))

		if response.Code != http.StatusOK {
			t.Fatalf("response = %d, want 200", response.Code)
		}
	})

	t.Run("control channel alone is offline", func(t *testing.T) {
		registry := session.NewRegistry()
		registry.Replace(&fakeOnlineSession{name: "Demo client"})
		service := NewService(registry, nil, nil, time.Second, 1024, 1024,
			nil, nil, nil, store.TrafficDetailOptions{})

		response := httptest.NewRecorder()
		service.ServeHTTP(response, specusRequest(http.MethodGet, "/http/Demo%20client/api/ping", ""))

		if response.Code != http.StatusBadGateway {
			t.Fatalf("response = %d, want 502", response.Code)
		}
	})
}

func TestServeHTTPDoesNotWaitForUnknownClient(t *testing.T) {
	service := NewService(session.NewRegistry(), nil, nil, time.Second, 1024, 1024,
		nil, nil, nil, store.TrafficDetailOptions{})
	service.SetReconnectGrace(time.Second)
	response := httptest.NewRecorder()
	startedAt := time.Now()

	service.ServeHTTP(response, specusRequest(http.MethodGet, "/http/Demo%20client/api/ping", ""))

	if response.Code != http.StatusBadGateway || time.Since(startedAt) > 500*time.Millisecond {
		t.Fatalf("response/elapsed = %d/%s, want immediate 502", response.Code, time.Since(startedAt))
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
	request := specusRequest(http.MethodPatch, "/http/Demo%20client/api/items?x=%2F", "request-body")
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

func TestServeHTTPCapturesOriginalMediaResponseAndExternalizesDetailBody(t *testing.T) {
	recorder := &capturingDetailRecorder{}
	stream := newFakeStream()
	stream.head = map[string]any{
		"statusCode": 206,
		"headers":    []string{"Content-Type:video/mp4", "Content-Range:bytes 0-5/6"},
	}
	stream.responses = []fakeResponse{{data: []byte("abc")}, {data: []byte("def")}, {end: true}}
	capture := &capturingMediaSession{externalized: true}
	service := NewService(onlineRegistry("Demo client"), func(string, map[string]any) (Stream, error) {
		return stream, nil
	}, nil, time.Second, 1024, 1024, nil, nil, recorder, store.TrafficDetailOptions{Enabled: true})
	var openedSource string
	service.SetMediaCapture(func(_ context.Context, clientName, route, method, sourceURL string,
		status int, headers []string) MediaCaptureSession {
		if clientName != "Demo client" || route != "api" || method != http.MethodGet || status != 206 || len(headers) != 2 {
			t.Fatalf("unexpected media open: %s %s %s %d %#v", clientName, route, method, status, headers)
		}
		openedSource = sourceURL
		return capture
	})
	response := httptest.NewRecorder()

	service.ServeHTTP(response, specusRequest(http.MethodGet,
		"/http/Demo%20client/api/movie.mp4?token=secret", ""))

	if response.Code != http.StatusPartialContent || response.Body.String() != "abcdef" {
		t.Fatalf("response=%d/%q", response.Code, response.Body.String())
	}
	if openedSource != "/movie.mp4?token=secret" || capture.body.String() != "abcdef" ||
		!capture.completed || capture.failed {
		t.Fatalf("capture source=%q body=%q complete=%t failed=%t",
			openedSource, capture.body.String(), capture.completed, capture.failed)
	}
	if len(recorder.record.ResponseBody) != 0 {
		t.Fatalf("externalized media leaked into HTTP detail body: %q", recorder.record.ResponseBody)
	}
}

func TestServeHTTPFiltersUndeclaredAndUnsafePeerResponseTrailers(t *testing.T) {
	stream := newFakeStream()
	stream.head = map[string]any{
		"statusCode":   200,
		"trailerNames": []string{"Digest", "Content-Length", "X-Injected", "digest"},
	}
	stream.responses = []fakeResponse{{end: true, metadata: map[string]any{"trailers": []string{
		"Digest:sha-256=valid",
		"X-Undeclared:must-not-cross",
		"Content-Length:999",
		"X-Injected:ok\r\nX-Evil: yes",
	}}}}
	service := NewService(onlineRegistry("Demo client"), func(string, map[string]any) (Stream, error) {
		return stream, nil
	}, nil, time.Second, 1024, 1024, nil, nil, nil, store.TrafficDetailOptions{})
	recorder := httptest.NewRecorder()

	service.ServeHTTP(recorder, specusRequest(http.MethodGet, "/http/Demo%20client/api/ping", ""))
	response := recorder.Result()

	if response.Trailer.Get("Digest") != "sha-256=valid" {
		t.Fatalf("Digest trailer = %q, want valid value", response.Trailer.Get("Digest"))
	}
	for _, name := range []string{"X-Undeclared", "Content-Length", "X-Injected", "X-Evil"} {
		if response.Trailer.Get(name) != "" || response.Header.Get(name) != "" {
			t.Fatalf("unsafe trailer %q escaped: header=%q trailer=%q", name,
				response.Header.Get(name), response.Trailer.Get(name))
		}
	}
}

func TestCollectDeclaredTrailersUsesOpenDeclarationIntersection(t *testing.T) {
	header := http.Header{
		"Digest":            {"sha-256=valid"},
		"X-Undeclared":      {"must-not-cross"},
		"Content-Length":    {"999"},
		"X-Injected":        {"ok\r\nX-Evil: yes"},
		"Transfer-Encoding": {"chunked"},
	}

	got := collectDeclaredTrailers(header,
		[]string{"Digest", "Content-Length", "X-Injected", "Transfer-Encoding"}, false)
	if len(got) != 1 || got[0] != "Digest:sha-256=valid" {
		t.Fatalf("trailers = %#v, want only declared safe Digest", got)
	}
}

func TestServeHTTPOmitsUnknownContentLengthFromOpen(t *testing.T) {
	registry := onlineRegistry("Demo client")
	stream := newFakeStream()
	stream.head = map[string]any{"statusCode": 200}
	stream.responses = []fakeResponse{{end: true}}
	var opened map[string]any
	service := NewService(registry, func(_ string, metadata map[string]any) (Stream, error) {
		opened = metadata
		return stream, nil
	}, nil, time.Second, 1024, 1024, nil, nil, nil, store.TrafficDetailOptions{})
	request := specusRequest("PROPFIND", "/http/Demo%20client/api/items", "payload")
	request.ContentLength = -1
	request.TransferEncoding = []string{"chunked"}
	response := httptest.NewRecorder()

	service.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("response = %d, want 200", response.Code)
	}
	if opened["method"] != "PROPFIND" {
		t.Fatalf("method = %v, want PROPFIND", opened["method"])
	}
	if _, exists := opened["contentLength"]; exists {
		t.Fatalf("unknown contentLength must be omitted: %+v", opened)
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
	request := specusRequest(http.MethodGet, "/http/Demo%20client/api/%E4%BD%A0%2Fok/%252F?x=%2F", "")
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

	service.ServeHTTP(response, specusRequest(http.MethodGet, "/http/Demo%20client/api/ping", ""))

	if response.Code != http.StatusGatewayTimeout || stream.resetReason == "" {
		t.Fatalf("timeout response/reset = %d/%q", response.Code, stream.resetReason)
	}
}

func TestServeHTTPEnforcesManagedRouteBasicAuthentication(t *testing.T) {
	policy := &store.HTTPRouteAccessPolicy{
		Enabled: true, AuthEnabled: true, AuthUsername: "route-user", AuthPasswordHash: auth.HashPassword("route-password"),
	}
	routes := &staticRouteSettings{policy: policy}
	opened := false
	service := NewService(onlineRegistry("Demo client"), func(string, map[string]any) (Stream, error) {
		opened = true
		return nil, errors.New("must not open")
	}, nil, time.Second, 1024, 1024, nil, routes, nil, store.TrafficDetailOptions{})

	for name, configure := range map[string]func(*http.Request){
		"missing": nil,
		"bearer":  func(request *http.Request) { request.Header.Set("Authorization", "Bearer token") },
		"username": func(request *http.Request) {
			request.SetBasicAuth("wrong-user", "route-password")
		},
		"password": func(request *http.Request) {
			request.SetBasicAuth("route-user", "wrong-password")
		},
	} {
		t.Run(name, func(t *testing.T) {
			opened = false
			request := specusRequest(http.MethodPost, "/http/Demo%20client/api/private", "secret-body")
			if configure != nil {
				configure(request)
			}
			response := httptest.NewRecorder()

			service.ServeHTTP(response, request)

			if response.Code != http.StatusUnauthorized || opened {
				t.Fatalf("response/opened = %d/%t, want 401/false", response.Code, opened)
			}
			if challenge := response.Header().Get("WWW-Authenticate"); !strings.HasPrefix(challenge, "Basic ") {
				t.Fatalf("WWW-Authenticate = %q", challenge)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestServeHTTPStripsProtectedRouteAuthorizationFromTunnelAndDetail(t *testing.T) {
	stream := newFakeStream()
	stream.head = map[string]any{"statusCode": 200, "headers": []string{"Content-Type:text/plain"}}
	stream.responses = []fakeResponse{{data: []byte("ok")}, {end: true}}
	recorder := &capturingDetailRecorder{}
	var opened map[string]any
	service := NewService(onlineRegistry("Demo client"), func(_ string, metadata map[string]any) (Stream, error) {
		opened = metadata
		return stream, nil
	}, nil, time.Second, 1024, 1024, nil, &staticRouteSettings{policy: &store.HTTPRouteAccessPolicy{
		Enabled: true, AuthEnabled: true, AuthUsername: "route-user", AuthPasswordHash: auth.HashPassword("route-password"),
	}}, recorder, store.TrafficDetailOptions{Enabled: true})
	request := specusRequest(http.MethodGet, "/http/Demo%20client/api/private", "")
	request.SetBasicAuth("route-user", "route-password")
	request.Header.Set("X-Request", "visible")
	response := httptest.NewRecorder()

	service.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Body.String() != "ok" {
		t.Fatalf("response = %d/%q", response.Code, response.Body.String())
	}
	assertNoAuthorizationHeader(t, metadataStrings(opened, "headers"))
	assertNoAuthorizationHeader(t, recorder.record.RequestHeaders)
	if !containsHeader(opened, "X-Request:visible") {
		t.Fatalf("ordinary request header was not forwarded: %#v", opened["headers"])
	}
}

func TestServeHTTPKeepsAuthorizationForPublicAndUnmanagedRoutes(t *testing.T) {
	for name, settings := range map[string]RouteSettings{
		"unmanaged": &staticRouteSettings{},
		"managed public": &staticRouteSettings{policy: &store.HTTPRouteAccessPolicy{
			Enabled: true, AuthEnabled: false,
		}},
	} {
		t.Run(name, func(t *testing.T) {
			stream := newFakeStream()
			stream.head = map[string]any{"statusCode": 204}
			stream.responses = []fakeResponse{{end: true}}
			var opened map[string]any
			service := NewService(onlineRegistry("Demo client"), func(_ string, metadata map[string]any) (Stream, error) {
				opened = metadata
				return stream, nil
			}, nil, time.Second, 1024, 1024, nil, settings, nil, store.TrafficDetailOptions{})
			request := specusRequest(http.MethodGet, "/http/Demo%20client/api/public", "")
			request.Header.Set("Authorization", "Bearer upstream-token")
			response := httptest.NewRecorder()

			service.ServeHTTP(response, request)

			if response.Code != http.StatusNoContent || !containsHeader(opened, "Authorization:Bearer upstream-token") {
				t.Fatalf("response/headers = %d/%#v", response.Code, opened["headers"])
			}
		})
	}
}

func TestServeHTTPFiltersAuthorizationRequestTrailersByRoutePolicy(t *testing.T) {
	tests := []struct {
		name      string
		settings  RouteSettings
		protected bool
	}{
		{name: "protected", settings: &staticRouteSettings{policy: &store.HTTPRouteAccessPolicy{
			Enabled: true, AuthEnabled: true, AuthUsername: "route-user",
			AuthPasswordHash: auth.HashPassword("route-password"),
		}}, protected: true},
		{name: "managed public", settings: &staticRouteSettings{policy: &store.HTTPRouteAccessPolicy{
			Enabled: true,
		}}},
		{name: "legacy unmanaged", settings: &staticRouteSettings{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stream := newFakeStream()
			stream.head = map[string]any{"statusCode": 204}
			stream.responses = []fakeResponse{{end: true}}
			var opened map[string]any
			service := NewService(onlineRegistry("Demo client"), func(_ string, metadata map[string]any) (Stream, error) {
				opened = metadata
				return stream, nil
			}, nil, time.Second, 1024, 1024, nil, test.settings, nil, store.TrafficDetailOptions{})
			request := specusRequest(http.MethodPost, "/http/Demo%20client/api/trailers", "body")
			if test.protected {
				request.SetBasicAuth("route-user", "route-password")
			} else {
				request.Header.Set("Authorization", "Bearer upstream-token")
			}
			request.Trailer = http.Header{
				"Authorization": {"Bearer trailer-token"},
				"X-Trailer":     {"visible"},
			}
			response := httptest.NewRecorder()

			service.ServeHTTP(response, request)

			if response.Code != http.StatusNoContent {
				t.Fatalf("response = %d, want 204", response.Code)
			}
			trailerNames := metadataStrings(opened, "trailerNames")
			trailers := metadataStrings(stream.finishedMetadata(), "trailers")
			if !containsFold(trailerNames, "X-Trailer") || !containsHeaderValue(trailers, "X-Trailer:visible") {
				t.Fatalf("ordinary trailer missing: names=%#v values=%#v", trailerNames, trailers)
			}
			if test.protected {
				assertNoAuthorizationHeader(t, trailers)
				if containsFold(trailerNames, "Authorization") {
					t.Fatalf("protected trailer names leaked Authorization: %#v", trailerNames)
				}
			} else if !containsFold(trailerNames, "Authorization") ||
				!containsHeaderValue(trailers, "Authorization:Bearer trailer-token") {
				t.Fatalf("public/legacy Authorization trailer was not preserved: names=%#v values=%#v",
					trailerNames, trailers)
			}
		})
	}
}

func TestServeHTTPFailsClosedWhenRoutePolicyCannotBeLoaded(t *testing.T) {
	opened := false
	service := NewService(onlineRegistry("Demo client"), func(string, map[string]any) (Stream, error) {
		opened = true
		return nil, nil
	}, nil, time.Second, 1024, 1024, nil, &staticRouteSettings{err: errors.New("database unavailable")},
		nil, store.TrafficDetailOptions{})
	response := httptest.NewRecorder()

	service.ServeHTTP(response, specusRequest(http.MethodGet, "/http/Demo%20client/api/private", ""))

	if response.Code != http.StatusServiceUnavailable || opened {
		t.Fatalf("response/opened = %d/%t, want 503/false", response.Code, opened)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
}

func TestServeHTTPRejectsDisabledAndIncompleteManagedPolicies(t *testing.T) {
	tests := []struct {
		name       string
		policy     *store.HTTPRouteAccessPolicy
		username   string
		password   string
		wantStatus int
	}{
		{name: "disabled", policy: &store.HTTPRouteAccessPolicy{Enabled: false},
			username: "route-user", password: "password", wantStatus: http.StatusNotFound},
		{name: "missing username", policy: &store.HTTPRouteAccessPolicy{
			Enabled: true, AuthEnabled: true, AuthPasswordHash: auth.HashPassword("password"),
		}, username: "", password: "password", wantStatus: http.StatusServiceUnavailable},
		{name: "whitespace username", policy: &store.HTTPRouteAccessPolicy{
			Enabled: true, AuthEnabled: true, AuthUsername: "   ", AuthPasswordHash: auth.HashPassword("password"),
		}, username: "   ", password: "password", wantStatus: http.StatusServiceUnavailable},
		{name: "missing password hash", policy: &store.HTTPRouteAccessPolicy{
			Enabled: true, AuthEnabled: true, AuthUsername: "route-user",
		}, username: "route-user", password: "password", wantStatus: http.StatusServiceUnavailable},
		{name: "wrong password hash length", policy: &store.HTTPRouteAccessPolicy{
			Enabled: true, AuthEnabled: true, AuthUsername: "route-user", AuthPasswordHash: strings.Repeat("a", 63),
		}, username: "route-user", password: "password", wantStatus: http.StatusServiceUnavailable},
		{name: "non-hex password hash", policy: &store.HTTPRouteAccessPolicy{
			Enabled: true, AuthEnabled: true, AuthUsername: "route-user", AuthPasswordHash: strings.Repeat("z", 64),
		}, username: "route-user", password: "password", wantStatus: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opened := false
			service := NewService(onlineRegistry("Demo client"), func(string, map[string]any) (Stream, error) {
				opened = true
				return nil, nil
			}, nil, time.Second, 1024, 1024, nil, &staticRouteSettings{policy: test.policy},
				nil, store.TrafficDetailOptions{})
			request := specusRequest(http.MethodGet, "/http/Demo%20client/api/private", "")
			request.SetBasicAuth(test.username, test.password)
			response := httptest.NewRecorder()

			service.ServeHTTP(response, request)

			if response.Code != test.wantStatus || opened {
				t.Fatalf("response/opened = %d/%t, want %d/false", response.Code, opened, test.wantStatus)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
			}
			if test.wantStatus == http.StatusServiceUnavailable && response.Header().Get("WWW-Authenticate") != "" {
				t.Fatalf("invalid server auth configuration must not challenge the caller: %q",
					response.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func specusRequest(method, target, body string) *http.Request {
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
	registry.ReplaceData(&fakeOnlineSession{name: name})
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
	mu             sync.Mutex
	request        bytes.Buffer
	finished       chan struct{}
	finishOnce     sync.Once
	head           map[string]any
	responses      []fakeResponse
	responseIndex  int
	consumed       int
	resetReason    string
	blockHead      bool
	finishMetadata map[string]any
}

func newFakeStream() *fakeStream { return &fakeStream{finished: make(chan struct{})} }
func (s *fakeStream) SendData(_ context.Context, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.request.Write(data)
	return nil
}
func (s *fakeStream) FinishRequest(metadata map[string]any) error {
	s.mu.Lock()
	s.finishMetadata = metadata
	s.mu.Unlock()
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
func (s *fakeStream) finishedMetadata() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.finishMetadata
}

type capturingMediaSession struct {
	body         bytes.Buffer
	externalized bool
	completed    bool
	failed       bool
}

func (s *capturingMediaSession) Append(data []byte) { _, _ = s.body.Write(data) }
func (s *capturingMediaSession) Complete()          { s.completed = true }
func (s *capturingMediaSession) Fail(string)        { s.failed = true }
func (s *capturingMediaSession) Active() bool       { return !s.completed && !s.failed }
func (s *capturingMediaSession) Externalized() bool { return s.externalized }

type capturingDetailRecorder struct{ record store.HTTPExchangeRecord }

func (r *capturingDetailRecorder) RecordHTTPExchange(_ context.Context, record store.HTTPExchangeRecord) error {
	r.record = record
	return nil
}

type capturingTrafficRecorder struct{ upload, download int64 }

func (r *capturingTrafficRecorder) RecordHTTPUpload(_, _ string, bytes int64)   { r.upload += bytes }
func (r *capturingTrafficRecorder) RecordHTTPDownload(_, _ string, bytes int64) { r.download += bytes }

type staticRouteSettings struct {
	policy *store.HTTPRouteAccessPolicy
	err    error
}

type countingRouteSettings struct {
	policy *store.HTTPRouteAccessPolicy
	calls  atomic.Int32
}

func (s *countingRouteSettings) HTTPRouteAccessPolicy(context.Context, string, string) (*store.HTTPRouteAccessPolicy, error) {
	s.calls.Add(1)
	return s.policy, nil
}

func TestRoutePolicyCacheUsesConfiguredTTL(t *testing.T) {
	routes := &countingRouteSettings{policy: &store.HTTPRouteAccessPolicy{Enabled: true, PathRewriteEnabled: true}}
	service := NewService(nil, nil, nil, time.Second, 1024, 1024, nil, routes, nil, store.TrafficDetailOptions{})
	service.SetRouteCacheTTL(25 * time.Millisecond)
	if _, err := service.routePolicy(context.Background(), "client", "route"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.routePolicy(context.Background(), "client", "route"); err != nil {
		t.Fatal(err)
	}
	if got := routes.calls.Load(); got != 1 {
		t.Fatalf("route lookup calls = %d, want 1 inside TTL", got)
	}
	time.Sleep(35 * time.Millisecond)
	if _, err := service.routePolicy(context.Background(), "client", "route"); err != nil {
		t.Fatal(err)
	}
	if got := routes.calls.Load(); got != 2 {
		t.Fatalf("route lookup calls = %d, want refresh after TTL", got)
	}
}

func (s *staticRouteSettings) HTTPRouteAccessPolicy(context.Context, string, string) (*store.HTTPRouteAccessPolicy, error) {
	return s.policy, s.err
}

func assertNoAuthorizationHeader(t *testing.T, headers []string) {
	t.Helper()
	for _, header := range headers {
		if strings.HasPrefix(strings.ToLower(header), "authorization:") {
			t.Fatalf("Authorization must not leave the route auth gate: %q", header)
		}
	}
}

func containsHeader(metadata map[string]any, expected string) bool {
	for _, header := range metadataStrings(metadata, "headers") {
		if header == expected {
			return true
		}
	}
	return false
}

func containsFold(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(value, expected) {
			return true
		}
	}
	return false
}

func containsHeaderValue(headers []string, expected string) bool {
	for _, header := range headers {
		if strings.EqualFold(header, expected) {
			return true
		}
	}
	return false
}
