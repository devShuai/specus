// Package directhttp forwards inbound HTTP requests to an online client over the control
// channel (DIRECT_HTTP_REQUEST) and relays the client's DIRECT_HTTP_RESPONSE back. Mirrors the
// C# DirectHttpDispatcher / DirectHttpEndpoints.
package directhttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/protocol"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/session"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/store"
)

var skippedHeaders = map[string]struct{}{
	"connection": {}, "content-length": {}, "host": {}, "keep-alive": {},
	"proxy-authenticate": {}, "proxy-authorization": {}, "te": {}, "trailer": {},
	"transfer-encoding": {}, "upgrade": {},
}

// TrafficRecorder lets the forwarder account request/response bytes (optional).
type TrafficRecorder interface {
	RecordHTTPUpload(clientName, route string, bytes int64)
	RecordHTTPDownload(clientName, route string, bytes int64)
}

// RouteSettings looks up server-side options for an HTTP route.
type RouteSettings interface {
	HTTPRoutePathRewriteEnabled(ctx context.Context, clientName, route string) (bool, error)
}

// DetailRecorder optionally persists full HTTP exchange details.
type DetailRecorder interface {
	RecordHTTPExchange(ctx context.Context, record store.HTTPExchangeRecord) error
}

// Service forwards HTTP requests and matches responses by request id.
type Service struct {
	sessions    *session.Registry
	timeout     time.Duration
	maxBodySize int
	traffic     TrafficRecorder
	routes      RouteSettings
	detail      DetailRecorder
	detailOpts  store.TrafficDetailOptions
	rewriter    responseRewriter

	mu      sync.Mutex
	pending map[string]chan protocol.DirectHTTPResponse
}

// NewService builds the Direct HTTP forwarder.
func NewService(sessions *session.Registry, timeout time.Duration, maxBodySize int, rewriteMaxBodyBytes int,
	traffic TrafficRecorder, routes RouteSettings, detail DetailRecorder, detailOpts store.TrafficDetailOptions) *Service {
	return &Service{
		sessions:    sessions,
		timeout:     timeout,
		maxBodySize: maxBodySize,
		traffic:     traffic,
		routes:      routes,
		detail:      detail,
		detailOpts:  detailOpts,
		rewriter:    newResponseRewriter(rewriteMaxBodyBytes),
		pending:     make(map[string]chan protocol.DirectHTTPResponse),
	}
}

// Ack completes a pending request when its response arrives on the control channel.
func (s *Service) Ack(response protocol.DirectHTTPResponse) {
	s.mu.Lock()
	ch, ok := s.pending[response.RequestID]
	if ok {
		delete(s.pending, response.RequestID)
	}
	s.mu.Unlock()
	if ok {
		ch <- response
	}
}

// ServeHTTP handles /http/{clientName}/{route}[/{rest...}] for all methods.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startedAt := time.Now()
	clientName := r.PathValue("clientName")
	route := r.PathValue("route")

	body, err := io.ReadAll(io.LimitReader(r.Body, int64(s.maxBodySize)+1))
	if err != nil {
		writeTextError(w, http.StatusBadGateway, "读取请求体失败")
		return
	}
	relativePath := relativePath(r)
	request := protocol.DirectHTTPRequest{
		RequestID:     newRequestID(),
		RequestMethod: r.Method,
		Route:         route,
		RelativePath:  relativePath,
		RawQuery:      r.URL.RawQuery,
		Headers:       collectHeaders(r.Header),
		Body:          body,
	}
	if len(body) > s.maxBodySize {
		errorText := "HTTP 请求体超过限制"
		s.recordHTTPDetail(r.Context(), clientName, route, request, protocol.DirectHTTPResponse{
			StatusCode: http.StatusRequestEntityTooLarge,
			Headers:    plainErrorHeaders(),
			Body:       []byte(errorText),
			Error:      stringPtr(errorText),
		}, startedAt, r.RemoteAddr)
		writeTextError(w, http.StatusRequestEntityTooLarge, errorText)
		return
	}

	response, err := s.forward(clientName, request)
	if err != nil {
		status := statusForError(err)
		errorText := err.Error()
		s.recordHTTPDetail(r.Context(), clientName, route, request, protocol.DirectHTTPResponse{
			StatusCode: status,
			Headers:    plainErrorHeaders(),
			Body:       []byte(errorText),
			Error:      stringPtr(errorText),
		}, startedAt, r.RemoteAddr)
		writeTextError(w, status, errorText)
		return
	}
	if s.traffic != nil {
		s.traffic.RecordHTTPUpload(clientName, route, int64(len(body)))
		s.traffic.RecordHTTPDownload(clientName, route, int64(len(response.Body)))
	}
	if response.Error != nil && *response.Error != "" {
		status := response.StatusCode
		if status <= 0 {
			status = http.StatusBadGateway
		}
		errorText := *response.Error
		s.recordHTTPDetail(r.Context(), clientName, route, request, protocol.DirectHTTPResponse{
			StatusCode: status,
			Headers:    plainErrorHeaders(),
			Body:       []byte(errorText),
			Error:      stringPtr(errorText),
		}, startedAt, r.RemoteAddr)
		writeTextError(w, status, errorText)
		return
	}
	responseHeaders := response.Headers
	if s.pathRewriteEnabled(r.Context(), clientName, route) {
		if rewritten, ok := s.rewriter.rewrite(response.Body, clientName, route, responseHeaders); ok {
			response.Body = rewritten
			responseHeaders = stripRewriteHeaders(responseHeaders)
		}
	}
	applyResponseHeaders(w, responseHeaders)
	status := response.StatusCode
	if status <= 0 {
		status = http.StatusOK
	}
	s.recordHTTPDetail(r.Context(), clientName, route, request, response, startedAt, r.RemoteAddr)
	w.WriteHeader(status)
	_, _ = w.Write(response.Body)
}

func (s *Service) recordHTTPDetail(ctx context.Context, clientName, route string, request protocol.DirectHTTPRequest,
	response protocol.DirectHTTPResponse, startedAt time.Time, remoteAddress string) {
	if s.detail == nil {
		return
	}
	errText := ""
	if response.Error != nil {
		errText = *response.Error
	}
	statusCode := response.StatusCode
	if statusCode <= 0 {
		if errText != "" {
			statusCode = http.StatusBadGateway
		} else {
			statusCode = http.StatusOK
		}
	}
	_ = s.detail.RecordHTTPExchange(ctx, store.HTTPExchangeRecord{
		ClientName:      clientName,
		Route:           route,
		Method:          request.RequestMethod,
		RelativePath:    request.RelativePath,
		RawQuery:        request.RawQuery,
		RequestHeaders:  request.Headers,
		RequestBody:     request.Body,
		StatusCode:      statusCode,
		ResponseHeaders: response.Headers,
		ResponseBody:    response.Body,
		StartedAt:       startedAt,
		RemoteAddress:   remoteAddress,
		Error:           errText,
		Options:         s.detailOpts,
	})
}

func (s *Service) pathRewriteEnabled(ctx context.Context, clientName, route string) bool {
	if s.routes == nil {
		return false
	}
	enabled, err := s.routes.HTTPRoutePathRewriteEnabled(ctx, clientName, route)
	return err == nil && enabled
}

func (s *Service) forward(clientName string, request protocol.DirectHTTPRequest) (protocol.DirectHTTPResponse, error) {
	bound, ok := s.sessions.Find(clientName)
	if !ok {
		return protocol.DirectHTTPResponse{}, fmt.Errorf("%w: %s", errOffline, clientName)
	}

	ch := make(chan protocol.DirectHTTPResponse, 1)
	s.mu.Lock()
	s.pending[request.RequestID] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, request.RequestID)
		s.mu.Unlock()
	}()

	if err := bound.Send(request); err != nil {
		errorText := "HTTP 转发请求发送失败"
		return protocol.DirectHTTPResponse{
			RequestID:  request.RequestID,
			StatusCode: http.StatusBadGateway,
			Headers:    nil,
			Body:       nil,
			Error:      stringPtr(errorText),
		}, nil
	}
	select {
	case response := <-ch:
		return response, nil
	case <-time.After(s.timeout):
		return protocol.DirectHTTPResponse{}, errTimeout
	}
}

func collectHeaders(header http.Header) []string {
	var headers []string
	for name, values := range header {
		if _, skip := skippedHeaders[strings.ToLower(name)]; skip {
			continue
		}
		for _, value := range values {
			headers = append(headers, name+":"+value)
		}
	}
	return headers
}

func relativePath(r *http.Request) string {
	path := r.URL.EscapedPath()
	const prefix = "/http/"
	if !strings.HasPrefix(path, prefix) {
		rest := r.PathValue("rest")
		if rest == "" {
			return "/"
		}
		return "/" + rest
	}
	clientSeparator := strings.IndexByte(path[len(prefix):], '/')
	if clientSeparator < 0 {
		return "/"
	}
	afterClient := len(prefix) + clientSeparator + 1
	routeSeparator := strings.IndexByte(path[afterClient:], '/')
	if routeSeparator < 0 {
		return "/"
	}
	return path[afterClient+routeSeparator:]
}

func applyResponseHeaders(w http.ResponseWriter, headers []string) {
	for _, header := range headers {
		idx := strings.IndexByte(header, ':')
		if idx <= 0 {
			continue
		}
		name := strings.TrimSpace(header[:idx])
		if _, skip := skippedHeaders[strings.ToLower(name)]; skip {
			continue
		}
		w.Header().Add(name, strings.TrimSpace(header[idx+1:]))
	}
}

func stripRewriteHeaders(headers []string) []string {
	result := make([]string, 0, len(headers))
	for _, header := range headers {
		idx := strings.IndexByte(header, ':')
		if idx <= 0 {
			result = append(result, header)
			continue
		}
		name := strings.TrimSpace(header[:idx])
		if strings.EqualFold(name, "content-encoding") || strings.EqualFold(name, "content-length") {
			continue
		}
		result = append(result, header)
	}
	return result
}

func plainErrorHeaders() []string {
	return []string{"Content-Type:text/plain;charset=UTF-8"}
}

func writeTextError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/plain;charset=UTF-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, message)
}

func newRequestID() string {
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func stringPtr(value string) *string { return &value }
