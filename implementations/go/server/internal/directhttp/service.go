// Package directhttp forwards inbound HTTP requests to an online client over the control
// channel (DIRECT_HTTP_REQUEST) and relays the client's DIRECT_HTTP_RESPONSE back. Mirrors the
// C# DirectHttpDispatcher / DirectHttpEndpoints.
package directhttp

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/protocol"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/session"
)

var skippedHeaders = map[string]struct{}{
	"connection": {}, "content-length": {}, "host": {}, "keep-alive": {},
	"proxy-authenticate": {}, "proxy-authorization": {}, "te": {}, "trailer": {},
	"transfer-encoding": {}, "upgrade": {},
}

// TrafficRecorder lets the forwarder account request/response bytes (optional).
type TrafficRecorder interface {
	RecordUpload(clientName string, bytes int64)
	RecordDownload(clientName string, bytes int64)
}

// Service forwards HTTP requests and matches responses by request id.
type Service struct {
	sessions    *session.Registry
	timeout     time.Duration
	maxBodySize int
	traffic     TrafficRecorder

	mu      sync.Mutex
	pending map[string]chan protocol.DirectHTTPResponse
}

// NewService builds the Direct HTTP forwarder.
func NewService(sessions *session.Registry, timeout time.Duration, maxBodySize int, traffic TrafficRecorder) *Service {
	return &Service{
		sessions:    sessions,
		timeout:     timeout,
		maxBodySize: maxBodySize,
		traffic:     traffic,
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
	clientName := r.PathValue("clientName")
	route := r.PathValue("route")
	rest := r.PathValue("rest")

	body, err := io.ReadAll(io.LimitReader(r.Body, int64(s.maxBodySize)+1))
	if err != nil {
		writeTextError(w, http.StatusBadGateway, "读取请求体失败")
		return
	}
	if len(body) > s.maxBodySize {
		writeTextError(w, http.StatusRequestEntityTooLarge, "HTTP 请求体超过限制")
		return
	}

	relativePath := "/"
	if rest != "" {
		relativePath = "/" + rest
	}
	request := protocol.DirectHTTPRequest{
		RequestID:     newRequestID(),
		RequestMethod: r.Method,
		Route:         route,
		RelativePath:  relativePath,
		RawQuery:      r.URL.RawQuery,
		Headers:       collectHeaders(r.Header),
		Body:          body,
	}

	response, err := s.forward(clientName, request)
	if err != nil {
		writeTextError(w, statusForError(err), err.Error())
		return
	}
	if s.traffic != nil {
		s.traffic.RecordUpload(clientName, int64(len(body)))
		s.traffic.RecordDownload(clientName, int64(len(response.Body)))
	}
	if response.Error != nil && *response.Error != "" {
		status := response.StatusCode
		if status <= 0 {
			status = http.StatusBadGateway
		}
		writeTextError(w, status, *response.Error)
		return
	}
	applyResponseHeaders(w, response.Headers)
	status := response.StatusCode
	if status <= 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(response.Body)
}

func (s *Service) forward(clientName string, request protocol.DirectHTTPRequest) (protocol.DirectHTTPResponse, error) {
	bound, ok := s.sessions.Find(clientName)
	if !ok {
		return protocol.DirectHTTPResponse{}, errOffline
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
		return protocol.DirectHTTPResponse{}, errForward
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
