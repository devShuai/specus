package directhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/session"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/store"
)

const (
	httpChunkBytes       = 64 * 1024
	maxHTTPResponseBytes = 64 * 1024 * 1024
	detailCaptureBytes   = 64 * 1024
)

var errRequestTooLarge = errors.New("HTTP 请求体超过限制")

var skippedHeaders = map[string]struct{}{
	"connection": {}, "content-length": {}, "host": {}, "keep-alive": {},
	"proxy-authenticate": {}, "proxy-authorization": {}, "te": {},
	"trailer": {}, "transfer-encoding": {}, "upgrade": {},
}

// wsSkippedHeaders 在 WS 升级请求上额外跳过握手头（对齐 Java WebSocketTunnelHandshakeInterceptor）。
var wsSkippedHeaders = map[string]struct{}{
	"connection": {}, "content-length": {}, "host": {}, "keep-alive": {},
	"proxy-authenticate": {}, "proxy-authorization": {}, "te": {},
	"trailer": {}, "transfer-encoding": {}, "upgrade": {},
	"sec-websocket-key": {}, "sec-websocket-version": {}, "sec-websocket-extensions": {},
	"sec-websocket-protocol": {}, "sec-websocket-accept": {},
}

// Stream is the HTTP-facing contract of one NAT stream v2 exchange.
type Stream interface {
	SendData(context.Context, []byte) error
	FinishRequest(map[string]any) error
	WaitResponseHead(context.Context) (map[string]any, error)
	ReadResponse(context.Context) ([]byte, map[string]any, bool, error)
	Consume(int) error
	Reset(uint32, string)
	Close()
}

// OpenStreamFunc allocates a stream in an authenticated client's NAT namespace.
type OpenStreamFunc func(clientName string, metadata map[string]any) (Stream, error)

// OpenWSStreamFunc allocates a WebSocket tunnel stream in an authenticated client's NAT namespace.
type OpenWSStreamFunc func(clientName string, metadata map[string]any, conn *websocket.Conn) (*WebSocketTunnel, error)

type TrafficRecorder interface {
	RecordHTTPUpload(clientName, route string, bytes int64)
	RecordHTTPDownload(clientName, route string, bytes int64)
}

type RouteSettings interface {
	HTTPRoutePathRewriteEnabled(ctx context.Context, clientName, route string) (bool, error)
}

type DetailRecorder interface {
	RecordHTTPExchange(ctx context.Context, record store.HTTPExchangeRecord) error
}

// Service streams public HTTP requests through mandatory NAT stream v2 frames.
type Service struct {
	sessions       *session.Registry
	openStream     OpenStreamFunc
	openWS         OpenWSStreamFunc
	timeout        time.Duration
	maxBodySize    int
	traffic        TrafficRecorder
	routes         RouteSettings
	detail         DetailRecorder
	detailOpts     store.TrafficDetailOptions
	rewriter       responseRewriter
	reconnectGrace time.Duration
}

func NewService(sessions *session.Registry, openStream OpenStreamFunc, openWS OpenWSStreamFunc,
	timeout time.Duration, maxBodySize int, rewriteMaxBodyBytes int, traffic TrafficRecorder,
	routes RouteSettings, detail DetailRecorder, detailOpts store.TrafficDetailOptions) *Service {
	return &Service{
		sessions: sessions, openStream: openStream, openWS: openWS, timeout: timeout, maxBodySize: maxBodySize,
		traffic: traffic, routes: routes, detail: detail, detailOpts: detailOpts,
		rewriter: newResponseRewriter(rewriteMaxBodyBytes),
	}
}

// SetReconnectGrace allows a briefly reconnecting client to restore its mandatory v2
// data connection before an HTTP/WS request is reported as offline.
func (s *Service) SetReconnectGrace(grace time.Duration) {
	if grace < 0 {
		grace = 0
	}
	s.reconnectGrace = grace
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 带 Upgrade: websocket 的 /http/** 请求走 WS 隧道（对齐 Java WebSocketTunnelConfig 的路由分流）。
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		s.serveWebSocket(w, r)
		return
	}
	startedAt := time.Now()
	clientName := r.PathValue("clientName")
	route := r.PathValue("route")
	path := relativePath(r)
	requestHeaders := collectHeaders(r.Header, skippedHeaders)
	requestCapture := &limitedCapture{limit: detailCaptureBytes}

	fail := func(status int, message string) {
		writeTextError(w, status, message)
		s.recordHTTPDetail(r.Context(), clientName, route, r.Method, path, r.URL.RawQuery,
			requestHeaders, requestCapture.Bytes(), status, plainErrorHeaders(), []byte(message), message,
			startedAt, r.RemoteAddr)
	}
	if r.ContentLength > int64(s.maxBodySize) && s.maxBodySize >= 0 {
		captureSize := min(detailCaptureBytes, s.maxBodySize+1)
		if captureSize > 0 {
			buffer := make([]byte, captureSize)
			read, _ := io.ReadFull(r.Body, buffer)
			requestCapture.Write(buffer[:read])
		}
		_ = r.Body.Close()
		fail(http.StatusRequestEntityTooLarge, errRequestTooLarge.Error())
		return
	}

	if !s.clientOnline(r.Context(), clientName) {
		fail(statusForError(errOffline), errOffline.Error()+": "+clientName)
		return
	}
	if s.openStream == nil {
		fail(http.StatusBadGateway, "HTTP 流服务不可用")
		return
	}

	metadata := map[string]any{
		"source": "http", "phase": "request", "method": r.Method, "route": route,
		"relativePath": path, "rawQuery": r.URL.RawQuery, "headers": requestHeaders,
		"contentLength": r.ContentLength, "trailerNames": headerNames(r.Trailer),
	}
	stream, err := s.openStream(clientName, metadata)
	if err != nil {
		fail(http.StatusBadGateway, "HTTP 转发请求发送失败")
		return
	}
	defer stream.Close()

	pumpResult := make(chan error, 1)
	go func() {
		pumpResult <- s.pumpRequest(r.Context(), r.Body, r.Trailer, stream, clientName, route, requestCapture)
	}()

	headerCtx := r.Context()
	var cancel context.CancelFunc
	if s.timeout > 0 {
		headerCtx, cancel = context.WithTimeout(headerCtx, s.timeout)
		defer cancel()
	}
	head, err := stream.WaitResponseHead(headerCtx)
	if err != nil {
		stream.Reset(1, "HTTP downstream closed before response headers")
		_ = r.Body.Close()
		requestErr := receivePumpResult(pumpResult)
		if errors.Is(requestErr, errRequestTooLarge) {
			fail(http.StatusRequestEntityTooLarge, errRequestTooLarge.Error())
			return
		}
		if errors.Is(err, context.DeadlineExceeded) {
			fail(http.StatusGatewayTimeout, errTimeout.Error())
			return
		}
		fail(http.StatusBadGateway, errorText(err))
		return
	}

	status, ok := metadataInt(head, "statusCode")
	if !ok || status < 100 || status > 599 {
		stream.Reset(2, "invalid HTTP response status")
		fail(http.StatusBadGateway, "HTTP 响应状态无效")
		return
	}
	responseHeaders := metadataStrings(head, "headers")
	declareTrailers(w, metadataStrings(head, "trailerNames"))

	rewrite := s.pathRewriteEnabled(r.Context(), clientName, route) &&
		isRewritableContentType(responseHeaders)
	responseCapture := &limitedCapture{limit: detailCaptureBytes}
	var rewriteBuffer bytes.Buffer
	responseStarted := false
	totalResponse := 0
	trailers := []string(nil)

	startResponse := func(headers []string) {
		if responseStarted {
			return
		}
		applyResponseHeaders(w, headers)
		w.WriteHeader(status)
		responseStarted = true
	}
	writeChunk := func(data []byte) error {
		if len(data) == 0 {
			return nil
		}
		written, writeErr := w.Write(data)
		if written > 0 {
			responseCapture.Write(data[:written])
			if s.traffic != nil {
				s.traffic.RecordHTTPDownload(clientName, route, int64(written))
			}
			if consumeErr := stream.Consume(written); consumeErr != nil && writeErr == nil {
				writeErr = consumeErr
			}
		}
		if writeErr == nil && written != len(data) {
			writeErr = io.ErrShortWrite
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		return writeErr
	}

	for {
		data, endMetadata, end, readErr := stream.ReadResponse(r.Context())
		if readErr != nil {
			stream.Reset(3, "HTTP response stream failed")
			if !responseStarted {
				fail(http.StatusBadGateway, errorText(readErr))
			}
			return
		}
		if end {
			trailers = metadataStrings(endMetadata, "trailers")
			break
		}
		totalResponse += len(data)
		if totalResponse > maxHTTPResponseBytes {
			stream.Reset(4, "HTTP response body exceeds limit")
			if !responseStarted {
				fail(http.StatusBadGateway, "HTTP 响应体超过限制")
			}
			return
		}

		if rewrite {
			if rewriteBuffer.Len()+len(data) <= s.rewriter.maxBodyBytes {
				_, _ = rewriteBuffer.Write(data)
				if err := stream.Consume(len(data)); err != nil {
					stream.Reset(5, err.Error())
					return
				}
				continue
			}
			startResponse(responseHeaders)
			if err := writeBufferedWithoutCredit(w, &rewriteBuffer, responseCapture, s.traffic, clientName, route); err != nil {
				stream.Reset(6, "HTTP downstream write failed")
				return
			}
			rewrite = false
		}
		startResponse(responseHeaders)
		if err := writeChunk(data); err != nil {
			stream.Reset(6, "HTTP downstream write failed")
			return
		}
	}

	if rewrite {
		body := rewriteBuffer.Bytes()
		if rewritten, changed := s.rewriter.rewrite(body, clientName, route, responseHeaders); changed {
			body = rewritten
			responseHeaders = stripRewriteHeaders(responseHeaders)
		}
		startResponse(responseHeaders)
		if err := writeBufferedWithoutCredit(w, bytes.NewBuffer(body), responseCapture,
			s.traffic, clientName, route); err != nil {
			stream.Reset(6, "HTTP downstream write failed")
			return
		}
	} else if !responseStarted {
		startResponse(responseHeaders)
	}
	applyTrailers(w, trailers)
	_ = r.Body.Close()

	s.recordHTTPDetail(r.Context(), clientName, route, r.Method, path, r.URL.RawQuery,
		requestHeaders, requestCapture.Bytes(), status, responseHeaders, responseCapture.Bytes(), "",
		startedAt, r.RemoteAddr)
}

// serveWebSocket 处理 /http/{clientName}/{route}/** 的 WS 升级请求（对齐 Java WebSocketTunnelHandler）：
// 握手成功后发送带 source=ws metadata 的 OPEN 帧，随后进入浏览器消息的读循环。
func (s *Service) serveWebSocket(w http.ResponseWriter, r *http.Request) {
	clientName := r.PathValue("clientName")
	route := r.PathValue("route")
	// InsecureSkipVerify 跳过 Origin 校验，对齐 Java setAllowedOriginPatterns("*")。
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	fail := func(reason string) {
		_ = conn.Close(websocket.StatusInternalError, reason)
	}
	if !s.clientOnline(r.Context(), clientName) {
		fail(errOffline.Error() + ": " + clientName)
		return
	}
	if s.openWS == nil {
		fail("WS 隧道服务不可用")
		return
	}

	metadata := map[string]any{
		"source": "ws", "channelId": newWSChannelID(), "clientName": clientName,
		"route": route, "relativePath": relativePath(r), "rawQuery": r.URL.RawQuery,
		"headers": collectHeaders(r.Header, wsSkippedHeaders), "body": []byte{},
	}
	tunnel, err := s.openWS(clientName, metadata, conn)
	if err != nil {
		fail("WS 隧道请求发送失败")
		return
	}
	tunnel.ReadLoop(r.Context())
}

func (s *Service) clientOnline(ctx context.Context, clientName string) bool {
	if s.sessions == nil {
		return false
	}
	if s.reconnectGrace <= 0 {
		_, online := s.sessions.FindData(clientName)
		return online
	}
	waitCtx, cancel := context.WithTimeout(ctx, s.reconnectGrace)
	defer cancel()
	return s.sessions.WaitForDataReconnect(waitCtx, clientName, s.reconnectGrace)
}

func (s *Service) pumpRequest(ctx context.Context, body io.ReadCloser, trailers http.Header, stream Stream,
	clientName, route string, capture *limitedCapture) error {
	defer body.Close()
	buffer := make([]byte, httpChunkBytes)
	total := 0
	for {
		read, err := body.Read(buffer)
		if read > 0 {
			capture.Write(buffer[:read])
			total += read
			if total > s.maxBodySize {
				stream.Reset(7, errRequestTooLarge.Error())
				return errRequestTooLarge
			}
			payload := append([]byte(nil), buffer[:read]...)
			if sendErr := stream.SendData(ctx, payload); sendErr != nil {
				return sendErr
			}
			if s.traffic != nil {
				s.traffic.RecordHTTPUpload(clientName, route, int64(read))
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				metadata := map[string]any(nil)
				if values := collectHeaders(trailers, skippedHeaders); len(values) > 0 {
					metadata = map[string]any{"trailers": values}
				}
				return stream.FinishRequest(metadata)
			}
			stream.Reset(8, "HTTP request body read failed")
			return err
		}
	}
}

func (s *Service) recordHTTPDetail(ctx context.Context, clientName, route, method, relativePath,
	rawQuery string, requestHeaders []string, requestBody []byte, status int, responseHeaders []string,
	responseBody []byte, errText string, startedAt time.Time, remoteAddress string) {
	if s.detail == nil {
		return
	}
	_ = s.detail.RecordHTTPExchange(ctx, store.HTTPExchangeRecord{
		ClientName: clientName, Route: route, Method: method, RelativePath: relativePath,
		RawQuery: rawQuery, RequestHeaders: requestHeaders, RequestBody: requestBody,
		StatusCode: status, ResponseHeaders: responseHeaders, ResponseBody: responseBody,
		StartedAt: startedAt, RemoteAddress: remoteAddress, Error: errText, Options: s.detailOpts,
	})
}

func (s *Service) pathRewriteEnabled(ctx context.Context, clientName, route string) bool {
	if s.routes == nil {
		return false
	}
	enabled, err := s.routes.HTTPRoutePathRewriteEnabled(ctx, clientName, route)
	return err == nil && enabled
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

func collectHeaders(header http.Header, skipped map[string]struct{}) []string {
	var headers []string
	for name, values := range header {
		if _, skip := skipped[strings.ToLower(name)]; skip {
			continue
		}
		for _, value := range values {
			headers = append(headers, name+":"+value)
		}
	}
	return headers
}

func headerNames(header http.Header) []string {
	names := make([]string, 0, len(header))
	for name := range header {
		if httpgutsValidHeaderName(name) {
			names = append(names, name)
		}
	}
	return names
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
		if idx > 0 {
			name := strings.TrimSpace(header[:idx])
			if strings.EqualFold(name, "content-encoding") || strings.EqualFold(name, "content-length") {
				continue
			}
		}
		result = append(result, header)
	}
	return result
}

func isRewritableContentType(headers []string) bool {
	_, ok := rewritableContentTypes[contentType(headers)]
	return ok
}

func plainErrorHeaders() []string { return []string{"Content-Type:text/plain;charset=UTF-8"} }

// newWSChannelID 生成 WS 流的 channelId（对齐 Java WebSocketTunnelHandler 的 UUID 随机标识）。
func newWSChannelID() string {
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	return hex.EncodeToString(raw[:])
}

func writeTextError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/plain;charset=UTF-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, message)
}

func metadataInt(metadata map[string]any, key string) (int, bool) {
	value, ok := metadata[key]
	if !ok {
		return 0, false
	}
	switch number := value.(type) {
	case float64:
		return int(number), true
	case int:
		return number, true
	case int64:
		return int(number), true
	default:
		var result int
		_, err := fmt.Sscan(fmt.Sprint(value), &result)
		return result, err == nil
	}
}

func metadataStrings(metadata map[string]any, key string) []string {
	value, ok := metadata[key]
	if !ok || value == nil {
		return nil
	}
	items, ok := value.([]any)
	if !ok {
		if stringsValue, ok := value.([]string); ok {
			return append([]string(nil), stringsValue...)
		}
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if item != nil {
			result = append(result, fmt.Sprint(item))
		}
	}
	return result
}

func declareTrailers(w http.ResponseWriter, names []string) {
	for _, name := range names {
		if httpgutsValidHeaderName(name) {
			w.Header().Add("Trailer", name)
		}
	}
}

func applyTrailers(w http.ResponseWriter, trailers []string) {
	for _, trailer := range trailers {
		idx := strings.IndexByte(trailer, ':')
		if idx <= 0 {
			continue
		}
		name := strings.TrimSpace(trailer[:idx])
		if httpgutsValidHeaderName(name) {
			w.Header().Add(name, strings.TrimSpace(trailer[idx+1:]))
		}
	}
}

func httpgutsValidHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, ch := range name {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' ||
			strings.ContainsRune("!#$%&'*+-.^_`|~", ch)) {
			return false
		}
	}
	return true
}

func receivePumpResult(result <-chan error) error {
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		return nil
	}
}

func errorText(err error) string {
	if err == nil || strings.TrimSpace(err.Error()) == "" {
		return "HTTP 转发请求失败"
	}
	return err.Error()
}

func writeBufferedWithoutCredit(w http.ResponseWriter, buffer *bytes.Buffer, capture *limitedCapture,
	traffic TrafficRecorder, clientName, route string) error {
	data := buffer.Bytes()
	if len(data) == 0 {
		return nil
	}
	written, err := w.Write(data)
	if written > 0 {
		capture.Write(data[:written])
		if traffic != nil {
			traffic.RecordHTTPDownload(clientName, route, int64(written))
		}
	}
	if err == nil && written != len(data) {
		return io.ErrShortWrite
	}
	return err
}

type limitedCapture struct {
	mu    sync.Mutex
	limit int
	data  []byte
}

func (c *limitedCapture) Write(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	remaining := c.limit - len(c.data)
	if remaining <= 0 {
		return
	}
	if len(data) > remaining {
		data = data[:remaining]
	}
	c.data = append(c.data, data...)
}

func (c *limitedCapture) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.data...)
}
