package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/devShuai/specus/implementations/go/client/internal/protocol"
)

const (
	maxHTTPRequestBodySize  = 16 * 1024 * 1024
	maxHTTPResponseBodySize = 64 * 1024 * 1024
	httpStreamChunkBytes    = 64 * 1024
	httpRequestQueueChunks  = 32
)

var forwardingHTTPClient = &http.Client{
	Transport: &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		DisableCompression:    true,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, // Operator-configured LAN targets may use self-signed HTTPS.
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	},
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
}

type httpRequestStream struct {
	client     *Client
	connection net.Conn
	streamID   uint32
	metadata   map[string]any
	body       *httpRequestBody
	ctx        context.Context
	cancel     context.CancelFunc
	once       sync.Once
}

func newHTTPRequestStream(client *Client, connection net.Conn, streamID uint32,
	metadata map[string]any) *httpRequestStream {
	ctx, cancel := context.WithCancel(context.Background())
	stream := &httpRequestStream{
		client: client, connection: connection, streamID: streamID,
		metadata: cloneHTTPMetadata(metadata), ctx: ctx, cancel: cancel,
	}
	stream.body = newHTTPRequestBody(func(bytes int) {
		client.sendNatWindowUpdate(connection, streamID, bytes)
	})
	return stream
}

func (client *Client) openHTTPStream(connection net.Conn, streamID uint32, metadata map[string]any) {
	phase, _ := metadataStringOptional(metadata, "phase")
	if phase != "request" {
		client.sendNatReset(connection, streamID, 20, "invalid HTTP OPEN phase")
		client.closeNatFlow(streamID)
		return
	}
	stream := newHTTPRequestStream(client, connection, streamID, metadata)
	client.httpMu.Lock()
	if previous := client.httpStreams[streamID]; previous != nil {
		client.httpMu.Unlock()
		client.sendNatReset(connection, streamID, 21, "duplicate HTTP stream")
		client.closeNatFlow(streamID)
		return
	}
	client.httpStreams[streamID] = stream
	client.httpMu.Unlock()
	go stream.forward()
}

func (client *Client) writeHTTPData(streamID uint32, data []byte) bool {
	client.httpMu.Lock()
	stream := client.httpStreams[streamID]
	client.httpMu.Unlock()
	if stream == nil {
		return false
	}
	if !stream.body.offer(data) {
		stream.fail(22, "HTTP request queue or size limit exceeded")
	}
	return true
}

func (client *Client) finishHTTPRequest(streamID uint32, metadata map[string]any) bool {
	client.httpMu.Lock()
	stream := client.httpStreams[streamID]
	client.httpMu.Unlock()
	if stream == nil {
		return false
	}
	stream.body.finish(metadataStrings(metadata, "trailers"))
	return true
}

func (client *Client) resetHTTPStream(streamID uint32, reason string) bool {
	client.httpMu.Lock()
	stream := client.httpStreams[streamID]
	if stream != nil {
		delete(client.httpStreams, streamID)
	}
	client.httpMu.Unlock()
	if stream == nil {
		return false
	}
	stream.abort(reason)
	return true
}

func (client *Client) closeHTTPStreams() {
	client.httpMu.Lock()
	streams := client.httpStreams
	client.httpStreams = make(map[uint32]*httpRequestStream)
	client.httpMu.Unlock()
	for _, stream := range streams {
		stream.abort("control channel closed")
	}
}

func (stream *httpRequestStream) forward() {
	defer stream.complete()
	method, err := requiredHTTPMetadata(stream.metadata, "method")
	if err != nil {
		stream.fail(23, err.Error())
		return
	}
	route, err := requiredHTTPMetadata(stream.metadata, "route")
	if err != nil {
		stream.fail(23, err.Error())
		return
	}
	relativePath, _ := metadataStringOptional(stream.metadata, "relativePath")
	rawQuery, _ := metadataStringOptional(stream.metadata, "rawQuery")
	target, err := buildTarget(stream.client.routeTarget(route), relativePath, rawQuery)
	if err != nil {
		stream.fail(24, err.Error())
		return
	}

	contentLength, hasLength := metadataInt64(stream.metadata, "contentLength")
	var body io.Reader = stream.body
	if hasLength && contentLength == 0 {
		body = http.NoBody
	}
	request, err := http.NewRequestWithContext(stream.ctx, method, target.String(), body)
	if err != nil {
		stream.fail(25, err.Error())
		return
	}
	if hasLength && contentLength >= 0 {
		request.ContentLength = contentLength
	}
	request.Trailer = make(http.Header)
	for _, name := range metadataStrings(stream.metadata, "trailerNames") {
		if shouldForwardHeader(name) {
			request.Trailer[http.CanonicalHeaderKey(name)] = nil
		}
	}
	stream.body.setTrailerTarget(request.Trailer)
	headers := metadataStrings(stream.metadata, "headers")
	rangeHeader := boundedRange(firstListHeader(headers, "range"))
	copyListHeaders(headers, request.Header, rangeHeader != "")
	if rangeHeader != "" {
		request.Header.Set("Range", rangeHeader)
	}

	upstream, err := forwardingHTTPClient.Do(request)
	if err != nil {
		if stream.ctx.Err() == nil {
			stream.fail(26, err.Error())
		}
		return
	}
	defer upstream.Body.Close()

	responseMetadata := map[string]any{
		"source": "http", "phase": "response", "statusCode": upstream.StatusCode,
		"headers": flattenHeaders(upstream.Header), "trailerNames": trailerNames(upstream.Trailer),
	}
	if err := stream.send(protocol.NatMessage{
		Type: protocol.NatOpen, StreamID: stream.streamID, Metadata: responseMetadata,
	}); err != nil {
		return
	}

	buffer := make([]byte, httpStreamChunkBytes)
	total := 0
	for {
		read, readErr := upstream.Body.Read(buffer)
		if read > 0 {
			total += read
			if total > maxHTTPResponseBodySize {
				stream.fail(27, "HTTP 响应体超过限制")
				return
			}
			if !stream.client.takeNatCredit(stream.streamID, read) {
				return
			}
			payload := append([]byte(nil), buffer[:read]...)
			if err := stream.send(protocol.NatMessage{
				Type: protocol.NatData, StreamID: stream.streamID, Data: payload,
			}); err != nil {
				return
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				stream.fail(28, readErr.Error())
				return
			}
			trailers := flattenHeaders(upstream.Trailer)
			metadata := map[string]any(nil)
			if len(trailers) > 0 {
				metadata = map[string]any{"trailers": trailers}
			}
			if err := stream.send(protocol.NatMessage{
				Type: protocol.NatFin, StreamID: stream.streamID, Metadata: metadata,
			}); err != nil {
				return
			}
			return
		}
	}
}

func (stream *httpRequestStream) send(message protocol.NatMessage) error {
	body, err := protocol.EncodeNatMessage(message)
	if err == nil {
		err = stream.client.send(stream.connection, protocol.CommandNatMessage, body)
	}
	return err
}

func (stream *httpRequestStream) fail(code uint32, reason string) {
	stream.client.sendNatReset(stream.connection, stream.streamID, code, reason)
	stream.abort(reason)
}

func (stream *httpRequestStream) abort(reason string) {
	stream.once.Do(func() {
		stream.cancel()
		stream.body.abort(reason)
	})
}

func (stream *httpRequestStream) complete() {
	stream.client.httpMu.Lock()
	if stream.client.httpStreams[stream.streamID] == stream {
		delete(stream.client.httpStreams, stream.streamID)
	}
	stream.client.httpMu.Unlock()
	stream.abort("HTTP stream complete")
	stream.client.closeNatFlow(stream.streamID)
}

type httpBodyChunk struct {
	data     []byte
	trailers []string
	err      error
	end      bool
}

type httpRequestBody struct {
	queue     chan httpBodyChunk
	done      chan struct{}
	consumed  func(int)
	current   []byte
	offset    int
	total     int
	mu        sync.Mutex
	accepting bool
	aborted   bool
	abortErr  error
	trailers  http.Header
}

func newHTTPRequestBody(consumed func(int)) *httpRequestBody {
	return &httpRequestBody{
		queue: make(chan httpBodyChunk, httpRequestQueueChunks), done: make(chan struct{}),
		consumed: consumed, accepting: true,
	}
}

func (body *httpRequestBody) offer(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	body.mu.Lock()
	if !body.accepting || body.total > maxHTTPRequestBodySize-len(data) {
		body.mu.Unlock()
		return false
	}
	body.total += len(data)
	body.mu.Unlock()
	chunk := httpBodyChunk{data: append([]byte(nil), data...)}
	select {
	case body.queue <- chunk:
		return true
	default:
		return false
	}
}

func (body *httpRequestBody) finish(trailers []string) {
	body.mu.Lock()
	if !body.accepting {
		body.mu.Unlock()
		return
	}
	body.accepting = false
	body.mu.Unlock()
	select {
	case body.queue <- httpBodyChunk{trailers: trailers, end: true}:
	default:
		body.abort("HTTP request queue full on FIN")
	}
}

func (body *httpRequestBody) abort(reason string) {
	body.mu.Lock()
	if body.aborted {
		body.mu.Unlock()
		return
	}
	body.accepting = false
	body.aborted = true
	body.abortErr = errors.New(defaultHTTPReason(reason))
	close(body.done)
	body.mu.Unlock()
}

func (body *httpRequestBody) Read(target []byte) (int, error) {
	for len(body.current) == 0 || body.offset == len(body.current) {
		if len(body.current) > 0 && body.consumed != nil {
			body.consumed(len(body.current))
		}
		select {
		case <-body.done:
			body.mu.Lock()
			err := body.abortErr
			body.mu.Unlock()
			return 0, err
		default:
		}
		var chunk httpBodyChunk
		select {
		case <-body.done:
			body.mu.Lock()
			err := body.abortErr
			body.mu.Unlock()
			return 0, err
		case chunk = <-body.queue:
		}
		if chunk.err != nil {
			return 0, chunk.err
		}
		if chunk.end {
			body.applyTrailers(chunk.trailers)
			return 0, io.EOF
		}
		body.current = chunk.data
		body.offset = 0
	}
	copied := copy(target, body.current[body.offset:])
	body.offset += copied
	return copied, nil
}

func (body *httpRequestBody) Close() error {
	body.abort("HTTP request body closed")
	return nil
}

func (body *httpRequestBody) setTrailerTarget(trailers http.Header) {
	body.mu.Lock()
	body.trailers = trailers
	body.mu.Unlock()
}

func (body *httpRequestBody) applyTrailers(values []string) {
	body.mu.Lock()
	defer body.mu.Unlock()
	for _, value := range values {
		separator := strings.IndexByte(value, ':')
		if separator <= 0 {
			continue
		}
		name := http.CanonicalHeaderKey(strings.TrimSpace(value[:separator]))
		if _, declared := body.trailers[name]; declared && shouldForwardHeader(name) {
			body.trailers.Add(name, strings.TrimSpace(value[separator+1:]))
		}
	}
}

func requiredHTTPMetadata(metadata map[string]any, key string) (string, error) {
	value, ok := metadataStringOptional(metadata, key)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("HTTP OPEN missing %s", key)
	}
	return value, nil
}

func metadataStrings(metadata map[string]any, key string) []string {
	value, ok := metadata[key]
	if !ok || value == nil {
		return nil
	}
	if values, ok := value.([]string); ok {
		return append([]string(nil), values...)
	}
	items, ok := value.([]any)
	if !ok {
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

func metadataInt64(metadata map[string]any, key string) (int64, bool) {
	value, ok := metadata[key]
	if !ok || value == nil {
		return 0, false
	}
	switch number := value.(type) {
	case float64:
		return int64(number), true
	case int64:
		return number, true
	case int:
		return int64(number), true
	default:
		var result int64
		_, err := fmt.Sscan(fmt.Sprint(value), &result)
		return result, err == nil
	}
}

func trailerNames(trailer http.Header) []string {
	result := make([]string, 0, len(trailer))
	for name := range trailer {
		result = append(result, name)
	}
	return result
}

func cloneHTTPMetadata(metadata map[string]any) map[string]any {
	result := make(map[string]any, len(metadata))
	for key, value := range metadata {
		result[key] = value
	}
	return result
}

func defaultHTTPReason(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return "HTTP stream reset"
	}
	return reason
}
