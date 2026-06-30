package client

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/client/internal/protocol"
)

const (
	maxHTTPRequestBodySize  = 16 * 1024 * 1024
	maxHTTPResponseBodySize = 64 * 1024 * 1024
	maxHTTPRangeBytes       = 8 * 1024 * 1024
)

var skippedHTTPHeaders = map[string]struct{}{
	"connection":          {},
	"content-length":      {},
	"host":                {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

var forwardingHTTPClient = &http.Client{
	Transport: &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		DisableCompression:    true,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, // Java parity: operator-configured LAN upstreams often use self-signed HTTPS.
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	},
	Timeout: 20 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func (client *Client) forwardDirectHTTP(connection net.Conn, body []byte) {
	packet, err := protocol.DecodeDirectHTTPRequest(body)
	if err != nil {
		client.logger.Printf("[http-direct][client-ingress] decode failed: %v", err)
		return
	}
	startedAt := time.Now()
	client.logger.Printf("[http-direct][client-ingress] requestId=%s method=%s route=%s path=%s queryPresent=%t bodyBytes=%d",
		packet.RequestID, packet.Method, packet.Route, packet.RelativePath, packet.RawQuery != "", len(packet.Body))
	response := protocol.DirectHTTPResponse{RequestID: packet.RequestID}
	if len(packet.Body) > maxHTTPRequestBodySize {
		response.StatusCode = http.StatusBadGateway
		response.Error = stringPtr("HTTP 请求体超过限制")
	} else {
		response = client.executeDirectHTTP(packet)
	}
	client.logger.Printf("[http-direct][client-egress] requestId=%s status=%d error=%q bodyBytes=%d elapsedMs=%d",
		packet.RequestID, response.StatusCode, optionalString(response.Error), len(response.Body), time.Since(startedAt).Milliseconds())
	encoded, err := protocol.EncodeDirectHTTPResponse(response)
	if err == nil {
		err = client.send(connection, protocol.CommandDirectHTTPResponse, encoded)
	}
	if err != nil {
		client.logger.Printf("[http-direct][client->server] requestId=%s write failed: %v", packet.RequestID, err)
	}
}

func (client *Client) executeDirectHTTP(packet protocol.DirectHTTPRequest) protocol.DirectHTTPResponse {
	response := protocol.DirectHTTPResponse{RequestID: packet.RequestID}
	target, err := buildTarget(client.routeTarget(packet.Route), packet.RelativePath, packet.RawQuery)
	if err != nil {
		response.StatusCode = http.StatusBadGateway
		response.Error = stringPtr(err.Error())
		return response
	}
	client.logger.Printf("[http-direct][client->upstream] requestId=%s method=%s route=%s target=%s queryPresent=%t bodyBytes=%d",
		packet.RequestID, packet.Method, packet.Route, targetWithoutQuery(target), target.RawQuery != "", len(packet.Body))
	request, err := http.NewRequest(packet.Method, target.String(), bytes.NewReader(packet.Body))
	if err != nil {
		response.StatusCode = http.StatusBadGateway
		response.Error = stringPtr(err.Error())
		return response
	}
	originalRange := firstListHeader(packet.Headers, "range")
	boundedRange := boundedRange(originalRange)
	copyListHeaders(packet.Headers, request.Header, boundedRange != "")
	if boundedRange != "" {
		request.Header.Set("Range", boundedRange)
		if strings.TrimSpace(originalRange) != "" && !strings.EqualFold(strings.TrimSpace(originalRange), boundedRange) {
			client.logger.Printf("[http-direct][client->upstream] requestId=%s range bounded: %s -> %s",
				packet.RequestID, strings.TrimSpace(originalRange), boundedRange)
		}
	}
	upstream, err := forwardingHTTPClient.Do(request)
	if err != nil {
		response.StatusCode = http.StatusBadGateway
		response.Error = stringPtr(err.Error())
		return response
	}
	defer upstream.Body.Close()
	response.StatusCode = upstream.StatusCode
	response.Headers = flattenHeaders(upstream.Header)
	response.Body, err = readLimitedBody(upstream.Body)
	if err != nil {
		response.StatusCode = http.StatusBadGateway
		response.Headers = nil
		response.Body = nil
		response.Error = stringPtr(err.Error())
	}
	return response
}

func stringPtr(value string) *string {
	return &value
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func buildHTTPRouteMap(configs []HTTPTunnelConfig) map[string]string {
	routes := make(map[string]string, len(configs))
	for _, config := range configs {
		if strings.TrimSpace(config.Route) == "" {
			continue
		}
		routes[config.Route] = config.TargetBaseURL
	}
	return routes
}

func (client *Client) syncHTTPTunnelConfigs(configs []HTTPTunnelConfig) {
	next := buildHTTPRouteMap(configs)
	client.routesMu.Lock()
	previous := len(client.routes)
	client.routes = next
	client.routesMu.Unlock()
	client.logger.Printf("[http-direct] routes updated: %d -> %d entries", previous, len(next))
}

func (client *Client) routeTarget(route string) string {
	client.routesMu.RLock()
	defer client.routesMu.RUnlock()
	return client.routes[route]
}

func (client *Client) snapshotHTTPRoutes() map[string]string {
	client.routesMu.RLock()
	defer client.routesMu.RUnlock()
	snapshot := make(map[string]string, len(client.routes))
	for route, target := range client.routes {
		snapshot[route] = target
	}
	return snapshot
}

func (client *Client) reportHTTPRoutes(connection net.Conn) {
	client.httpRoutesReportedMu.Lock()
	if client.httpRoutesReported {
		client.httpRoutesReportedMu.Unlock()
		return
	}
	client.httpRoutesReported = true
	client.httpRoutesReportedMu.Unlock()

	snapshot := client.snapshotHTTPRoutes()
	routes := make([]map[string]string, 0, len(snapshot))
	for route, target := range snapshot {
		if strings.TrimSpace(route) == "" {
			continue
		}
		routes = append(routes, map[string]string{
			"route":         route,
			"targetBaseUrl": target,
		})
	}
	body, err := protocol.EncodeNatMessage(protocol.NatMessage{
		Type: protocol.NatHTTPRoutesReport,
		Metadata: map[string]any{
			"clientName": client.currentClientName(),
			"routes":     routes,
		},
	})
	if err == nil {
		err = client.send(connection, protocol.CommandNatMessage, body)
	}
	if err != nil {
		client.logger.Printf("report HTTP routes failed: %v", err)
	}
}

func (client *Client) forwardLegacyHTTP(connection net.Conn, body []byte) {
	packet, err := protocol.DecodeLegacyHTTPRequest(body)
	if err != nil {
		client.logger.Printf("[http-legacy] decode failed: %v", err)
		return
	}
	target, err := url.Parse(packet.RequestURL)
	if err != nil {
		client.logger.Printf("[http-legacy] invalid URL requestId=%s: %v", packet.RequestID, err)
		return
	}
	query := target.Query()
	for name, value := range packet.Params {
		query.Add(name, value)
	}
	target.RawQuery = query.Encode()
	request, err := http.NewRequest(packet.Method, target.String(), strings.NewReader(packet.Body))
	if err != nil {
		client.logger.Printf("[http-legacy] build request failed requestId=%s: %v", packet.RequestID, err)
		return
	}
	for name, value := range packet.Headers {
		if shouldForwardHeader(name) {
			request.Header.Add(name, value)
		}
	}
	upstream, err := forwardingHTTPClient.Do(request)
	if err != nil {
		client.logger.Printf("[http-legacy] upstream failed requestId=%s: %v", packet.RequestID, err)
		return
	}
	defer upstream.Body.Close()
	responseBody, err := readLimitedBody(upstream.Body)
	if err != nil {
		client.logger.Printf("[http-legacy] response failed requestId=%s: %v", packet.RequestID, err)
		return
	}
	encoded, err := protocol.EncodeLegacyHTTPResponse(protocol.LegacyHTTPResponse{
		ClientName:   packet.ClientName,
		ToClientName: packet.ToClientName,
		RequestID:    packet.RequestID,
		Response:     string(responseBody),
	})
	if err == nil {
		err = client.send(connection, protocol.CommandLegacyHTTPResponse, encoded)
	}
	if err != nil {
		client.logger.Printf("[http-legacy] write failed requestId=%s: %v", packet.RequestID, err)
	}
}

func buildTarget(targetBaseURL, relativePath, rawQuery string) (*url.URL, error) {
	if strings.TrimSpace(targetBaseURL) == "" {
		return nil, fmt.Errorf("未配置 HTTP route")
	}
	base, err := url.Parse(targetBaseURL)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(base.Scheme, "http") && !strings.EqualFold(base.Scheme, "https") {
		return nil, fmt.Errorf("HTTP route 仅支持 http 和 https")
	}
	if base.Hostname() == "" || base.RawQuery != "" || base.Fragment != "" {
		return nil, fmt.Errorf("HTTP route 地址无效")
	}
	path := relativePath
	if strings.TrimSpace(path) == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n") {
		return nil, fmt.Errorf("HTTP 转发路径无效")
	}
	baseURL := strings.TrimSuffix(targetBaseURL, "/")
	target, err := url.Parse(baseURL + path)
	if err != nil || !strings.EqualFold(base.Scheme, target.Scheme) || !strings.EqualFold(base.Hostname(), target.Hostname()) || base.Port() != target.Port() {
		return nil, fmt.Errorf("HTTP 转发目标越界")
	}
	for _, segment := range strings.Split(target.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, fmt.Errorf("HTTP 转发路径越界")
		}
	}
	basePath := strings.TrimSuffix(base.Path, "/")
	if basePath == "" {
		basePath = "/"
	}
	if basePath != "/" && target.Path != basePath && !strings.HasPrefix(target.Path, basePath+"/") {
		return nil, fmt.Errorf("HTTP 转发路径越界")
	}
	target.RawQuery = rawQuery
	return target, nil
}

func targetWithoutQuery(target *url.URL) string {
	clone := *target
	clone.RawQuery = ""
	return clone.String()
}

func copyListHeaders(headers []string, target http.Header, skipRange bool) {
	for _, header := range headers {
		separator := strings.IndexByte(header, ':')
		if separator <= 0 {
			continue
		}
		name := header[:separator]
		if skipRange && strings.EqualFold(name, "range") {
			continue
		}
		if shouldForwardHeader(name) {
			target.Add(name, header[separator+1:])
		}
	}
}

func flattenHeaders(headers http.Header) []string {
	result := make([]string, 0, len(headers))
	for name, values := range headers {
		if !shouldForwardHeader(name) {
			continue
		}
		for _, value := range values {
			result = append(result, name+":"+value)
		}
	}
	return result
}

func shouldForwardHeader(name string) bool {
	_, skipped := skippedHTTPHeaders[strings.ToLower(name)]
	return name != "" && !skipped
}

func firstListHeader(headers []string, headerName string) string {
	for _, header := range headers {
		separator := strings.IndexByte(header, ':')
		if separator > 0 && strings.EqualFold(header[:separator], headerName) {
			return header[separator+1:]
		}
	}
	return ""
}

func boundedRange(rangeHeader string) string {
	value := strings.TrimSpace(rangeHeader)
	if len(value) < len("bytes=") || !strings.EqualFold(value[:len("bytes=")], "bytes=") {
		return ""
	}
	spec := strings.TrimSpace(value[len("bytes="):])
	if spec == "" || strings.Contains(spec, ",") {
		return ""
	}
	dash := strings.IndexByte(spec, '-')
	if dash < 0 {
		return ""
	}

	startPart := strings.TrimSpace(spec[:dash])
	endPart := strings.TrimSpace(spec[dash+1:])
	if startPart == "" {
		if endPart == "" {
			return ""
		}
		suffixLength, err := strconv.ParseInt(endPart, 10, 64)
		if err != nil || suffixLength <= 0 {
			return ""
		}
		if suffixLength > maxHTTPRangeBytes {
			suffixLength = maxHTTPRangeBytes
		}
		return fmt.Sprintf("bytes=-%d", suffixLength)
	}

	start, err := strconv.ParseInt(startPart, 10, 64)
	if err != nil || start < 0 {
		return ""
	}
	maxEnd := boundedRangeEnd(start)
	if endPart == "" {
		return fmt.Sprintf("bytes=%d-%d", start, maxEnd)
	}
	end, err := strconv.ParseInt(endPart, 10, 64)
	if err != nil || end < start {
		return ""
	}
	if end > maxEnd {
		end = maxEnd
	}
	return fmt.Sprintf("bytes=%d-%d", start, end)
}

func boundedRangeEnd(start int64) int64 {
	delta := int64(maxHTTPRangeBytes - 1)
	if math.MaxInt64-start < delta {
		return math.MaxInt64
	}
	return start + delta
}

func readLimitedBody(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maxHTTPResponseBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxHTTPResponseBodySize {
		return nil, fmt.Errorf("HTTP 响应体超过限制")
	}
	return body, nil
}
