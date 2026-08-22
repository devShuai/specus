package client

import (
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const maxHTTPRangeBytes = 8 * 1024 * 1024

var skippedHTTPHeaders = map[string]struct{}{
	"connection": {}, "content-length": {}, "host": {}, "keep-alive": {},
	"proxy-authenticate": {}, "proxy-authorization": {}, "te": {},
	"trailer": {}, "transfer-encoding": {}, "upgrade": {},
}

func buildHTTPRouteMap(configs []HTTPSpecusConfig) map[string]HTTPSpecusConfig {
	routes := make(map[string]HTTPSpecusConfig, len(configs))
	for _, config := range configs {
		route := strings.TrimSpace(config.Route)
		if route != "" {
			config.Route = route
			routes[route] = config
		}
	}
	return routes
}

func (client *Client) syncHTTPSpecusConfigs(configs []HTTPSpecusConfig) {
	next := buildHTTPRouteMap(configs)
	client.routesMu.Lock()
	previous := len(client.routes)
	client.routes = next
	client.routesMu.Unlock()
	client.logger.Printf("[http-stream] routes updated: %d -> %d entries", previous, len(next))
}

func (client *Client) routeConfig(route string) (HTTPSpecusConfig, bool) {
	client.routesMu.RLock()
	defer client.routesMu.RUnlock()
	config, ok := client.routes[route]
	return config, ok
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
	if err != nil || !strings.EqualFold(base.Scheme, target.Scheme) ||
		!strings.EqualFold(base.Hostname(), target.Hostname()) || base.Port() != target.Port() {
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

func rewriteUpstreamAuthorityHeaders(headers http.Header, target *url.URL) {
	origin := httpOriginOf(target)
	if origin == "" {
		return
	}
	if headers.Get("Origin") != "" {
		headers.Set("Origin", origin)
	}
	if referer := headers.Get("Referer"); referer != "" {
		headers.Set("Referer", rewriteRefererOrigin(referer, origin))
	}
	if strings.EqualFold(headers.Get("Sec-Fetch-Site"), "cross-site") {
		headers.Set("Sec-Fetch-Site", "same-origin")
	}
}

func rewriteHeaderLines(lines []string, target *url.URL) []string {
	origin := httpOriginOf(target)
	if origin == "" || len(lines) == 0 {
		return lines
	}
	rewritten := make([]string, 0, len(lines))
	for _, line := range lines {
		separator := strings.IndexByte(line, ':')
		if separator <= 0 {
			rewritten = append(rewritten, line)
			continue
		}
		name := line[:separator]
		value := line[separator+1:]
		switch {
		case strings.EqualFold(name, "Origin"):
			rewritten = append(rewritten, name+":"+origin)
		case strings.EqualFold(name, "Referer"):
			rewritten = append(rewritten, name+":"+rewriteRefererOrigin(value, origin))
		case strings.EqualFold(name, "Sec-Fetch-Site") && strings.EqualFold(strings.TrimSpace(value), "cross-site"):
			rewritten = append(rewritten, name+":same-origin")
		default:
			rewritten = append(rewritten, line)
		}
	}
	return rewritten
}

func httpOriginOf(target *url.URL) string {
	if target == nil || target.Host == "" {
		return ""
	}
	scheme := strings.ToLower(target.Scheme)
	switch scheme {
	case "ws":
		scheme = "http"
	case "wss":
		scheme = "https"
	case "http", "https":
	default:
		return ""
	}
	return scheme + "://" + target.Host
}

func rewriteRefererOrigin(referer, origin string) string {
	parsed, err := url.Parse(strings.TrimSpace(referer))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return origin + "/"
	}
	base, err := url.Parse(origin)
	if err != nil {
		return origin + "/"
	}
	parsed.Scheme = base.Scheme
	parsed.Host = base.Host
	parsed.User = nil
	return parsed.String()
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
		if shouldForwardHeader(name) {
			for _, value := range values {
				result = append(result, name+":"+value)
			}
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
	startPart, endPart := strings.TrimSpace(spec[:dash]), strings.TrimSpace(spec[dash+1:])
	if startPart == "" {
		suffix, err := strconv.ParseInt(endPart, 10, 64)
		if err != nil || suffix <= 0 {
			return ""
		}
		return fmt.Sprintf("bytes=-%d", min(suffix, int64(maxHTTPRangeBytes)))
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
	return fmt.Sprintf("bytes=%d-%d", start, min(end, maxEnd))
}

func boundedRangeEnd(start int64) int64 {
	delta := int64(maxHTTPRangeBytes - 1)
	if math.MaxInt64-start < delta {
		return math.MaxInt64
	}
	return start + delta
}
