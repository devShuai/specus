package client

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devShuai/shuai-tunnel/tunnel-client-go/internal/protocol"
)

func TestBuildTarget(t *testing.T) {
	target, err := buildTarget("https://example.com:443/base", "/api/hello", "source=tunnel")
	if err != nil {
		t.Fatalf("buildTarget() error = %v", err)
	}
	if actual := target.String(); actual != "https://example.com:443/base/api/hello?source=tunnel" {
		t.Fatalf("buildTarget() = %q", actual)
	}
}

func TestBuildTargetRejectsTraversal(t *testing.T) {
	if _, err := buildTarget("https://example.com/base", "/../secret", ""); err == nil {
		t.Fatal("buildTarget() accepted a traversal path")
	}
}

func TestBuildTargetErrorsUseJavaMessages(t *testing.T) {
	tests := []struct {
		name        string
		targetBase  string
		relativeURL string
		want        string
	}{
		{name: "missing route", targetBase: "", relativeURL: "/", want: "未配置 HTTP route"},
		{name: "unsupported scheme", targetBase: "ftp://example.com/base", relativeURL: "/", want: "HTTP route 仅支持 http 和 https"},
		{name: "invalid base", targetBase: "https://example.com/base?x=1", relativeURL: "/", want: "HTTP route 地址无效"},
		{name: "invalid path", targetBase: "https://example.com/base", relativeURL: "api", want: "HTTP 转发路径无效"},
		{name: "path traversal", targetBase: "https://example.com/base", relativeURL: "/../secret", want: "HTTP 转发路径越界"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildTarget(tc.targetBase, tc.relativeURL, "")
			if err == nil || err.Error() != tc.want {
				t.Fatalf("buildTarget() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestBuildTargetRejectsEncodedTraversalLikeJava(t *testing.T) {
	if _, err := buildTarget("https://example.com/base", "/v1/%2e%2e/secret", ""); err == nil {
		t.Fatal("buildTarget() accepted an encoded traversal path")
	}
}

func TestBuildTargetAcceptsDoubleSlashPathLikeJava(t *testing.T) {
	target, err := buildTarget("https://example.com/base", "//assets/app.js", "")
	if err != nil {
		t.Fatalf("buildTarget() error = %v", err)
	}
	if actual := target.String(); actual != "https://example.com/base//assets/app.js" {
		t.Fatalf("buildTarget() = %q", actual)
	}
}

func TestExecuteDirectHTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if actual := request.Header.Get("X-Tunnel-Test"); actual != "demo" {
			t.Errorf("X-Tunnel-Test = %q", actual)
		}
		if actual, _ := io.ReadAll(request.Body); string(actual) != "request" {
			t.Errorf("body = %q", actual)
		}
		response.Header().Set("X-Upstream", "ok")
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte("response"))
	}))
	defer upstream.Close()

	tunnelClient := New(Config{}, nil)
	tunnelClient.applyRuntime(RuntimeConfig{
		ClientName:           "Demo client",
		HTTPTunnelConfigList: []HTTPTunnelConfig{{Route: "web", TargetBaseURL: upstream.URL}},
	})
	response := tunnelClient.executeDirectHTTP(protocol.DirectHTTPRequest{
		RequestID: "8b284fef-0987-4948-ac66-7f2059336989",
		Method:    http.MethodPost,
		Route:     "web",
		Headers:   []string{"X-Tunnel-Test:demo", "Host:ignored"},
		Body:      []byte("request"),
	})
	if response.Error != nil || response.StatusCode != http.StatusCreated || string(response.Body) != "response" {
		t.Fatalf("executeDirectHTTP() = %#v", response)
	}
	if len(response.Headers) != 3 && len(response.Headers) != 4 {
		t.Fatalf("response headers = %#v", response.Headers)
	}
}

func TestExecuteDirectHTTPTrustsSelfSignedHTTPS(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("secure"))
	}))
	defer upstream.Close()

	tunnelClient := New(Config{}, nil)
	tunnelClient.applyRuntime(RuntimeConfig{
		ClientName:           "Demo client",
		HTTPTunnelConfigList: []HTTPTunnelConfig{{Route: "secure", TargetBaseURL: upstream.URL}},
	})
	response := tunnelClient.executeDirectHTTP(protocol.DirectHTTPRequest{
		RequestID: "8b284fef-0987-4948-ac66-7f2059336992",
		Method:    http.MethodGet,
		Route:     "secure",
	})
	if response.Error != nil || response.StatusCode != http.StatusOK || string(response.Body) != "secure" {
		t.Fatalf("executeDirectHTTP() = %#v", response)
	}
}

func TestExecuteDirectHTTPBoundsRange(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if actual := request.Header.Get("Range"); actual != "bytes=0-8388607" {
			t.Errorf("Range = %q", actual)
		}
		response.WriteHeader(http.StatusPartialContent)
		_, _ = response.Write([]byte("range"))
	}))
	defer upstream.Close()

	tunnelClient := New(Config{}, nil)
	tunnelClient.applyRuntime(RuntimeConfig{
		ClientName:           "Demo client",
		HTTPTunnelConfigList: []HTTPTunnelConfig{{Route: "web", TargetBaseURL: upstream.URL}},
	})
	response := tunnelClient.executeDirectHTTP(protocol.DirectHTTPRequest{
		RequestID: "8b284fef-0987-4948-ac66-7f2059336993",
		Method:    http.MethodGet,
		Route:     "web",
		Headers:   []string{"Range:bytes=0-"},
	})
	if response.Error != nil || response.StatusCode != http.StatusPartialContent || string(response.Body) != "range" {
		t.Fatalf("executeDirectHTTP() = %#v", response)
	}
}

func TestBoundedRange(t *testing.T) {
	tests := map[string]string{
		"bytes=0-":          "bytes=0-8388607",
		"bytes=10-20":       "bytes=10-20",
		"bytes=10-99999999": "bytes=10-8388617",
		"bytes=-99999999":   "bytes=-8388608",
		"bytes=20-10":       "",
		"bytes=0-1,2-3":     "",
		"items=0-10":        "",
	}
	for input, expected := range tests {
		if actual := boundedRange(input); actual != expected {
			t.Fatalf("boundedRange(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestReadLimitedBodyErrorUsesJavaMessage(t *testing.T) {
	_, err := readLimitedBody(io.LimitReader(repeatingReader{}, maxHTTPResponseBodySize+1))
	if err == nil || err.Error() != "HTTP 响应体超过限制" {
		t.Fatalf("readLimitedBody() error = %v, want Java message", err)
	}
}

type repeatingReader struct{}

func (repeatingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func TestSyncHTTPTunnelConfigsUpdatesDirectHTTPRoutes(t *testing.T) {
	upstreamA := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte("a"))
	}))
	defer upstreamA.Close()
	upstreamB := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte("b"))
	}))
	defer upstreamB.Close()

	tunnelClient := New(Config{}, nil)
	tunnelClient.applyRuntime(RuntimeConfig{
		ClientName:           "Demo client",
		HTTPTunnelConfigList: []HTTPTunnelConfig{{Route: "web", TargetBaseURL: upstreamA.URL}},
	})
	response := tunnelClient.executeDirectHTTP(protocol.DirectHTTPRequest{
		RequestID: "8b284fef-0987-4948-ac66-7f2059336989",
		Method:    http.MethodGet,
		Route:     "web",
	})
	if string(response.Body) != "a" {
		t.Fatalf("initial response = %#v", response)
	}

	tunnelClient.syncHTTPTunnelConfigs([]HTTPTunnelConfig{{Route: "web", TargetBaseURL: upstreamB.URL}})
	response = tunnelClient.executeDirectHTTP(protocol.DirectHTTPRequest{
		RequestID: "8b284fef-0987-4948-ac66-7f2059336990",
		Method:    http.MethodGet,
		Route:     "web",
	})
	if string(response.Body) != "b" {
		t.Fatalf("updated response = %#v", response)
	}

	tunnelClient.syncHTTPTunnelConfigs([]HTTPTunnelConfig{})
	response = tunnelClient.executeDirectHTTP(protocol.DirectHTTPRequest{
		RequestID: "8b284fef-0987-4948-ac66-7f2059336991",
		Method:    http.MethodGet,
		Route:     "web",
	})
	if response.StatusCode != http.StatusBadGateway || response.Error == nil || *response.Error == "" {
		t.Fatalf("cleared response = %#v", response)
	}
}

func TestReportHTTPRoutesSendsNatReport(t *testing.T) {
	reader, writer := net.Pipe()
	defer reader.Close()
	defer writer.Close()

	tunnelClient := New(Config{}, nil)
	tunnelClient.applyRuntime(RuntimeConfig{
		ClientName:           "Demo client",
		HTTPTunnelConfigList: []HTTPTunnelConfig{{Route: "web", TargetBaseURL: "http://127.0.0.1:8080"}},
	})
	done := make(chan struct{})
	go func() {
		tunnelClient.reportHTTPRoutes(writer)
		close(done)
	}()

	packet, err := protocol.ReadPacket(reader)
	if err != nil {
		t.Fatalf("read packet: %v", err)
	}
	<-done
	if packet.Command != protocol.CommandNatMessage {
		t.Fatalf("command = %d", packet.Command)
	}
	message, err := protocol.DecodeNatMessage(packet.Body)
	if err != nil {
		t.Fatalf("decode NAT message: %v", err)
	}
	if message.Type != protocol.NatHTTPRoutesReport {
		t.Fatalf("message type = %d", message.Type)
	}
	if message.Metadata["clientName"] != "Demo client" {
		t.Fatalf("clientName metadata = %#v", message.Metadata["clientName"])
	}
	routes, ok := message.Metadata["routes"].([]any)
	if !ok || len(routes) != 1 {
		t.Fatalf("routes metadata = %#v", message.Metadata["routes"])
	}
	route, ok := routes[0].(map[string]any)
	if !ok || route["route"] != "web" || route["targetBaseUrl"] != "http://127.0.0.1:8080" {
		t.Fatalf("route metadata = %#v", routes[0])
	}
}
