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
	if response.Error != "" || response.StatusCode != http.StatusCreated || string(response.Body) != "response" {
		t.Fatalf("executeDirectHTTP() = %#v", response)
	}
	if len(response.Headers) != 3 && len(response.Headers) != 4 {
		t.Fatalf("response headers = %#v", response.Headers)
	}
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
	if response.StatusCode != http.StatusBadGateway || response.Error == "" {
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
