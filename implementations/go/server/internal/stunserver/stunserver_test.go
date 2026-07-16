package stunserver

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestConfigCreatesRFC5780TopologyAndReadsProtection(t *testing.T) {
	config, err := ConfigFromMap(map[string]string{
		"STUN_PRIMARY_BIND_ADDRESS":         "10.0.0.10",
		"STUN_PRIMARY_PUBLIC_ADDRESS":       "203.0.113.10",
		"STUN_ALTERNATE_BIND_ADDRESS":       "10.0.0.11",
		"STUN_ALTERNATE_PUBLIC_ADDRESS":     "203.0.113.11",
		"STUN_PRIMARY_PORT":                 "3478",
		"STUN_ALTERNATE_PORT":               "3479",
		"STUN_RATE_LIMIT_PER_SECOND":        "25",
		"STUN_RATE_LIMIT_BURST":             "40",
		"STUN_MAX_PADDING_RESPONSE_BYTES":   "1200",
		"STUN_METRICS_BIND_ADDRESS":         "127.0.0.2",
		"STUN_METRICS_PORT":                 "9191",
		"STUN_GLOBAL_RATE_LIMIT_PER_SECOND": "1000",
		"STUN_GLOBAL_RATE_LIMIT_BURST":      "2000",
		"STUN_MAX_TRACKED_SOURCES":          "1234",
		"STUN_SOURCE_IDLE_SECONDS":          "30",
		"STUN_MAX_PACKET_BYTES":             "4096",
	})
	if err != nil {
		t.Fatalf("ConfigFromMap: %v", err)
	}
	if !config.Topology.SupportsRFC5780() || len(config.Topology.Endpoints()) != 4 {
		t.Fatalf("topology = %+v", config.Topology)
	}
	if config.Protect.SourceRatePerSecond != 25 ||
		config.Protect.SourceBurst != 40 ||
		config.Protect.MaxPaddingBytes != 1200 ||
		config.Metrics.Port != 9191 {
		t.Fatalf("config = %+v", config)
	}
}

func TestBindingRoutesChangeResponsePortAndPadding(t *testing.T) {
	topology := testTopology(t)
	service := NewBindingService(topology, "test-stun", false, 64)
	remote := &net.UDPAddr{IP: net.ParseIP("198.51.100.25"), Port: 53000}
	request := Message{
		Type:          BindingRequest,
		TransactionID: [transactionIDBytes]byte{1, 2, 3},
		Attributes: []Attribute{
			ChangeRequestAttribute(true, true),
			ResponsePortAttribute(54321),
		},
	}
	result, err := service.Process(request, remote, Primary, stunHeaderBytes+16)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if result.ResponseEndpoint != Alternate ||
		result.ResponseTarget.Port != 54321 ||
		!result.ResponseTarget.IP.Equal(remote.IP) {
		t.Fatalf("result = %+v", result)
	}
	origin, ok := result.Response.ResponseOrigin()
	if !ok || !origin.IP.Equal(net.ParseIP("203.0.113.11")) || origin.Port != 3479 {
		t.Fatalf("origin = %v, ok=%v", origin, ok)
	}

	padded := Message{
		Type:          BindingRequest,
		TransactionID: [transactionIDBytes]byte{4, 5, 6},
		Attributes:    []Attribute{PaddingAttribute(256)},
	}
	paddedResult, err := service.Process(padded, remote, Primary, 300)
	if err != nil {
		t.Fatalf("padding Process: %v", err)
	}
	padding, ok := paddedResult.Response.First(AttrPadding)
	if !ok || len(padding.Value) != 64 {
		t.Fatalf("response padding = %d, ok=%v", len(padding.Value), ok)
	}

	invalid := Message{
		Type:          BindingRequest,
		TransactionID: [transactionIDBytes]byte{7, 8, 9},
		Attributes:    []Attribute{ResponsePortAttribute(54321), PaddingAttribute(16)},
	}
	invalidResult, err := service.Process(invalid, remote, Primary, 64)
	if err != nil {
		t.Fatalf("invalid Process: %v", err)
	}
	if invalidResult.Response.ErrorCode() != 400 ||
		invalidResult.ResponseTarget.Port != remote.Port {
		t.Fatalf("invalid result = %+v", invalidResult)
	}
}

func TestLimiterAndMetrics(t *testing.T) {
	config := DefaultProtectionConfig()
	config.SourceRatePerSecond = 1
	config.SourceBurst = 2
	config.GlobalRatePerSecond = 100
	config.GlobalBurst = 100
	config.MaxTrackedSources = 1
	limiter := NewRequestLimiter(config)
	first := net.ParseIP("198.51.100.1")
	second := net.ParseIP("198.51.100.2")
	if limiter.Allow(first) != LimitAllowed ||
		limiter.Allow(first) != LimitAllowed ||
		limiter.Allow(first) != LimitSourceRate ||
		limiter.Allow(second) != LimitSourceTable {
		t.Fatal("limiter decisions did not match configured burst and source table")
	}

	metrics := NewMetrics()
	metrics.RecordPacket(20)
	metrics.RecordAcceptedRequest()
	metrics.RecordFeature("padding")
	metrics.RecordResponse(200, 64)
	rendered := metrics.Render(limiter.TrackedSources())
	for _, expected := range []string{
		"stun_packets_received_total 1",
		`stun_feature_requests_total{feature="padding"} 1`,
		`stun_responses_total{code="200"} 1`,
		"stun_tracked_sources 1",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("metrics missing %q:\n%s", expected, rendered)
		}
	}
}

func TestStandaloneServerSendsBindingResponse(t *testing.T) {
	port := freeUDPPort(t)
	config, err := ConfigFromMap(map[string]string{
		"STUN_PRIMARY_BIND_ADDRESS":   "127.0.0.1",
		"STUN_PRIMARY_PUBLIC_ADDRESS": "127.0.0.1",
		"STUN_PRIMARY_PORT":           stringInt(port),
		"STUN_ALTERNATE_PORT":         "0",
		"STUN_METRICS_PORT":           "0",
	})
	if err != nil {
		t.Fatalf("ConfigFromMap: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := NewServer(config)
	done := make(chan error, 1)
	go func() {
		done <- server.Run(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	time.Sleep(25 * time.Millisecond)

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer client.Close()
	request := Message{
		Type:          BindingRequest,
		TransactionID: [transactionIDBytes]byte{9, 8, 7},
	}
	packet, err := request.Bytes()
	if err != nil {
		t.Fatalf("request.Bytes: %v", err)
	}
	if _, err := client.WriteToUDP(packet, &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: port,
	}); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buffer := make([]byte, 2048)
	n, _, err := client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("ReadFromUDP: %v", err)
	}
	response, err := ParseMessage(buffer[:n])
	if err != nil || response.Type != BindingSuccess {
		t.Fatalf("response = %+v, err=%v", response, err)
	}
}

func testTopology(t *testing.T) Topology {
	t.Helper()
	config, err := ConfigFromMap(map[string]string{
		"STUN_PRIMARY_BIND_ADDRESS":     "10.0.0.10",
		"STUN_PRIMARY_PUBLIC_ADDRESS":   "203.0.113.10",
		"STUN_ALTERNATE_BIND_ADDRESS":   "10.0.0.11",
		"STUN_ALTERNATE_PUBLIC_ADDRESS": "203.0.113.11",
		"STUN_PRIMARY_PORT":             "3478",
		"STUN_ALTERNATE_PORT":           "3479",
		"STUN_METRICS_PORT":             "0",
	})
	if err != nil {
		t.Fatalf("ConfigFromMap: %v", err)
	}
	return config.Topology
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("find free UDP port: %v", err)
	}
	port := socket.LocalAddr().(*net.UDPAddr).Port
	if err := socket.Close(); err != nil {
		t.Fatalf("close free UDP port probe: %v", err)
	}
	return port
}

func stringInt(value int) string {
	return strconv.Itoa(value)
}
