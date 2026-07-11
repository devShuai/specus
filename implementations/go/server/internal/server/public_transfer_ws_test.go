package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/config"
)

func TestPublicTransferDiscoveryIsolationRosterAndTargetedSignal(t *testing.T) {
	hub := newPublicTransferDiscoveryHub(config.PublicTransferConfig{
		MaxDiscoveryPeersPerRoom:               2,
		DiscoveryMessageRateLimitPerConnection: 10,
		DiscoveryMessageRateLimitWindowSeconds: 60,
	})
	server := httptest.NewServer(hub)
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/?roomId=room-a&roomToken=shared-secret"
	a := dialDiscovery(t, wsURL+"&peerId=a", "198.51.100.1")
	defer a.Close(websocket.StatusNormalClosure, "bye")
	readDiscoveryType(t, a, "hello")
	readDiscoveryType(t, a, "roster")

	b := dialDiscovery(t, wsURL+"&peerId=b", "203.0.113.2")
	defer b.Close(websocket.StatusNormalClosure, "bye")
	readDiscoveryType(t, b, "hello")
	roster := readDiscoveryType(t, b, "roster")
	peers, ok := roster["peers"].([]any)
	if !ok || len(peers) != 2 {
		t.Fatalf("shared-token peers were not grouped across public IPs: %#v", roster)
	}

	message := []byte(`{"type":"offer","targetPeerId":"b","payload":{"sdp":"test"}}`)
	if err := a.Write(context.Background(), websocket.MessageText, message); err != nil {
		t.Fatal(err)
	}
	delivered := readDiscoveryType(t, b, "offer")
	if delivered["sourcePeerId"] != "a" || delivered["targetPeerId"] != "b" || delivered["publicAddress"] != "198.51.100.1" {
		t.Fatalf("unexpected targeted envelope: %#v", delivered)
	}

	if err := a.Write(context.Background(), websocket.MessageText, []byte(`"valid-non-object-json"`)); err != nil {
		t.Fatal(err)
	}
	defaultSignal := readDiscoveryType(t, b, "signal")
	if value, exists := defaultSignal["payload"]; !exists || value != nil {
		t.Fatalf("non-object JSON did not use Java's default signal/null payload: %#v", defaultSignal)
	}
	if value, exists := defaultSignal["targetPeerId"]; !exists || value != nil {
		t.Fatalf("default signal did not retain Java's null target: %#v", defaultSignal)
	}
	if err := a.Write(context.Background(), websocket.MessageText, []byte(`{"payload":null}`)); err != nil {
		t.Fatal(err)
	}
	explicitNull := readDiscoveryType(t, b, "signal")
	if value, exists := explicitNull["payload"]; !exists || value != nil {
		t.Fatalf("explicit payload:null was dropped: %#v", explicitNull)
	}

	third := dialDiscovery(t, wsURL+"&peerId=c", "192.0.2.3")
	defer third.Close(websocket.StatusNormalClosure, "bye")
	errorMessage := readDiscoveryType(t, third, "error")
	if errorMessage["error"] != "room is full" {
		t.Fatalf("unexpected room-full error: %#v", errorMessage)
	}

	isolatedURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/?roomId=room-a&peerId=isolated"
	isolated := dialDiscovery(t, isolatedURL, "192.0.2.99")
	defer isolated.Close(websocket.StatusNormalClosure, "bye")
	readDiscoveryType(t, isolated, "hello")
	isolatedRoster := readDiscoveryType(t, isolated, "roster")
	if got := len(isolatedRoster["peers"].([]any)); got != 1 {
		t.Fatalf("public-IP room leaked peers: %d", got)
	}
}

func TestPublicTransferDiscoveryRejectsDuplicatePeerIDInSameGroup(t *testing.T) {
	hub := newPublicTransferDiscoveryHub(config.PublicTransferConfig{
		MaxDiscoveryPeersPerRoom:               4,
		DiscoveryMessageRateLimitPerConnection: 10,
		DiscoveryMessageRateLimitWindowSeconds: 60,
	})
	server := httptest.NewServer(hub)
	defer server.Close()
	baseURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/?roomId=duplicate-room&roomToken=secret"

	first := dialDiscovery(t, baseURL+"&peerId=reused", "198.51.100.1")
	defer first.CloseNow()
	readDiscoveryType(t, first, "hello")
	readDiscoveryType(t, first, "roster")

	duplicate := dialDiscovery(t, baseURL+"&peerId=reused", "203.0.113.2")
	defer duplicate.CloseNow()
	errorMessage := readDiscoveryType(t, duplicate, "error")
	if errorMessage["error"] != "peer id is already connected" {
		t.Fatalf("unexpected duplicate-peer error: %#v", errorMessage)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, err := duplicate.Read(ctx)
	if status := websocket.CloseStatus(err); status != websocket.StatusPolicyViolation {
		t.Fatalf("duplicate-peer close status = %d err=%v, want %d", status, err, websocket.StatusPolicyViolation)
	}
	var closeError websocket.CloseError
	if !errors.As(err, &closeError) || closeError.Reason != "peer id is already connected" {
		t.Fatalf("duplicate-peer close reason = %#v, want %q", closeError.Reason, "peer id is already connected")
	}

	otherGroup := dialDiscovery(t, baseURL+"-other&peerId=reused", "192.0.2.3")
	defer otherGroup.CloseNow()
	readDiscoveryType(t, otherGroup, "hello")
	readDiscoveryType(t, otherGroup, "roster")
}

func TestPublicTransferDiscoveryRateLimitAndTrustedAddress(t *testing.T) {
	hub := newPublicTransferDiscoveryHub(config.PublicTransferConfig{
		MaxDiscoveryPeersPerRoom:               4,
		DiscoveryMessageRateLimitPerConnection: 1,
		DiscoveryMessageRateLimitWindowSeconds: 60,
	})
	server := httptest.NewServer(hub)
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/?peerId=a"
	conn := dialDiscoveryWithHeaders(t, wsURL, http.Header{
		"X-Forwarded-For": []string{"198.51.100.7, 203.0.113.8"},
	})
	defer conn.Close(websocket.StatusNormalClosure, "bye")
	hello := readDiscoveryType(t, conn, "hello")
	if hello["publicAddress"] != "203.0.113.8" {
		t.Fatalf("trusted XFF last hop not used: %#v", hello)
	}
	readDiscoveryType(t, conn, "roster")
	_ = conn.Write(context.Background(), websocket.MessageText, []byte(`{"type":"ping"}`))
	readDiscoveryType(t, conn, "pong")
	_ = conn.Write(context.Background(), websocket.MessageText, []byte(`{"type":"ping"}`))
	limited := readDiscoveryType(t, conn, "error")
	if limited["error"] != "rate limited" {
		t.Fatalf("unexpected rate response: %#v", limited)
	}
}

func TestDiscoveryQueryTruncationIsUTF8SafeAndUsesJavaLength(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/?displayName="+url.QueryEscape(strings.Repeat("中", 121)), nil)
	value := queryValue(request, "displayName", "web", 120)
	if len([]rune(value)) != 120 || !json.Valid([]byte(`"`+value+`"`)) {
		t.Fatalf("BMP value was not truncated safely: runes=%d value=%q", len([]rune(value)), value)
	}
	request = httptest.NewRequest(http.MethodGet, "/?displayName="+url.QueryEscape(strings.Repeat("😀", 61)), nil)
	value = queryValue(request, "displayName", "web", 120)
	if len([]rune(value)) != 60 {
		t.Fatalf("UTF-16 surrogate-pair limit mismatch: runes=%d", len([]rune(value)))
	}
}

func TestPublicTransferDiscoveryAcceptsJavaSizedMultibyteTextAndRejectsBinary(t *testing.T) {
	hub := newPublicTransferDiscoveryHub(config.PublicTransferConfig{
		MaxDiscoveryPeersPerRoom:               2,
		DiscoveryMessageRateLimitPerConnection: 10,
		DiscoveryMessageRateLimitWindowSeconds: 60,
	})
	server := httptest.NewServer(hub)
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/?peerId=utf8"
	conn := dialDiscovery(t, wsURL, "192.0.2.20")
	defer conn.CloseNow()
	readDiscoveryType(t, conn, "hello")
	readDiscoveryType(t, conn, "roster")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	payload := []byte(`{"type":"ping","padding":"` + strings.Repeat("中", 22_000) + `"}`)
	if len(payload) <= 64*1024 {
		t.Fatalf("test payload is only %d UTF-8 bytes", len(payload))
	}
	if err := conn.Write(ctx, websocket.MessageText, payload); err != nil {
		t.Fatalf("write multibyte discovery message: %v", err)
	}
	readDiscoveryType(t, conn, "pong")
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("binary")); err != nil {
		t.Fatalf("write binary message: %v", err)
	}
	_, _, err := conn.Read(ctx)
	if status := websocket.CloseStatus(err); status != websocket.StatusUnsupportedData {
		t.Fatalf("binary close status = %d err=%v, want %d", status, err, websocket.StatusUnsupportedData)
	}
}

func dialDiscovery(t *testing.T, rawURL, realIP string) *websocket.Conn {
	t.Helper()
	return dialDiscoveryWithHeaders(t, rawURL, http.Header{"X-Real-IP": []string{realIP}})
}

func dialDiscoveryWithHeaders(t *testing.T, rawURL string, headers http.Header) *websocket.Conn {
	t.Helper()
	if _, err := url.Parse(rawURL); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, rawURL, &websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		t.Fatalf("dial discovery: %v", err)
	}
	return conn
}

func readDiscoveryType(t *testing.T, conn *websocket.Conn, expected string) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	messageType, payload, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read %s: %v", expected, err)
	}
	if messageType != websocket.MessageText {
		t.Fatalf("message type = %v", messageType)
	}
	var value map[string]any
	if err := json.Unmarshal(payload, &value); err != nil {
		t.Fatal(err)
	}
	if value["type"] != expected {
		t.Fatalf("type = %#v, want %q; payload=%s", value["type"], expected, payload)
	}
	return value
}
