package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/config"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/security"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/store"
)

func TestPublicTransferClusterFrameMatchesCanonicalVector(t *testing.T) {
	var vectors struct {
		GroupIDDerivation struct {
			RoomID  string `json:"roomId"`
			RoomKey string `json:"roomKey"`
			GroupID string `json:"groupId"`
		} `json:"groupIdDerivation"`
		CanonicalText struct {
			Kind          byte   `json:"kind"`
			ExcludeSource bool   `json:"excludeSource"`
			Revision      uint64 `json:"revision"`
			GroupID       string `json:"groupId"`
			TargetPeerID  string `json:"targetPeerId"`
			SourceLeaseID string `json:"sourceLeaseId"`
			PayloadUTF8   string `json:"payloadUtf8"`
			FrameHex      string `json:"frameHex"`
		} `json:"canonicalText"`
		CanonicalManagement struct {
			Kind          byte   `json:"kind"`
			ExcludeSource bool   `json:"excludeSource"`
			Revision      uint64 `json:"revision"`
			TenantID      string `json:"tenantId"`
			GroupID       string `json:"groupId"`
			TargetPeerID  string `json:"targetPeerId"`
			SourceLeaseID string `json:"sourceLeaseId"`
			PayloadUTF8   string `json:"payloadUtf8"`
			FrameHex      string `json:"frameHex"`
		} `json:"canonicalManagement"`
	}
	contents, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "protocol",
		"test-vectors", "public-transfer-cluster-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(contents, &vectors); err != nil {
		t.Fatal(err)
	}
	vector := vectors.CanonicalText
	encoded, err := encodePublicTransferClusterEvent(publicTransferClusterEvent{
		kind: vector.Kind, excludeSource: vector.ExcludeSource, revision: vector.Revision,
		groupID: vector.GroupID, targetPeerID: vector.TargetPeerID,
		sourceLeaseID: vector.SourceLeaseID, payload: []byte(vector.PayloadUTF8),
	})
	if err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString(vector.FrameHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, expected) {
		t.Fatalf("STCE frame = %x, want %x", encoded, expected)
	}
	decoded, err := decodePublicTransferClusterEvent(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.kind != vector.Kind || decoded.revision != vector.Revision ||
		decoded.groupID != vector.GroupID || decoded.targetPeerID != vector.TargetPeerID ||
		decoded.sourceLeaseID != vector.SourceLeaseID || !bytes.Equal(decoded.payload, []byte(vector.PayloadUTF8)) {
		t.Fatalf("decoded STCE event mismatch: %+v", decoded)
	}
	derivation := vectors.GroupIDDerivation
	if actual := publicTransferGroupID(derivation.RoomID, derivation.RoomKey); actual != derivation.GroupID {
		t.Fatalf("group id = %s, want %s", actual, derivation.GroupID)
	}
	if _, err := decodePublicTransferClusterEvent(append(encoded, 0)); err == nil {
		t.Fatal("STCE decoder accepted trailing byte")
	}
	management := vectors.CanonicalManagement
	managementEncoded, err := encodePublicTransferClusterEvent(publicTransferClusterEvent{
		kind: management.Kind, excludeSource: management.ExcludeSource,
		revision: management.Revision, groupID: management.GroupID,
		targetPeerID: management.TargetPeerID, sourceLeaseID: management.SourceLeaseID,
		payload: []byte(management.PayloadUTF8),
	})
	if err != nil {
		t.Fatal(err)
	}
	managementExpected, err := hex.DecodeString(management.FrameHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(managementEncoded, managementExpected) {
		t.Fatalf("management STCE frame = %x, want %x", managementEncoded, managementExpected)
	}
	if managementGroupID(management.TenantID) != management.GroupID {
		t.Fatalf("management group id does not bind tenant %q", management.TenantID)
	}
	if _, err := encodePublicTransferClusterEvent(publicTransferClusterEvent{
		kind: clusterEventKindManagement, groupID: management.GroupID,
		targetPeerID: "unexpected-target", payload: []byte(management.PayloadUTF8),
	}); err == nil {
		t.Fatal("management STCE accepted a target identity")
	}
}

func TestDiscoveryParticipantViewPreservesRoomRole(t *testing.T) {
	owner := discoveryParticipant{peerID: "owner", roomRole: "OWNER", connectedAt: time.Now()}
	if got := discoveryParticipantView(owner)["roomRole"]; got != "OWNER" {
		t.Fatalf("owner roomRole = %#v, want OWNER", got)
	}
	editor := discoveryParticipant{peerID: "editor", connectedAt: time.Now()}
	if got := discoveryParticipantView(editor)["roomRole"]; got != "EDITOR" {
		t.Fatalf("default roomRole = %#v, want EDITOR", got)
	}
}

func TestPublicTransferDiscoveryIsolationRosterAndTargetedSignal(t *testing.T) {
	server, tickets := newDiscoveryTestServer(t, config.PublicTransferConfig{
		MaxDiscoveryPeersPerRoom:               2,
		DiscoveryMessageRateLimitPerConnection: 10,
		DiscoveryMessageRateLimitWindowSeconds: 60,
	})
	a := dialDiscovery(t, discoveryTicketURL(t, server.URL, tickets, "room-a", "shared-secret", "a", "198.51.100.1"), "198.51.100.1")
	defer a.Close(websocket.StatusNormalClosure, "bye")
	readDiscoveryType(t, a, "hello")
	readDiscoveryType(t, a, "roster")

	b := dialDiscovery(t, discoveryTicketURL(t, server.URL, tickets, "room-a", "shared-secret", "b", "203.0.113.2"), "203.0.113.2")
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

	appFrame := publicTransferTestAppFrame(2, []byte("clipboard"))
	if err := a.Write(context.Background(), websocket.MessageBinary,
		publicTransferTestClientRelay("b", appFrame)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	messageType, binaryPayload, err := b.Read(ctx)
	if err != nil || messageType != websocket.MessageBinary {
		t.Fatalf("read binary relay: type=%v err=%v", messageType, err)
	}
	expected, err := encodePublicRelayServerFrame("b", "a", appFrame)
	if err != nil || !bytes.Equal(binaryPayload, expected) {
		t.Fatalf("binary relay mismatch: err=%v payload=%x expected=%x", err, binaryPayload, expected)
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

	third := dialDiscovery(t, discoveryTicketURL(t, server.URL, tickets, "room-a", "shared-secret", "c", "192.0.2.3"), "192.0.2.3")
	defer third.Close(websocket.StatusNormalClosure, "bye")
	errorMessage := readDiscoveryType(t, third, "error")
	if errorMessage["error"] != "room is full" {
		t.Fatalf("unexpected room-full error: %#v", errorMessage)
	}

	isolated := dialDiscovery(t, discoveryTicketURL(t, server.URL, tickets, "room-a", "", "isolated", "192.0.2.99"), "192.0.2.99")
	defer isolated.Close(websocket.StatusNormalClosure, "bye")
	readDiscoveryType(t, isolated, "hello")
	isolatedRoster := readDiscoveryType(t, isolated, "roster")
	if got := len(isolatedRoster["peers"].([]any)); got != 1 {
		t.Fatalf("public-IP room leaked peers: %d", got)
	}
}

func TestPublicTransferDiscoveryRejectsDuplicatePeerIDInSameGroup(t *testing.T) {
	server, tickets := newDiscoveryTestServer(t, config.PublicTransferConfig{
		MaxDiscoveryPeersPerRoom:               4,
		DiscoveryMessageRateLimitPerConnection: 10,
		DiscoveryMessageRateLimitWindowSeconds: 60,
	})
	first := dialDiscovery(t, discoveryTicketURL(t, server.URL, tickets, "duplicate-room", "secret", "reused", "198.51.100.1"), "198.51.100.1")
	defer first.CloseNow()
	readDiscoveryType(t, first, "hello")
	readDiscoveryType(t, first, "roster")

	duplicate := dialDiscovery(t, discoveryTicketURL(t, server.URL, tickets, "duplicate-room", "secret", "reused", "203.0.113.2"), "203.0.113.2")
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

	otherGroup := dialDiscovery(t, discoveryTicketURLWithDisplayName(t, server.URL, tickets,
		"duplicate-room", "secret-other", "reused", "reused-other-room", "192.0.2.3"), "192.0.2.3")
	defer otherGroup.CloseNow()
	readDiscoveryType(t, otherGroup, "hello")
	readDiscoveryType(t, otherGroup, "roster")
}

func TestPublicTransferDiscoveryRateLimitAndTrustedAddress(t *testing.T) {
	server, tickets := newDiscoveryTestServer(t, config.PublicTransferConfig{
		MaxDiscoveryPeersPerRoom:               4,
		DiscoveryMessageRateLimitPerConnection: 1,
		DiscoveryMessageRateLimitWindowSeconds: 60,
	})
	wsURL := discoveryTicketURL(t, server.URL, tickets, "nearby", "", "a", "203.0.113.8")
	conn := dialDiscoveryWithHeaders(t, wsURL, http.Header{
		"X-Forwarded-For": []string{"198.51.100.7, 203.0.113.8"},
	})
	defer conn.Close(websocket.StatusNormalClosure, "bye")
	hello := readDiscoveryType(t, conn, "hello")
	if hello["publicAddress"] != "203.0.113.8" {
		t.Fatalf("trusted XFF last hop not used: %#v", hello)
	}
	if hello["roomRole"] != "EDITOR" {
		t.Fatalf("hello roomRole = %#v, want EDITOR", hello["roomRole"])
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

func TestDiscoveryTicketValueTruncationIsUTF8SafeAndUsesJavaLength(t *testing.T) {
	value := truncateUTF16(strings.Repeat("中", 121), 120)
	if len([]rune(value)) != 120 || !json.Valid([]byte(`"`+value+`"`)) {
		t.Fatalf("BMP value was not truncated safely: runes=%d value=%q", len([]rune(value)), value)
	}
	value = truncateUTF16(strings.Repeat("😀", 61), 120)
	if len([]rune(value)) != 60 {
		t.Fatalf("UTF-16 surrogate-pair limit mismatch: runes=%d", len([]rune(value)))
	}
}

func TestPublicTransferDiscoveryAcceptsJavaSizedMultibyteTextAndRejectsMalformedBinary(t *testing.T) {
	server, tickets := newDiscoveryTestServer(t, config.PublicTransferConfig{
		MaxDiscoveryPeersPerRoom:               2,
		DiscoveryMessageRateLimitPerConnection: 10,
		DiscoveryMessageRateLimitWindowSeconds: 60,
	})
	wsURL := discoveryTicketURL(t, server.URL, tickets, "nearby", "", "utf8", "192.0.2.20")
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
	invalid := readDiscoveryType(t, conn, "error")
	if invalid["error"] != "invalid binary relay frame" {
		t.Fatalf("unexpected binary error: %#v", invalid)
	}
	_, _, err := conn.Read(ctx)
	if status := websocket.CloseStatus(err); status != websocket.StatusPolicyViolation {
		t.Fatalf("binary close status = %d err=%v, want %d", status, err, websocket.StatusPolicyViolation)
	}
}

func TestPublicTransferRelayRejectsSpoofedSourceAndTrailingBytes(t *testing.T) {
	app := publicTransferTestAppFrame(1, []byte{1})
	serverFrame, err := encodePublicRelayServerFrame("target", "spoofed", app)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodePublicRelayClientFrame(serverFrame); err == nil {
		t.Fatal("client relay accepted a caller-supplied source")
	}
	app = append(app, 0)
	if _, err := decodePublicRelayClientFrame(publicTransferTestClientRelay("target", app)); err == nil {
		t.Fatal("client relay accepted trailing app bytes")
	}
}

func TestPublicTransferDiscoveryRejectsMissingAndReusedTicket(t *testing.T) {
	server, tickets := newDiscoveryTestServer(t, config.PublicTransferConfig{MaxDiscoveryPeersPerRoom: 2})
	baseURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, response, err := websocket.Dial(ctx, baseURL+"?roomId=legacy&roomToken=legacy", nil)
	if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("legacy query was not rejected: response=%v err=%v", response, err)
	}
	issuedURL := discoveryTicketURL(t, server.URL, tickets, "nearby", "", "once", "192.0.2.44")
	first := dialDiscovery(t, issuedURL, "192.0.2.44")
	readDiscoveryType(t, first, "hello")
	readDiscoveryType(t, first, "roster")
	_ = first.Close(websocket.StatusNormalClosure, "bye")
	_, response, err = websocket.Dial(ctx, issuedURL, &websocket.DialOptions{HTTPHeader: http.Header{"X-Real-IP": []string{"192.0.2.44"}}})
	if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("reused ticket was not rejected: response=%v err=%v", response, err)
	}
}

func newDiscoveryTestServer(t *testing.T, cfg config.PublicTransferConfig) (*httptest.Server, *security.WebSocketTicketService) {
	t.Helper()
	db, err := store.Open("sqlite", t.TempDir()+"/discovery.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	tickets := security.NewWebSocketTicketService(db)
	server := httptest.NewServer(newPublicTransferDiscoveryHub(cfg, tickets))
	t.Cleanup(server.Close)
	return server, tickets
}

func discoveryTicketURL(t *testing.T, serverURL string, tickets *security.WebSocketTicketService,
	roomID, roomToken, peerID, remoteAddress string) string {
	t.Helper()
	return discoveryTicketURLWithDisplayName(t, serverURL, tickets,
		roomID, roomToken, peerID, peerID, remoteAddress)
}

func discoveryTicketURLWithDisplayName(t *testing.T, serverURL string, tickets *security.WebSocketTicketService,
	roomID, roomToken, peerID, displayName, remoteAddress string) string {
	t.Helper()
	claims := security.WebSocketTicketClaims{RoomID: roomID, PeerID: peerID, DisplayName: displayName}
	if roomToken != "" {
		digest := sha256.Sum256([]byte(roomToken))
		claims.SharedRoom = true
		claims.RoomKey = "token:" + hex.EncodeToString(digest[:])
	}
	issued, err := tickets.Issue(context.Background(), security.WebSocketScopePublicTransfer, remoteAddress, claims)
	if err != nil {
		t.Fatal(err)
	}
	return "ws" + strings.TrimPrefix(serverURL, "http") + "/?ticket=" + url.QueryEscape(issued.Ticket)
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

func publicTransferTestClientRelay(targetPeerID string, appFrame []byte) []byte {
	target := []byte(targetPeerID)
	result := make([]byte, publicRelayHeaderBytes+len(target)+len(appFrame))
	copy(result[:4], "STWR")
	result[4] = 2
	binary.BigEndian.PutUint16(result[6:8], uint16(len(target)))
	binary.BigEndian.PutUint32(result[10:14], uint32(len(appFrame)))
	copy(result[publicRelayHeaderBytes:], target)
	copy(result[publicRelayHeaderBytes+len(target):], appFrame)
	return result
}

func publicTransferTestAppFrame(appType byte, payload []byte) []byte {
	result := make([]byte, publicAppHeaderBytes+len(payload))
	copy(result[:4], "STAP")
	result[4] = 2
	result[5] = appType
	binary.BigEndian.PutUint32(result[28:32], 1)
	binary.BigEndian.PutUint32(result[32:36], uint32(len(payload)))
	binary.BigEndian.PutUint32(result[36:40], uint32(len(payload)))
	copy(result[publicAppHeaderBytes:], payload)
	return result
}
