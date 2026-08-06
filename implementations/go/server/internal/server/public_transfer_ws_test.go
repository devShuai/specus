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
	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
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
	recipient := discoveryParticipant{peerID: "recipient", roomKey: "room:1", connectedAt: time.Now()}
	owner := discoveryParticipant{peerID: "owner", roomKey: "room:1", roomRole: "OWNER", connectedAt: time.Now()}
	view := discoveryParticipantView(owner, recipient)
	if got := view["roomRole"]; got != "OWNER" {
		t.Fatalf("owner roomRole = %#v, want OWNER", got)
	}
	if got := view["sameRoom"]; got != true {
		t.Fatalf("same-room peer sameRoom = %#v, want true", got)
	}
	editor := discoveryParticipant{peerID: "editor", roomKey: "room:2", connectedAt: time.Now()}
	editorView := discoveryParticipantView(editor, recipient)
	if got := editorView["roomRole"]; got != "EDITOR" {
		t.Fatalf("default roomRole = %#v, want EDITOR", got)
	}
	if got := editorView["sameRoom"]; got != false {
		t.Fatalf("net-only peer sameRoom = %#v, want false", got)
	}
}

func TestDiscoveryParticipantSameNetAndNetID(t *testing.T) {
	base := discoveryParticipant{roomID: "room", publicAddress: "203.0.113.7", roomKey: "room:1"}
	sameNetPeer := discoveryParticipant{roomID: "room", publicAddress: "203.0.113.7", roomKey: "room:2"}
	if !base.sameNet(sameNetPeer) || !base.sameScope(sameNetPeer) || base.sameGroup(sameNetPeer) {
		t.Fatal("same publicAddress across roomKeys must be sameNet but not sameGroup")
	}
	otherAddress := discoveryParticipant{roomID: "room", publicAddress: "198.51.100.9", roomKey: "room:1"}
	if base.sameNet(otherAddress) || !base.sameGroup(otherAddress) || !base.sameScope(otherAddress) {
		t.Fatal("same roomKey across public addresses must stay visible through sameGroup")
	}
	// Same egress address links devices across different roomIDs: renaming or recreating
	// a room must not hide same-net peers.
	otherRoom := discoveryParticipant{roomID: "other", publicAddress: "203.0.113.7", roomKey: "room:9"}
	if !base.sameNet(otherRoom) || !base.sameScope(otherRoom) || base.sameGroup(otherRoom) {
		t.Fatal("same publicAddress across roomIDs must be sameNet but not sameGroup")
	}
	stranger := discoveryParticipant{roomID: "other", publicAddress: "198.51.100.9", roomKey: "room:1"}
	if base.sameScope(stranger) {
		t.Fatal("different roomID and different publicAddress must stay invisible")
	}
	// The "unknown"/empty fallback address must never group clients into a net...
	unknownA := discoveryParticipant{roomID: "room", publicAddress: "unknown", roomKey: "room:1"}
	unknownB := discoveryParticipant{roomID: "room", publicAddress: "unknown", roomKey: "room:2"}
	if unknownA.sameNet(unknownB) || unknownA.sameScope(unknownB) {
		t.Fatal("the unknown fallback address must not form a net")
	}
	emptyA := discoveryParticipant{roomID: "room", publicAddress: "", roomKey: "room:1"}
	emptyB := discoveryParticipant{roomID: "room", publicAddress: "", roomKey: "room:2"}
	if emptyA.sameNet(emptyB) || emptyA.sameScope(emptyB) {
		t.Fatal("an empty public address must not form a net")
	}
	// ...but same-group visibility does not depend on the address at all.
	unknownRoommate := discoveryParticipant{roomID: "room", publicAddress: "unknown", roomKey: "room:1"}
	if unknownA.sameNet(unknownRoommate) || !unknownA.sameGroup(unknownRoommate) || !unknownA.sameScope(unknownRoommate) {
		t.Fatal("sameGroup must stay visible with an unusable public address")
	}
	if got, want := base.netID(), digestString("203.0.113.7"); got != want {
		t.Fatalf("netID = %s, want %s", got, want)
	}
	if base.netID() == base.groupID() {
		t.Fatal("netID and groupID must derive from different inputs")
	}
	if got := publicTransferNetID("203.0.113.7"); got != base.netID() {
		t.Fatalf("publicTransferNetID = %s, want %s", got, base.netID())
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
	return discoveryTicketURLWithClaims(t, serverURL, tickets,
		roomID, roomToken, peerID, displayName, remoteAddress, true)
}

func discoveryTicketURLWithClaims(t *testing.T, serverURL string, tickets *security.WebSocketTicketService,
	roomID, roomToken, peerID, displayName, remoteAddress string, discoverable bool) string {
	t.Helper()
	claims := security.WebSocketTicketClaims{RoomID: roomID, PeerID: peerID, DisplayName: displayName,
		Discoverable: discoverable}
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

// readRosterUntil reads messages until a roster whose peer set (peerID -> sameRoom)
// exactly matches want arrives. Intermediate rosters from earlier broadcasts are
// skipped. Note: a read timeout closes a coder/websocket connection, so this must only
// be used when a matching roster is guaranteed to arrive in time.
func readRosterUntil(t *testing.T, conn *websocket.Conn, want map[string]bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Until(deadline))
		messageType, payload, err := conn.Read(ctx)
		cancel()
		if err != nil {
			t.Fatalf("roster with peers %v never arrived: %v", want, err)
		}
		if messageType != websocket.MessageText {
			continue
		}
		var value map[string]any
		if json.Unmarshal(payload, &value) != nil || value["type"] != "roster" {
			continue
		}
		if rosterPeersMatch(value, want) {
			return value
		}
	}
}

func rosterPeersMatch(roster map[string]any, want map[string]bool) bool {
	peers, ok := roster["peers"].([]any)
	if !ok || len(peers) != len(want) {
		return false
	}
	for _, item := range peers {
		peer, ok := item.(map[string]any)
		if !ok {
			return false
		}
		peerID, _ := peer["peerId"].(string)
		sameRoom, _ := peer["sameRoom"].(bool)
		wantSameRoom, ok := want[peerID]
		if !ok || wantSameRoom != sameRoom {
			return false
		}
	}
	return true
}

// expectNoDiscoveryMessage asserts the connection stays silent for wait. Beware: the
// timing-out read closes the websocket connection, so only use this at the end of a test.
func expectNoDiscoveryMessage(t *testing.T, conn *websocket.Conn, wait time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	messageType, payload, err := conn.Read(ctx)
	if err == nil {
		t.Fatalf("expected silence, got type=%v payload=%s", messageType, payload)
	}
}

func TestPublicTransferDiscoveryMergesNetRosterAcrossGroups(t *testing.T) {
	server, tickets := newDiscoveryTestServer(t, config.PublicTransferConfig{
		MaxDiscoveryPeersPerRoom:               8,
		DiscoveryMessageRateLimitPerConnection: 10,
		DiscoveryMessageRateLimitWindowSeconds: 60,
	})
	const ipX, ipY = "203.0.113.10", "198.51.100.10"
	dial := func(roomID, token, peerID, ip string) *websocket.Conn {
		conn := dialDiscovery(t, discoveryTicketURL(t, server.URL, tickets, roomID, token, peerID, ip), ip)
		readDiscoveryType(t, conn, "hello")
		return conn
	}
	a := dial("room-m", "token-one", "a", ipX) // group one, net X
	b := dial("room-n", "token-two", "b", ipX) // other roomID and token, net X (net-only peer of a)
	c := dial("room-m", "token-one", "c", ipX) // group one, net X (roommate of a)
	d := dial("room-m", "token-one", "d", ipY) // group one, net Y (remote roommate of a)
	e := dial("room-o", "", "e", ipY)          // other roomID, no token, net Y (net-only peer of d)
	defer a.CloseNow()
	defer b.CloseNow()
	defer c.CloseNow()
	defer d.CloseNow()
	defer e.CloseNow()

	rosters := map[*websocket.Conn]map[string]any{}
	rosters[a] = readRosterUntil(t, a, map[string]bool{"a": true, "b": false, "c": true, "d": true})
	rosters[c] = readRosterUntil(t, c, map[string]bool{"a": true, "b": false, "c": true, "d": true})
	// b shares no room with anyone; only net-X mates are visible (d/e are remote to b).
	rosters[b] = readRosterUntil(t, b, map[string]bool{"a": false, "b": true, "c": false})
	// d sees its roommates a/c across nets plus net-Y mate e; never b.
	rosters[d] = readRosterUntil(t, d, map[string]bool{"a": true, "c": true, "d": true, "e": false})
	// e is roomless: only the net-Y roommate d is visible.
	rosters[e] = readRosterUntil(t, e, map[string]bool{"d": false, "e": true})
}

func TestPublicTransferDiscoveryTargetedSignalCrossesGroupsWithinNet(t *testing.T) {
	server, tickets := newDiscoveryTestServer(t, config.PublicTransferConfig{
		MaxDiscoveryPeersPerRoom:               8,
		DiscoveryMessageRateLimitPerConnection: 10,
		DiscoveryMessageRateLimitWindowSeconds: 60,
	})
	const ipX, ipY = "203.0.113.11", "198.51.100.11"
	dial := func(roomID, token, peerID, ip string) *websocket.Conn {
		conn := dialDiscovery(t, discoveryTicketURL(t, server.URL, tickets, roomID, token, peerID, ip), ip)
		readDiscoveryType(t, conn, "hello")
		return conn
	}
	a := dial("room-s", "token-one", "a", ipX)
	b := dial("room-t", "token-two", "b", ipX) // different roomID and token, same net
	c := dial("room-s", "token-one", "c", ipX)
	d := dial("room-s", "token-one", "d", ipY)
	defer a.CloseNow()
	defer b.CloseNow()
	defer c.CloseNow()
	defer d.CloseNow()
	// Synchronize on the final rosters so all joins are fully processed before signaling.
	readRosterUntil(t, a, map[string]bool{"a": true, "b": false, "c": true, "d": true})
	readRosterUntil(t, b, map[string]bool{"a": false, "b": true, "c": false})
	readRosterUntil(t, c, map[string]bool{"a": true, "b": false, "c": true, "d": true})
	readRosterUntil(t, d, map[string]bool{"a": true, "c": true, "d": true})

	// Targeted signal reaches a same-net peer in another room (different roomID and
	// token room), both ways.
	if err := a.Write(context.Background(), websocket.MessageText,
		[]byte(`{"type":"offer","targetPeerId":"b","payload":{"sdp":"x"}}`)); err != nil {
		t.Fatal(err)
	}
	offer := readDiscoveryType(t, b, "offer")
	if offer["sourcePeerId"] != "a" || offer["targetPeerId"] != "b" {
		t.Fatalf("unexpected cross-group offer: %#v", offer)
	}
	if err := b.Write(context.Background(), websocket.MessageText,
		[]byte(`{"type":"answer","targetPeerId":"a","payload":{"sdp":"y"}}`)); err != nil {
		t.Fatal(err)
	}
	readDiscoveryType(t, a, "answer")

	// Binary relay also reaches across groups within the net.
	appFrame := publicTransferTestAppFrame(2, []byte("file-part"))
	if err := a.Write(context.Background(), websocket.MessageBinary,
		publicTransferTestClientRelay("b", appFrame)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	messageType, payload, err := b.Read(ctx)
	cancel()
	if err != nil || messageType != websocket.MessageBinary {
		t.Fatalf("read cross-group binary relay: type=%v err=%v", messageType, err)
	}
	expected, err := encodePublicRelayServerFrame("b", "a", appFrame)
	if err != nil || !bytes.Equal(payload, expected) {
		t.Fatalf("cross-group binary relay mismatch: err=%v", err)
	}

	// Untargeted broadcast stays group-scoped: roommates c (same net) and d (remote)
	// receive it, net-only peer b does not. The silence check runs last because the
	// timing-out read closes b's connection.
	if err := a.Write(context.Background(), websocket.MessageText,
		[]byte(`{"type":"clipboard","payload":{"text":"hello"}}`)); err != nil {
		t.Fatal(err)
	}
	readDiscoveryType(t, c, "clipboard")
	readDiscoveryType(t, d, "clipboard")
	expectNoDiscoveryMessage(t, b, 400*time.Millisecond)
}

func TestPublicTransferDiscoveryRejectsDuplicatePeerIDAcrossNet(t *testing.T) {
	server, tickets := newDiscoveryTestServer(t, config.PublicTransferConfig{
		MaxDiscoveryPeersPerRoom:               4,
		DiscoveryMessageRateLimitPerConnection: 10,
		DiscoveryMessageRateLimitWindowSeconds: 60,
	})
	const ipX = "203.0.113.12"
	first := dialDiscovery(t, discoveryTicketURL(t, server.URL, tickets, "room-d", "token-one", "dup", ipX), ipX)
	defer first.CloseNow()
	readDiscoveryType(t, first, "hello")

	// Same peerID in a different token room but on the same net now collides.
	duplicate := dialDiscovery(t, discoveryTicketURL(t, server.URL, tickets, "room-d", "token-two", "dup", ipX), ipX)
	defer duplicate.CloseNow()
	errorMessage := readDiscoveryType(t, duplicate, "error")
	if errorMessage["error"] != "peer id is already connected" {
		t.Fatalf("unexpected duplicate-peer error: %#v", errorMessage)
	}

	// The same peerID on a different net stays allowed.
	remote := dialDiscovery(t, discoveryTicketURLWithDisplayName(t, server.URL, tickets,
		"room-d", "token-two", "dup", "dup-remote", "198.51.100.12"), "198.51.100.12")
	defer remote.CloseNow()
	readDiscoveryType(t, remote, "hello")
}

func TestPublicTransferDiscoveryHiddenParticipantStaysOutOfRoster(t *testing.T) {
	server, tickets := newDiscoveryTestServer(t, config.PublicTransferConfig{
		MaxDiscoveryPeersPerRoom:               4,
		DiscoveryMessageRateLimitPerConnection: 10,
		DiscoveryMessageRateLimitWindowSeconds: 60,
	})
	const ipX = "203.0.113.13"
	a := dialDiscovery(t, discoveryTicketURL(t, server.URL, tickets, "room-h", "token-one", "a", ipX), ipX)
	defer a.CloseNow()
	readDiscoveryType(t, a, "hello")

	hidden := dialDiscovery(t, discoveryTicketURLWithClaims(t, server.URL, tickets,
		"room-h", "token-two", "ghost", "ghost", ipX, false), ipX)
	defer hidden.CloseNow()
	hello := readDiscoveryType(t, hidden, "hello")
	if hello["rosterRevision"] != float64(0) {
		t.Fatalf("hidden hello rosterRevision = %#v, want 0", hello["rosterRevision"])
	}

	// The hidden peer is nowhere in the visible peer's roster.
	readRosterUntil(t, a, map[string]bool{"a": true})
	// ...but still receives rosters itself and sees discoverable net-mates.
	readRosterUntil(t, hidden, map[string]bool{"a": false})
	// Drain the second roster a received from the hidden peer's join broadcast.
	readRosterUntil(t, a, map[string]bool{"a": true})

	// A hidden peer may still initiate and receive targeted signaling (Java parity).
	if err := hidden.Write(context.Background(), websocket.MessageText,
		[]byte(`{"type":"offer","targetPeerId":"a","payload":{"sdp":"h"}}`)); err != nil {
		t.Fatal(err)
	}
	offer := readDiscoveryType(t, a, "offer")
	if offer["sourcePeerId"] != "ghost" {
		t.Fatalf("unexpected hidden offer: %#v", offer)
	}
	if err := a.Write(context.Background(), websocket.MessageText,
		[]byte(`{"type":"answer","targetPeerId":"ghost","payload":{"sdp":"a"}}`)); err != nil {
		t.Fatal(err)
	}
	readDiscoveryType(t, hidden, "answer")
}

func TestPublicTransferDiscoveryUnknownAddressNeverFormsNet(t *testing.T) {
	server, tickets := newDiscoveryTestServer(t, config.PublicTransferConfig{
		MaxDiscoveryPeersPerRoom:               8,
		DiscoveryMessageRateLimitPerConnection: 10,
		DiscoveryMessageRateLimitWindowSeconds: 60,
	})
	// X-Real-IP "unknown" stands in for trustedClientIP's no-usable-address fallback.
	dial := func(token, peerID string) *websocket.Conn {
		conn := dialDiscovery(t, discoveryTicketURL(t, server.URL, tickets, "room-u", token, peerID, "unknown"), "unknown")
		readDiscoveryType(t, conn, "hello")
		return conn
	}
	u1 := dial("token-one", "u1")
	u2 := dial("token-two", "u2") // same "unknown" address, other token room: must stay invisible
	u3 := dial("token-one", "u3") // same token room: visible through sameGroup despite the address
	defer u1.CloseNow()
	defer u2.CloseNow()
	defer u3.CloseNow()

	readRosterUntil(t, u1, map[string]bool{"u1": true, "u3": true})
	readRosterUntil(t, u2, map[string]bool{"u2": true})
	readRosterUntil(t, u3, map[string]bool{"u1": true, "u3": true})
}
