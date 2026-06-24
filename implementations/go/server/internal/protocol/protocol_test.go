package protocol

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "fixtures", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// decodeFixture decodes a golden frame and (when byteExact) asserts re-encoding reproduces it.
func decodeFixture(t *testing.T, name string, byteExact bool) Packet {
	t.Helper()
	raw := readFixture(t, name)
	packet, consumed, err := DecodeFrame(raw)
	if err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	if consumed != len(raw) {
		t.Fatalf("%s: consumed %d of %d bytes", name, consumed, len(raw))
	}
	if byteExact {
		encoded, err := EncodeFrame(packet)
		if err != nil {
			t.Fatalf("re-encode %s: %v", name, err)
		}
		if !bytes.Equal(raw, encoded) {
			t.Fatalf("%s: re-encoded bytes differ\n want %x\n got  %x", name, raw, encoded)
		}
	} else {
		// Deflate-compressed fixtures cannot match byte-for-byte (Go's compress/flate emits
		// different bytes than Java/.NET zlib) but inflate identically, so they interoperate.
		// Verify Go's own encode->decode is lossless instead.
		encoded, err := EncodeFrame(packet)
		if err != nil {
			t.Fatalf("re-encode %s: %v", name, err)
		}
		roundtripped, _, err := DecodeFrame(encoded)
		if err != nil {
			t.Fatalf("self round-trip decode %s: %v", name, err)
		}
		if !reflect.DeepEqual(packet, roundtripped) {
			t.Fatalf("%s: self round-trip mismatch\n want %+v\n got  %+v", name, packet, roundtripped)
		}
	}
	return packet
}

func TestLoginRequestFixture(t *testing.T) {
	if _, _, err := DecodeFrame(readFixture(t, "login_request.bin")); err == nil {
		t.Fatal("legacy signed login fixture should be rejected")
	}
	packet := LoginRequest{ClientName: "Demo client", ClientSessionID: 42, AccessToken: "token"}
	encoded, err := EncodeFrame(packet)
	if err != nil {
		t.Fatalf("encode current login: %v", err)
	}
	decoded, consumed, err := DecodeFrame(encoded)
	if err != nil {
		t.Fatalf("decode current login: %v", err)
	}
	if consumed != len(encoded) {
		t.Fatalf("consumed %d of %d bytes", consumed, len(encoded))
	}
	got := decoded.(LoginRequest)
	if got != packet {
		t.Fatalf("current login roundtrip = %+v, want %+v", got, packet)
	}
}

func TestLoginResponseFixtures(t *testing.T) {
	ok := decodeFixture(t, "login_response.bin", true).(LoginResponse)
	if ok.ClientName != "Demo client" || !ok.Success || ok.Reason != nil {
		t.Fatalf("unexpected success response: %+v", ok)
	}
	fail := decodeFixture(t, "login_response_fail.bin", true).(LoginResponse)
	if fail.Success || fail.Reason == nil || *fail.Reason != "时间戳过期" {
		t.Fatalf("unexpected failure response: %+v", fail)
	}
}

func TestLogoutFixtures(t *testing.T) {
	decodeFixture(t, "logout_request.bin", true)
	resp := decodeFixture(t, "logout_response.bin", true).(LogoutResponse)
	if !resp.Success || resp.Reason != nil {
		t.Fatalf("unexpected logout response: %+v", resp)
	}
}

func TestHeartbeatFixtures(t *testing.T) {
	decodeFixture(t, "heartbeat_request.bin", true)
	decodeFixture(t, "heartbeat_response.bin", true)
}

func TestMessageRequestFixture(t *testing.T) {
	packet := decodeFixture(t, "message_request.bin", true).(MessageRequest)
	if packet.ClientName != "Demo client" || packet.ToClientName != "admin" ||
		packet.MessageType != MessageTypeClientToServer || packet.Message != "hello, server" {
		t.Fatalf("unexpected message request: %+v", packet)
	}
}

func TestMessageResponseFixture(t *testing.T) {
	packet := decodeFixture(t, "message_response.bin", false).(MessageResponse)
	if packet.ClientName != "admin" || packet.ToClientName != "Demo client" ||
		packet.MessageType != MessageTypeNatControl ||
		packet.Message != `{"clientName":"Demo client","remotePort":7010}` {
		t.Fatalf("unexpected message response: %+v", packet)
	}
}

func TestHTTPRequestFixture(t *testing.T) {
	// Decode-only: header/param maps have no stable byte order across encoders.
	packet := decodeFixture(t, "http_request.bin", false).(HTTPRequest)
	if packet.ClientName != "Demo client" || packet.ToClientName != "upstream" ||
		packet.RequestID != "123e4567-e89b-12d3-a456-426614174000" || packet.RequestMethod != "POST" ||
		packet.RequestURL != "http://127.0.0.1:8080/api/demo" || packet.Body != `{"hello":"world"}` {
		t.Fatalf("unexpected http request: %+v", packet)
	}
	if packet.HeaderMap["Content-Type"] != "application/json" || packet.HeaderMap["X-Request-Id"] != "fixture-1" {
		t.Fatalf("unexpected header map: %+v", packet.HeaderMap)
	}
	if packet.ParamMap["limit"] != "10" {
		t.Fatalf("unexpected param map: %+v", packet.ParamMap)
	}
}

func TestHTTPResponseFixture(t *testing.T) {
	packet := decodeFixture(t, "http_response.bin", true).(HTTPResponse)
	if packet.ClientName != "upstream" || packet.ToClientName != "Demo client" ||
		packet.RequestID != "123e4567-e89b-12d3-a456-426614174000" || packet.Response != `{"ok":true}` {
		t.Fatalf("unexpected http response: %+v", packet)
	}
}

func TestDirectHTTPRequestFixture(t *testing.T) {
	packet := decodeFixture(t, "direct_http_request.bin", false).(DirectHTTPRequest)
	if packet.RequestID != "11111111-2222-3333-4444-555555555555" || packet.RequestMethod != "GET" ||
		packet.Route != "api" || packet.RelativePath != "/v1/items" || packet.RawQuery != "limit=10&page=1" {
		t.Fatalf("unexpected direct http request: %+v", packet)
	}
	if len(packet.Headers) != 2 || packet.Headers[0] != "accept: application/json" || packet.Headers[1] != "x-fixture: 1" {
		t.Fatalf("unexpected headers: %+v", packet.Headers)
	}
	if len(packet.Body) != 0 {
		t.Fatalf("body should be empty, got %d bytes", len(packet.Body))
	}
}

func TestDirectHTTPResponseFixture(t *testing.T) {
	packet := decodeFixture(t, "direct_http_response.bin", false).(DirectHTTPResponse)
	if packet.RequestID != "11111111-2222-3333-4444-555555555555" || packet.StatusCode != 200 {
		t.Fatalf("unexpected direct http response: %+v", packet)
	}
	if len(packet.Headers) != 1 || packet.Headers[0] != "content-type: application/json" {
		t.Fatalf("unexpected headers: %+v", packet.Headers)
	}
	if string(packet.Body) != `{"ok":true}` || packet.Error != nil {
		t.Fatalf("unexpected body/error: %q / %v", packet.Body, packet.Error)
	}
}

func TestNatFixtures(t *testing.T) {
	reg := decodeFixture(t, "nat_register.bin", true).(NatMessage)
	if reg.Type != NatRegister || reg.Metadata["clientName"] != "Demo client" ||
		reg.Metadata["port"].(float64) != 18080 || reg.Metadata["tunnelAddress"] != "127.0.0.1" ||
		reg.Metadata["tunnelPort"].(float64) != 80 || reg.Data != nil {
		t.Fatalf("unexpected register: %+v", reg)
	}

	res := decodeFixture(t, "nat_register_result.bin", true).(NatMessage)
	if res.Type != NatRegisterResult || res.Metadata["port"].(float64) != 18080 || res.Metadata["success"] != true {
		t.Fatalf("unexpected register result: %+v", res)
	}

	conn := decodeFixture(t, "nat_connected.bin", true).(NatMessage)
	if conn.Type != NatConnected || conn.Metadata["channelId"] != "00010203-aaaa-bbbb-cccc-ddddeeeeffff" {
		t.Fatalf("unexpected connected: %+v", conn)
	}

	disc := decodeFixture(t, "nat_disconnected.bin", true).(NatMessage)
	if disc.Type != NatDisconnected || disc.Metadata["channelId"] != "00010203-aaaa-bbbb-cccc-ddddeeeeffff" {
		t.Fatalf("unexpected disconnected: %+v", disc)
	}

	ka := decodeFixture(t, "nat_keepalive.bin", true).(NatMessage)
	if ka.Type != NatKeepalive || ka.Metadata == nil || len(ka.Metadata) != 0 {
		t.Fatalf("unexpected keepalive: %+v", ka)
	}

	unreg := decodeFixture(t, "nat_unregister.bin", true).(NatMessage)
	if unreg.Type != NatUnregister || unreg.Metadata["port"].(float64) != 18080 {
		t.Fatalf("unexpected unregister: %+v", unreg)
	}

	small := decodeFixture(t, "nat_data_small.bin", true).(NatMessage)
	if small.Type != NatData || string(small.Data) != "hello" {
		t.Fatalf("unexpected small data: %+v", small)
	}

	// Deflated DATA: decode-only (Go flate vs Java Deflater emit different bytes).
	large := decodeFixture(t, "nat_data_large_deflated.bin", false).(NatMessage)
	if large.Type != NatData || len(large.Data) != 256 {
		t.Fatalf("unexpected large data length: %d", len(large.Data))
	}
	for i, b := range large.Data {
		if b != 'A' {
			t.Fatalf("large data[%d] = %d, want 'A'", i, b)
		}
	}
}

func TestLargeDataSelfRoundtrip(t *testing.T) {
	payload := bytes.Repeat([]byte("A"), 256)
	msg := NatMessage{Type: NatData, Metadata: map[string]any{"channelId": "abc"}, Data: payload}
	body, err := EncodeNatMessage(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeNatMessage(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got.Data, payload) {
		t.Fatalf("data round-trip mismatch")
	}
}
