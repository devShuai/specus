package protocol

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "protocol",
		"test-vectors", "control-v2", "frames", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func decodeFixture(t *testing.T, name string, byteExact bool) Packet {
	t.Helper()
	raw := readFixture(t, name)
	packet, consumed, err := DecodeFrame(raw)
	if err != nil || consumed != len(raw) {
		t.Fatalf("decode %s: consumed=%d/%d err=%v", name, consumed, len(raw), err)
	}
	encoded, err := EncodeFrame(packet)
	if err != nil {
		t.Fatalf("re-encode %s: %v", name, err)
	}
	if byteExact {
		if !bytes.Equal(raw, encoded) {
			t.Fatalf("%s re-encoded bytes differ", name)
		}
	} else {
		roundtripped, _, err := DecodeFrame(encoded)
		if err != nil || !reflect.DeepEqual(packet, roundtripped) {
			t.Fatalf("%s semantic roundtrip mismatch: err=%v", name, err)
		}
	}
	return packet
}

func TestReadFrameLimitCountsHeaderBytes(t *testing.T) {
	const fullFrameLimit = 64
	header := make([]byte, FrameHeaderSize)
	binary.BigEndian.PutUint32(header[:4], MagicNumber)
	header[4] = Version
	header[5] = SerializerCompact
	header[6] = byte(CommandNatMessage)
	binary.BigEndian.PutUint32(header[7:11], uint32(fullFrameLimit-FrameHeaderSize+1))
	if _, _, err := ReadFrameLimit(bytes.NewReader(header), fullFrameLimit); err == nil {
		t.Fatal("oversized frame was accepted")
	}
}

func TestControlFixtures(t *testing.T) {
	login := decodeFixture(t, "login_request.bin", true).(LoginRequest)
	if login.ClientName != "Demo client" || login.ClientSessionID != 1700000000000 ||
		login.ConnectionRole != ConnectionRoleControl {
		t.Fatalf("unexpected login: %+v", login)
	}
	decodeFixture(t, "login_response.bin", true)
	decodeFixture(t, "login_response_fail.bin", true)
	decodeFixture(t, "logout_request.bin", true)
	decodeFixture(t, "logout_response.bin", true)
	decodeFixture(t, "heartbeat_request.bin", true)
	decodeFixture(t, "heartbeat_response.bin", true)
	request := decodeFixture(t, "message_request.bin", true).(MessageRequest)
	if request.MessageType != MessageTypeClientToServer {
		t.Fatalf("unexpected message type: %d", request.MessageType)
	}
	decodeFixture(t, "message_response.bin", false)
}

func TestNatFixtures(t *testing.T) {
	fixtures := []string{
		"nat_register.bin", "nat_register_result.bin", "nat_open.bin", "nat_fin.bin",
		"nat_rst.bin", "nat_window_update.bin", "nat_keepalive.bin", "nat_unregister.bin",
		"nat_data_small.bin", "nat_data_large.bin",
		"http_stream_request_open.bin", "http_stream_request_data.bin", "http_stream_request_fin.bin",
		"http_stream_response_open.bin", "http_stream_response_data.bin", "http_stream_response_fin.bin",
	}
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) { decodeFixture(t, name, false) })
	}
}

func TestNatFinCarriesTrailerMetadata(t *testing.T) {
	expected := NatMessage{
		Type: NatFin, StreamID: 7,
		Metadata: map[string]any{"trailers": []string{"X-Checksum:ok"}},
	}
	encoded, err := EncodeFrame(expected)
	if err != nil {
		t.Fatalf("encode FIN: %v", err)
	}
	decoded, _, err := DecodeFrame(encoded)
	if err != nil {
		t.Fatalf("decode FIN: %v", err)
	}
	actual := decoded.(NatMessage)
	if actual.Type != NatFin || actual.StreamID != 7 || len(actual.Metadata) == 0 {
		t.Fatalf("unexpected FIN: %+v", actual)
	}
}

func TestRemovedHTTPCommandsAreRejected(t *testing.T) {
	for _, command := range []int8{5, -5, 7, -7} {
		header := make([]byte, FrameHeaderSize)
		binary.BigEndian.PutUint32(header[:4], MagicNumber)
		header[4] = Version
		header[5] = SerializerCompact
		header[6] = byte(command)
		if _, _, err := DecodeFrame(header); err == nil {
			t.Fatalf("removed command %d was accepted", command)
		}
	}
}

func TestMalformedCanonicalFramesAreRejected(t *testing.T) {
	fixtures := []string{
		"invalid_bad_magic.bin", "invalid_version_v1.bin", "invalid_serializer.bin",
		"invalid_unknown_command.bin", "invalid_truncated_header.bin", "invalid_truncated_body.bin",
		"invalid_trailing_body.bin", "invalid_heartbeat_body.bin", "invalid_oversized_length.bin",
	}
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			if _, _, err := DecodeFrame(readFixture(t, name)); err == nil {
				t.Fatalf("malformed fixture %s was accepted", name)
			}
		})
	}
}
