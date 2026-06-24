package protocol

import (
	"bytes"
	"reflect"
	"testing"
)

func TestPacketRoundTrip(t *testing.T) {
	var encoded bytes.Buffer
	expectedBody := []byte("hello")
	if err := WritePacket(&encoded, CommandHeartbeatRequest, expectedBody); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	packet, err := ReadPacket(&encoded)
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if packet.Command != CommandHeartbeatRequest || !bytes.Equal(packet.Body, expectedBody) {
		t.Fatalf("ReadPacket() = %#v", packet)
	}
}

func TestDirectHTTPResponseRoundTrip(t *testing.T) {
	expected := DirectHTTPResponse{
		RequestID:  "8b284fef-0987-4948-ac66-7f2059336989",
		StatusCode: 200,
		Headers:    []string{"Content-Type:text/plain"},
		Body:       []byte("ok"),
	}
	encoded, err := EncodeDirectHTTPResponse(expected)
	if err != nil {
		t.Fatalf("EncodeDirectHTTPResponse() error = %v", err)
	}
	if encoded[len(encoded)-1] != 0 {
		t.Fatalf("successful response error marker = %d, want null marker", encoded[len(encoded)-1])
	}
	actual, err := DecodeDirectHTTPResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeDirectHTTPResponse() error = %v", err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("DecodeDirectHTTPResponse() = %#v, want %#v", actual, expected)
	}
}

func TestNatMessageRoundTrip(t *testing.T) {
	expected := NatMessage{
		Type:     NatData,
		Metadata: map[string]any{"channelId": "demo"},
		Data:     bytes.Repeat([]byte("compressible-data"), 128),
	}
	encoded, err := EncodeNatMessage(expected)
	if err != nil {
		t.Fatalf("EncodeNatMessage() error = %v", err)
	}
	actual, err := DecodeNatMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeNatMessage() error = %v", err)
	}
	if actual.Type != expected.Type || actual.Metadata["channelId"] != "demo" || !bytes.Equal(actual.Data, expected.Data) {
		t.Fatalf("DecodeNatMessage() = %#v", actual)
	}
}
