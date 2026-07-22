package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestReadPacketRejectsBodyThatExceedsFullFrameLimit(t *testing.T) {
	header := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint32(header[:4], MagicNumber)
	header[4] = Version
	header[5] = SerializerCompact
	header[6] = byte(CommandHeartbeatRequest)
	binary.BigEndian.PutUint32(header[7:11], uint32(maxFrameBodySize+1))
	if _, err := ReadPacket(bytes.NewReader(header)); err == nil {
		t.Fatal("oversized frame was accepted")
	}
}

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

func TestRemovedHTTPCommandsAreRejected(t *testing.T) {
	for _, command := range []int8{5, -5, 7, -7} {
		var frame bytes.Buffer
		header := make([]byte, frameHeaderSize)
		binary.BigEndian.PutUint32(header[:4], MagicNumber)
		header[4] = Version
		header[5] = SerializerCompact
		header[6] = byte(command)
		frame.Write(header)
		if _, err := ReadPacket(&frame); err == nil {
			t.Fatalf("removed command %d was accepted", command)
		}
	}
}

func TestZeroClientSessionIDEncodesAsNonNullLongLikeJava(t *testing.T) {
	encoded, err := EncodeLoginRequest("go-client", 0, "token", ConnectionRoleControl)
	if err != nil {
		t.Fatalf("EncodeLoginRequest() error = %v", err)
	}
	input, err := newCompactInput(encoded)
	if err != nil {
		t.Fatalf("newCompactInput() error = %v", err)
	}
	_, _ = input.readString()
	marker, err := input.readByte()
	if err != nil || marker != 1 {
		t.Fatalf("session marker = %d, err=%v", marker, err)
	}
	value, err := input.readVarLong()
	if err != nil || value != 0 {
		t.Fatalf("session value = %d, err=%v", value, err)
	}
}

func TestPeerControlMessageRequestEncoding(t *testing.T) {
	encoded := EncodeMessageRequest("go-client", "", MessageTypePeerControl, `{"type":"device-report"}`)
	input, err := newCompactInput(encoded)
	if err != nil {
		t.Fatalf("newCompactInput() error = %v", err)
	}
	clientName, _ := input.readString()
	toClientName, _ := input.readString()
	messageType, _ := input.readNullableEnum()
	message, _ := input.readString()
	if err := input.finish(); err != nil {
		t.Fatalf("finish error = %v", err)
	}
	if clientName != "go-client" || toClientName != "" ||
		messageType != MessageTypePeerControl || message != `{"type":"device-report"}` {
		t.Fatalf("decoded peer control = %q/%q/%d/%q", clientName, toClientName, messageType, message)
	}
}

func TestPeerControlMessageResponseDecoding(t *testing.T) {
	output := newCompactOutput()
	output.writeString("server")
	output.writeString("go-client")
	output.writeEnum(MessageTypePeerControl)
	output.writeString(`{"type":"roster","peers":[]}`)
	response, err := DecodeMessageResponse(encodePayload(output.Bytes()))
	if err != nil || response.MessageType != MessageTypePeerControl {
		t.Fatalf("DecodeMessageResponse() = %+v, err=%v", response, err)
	}
}

func TestNatMessageRoundTripWithFinMetadata(t *testing.T) {
	for _, expected := range []NatMessage{
		{Type: NatData, StreamID: 1, Data: bytes.Repeat([]byte("data"), 128)},
		{Type: NatFin, StreamID: 2, Metadata: map[string]any{"trailers": []string{"X-End:ok"}}},
	} {
		encoded, err := EncodeNatMessage(expected)
		if err != nil {
			t.Fatalf("EncodeNatMessage() error = %v", err)
		}
		actual, err := DecodeNatMessage(encoded)
		if err != nil || actual.Type != expected.Type || actual.StreamID != expected.StreamID {
			t.Fatalf("DecodeNatMessage() = %#v, err=%v", actual, err)
		}
	}
}
