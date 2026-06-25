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

func TestCommandCodesMatchJava(t *testing.T) {
	if CommandLogoutRequest != 3 || CommandLogoutResponse != -3 {
		t.Fatalf("logout command codes mismatch: request=%d response=%d", CommandLogoutRequest, CommandLogoutResponse)
	}
}

func TestZeroClientSessionIDEncodesAsNonNullLongLikeJava(t *testing.T) {
	encoded, err := EncodeLoginRequest("go-client", 0, "token")
	if err != nil {
		t.Fatalf("EncodeLoginRequest() error = %v", err)
	}
	input, err := newCompactInput(encoded)
	if err != nil {
		t.Fatalf("newCompactInput() error = %v", err)
	}
	if _, err := input.readString(); err != nil {
		t.Fatalf("clientName read error = %v", err)
	}
	marker, err := input.readByte()
	if err != nil {
		t.Fatalf("session marker read error = %v", err)
	}
	if marker != 1 {
		t.Fatalf("zero clientSessionId marker = %d, want Java non-null long marker 1", marker)
	}
	value, err := input.readVarLong()
	if err != nil {
		t.Fatalf("session value read error = %v", err)
	}
	if value != 0 {
		t.Fatalf("zero clientSessionId zigzag value = %d, want 0", value)
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

func TestDirectHTTPResponseEmptyErrorPreservesNonNullStringLikeJava(t *testing.T) {
	empty := ""
	encoded, err := EncodeDirectHTTPResponse(DirectHTTPResponse{
		RequestID:  "8b284fef-0987-4948-ac66-7f2059336989",
		StatusCode: 502,
		Error:      &empty,
	})
	if err != nil {
		t.Fatalf("EncodeDirectHTTPResponse() error = %v", err)
	}
	actual, err := DecodeDirectHTTPResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeDirectHTTPResponse() error = %v", err)
	}
	if actual.Error == nil || *actual.Error != "" {
		t.Fatalf("Error = %#v, want non-nil empty string", actual.Error)
	}
	input, err := newCompactInput(encoded)
	if err != nil {
		t.Fatalf("newCompactInput() error = %v", err)
	}
	if _, err := input.readUUIDString(); err != nil {
		t.Fatalf("uuid read error = %v", err)
	}
	if _, err := input.readVarInt(); err != nil {
		t.Fatalf("status read error = %v", err)
	}
	if _, err := input.readStringList(); err != nil {
		t.Fatalf("headers read error = %v", err)
	}
	if _, err := input.readByteArray(); err != nil {
		t.Fatalf("body read error = %v", err)
	}
	errorMarker, err := input.readVarInt()
	if err != nil {
		t.Fatalf("error marker read error = %v", err)
	}
	if errorMarker != 1 {
		t.Fatalf("empty error marker = %d, want Java empty string marker 1", errorMarker)
	}
}

func TestUUIDCodecPreservesNonCanonicalCaseLikeJava(t *testing.T) {
	expected := DirectHTTPResponse{
		RequestID:  "8B284FEF-0987-4948-AC66-7F2059336989",
		StatusCode: 204,
	}
	encoded, err := EncodeDirectHTTPResponse(expected)
	if err != nil {
		t.Fatalf("EncodeDirectHTTPResponse() error = %v", err)
	}
	actual, err := DecodeDirectHTTPResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeDirectHTTPResponse() error = %v", err)
	}
	if actual.RequestID != expected.RequestID {
		t.Fatalf("RequestID = %q, want %q", actual.RequestID, expected.RequestID)
	}
}

func TestEmptyUUIDEncodesAsStringLikeJava(t *testing.T) {
	encoded, err := EncodeDirectHTTPResponse(DirectHTTPResponse{RequestID: "", StatusCode: 204})
	if err != nil {
		t.Fatalf("EncodeDirectHTTPResponse() error = %v", err)
	}
	input, err := newCompactInput(encoded)
	if err != nil {
		t.Fatalf("newCompactInput() error = %v", err)
	}
	marker, err := input.readByte()
	if err != nil {
		t.Fatalf("uuid marker read error = %v", err)
	}
	if marker != 2 {
		t.Fatalf("empty UUID marker = %d, want Java string marker 2", marker)
	}
	value, err := input.readString()
	if err != nil {
		t.Fatalf("uuid string read error = %v", err)
	}
	if value != "" {
		t.Fatalf("empty UUID string = %q, want empty", value)
	}
}

func TestNilAndEmptyCollectionsUseJavaMarkers(t *testing.T) {
	for _, tc := range []struct {
		name          string
		headers       []string
		body          []byte
		wantHeaders   int
		wantBodyBytes int
	}{
		{name: "nil", headers: nil, body: nil, wantHeaders: 0, wantBodyBytes: 0},
		{name: "empty", headers: []string{}, body: []byte{}, wantHeaders: 1, wantBodyBytes: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := EncodeDirectHTTPResponse(DirectHTTPResponse{
				RequestID:  "8b284fef-0987-4948-ac66-7f2059336989",
				StatusCode: 204,
				Headers:    tc.headers,
				Body:       tc.body,
			})
			if err != nil {
				t.Fatalf("EncodeDirectHTTPResponse() error = %v", err)
			}
			input, err := newCompactInput(encoded)
			if err != nil {
				t.Fatalf("newCompactInput() error = %v", err)
			}
			if _, err := input.readUUIDString(); err != nil {
				t.Fatalf("uuid read error = %v", err)
			}
			if _, err := input.readVarInt(); err != nil {
				t.Fatalf("status read error = %v", err)
			}
			headersMarker, err := input.readVarInt()
			if err != nil {
				t.Fatalf("headers marker read error = %v", err)
			}
			if headersMarker != tc.wantHeaders {
				t.Fatalf("headers marker = %d, want %d", headersMarker, tc.wantHeaders)
			}
			bodyMarker, err := input.readVarInt()
			if err != nil {
				t.Fatalf("body marker read error = %v", err)
			}
			if bodyMarker != tc.wantBodyBytes {
				t.Fatalf("body marker = %d, want %d", bodyMarker, tc.wantBodyBytes)
			}
		})
	}
}

func TestPeerControlMessageRequestEncoding(t *testing.T) {
	encoded := EncodeMessageRequest("go-client", "", MessageTypePeerControl, `{"type":"device-report"}`)
	input, err := newCompactInput(encoded)
	if err != nil {
		t.Fatalf("newCompactInput() error = %v", err)
	}
	clientName, err := input.readString()
	if err != nil {
		t.Fatalf("clientName read error = %v", err)
	}
	toClientName, err := input.readString()
	if err != nil {
		t.Fatalf("toClientName read error = %v", err)
	}
	messageType, err := input.readNullableEnum()
	if err != nil {
		t.Fatalf("messageType read error = %v", err)
	}
	message, err := input.readString()
	if err != nil {
		t.Fatalf("message read error = %v", err)
	}
	if err := input.finish(); err != nil {
		t.Fatalf("finish error = %v", err)
	}
	if clientName != "go-client" || toClientName != "" ||
		messageType != MessageTypePeerControl || message != `{"type":"device-report"}` {
		t.Fatalf("decoded peer control = clientName=%q to=%q type=%d message=%q",
			clientName, toClientName, messageType, message)
	}
}

func TestPeerControlMessageResponseDecoding(t *testing.T) {
	output := newCompactOutput()
	output.writeString("server")
	output.writeString("go-client")
	output.writeEnum(MessageTypePeerControl)
	output.writeString(`{"type":"roster","peers":[]}`)

	response, err := DecodeMessageResponse(encodePayload(output.Bytes()))
	if err != nil {
		t.Fatalf("DecodeMessageResponse() error = %v", err)
	}
	if response.ClientName != "server" ||
		response.ToClientName != "go-client" ||
		response.MessageType != MessageTypePeerControl ||
		response.Message != `{"type":"roster","peers":[]}` {
		t.Fatalf("decoded peer control response = %+v", response)
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
