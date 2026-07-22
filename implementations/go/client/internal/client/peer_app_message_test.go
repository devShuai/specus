package client

import (
	"bytes"
	"testing"
)

func TestPeerAppMessageCodecMatchesJavaPrefixAndFields(t *testing.T) {
	want := peerAppMessage{
		Type: peerAppMessageTypeMessage, ID: "message-1",
		FromClientID: 1, FromClientName: "sender",
		ToClientID: 2, ToClientName: "receiver",
		Message: "hello", CreatedAtMillis: 1234,
	}
	payload, err := encodePeerAppMessage(want)
	if err != nil {
		t.Fatalf("encode app message: %v", err)
	}
	if !bytes.HasPrefix(payload, []byte("STMSG2\n")) {
		t.Fatalf("prefix = %q", payload)
	}
	got, ok := decodePeerAppMessage(payload)
	if !ok || *got != want {
		t.Fatalf("decoded = %+v/%v, want %+v", got, ok, want)
	}
}

func TestPeerAppMessageCodecRejectsMalformedPayload(t *testing.T) {
	for _, payload := range [][]byte{
		[]byte(`{"type":"message"}`),
		[]byte("STMSG2\n{"),
		[]byte("STMSG2\n{}"),
		[]byte("STMSG1\n{\"type\":\"message\"}"),
	} {
		if _, ok := decodePeerAppMessage(payload); ok {
			t.Fatalf("accepted malformed payload %q", payload)
		}
	}
}
