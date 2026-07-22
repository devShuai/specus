package client

import "testing"

func TestTurnChannelDataRoundTripAndRejectsTrailingBytes(t *testing.T) {
	packet, err := encodeTurnChannelData(turnChannelMin, []byte("abc"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	frame, err := parseTurnChannelData(packet)
	if err != nil || frame.Channel != turnChannelMin || string(frame.Payload) != "abc" {
		t.Fatalf("round trip = %+v err=%v", frame, err)
	}
	if _, err := parseTurnChannelData(append(packet, 1)); err == nil {
		t.Fatal("ChannelData accepted non-zero padding")
	}
}
