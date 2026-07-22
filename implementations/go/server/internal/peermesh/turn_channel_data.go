package peermesh

import (
	"encoding/binary"
	"fmt"
)

const (
	turnChannelMin = 0x4000
	turnChannelMax = 0x7fff
)

type turnChannelData struct {
	Channel uint16
	Payload []byte
}

func looksLikeTurnChannelData(packet []byte) bool {
	if len(packet) < 4 {
		return false
	}
	channel := binary.BigEndian.Uint16(packet[:2])
	return channel >= turnChannelMin && channel <= turnChannelMax
}

func parseTurnChannelData(packet []byte) (turnChannelData, error) {
	if !looksLikeTurnChannelData(packet) {
		return turnChannelData{}, fmt.Errorf("not TURN ChannelData")
	}
	payloadLength := int(binary.BigEndian.Uint16(packet[2:4]))
	end := 4 + payloadLength
	if end > len(packet) || len(packet)-end > 3 {
		return turnChannelData{}, fmt.Errorf("invalid TURN ChannelData length")
	}
	for _, padding := range packet[end:] {
		if padding != 0 {
			return turnChannelData{}, fmt.Errorf("non-zero TURN ChannelData padding")
		}
	}
	return turnChannelData{
		Channel: binary.BigEndian.Uint16(packet[:2]),
		Payload: append([]byte(nil), packet[4:end]...),
	}, nil
}

func encodeTurnChannelData(channel uint16, payload []byte) ([]byte, error) {
	if channel < turnChannelMin || channel > turnChannelMax {
		return nil, fmt.Errorf("invalid TURN channel number")
	}
	if len(payload) > 0xffff {
		return nil, fmt.Errorf("TURN ChannelData payload exceeds 65535 bytes")
	}
	padding := stunPadding(len(payload))
	packet := make([]byte, 4+len(payload)+padding)
	binary.BigEndian.PutUint16(packet[:2], channel)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(payload)))
	copy(packet[4:], payload)
	return packet, nil
}
