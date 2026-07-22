package client

import (
	"encoding/binary"
	"fmt"
)

const (
	webSocketTunnelHeaderBytes = 12
	maxWebSocketFramePayload   = 64*1024 - webSocketTunnelHeaderBytes
)

var webSocketTunnelMagic = [4]byte{'S', 'W', 'S', '2'}

type webSocketTunnelFrame struct {
	opcode    byte
	fin       bool
	rsv       byte
	closeCode uint16
	payload   []byte
}

func encodeWebSocketTunnelFrame(frame webSocketTunnelFrame) ([]byte, error) {
	if err := validateWebSocketTunnelFrame(frame); err != nil {
		return nil, err
	}
	encoded := make([]byte, webSocketTunnelHeaderBytes+len(frame.payload))
	copy(encoded[:4], webSocketTunnelMagic[:])
	encoded[4] = frame.opcode
	if frame.fin {
		encoded[5] = 1
	}
	encoded[5] |= (frame.rsv & 7) << 1
	binary.BigEndian.PutUint16(encoded[6:8], frame.closeCode)
	binary.BigEndian.PutUint32(encoded[8:12], uint32(len(frame.payload)))
	copy(encoded[12:], frame.payload)
	return encoded, nil
}

func decodeWebSocketTunnelFrame(encoded []byte) (webSocketTunnelFrame, error) {
	if len(encoded) < webSocketTunnelHeaderBytes {
		return webSocketTunnelFrame{}, fmt.Errorf("truncated SWS2 frame")
	}
	if string(encoded[:4]) != string(webSocketTunnelMagic[:]) {
		return webSocketTunnelFrame{}, fmt.Errorf("invalid SWS2 magic")
	}
	flags := encoded[5]
	if flags&0xF0 != 0 {
		return webSocketTunnelFrame{}, fmt.Errorf("unknown SWS2 flags")
	}
	payloadLength := binary.BigEndian.Uint32(encoded[8:12])
	if payloadLength > maxWebSocketFramePayload || int(payloadLength) != len(encoded)-webSocketTunnelHeaderBytes {
		return webSocketTunnelFrame{}, fmt.Errorf("invalid SWS2 payload length")
	}
	frame := webSocketTunnelFrame{
		opcode:    encoded[4],
		fin:       flags&1 != 0,
		rsv:       (flags >> 1) & 7,
		closeCode: binary.BigEndian.Uint16(encoded[6:8]),
		payload:   append([]byte(nil), encoded[12:]...),
	}
	if err := validateWebSocketTunnelFrame(frame); err != nil {
		return webSocketTunnelFrame{}, err
	}
	return frame, nil
}

func validateWebSocketTunnelFrame(frame webSocketTunnelFrame) error {
	switch frame.opcode {
	case webSocketOpcodeContinuation, webSocketOpcodeText, webSocketOpcodeBinary,
		webSocketOpcodeClose, webSocketOpcodePing, webSocketOpcodePong:
	default:
		return fmt.Errorf("unsupported SWS2 opcode %d", frame.opcode)
	}
	if frame.rsv > 7 || len(frame.payload) > maxWebSocketFramePayload {
		return fmt.Errorf("invalid SWS2 frame bounds")
	}
	if frame.opcode >= webSocketOpcodeClose && (!frame.fin || frame.rsv != 0 || len(frame.payload) > 125) {
		return fmt.Errorf("invalid fragmented/control SWS2 frame")
	}
	if frame.opcode == webSocketOpcodeClose {
		if len(frame.payload) > 123 {
			return fmt.Errorf("websocket close reason exceeds 123 bytes")
		}
		if frame.closeCode != 0 && (frame.closeCode < 1000 || frame.closeCode >= 5000) {
			return fmt.Errorf("invalid websocket close code")
		}
		if frame.closeCode == 0 && len(frame.payload) != 0 {
			return fmt.Errorf("websocket close reason requires a close code")
		}
	} else if frame.closeCode != 0 {
		return fmt.Errorf("close code is only valid on CLOSE")
	}
	return nil
}
