package directhttp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// SWS2 是 NAT stream v2 DATA 里承载 WebSocket 帧的 12 字节显式封装，
// 与 Java common 的 WebSocketSpecusFrame 及 Go client 的 webSocketSpecusFrame 对齐。
const (
	sws2Magic       = 0x53575332 // "SWS2"
	sws2HeaderBytes = 12
	maxSWS2Payload  = 64*1024 - sws2HeaderBytes
	// sws2MaxCloseReasonBytes 是 WS 关闭原因的最大字节数（WS 控制帧 125 - 2 字节关闭码）。
	sws2MaxCloseReasonBytes = 123
)

const (
	sws2OpcodeContinuation byte = 0x0
	sws2OpcodeText         byte = 0x1
	sws2OpcodeBinary       byte = 0x2
	sws2OpcodeClose        byte = 0x8
	sws2OpcodePing         byte = 0x9
	sws2OpcodePong         byte = 0xA
)

// sws2Frame 保留 opcode、FIN、RSV、close code 和 payload，避免隧道两端丢帧语义。
type sws2Frame struct {
	opcode    byte
	fin       bool
	rsv       byte
	closeCode uint16
	payload   []byte
}

// encodeSWS2 编码一帧 SWS2：magic u32 | opcode u8 | flags u8 | closeCode u16 | payloadLen i32 | payload。
func encodeSWS2(opcode byte, fin bool, rsv byte, closeCode uint16, payload []byte) ([]byte, error) {
	if err := validateSWS2(opcode, fin, rsv, closeCode, len(payload)); err != nil {
		return nil, err
	}
	encoded := make([]byte, sws2HeaderBytes+len(payload))
	binary.BigEndian.PutUint32(encoded[0:4], sws2Magic)
	encoded[4] = opcode
	var flags byte
	if fin {
		flags |= 0x01
	}
	flags |= (rsv & 0x07) << 1
	encoded[5] = flags
	binary.BigEndian.PutUint16(encoded[6:8], closeCode)
	binary.BigEndian.PutUint32(encoded[8:12], uint32(len(payload)))
	copy(encoded[sws2HeaderBytes:], payload)
	return encoded, nil
}

func decodeSWS2(encoded []byte) (sws2Frame, error) {
	if len(encoded) < sws2HeaderBytes {
		return sws2Frame{}, errors.New("truncated SWS2 frame")
	}
	if binary.BigEndian.Uint32(encoded[0:4]) != sws2Magic {
		return sws2Frame{}, errors.New("invalid SWS2 magic")
	}
	flags := encoded[5]
	if flags&0xF0 != 0 {
		return sws2Frame{}, errors.New("unknown SWS2 flags")
	}
	payloadLength := binary.BigEndian.Uint32(encoded[8:12])
	if payloadLength > maxSWS2Payload || int(payloadLength) != len(encoded)-sws2HeaderBytes {
		return sws2Frame{}, errors.New("invalid SWS2 payload length")
	}
	frame := sws2Frame{
		opcode:    encoded[4],
		fin:       flags&0x01 != 0,
		rsv:       (flags >> 1) & 0x07,
		closeCode: binary.BigEndian.Uint16(encoded[6:8]),
		payload:   append([]byte(nil), encoded[sws2HeaderBytes:]...),
	}
	if err := validateSWS2(frame.opcode, frame.fin, frame.rsv, frame.closeCode, len(frame.payload)); err != nil {
		return sws2Frame{}, err
	}
	return frame, nil
}

// validateSWS2 与 Java WebSocketSpecusFrame.validate 的规则逐条对应。
func validateSWS2(opcode byte, fin bool, rsv byte, closeCode uint16, payloadLength int) error {
	switch opcode {
	case sws2OpcodeContinuation, sws2OpcodeText, sws2OpcodeBinary,
		sws2OpcodeClose, sws2OpcodePing, sws2OpcodePong:
	default:
		return fmt.Errorf("unsupported SWS2 opcode: %d", opcode)
	}
	if rsv > 7 {
		return errors.New("invalid SWS2 RSV bits")
	}
	if payloadLength < 0 || payloadLength > maxSWS2Payload {
		return errors.New("SWS2 payload exceeds frame limit")
	}
	if control := opcode >= sws2OpcodeClose; control && (!fin || payloadLength > 125 || rsv != 0) {
		return errors.New("invalid fragmented/control SWS2 frame")
	}
	if opcode == sws2OpcodeClose {
		if payloadLength > sws2MaxCloseReasonBytes {
			return errors.New("WebSocket close reason exceeds 123 bytes")
		}
		if closeCode != 0 && (closeCode < 1000 || closeCode >= 5000 ||
			isWireForbiddenCloseCode(closeCode)) {
			return errors.New("invalid WebSocket close code")
		}
		if closeCode == 0 && payloadLength != 0 {
			return errors.New("WebSocket close reason requires a close code")
		}
	} else if closeCode != 0 {
		return errors.New("close code is only valid on CLOSE")
	}
	return nil
}

func isWireForbiddenCloseCode(closeCode uint16) bool {
	return closeCode == 1004 || closeCode == 1005 || closeCode == 1006 || closeCode == 1015
}
