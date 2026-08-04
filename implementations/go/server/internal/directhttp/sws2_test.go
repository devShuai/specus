package directhttp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestSWS2RoundTrip(t *testing.T) {
	cases := []sws2Frame{
		{opcode: sws2OpcodeText, fin: true, payload: []byte("hello")},
		{opcode: sws2OpcodeBinary, fin: true, payload: []byte{0x00, 0xFF, 0x10}},
		// 分片序列：首帧 TEXT fin=false，随后 CONTINUATION fin=true。
		{opcode: sws2OpcodeText, fin: false, payload: []byte("frag-")},
		{opcode: sws2OpcodeContinuation, fin: true, payload: []byte("ment")},
		{opcode: sws2OpcodePing, fin: true, payload: []byte("pi")},
		{opcode: sws2OpcodePong, fin: true, payload: []byte("po")},
		{opcode: sws2OpcodeClose, fin: true, closeCode: 1000, payload: []byte("bye")},
		{opcode: sws2OpcodeClose, fin: true, closeCode: 0},
		// 空 payload 的应用帧也合法（对齐 Java handleAppFrame 的 do-while）。
		{opcode: sws2OpcodeText, fin: true},
		// 最大 payload 边界。
		{opcode: sws2OpcodeBinary, fin: true, payload: make([]byte, maxSWS2Payload)},
	}
	for _, want := range cases {
		encoded, err := encodeSWS2(want.opcode, want.fin, want.rsv, want.closeCode, want.payload)
		if err != nil {
			t.Fatalf("encodeSWS2(opcode=%d) failed: %v", want.opcode, err)
		}
		if len(encoded) != sws2HeaderBytes+len(want.payload) {
			t.Fatalf("encoded length = %d, want %d", len(encoded), sws2HeaderBytes+len(want.payload))
		}
		if binary.BigEndian.Uint32(encoded[0:4]) != sws2Magic {
			t.Fatalf("magic = %#x, want %#x", binary.BigEndian.Uint32(encoded[0:4]), sws2Magic)
		}
		got, err := decodeSWS2(encoded)
		if err != nil {
			t.Fatalf("decodeSWS2(opcode=%d) failed: %v", want.opcode, err)
		}
		if got.opcode != want.opcode || got.fin != want.fin || got.rsv != want.rsv ||
			got.closeCode != want.closeCode || !bytes.Equal(got.payload, want.payload) {
			t.Fatalf("round trip = %+v, want %+v", got, want)
		}
	}
}

func TestSWS2HeaderLayoutMatchesJava(t *testing.T) {
	encoded, err := encodeSWS2(sws2OpcodeClose, true, 0, 1001, []byte("rs"))
	if err != nil {
		t.Fatalf("encodeSWS2 failed: %v", err)
	}
	// magic u32 | opcode u8 | flags u8(FIN=bit0, RSV=bits1-3) | closeCode u16 | payloadLen i32。
	want := []byte{0x53, 0x57, 0x53, 0x32, 0x08, 0x01, 0x03, 0xE9, 0x00, 0x00, 0x00, 0x02, 'r', 's'}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("header layout = %x, want %x", encoded, want)
	}
}

func TestSWS2EncodeRejectsInvalidFrames(t *testing.T) {
	cases := map[string]struct {
		opcode    byte
		fin       bool
		rsv       byte
		closeCode uint16
		payload   []byte
	}{
		"unsupported opcode":        {opcode: 0x3, fin: true},
		"fragmented control frame":  {opcode: sws2OpcodePing, fin: false},
		"control payload too large": {opcode: sws2OpcodePong, fin: true, payload: make([]byte, 126)},
		"control frame with rsv":    {opcode: sws2OpcodeClose, fin: true, rsv: 1, closeCode: 1000},
		"close reason too long":     {opcode: sws2OpcodeClose, fin: true, closeCode: 1000, payload: make([]byte, sws2MaxCloseReasonBytes+1)},
		"invalid close code":        {opcode: sws2OpcodeClose, fin: true, closeCode: 999},
		"close reason without code": {opcode: sws2OpcodeClose, fin: true, payload: []byte("x")},
		"close code on data frame":  {opcode: sws2OpcodeText, fin: true, closeCode: 1000},
		"payload exceeds limit":     {opcode: sws2OpcodeBinary, fin: true, payload: make([]byte, maxSWS2Payload+1)},
	}
	for name, tc := range cases {
		if _, err := encodeSWS2(tc.opcode, tc.fin, tc.rsv, tc.closeCode, tc.payload); err == nil {
			t.Fatalf("%s: encodeSWS2 should fail", name)
		}
	}
}

func TestSWS2RejectsWireForbiddenCloseCodesFromCentralVector(t *testing.T) {
	var vectors struct {
		WebSocket struct {
			WireForbiddenCloseCodes []uint16 `json:"wireForbiddenCloseCodes"`
		} `json:"webSocket"`
	}
	contents, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..",
		"protocol", "test-vectors", "application-protocol-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(contents, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.WebSocket.WireForbiddenCloseCodes) == 0 {
		t.Fatal("central SWS2 vector has no wire-forbidden close codes")
	}
	for _, closeCode := range vectors.WebSocket.WireForbiddenCloseCodes {
		t.Run(fmt.Sprintf("close-code-%d", closeCode), func(t *testing.T) {
			if _, err := encodeSWS2(sws2OpcodeClose, true, 0, closeCode, nil); err == nil {
				t.Fatal("wire-forbidden close code was encoded")
			}
			raw := make([]byte, sws2HeaderBytes)
			binary.BigEndian.PutUint32(raw[0:4], sws2Magic)
			raw[4] = sws2OpcodeClose
			raw[5] = 1
			binary.BigEndian.PutUint16(raw[6:8], closeCode)
			if _, err := decodeSWS2(raw); err == nil {
				t.Fatal("wire-forbidden close code was decoded")
			}
		})
	}
}

func TestSWS2DecodeRejectsMalformedFrames(t *testing.T) {
	valid, err := encodeSWS2(sws2OpcodeText, true, 0, 0, []byte("ok"))
	if err != nil {
		t.Fatalf("encodeSWS2 failed: %v", err)
	}
	cases := map[string][]byte{
		"truncated header": valid[:sws2HeaderBytes-1],
		"bad magic":        {0x00, 0x57, 0x53, 0x32, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 'o', 'k'},
		"unknown flags": func() []byte {
			frame := bytes.Clone(valid)
			frame[5] |= 0x80
			return frame
		}(),
		"payload length mismatch": valid[:len(valid)-1],
		"declared length too large": func() []byte {
			frame := bytes.Clone(valid)
			binary.BigEndian.PutUint32(frame[8:12], maxSWS2Payload+1)
			return frame
		}(),
		"unsupported opcode": func() []byte {
			frame := bytes.Clone(valid)
			frame[4] = 0x7
			return frame
		}(),
	}
	for name, frame := range cases {
		if _, err := decodeSWS2(frame); err == nil {
			t.Fatalf("%s: decodeSWS2 should fail", name)
		}
	}
}
