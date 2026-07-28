package client

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type applicationProtocolVectors struct {
	WebSocket struct {
		Opcode          byte   `json:"opcode"`
		FinalFragment   bool   `json:"finalFragment"`
		RSV             byte   `json:"rsv"`
		CloseCode       uint16 `json:"closeCode"`
		PayloadUTF8     string `json:"payloadUtf8"`
		FrameHex        string `json:"frameHex"`
		InvalidMagicHex string `json:"invalidMagicHex"`
		TruncatedHex    string `json:"truncatedHex"`
		TrailingHex     string `json:"trailingHex"`
	} `json:"webSocket"`
	ClientMessage struct {
		Type            string `json:"type"`
		ID              string `json:"id"`
		FromClientID    int64  `json:"fromClientId"`
		FromClientName  string `json:"fromClientName"`
		ToClientID      int64  `json:"toClientId"`
		ToClientName    string `json:"toClientName"`
		Message         string `json:"message"`
		CreatedAtMillis int64  `json:"createdAtMillis"`
		PayloadHex      string `json:"payloadHex"`
	} `json:"clientMessage"`
}

func TestApplicationProtocolMatchesCentralSWS2Vector(t *testing.T) {
	vectors := readApplicationProtocolVectors(t)
	want := decodeVectorHex(t, vectors.WebSocket.FrameHex)
	encoded, err := encodeWebSocketSpecusFrame(webSocketSpecusFrame{
		opcode:    vectors.WebSocket.Opcode,
		fin:       vectors.WebSocket.FinalFragment,
		rsv:       vectors.WebSocket.RSV,
		closeCode: vectors.WebSocket.CloseCode,
		payload:   []byte(vectors.WebSocket.PayloadUTF8),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("SWS2 frame = %x, want %x", encoded, want)
	}
	decoded, err := decodeWebSocketSpecusFrame(want)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.opcode != vectors.WebSocket.Opcode || decoded.fin != vectors.WebSocket.FinalFragment ||
		decoded.rsv != vectors.WebSocket.RSV || decoded.closeCode != vectors.WebSocket.CloseCode ||
		string(decoded.payload) != vectors.WebSocket.PayloadUTF8 {
		t.Fatalf("SWS2 decoded frame = %#v", decoded)
	}
	for name, value := range map[string]string{
		"invalid magic": vectors.WebSocket.InvalidMagicHex,
		"truncated":     vectors.WebSocket.TruncatedHex,
		"trailing":      vectors.WebSocket.TrailingHex,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeWebSocketSpecusFrame(decodeVectorHex(t, value)); err == nil {
				t.Fatal("malformed SWS2 vector was accepted")
			}
		})
	}
}

func TestApplicationProtocolMatchesCentralSTMSG2Vector(t *testing.T) {
	vectors := readApplicationProtocolVectors(t)
	v := vectors.ClientMessage
	message := peerAppMessage{
		Type: v.Type, ID: v.ID,
		FromClientID: v.FromClientID, FromClientName: v.FromClientName,
		ToClientID: v.ToClientID, ToClientName: v.ToClientName,
		Message: v.Message, CreatedAtMillis: v.CreatedAtMillis,
	}
	encoded, err := encodePeerAppMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	want := decodeVectorHex(t, v.PayloadHex)
	if !bytes.Equal(encoded, want) {
		t.Fatalf("STMSG2 payload = %s, want %s", encoded, want)
	}
	decoded, ok := decodePeerAppMessage(want)
	if !ok || *decoded != message {
		t.Fatalf("STMSG2 decoded message = %#v, ok=%v", decoded, ok)
	}
}

func readApplicationProtocolVectors(t *testing.T) applicationProtocolVectors {
	t.Helper()
	var vectors applicationProtocolVectors
	readRepositoryJSON(t, "protocol/test-vectors/application-protocol-v2.json", &vectors)
	return vectors
}

func readRepositoryJSON(t *testing.T, relative string, target any) {
	t.Helper()
	path := findRepositoryFile(t, filepath.FromSlash(relative))
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(contents, target); err != nil {
		t.Fatal(err)
	}
}

func findRepositoryFile(t *testing.T, relative string) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for depth := 0; depth < 8; depth++ {
		candidate := filepath.Join(directory, relative)
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
		directory = parent
	}
	t.Fatalf("cannot locate repository file %s", relative)
	return ""
}

func decodeVectorHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
