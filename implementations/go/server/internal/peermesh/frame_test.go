package peermesh

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParseDataFrameHeaderV2(t *testing.T) {
	var vector struct {
		SessionID int64  `json:"sessionId"`
		Sequence  int64  `json:"sequence"`
		FrameHex  string `json:"frameHex"`
	}
	contents, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..",
		"protocol", "test-vectors", "peer-mesh-spm2.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(contents, &vector); err != nil {
		t.Fatal(err)
	}
	frame, err := hex.DecodeString(vector.FrameHex)
	if err != nil {
		t.Fatal(err)
	}
	header, ok := ParseDataFrameHeader(frame)
	if !ok || header != (DataFrameHeader{SessionID: vector.SessionID, Sequence: vector.Sequence}) {
		t.Fatalf("unexpected SPM2 header: %+v/%v", header, ok)
	}

	binary.BigEndian.PutUint64(frame[12:20], 0)
	if _, ok := ParseDataFrameHeader(frame); ok {
		t.Fatal("SPM2 frame with zero sequence should be rejected")
	}
}

func TestParseDataFrameHeaderRejectsRemovedV1(t *testing.T) {
	frame := make([]byte, 70)
	binary.BigEndian.PutUint32(frame[:4], 0x53504d31)
	if LooksLikeDataFrame(frame) {
		t.Fatal("removed SPM1 frame must not be recognized")
	}
	if _, ok := ParseDataFrameHeader(frame); ok {
		t.Fatal("removed SPM1 frame must be rejected")
	}
}
