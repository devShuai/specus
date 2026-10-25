package protocol

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type natMetadataVector struct {
	Version  int `json:"version"`
	Accepted []struct {
		Name        string `json:"name"`
		MetadataHex string `json:"metadataHex"`
	} `json:"accepted"`
	Rejected []struct {
		Name        string `json:"name"`
		MetadataHex string `json:"metadataHex"`
	} `json:"rejected"`
}

// openBody is the body of a NAT OPEN on stream 1 that carries metadata.
func openBody(t *testing.T, metadataHex string) []byte {
	t.Helper()
	metadata, err := hex.DecodeString(metadataHex)
	if err != nil {
		t.Fatalf("metadata hex: %v", err)
	}
	body := make([]byte, natBodyHeaderSize, natBodyHeaderSize+len(metadata))
	body[0] = NatOpen
	binary.BigEndian.PutUint16(body[2:4], uint16(len(metadata)))
	binary.BigEndian.PutUint32(body[4:8], 1)
	return append(body, metadata...)
}

// TestNatMetadataJSONVector replays protocol/test-vectors/nat-metadata-json-v1.json: NAT metadata
// is read strictly by RFC 8259 as one UTF-8 JSON object.
func TestNatMetadataJSONVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "protocol", "test-vectors",
		"nat-metadata-json-v1.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vector natMetadataVector
	if err := json.Unmarshal(raw, &vector); err != nil || vector.Version != 1 {
		t.Fatalf("vector: version %d, %v", vector.Version, err)
	}
	for _, c := range vector.Accepted {
		if _, err := DecodeNatMessage(openBody(t, c.MetadataHex)); err != nil {
			t.Errorf("%s: refused: %v", c.Name, err)
		}
	}
	for _, c := range vector.Rejected {
		if _, err := DecodeNatMessage(openBody(t, c.MetadataHex)); err == nil {
			t.Errorf("%s: accepted", c.Name)
		}
	}
	if len(vector.Accepted) != 8 || len(vector.Rejected) != 34 {
		t.Fatalf("vector has %d accepted and %d rejected cases, want 8 and 34",
			len(vector.Accepted), len(vector.Rejected))
	}
}
