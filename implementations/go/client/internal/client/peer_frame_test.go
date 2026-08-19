package client

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestPeerMeshDeriveAESKeyMatchesBothSides(t *testing.T) {
	alice, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aliceKey, err := derivePeerMeshAESKey(alice, encodeX25519PublicKeyDER(bob.PublicKey()), 1001, "token", 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	bobKey, err := derivePeerMeshAESKey(bob, encodeX25519PublicKeyDER(alice.PublicKey()), 1001, "token", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aliceKey, bobKey) {
		t.Fatal("derived keys differ")
	}
}

func TestPeerMeshDeriveAESKeyAcceptsRawPublicKey(t *testing.T) {
	alice, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rawPublic := base64.StdEncoding.EncodeToString(bob.PublicKey().Bytes())
	if _, err := derivePeerMeshAESKey(alice, rawPublic, 1001, "token", 1, 2); err != nil {
		t.Fatalf("raw public key should be accepted: %v", err)
	}
}

func TestPeerDataFrameRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	payload := []byte("hello peer mesh")
	frame, err := encodePeerDataFrame(key, 1001, 1, 2, "epoch-a", 1, payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePeerDataFrame(key, 1, 2, "epoch-a", frame)
	if err != nil {
		t.Fatal(err)
	}
	sessionID, ok := peerDataFrameSessionID(frame)
	if !ok || sessionID != 1001 {
		t.Fatalf("peerDataFrameSessionID() = %d/%v, want 1001/true", sessionID, ok)
	}
	if decoded.SessionID != 1001 || decoded.Sequence != 1 {
		t.Fatalf("unexpected frame header: %+v", decoded)
	}
	if !bytes.Equal(decoded.Payload, payload) {
		t.Fatalf("payload mismatch: %q", decoded.Payload)
	}
}

func TestPeerDataFrameRejectsWrongKey(t *testing.T) {
	frame, err := encodePeerDataFrame(bytes.Repeat([]byte{7}, 32), 1001, 1, 2, "epoch-a", 1, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodePeerDataFrame(bytes.Repeat([]byte{8}, 32), 1, 2, "epoch-a", frame); err == nil {
		t.Fatal("wrong key should fail")
	}
}

func TestPeerDataFrameCanonicalVector(t *testing.T) {
	var vector struct {
		SessionKeyHex  string `json:"sessionKeyHex"`
		SessionID      int64  `json:"sessionId"`
		FromClientID   int64  `json:"fromClientId"`
		ToClientID     int64  `json:"toClientId"`
		SenderKeyEpoch string `json:"senderKeyEpoch"`
		Sequence       uint64 `json:"sequence"`
		PlaintextUTF8  string `json:"plaintextUtf8"`
		FrameHex       string `json:"frameHex"`
	}
	readRepositoryJSON(t, "protocol/test-vectors/peer-mesh-spm2.json", &vector)
	key := decodeVectorHex(t, vector.SessionKeyHex)
	frame, err := encodePeerDataFrame(
		key, vector.SessionID, vector.FromClientID, vector.ToClientID,
		vector.SenderKeyEpoch, vector.Sequence, []byte(vector.PlaintextUTF8))
	if err != nil {
		t.Fatal(err)
	}
	want := decodeVectorHex(t, vector.FrameHex)
	if !bytes.Equal(want, frame) {
		t.Fatalf("SPM2 wire vector mismatch:\n got %x\nwant %x", frame, want)
	}
	decoded, err := decodePeerDataFrame(key, vector.FromClientID, vector.ToClientID, vector.SenderKeyEpoch, frame)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SessionID != vector.SessionID || decoded.Sequence != vector.Sequence {
		t.Fatalf("unexpected SPM2 header: %+v", decoded)
	}
	if !bytes.Equal(decoded.Payload, []byte(vector.PlaintextUTF8)) {
		t.Fatalf("payload mismatch: %q", decoded.Payload)
	}
	if _, err := decodePeerDataFrame(key, vector.ToClientID, vector.FromClientID, vector.SenderKeyEpoch, frame); err == nil {
		t.Fatal("direction change should invalidate the SPM2 traffic key and tag")
	}
	if _, err := encodePeerDataFrame(
		key, vector.SessionID, vector.FromClientID, vector.ToClientID, vector.SenderKeyEpoch, 0, nil); err == nil {
		t.Fatal("encoder should reject sequence zero")
	}
}

func TestPeerDataFrameSessionIDRejectsMalformedFrame(t *testing.T) {
	if sessionID, ok := peerDataFrameSessionID([]byte{1, 2, 3}); ok || sessionID != 0 {
		t.Fatalf("peerDataFrameSessionID() = %d/%v, want 0/false", sessionID, ok)
	}
}

func TestPeerReplayWindowRejectsDuplicateAndOldPackets(t *testing.T) {
	var window peerReplayWindow
	if !window.accept(10) {
		t.Fatal("first packet should be accepted")
	}
	if window.accept(10) {
		t.Fatal("duplicate packet should be rejected")
	}
	if !window.accept(9) {
		t.Fatal("out-of-order packet inside window should be accepted once")
	}
	if window.accept(9) {
		t.Fatal("duplicate out-of-order packet should be rejected")
	}
	if !window.accept(5000) {
		t.Fatal("new high packet should be accepted")
	}
	if window.accept(15) {
		t.Fatal("packet outside replay window should be rejected")
	}
}

func TestPeerSessionReplayWindowRejectsDuplicates(t *testing.T) {
	session := &peerMeshSession{}
	if !session.acceptInboundFrame(&peerDataFrame{Sequence: 7}) {
		t.Fatal("first SPM2 sequence should be accepted")
	}
	if session.acceptInboundFrame(&peerDataFrame{Sequence: 7}) {
		t.Fatal("duplicate sequence should be rejected")
	}
	if session.acceptInboundFrame(&peerDataFrame{Sequence: 0}) {
		t.Fatal("sequence zero must be rejected")
	}
}

func BenchmarkPeerDataFrameCodec(b *testing.B) {
	for _, payloadBytes := range []int{64, 512, 1200} {
		b.Run(fmt.Sprintf("encode/%d", payloadBytes), func(b *testing.B) {
			key := bytes.Repeat([]byte{7}, 32)
			payload := make([]byte, payloadBytes)
			codec, err := newPeerDataFrameTrafficCodec(key, 1001, 1, 2, "epoch-a")
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(payloadBytes))
			for index := 0; index < b.N; index++ {
				if _, err := codec.encode(1001, uint64(index)+1, payload); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("decode/%d", payloadBytes), func(b *testing.B) {
			key := bytes.Repeat([]byte{7}, 32)
			frame, err := encodePeerDataFrame(key, 1001, 1, 2, "epoch-a", 1, make([]byte, payloadBytes))
			if err != nil {
				b.Fatal(err)
			}
			codec, err := newPeerDataFrameTrafficCodec(key, 1001, 1, 2, "epoch-a")
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(payloadBytes))
			for index := 0; index < b.N; index++ {
				if _, err := codec.decode(frame, 1001); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestPeerDataFrameKeyEpochIsolatesNonceSpace(t *testing.T) {
	// A restarted client may be handed back the same sessionID/token while its sequence
	// restarts at 1. The epoch must change the traffic key, otherwise the same nonce space
	// is replayed under the same AES-GCM key.
	key := bytes.Repeat([]byte{7}, 32)
	before, err := encodePeerDataFrame(key, 1001, 1, 2, "epoch-before-restart", 1, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	after, err := encodePeerDataFrame(key, 1001, 1, 2, "epoch-after-restart", 1, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("a new key epoch must produce a different frame for the same sequence")
	}
	if _, err := decodePeerDataFrame(key, 1, 2, "epoch-after-restart", before); err == nil {
		t.Fatal("frames from the previous epoch must not decrypt under the new epoch")
	}
	if _, err := encodePeerDataFrame(key, 1001, 1, 2, "  ", 1, []byte("payload")); err == nil {
		t.Fatal("a blank key epoch must be rejected")
	}
}
