package client

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
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
	frame, err := encodePeerDataFrame(key, 1001, 1, 2, 1, payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePeerDataFrame(key, frame)
	if err != nil {
		t.Fatal(err)
	}
	sessionID, ok := peerDataFrameSessionID(frame)
	if !ok || sessionID != 1001 {
		t.Fatalf("peerDataFrameSessionID() = %d/%v, want 1001/true", sessionID, ok)
	}
	if decoded.SessionID != 1001 || decoded.FromClientID != 1 || decoded.ToClientID != 2 || decoded.Sequence != 1 {
		t.Fatalf("unexpected frame header: %+v", decoded)
	}
	if !bytes.Equal(decoded.Payload, payload) {
		t.Fatalf("payload mismatch: %q", decoded.Payload)
	}
}

func TestPeerDataFrameRejectsWrongKey(t *testing.T) {
	frame, err := encodePeerDataFrame(bytes.Repeat([]byte{7}, 32), 1001, 1, 2, 1, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodePeerDataFrame(bytes.Repeat([]byte{8}, 32), frame); err == nil {
		t.Fatal("wrong key should fail")
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
	if !window.accept(80) {
		t.Fatal("new high packet should be accepted")
	}
	if window.accept(15) {
		t.Fatal("packet outside replay window should be rejected")
	}
}
