package client

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
)

const (
	peerDataFrameMagic       uint32 = 0x53504d32
	peerDataFrameNonceBytes         = 12
	peerDataFrameTagBytes           = 16
	peerDataFrameMaxBytes           = 65535
	peerDataFrameHeaderBytes        = 4 + 8*2
	peerDataFrameMinBytes           = peerDataFrameHeaderBytes + peerDataFrameTagBytes
	peerReplayWindowSize            = 4096
	peerReplayWindowMask            = peerReplayWindowSize - 1
)

var (
	x25519PublicKeyDERPrefix  = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00}
	x25519PrivateKeyDERPrefix = []byte{0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20}
)

type peerDataFrame struct {
	SessionID int64
	Sequence  uint64
	Payload   []byte
}

type peerDataFrameTrafficCodec struct {
	aead        cipher.AEAD
	noncePrefix uint32
	mu          sync.Mutex
}

type peerReplayWindow struct {
	highest   uint64
	sequences [peerReplayWindowSize]uint64
}

func derivePeerMeshAESKey(localPrivate *ecdh.PrivateKey, remotePublicKeyBase64 string, sessionID int64, sessionToken string, localClientID, remoteClientID int64) ([]byte, error) {
	if localPrivate == nil {
		return nil, fmt.Errorf("missing local peer private key")
	}
	remoteRaw, err := decodeX25519PublicKey(remotePublicKeyBase64)
	if err != nil {
		return nil, err
	}
	remotePublic, err := ecdh.X25519().NewPublicKey(remoteRaw)
	if err != nil {
		return nil, fmt.Errorf("decode remote peer public key: %w", err)
	}
	sharedSecret, err := localPrivate.ECDH(remotePublic)
	if err != nil {
		return nil, fmt.Errorf("derive X25519 secret: %w", err)
	}
	minID, maxID := localClientID, remoteClientID
	if minID > maxID {
		minID, maxID = maxID, minID
	}
	salt := sha256.Sum256([]byte(fmt.Sprintf("specus-peer-mesh\n%d\n%s\n%d\n%d", sessionID, sessionToken, minID, maxID)))
	prk := hmacSHA256(salt[:], sharedSecret)
	return hkdfExpandSHA256(prk, []byte("specus-peer-mesh/aes-gcm/v1"), 32), nil
}

func encodePeerDataFrame(aesKey []byte, sessionID, fromClientID, toClientID int64, senderKeyEpoch string, sequence uint64, payload []byte) ([]byte, error) {
	codec, err := newPeerDataFrameTrafficCodec(aesKey, sessionID, fromClientID, toClientID, senderKeyEpoch)
	if err != nil {
		return nil, err
	}
	return codec.encode(sessionID, sequence, payload)
}

func newPeerDataFrameTrafficCodec(aesKey []byte, sessionID, fromClientID, toClientID int64, senderKeyEpoch string) (*peerDataFrameTrafficCodec, error) {
	if len(aesKey) != 32 || sessionID <= 0 || fromClientID <= 0 || toClientID <= 0 || fromClientID == toClientID {
		return nil, fmt.Errorf("invalid SPM2 key, session, or direction")
	}
	if strings.TrimSpace(senderKeyEpoch) == "" {
		return nil, fmt.Errorf("SPM2 traffic key requires the sender key epoch")
	}
	trafficKey, noncePrefix := derivePeerDataFrameV2TrafficMaterial(aesKey, sessionID, fromClientID, toClientID, senderKeyEpoch)
	block, err := aes.NewCipher(trafficKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &peerDataFrameTrafficCodec{aead: aead, noncePrefix: noncePrefix}, nil
}

func (codec *peerDataFrameTrafficCodec) encode(sessionID int64, sequence uint64, payload []byte) ([]byte, error) {
	if codec == nil || sessionID <= 0 || sequence == 0 {
		return nil, fmt.Errorf("invalid SPM2 codec, session, or sequence")
	}
	if peerDataFrameHeaderBytes+len(payload)+peerDataFrameTagBytes > peerDataFrameMaxBytes {
		return nil, fmt.Errorf("peer data frame is too large")
	}
	frame := make([]byte, peerDataFrameHeaderBytes, peerDataFrameHeaderBytes+len(payload)+peerDataFrameTagBytes)
	binary.BigEndian.PutUint32(frame[0:4], peerDataFrameMagic)
	binary.BigEndian.PutUint64(frame[4:12], uint64(sessionID))
	binary.BigEndian.PutUint64(frame[12:20], sequence)
	nonce := peerDataFrameV2Nonce(codec.noncePrefix, sequence)
	codec.mu.Lock()
	frame = codec.aead.Seal(frame, nonce, payload, frame[:peerDataFrameHeaderBytes])
	codec.mu.Unlock()
	return frame, nil
}

func decodePeerDataFrame(aesKey []byte, expectedFromClientID, expectedToClientID int64, senderKeyEpoch string, packet []byte) (*peerDataFrame, error) {
	if len(aesKey) != 32 || len(packet) < peerDataFrameMinBytes || len(packet) > peerDataFrameMaxBytes || binary.BigEndian.Uint32(packet[:4]) != peerDataFrameMagic {
		return nil, fmt.Errorf("invalid SPM2 peer data frame")
	}
	sessionID := int64(binary.BigEndian.Uint64(packet[4:12]))
	sequence := binary.BigEndian.Uint64(packet[12:20])
	if sessionID <= 0 || expectedFromClientID <= 0 || expectedToClientID <= 0 || expectedFromClientID == expectedToClientID || sequence == 0 {
		return nil, fmt.Errorf("invalid SPM2 session, direction, or sequence")
	}
	codec, err := newPeerDataFrameTrafficCodec(aesKey, sessionID, expectedFromClientID, expectedToClientID, senderKeyEpoch)
	if err != nil {
		return nil, err
	}
	return codec.decode(packet, sessionID)
}

func (codec *peerDataFrameTrafficCodec) decode(packet []byte, expectedSessionID int64) (*peerDataFrame, error) {
	if codec == nil || len(packet) < peerDataFrameMinBytes || len(packet) > peerDataFrameMaxBytes ||
		binary.BigEndian.Uint32(packet[:4]) != peerDataFrameMagic {
		return nil, fmt.Errorf("invalid SPM2 peer data frame")
	}
	sessionID := int64(binary.BigEndian.Uint64(packet[4:12]))
	sequence := binary.BigEndian.Uint64(packet[12:20])
	if sessionID <= 0 || sessionID != expectedSessionID || sequence == 0 {
		return nil, fmt.Errorf("invalid SPM2 session or sequence")
	}
	codec.mu.Lock()
	payload, err := codec.aead.Open(nil, peerDataFrameV2Nonce(codec.noncePrefix, sequence),
		packet[peerDataFrameHeaderBytes:], packet[:peerDataFrameHeaderBytes])
	codec.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("decrypt SPM2 peer data frame: %w", err)
	}
	return &peerDataFrame{
		SessionID: sessionID,
		Sequence:  sequence,
		Payload:   payload,
	}, nil
}

func peerDataFrameSessionID(packet []byte) (int64, bool) {
	if len(packet) < peerDataFrameMinBytes || len(packet) > peerDataFrameMaxBytes {
		return 0, false
	}
	if binary.BigEndian.Uint32(packet[0:4]) != peerDataFrameMagic {
		return 0, false
	}
	return int64(binary.BigEndian.Uint64(packet[4:12])), true
}

func looksLikePeerDataFrame(packet []byte) bool {
	if len(packet) < 4 {
		return false
	}
	return binary.BigEndian.Uint32(packet[0:4]) == peerDataFrameMagic
}

// derivePeerDataFrameV2TrafficMaterial derives the one-way traffic key. senderKeyEpoch is the
// sender's per-process random epoch and is mandatory: sessionID/token are reused within the
// server session TTL and X25519 keys are persisted on disk, so without a fresh epoch a client
// restart would replay the same nonce space under the same AES-GCM key.
func derivePeerDataFrameV2TrafficMaterial(aesKey []byte, sessionID, fromClientID, toClientID int64, senderKeyEpoch string) ([]byte, uint32) {
	var salt [8]byte
	binary.BigEndian.PutUint64(salt[:], uint64(sessionID))
	prk := hmacSHA256(salt[:], aesKey)
	info := []byte(fmt.Sprintf("specus-peer-mesh/spm2/aes-gcm\n%d\n%d\n%d\n%s", sessionID, fromClientID, toClientID, senderKeyEpoch))
	material := hkdfExpandSHA256(prk, info, 36)
	return material[:32], binary.BigEndian.Uint32(material[32:36])
}

func peerDataFrameV2Nonce(prefix uint32, sequence uint64) []byte {
	nonce := make([]byte, peerDataFrameNonceBytes)
	binary.BigEndian.PutUint32(nonce[:4], prefix)
	binary.BigEndian.PutUint64(nonce[4:], sequence)
	return nonce
}

func (window *peerReplayWindow) accept(sequence uint64) bool {
	if sequence == 0 {
		return false
	}
	if window.highest >= peerReplayWindowSize && sequence <= window.highest-peerReplayWindowSize {
		return false
	}
	slot := sequence & peerReplayWindowMask
	if window.sequences[slot] == sequence {
		return false
	}
	window.sequences[slot] = sequence
	if sequence > window.highest {
		window.highest = sequence
	}
	return true
}

func encodeX25519PublicKeyDER(publicKey *ecdh.PublicKey) string {
	if publicKey == nil {
		return ""
	}
	encoded := append([]byte(nil), x25519PublicKeyDERPrefix...)
	encoded = append(encoded, publicKey.Bytes()...)
	return base64.StdEncoding.EncodeToString(encoded)
}

func decodeX25519PublicKey(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode remote peer public key: %w", err)
	}
	switch {
	case len(decoded) == 32:
		return decoded, nil
	case len(decoded) == len(x25519PublicKeyDERPrefix)+32 && bytes.Equal(decoded[:len(x25519PublicKeyDERPrefix)], x25519PublicKeyDERPrefix):
		return decoded[len(x25519PublicKeyDERPrefix):], nil
	default:
		return nil, fmt.Errorf("unsupported remote peer public key format")
	}
}

func decodeX25519PrivateKey(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode peer private key: %w", err)
	}
	switch {
	case len(decoded) == 32:
		return decoded, nil
	case len(decoded) == len(x25519PrivateKeyDERPrefix)+32 && bytes.Equal(decoded[:len(x25519PrivateKeyDERPrefix)], x25519PrivateKeyDERPrefix):
		return decoded[len(x25519PrivateKeyDERPrefix):], nil
	default:
		return nil, fmt.Errorf("unsupported peer private key format")
	}
}

func hkdfExpandSHA256(prk, info []byte, length int) []byte {
	result := make([]byte, length)
	previous := []byte{}
	copied := 0
	counter := byte(1)
	for copied < length {
		input := make([]byte, 0, len(previous)+len(info)+1)
		input = append(input, previous...)
		input = append(input, info...)
		input = append(input, counter)
		previous = hmacSHA256(prk, input)
		copied += copy(result[copied:], previous)
		counter++
	}
	return result
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}
