package client

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
)

const (
	peerDataFrameMagic      uint32 = 0x53504d31
	peerDataFrameVersion    byte   = 1
	peerDataFrameTypeData   byte   = 1
	peerDataFrameNonceBytes        = 12
	peerDataFrameAADBytes          = 4 + 2 + 8*4 + peerDataFrameNonceBytes
	peerDataFrameTagBytes          = 16
	peerDataFrameMinBytes          = peerDataFrameAADBytes + 4 + peerDataFrameTagBytes
	peerDataFrameMaxBytes          = 65535
)

var (
	x25519PublicKeyDERPrefix  = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00}
	x25519PrivateKeyDERPrefix = []byte{0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20}
)

type peerDataFrame struct {
	SessionID    int64
	FromClientID int64
	ToClientID   int64
	Sequence     uint64
	Payload      []byte
}

type peerReplayWindow struct {
	highest uint64
	bits    uint64
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
	salt := sha256.Sum256([]byte(fmt.Sprintf("shuai-peer-mesh\n%d\n%s\n%d\n%d", sessionID, sessionToken, minID, maxID)))
	prk := hmacSHA256(salt[:], sharedSecret)
	return hkdfExpandSHA256(prk, []byte("shuai-peer-mesh/aes-gcm/v1"), 32), nil
}

func encodePeerDataFrame(aesKey []byte, sessionID, fromClientID, toClientID int64, sequence uint64, payload []byte) ([]byte, error) {
	if len(aesKey) != 32 {
		return nil, fmt.Errorf("peer data frame AES key must be 32 bytes")
	}
	if sequence == 0 || sequence > math.MaxInt64 {
		return nil, fmt.Errorf("peer data frame sequence out of range")
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, peerDataFrameNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aad := make([]byte, peerDataFrameAADBytes)
	writePeerFrameHeader(aad, sessionID, fromClientID, toClientID, sequence, nonce)
	ciphertext := gcm.Seal(nil, nonce, payload, aad)
	if peerDataFrameAADBytes+4+len(ciphertext) > peerDataFrameMaxBytes {
		return nil, fmt.Errorf("peer data frame is too large")
	}
	frame := make([]byte, peerDataFrameAADBytes+4+len(ciphertext))
	copy(frame, aad)
	binary.BigEndian.PutUint32(frame[peerDataFrameAADBytes:], uint32(len(ciphertext)))
	copy(frame[peerDataFrameAADBytes+4:], ciphertext)
	return frame, nil
}

func decodePeerDataFrame(aesKey []byte, packet []byte) (*peerDataFrame, error) {
	if len(aesKey) != 32 {
		return nil, fmt.Errorf("peer data frame AES key must be 32 bytes")
	}
	if len(packet) < peerDataFrameMinBytes {
		return nil, fmt.Errorf("peer data frame is too short")
	}
	if binary.BigEndian.Uint32(packet[0:4]) != peerDataFrameMagic {
		return nil, fmt.Errorf("invalid peer data frame magic")
	}
	if packet[4] != peerDataFrameVersion || packet[5] != peerDataFrameTypeData {
		return nil, fmt.Errorf("unsupported peer data frame version/type")
	}
	cipherLength := int(binary.BigEndian.Uint32(packet[peerDataFrameAADBytes:]))
	if cipherLength < peerDataFrameTagBytes || len(packet) != peerDataFrameAADBytes+4+cipherLength {
		return nil, fmt.Errorf("invalid peer data frame ciphertext length")
	}
	sessionID := int64(binary.BigEndian.Uint64(packet[6:14]))
	fromClientID := int64(binary.BigEndian.Uint64(packet[14:22]))
	toClientID := int64(binary.BigEndian.Uint64(packet[22:30]))
	sequence := binary.BigEndian.Uint64(packet[30:38])
	nonce := packet[38:50]
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	payload, err := gcm.Open(nil, nonce, packet[peerDataFrameAADBytes+4:], packet[:peerDataFrameAADBytes])
	if err != nil {
		return nil, fmt.Errorf("decrypt peer data frame: %w", err)
	}
	return &peerDataFrame{
		SessionID:    sessionID,
		FromClientID: fromClientID,
		ToClientID:   toClientID,
		Sequence:     sequence,
		Payload:      payload,
	}, nil
}

func looksLikePeerDataFrame(packet []byte) bool {
	return len(packet) >= 4 && binary.BigEndian.Uint32(packet[0:4]) == peerDataFrameMagic
}

func (window *peerReplayWindow) accept(sequence uint64) bool {
	if sequence == 0 {
		return false
	}
	if window.highest == 0 {
		window.highest = sequence
		window.bits = 1
		return true
	}
	if sequence > window.highest {
		shift := sequence - window.highest
		if shift >= 64 {
			window.bits = 1
		} else {
			window.bits = (window.bits << shift) | 1
		}
		window.highest = sequence
		return true
	}
	offset := window.highest - sequence
	if offset >= 64 {
		return false
	}
	mask := uint64(1) << offset
	if window.bits&mask != 0 {
		return false
	}
	window.bits |= mask
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

func writePeerFrameHeader(header []byte, sessionID, fromClientID, toClientID int64, sequence uint64, nonce []byte) {
	binary.BigEndian.PutUint32(header[0:4], peerDataFrameMagic)
	header[4] = peerDataFrameVersion
	header[5] = peerDataFrameTypeData
	binary.BigEndian.PutUint64(header[6:14], uint64(sessionID))
	binary.BigEndian.PutUint64(header[14:22], uint64(fromClientID))
	binary.BigEndian.PutUint64(header[22:30], uint64(toClientID))
	binary.BigEndian.PutUint64(header[30:38], sequence)
	copy(header[38:50], nonce)
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
