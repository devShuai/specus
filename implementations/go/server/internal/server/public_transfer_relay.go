package server

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

const (
	publicRelayHeaderBytes = 14
	publicAppHeaderBytes   = 72
	publicRelayMaxBytes    = 64 * 1024
	publicAppMaxBytes      = 8 * 1024 * 1024
	publicAppMaxChunks     = 2048
	publicAppTypeACK       = 127
)

var errInvalidPublicRelayFrame = errors.New("invalid public transfer relay frame")

type publicRelayClientFrame struct {
	targetPeerID string
	appType      byte
	appFrame     []byte
}

func decodePublicRelayClientFrame(frame []byte) (publicRelayClientFrame, error) {
	if len(frame) < publicRelayHeaderBytes+publicAppHeaderBytes || len(frame) > publicRelayMaxBytes ||
		string(frame[:4]) != "STWR" || frame[4] != 2 || frame[5] != 0 {
		return publicRelayClientFrame{}, errInvalidPublicRelayFrame
	}
	targetLen := int(binary.BigEndian.Uint16(frame[6:8]))
	sourceLen := int(binary.BigEndian.Uint16(frame[8:10]))
	payloadLen := int(binary.BigEndian.Uint32(frame[10:14]))
	if targetLen < 1 || targetLen > 512 || sourceLen != 0 || payloadLen < publicAppHeaderBytes ||
		publicRelayHeaderBytes+targetLen+payloadLen != len(frame) {
		return publicRelayClientFrame{}, errInvalidPublicRelayFrame
	}
	targetBytes := frame[publicRelayHeaderBytes : publicRelayHeaderBytes+targetLen]
	if !utf8.Valid(targetBytes) {
		return publicRelayClientFrame{}, errInvalidPublicRelayFrame
	}
	targetPeerID := string(targetBytes)
	if targetPeerID == "" {
		return publicRelayClientFrame{}, errInvalidPublicRelayFrame
	}
	for _, char := range targetPeerID {
		if char < 0x20 || char == 0x7f {
			return publicRelayClientFrame{}, errInvalidPublicRelayFrame
		}
	}
	appFrame := append([]byte(nil), frame[publicRelayHeaderBytes+targetLen:]...)
	appType, err := validatePublicAppFrame(appFrame)
	if err != nil {
		return publicRelayClientFrame{}, err
	}
	return publicRelayClientFrame{targetPeerID: targetPeerID, appType: appType, appFrame: appFrame}, nil
}

func encodePublicRelayServerFrame(targetPeerID, sourcePeerID string, appFrame []byte) ([]byte, error) {
	target := []byte(targetPeerID)
	source := []byte(sourcePeerID)
	if len(target) < 1 || len(target) > 512 || len(source) < 1 || len(source) > 512 ||
		!utf8.Valid(target) || !utf8.Valid(source) {
		return nil, errInvalidPublicRelayFrame
	}
	if _, err := validatePublicAppFrame(appFrame); err != nil {
		return nil, err
	}
	wireLen := publicRelayHeaderBytes + len(target) + len(source) + len(appFrame)
	if wireLen > publicRelayMaxBytes {
		return nil, errInvalidPublicRelayFrame
	}
	result := make([]byte, wireLen)
	copy(result[:4], "STWR")
	result[4] = 2
	binary.BigEndian.PutUint16(result[6:8], uint16(len(target)))
	binary.BigEndian.PutUint16(result[8:10], uint16(len(source)))
	binary.BigEndian.PutUint32(result[10:14], uint32(len(appFrame)))
	offset := publicRelayHeaderBytes
	copy(result[offset:], target)
	offset += len(target)
	copy(result[offset:], source)
	offset += len(source)
	copy(result[offset:], appFrame)
	return result, nil
}

func validatePublicAppFrame(frame []byte) (byte, error) {
	if len(frame) < publicAppHeaderBytes || string(frame[:4]) != "STAP" || frame[4] != 2 {
		return 0, errInvalidPublicRelayFrame
	}
	appType := frame[5]
	if appType != 1 && appType != 2 && appType != 3 && appType != publicAppTypeACK {
		return 0, errInvalidPublicRelayFrame
	}
	flags := binary.BigEndian.Uint16(frame[6:8])
	if flags & ^uint16(1) != 0 || appType == publicAppTypeACK && flags != 0 {
		return 0, errInvalidPublicRelayFrame
	}
	chunkIndex := binary.BigEndian.Uint32(frame[24:28])
	chunkCount := binary.BigEndian.Uint32(frame[28:32])
	totalLen := binary.BigEndian.Uint32(frame[32:36])
	payloadLen := binary.BigEndian.Uint32(frame[36:40])
	if chunkCount < 1 || chunkCount > publicAppMaxChunks || chunkIndex >= chunkCount ||
		totalLen > publicAppMaxBytes || payloadLen > totalLen ||
		uint64(publicAppHeaderBytes)+uint64(payloadLen) != uint64(len(frame)) {
		return 0, errInvalidPublicRelayFrame
	}
	return appType, nil
}
