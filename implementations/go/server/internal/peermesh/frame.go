package peermesh

import "encoding/binary"

const (
	peerDataMagic       = 0x53504d32 // SPM2
	peerDataHeaderBytes = 20
	peerDataTagBytes    = 16
	peerDataMaxBytes    = 65535
)

type DataFrameHeader struct {
	SessionID int64
	Sequence  int64
}

func LooksLikeDataFrame(frame []byte) bool {
	return len(frame) >= 4 && binary.BigEndian.Uint32(frame[:4]) == peerDataMagic
}

func ParseDataFrameHeader(frame []byte) (DataFrameHeader, bool) {
	if len(frame) < peerDataHeaderBytes+peerDataTagBytes || len(frame) > peerDataMaxBytes || !LooksLikeDataFrame(frame) {
		return DataFrameHeader{}, false
	}
	sequence := int64(binary.BigEndian.Uint64(frame[12:20]))
	if sequence <= 0 {
		return DataFrameHeader{}, false
	}
	return DataFrameHeader{
		SessionID: int64(binary.BigEndian.Uint64(frame[4:12])),
		Sequence:  sequence,
	}, true
}
