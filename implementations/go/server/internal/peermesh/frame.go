package peermesh

import "encoding/binary"

const (
	peerDataMagic       = 0x53504d31
	peerDataVersion     = 1
	peerDataTypeData    = 1
	peerDataHeaderBytes = 50
)

type DataFrameHeader struct {
	SessionID    int64
	FromClientID int64
	ToClientID   int64
	Sequence     int64
}

func ParseDataFrameHeader(frame []byte) (DataFrameHeader, bool) {
	if len(frame) < peerDataHeaderBytes || binary.BigEndian.Uint32(frame[:4]) != peerDataMagic {
		return DataFrameHeader{}, false
	}
	if frame[4] != peerDataVersion || frame[5] != peerDataTypeData {
		return DataFrameHeader{}, false
	}
	return DataFrameHeader{
		SessionID:    int64(binary.BigEndian.Uint64(frame[6:14])),
		FromClientID: int64(binary.BigEndian.Uint64(frame[14:22])),
		ToClientID:   int64(binary.BigEndian.Uint64(frame[22:30])),
		Sequence:     int64(binary.BigEndian.Uint64(frame[30:38])),
	}, true
}
