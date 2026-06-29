package client

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
)

const (
	stunMagicCookie        = 0x2112A442
	stunHeaderBytes        = 20
	stunTransactionIDBytes = 12

	stunBindingRequest          = 0x0001
	stunBindingSuccess          = 0x0101
	stunAllocateRequest         = 0x0003
	stunAllocateSuccess         = 0x0103
	stunRefreshRequest          = 0x0004
	stunRefreshSuccess          = 0x0104
	stunCreatePermissionRequest = 0x0008
	stunCreatePermissionSuccess = 0x0108
	stunSendIndication          = 0x0016
	stunDataIndication          = 0x0017

	stunAttrLifetime           = 0x000D
	stunAttrXorPeerAddress     = 0x0012
	stunAttrData               = 0x0013
	stunAttrXorRelayedAddress  = 0x0016
	stunAttrRequestedTransport = 0x0019
	stunAttrXorMappedAddress   = 0x0020
	stunAttrSoftware           = 0x8022
	stunAttrOtherAddress       = 0x802C

	stunTransportUDP = 17
)

type stunAttribute struct {
	Type  uint16
	Value []byte
}

type stunMessage struct {
	Type          uint16
	TransactionID [stunTransactionIDBytes]byte
	Attributes    []stunAttribute
}

func newStunMessage(typ uint16, tx [stunTransactionIDBytes]byte, attrs ...stunAttribute) stunMessage {
	return stunMessage{Type: typ, TransactionID: tx, Attributes: attrs}
}

func newStunTransactionID() [stunTransactionIDBytes]byte {
	var tx [stunTransactionIDBytes]byte
	_, _ = rand.Read(tx[:])
	return tx
}

func stunTransactionHex(tx [stunTransactionIDBytes]byte) string {
	return hex.EncodeToString(tx[:])
}

func looksLikeStun(packet []byte) bool {
	if len(packet) < stunHeaderBytes || packet[0]&0xC0 != 0 {
		return false
	}
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	cookie := binary.BigEndian.Uint32(packet[4:8])
	return cookie == stunMagicCookie && length+stunHeaderBytes <= len(packet)
}

func parseStunMessage(packet []byte) (*stunMessage, error) {
	if !looksLikeStun(packet) {
		return nil, fmt.Errorf("not a stun message")
	}
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	end := stunHeaderBytes + length
	message := &stunMessage{Type: binary.BigEndian.Uint16(packet[:2])}
	copy(message.TransactionID[:], packet[8:20])
	for offset := stunHeaderBytes; offset < end; {
		if end-offset < 4 {
			return nil, fmt.Errorf("truncated stun attribute")
		}
		attrType := binary.BigEndian.Uint16(packet[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		offset += 4
		if attrLen > end-offset {
			return nil, fmt.Errorf("invalid stun attribute length")
		}
		value := append([]byte(nil), packet[offset:offset+attrLen]...)
		message.Attributes = append(message.Attributes, stunAttribute{Type: attrType, Value: value})
		offset += attrLen + stunPadding(attrLen)
	}
	return message, nil
}

func (m stunMessage) bytes() []byte {
	length := 0
	for _, attr := range m.Attributes {
		length += 4 + len(attr.Value) + stunPadding(len(attr.Value))
	}
	packet := make([]byte, stunHeaderBytes+length)
	binary.BigEndian.PutUint16(packet[:2], m.Type)
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	binary.BigEndian.PutUint32(packet[4:8], stunMagicCookie)
	copy(packet[8:20], m.TransactionID[:])
	offset := stunHeaderBytes
	for _, attr := range m.Attributes {
		binary.BigEndian.PutUint16(packet[offset:offset+2], attr.Type)
		binary.BigEndian.PutUint16(packet[offset+2:offset+4], uint16(len(attr.Value)))
		offset += 4
		copy(packet[offset:offset+len(attr.Value)], attr.Value)
		offset += len(attr.Value) + stunPadding(len(attr.Value))
	}
	return packet
}

func (m stunMessage) first(attrType uint16) (stunAttribute, bool) {
	for _, attr := range m.Attributes {
		if attr.Type == attrType {
			return attr, true
		}
	}
	return stunAttribute{}, false
}

func (m stunMessage) xorMappedAddress() (*net.UDPAddr, bool) {
	attr, ok := m.first(stunAttrXorMappedAddress)
	if !ok {
		return nil, false
	}
	return decodeStunXorAddress(attr.Value, m.TransactionID)
}

func (m stunMessage) xorRelayedAddress() (*net.UDPAddr, bool) {
	attr, ok := m.first(stunAttrXorRelayedAddress)
	if !ok {
		return nil, false
	}
	return decodeStunXorAddress(attr.Value, m.TransactionID)
}

func (m stunMessage) xorPeerAddress() (*net.UDPAddr, bool) {
	attr, ok := m.first(stunAttrXorPeerAddress)
	if !ok {
		return nil, false
	}
	return decodeStunXorAddress(attr.Value, m.TransactionID)
}

func (m stunMessage) otherAddress() (*net.UDPAddr, bool) {
	attr, ok := m.first(stunAttrOtherAddress)
	if !ok {
		return nil, false
	}
	return decodeStunXorAddress(attr.Value, m.TransactionID)
}

func (m stunMessage) data() ([]byte, bool) {
	attr, ok := m.first(stunAttrData)
	if !ok {
		return nil, false
	}
	return append([]byte(nil), attr.Value...), true
}

func (m stunMessage) lifetimeSeconds(fallback int64) int64 {
	attr, ok := m.first(stunAttrLifetime)
	if !ok || len(attr.Value) != 4 {
		return fallback
	}
	return int64(binary.BigEndian.Uint32(attr.Value))
}

func newStunAttrXorPeerAddress(addr *net.UDPAddr, tx [stunTransactionIDBytes]byte) stunAttribute {
	return stunAttribute{Type: stunAttrXorPeerAddress, Value: encodeStunXorAddress(addr, tx)}
}

func stunAttrDataValue(payload []byte) stunAttribute {
	return stunAttribute{Type: stunAttrData, Value: append([]byte(nil), payload...)}
}

func stunAttrLifetimeValue(seconds int64) stunAttribute {
	if seconds < 0 {
		seconds = 0
	}
	if seconds > 1<<32-1 {
		seconds = 1<<32 - 1
	}
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value, uint32(seconds))
	return stunAttribute{Type: stunAttrLifetime, Value: value}
}

func stunAttrRequestedUDPTransport() stunAttribute {
	return stunAttribute{Type: stunAttrRequestedTransport, Value: []byte{stunTransportUDP, 0, 0, 0}}
}

func stunAttrSoftwareValue(value string) stunAttribute {
	return stunAttribute{Type: stunAttrSoftware, Value: []byte(value)}
}

func encodeStunXorAddress(addr *net.UDPAddr, tx [stunTransactionIDBytes]byte) []byte {
	if addr == nil || addr.IP == nil {
		return nil
	}
	ip4 := addr.IP.To4()
	if ip4 != nil {
		value := make([]byte, 8)
		value[1] = 0x01
		binary.BigEndian.PutUint16(value[2:4], uint16(addr.Port^(stunMagicCookie>>16)))
		cookie := []byte{0x21, 0x12, 0xA4, 0x42}
		for i := 0; i < 4; i++ {
			value[4+i] = ip4[i] ^ cookie[i]
		}
		return value
	}
	ip16 := addr.IP.To16()
	if ip16 == nil {
		return nil
	}
	value := make([]byte, 20)
	value[1] = 0x02
	binary.BigEndian.PutUint16(value[2:4], uint16(addr.Port^(stunMagicCookie>>16)))
	mask := make([]byte, 16)
	binary.BigEndian.PutUint32(mask[:4], stunMagicCookie)
	copy(mask[4:], tx[:])
	for i := 0; i < 16; i++ {
		value[4+i] = ip16[i] ^ mask[i]
	}
	return value
}

func decodeStunXorAddress(value []byte, tx [stunTransactionIDBytes]byte) (*net.UDPAddr, bool) {
	if len(value) != 8 && len(value) != 20 {
		return nil, false
	}
	port := int(binary.BigEndian.Uint16(value[2:4]) ^ uint16(stunMagicCookie>>16))
	switch value[1] {
	case 0x01:
		if len(value) < 8 {
			return nil, false
		}
		cookie := []byte{0x21, 0x12, 0xA4, 0x42}
		ip := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			ip[i] = value[4+i] ^ cookie[i]
		}
		return &net.UDPAddr{IP: ip, Port: port}, true
	case 0x02:
		if len(value) < 20 {
			return nil, false
		}
		mask := make([]byte, 16)
		binary.BigEndian.PutUint32(mask[:4], stunMagicCookie)
		copy(mask[4:], tx[:])
		ip := make(net.IP, 16)
		for i := 0; i < 16; i++ {
			ip[i] = value[4+i] ^ mask[i]
		}
		return &net.UDPAddr{IP: ip, Port: port}, true
	default:
		return nil, false
	}
}

func stunPadding(length int) int {
	return (4 - (length % 4)) % 4
}
