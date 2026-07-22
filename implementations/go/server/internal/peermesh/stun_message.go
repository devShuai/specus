package peermesh

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
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
	stunBindingError            = 0x0111
	stunAllocateRequest         = 0x0003
	stunAllocateSuccess         = 0x0103
	stunAllocateError           = 0x0113
	stunRefreshRequest          = 0x0004
	stunRefreshSuccess          = 0x0104
	stunRefreshError            = 0x0114
	stunCreatePermissionRequest = 0x0008
	stunCreatePermissionSuccess = 0x0108
	stunCreatePermissionError   = 0x0118
	stunChannelBindRequest      = 0x0009
	stunChannelBindSuccess      = 0x0109
	stunChannelBindError        = 0x0119
	stunSendIndication          = 0x0016
	stunDataIndication          = 0x0017

	stunAttrChannelNumber      = 0x000C
	stunAttrErrorCode          = 0x0009
	stunAttrLifetime           = 0x000D
	stunAttrXorPeerAddress     = 0x0012
	stunAttrData               = 0x0013
	stunAttrXorRelayedAddress  = 0x0016
	stunAttrRequestedTransport = 0x0019
	stunAttrXorMappedAddress   = 0x0020
	stunAttrSoftware           = 0x8022
	stunAttrResponseOrigin     = 0x802B
	stunAttrOtherAddress       = 0x802C

	stunTransportUDP = 17

	stunAttrUsername         = 0x0006
	stunAttrMessageIntegrity = 0x0008
	stunAttrRealm            = 0x0014
	stunAttrNonce            = 0x0015
)

type stunAttribute struct {
	Type  uint16
	Value []byte
}

type stunMessage struct {
	Type          uint16
	TransactionID [stunTransactionIDBytes]byte
	Attributes    []stunAttribute
	Raw           []byte
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
	return cookie == stunMagicCookie && length+stunHeaderBytes == len(packet)
}

func parseStunMessage(packet []byte) (*stunMessage, error) {
	if !looksLikeStun(packet) {
		return nil, fmt.Errorf("not a stun message")
	}
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	end := stunHeaderBytes + length
	message := &stunMessage{Type: binary.BigEndian.Uint16(packet[:2])}
	message.Raw = append([]byte(nil), packet[:end]...)
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
	return m.serialize(m.attributeBytes(), m.Attributes)
}

func (m stunMessage) bytesWithIntegrity(key []byte) []byte {
	if len(key) == 0 {
		return m.bytes()
	}
	beforeIntegrity := m.serialize(m.attributeBytes()+24, m.Attributes)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(beforeIntegrity)
	digest := mac.Sum(nil)
	result := make([]byte, len(beforeIntegrity)+24)
	copy(result, beforeIntegrity)
	offset := len(beforeIntegrity)
	binary.BigEndian.PutUint16(result[offset:offset+2], stunAttrMessageIntegrity)
	binary.BigEndian.PutUint16(result[offset+2:offset+4], uint16(len(digest)))
	copy(result[offset+4:], digest)
	return result
}

func (m stunMessage) attributeBytes() int {
	length := 0
	for _, attr := range m.Attributes {
		length += 4 + len(attr.Value) + stunPadding(len(attr.Value))
	}
	return length
}

func (m stunMessage) serialize(declaredLength int, attrs []stunAttribute) []byte {
	actualLength := 0
	for _, attr := range attrs {
		actualLength += 4 + len(attr.Value) + stunPadding(len(attr.Value))
	}
	packet := make([]byte, stunHeaderBytes+actualLength)
	binary.BigEndian.PutUint16(packet[:2], m.Type)
	binary.BigEndian.PutUint16(packet[2:4], uint16(declaredLength))
	binary.BigEndian.PutUint32(packet[4:8], stunMagicCookie)
	copy(packet[8:20], m.TransactionID[:])
	offset := stunHeaderBytes
	for _, attr := range attrs {
		binary.BigEndian.PutUint16(packet[offset:offset+2], attr.Type)
		binary.BigEndian.PutUint16(packet[offset+2:offset+4], uint16(len(attr.Value)))
		offset += 4
		copy(packet[offset:offset+len(attr.Value)], attr.Value)
		offset += len(attr.Value) + stunPadding(len(attr.Value))
	}
	return packet
}

func (m stunMessage) verifyMessageIntegrity(key []byte) bool {
	packet := m.Raw
	if len(key) == 0 || !looksLikeStun(packet) {
		return false
	}
	end := stunHeaderBytes + int(binary.BigEndian.Uint16(packet[2:4]))
	for position := stunHeaderBytes; position < end; {
		if end-position < 4 {
			return false
		}
		attrType := binary.BigEndian.Uint16(packet[position : position+2])
		attrLength := int(binary.BigEndian.Uint16(packet[position+2 : position+4]))
		valueOffset := position + 4
		next := valueOffset + attrLength + stunPadding(attrLength)
		if attrLength > end-valueOffset || next > end {
			return false
		}
		if attrType == stunAttrMessageIntegrity {
			if attrLength != sha1.Size {
				return false
			}
			signed := append([]byte(nil), packet[:position]...)
			binary.BigEndian.PutUint16(signed[2:4], uint16(position+24-stunHeaderBytes))
			mac := hmac.New(sha1.New, key)
			_, _ = mac.Write(signed)
			return hmac.Equal(mac.Sum(nil), packet[valueOffset:valueOffset+attrLength])
		}
		position = next
	}
	return false
}

func (m stunMessage) first(attrType uint16) (stunAttribute, bool) {
	for _, attr := range m.Attributes {
		if attr.Type == attrType {
			return attr, true
		}
	}
	return stunAttribute{}, false
}

func (m stunMessage) all(attrType uint16) []stunAttribute {
	attrs := make([]stunAttribute, 0, 1)
	for _, attr := range m.Attributes {
		if attr.Type == attrType {
			attrs = append(attrs, attr)
		}
	}
	return attrs
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

func (m stunMessage) text(attrType uint16) string {
	attr, ok := m.first(attrType)
	if !ok {
		return ""
	}
	return string(attr.Value)
}

func (m stunMessage) lifetimeSeconds(fallback int64) int64 {
	attr, ok := m.first(stunAttrLifetime)
	if !ok || len(attr.Value) != 4 {
		return fallback
	}
	return int64(binary.BigEndian.Uint32(attr.Value))
}

func (m stunMessage) requestedUDPTransport() bool {
	attr, ok := m.first(stunAttrRequestedTransport)
	return ok && len(attr.Value) > 0 && attr.Value[0] == stunTransportUDP
}

func (m stunMessage) channelNumber() (uint16, bool) {
	attr, ok := m.first(stunAttrChannelNumber)
	if !ok || len(attr.Value) != 4 {
		return 0, false
	}
	channel := binary.BigEndian.Uint16(attr.Value[:2])
	return channel, channel >= turnChannelMin && channel <= turnChannelMax
}

func newStunAttrXorMappedAddress(addr *net.UDPAddr, tx [stunTransactionIDBytes]byte) stunAttribute {
	return stunAttribute{Type: stunAttrXorMappedAddress, Value: encodeStunXorAddress(addr, tx)}
}

func newStunAttrXorRelayedAddress(addr *net.UDPAddr, tx [stunTransactionIDBytes]byte) stunAttribute {
	return stunAttribute{Type: stunAttrXorRelayedAddress, Value: encodeStunXorAddress(addr, tx)}
}

func newStunAttrXorPeerAddress(addr *net.UDPAddr, tx [stunTransactionIDBytes]byte) stunAttribute {
	return stunAttribute{Type: stunAttrXorPeerAddress, Value: encodeStunXorAddress(addr, tx)}
}

func stunAttrChannelNumberValue(channel uint16) stunAttribute {
	value := make([]byte, 4)
	binary.BigEndian.PutUint16(value[:2], channel)
	return stunAttribute{Type: stunAttrChannelNumber, Value: value}
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

func stunAttrUsernameValue(value string) stunAttribute {
	return stunAttribute{Type: stunAttrUsername, Value: []byte(value)}
}

func stunAttrRealmValue(value string) stunAttribute {
	return stunAttribute{Type: stunAttrRealm, Value: []byte(value)}
}

func stunAttrNonceValue(value string) stunAttribute {
	return stunAttribute{Type: stunAttrNonce, Value: []byte(value)}
}

func stunAttrErrorCodeValue(code int, reason string) stunAttribute {
	class := code / 100
	if class < 3 {
		class = 3
	} else if class > 6 {
		class = 6
	}
	number := code % 100
	if number < 0 {
		number = 0
	} else if number > 99 {
		number = 99
	}
	value := append([]byte{0, 0, byte(class), byte(number)}, []byte(reason)...)
	return stunAttribute{Type: stunAttrErrorCode, Value: value}
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
