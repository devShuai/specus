package client

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

	stunAttrMappedAddress      = 0x0001
	stunAttrChangeRequest      = 0x0003
	stunAttrErrorCode          = 0x0009
	stunAttrUnknownAttributes  = 0x000A
	stunAttrLifetime           = 0x000D
	stunAttrChannelNumber      = 0x000C
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

func (m stunMessage) mappedAddress() (*net.UDPAddr, bool) {
	attr, ok := m.first(stunAttrMappedAddress)
	if !ok {
		return nil, false
	}
	return decodeStunAddress(attr.Value)
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
	return decodeStunAddress(attr.Value)
}

func (m stunMessage) responseOrigin() (*net.UDPAddr, bool) {
	attr, ok := m.first(stunAttrResponseOrigin)
	if !ok {
		return nil, false
	}
	return decodeStunAddress(attr.Value)
}

func (m stunMessage) legacyXorOtherAddress() (*net.UDPAddr, bool) {
	attr, ok := m.first(stunAttrOtherAddress)
	if !ok {
		return nil, false
	}
	return decodeStunXorAddress(attr.Value, m.TransactionID)
}

func (m stunMessage) legacyXorResponseOrigin() (*net.UDPAddr, bool) {
	attr, ok := m.first(stunAttrResponseOrigin)
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

func (m stunMessage) errorCode() int {
	attr, ok := m.first(stunAttrErrorCode)
	if !ok || len(attr.Value) < 4 {
		return -1
	}
	return int(attr.Value[2]&0x07)*100 + int(attr.Value[3])
}

func (m stunMessage) unknownAttributes() []uint16 {
	attr, ok := m.first(stunAttrUnknownAttributes)
	if !ok {
		return nil
	}
	result := make([]uint16, 0, len(attr.Value)/2)
	for offset := 0; offset+2 <= len(attr.Value); offset += 2 {
		result = append(result, binary.BigEndian.Uint16(attr.Value[offset:offset+2]))
	}
	return result
}

func (m stunMessage) changeRequest() (changeIP, changePort, ok bool) {
	attr, found := m.first(stunAttrChangeRequest)
	if !found || len(attr.Value) != 4 {
		return false, false, false
	}
	flags := binary.BigEndian.Uint32(attr.Value)
	return flags&0x04 != 0, flags&0x02 != 0, true
}

func (m stunMessage) lifetimeSeconds(fallback int64) int64 {
	attr, ok := m.first(stunAttrLifetime)
	if !ok || len(attr.Value) != 4 {
		return fallback
	}
	return int64(binary.BigEndian.Uint32(attr.Value))
}

func (m stunMessage) channelNumber() (uint16, bool) {
	attr, ok := m.first(stunAttrChannelNumber)
	if !ok || len(attr.Value) != 4 {
		return 0, false
	}
	channel := binary.BigEndian.Uint16(attr.Value[:2])
	return channel, channel >= turnChannelMin && channel <= turnChannelMax
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

func stunAttrChangeRequestValue(changeIP, changePort bool) stunAttribute {
	flags := uint32(0)
	if changeIP {
		flags |= 0x04
	}
	if changePort {
		flags |= 0x02
	}
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value, flags)
	return stunAttribute{Type: stunAttrChangeRequest, Value: value}
}

func stunAttrResponseOriginValue(addr *net.UDPAddr) stunAttribute {
	return stunAttribute{Type: stunAttrResponseOrigin, Value: encodeStunAddress(addr)}
}

func stunAttrOtherAddressValue(addr *net.UDPAddr) stunAttribute {
	return stunAttribute{Type: stunAttrOtherAddress, Value: encodeStunAddress(addr)}
}

func stunAttrUnknownAttributesValue(types ...uint16) stunAttribute {
	value := make([]byte, len(types)*2)
	for index, attrType := range types {
		binary.BigEndian.PutUint16(value[index*2:index*2+2], attrType)
	}
	return stunAttribute{Type: stunAttrUnknownAttributes, Value: value}
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

func encodeStunAddress(addr *net.UDPAddr) []byte {
	if addr == nil || addr.IP == nil {
		return nil
	}
	ip4 := addr.IP.To4()
	if ip4 != nil {
		value := make([]byte, 8)
		value[1] = 0x01
		binary.BigEndian.PutUint16(value[2:4], uint16(addr.Port))
		copy(value[4:], ip4)
		return value
	}
	ip16 := addr.IP.To16()
	if ip16 == nil {
		return nil
	}
	value := make([]byte, 20)
	value[1] = 0x02
	binary.BigEndian.PutUint16(value[2:4], uint16(addr.Port))
	copy(value[4:], ip16)
	return value
}

func decodeStunAddress(value []byte) (*net.UDPAddr, bool) {
	if len(value) != 8 && len(value) != 20 {
		return nil, false
	}
	port := int(binary.BigEndian.Uint16(value[2:4]))
	switch value[1] {
	case 0x01:
		if len(value) != 8 {
			return nil, false
		}
		return &net.UDPAddr{IP: append(net.IP(nil), value[4:8]...), Port: port}, true
	case 0x02:
		if len(value) != 20 {
			return nil, false
		}
		return &net.UDPAddr{IP: append(net.IP(nil), value[4:20]...), Port: port}, true
	default:
		return nil, false
	}
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
