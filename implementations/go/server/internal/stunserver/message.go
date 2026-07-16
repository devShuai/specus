package stunserver

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	stunMagicCookie = 0x2112A442
	stunHeaderBytes = 20

	BindingRequest = 0x0001
	BindingSuccess = 0x0101
	BindingError   = 0x0111

	AttrMappedAddress  = 0x0001
	AttrChangeRequest  = 0x0003
	AttrErrorCode      = 0x0009
	AttrUnknownAttrs   = 0x000A
	AttrXorMapped      = 0x0020
	AttrPadding        = 0x0026
	AttrResponsePort   = 0x0027
	AttrSoftware       = 0x8022
	AttrResponseOrigin = 0x802B
	AttrOtherAddress   = 0x802C
	changeRequestMask  = 0x06
	transactionIDBytes = 12
)

type Attribute struct {
	Type  uint16
	Value []byte
}

type Message struct {
	Type          uint16
	TransactionID [transactionIDBytes]byte
	Attributes    []Attribute
}

type ChangeRequest struct {
	ChangeIP   bool
	ChangePort bool
}

func ParseMessage(packet []byte) (Message, error) {
	if len(packet) < stunHeaderBytes || packet[0]&0xC0 != 0 {
		return Message{}, fmt.Errorf("not a STUN packet")
	}
	if binary.BigEndian.Uint32(packet[4:8]) != stunMagicCookie {
		return Message{}, fmt.Errorf("invalid STUN magic cookie")
	}
	messageBytes := int(binary.BigEndian.Uint16(packet[2:4]))
	end := stunHeaderBytes + messageBytes
	if end > len(packet) {
		return Message{}, fmt.Errorf("truncated STUN message")
	}
	result := Message{Type: binary.BigEndian.Uint16(packet[:2])}
	copy(result.TransactionID[:], packet[8:20])
	for offset := stunHeaderBytes; offset < end; {
		if end-offset < 4 {
			return Message{}, fmt.Errorf("truncated STUN attribute")
		}
		attrType := binary.BigEndian.Uint16(packet[offset : offset+2])
		attrBytes := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		offset += 4
		if attrBytes > end-offset {
			return Message{}, fmt.Errorf("invalid STUN attribute length")
		}
		value := append([]byte(nil), packet[offset:offset+attrBytes]...)
		result.Attributes = append(result.Attributes, Attribute{Type: attrType, Value: value})
		offset += attrBytes + alignmentPadding(attrBytes)
		if offset > end {
			return Message{}, fmt.Errorf("invalid STUN attribute padding")
		}
	}
	return result, nil
}

func (m Message) Bytes() ([]byte, error) {
	attributeBytes := 0
	for _, attr := range m.Attributes {
		attributeBytes += 4 + len(attr.Value) + alignmentPadding(len(attr.Value))
	}
	if attributeBytes > 65535 {
		return nil, fmt.Errorf("STUN message attributes exceed 65535 bytes")
	}
	packet := make([]byte, stunHeaderBytes+attributeBytes)
	binary.BigEndian.PutUint16(packet[:2], m.Type)
	binary.BigEndian.PutUint16(packet[2:4], uint16(attributeBytes))
	binary.BigEndian.PutUint32(packet[4:8], stunMagicCookie)
	copy(packet[8:20], m.TransactionID[:])
	offset := stunHeaderBytes
	for _, attr := range m.Attributes {
		if len(attr.Value) > 65535 {
			return nil, fmt.Errorf("STUN attribute 0x%04x exceeds 65535 bytes", attr.Type)
		}
		binary.BigEndian.PutUint16(packet[offset:offset+2], attr.Type)
		binary.BigEndian.PutUint16(packet[offset+2:offset+4], uint16(len(attr.Value)))
		offset += 4
		copy(packet[offset:offset+len(attr.Value)], attr.Value)
		offset += len(attr.Value) + alignmentPadding(len(attr.Value))
	}
	return packet, nil
}

func (m Message) First(attrType uint16) (Attribute, bool) {
	for _, attr := range m.Attributes {
		if attr.Type == attrType {
			return Attribute{Type: attr.Type, Value: append([]byte(nil), attr.Value...)}, true
		}
	}
	return Attribute{}, false
}

func (m Message) Has(attrType uint16) bool {
	_, ok := m.First(attrType)
	return ok
}

func (m Message) ChangeRequest() (ChangeRequest, bool) {
	attr, ok := m.First(AttrChangeRequest)
	if !ok || len(attr.Value) != 4 {
		return ChangeRequest{}, false
	}
	flags := binary.BigEndian.Uint32(attr.Value)
	return ChangeRequest{ChangeIP: flags&0x04 != 0, ChangePort: flags&0x02 != 0}, true
}

func (m Message) ResponsePort() (int, bool) {
	attr, ok := m.First(AttrResponsePort)
	if !ok || len(attr.Value) != 2 {
		return 0, false
	}
	return int(binary.BigEndian.Uint16(attr.Value)), true
}

func (m Message) ErrorCode() int {
	attr, ok := m.First(AttrErrorCode)
	if !ok || len(attr.Value) < 4 {
		return -1
	}
	return int(attr.Value[2]&0x07)*100 + int(attr.Value[3])
}

func (m Message) MappedAddress() (*net.UDPAddr, bool) {
	attr, ok := m.First(AttrMappedAddress)
	if !ok {
		return nil, false
	}
	return decodeAddress(attr.Value)
}

func (m Message) XorMappedAddress() (*net.UDPAddr, bool) {
	attr, ok := m.First(AttrXorMapped)
	if !ok {
		return nil, false
	}
	return decodeXorAddress(attr.Value, m.TransactionID)
}

func (m Message) ResponseOrigin() (*net.UDPAddr, bool) {
	attr, ok := m.First(AttrResponseOrigin)
	if !ok {
		return nil, false
	}
	return decodeAddress(attr.Value)
}

func (m Message) OtherAddress() (*net.UDPAddr, bool) {
	attr, ok := m.First(AttrOtherAddress)
	if !ok {
		return nil, false
	}
	return decodeAddress(attr.Value)
}

func MappedAddressAttribute(address *net.UDPAddr) Attribute {
	return Attribute{Type: AttrMappedAddress, Value: encodeAddress(address)}
}

func XorMappedAddressAttribute(address *net.UDPAddr, transactionID [transactionIDBytes]byte) Attribute {
	return Attribute{Type: AttrXorMapped, Value: encodeXorAddress(address, transactionID)}
}

func ResponseOriginAttribute(address *net.UDPAddr) Attribute {
	return Attribute{Type: AttrResponseOrigin, Value: encodeAddress(address)}
}

func OtherAddressAttribute(address *net.UDPAddr) Attribute {
	return Attribute{Type: AttrOtherAddress, Value: encodeAddress(address)}
}

func ChangeRequestAttribute(changeIP, changePort bool) Attribute {
	flags := uint32(0)
	if changeIP {
		flags |= 0x04
	}
	if changePort {
		flags |= 0x02
	}
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value, flags)
	return Attribute{Type: AttrChangeRequest, Value: value}
}

func ResponsePortAttribute(port int) Attribute {
	value := make([]byte, 2)
	binary.BigEndian.PutUint16(value, uint16(port))
	return Attribute{Type: AttrResponsePort, Value: value}
}

func PaddingAttribute(length int) Attribute {
	return Attribute{Type: AttrPadding, Value: make([]byte, max(0, min(65503, length)))}
}

func SoftwareAttribute(value string) Attribute {
	return Attribute{Type: AttrSoftware, Value: []byte(value)}
}

func ErrorCodeAttribute(code int, reason string) Attribute {
	class := max(3, min(6, code/100))
	number := max(0, min(99, code%100))
	value := append([]byte{0, 0, byte(class), byte(number)}, []byte(reason)...)
	return Attribute{Type: AttrErrorCode, Value: value}
}

func UnknownAttributesAttribute(types ...uint16) Attribute {
	value := make([]byte, len(types)*2)
	for index, attrType := range types {
		binary.BigEndian.PutUint16(value[index*2:index*2+2], attrType)
	}
	return Attribute{Type: AttrUnknownAttrs, Value: value}
}

func encodeAddress(address *net.UDPAddr) []byte {
	if address == nil || address.IP == nil {
		return nil
	}
	if ipv4 := address.IP.To4(); ipv4 != nil {
		value := make([]byte, 8)
		value[1] = 0x01
		binary.BigEndian.PutUint16(value[2:4], uint16(address.Port))
		copy(value[4:], ipv4)
		return value
	}
	ipv6 := address.IP.To16()
	if ipv6 == nil {
		return nil
	}
	value := make([]byte, 20)
	value[1] = 0x02
	binary.BigEndian.PutUint16(value[2:4], uint16(address.Port))
	copy(value[4:], ipv6)
	return value
}

func decodeAddress(value []byte) (*net.UDPAddr, bool) {
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

func encodeXorAddress(address *net.UDPAddr, transactionID [transactionIDBytes]byte) []byte {
	value := encodeAddress(address)
	if len(value) != 8 && len(value) != 20 {
		return nil
	}
	binary.BigEndian.PutUint16(value[2:4], binary.BigEndian.Uint16(value[2:4])^uint16(stunMagicCookie>>16))
	mask := make([]byte, 16)
	binary.BigEndian.PutUint32(mask[:4], stunMagicCookie)
	copy(mask[4:], transactionID[:])
	for index := 4; index < len(value); index++ {
		value[index] ^= mask[index-4]
	}
	return value
}

func decodeXorAddress(value []byte, transactionID [transactionIDBytes]byte) (*net.UDPAddr, bool) {
	if len(value) != 8 && len(value) != 20 {
		return nil, false
	}
	decoded := append([]byte(nil), value...)
	binary.BigEndian.PutUint16(decoded[2:4], binary.BigEndian.Uint16(decoded[2:4])^uint16(stunMagicCookie>>16))
	mask := make([]byte, 16)
	binary.BigEndian.PutUint32(mask[:4], stunMagicCookie)
	copy(mask[4:], transactionID[:])
	for index := 4; index < len(decoded); index++ {
		decoded[index] ^= mask[index-4]
	}
	return decodeAddress(decoded)
}

func alignmentPadding(length int) int {
	return (4 - length%4) % 4
}
