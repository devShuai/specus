// Package protocol implements the shuai-tunnel wire protocol: the 11-byte framing
// header, the CompactBinary body serializer, the NAT_MESSAGE sub-protocol, and HMAC
// login signing. It is byte-compatible with the Java client/common and the C# server,
// and implements both directions (the server decodes requests and encodes responses,
// the reverse of the Go client's protocol package).
package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	// MagicNumber prefixes every frame (big-endian int32).
	MagicNumber = 0x14353565
	// Version is the only accepted control protocol version.
	Version byte = 2

	// SerializerCompact is the sole v2 serializer identifier, including NAT_MESSAGE.
	SerializerCompact byte = 4

	CommandLoginRequest      int8 = 1
	CommandLoginResponse     int8 = -1
	CommandMessageRequest    int8 = 2
	CommandMessageResponse   int8 = -2
	CommandLogoutRequest     int8 = 3
	CommandLogoutResponse    int8 = -3
	CommandHeartbeatRequest  int8 = 4
	CommandHeartbeatResponse int8 = -4
	CommandNatMessage        int8 = 6

	// MessageType values are stable wire IDs, never language enum ordinals.
	MessageTypeServerToClient = 1
	MessageTypeClientToServer = 2
	MessageTypeClientToClient = 3
	MessageTypeNatControl     = 4
	MessageTypePeerControl    = 5

	// NAT_MESSAGE sub-types (the explicit wire code).
	NatRegister       = 1
	NatRegisterResult = 2
	NatOpen           = 3
	NatFin            = 4
	NatData           = 5
	NatKeepalive      = 6
	NatUnregister     = 7
	NatRST            = 8
	NatWindowUpdate   = 9
	NatFlagEndStream  = 0x01

	// FrameHeaderSize is the fixed framing header length.
	FrameHeaderSize = 11

	// MaxFrameSize is Java Netty's full frame limit, including the 11-byte header.
	MaxFrameSize        = 32 * 1024 * 1024
	MaxFrameBodySize    = MaxFrameSize - FrameHeaderSize
	PreAuthMaxFrameSize = 16 * 1024
)

// ReadFrame reads a single framed packet from reader, returning the command byte and
// the raw (still CompactBinary-wrapped) body. It validates magic and length bounds.
func ReadFrame(reader io.Reader) (command int8, body []byte, err error) {
	return ReadFrameLimit(reader, MaxFrameSize)
}

// ReadFrameLimit reads a frame using a full-frame limit (header + body).
func ReadFrameLimit(reader io.Reader, maxFrameSize int) (command int8, body []byte, err error) {
	if maxFrameSize < FrameHeaderSize {
		return 0, nil, fmt.Errorf("max frame size must be at least header size: %d", maxFrameSize)
	}
	header := make([]byte, FrameHeaderSize)
	if _, err = io.ReadFull(reader, header); err != nil {
		return 0, nil, err
	}
	if binary.BigEndian.Uint32(header[:4]) != MagicNumber {
		return 0, nil, errors.New("invalid packet magic number")
	}
	if header[4] != Version {
		return 0, nil, fmt.Errorf("unsupported protocol version: %d", header[4])
	}
	if header[5] != SerializerCompact {
		return 0, nil, fmt.Errorf("unsupported serializer: %d", header[5])
	}
	command = int8(header[6])
	if !knownCommand(command) {
		return 0, nil, fmt.Errorf("unknown command: %d", command)
	}
	length := int(int32(binary.BigEndian.Uint32(header[7:11])))
	if length < 0 || length > maxFrameSize-FrameHeaderSize {
		return 0, nil, fmt.Errorf("invalid packet body length: %d", length)
	}
	if err := validateBodyLength(command, length); err != nil {
		return 0, nil, err
	}
	body = make([]byte, length)
	if _, err = io.ReadFull(reader, body); err != nil {
		return 0, nil, err
	}
	return command, body, nil
}

// writeFrameBytes writes a framed packet for the given command and body to writer.
func writeFrameBytes(writer io.Writer, command int8, body []byte) error {
	if len(body) > MaxFrameBodySize {
		return fmt.Errorf("packet body exceeds limit: %d", len(body))
	}
	if err := validateBodyLength(command, len(body)); err != nil {
		return err
	}
	header := make([]byte, FrameHeaderSize)
	binary.BigEndian.PutUint32(header[:4], MagicNumber)
	header[4] = Version
	header[5] = SerializerCompact
	if !knownCommand(command) {
		return fmt.Errorf("unknown command: %d", command)
	}
	header[6] = byte(command)
	binary.BigEndian.PutUint32(header[7:11], uint32(len(body)))
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(body)
	return err
}

// ---- compact writer ------------------------------------------------------------------

type compactOutput struct {
	bytes.Buffer
}

func newCompactOutput() *compactOutput { return &compactOutput{} }

func (output *compactOutput) payload() []byte { return append([]byte(nil), output.Bytes()...) }

func (output *compactOutput) writeString(value string) {
	_ = output.writeVarInt(len([]byte(value)) + 1)
	output.WriteString(value)
}

// writeOptionalString writes a nullable string: nil -> VarInt(0); otherwise len+1 + bytes.
func (output *compactOutput) writeOptionalString(value *string) {
	if value == nil {
		_ = output.writeVarInt(0)
		return
	}
	output.writeString(*value)
}

func (output *compactOutput) writeByteArray(value []byte) {
	if value == nil {
		_ = output.writeVarInt(0)
		return
	}
	_ = output.writeVarInt(len(value) + 1)
	output.Write(value)
}

func (output *compactOutput) writeBool(value bool) {
	if value {
		output.WriteByte(1)
	} else {
		output.WriteByte(0)
	}
}

func (output *compactOutput) writeEnum(wireID int) {
	output.writeVarLong(uint64(wireID))
}

func (output *compactOutput) writeStringList(values []string) {
	if values == nil {
		_ = output.writeVarInt(0)
		return
	}
	_ = output.writeVarInt(len(values) + 1)
	for _, value := range values {
		output.writeString(value)
	}
}

func (output *compactOutput) writeVarInt(value int) error {
	if value < 0 {
		return errors.New("variable-length integer cannot be negative")
	}
	output.writeVarLong(uint64(value))
	return nil
}

func (output *compactOutput) writeVarLong(value uint64) {
	for value&^0x7f != 0 {
		output.WriteByte(byte(value&0x7f | 0x80))
		value >>= 7
	}
	output.WriteByte(byte(value))
}

func (output *compactOutput) writeNullableLong(value int64) {
	output.WriteByte(1)
	output.writeVarLong(uint64(value<<1) ^ uint64(value>>63))
}

func (output *compactOutput) writeNumericString(value string) {
	number, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		output.WriteByte(2)
		output.writeString(value)
		return
	}
	output.WriteByte(1)
	output.writeVarLong(uint64(number<<1) ^ uint64(number>>63))
}

func (output *compactOutput) writeHTTPMethod(value string) {
	switch value {
	case "GET":
		output.WriteByte(1)
	case "POST":
		output.WriteByte(2)
	case "PUT":
		output.WriteByte(3)
	case "DELETE":
		output.WriteByte(4)
	default:
		output.WriteByte(5)
		output.writeString(value)
	}
}

func (output *compactOutput) writeUUIDString(value string) {
	decoded, ok := parseUUID(value)
	if !ok {
		output.WriteByte(2)
		output.writeString(value)
		return
	}
	output.WriteByte(1)
	output.Write(decoded)
}

// ---- compact reader ------------------------------------------------------------------

type compactInput struct {
	reader *bytes.Reader
}

func newCompactInput(encoded []byte) (*compactInput, error) {
	return &compactInput{reader: bytes.NewReader(encoded)}, nil
}

func (input *compactInput) finish() error {
	if input.reader.Len() != 0 {
		return fmt.Errorf("compact payload has %d trailing bytes", input.reader.Len())
	}
	return nil
}

func (input *compactInput) readByte() (byte, error) { return input.reader.ReadByte() }

func (input *compactInput) readBytes(length int) ([]byte, error) {
	if length < 0 || length > input.reader.Len() {
		return nil, errors.New("unexpected end of compact payload")
	}
	value := make([]byte, length)
	_, err := io.ReadFull(input.reader, value)
	return value, err
}

func (input *compactInput) readString() (string, error) {
	length, err := input.readVarInt()
	if err != nil {
		return "", err
	}
	if length == 0 {
		return "", nil
	}
	value, err := input.readBytes(length - 1)
	return string(value), err
}

// readOptionalString preserves the null/empty distinction: VarInt(0) -> nil.
func (input *compactInput) readOptionalString() (*string, error) {
	length, err := input.readVarInt()
	if err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	value, err := input.readBytes(length - 1)
	if err != nil {
		return nil, err
	}
	s := string(value)
	return &s, nil
}

func (input *compactInput) readByteArray() ([]byte, error) {
	length, err := input.readVarInt()
	if err != nil || length == 0 {
		return nil, err
	}
	return input.readBytes(length - 1)
}

func (input *compactInput) readStringList() ([]string, error) {
	length, err := input.readVarInt()
	if err != nil || length == 0 {
		return nil, err
	}
	values := make([]string, 0, length-1)
	for range length - 1 {
		value, err := input.readString()
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

func (input *compactInput) readStringMap() (map[string]string, error) {
	length, err := input.readVarInt()
	if err != nil || length == 0 {
		return nil, err
	}
	values := make(map[string]string, length-1)
	for range length - 1 {
		key, err := input.readString()
		if err != nil {
			return nil, err
		}
		value, err := input.readString()
		if err != nil {
			return nil, err
		}
		values[key] = value
	}
	return values, nil
}

func (input *compactInput) readBool() (bool, error) {
	value, err := input.readByte()
	if err != nil {
		return false, err
	}
	if value > 1 {
		return false, fmt.Errorf("invalid boolean value: %d", value)
	}
	return value == 1, nil
}

func (input *compactInput) readVarInt() (int, error) {
	value, err := input.readVarLong()
	if err != nil {
		return 0, err
	}
	if value > uint64(^uint(0)>>1) {
		return 0, errors.New("variable-length integer is too large")
	}
	return int(value), nil
}

func (input *compactInput) readVarLong() (uint64, error) {
	var value uint64
	for shift := 0; shift < 64; shift += 7 {
		current, err := input.readByte()
		if err != nil {
			return 0, err
		}
		value |= uint64(current&0x7f) << shift
		if current&0x80 == 0 {
			return value, nil
		}
	}
	return 0, errors.New("variable-length integer is too long")
}

func (input *compactInput) readNullableLong() (int64, error) {
	marker, err := input.readByte()
	if err != nil {
		return 0, err
	}
	switch marker {
	case 0:
		return 0, nil
	case 1:
		zigzag, err := input.readVarLong()
		if err != nil {
			return 0, err
		}
		return int64(zigzag>>1) ^ -int64(zigzag&1), nil
	default:
		return 0, fmt.Errorf("invalid long marker: %d", marker)
	}
}

func (input *compactInput) readEnum() (int, error) {
	value, err := input.readVarInt()
	if err != nil {
		return 0, err
	}
	if value < MessageTypeServerToClient || value > MessageTypePeerControl {
		return 0, fmt.Errorf("invalid message type wire id: %d", value)
	}
	return value, nil
}

func knownCommand(command int8) bool {
	switch command {
	case CommandLoginRequest, CommandLoginResponse,
		CommandMessageRequest, CommandMessageResponse,
		CommandLogoutRequest, CommandLogoutResponse,
		CommandHeartbeatRequest, CommandHeartbeatResponse, CommandNatMessage:
		return true
	default:
		return false
	}
}

func (input *compactInput) readNumericString() (string, error) {
	marker, err := input.readByte()
	if err != nil {
		return "", err
	}
	switch marker {
	case 0:
		return "", nil
	case 1:
		zigzag, err := input.readVarLong()
		if err != nil {
			return "", err
		}
		value := int64(zigzag>>1) ^ -int64(zigzag&1)
		return strconv.FormatInt(value, 10), nil
	case 2:
		return input.readString()
	default:
		return "", fmt.Errorf("invalid numeric-string marker: %d", marker)
	}
}

func (input *compactInput) readHTTPMethod() (string, error) {
	methods := []string{"GET", "POST", "PUT", "DELETE"}
	marker, err := input.readByte()
	if err != nil {
		return "", err
	}
	if marker == 0 {
		return "", nil
	}
	if int(marker) <= len(methods) {
		return methods[marker-1], nil
	}
	if int(marker) == len(methods)+1 {
		return input.readString()
	}
	return "", fmt.Errorf("invalid HTTP method marker: %d", marker)
}

func (input *compactInput) readUUIDString() (string, error) {
	marker, err := input.readByte()
	if err != nil {
		return "", err
	}
	switch marker {
	case 0:
		return "", nil
	case 1:
		value, err := input.readBytes(16)
		if err != nil {
			return "", err
		}
		return formatUUID(value), nil
	case 2:
		return input.readString()
	default:
		return "", fmt.Errorf("invalid UUID marker: %d", marker)
	}
}

func parseUUID(value string) ([]byte, bool) {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return nil, false
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(decoded) != 16 {
		return nil, false
	}
	return decoded, formatUUID(decoded) == value
}

func formatUUID(value []byte) string {
	encoded := hex.EncodeToString(value)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}
