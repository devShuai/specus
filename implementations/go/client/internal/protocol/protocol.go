package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	MagicNumber      = 0x14353565
	Version     byte = 2

	SerializerCompact     byte = 4
	ConnectionRoleControl      = "control"
	ConnectionRoleData         = "data"

	CommandLoginRequest      int8 = 1
	CommandLoginResponse     int8 = -1
	CommandMessageRequest    int8 = 2
	CommandMessageResponse   int8 = -2
	CommandLogoutRequest     int8 = 3
	CommandLogoutResponse    int8 = -3
	CommandHeartbeatRequest  int8 = 4
	CommandHeartbeatResponse int8 = -4
	CommandNatMessage        int8 = 6

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

	MessageTypeServerToClient = 1
	MessageTypeClientToServer = 2
	MessageTypeClientToClient = 3
	MessageTypeNatControl     = 4
	MessageTypePeerControl    = 5

	frameHeaderSize     = 11
	maxFrameSize        = 32 * 1024 * 1024
	maxFrameBodySize    = maxFrameSize - frameHeaderSize
	preAuthMaxFrameSize = 16 * 1024
	maxNatMetadataBytes = 65535
	maxMessageBodyBytes = 1024 * 1024
	natBodyHeaderSize   = 16
	natFlagEndStream    = 1
)

type Packet struct {
	Command int8
	Body    []byte
}

type LoginResponse struct {
	ClientName string
	Success    bool
	Reason     string
}

type MessageResponse struct {
	ClientName   string
	ToClientName string
	MessageType  int
	Message      string
}

func EncodeMessageRequest(clientName, toClientName string, messageType int, message string) []byte {
	output := newCompactOutput()
	output.writeString(clientName)
	output.writeString(toClientName)
	output.writeEnum(messageType)
	output.writeString(message)
	return encodePayload(output.Bytes())
}

type NatMessage struct {
	Type     int
	Flags    byte
	StreamID uint32
	Value    uint32
	Metadata map[string]any
	Data     []byte
}

func ReadPacket(reader io.Reader) (Packet, error) {
	return ReadPacketLimit(reader, maxFrameSize)
}

// ReadPacketLimit reads one frame with a full-frame limit, including the fixed header.
func ReadPacketLimit(reader io.Reader, limit int) (Packet, error) {
	if limit < frameHeaderSize {
		return Packet{}, fmt.Errorf("frame limit is smaller than header: %d", limit)
	}
	header := make([]byte, frameHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return Packet{}, err
	}
	if binary.BigEndian.Uint32(header[:4]) != MagicNumber {
		return Packet{}, errors.New("invalid packet magic number")
	}
	if header[4] != Version {
		return Packet{}, fmt.Errorf("unsupported protocol version: %d", header[4])
	}
	if header[5] != SerializerCompact {
		return Packet{}, fmt.Errorf("unsupported serializer: %d", header[5])
	}
	command := int8(header[6])
	if !knownCommand(command) {
		return Packet{}, fmt.Errorf("unknown command: %d", command)
	}
	length := int(binary.BigEndian.Uint32(header[7:11]))
	if length < 0 || length > limit-frameHeaderSize {
		return Packet{}, fmt.Errorf("invalid packet body length: %d", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return Packet{}, err
	}
	if err := validateBodyLength(command, length); err != nil {
		return Packet{}, err
	}
	return Packet{Command: command, Body: body}, nil
}

func PreAuthMaxFrameSize() int { return preAuthMaxFrameSize }

func WritePacket(writer io.Writer, command int8, body []byte) error {
	if len(body) > maxFrameBodySize {
		return fmt.Errorf("packet body exceeds limit: %d", len(body))
	}
	header := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint32(header[:4], MagicNumber)
	header[4] = Version
	header[5] = SerializerCompact
	if !knownCommand(command) {
		return fmt.Errorf("unknown command: %d", command)
	}
	if err := validateBodyLength(command, len(body)); err != nil {
		return err
	}
	header[6] = byte(command)
	binary.BigEndian.PutUint32(header[7:11], uint32(len(body)))
	if err := writeAll(writer, header); err != nil {
		return err
	}
	return writeAll(writer, body)
}

func EncodeLoginRequest(clientName string, clientSessionID int64, accessToken, connectionRole string) ([]byte, error) {
	if connectionRole != ConnectionRoleControl && connectionRole != ConnectionRoleData {
		return nil, fmt.Errorf("invalid connection role: %q", connectionRole)
	}
	output := newCompactOutput()
	output.writeString(clientName)
	output.writeNullableLong(clientSessionID)
	output.writeString(accessToken)
	output.writeString(connectionRole)
	return encodePayload(output.Bytes()), nil
}

func DecodeLoginResponse(body []byte) (LoginResponse, error) {
	input, err := newCompactInput(body)
	if err != nil {
		return LoginResponse{}, err
	}
	clientName, err := input.readString()
	if err != nil {
		return LoginResponse{}, err
	}
	success, err := input.readBool()
	if err != nil {
		return LoginResponse{}, err
	}
	reason, err := input.readString()
	if err != nil {
		return LoginResponse{}, err
	}
	if err := input.finish(); err != nil {
		return LoginResponse{}, err
	}
	return LoginResponse{ClientName: clientName, Success: success, Reason: reason}, nil
}

func EncodeHeartbeat() []byte {
	return encodePayload(nil)
}

func DecodeMessageResponse(body []byte) (MessageResponse, error) {
	input, err := newCompactInput(body)
	if err != nil {
		return MessageResponse{}, err
	}
	clientName, err := input.readString()
	if err != nil {
		return MessageResponse{}, err
	}
	toClientName, err := input.readString()
	if err != nil {
		return MessageResponse{}, err
	}
	messageType, err := input.readNullableEnum()
	if err != nil {
		return MessageResponse{}, err
	}
	message, err := input.readString()
	if err != nil {
		return MessageResponse{}, err
	}
	if err := input.finish(); err != nil {
		return MessageResponse{}, err
	}
	return MessageResponse{
		ClientName:   clientName,
		ToClientName: toClientName,
		MessageType:  messageType,
		Message:      message,
	}, nil
}

func EncodeNatMessage(message NatMessage) ([]byte, error) {
	if message.Type < NatRegister || message.Type > NatWindowUpdate {
		return nil, fmt.Errorf("unknown NAT message type: %d", message.Type)
	}
	metadata, err := encodeNatMetadata(message.Metadata)
	if err != nil {
		return nil, err
	}
	if err := validateNatSemantics(message.Type, message.Flags, message.StreamID, message.Value, len(metadata), len(message.Data)); err != nil {
		return nil, err
	}
	if len(message.Data) > maxFrameBodySize-natBodyHeaderSize-len(metadata) {
		return nil, errors.New("NAT data exceeds frame limit")
	}
	output := make([]byte, natBodyHeaderSize, natBodyHeaderSize+len(metadata)+len(message.Data))
	output[0] = byte(message.Type)
	output[1] = message.Flags
	binary.BigEndian.PutUint16(output[2:4], uint16(len(metadata)))
	binary.BigEndian.PutUint32(output[4:8], message.StreamID)
	binary.BigEndian.PutUint32(output[8:12], message.Value)
	binary.BigEndian.PutUint32(output[12:16], uint32(len(message.Data)))
	output = append(output, metadata...)
	output = append(output, message.Data...)
	return output, nil
}

func DecodeNatMessage(body []byte) (NatMessage, error) {
	if len(body) < natBodyHeaderSize {
		return NatMessage{}, errors.New("NAT packet is too short")
	}
	messageType := int(body[0])
	if messageType < NatRegister || messageType > NatWindowUpdate {
		return NatMessage{}, fmt.Errorf("unknown NAT message type: %d", messageType)
	}
	flags := body[1]
	if flags & ^byte(natFlagEndStream) != 0 {
		return NatMessage{}, fmt.Errorf("unknown NAT flags: %d", flags)
	}
	metadataLength := int(binary.BigEndian.Uint16(body[2:4]))
	streamID := binary.BigEndian.Uint32(body[4:8])
	value := binary.BigEndian.Uint32(body[8:12])
	dataLength := int(binary.BigEndian.Uint32(body[12:16]))
	if metadataLength > maxNatMetadataBytes ||
		len(body) != natBodyHeaderSize+metadataLength+dataLength {
		return NatMessage{}, errors.New("invalid NAT metadata/data length")
	}
	metadata, err := decodeNatMetadata(body[natBodyHeaderSize : natBodyHeaderSize+metadataLength])
	if err != nil {
		return NatMessage{}, err
	}
	var data []byte
	if dataLength > 0 {
		data = append([]byte(nil), body[natBodyHeaderSize+metadataLength:]...)
	}
	if err := validateNatSemantics(messageType, flags, streamID, value, metadataLength, dataLength); err != nil {
		return NatMessage{}, err
	}
	return NatMessage{Type: messageType, Flags: flags, StreamID: streamID, Value: value, Metadata: metadata, Data: data}, nil
}

func encodeNatMetadata(metadata map[string]any) ([]byte, error) {
	if len(metadata) == 0 {
		return nil, nil
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("encode NAT metadata: %w", err)
	}
	if len(encoded) > maxNatMetadataBytes {
		return nil, errors.New("NAT metadata exceeds limit")
	}
	return encoded, nil
}

func decodeNatMetadata(encoded []byte) (map[string]any, error) {
	if len(encoded) == 0 {
		return map[string]any{}, nil
	}
	metadata := make(map[string]any)
	if err := json.Unmarshal(encoded, &metadata); err != nil {
		return nil, fmt.Errorf("decode NAT metadata: %w", err)
	}
	if metadata == nil {
		return nil, errors.New("NAT metadata must be an object")
	}
	return metadata, nil
}

func validateNatSemantics(messageType int, flags byte, streamID, value uint32, metadataLength, dataLength int) error {
	streamFrame := messageType == NatOpen || messageType == NatFin || messageType == NatData ||
		messageType == NatRST || messageType == NatWindowUpdate
	if streamFrame == (streamID == 0) {
		if streamFrame {
			return errors.New("stream frame requires a non-zero stream id")
		}
		return errors.New("connection frame requires stream id zero")
	}
	if messageType != NatData && flags != 0 {
		return errors.New("flags are only valid on DATA")
	}
	if messageType == NatData && (metadataLength != 0 || value != 0) {
		return errors.New("DATA cannot carry metadata/value")
	}
	if messageType == NatWindowUpdate && (metadataLength != 0 || dataLength != 0 || flags != 0) {
		return errors.New("WINDOW_UPDATE cannot carry payload")
	}
	if messageType == NatFin && (dataLength != 0 || flags != 0) {
		return errors.New("FIN cannot carry binary data or flags")
	}
	if messageType == NatWindowUpdate && value == 0 {
		return errors.New("WINDOW_UPDATE credit must be positive")
	}
	if messageType == NatFin && value != 0 {
		return errors.New("FIN value must be zero")
	}
	if messageType == NatRST && dataLength != 0 {
		return errors.New("RST cannot carry binary data")
	}
	if !streamFrame && (value != 0 || flags != 0 || dataLength != 0) {
		return errors.New("connection control frame cannot carry stream value/data")
	}
	return nil
}

func encodePayload(raw []byte) []byte {
	return append([]byte(nil), raw...)
}

func decodePayload(encoded []byte) ([]byte, error) {
	return append([]byte(nil), encoded...), nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

type compactOutput struct {
	bytes.Buffer
}

func newCompactOutput() *compactOutput {
	return &compactOutput{}
}

func (output *compactOutput) writeString(value string) {
	output.writeVarInt(len([]byte(value)) + 1)
	output.WriteString(value)
}

func (output *compactOutput) writeOptionalString(value *string) {
	if value == nil {
		output.writeVarInt(0)
		return
	}
	output.writeString(*value)
}

func (output *compactOutput) writeByteArray(value []byte) {
	if value == nil {
		output.writeVarInt(0)
		return
	}
	output.writeVarInt(len(value) + 1)
	output.Write(value)
}

func (output *compactOutput) writeStringList(values []string) {
	if values == nil {
		output.writeVarInt(0)
		return
	}
	output.writeVarInt(len(values) + 1)
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

func (output *compactOutput) writeEnum(wireID int) {
	output.writeVarLong(uint64(wireID))
}

func (output *compactOutput) writeNumericString(value string) error {
	number, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		output.WriteByte(2)
		output.writeString(value)
		return nil
	}
	output.WriteByte(1)
	output.writeVarLong(uint64(number<<1) ^ uint64(number>>63))
	return nil
}

func (output *compactOutput) writeFixedHexString(value string, byteLength int) error {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != byteLength {
		output.WriteByte(3)
		output.writeString(value)
		return nil
	}
	output.WriteByte(1)
	output.Write(decoded)
	return nil
}

func (output *compactOutput) writeUUIDString(value string) error {
	decoded, ok := parseUUID(value)
	if !ok {
		output.WriteByte(2)
		output.writeString(value)
		return nil
	}
	output.WriteByte(1)
	output.Write(decoded)
	return nil
}

type compactInput struct {
	reader *bytes.Reader
}

func newCompactInput(encoded []byte) (*compactInput, error) {
	decoded, err := decodePayload(encoded)
	if err != nil {
		return nil, err
	}
	return &compactInput{reader: bytes.NewReader(decoded)}, nil
}

func (input *compactInput) finish() error {
	if input.reader.Len() != 0 {
		return fmt.Errorf("compact payload has %d trailing bytes", input.reader.Len())
	}
	return nil
}

func (input *compactInput) readByte() (byte, error) {
	return input.reader.ReadByte()
}

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
	result := string(value)
	return &result, nil
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

func (input *compactInput) readNullableEnum() (int, error) {
	value, err := input.readVarInt()
	if err != nil {
		return 0, err
	}
	if value < MessageTypeServerToClient || value > MessageTypePeerControl {
		return 0, fmt.Errorf("invalid message type wire id: %d", value)
	}
	return value, nil
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

func validateBodyLength(command int8, length int) error {
	maximum := maxFrameBodySize
	if command == CommandLoginRequest || command == CommandLoginResponse {
		maximum = preAuthMaxFrameSize - frameHeaderSize
	} else if command == CommandMessageRequest || command == CommandMessageResponse {
		maximum = maxMessageBodyBytes
	}
	if length < 0 || length > maximum {
		return fmt.Errorf("command %d body exceeds limit: %d/%d", command, length, maximum)
	}
	return nil
}
