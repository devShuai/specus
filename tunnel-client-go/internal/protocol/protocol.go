package protocol

import (
	"bytes"
	"compress/flate"
	"crypto/md5"
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
	Version     byte = 1

	SerializerFastJSON byte = 1
	SerializerCompact  byte = 4

	CommandLoginRequest       int8 = 1
	CommandLoginResponse      int8 = -1
	CommandMessageResponse    int8 = -2
	CommandHeartbeatRequest   int8 = 4
	CommandHeartbeatResponse  int8 = -4
	CommandLegacyHTTPRequest  int8 = 5
	CommandLegacyHTTPResponse int8 = -5
	CommandNatMessage         int8 = 6
	CommandDirectHTTPRequest  int8 = 7
	CommandDirectHTTPResponse int8 = -7

	NatRegister       = 1
	NatRegisterResult = 2
	NatConnected      = 3
	NatDisconnected   = 4
	NatData           = 5
	NatKeepalive      = 6

	MessageTypeNatControl = 3

	maxFrameSize    = 32 * 1024 * 1024
	maxInflatedSize = 16 * 1024 * 1024
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

type DirectHTTPRequest struct {
	RequestID    string
	Method       string
	Route        string
	RelativePath string
	RawQuery     string
	Headers      []string
	Body         []byte
}

type DirectHTTPResponse struct {
	RequestID  string
	StatusCode int
	Headers    []string
	Body       []byte
	Error      string
}

type LegacyHTTPRequest struct {
	ClientName   string
	ToClientName string
	RequestID    string
	Method       string
	RequestURL   string
	Headers      map[string]string
	Params       map[string]string
	Body         string
}

type LegacyHTTPResponse struct {
	ClientName   string
	ToClientName string
	RequestID    string
	Response     string
}

type NatMessage struct {
	Type     int
	Metadata map[string]any
	Data     []byte
}

func ReadPacket(reader io.Reader) (Packet, error) {
	header := make([]byte, 11)
	if _, err := io.ReadFull(reader, header); err != nil {
		return Packet{}, err
	}
	if binary.BigEndian.Uint32(header[:4]) != MagicNumber {
		return Packet{}, errors.New("invalid packet magic number")
	}
	length := int(binary.BigEndian.Uint32(header[7:11]))
	if length < 0 || length > maxFrameSize {
		return Packet{}, fmt.Errorf("invalid packet body length: %d", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return Packet{}, err
	}
	return Packet{Command: int8(header[6]), Body: body}, nil
}

func WritePacket(writer io.Writer, command int8, body []byte) error {
	if len(body) > maxFrameSize {
		return fmt.Errorf("packet body exceeds limit: %d", len(body))
	}
	header := make([]byte, 11)
	binary.BigEndian.PutUint32(header[:4], MagicNumber)
	header[4] = Version
	header[5] = SerializerCompact
	if command == CommandNatMessage {
		header[5] = SerializerFastJSON
	}
	header[6] = byte(command)
	binary.BigEndian.PutUint32(header[7:11], uint32(len(body)))
	if err := writeAll(writer, header); err != nil {
		return err
	}
	return writeAll(writer, body)
}

func EncodeLoginRequest(clientName, password, timestamp string) ([]byte, error) {
	sign := fmt.Sprintf("%x", md5.Sum([]byte("May the Force be with you"+clientName+password+timestamp)))
	output := newCompactOutput()
	output.writeString(clientName)
	output.writeString(password)
	if err := output.writeNumericString(timestamp); err != nil {
		return nil, err
	}
	if err := output.writeFixedHexString(sign, 16); err != nil {
		return nil, err
	}
	return encodePayload(output.bytes()), nil
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

func DecodeDirectHTTPRequest(body []byte) (DirectHTTPRequest, error) {
	input, err := newCompactInput(body)
	if err != nil {
		return DirectHTTPRequest{}, err
	}
	requestID, err := input.readUUIDString()
	if err != nil {
		return DirectHTTPRequest{}, err
	}
	method, err := input.readHTTPMethod()
	if err != nil {
		return DirectHTTPRequest{}, err
	}
	route, err := input.readString()
	if err != nil {
		return DirectHTTPRequest{}, err
	}
	relativePath, err := input.readString()
	if err != nil {
		return DirectHTTPRequest{}, err
	}
	rawQuery, err := input.readString()
	if err != nil {
		return DirectHTTPRequest{}, err
	}
	headers, err := input.readStringList()
	if err != nil {
		return DirectHTTPRequest{}, err
	}
	requestBody, err := input.readByteArray()
	if err != nil {
		return DirectHTTPRequest{}, err
	}
	if err := input.finish(); err != nil {
		return DirectHTTPRequest{}, err
	}
	return DirectHTTPRequest{
		RequestID: requestID, Method: method, Route: route, RelativePath: relativePath,
		RawQuery: rawQuery, Headers: headers, Body: requestBody,
	}, nil
}

func EncodeDirectHTTPResponse(response DirectHTTPResponse) ([]byte, error) {
	output := newCompactOutput()
	if err := output.writeUUIDString(response.RequestID); err != nil {
		return nil, err
	}
	if err := output.writeVarInt(response.StatusCode); err != nil {
		return nil, err
	}
	output.writeStringList(response.Headers)
	output.writeByteArray(response.Body)
	output.writeOptionalString(response.Error)
	return encodePayload(output.bytes()), nil
}

func DecodeDirectHTTPResponse(body []byte) (DirectHTTPResponse, error) {
	input, err := newCompactInput(body)
	if err != nil {
		return DirectHTTPResponse{}, err
	}
	requestID, err := input.readUUIDString()
	if err != nil {
		return DirectHTTPResponse{}, err
	}
	statusCode, err := input.readVarInt()
	if err != nil {
		return DirectHTTPResponse{}, err
	}
	headers, err := input.readStringList()
	if err != nil {
		return DirectHTTPResponse{}, err
	}
	responseBody, err := input.readByteArray()
	if err != nil {
		return DirectHTTPResponse{}, err
	}
	responseError, err := input.readString()
	if err != nil {
		return DirectHTTPResponse{}, err
	}
	if err := input.finish(); err != nil {
		return DirectHTTPResponse{}, err
	}
	return DirectHTTPResponse{
		RequestID:  requestID,
		StatusCode: statusCode,
		Headers:    headers,
		Body:       responseBody,
		Error:      responseError,
	}, nil
}

func DecodeLegacyHTTPRequest(body []byte) (LegacyHTTPRequest, error) {
	input, err := newCompactInput(body)
	if err != nil {
		return LegacyHTTPRequest{}, err
	}
	clientName, err := input.readString()
	if err != nil {
		return LegacyHTTPRequest{}, err
	}
	toClientName, err := input.readString()
	if err != nil {
		return LegacyHTTPRequest{}, err
	}
	requestID, err := input.readUUIDString()
	if err != nil {
		return LegacyHTTPRequest{}, err
	}
	method, err := input.readHTTPMethod()
	if err != nil {
		return LegacyHTTPRequest{}, err
	}
	requestURL, err := input.readString()
	if err != nil {
		return LegacyHTTPRequest{}, err
	}
	headers, err := input.readStringMap()
	if err != nil {
		return LegacyHTTPRequest{}, err
	}
	params, err := input.readStringMap()
	if err != nil {
		return LegacyHTTPRequest{}, err
	}
	requestBody, err := input.readString()
	if err != nil {
		return LegacyHTTPRequest{}, err
	}
	if err := input.finish(); err != nil {
		return LegacyHTTPRequest{}, err
	}
	return LegacyHTTPRequest{
		ClientName: clientName, ToClientName: toClientName, RequestID: requestID,
		Method: method, RequestURL: requestURL, Headers: headers, Params: params, Body: requestBody,
	}, nil
}

func EncodeLegacyHTTPResponse(response LegacyHTTPResponse) ([]byte, error) {
	output := newCompactOutput()
	output.writeString(response.ClientName)
	output.writeString(response.ToClientName)
	if err := output.writeUUIDString(response.RequestID); err != nil {
		return nil, err
	}
	output.writeString(response.Response)
	return encodePayload(output.bytes()), nil
}

func EncodeNatMessage(message NatMessage) ([]byte, error) {
	metadata, err := json.Marshal(message.Metadata)
	if err != nil {
		return nil, fmt.Errorf("encode NAT metadata: %w", err)
	}
	var output bytes.Buffer
	if err := binary.Write(&output, binary.BigEndian, int32(message.Type)); err != nil {
		return nil, err
	}
	if err := binary.Write(&output, binary.BigEndian, int32(len(metadata))); err != nil {
		return nil, err
	}
	output.Write(metadata)
	if len(message.Data) > 0 {
		output.Write(encodePayload(message.Data))
	}
	return output.Bytes(), nil
}

func DecodeNatMessage(body []byte) (NatMessage, error) {
	if len(body) < 8 {
		return NatMessage{}, errors.New("NAT packet is too short")
	}
	messageType := int(int32(binary.BigEndian.Uint32(body[:4])))
	metadataLength := int(int32(binary.BigEndian.Uint32(body[4:8])))
	if metadataLength < 0 || len(body)-8 < metadataLength {
		return NatMessage{}, errors.New("invalid NAT metadata length")
	}
	metadata := make(map[string]any)
	if err := json.Unmarshal(body[8:8+metadataLength], &metadata); err != nil {
		return NatMessage{}, fmt.Errorf("decode NAT metadata: %w", err)
	}
	var data []byte
	if len(body) > 8+metadataLength {
		var err error
		data, err = decodePayload(body[8+metadataLength:])
		if err != nil {
			return NatMessage{}, err
		}
	}
	return NatMessage{Type: messageType, Metadata: metadata, Data: data}, nil
}

func encodePayload(raw []byte) []byte {
	compressed, err := deflate(raw)
	if len(raw) >= 64 && err == nil && len(compressed) < len(raw) {
		return append([]byte{1}, compressed...)
	}
	return append([]byte{0}, raw...)
}

func decodePayload(encoded []byte) ([]byte, error) {
	if len(encoded) == 0 {
		return nil, errors.New("compact payload is empty")
	}
	switch encoded[0] {
	case 0:
		return append([]byte(nil), encoded[1:]...), nil
	case 1:
		reader := flate.NewReader(bytes.NewReader(encoded[1:]))
		defer reader.Close()
		data, err := io.ReadAll(io.LimitReader(reader, maxInflatedSize+1))
		if err != nil {
			return nil, fmt.Errorf("inflate compact payload: %w", err)
		}
		if len(data) > maxInflatedSize {
			return nil, errors.New("inflated compact payload exceeds limit")
		}
		return data, nil
	default:
		return nil, fmt.Errorf("unknown compact payload type: %d", encoded[0])
	}
}

func deflate(raw []byte) ([]byte, error) {
	var output bytes.Buffer
	writer, err := flate.NewWriter(&output, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(raw); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
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

func (output *compactOutput) writeOptionalString(value string) {
	if value == "" {
		output.writeVarInt(0)
		return
	}
	output.writeString(value)
}

func (output *compactOutput) writeByteArray(value []byte) {
	output.writeVarInt(len(value) + 1)
	output.Write(value)
}

func (output *compactOutput) writeStringList(values []string) {
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
	return value - 1, nil
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
	return decoded, err == nil && len(decoded) == 16
}

func formatUUID(value []byte) string {
	encoded := hex.EncodeToString(value)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}
