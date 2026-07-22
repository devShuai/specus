package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

const (
	maxNatMetadataBytes = 65535
	maxMessageBodyBytes = 1024 * 1024
	natBodyHeaderSize   = 16
	natFlagEndStream    = 1
)

// Packet is any decoded control-channel message.
type Packet interface {
	// Command returns the wire command byte for this packet.
	Command() int8
}

// LoginRequest (command 1) — client authenticates with an access token obtained via HTTP login.
type LoginRequest struct {
	ClientName      string
	ClientSessionID int64
	AccessToken     string
	ConnectionRole  string
}

const (
	ConnectionRoleControl = "control"
	ConnectionRoleData    = "data"
)

// LoginResponse (command -1).
type LoginResponse struct {
	ClientName string
	Success    bool
	Reason     *string
}

// MessageRequest (command 2).
type MessageRequest struct {
	ClientName   string
	ToClientName string
	MessageType  int
	Message      string
}

// MessageResponse (command -2) — also carries NAT_CONTROL pushes (MessageType=3).
type MessageResponse struct {
	ClientName   string
	ToClientName string
	MessageType  int
	Message      string
}

// LogoutRequest (command 3) — empty body.
type LogoutRequest struct{}

// LogoutResponse (command -3).
type LogoutResponse struct {
	Success bool
	Reason  *string
}

// HeartbeatRequest (command 4) — empty body.
type HeartbeatRequest struct{}

// HeartbeatResponse (command -4) — empty body; also used as a server keep-alive.
type HeartbeatResponse struct{}

// NatMessage (command 6) — the NAT forwarding sub-protocol.
type NatMessage struct {
	Type     int
	Flags    byte
	StreamID uint32
	Value    uint32
	Metadata map[string]any
	Data     []byte
}

func (LoginRequest) Command() int8      { return CommandLoginRequest }
func (LoginResponse) Command() int8     { return CommandLoginResponse }
func (MessageRequest) Command() int8    { return CommandMessageRequest }
func (MessageResponse) Command() int8   { return CommandMessageResponse }
func (LogoutRequest) Command() int8     { return CommandLogoutRequest }
func (LogoutResponse) Command() int8    { return CommandLogoutResponse }
func (HeartbeatRequest) Command() int8  { return CommandHeartbeatRequest }
func (HeartbeatResponse) Command() int8 { return CommandHeartbeatResponse }
func (NatMessage) Command() int8        { return CommandNatMessage }

// Decode parses a packet body (the raw bytes after the 11-byte header) for the given command.
func Decode(command int8, body []byte) (Packet, error) {
	if !knownCommand(command) {
		return nil, fmt.Errorf("unknown command: %d", command)
	}
	if err := validateBodyLength(command, len(body)); err != nil {
		return nil, err
	}
	switch command {
	case CommandLoginRequest:
		return decodeLoginRequest(body)
	case CommandLoginResponse:
		return decodeLoginResponse(body)
	case CommandMessageRequest:
		return decodeMessage(body, false)
	case CommandMessageResponse:
		return decodeMessage(body, true)
	case CommandLogoutRequest:
		if len(body) != 0 {
			return nil, errors.New("logout request body must be empty")
		}
		return LogoutRequest{}, nil
	case CommandLogoutResponse:
		return decodeLogoutResponse(body)
	case CommandHeartbeatRequest:
		if len(body) != 0 {
			return nil, errors.New("heartbeat request body must be empty")
		}
		return HeartbeatRequest{}, nil
	case CommandHeartbeatResponse:
		if len(body) != 0 {
			return nil, errors.New("heartbeat response body must be empty")
		}
		return HeartbeatResponse{}, nil
	case CommandNatMessage:
		return DecodeNatMessage(body)
	}
	return nil, fmt.Errorf("unknown command: %d", command)
}

// EncodeBody serializes a packet to its body bytes (without the framing header).
func EncodeBody(packet Packet) ([]byte, error) {
	switch p := packet.(type) {
	case LoginRequest:
		if p.ConnectionRole != ConnectionRoleControl && p.ConnectionRole != ConnectionRoleData {
			return nil, fmt.Errorf("invalid connection role: %q", p.ConnectionRole)
		}
		return encodeLoginRequest(p), nil
	case LoginResponse:
		return encodeLoginResponse(p), nil
	case MessageRequest:
		return encodeMessage(p.ClientName, p.ToClientName, p.MessageType, p.Message), nil
	case MessageResponse:
		return encodeMessage(p.ClientName, p.ToClientName, p.MessageType, p.Message), nil
	case LogoutRequest:
		return []byte{}, nil
	case LogoutResponse:
		return encodeLogoutResponse(p), nil
	case HeartbeatRequest:
		return []byte{}, nil
	case HeartbeatResponse:
		return []byte{}, nil
	case NatMessage:
		return EncodeNatMessage(p)
	default:
		return nil, fmt.Errorf("cannot encode packet type %T", packet)
	}
}

// EncodeFrame serializes a packet to a complete framed wire message.
func EncodeFrame(packet Packet) ([]byte, error) {
	return EncodeFrameLimit(packet, MaxFrameSize)
}

// EncodeFrameLimit serializes a packet while enforcing a full-frame limit.
func EncodeFrameLimit(packet Packet, maxFrameSize int) ([]byte, error) {
	body, err := EncodeBody(packet)
	if err != nil {
		return nil, err
	}
	if maxFrameSize < FrameHeaderSize {
		return nil, fmt.Errorf("max frame size must be at least header size: %d", maxFrameSize)
	}
	if len(body) > maxFrameSize-FrameHeaderSize {
		return nil, fmt.Errorf("packet body exceeds limit: %d", len(body))
	}
	header := make([]byte, FrameHeaderSize)
	binary.BigEndian.PutUint32(header[:4], MagicNumber)
	header[4] = Version
	header[5] = SerializerCompact
	if !knownCommand(packet.Command()) {
		return nil, fmt.Errorf("unknown command: %d", packet.Command())
	}
	if err := validateBodyLength(packet.Command(), len(body)); err != nil {
		return nil, err
	}
	header[6] = byte(packet.Command())
	binary.BigEndian.PutUint32(header[7:11], uint32(len(body)))
	return append(header, body...), nil
}

// WritePacket writes a packet as a complete framed message to writer.
func WritePacket(writer io.Writer, packet Packet) error {
	body, err := EncodeBody(packet)
	if err != nil {
		return err
	}
	return writeFrameBytes(writer, packet.Command(), body)
}

// DecodeFrame parses a complete framed message, returning the packet and bytes consumed.
// It is primarily used by tests against golden fixtures.
func DecodeFrame(data []byte) (Packet, int, error) {
	if len(data) < FrameHeaderSize {
		return nil, 0, errors.New("frame shorter than header")
	}
	if binary.BigEndian.Uint32(data[:4]) != MagicNumber {
		return nil, 0, errors.New("invalid packet magic number")
	}
	if data[4] != Version {
		return nil, 0, fmt.Errorf("unsupported protocol version: %d", data[4])
	}
	if data[5] != SerializerCompact {
		return nil, 0, fmt.Errorf("unsupported serializer: %d", data[5])
	}
	command := int8(data[6])
	if !knownCommand(command) {
		return nil, 0, fmt.Errorf("unknown command: %d", command)
	}
	length := int(int32(binary.BigEndian.Uint32(data[7:11])))
	if length < 0 || length > MaxFrameBodySize {
		return nil, 0, fmt.Errorf("invalid packet body length: %d", length)
	}
	if len(data) != FrameHeaderSize+length {
		return nil, 0, errors.New("declared body length does not match frame")
	}
	if err := validateBodyLength(command, length); err != nil {
		return nil, 0, err
	}
	packet, err := Decode(command, data[FrameHeaderSize:FrameHeaderSize+length])
	if err != nil {
		return nil, 0, err
	}
	return packet, FrameHeaderSize + length, nil
}

// ---- per-packet codecs ---------------------------------------------------------------

func encodeLoginRequest(p LoginRequest) []byte {
	output := newCompactOutput()
	output.writeString(p.ClientName)
	output.writeNullableLong(p.ClientSessionID)
	output.writeString(p.AccessToken)
	output.writeString(p.ConnectionRole)
	return output.payload()
}

func decodeLoginRequest(body []byte) (LoginRequest, error) {
	input, err := newCompactInput(body)
	if err != nil {
		return LoginRequest{}, err
	}
	clientName, err := input.readString()
	if err != nil {
		return LoginRequest{}, err
	}
	sessionID, err := input.readNullableLong()
	if err != nil {
		return LoginRequest{}, err
	}
	accessToken, err := input.readString()
	if err != nil {
		return LoginRequest{}, err
	}
	connectionRole, err := input.readString()
	if err != nil {
		return LoginRequest{}, err
	}
	if connectionRole != ConnectionRoleControl && connectionRole != ConnectionRoleData {
		return LoginRequest{}, fmt.Errorf("invalid connection role: %q", connectionRole)
	}
	if err := input.finish(); err != nil {
		return LoginRequest{}, err
	}
	return LoginRequest{ClientName: clientName, ClientSessionID: sessionID, AccessToken: accessToken,
		ConnectionRole: connectionRole}, nil
}

func encodeLoginResponse(p LoginResponse) []byte {
	output := newCompactOutput()
	output.writeString(p.ClientName)
	output.writeBool(p.Success)
	output.writeOptionalString(p.Reason)
	return output.payload()
}

func decodeLoginResponse(body []byte) (LoginResponse, error) {
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
	reason, err := input.readOptionalString()
	if err != nil {
		return LoginResponse{}, err
	}
	if err := input.finish(); err != nil {
		return LoginResponse{}, err
	}
	return LoginResponse{ClientName: clientName, Success: success, Reason: reason}, nil
}

func encodeMessage(clientName, toClientName string, messageType int, message string) []byte {
	output := newCompactOutput()
	output.writeString(clientName)
	output.writeString(toClientName)
	output.writeEnum(messageType)
	output.writeString(message)
	return output.payload()
}

func decodeMessage(body []byte, response bool) (Packet, error) {
	input, err := newCompactInput(body)
	if err != nil {
		return nil, err
	}
	clientName, err := input.readString()
	if err != nil {
		return nil, err
	}
	toClientName, err := input.readString()
	if err != nil {
		return nil, err
	}
	messageType, err := input.readEnum()
	if err != nil {
		return nil, err
	}
	message, err := input.readString()
	if err != nil {
		return nil, err
	}
	if err := input.finish(); err != nil {
		return nil, err
	}
	if response {
		return MessageResponse{ClientName: clientName, ToClientName: toClientName, MessageType: messageType, Message: message}, nil
	}
	return MessageRequest{ClientName: clientName, ToClientName: toClientName, MessageType: messageType, Message: message}, nil
}

func encodeLogoutResponse(p LogoutResponse) []byte {
	output := newCompactOutput()
	output.writeBool(p.Success)
	output.writeOptionalString(p.Reason)
	return output.payload()
}

func decodeLogoutResponse(body []byte) (LogoutResponse, error) {
	input, err := newCompactInput(body)
	if err != nil {
		return LogoutResponse{}, err
	}
	success, err := input.readBool()
	if err != nil {
		return LogoutResponse{}, err
	}
	reason, err := input.readOptionalString()
	if err != nil {
		return LogoutResponse{}, err
	}
	if err := input.finish(); err != nil {
		return LogoutResponse{}, err
	}
	return LogoutResponse{Success: success, Reason: reason}, nil
}

// EncodeNatMessage serializes a v2 NAT body:
// type(u8) | flags(u8) | metadataLength(u16) | streamId(u32) | value(u32) |
// dataLength(u32) | metadata | raw data.
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
	if len(message.Data) > MaxFrameBodySize-natBodyHeaderSize-len(metadata) {
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

// DecodeNatMessage parses a v2 NAT_MESSAGE body and requires exact byte consumption.
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

func validateBodyLength(command int8, length int) error {
	maximum := MaxFrameBodySize
	if command == CommandLoginRequest || command == CommandLoginResponse {
		maximum = PreAuthMaxFrameSize - FrameHeaderSize
	} else if command == CommandMessageRequest || command == CommandMessageResponse {
		maximum = maxMessageBodyBytes
	}
	if length < 0 || length > maximum {
		return fmt.Errorf("command %d body exceeds limit: %d/%d", command, length, maximum)
	}
	return nil
}

// writeStringMap writes a nullable string map. Note: Go map iteration is unordered, so the
// emitted byte order is not stable across calls; the server never relies on map byte-exactness
// (the legacy HTTP proxy is decode-only in practice). Keys are sorted for determinism.
func (output *compactOutput) writeStringMap(values map[string]string) {
	if values == nil {
		_ = output.writeVarInt(0)
		return
	}
	_ = output.writeVarInt(len(values) + 1)
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		output.writeString(key)
		output.writeString(values[key])
	}
}
