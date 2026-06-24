package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
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
}

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

// HTTPRequest (command 5) — legacy client-to-client HTTP proxy.
type HTTPRequest struct {
	ClientName    string
	ToClientName  string
	RequestID     string
	RequestMethod string
	RequestURL    string
	HeaderMap     map[string]string
	ParamMap      map[string]string
	Body          string
}

// HTTPResponse (command -5).
type HTTPResponse struct {
	ClientName   string
	ToClientName string
	RequestID    string
	Response     string
}

// DirectHTTPRequest (command 7) — server-originated HTTP forwarded to the client.
type DirectHTTPRequest struct {
	RequestID     string
	RequestMethod string
	Route         string
	RelativePath  string
	RawQuery      string
	Headers       []string
	Body          []byte
}

// DirectHTTPResponse (command -7).
type DirectHTTPResponse struct {
	RequestID  string
	StatusCode int
	Headers    []string
	Body       []byte
	Error      *string
}

// NatMessage (command 6) — the NAT forwarding sub-protocol.
type NatMessage struct {
	Type     int
	Metadata map[string]any
	Data     []byte
}

func (LoginRequest) Command() int8       { return CommandLoginRequest }
func (LoginResponse) Command() int8      { return CommandLoginResponse }
func (MessageRequest) Command() int8     { return CommandMessageRequest }
func (MessageResponse) Command() int8    { return CommandMessageResponse }
func (LogoutRequest) Command() int8      { return CommandLogoutRequest }
func (LogoutResponse) Command() int8     { return CommandLogoutResponse }
func (HeartbeatRequest) Command() int8   { return CommandHeartbeatRequest }
func (HeartbeatResponse) Command() int8  { return CommandHeartbeatResponse }
func (HTTPRequest) Command() int8        { return CommandHTTPRequest }
func (HTTPResponse) Command() int8       { return CommandHTTPResponse }
func (DirectHTTPRequest) Command() int8  { return CommandDirectHTTPRequest }
func (DirectHTTPResponse) Command() int8 { return CommandDirectHTTPResponse }
func (NatMessage) Command() int8         { return CommandNatMessage }

// Decode parses a packet body (the raw bytes after the 11-byte header) for the given command.
func Decode(command int8, body []byte) (Packet, error) {
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
		if _, err := newCompactInput(body); err != nil {
			return nil, err
		}
		return LogoutRequest{}, nil
	case CommandLogoutResponse:
		return decodeLogoutResponse(body)
	case CommandHeartbeatRequest:
		return HeartbeatRequest{}, nil
	case CommandHeartbeatResponse:
		return HeartbeatResponse{}, nil
	case CommandHTTPRequest:
		return decodeHTTPRequest(body)
	case CommandHTTPResponse:
		return decodeHTTPResponse(body)
	case CommandDirectHTTPRequest:
		return decodeDirectHTTPRequest(body)
	case CommandDirectHTTPResponse:
		return decodeDirectHTTPResponse(body)
	case CommandNatMessage:
		return DecodeNatMessage(body)
	default:
		return nil, fmt.Errorf("unknown command: %d", command)
	}
}

// EncodeBody serializes a packet to its body bytes (without the framing header).
func EncodeBody(packet Packet) ([]byte, error) {
	switch p := packet.(type) {
	case LoginRequest:
		return encodeLoginRequest(p), nil
	case LoginResponse:
		return encodeLoginResponse(p), nil
	case MessageRequest:
		return encodeMessage(p.ClientName, p.ToClientName, p.MessageType, p.Message), nil
	case MessageResponse:
		return encodeMessage(p.ClientName, p.ToClientName, p.MessageType, p.Message), nil
	case LogoutRequest:
		return encodePayload(nil), nil
	case LogoutResponse:
		return encodeLogoutResponse(p), nil
	case HeartbeatRequest:
		return encodePayload(nil), nil
	case HeartbeatResponse:
		return encodePayload(nil), nil
	case HTTPRequest:
		return encodeHTTPRequest(p), nil
	case HTTPResponse:
		return encodeHTTPResponse(p), nil
	case DirectHTTPRequest:
		return encodeDirectHTTPRequest(p), nil
	case DirectHTTPResponse:
		return encodeDirectHTTPResponse(p), nil
	case NatMessage:
		return EncodeNatMessage(p)
	default:
		return nil, fmt.Errorf("cannot encode packet type %T", packet)
	}
}

// EncodeFrame serializes a packet to a complete framed wire message.
func EncodeFrame(packet Packet) ([]byte, error) {
	body, err := EncodeBody(packet)
	if err != nil {
		return nil, err
	}
	header := make([]byte, FrameHeaderSize)
	binary.BigEndian.PutUint32(header[:4], MagicNumber)
	header[4] = Version
	header[5] = SerializerCompact
	if packet.Command() == CommandNatMessage {
		header[5] = SerializerFastJSON
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
	length := int(int32(binary.BigEndian.Uint32(data[7:11])))
	if length < 0 || length > MaxFrameSize {
		return nil, 0, fmt.Errorf("invalid packet body length: %d", length)
	}
	if len(data) < FrameHeaderSize+length {
		return nil, 0, errors.New("frame truncated")
	}
	command := int8(data[6])
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
	if err := input.finish(); err != nil {
		return LoginRequest{}, err
	}
	return LoginRequest{ClientName: clientName, ClientSessionID: sessionID, AccessToken: accessToken}, nil
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

func encodeHTTPRequest(p HTTPRequest) []byte {
	output := newCompactOutput()
	output.writeString(p.ClientName)
	output.writeString(p.ToClientName)
	output.writeUUIDString(p.RequestID)
	output.writeHTTPMethod(p.RequestMethod)
	output.writeString(p.RequestURL)
	output.writeStringMap(p.HeaderMap)
	output.writeStringMap(p.ParamMap)
	output.writeString(p.Body)
	return output.payload()
}

func decodeHTTPRequest(body []byte) (HTTPRequest, error) {
	input, err := newCompactInput(body)
	if err != nil {
		return HTTPRequest{}, err
	}
	clientName, err := input.readString()
	if err != nil {
		return HTTPRequest{}, err
	}
	toClientName, err := input.readString()
	if err != nil {
		return HTTPRequest{}, err
	}
	requestID, err := input.readUUIDString()
	if err != nil {
		return HTTPRequest{}, err
	}
	method, err := input.readHTTPMethod()
	if err != nil {
		return HTTPRequest{}, err
	}
	requestURL, err := input.readString()
	if err != nil {
		return HTTPRequest{}, err
	}
	headerMap, err := input.readStringMap()
	if err != nil {
		return HTTPRequest{}, err
	}
	paramMap, err := input.readStringMap()
	if err != nil {
		return HTTPRequest{}, err
	}
	requestBody, err := input.readString()
	if err != nil {
		return HTTPRequest{}, err
	}
	if err := input.finish(); err != nil {
		return HTTPRequest{}, err
	}
	return HTTPRequest{
		ClientName: clientName, ToClientName: toClientName, RequestID: requestID,
		RequestMethod: method, RequestURL: requestURL, HeaderMap: headerMap, ParamMap: paramMap, Body: requestBody,
	}, nil
}

func encodeHTTPResponse(p HTTPResponse) []byte {
	output := newCompactOutput()
	output.writeString(p.ClientName)
	output.writeString(p.ToClientName)
	output.writeUUIDString(p.RequestID)
	output.writeString(p.Response)
	return output.payload()
}

func decodeHTTPResponse(body []byte) (HTTPResponse, error) {
	input, err := newCompactInput(body)
	if err != nil {
		return HTTPResponse{}, err
	}
	clientName, err := input.readString()
	if err != nil {
		return HTTPResponse{}, err
	}
	toClientName, err := input.readString()
	if err != nil {
		return HTTPResponse{}, err
	}
	requestID, err := input.readUUIDString()
	if err != nil {
		return HTTPResponse{}, err
	}
	response, err := input.readString()
	if err != nil {
		return HTTPResponse{}, err
	}
	if err := input.finish(); err != nil {
		return HTTPResponse{}, err
	}
	return HTTPResponse{ClientName: clientName, ToClientName: toClientName, RequestID: requestID, Response: response}, nil
}

func encodeDirectHTTPRequest(p DirectHTTPRequest) []byte {
	output := newCompactOutput()
	output.writeUUIDString(p.RequestID)
	output.writeHTTPMethod(p.RequestMethod)
	output.writeString(p.Route)
	output.writeString(p.RelativePath)
	output.writeString(p.RawQuery)
	output.writeStringList(p.Headers)
	output.writeByteArray(p.Body)
	return output.payload()
}

func decodeDirectHTTPRequest(body []byte) (DirectHTTPRequest, error) {
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
	if requestBody == nil {
		requestBody = []byte{}
	}
	return DirectHTTPRequest{
		RequestID: requestID, RequestMethod: method, Route: route, RelativePath: relativePath,
		RawQuery: rawQuery, Headers: headers, Body: requestBody,
	}, nil
}

func encodeDirectHTTPResponse(p DirectHTTPResponse) []byte {
	output := newCompactOutput()
	output.writeUUIDString(p.RequestID)
	_ = output.writeVarInt(p.StatusCode)
	output.writeStringList(p.Headers)
	output.writeByteArray(p.Body)
	output.writeOptionalString(p.Error)
	return output.payload()
}

func decodeDirectHTTPResponse(body []byte) (DirectHTTPResponse, error) {
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
	responseError, err := input.readOptionalString()
	if err != nil {
		return DirectHTTPResponse{}, err
	}
	if err := input.finish(); err != nil {
		return DirectHTTPResponse{}, err
	}
	return DirectHTTPResponse{
		RequestID: requestID, StatusCode: statusCode, Headers: headers, Body: responseBody, Error: responseError,
	}, nil
}

// EncodeNatMessage serializes a NAT_MESSAGE body: int32 type | int32 metaLen | json meta | payload.
func EncodeNatMessage(message NatMessage) ([]byte, error) {
	var metadata []byte
	var err error
	if message.Metadata == nil {
		metadata = []byte("null")
	} else {
		metadata, err = json.Marshal(message.Metadata)
		if err != nil {
			return nil, fmt.Errorf("encode NAT metadata: %w", err)
		}
	}
	output := make([]byte, 8, 8+len(metadata)+len(message.Data)+1)
	binary.BigEndian.PutUint32(output[:4], uint32(int32(message.Type)))
	binary.BigEndian.PutUint32(output[4:8], uint32(int32(len(metadata))))
	output = append(output, metadata...)
	if len(message.Data) > 0 {
		output = append(output, encodePayload(message.Data)...)
	}
	return output, nil
}

// DecodeNatMessage parses a NAT_MESSAGE body.
func DecodeNatMessage(body []byte) (NatMessage, error) {
	if len(body) < 8 {
		return NatMessage{}, errors.New("NAT packet is too short")
	}
	messageType := int(int32(binary.BigEndian.Uint32(body[:4])))
	metadataLength := int(int32(binary.BigEndian.Uint32(body[4:8])))
	if metadataLength < 0 || len(body)-8 < metadataLength {
		return NatMessage{}, errors.New("invalid NAT metadata length")
	}
	var metadata map[string]any
	metaBytes := body[8 : 8+metadataLength]
	if metadataLength > 0 && string(metaBytes) != "null" {
		metadata = make(map[string]any)
		if err := json.Unmarshal(metaBytes, &metadata); err != nil {
			return NatMessage{}, fmt.Errorf("decode NAT metadata: %w", err)
		}
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
