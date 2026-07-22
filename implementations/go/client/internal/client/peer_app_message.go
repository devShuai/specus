package client

import (
	"bytes"
	"encoding/json"
	"strings"
)

const (
	peerAppMessageTypeMessage = "message"
	peerAppMessageTypeAck     = "ack"
)

var peerAppMessagePrefix = []byte("STMSG2\n")

// peerAppMessage is the Java PeerAppMessageCodec wire payload carried inside an
// encrypted SPM2 frame. It is deliberately independent from the control-channel
// CLIENT_TO_CLIENT fallback format.
type peerAppMessage struct {
	Type            string `json:"type"`
	ID              string `json:"id,omitempty"`
	FromClientID    int64  `json:"fromClientId,omitempty"`
	FromClientName  string `json:"fromClientName,omitempty"`
	ToClientID      int64  `json:"toClientId,omitempty"`
	ToClientName    string `json:"toClientName,omitempty"`
	Message         string `json:"message,omitempty"`
	CreatedAtMillis int64  `json:"createdAtMillis,omitempty"`
}

func looksLikePeerAppMessage(payload []byte) bool {
	return bytes.HasPrefix(payload, peerAppMessagePrefix)
}

func decodePeerAppMessage(payload []byte) (*peerAppMessage, bool) {
	if !looksLikePeerAppMessage(payload) {
		return nil, false
	}
	var message peerAppMessage
	if err := json.Unmarshal(payload[len(peerAppMessagePrefix):], &message); err != nil || strings.TrimSpace(message.Type) == "" {
		return nil, false
	}
	return &message, true
}

func encodePeerAppMessage(message peerAppMessage) ([]byte, error) {
	body, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, 0, len(peerAppMessagePrefix)+len(body))
	payload = append(payload, peerAppMessagePrefix...)
	payload = append(payload, body...)
	return payload, nil
}
