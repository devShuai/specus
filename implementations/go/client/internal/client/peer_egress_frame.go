package client

import (
	"encoding/binary"
	"encoding/json"
)

// SPEG1 is the third plaintext type carried inside an SPM2 frame, alongside a bare IPv4 packet and
// an STMSG2 application message. Egress traffic gets its own type on purpose: relaxing the existing
// bare-IPv4 checks to carry it would weaken the mesh path, so the two are separated the moment the
// payload is decrypted.
//
// Wire format and rejection cases: protocol/spec/peer-egress.md, driven by
// protocol/test-vectors/peer-egress-frame-v1.json.

const (
	peerEgressFrameHeaderLen = 8
	peerEgressTypeIPPacket   = 1
	peerEgressTypeControl    = 2

	// bit0 is set by an egress device when it forwards while acting as a consumer itself. An egress
	// that receives it refuses: there are no multi-hop egress chains.
	peerEgressFlagHop = 0x01
)

var peerEgressMagic = [5]byte{'S', 'P', 'E', 'G', '1'}

// Control message types this version understands. name-bind is reserved for phase two domain
// routing and must be refused now rather than silently treated as implemented.
const (
	peerEgressControlFlowReject = "flow-reject"
	peerEgressControlFlowPurge  = "flow-purge"
)

type peerEgressFrame struct {
	Type  byte
	Hop   bool
	Body  []byte
	Inner peerEgressInner
}

// peerEgressInner is the parsed IPv4 tuple of a type=1 body, filled only for that type.
type peerEgressInner struct {
	SourceIP        string
	DestinationIP   string
	Protocol        int
	SourcePort      int
	DestinationPort int
}

type peerEgressControl struct {
	Type            string   `json:"type"`
	Protocol        string   `json:"protocol,omitempty"`
	SourceIP        string   `json:"sourceIp,omitempty"`
	SourcePort      int      `json:"sourcePort,omitempty"`
	DestinationIP   string   `json:"destinationIp,omitempty"`
	DestinationPort int      `json:"destinationPort,omitempty"`
	Destinations    []string `json:"destinations,omitempty"`
	Code            string   `json:"code,omitempty"`
}

// looksLikePeerEgressFrame reports whether a decrypted payload carries the SPEG1 magic.
//
// Only the magic is checked, so a frame that is addressed to the egress path but malformed is still
// routed here and rejected with its own code, rather than falling through to the bare-IPv4 checks
// and being dropped for the wrong reason.
func looksLikePeerEgressFrame(payload []byte) bool {
	return len(payload) >= len(peerEgressMagic) &&
		string(payload[:len(peerEgressMagic)]) == string(peerEgressMagic[:])
}

// parsePeerEgressFrame decodes one SPEG1 frame, returning the failing result code on rejection.
//
// The checks run in a fixed order so every implementation reports the same code for a frame that
// violates more than one constraint.
func parsePeerEgressFrame(payload []byte) (peerEgressFrame, string) {
	if len(payload) < peerEgressFrameHeaderLen {
		return peerEgressFrame{}, egressCodeFrameTruncated
	}
	if string(payload[:5]) != string(peerEgressMagic[:]) {
		return peerEgressFrame{}, egressCodeFrameBadMagic
	}
	frameType := payload[5]
	if frameType != peerEgressTypeIPPacket && frameType != peerEgressTypeControl {
		return peerEgressFrame{}, egressCodeFrameUnknownType
	}
	flags := payload[6]
	// Reserved bits and the reserved byte are refused rather than ignored: tolerating them now
	// would make them unusable for a later version, since old builds would accept anything.
	if flags&^peerEgressFlagHop != 0 || payload[7] != 0 {
		return peerEgressFrame{}, egressCodeFrameReservedSet
	}
	frame := peerEgressFrame{Type: frameType, Hop: flags&peerEgressFlagHop != 0, Body: payload[peerEgressFrameHeaderLen:]}
	if frame.Hop {
		return peerEgressFrame{}, egressCodeHopNotAllowed
	}
	if frameType == peerEgressTypeControl {
		if code := validatePeerEgressControlBody(frame.Body); code != "" {
			return peerEgressFrame{}, code
		}
		return frame, ""
	}
	inner, code := parsePeerEgressInnerPacket(frame.Body)
	if code != "" {
		return peerEgressFrame{}, code
	}
	frame.Inner = inner
	return frame, ""
}

func parsePeerEgressInnerPacket(body []byte) (peerEgressInner, string) {
	if len(body) < 20 {
		return peerEgressInner{}, egressCodeFrameTruncated
	}
	if body[0]>>4 != 4 {
		return peerEgressInner{}, egressCodeIPv6Unsupported
	}
	ihl := int(body[0]&0x0f) * 4
	if ihl < 20 || len(body) < ihl {
		return peerEgressInner{}, egressCodeFrameTruncated
	}
	total := int(binary.BigEndian.Uint16(body[2:4]))
	if total < ihl || total > len(body) {
		return peerEgressInner{}, egressCodeFrameTruncated
	}
	// A body longer than the IPv4 total length means trailing bytes rode along; refuse rather than
	// silently keeping the prefix.
	if total != len(body) {
		return peerEgressInner{}, egressCodeFrameTrailingBytes
	}
	inner := peerEgressInner{
		SourceIP:      peerPacketSourceIPv4(body),
		DestinationIP: peerPacketDestinationIPv4(body),
		Protocol:      peerPacketProtocol(body),
	}
	if (inner.Protocol == ipv4ProtocolTCP || inner.Protocol == ipv4ProtocolUDP) && len(body) >= ihl+4 {
		inner.SourcePort = int(binary.BigEndian.Uint16(body[ihl : ihl+2]))
		inner.DestinationPort = int(binary.BigEndian.Uint16(body[ihl+2 : ihl+4]))
	}
	return inner, ""
}

func validatePeerEgressControlBody(body []byte) string {
	var control peerEgressControl
	if err := json.Unmarshal(body, &control); err != nil {
		return egressCodeFrameMalformedControl
	}
	switch control.Type {
	case peerEgressControlFlowReject, peerEgressControlFlowPurge:
		return ""
	default:
		// Includes name-bind, which phase two defines. Refusing keeps a phase-one egress from
		// looking like it honours domain rules it does not implement.
		return egressCodeControlUnsupported
	}
}

// decodePeerEgressControl reads a validated control body.
func decodePeerEgressControl(body []byte) (peerEgressControl, bool) {
	var control peerEgressControl
	if err := json.Unmarshal(body, &control); err != nil {
		return peerEgressControl{}, false
	}
	return control, true
}

// encodePeerEgressFrame builds a frame. hop is set only when this node forwards as a consumer.
func encodePeerEgressFrame(frameType byte, hop bool, body []byte) []byte {
	frame := make([]byte, peerEgressFrameHeaderLen+len(body))
	copy(frame[:5], peerEgressMagic[:])
	frame[5] = frameType
	if hop {
		frame[6] = peerEgressFlagHop
	}
	copy(frame[peerEgressFrameHeaderLen:], body)
	return frame
}

// encodePeerEgressControl serialises a control message with the key order the spec fixes, so two
// implementations produce byte-identical frames for the same message.
func encodePeerEgressControl(control peerEgressControl) ([]byte, error) {
	return json.Marshal(control)
}
