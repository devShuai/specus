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

// Control message types this version understands. name-bind is phase two's: a consumer binds a
// fake address to the name a flow to it should reach (protocol/spec/peer-egress-dns.md).
const (
	peerEgressControlFlowReject = "flow-reject"
	peerEgressControlFlowPurge  = "flow-purge"
	peerEgressControlNameBind   = "name-bind"
)

type peerEgressFrame struct {
	Type  byte
	Hop   bool
	Body  []byte
	Inner peerEgressInner
}

// peerEgressInner is the parsed tuple of a type=1 body, filled only for that type. For an IPv6 body
// the addresses are in RFC 5952 form and Protocol is the next header.
type peerEgressInner struct {
	SourceIP        string
	DestinationIP   string
	Protocol        int
	SourcePort      int
	DestinationPort int
	IPv6            bool
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
	// name-bind: the fake address and the name it stands for, in this order on the wire.
	Address string `json:"address,omitempty"`
	Name    string `json:"name,omitempty"`
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

// parsePeerEgressFrame decodes one SPEG1 frame as a receiver without the IPv6 data plane does,
// refusing an IPv6 body with EGRESS_IPV6_UNSUPPORTED. The consumer reads frames this way: it does not
// carry IPv6 (egressConsumerCarriesIPv6).
func parsePeerEgressFrame(payload []byte) (peerEgressFrame, string) {
	return parsePeerEgressFrameFor(payload, false)
}

// parsePeerEgressFrameFor decodes one SPEG1 frame, returning the failing result code on rejection.
// ipv6 says whether this receiver accepts an IPv6 body: an egress that announces ipv6PacketCapable.
//
// The checks run in a fixed order so every implementation reports the same code for a frame that
// violates more than one constraint.
func parsePeerEgressFrameFor(payload []byte, ipv6 bool) (peerEgressFrame, string) {
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
	inner, code := parsePeerEgressInnerPacket(frame.Body, ipv6)
	if code != "" {
		return peerEgressFrame{}, code
	}
	frame.Inner = inner
	return frame, ""
}

// parsePeerEgressInnerPacket reads a type=1 body. A body shorter than the smallest IPv4 header is
// truncated whatever its version, as it was before IPv6 bodies were read: no IPv6 header fits in it
// either. Then the version decides: 4 reads as IPv4, 6 as IPv6 when ipv6 is set, and anything else is
// EGRESS_IPV6_UNSUPPORTED.
func parsePeerEgressInnerPacket(body []byte, ipv6 bool) (peerEgressInner, string) {
	if len(body) < 20 {
		return peerEgressInner{}, egressCodeFrameTruncated
	}
	if ipv6 && body[0]>>4 == 6 {
		return parsePeerEgressInnerPacket6(body)
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

// parsePeerEgressInnerPacket6 reads an IPv6 body (protocol/spec/peer-egress.md, IPv6 数据面, 出口).
//
// Only the fixed header is read: the next header is the protocol, and ports are taken when it is TCP
// or UDP. An extension header is not walked; a packet that starts with one is refused later by
// protocol, the way ICMP over IPv4 is. There are no jumbograms, so a payload length of zero with
// bytes behind the header is trailing bytes like any other mismatch.
func parsePeerEgressInnerPacket6(body []byte) (peerEgressInner, string) {
	if len(body) < ipv6HeaderLen {
		return peerEgressInner{}, egressCodeFrameTruncated
	}
	total := ipv6HeaderLen + int(binary.BigEndian.Uint16(body[4:6]))
	if total > len(body) {
		return peerEgressInner{}, egressCodeFrameTruncated
	}
	if total < len(body) {
		return peerEgressInner{}, egressCodeFrameTrailingBytes
	}
	inner := peerEgressInner{
		SourceIP:      formatEgressAddress6([16]byte(body[8:24])),
		DestinationIP: formatEgressAddress6([16]byte(body[24:40])),
		Protocol:      int(body[6]),
		IPv6:          true,
	}
	if (inner.Protocol == ipv4ProtocolTCP || inner.Protocol == ipv4ProtocolUDP) && len(body) >= ipv6HeaderLen+4 {
		inner.SourcePort = int(binary.BigEndian.Uint16(body[ipv6HeaderLen : ipv6HeaderLen+2]))
		inner.DestinationPort = int(binary.BigEndian.Uint16(body[ipv6HeaderLen+2 : ipv6HeaderLen+4]))
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
	case peerEgressControlNameBind:
		// Both fields, both well formed: a binding the egress cannot resolve or dial is refused here
		// rather than stored.
		if _, ok := parseEgressAddress(control.Address); !ok || !validEgressName(control.Name) {
			return egressCodeFrameMalformedControl
		}
		return ""
	default:
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
