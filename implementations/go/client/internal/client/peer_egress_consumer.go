package client

import (
	"encoding/binary"
	"log"
	"strings"
	"sync"
	"time"
)

// The consumer data plane: packets leaving the TUN, and the replies coming back.
//
// The rule that shapes this file is that a destination matched by an egress rule must never quietly
// go out locally. If the egress is offline, its authorization has been withdrawn, or the flow
// cannot be opened, the packet is dropped. Falling back to the local stack would send the user's
// traffic from the address they arranged for it not to come from, which is worse than the
// connection failing, because it fails silently and in the direction they were guarding against.

type egressConsumerOutcome int

const (
	// egressOutcomeNotMine means no rule claims this destination, so the caller carries on with
	// its own handling. This is not a decision about the packet, it is the absence of one.
	egressOutcomeNotMine egressConsumerOutcome = iota
	egressOutcomeForwarded
	// egressOutcomeBlockedByRule is a rule that says block.
	egressOutcomeBlockedByRule
	// egressOutcomeBlockedNoEgress is a rule that says egress, for an egress that cannot take it.
	egressOutcomeBlockedNoEgress
	// egressOutcomeUnsupported is a packet this version cannot carry, such as IPv6 or ICMP.
	egressOutcomeUnsupported
)

func (o egressConsumerOutcome) String() string {
	switch o {
	case egressOutcomeForwarded:
		return "forwarded"
	case egressOutcomeBlockedByRule:
		return "blocked-by-rule"
	case egressOutcomeBlockedNoEgress:
		return "blocked-no-egress"
	case egressOutcomeUnsupported:
		return "unsupported"
	default:
		return "not-mine"
	}
}

// egressConsumerFlow is one flow this node opened through an egress.
//
// Tracked so a reply can be matched to something we actually asked for, and so a rule change can
// close exactly the flows it invalidates.
type egressConsumerFlow struct {
	Key      egressFlowKey
	Egress   int64
	LastSeen time.Time
}

type egressConsumer struct {
	mu       sync.Mutex
	logger   *log.Logger
	rules    []egressRule
	meshCIDR string
	// virtualIP is this node's mesh address, which every reply must be addressed to.
	virtualIP string

	// online is which egress peers can currently take a flow. Absent means no.
	online map[int64]bool
	flows  map[egressFlowKey]*egressConsumerFlow

	// send delivers an SPEG1 frame to an egress peer; toTun writes a packet to the local stack.
	send  func(egress int64, frame []byte) error
	toTun func(packet []byte) error

	blocked map[string]int64
}

func newEgressConsumer(logger *log.Logger, send func(int64, []byte) error, toTun func([]byte) error) *egressConsumer {
	if logger == nil {
		logger = log.Default()
	}
	return &egressConsumer{
		logger:   logger,
		meshCIDR: egressDefaultMeshCIDR,
		online:   map[int64]bool{},
		flows:    map[egressFlowKey]*egressConsumerFlow{},
		send:     send,
		toTun:    toTun,
		blocked:  map[string]int64{},
	}
}

// configure installs a rule set and closes the flows it invalidates.
//
// Established flows survive a rule change unless their rule stopped saying egress or stopped
// matching. The returned purge messages tell each affected egress to close its side; without them
// the egress would hold the socket until its own idle timer, and the user would see a connection
// that is dead at one end and open at the other.
func (c *egressConsumer) configure(rules []egressRule, meshCIDR string, virtualIP string, now time.Time) map[int64][]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rules = append([]egressRule(nil), rules...)
	if trimmed := strings.TrimSpace(meshCIDR); trimmed != "" {
		c.meshCIDR = trimmed
	}
	c.virtualIP = strings.TrimSpace(virtualIP)
	return c.purgeInvalidatedLocked(now)
}

// setEgressOnline records whether an egress peer can take flows.
//
// Going offline closes its flows rather than leaving them to time out, because every packet they
// would carry in the meantime is one the rule says must not go out locally.
func (c *egressConsumer) setEgressOnline(egress int64, online bool, now time.Time) map[int64][]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.online[egress] = online
	if online {
		return nil
	}
	return c.purgeInvalidatedLocked(now)
}

// purgeInvalidatedLocked drops flows whose rule no longer sends them to the egress they are using,
// and returns the destinations to purge per egress.
func (c *egressConsumer) purgeInvalidatedLocked(now time.Time) map[int64][]string {
	purge := map[int64][]string{}
	for key, flow := range c.flows {
		decision := matchEgressRules(c.rules, formatEgressAddress(key.remoteIP), c.meshCIDR)
		stillOurs := decision.Action == egressActionEgress &&
			decision.EgressClientID == flow.Egress &&
			c.online[flow.Egress]
		if stillOurs {
			continue
		}
		delete(c.flows, key)
		destination := formatEgressAddress(key.remoteIP) + "/32"
		purge[flow.Egress] = append(purge[flow.Egress], destination)
	}
	_ = now
	for egress := range purge {
		purge[egress] = dedupeSortedStrings(purge[egress])
	}
	return purge
}

func dedupeSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := values[:0]
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// handleOutbound decides what happens to one packet read from the TUN.
//
// A destination no rule claims returns egressOutcomeNotMine, so the caller falls through to its own
// handling. That is what keeps this from claiming the mesh's own traffic, which shares the device.
func (c *egressConsumer) handleOutbound(packet []byte, now time.Time) egressConsumerOutcome {
	if len(packet) < ipv4MinHeaderLen {
		return egressOutcomeNotMine
	}
	if packet[0]>>4 != 4 {
		// IPv6 has no rules in this version, so nothing can claim it and it is not ours.
		return egressOutcomeNotMine
	}
	destination := peerPacketDestinationIPv4(packet)
	if destination == "" {
		return egressOutcomeNotMine
	}

	c.mu.Lock()
	decision := matchEgressRules(c.rules, destination, c.meshCIDR)
	if decision.Reason != egressReasonMatched ||
		(decision.Action != egressActionEgress && decision.Action != egressActionBlock) {
		c.mu.Unlock()
		return egressOutcomeNotMine
	}
	if decision.Action == egressActionBlock {
		c.recordBlockedLocked("rule")
		c.mu.Unlock()
		return egressOutcomeBlockedByRule
	}

	protocol := peerPacketProtocol(packet)
	if egressProtocolName(protocol) == "" {
		// ICMP and anything else this version does not carry. The rule says this destination
		// must not go out locally, so it is dropped rather than handed back.
		c.recordBlockedLocked("unsupported-protocol")
		c.mu.Unlock()
		return egressOutcomeUnsupported
	}
	if !c.online[decision.EgressClientID] {
		c.recordBlockedLocked("egress-unavailable")
		c.mu.Unlock()
		return egressOutcomeBlockedNoEgress
	}

	key, ok := consumerFlowKeyFor(packet, protocol)
	if ok {
		if flow, known := c.flows[key]; known {
			flow.LastSeen = now
		} else {
			c.flows[key] = &egressConsumerFlow{Key: key, Egress: decision.EgressClientID, LastSeen: now}
		}
	}
	egress, send := decision.EgressClientID, c.send
	c.mu.Unlock()

	if send == nil {
		return egressOutcomeBlockedNoEgress
	}
	// hop stays clear: this node is acting as a consumer, not forwarding on behalf of another
	// egress. An egress that receives it set refuses, which is what stops multi-hop chains.
	if err := send(egress, encodePeerEgressFrame(peerEgressTypeIPPacket, false, packet)); err != nil {
		c.mu.Lock()
		c.recordBlockedLocked("send-failed")
		c.mu.Unlock()
		return egressOutcomeBlockedNoEgress
	}
	return egressOutcomeForwarded
}

// consumerFlowKeyFor builds the four-tuple as the consumer sees it, which is the mirror of what the
// egress recorded, so a reply can be matched against it.
func consumerFlowKeyFor(packet []byte, protocol int) (egressFlowKey, bool) {
	ihl := int(packet[0]&0x0f) * 4
	if ihl < ipv4MinHeaderLen || len(packet) < ihl+4 {
		return egressFlowKey{}, false
	}
	return egressFlowKey{
		protocol:     protocol,
		consumerIP:   binary.BigEndian.Uint32(packet[12:16]),
		consumerPort: binary.BigEndian.Uint16(packet[ihl : ihl+2]),
		remoteIP:     binary.BigEndian.Uint32(packet[16:20]),
		remotePort:   binary.BigEndian.Uint16(packet[ihl+2 : ihl+4]),
	}, true
}

// handleInbound takes one SPEG1 frame addressed to this node as a consumer and writes the packet to
// the TUN. It reports whether the frame was this node's to handle.
//
// A node can be a consumer and an egress at once, and both roles receive type=1 frames, so the two
// have to be told apart before either acts. A reply is addressed to this node's own virtual IP; a
// frame for the egress role is addressed to the wider network. Control messages split by type:
// flow-reject travels egress to consumer, flow-purge the other way. Anything not ours is left for
// the egress runtime rather than counted as an abuse of the return path.
func (c *egressConsumer) handleInbound(frame []byte, fromEgress int64, now time.Time) bool {
	if !looksLikePeerEgressFrame(frame) {
		return false
	}
	parsed, code := parsePeerEgressFrame(frame)
	if code != "" {
		// A frame nobody can read is not claimed. The egress runtime refuses it with its own
		// code, which is the one an operator needs, and counting it here as well would report
		// one malformed frame twice.
		return false
	}
	if parsed.Type == peerEgressTypeControl {
		control, decoded := decodePeerEgressControl(parsed.Body)
		if !decoded || control.Type != peerEgressControlFlowReject {
			return false
		}
		c.handleInboundControl(parsed, fromEgress, now)
		return true
	}
	if parsed.Type != peerEgressTypeIPPacket {
		return false
	}

	c.mu.Lock()
	if c.virtualIP == "" || parsed.Inner.DestinationIP != c.virtualIP {
		// Not addressed to us as a consumer, so it belongs to the egress role if this node has
		// one. Refusing it here would break a node that is both.
		c.mu.Unlock()
		return false
	}
	source, parsedSource := parseEgressAddress(parsed.Inner.SourceIP)
	if !parsedSource || egressContainedIn(source, []string{c.meshCIDR}) {
		// A reply claiming a mesh address would let an egress speak as another peer.
		c.recordBlockedLocked("return-mesh-source")
		c.mu.Unlock()
		return true
	}
	if !c.hasReturnFlowLocked(parsed.Inner, fromEgress, now) {
		c.recordBlockedLocked("return-no-flow")
		c.mu.Unlock()
		return true
	}
	toTun := c.toTun
	c.mu.Unlock()

	if toTun != nil {
		_ = toTun(parsed.Body)
	}
	return true
}

// hasReturnFlowLocked reports whether a reply belongs to a flow this node opened through this
// egress. The tuple is mirrored, since the reply travels the other way.
func (c *egressConsumer) hasReturnFlowLocked(inner peerEgressInner, fromEgress int64, now time.Time) bool {
	remote, remoteOK := parseEgressAddress(inner.SourceIP)
	local, localOK := parseEgressAddress(inner.DestinationIP)
	if !remoteOK || !localOK {
		return false
	}
	key := egressFlowKey{
		protocol:     inner.Protocol,
		consumerIP:   local,
		consumerPort: uint16(inner.DestinationPort),
		remoteIP:     remote,
		remotePort:   uint16(inner.SourcePort),
	}
	flow, known := c.flows[key]
	if !known || flow.Egress != fromEgress {
		return false
	}
	flow.LastSeen = now
	return true
}

// handleInboundControl reads a flow-reject. It is diagnostic: the application learns the flow is
// dead from the reset the egress user-space stack sends, and this only supplies a readable reason.
func (c *egressConsumer) handleInboundControl(frame peerEgressFrame, fromEgress int64, now time.Time) {
	control, ok := decodePeerEgressControl(frame.Body)
	if !ok || control.Type != peerEgressControlFlowReject {
		return
	}
	c.mu.Lock()
	c.recordBlockedLocked("rejected-" + strings.ToLower(control.Code))
	if remote, parsedRemote := parseEgressAddress(control.DestinationIP); parsedRemote {
		local, parsedLocal := parseEgressAddress(control.SourceIP)
		if parsedLocal {
			delete(c.flows, egressFlowKey{
				protocol:     protocolNumberForEgressName(control.Protocol),
				consumerIP:   local,
				consumerPort: uint16(control.SourcePort),
				remoteIP:     remote,
				remotePort:   uint16(control.DestinationPort),
			})
		}
	}
	logger := c.logger
	c.mu.Unlock()
	_ = now
	if logger != nil {
		logger.Printf("[peer-egress-consumer] egress=%d refused %s:%d code=%s",
			fromEgress, control.DestinationIP, control.DestinationPort, control.Code)
	}
}

func protocolNumberForEgressName(name string) int {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "udp":
		return ipv4ProtocolUDP
	case "tcp":
		return ipv4ProtocolTCP
	default:
		return 0
	}
}

// recordBlockedLocked counts why traffic did not go out. Aggregated by reason and never by
// destination, for the same reason the egress report is: a per-destination record is a browsing
// history, and this one would be the user's own.
func (c *egressConsumer) recordBlockedLocked(reason string) { c.blocked[reason]++ }

func (c *egressConsumer) blockedCounts() map[string]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int64, len(c.blocked))
	for reason, count := range c.blocked {
		out[reason] = count
	}
	return out
}

func (c *egressConsumer) flowCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.flows)
}
