package client

import (
	"encoding/binary"
	"log"
	"sort"
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
	// egressOutcomeBlockedFakeIP is a packet to a fake address that no name, or no rule, stands
	// behind any more (phase two).
	egressOutcomeBlockedFakeIP
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
	case egressOutcomeBlockedFakeIP:
		return "blocked-fake-ip"
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
	// registered orders flows that were last seen at the same moment, so eviction is
	// deterministic: of two equally idle flows, the one registered first goes.
	registered uint64
	// A TCP flow closes on an RST either way or once both directions have sent FIN; from then it
	// is kept only long enough to take the stragglers (egressConsumerClosedLinger).
	finOut, finIn bool
	closedAt      time.Time
	// What the application last said on a TCP flow, kept so the flow can be reset without waiting
	// for it to speak again. Its acknowledgement number is its receive-next, the one sequence
	// number a stack accepts a reset at (RFC 5961); its next sequence number is what the reset
	// acknowledges. Unknown until the application has sent a segment carrying ACK.
	AppAckKnown bool
	AppAck      uint32
	AppSeqNext  uint32
	// replied is set once the egress has sent anything back on this flow. Until then a flow to a
	// fake address carries its name-bind on every datagram (see handleOutbound).
	replied bool
}

type egressConsumer struct {
	mu       sync.Mutex
	logger   *log.Logger
	rules    []egressRule
	meshCIDR string
	// virtualIP is this node's mesh address, which every reply must be addressed to.
	virtualIP string

	// Phase two (protocol/spec/peer-egress-dns.md). fakeIPCIDR is the pool while phase two runs and
	// "" while it does not; fakeIP hands out its addresses. capable is which egresses the catalogue
	// says resolve names: a flow to a name goes only to one of those.
	fakeIPCIDR string
	fakeIP     *egressFakeIPPool
	capable    map[int64]bool
	// clock is what the status reads the pool's counts at; the data plane takes time as an
	// argument, like everything else here.
	clock func() time.Time

	// online is which egress peers can currently take a flow. Absent means no.
	online map[int64]bool
	flows  map[egressFlowKey]*egressConsumerFlow
	// flowCapacity bounds flows; flowOrder numbers them as they register. latest is the newest
	// time any caller passed in, which the status uses to count only the flows still remembered.
	flowCapacity int
	flowOrder    uint64
	latest       time.Time
	lastSweep    time.Time

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
		capable:  map[int64]bool{},
		clock:    time.Now,
		online:   map[int64]bool{},
		flows:    map[egressFlowKey]*egressConsumerFlow{},

		flowCapacity: egressConsumerFlowCapacity,
		send:         send,
		toTun:        toTun,
		blocked:      map[string]int64{},
	}
}

// configure installs a rule set and closes the flows it invalidates.
//
// Established flows survive a rule change unless their rule stopped saying egress or stopped
// matching. The returned purge messages tell each affected egress to close its side; without them
// the egress would hold the socket until its own idle timer, and the user would see a connection
// that is dead at one end and open at the other.
func (c *egressConsumer) configure(rules []egressRule, meshCIDR string, virtualIP string, now time.Time) map[int64][]string {
	return c.configureIn(rules, meshCIDR, virtualIP, "", now)
}

// configureIn is configure with phase two: fakeIPCIDR is the pool while phase two runs, "" while it
// does not. The pool's mappings outlive a rule change, since a name handed out under the old rules
// may still be in an application's cache and has to be recognised as stale rather than unmapped;
// they go only with the pool itself.
func (c *egressConsumer) configureIn(rules []egressRule, meshCIDR, virtualIP, fakeIPCIDR string, now time.Time) map[int64][]string {
	c.mu.Lock()
	c.rules = append([]egressRule(nil), rules...)
	if trimmed := strings.TrimSpace(meshCIDR); trimmed != "" {
		c.meshCIDR = trimmed
	}
	c.virtualIP = strings.TrimSpace(virtualIP)
	fakeIPCIDR = strings.TrimSpace(fakeIPCIDR)
	if fakeIPCIDR != c.fakeIPCIDR {
		c.fakeIPCIDR, c.fakeIP = "", nil
		if pool, ok := parseEgressCIDR(fakeIPCIDR); ok {
			c.fakeIPCIDR, c.fakeIP = fakeIPCIDR, newEgressFakeIPPool(pool)
		}
	}
	purge, resets := c.purgeInvalidatedLocked(now)
	toTun := c.toTun
	c.mu.Unlock()
	c.writeResets(toTun, resets)
	return purge
}

// setDomainCapable replaces which egresses resolve names, from an accepted catalogue, and closes the
// flows to names that an egress which no longer resolves them was carrying.
func (c *egressConsumer) setDomainCapable(capable map[int64]bool, now time.Time) map[int64][]string {
	c.mu.Lock()
	c.capable = make(map[int64]bool, len(capable))
	for id, able := range capable {
		c.capable[id] = able
	}
	purge, resets := c.purgeInvalidatedLocked(now)
	toTun := c.toTun
	c.mu.Unlock()
	c.writeResets(toTun, resets)
	return purge
}

// assignFakeIP hands out the pool address for a name the DNS responder is answering (step four of
// protocol/spec/peer-egress-dns.md). ok is false while phase two is not running. Each eviction and
// an exhausted pool are logged, by fake address and never by name: which names this device looked
// up is its user's browsing history.
func (c *egressConsumer) assignFakeIP(name string, now time.Time) (assignment egressFakeIPAssignment, ok bool) {
	c.mu.Lock()
	pool := c.fakeIP
	if pool != nil {
		assignment = pool.assign(name, now)
	}
	c.mu.Unlock()
	if pool == nil {
		return egressFakeIPAssignment{}, false
	}
	for _, evicted := range assignment.Evicted {
		c.logger.Printf("[peer-egress-consumer] fake-IP mapping %s evicted after %s unused",
			formatEgressAddress(evicted.Address), egressFakeIPMinLifetime)
	}
	if assignment.Exhausted {
		c.logger.Printf("[peer-egress-consumer] fake-IP pool exhausted; the query is answered SERVFAIL")
	}
	return assignment, true
}

// fakeIPName is the name a pool address was handed out for, for the responder's reverse answers.
// Not a use of the mapping, so it does not refresh it.
func (c *egressConsumer) fakeIPName(address uint32, now time.Time) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fakeIP == nil {
		return "", false
	}
	return c.fakeIP.nameFor(address, now, false)
}

// setEgressOnline records whether an egress peer can take flows.
//
// Going offline closes its flows rather than leaving them to time out, because every packet they
// would carry in the meantime is one the rule says must not go out locally.
func (c *egressConsumer) setEgressOnline(egress int64, online bool, now time.Time) map[int64][]string {
	c.mu.Lock()
	c.online[egress] = online
	if online {
		c.mu.Unlock()
		return nil
	}
	purge, resets := c.purgeInvalidatedLocked(now)
	toTun := c.toTun
	c.mu.Unlock()
	c.writeResets(toTun, resets)
	return purge
}

// purgeInvalidatedLocked drops flows whose rule no longer sends them to the egress they are using,
// and returns the destinations to purge per egress together with the resets that tell the
// application each flow is over.
//
// A flow to a fake address is re-examined by the same decision a new packet gets, without touching
// the mapping: a rule change is not traffic, and counting it as use would keep a name alive that
// nothing is using. The purge names the fake address itself, which is what the egress keyed the
// flow on.
//
// The resets are returned rather than written here, so the device is written to with no lock held.
func (c *egressConsumer) purgeInvalidatedLocked(now time.Time) (map[int64][]string, [][]byte) {
	// A flow already forgotten is not reset: its application stopped waiting long ago.
	c.sweepLocked(now)
	purge := map[int64][]string{}
	var resets [][]byte
	for key, flow := range c.flows {
		steering := c.steerLocked(key.remoteIP, now, false)
		stillOurs := steering.claimed && steering.blocked == "" &&
			steering.egress == flow.Egress &&
			c.online[flow.Egress] &&
			(steering.name == "" || c.capable[flow.Egress])
		if stillOurs {
			continue
		}
		delete(c.flows, key)
		destination := formatEgressAddress(key.remoteIP) + "/32"
		purge[flow.Egress] = append(purge[flow.Egress], destination)
		if reset := egressFlowResetPacket(flow); reset != nil {
			resets = append(resets, reset)
		}
	}
	for egress := range purge {
		purge[egress] = sortedUniqueStrings(purge[egress])
	}
	return purge, resets
}

func (c *egressConsumer) writeResets(toTun func([]byte) error, resets [][]byte) {
	if toTun == nil {
		return
	}
	for _, reset := range resets {
		_ = toTun(reset)
	}
}

// sortedUniqueStrings orders the destinations and drops repeats.
//
// Sorted because the flows they came from live in a map, so without it the same rule change would
// produce the destinations in a different order every run: an operator comparing two flow-purge
// messages, or a test reading one, could not tell a real difference from map iteration.
func sortedUniqueStrings(values []string) []string {
	sort.Strings(values)
	out := values[:0]
	for index, value := range values {
		if index > 0 && value == values[index-1] {
			continue
		}
		out = append(out, value)
	}
	return out
}

// egressSteering is what the rules say about one destination, before anything about the packet
// itself is looked at.
type egressSteering struct {
	// claimed is false when no rule claims the destination and it is not in the fake-IP pool.
	claimed bool
	// blocked is the reason a claimed destination goes nowhere, and answered whether the
	// application is told so at once.
	blocked  string
	answered bool
	// egress carries the destination otherwise, and name is the name a fake address stands for.
	egress int64
	name   string
}

// steerLocked decides a destination.
//
// A destination in the fake-IP pool is steered by the name it was handed out for and never by an
// address rule, which validation keeps out of the pool. It is always claimed: a pool address sent
// out locally or to the wrong egress would take the traffic somewhere no rule said, which is the one
// real leak of the fake-IP scheme. Outside the pool, phase one's address rules decide.
//
// touch refreshes the mapping, which traffic does and a rule change re-examining a flow does not.
func (c *egressConsumer) steerLocked(destination uint32, now time.Time, touch bool) egressSteering {
	if c.fakeIP != nil && c.fakeIP.contains(destination) {
		// The responder's own address, the network and the broadcast are never mapped, so they
		// fall here as well. Step four takes the responder's port 53 before this is reached.
		name, mapped := c.fakeIP.nameFor(destination, now, touch)
		if !mapped {
			return egressSteering{claimed: true, blocked: "fake-ip-unmapped", answered: true}
		}
		index := selectEgressDomainRule(c.rules, name, c.meshCIDR, c.fakeIPCIDR)
		if index < 0 || c.rules[index].Action == egressActionDirect {
			// The name was handed out under rules that no longer claim it. Its real address is
			// not known here, so letting it through could only be a guess; answering makes the
			// application ask again, and the new query goes wherever the rules now say.
			return egressSteering{claimed: true, blocked: "fake-ip-stale", answered: true}
		}
		rule := c.rules[index]
		if rule.Action == egressActionBlock {
			return egressSteering{claimed: true, blocked: "rule"}
		}
		return egressSteering{claimed: true, egress: rule.EgressClientID, name: name}
	}
	decision := matchEgressRulesIn(c.rules, formatEgressAddress(destination), c.meshCIDR, c.fakeIPCIDR)
	if decision.Reason != egressReasonMatched ||
		(decision.Action != egressActionEgress && decision.Action != egressActionBlock) {
		return egressSteering{}
	}
	if decision.Action == egressActionBlock {
		return egressSteering{claimed: true, blocked: "rule"}
	}
	return egressSteering{claimed: true, egress: decision.EgressClientID}
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
	destination, parsed := parseEgressAddress(peerPacketDestinationIPv4(packet))
	if !parsed {
		return egressOutcomeNotMine
	}
	protocol := peerPacketProtocol(packet)

	c.mu.Lock()
	steering := c.steerLocked(destination, now, true)
	if !steering.claimed {
		c.mu.Unlock()
		return egressOutcomeNotMine
	}
	if steering.blocked != "" {
		c.recordBlockedLocked(steering.blocked)
		toTun := c.toTun
		c.mu.Unlock()
		if !steering.answered {
			// A block rule is a drop, as in phase one.
			return egressOutcomeBlockedByRule
		}
		// A fake address nothing stands behind is answered like an unavailable egress, so the
		// application fails now and asks again rather than waiting on its own timeout.
		if answer := egressFailurePacket(packet, protocol); answer != nil && toTun != nil {
			_ = toTun(answer)
		}
		return egressOutcomeBlockedFakeIP
	}

	if egressProtocolName(protocol) == "" {
		// ICMP and anything else this version does not carry. The rule says this destination
		// must not go out locally, so it is dropped rather than handed back.
		c.recordBlockedLocked("unsupported-protocol")
		c.mu.Unlock()
		return egressOutcomeUnsupported
	}
	unavailable := ""
	switch {
	case !c.online[steering.egress]:
		unavailable = "egress-unavailable"
	case steering.name != "" && !c.capable[steering.egress]:
		// Online, but the catalogue does not say it resolves names. Sending the name anyway would
		// have it refused at the far end; resolving it here would send the traffic from the wrong
		// network. Answered the same way as an egress that is not there.
		unavailable = "egress-no-domain"
	}
	if unavailable != "" {
		c.recordBlockedLocked(unavailable)
		toTun := c.toTun
		c.mu.Unlock()
		// Answered, not just dropped. The rule is doing what it should, but the application
		// would only learn that from its own timeout; a reset or an unreachable lets it fail now
		// and retry when the egress is back. A failed send, by contrast, stays silent: the
		// session may be re-establishing and the flow may yet recover.
		if answer := egressFailurePacket(packet, protocol); answer != nil && toTun != nil {
			_ = toTun(answer)
		}
		return egressOutcomeBlockedNoEgress
	}

	key, ok := consumerFlowKeyFor(packet, protocol)
	created, unanswered := !ok, false
	if ok {
		flow := c.liveFlowLocked(key, now)
		if flow != nil && protocol == ipv4ProtocolTCP && !flow.closedAt.IsZero() && tcpPacketIsOpening(packet) {
			// A new connection reusing the four-tuple of one that closed.
			delete(c.flows, key)
			flow = nil
		}
		if flow == nil {
			flow = c.registerFlowLocked(key, steering.egress, now)
			created = true
		}
		flow.LastSeen = now
		if protocol == ipv4ProtocolTCP {
			flow.noteApplicationProgress(packet)
			flow.noteTCPFlags(tcpPacketFlags(packet), true, now)
		}
		unanswered = protocol == ipv4ProtocolUDP && !flow.replied
	}
	// The name goes ahead of the packet whenever the egress may be about to open a flow for it: a
	// new flow, every SYN including the application's retransmissions, and every datagram until
	// the egress has answered. Control messages are not reliable, so one copy is not enough; TCP
	// recovers a lost one on the SYN it retransmits anyway, while UDP retransmits nothing of its
	// own, so its datagrams carry the name until a reply shows the egress has it.
	var nameBind []byte
	if steering.name != "" && (created || unanswered || tcpPacketIsOpening(packet)) {
		body, err := encodePeerEgressControl(peerEgressControl{
			Type: peerEgressControlNameBind, Address: formatEgressAddress(destination), Name: steering.name,
		})
		if err == nil {
			nameBind = encodePeerEgressFrame(peerEgressTypeControl, false, body)
		}
	}
	egress, send := steering.egress, c.send
	c.mu.Unlock()

	if send == nil {
		return egressOutcomeBlockedNoEgress
	}
	// A packet whose name did not leave is not sent either: the egress would open a flow to the
	// fake address itself, which never works.
	if nameBind != nil {
		if err := send(egress, nameBind); err != nil {
			c.mu.Lock()
			c.recordBlockedLocked("send-failed")
			c.mu.Unlock()
			return egressOutcomeBlockedNoEgress
		}
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
	if !c.hasReturnFlowLocked(parsed.Inner, parsed.Body, fromEgress, now) {
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
func (c *egressConsumer) hasReturnFlowLocked(inner peerEgressInner, packet []byte, fromEgress int64, now time.Time) bool {
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
	flow := c.liveFlowLocked(key, now)
	if flow == nil || flow.Egress != fromEgress {
		return false
	}
	flow.LastSeen = now
	// The egress has the flow, and with it the name: the datagrams that follow need not carry it.
	flow.replied = true
	if inner.Protocol == ipv4ProtocolTCP {
		flow.noteTCPFlags(tcpPacketFlags(packet), false, now)
	}
	return true
}

// tcpPacketFlags reads the flags of an IPv4 TCP packet, or 0 for anything else.
func tcpPacketFlags(packet []byte) byte {
	if len(packet) < ipv4MinHeaderLen || packet[0]>>4 != 4 || int(packet[9]) != ipv4ProtocolTCP {
		return 0
	}
	ihl := int(packet[0]&0x0f) * 4
	if len(packet) < ihl+14 {
		return 0
	}
	return packet[ihl+13]
}

// tcpPacketIsOpening reports a SYN without ACK: the first packet of a connection.
func tcpPacketIsOpening(packet []byte) bool {
	flags := tcpPacketFlags(packet)
	return flags&tcpFlagSYN != 0 && flags&tcpFlagACK == 0
}

// A flow-reject can overtake (or survive loss of) the remote RST on the UDP peer path.
// Reset locally before forgetting the flow, and only accept its actual egress as the sender.
func (c *egressConsumer) handleInboundControl(frame peerEgressFrame, fromEgress int64, now time.Time) {
	control, ok := decodePeerEgressControl(frame.Body)
	if !ok || control.Type != peerEgressControlFlowReject {
		return
	}
	remote, remoteOK := parseEgressAddress(control.DestinationIP)
	local, localOK := parseEgressAddress(control.SourceIP)
	if !remoteOK || !localOK {
		return
	}
	key := egressFlowKey{protocol: protocolNumberForEgressName(control.Protocol),
		consumerIP: local, consumerPort: uint16(control.SourcePort),
		remoteIP: remote, remotePort: uint16(control.DestinationPort)}
	c.mu.Lock()
	flow, known := c.flows[key]
	if !known || flow.Egress != fromEgress {
		c.mu.Unlock()
		return
	}
	reset := egressFlowResetPacket(flow)
	delete(c.flows, key)
	c.recordBlockedLocked("rejected-" + strings.ToLower(control.Code))
	toTun := c.toTun
	c.mu.Unlock()
	_ = now
	if reset != nil && toTun != nil {
		_ = toTun(reset)
	}
	c.logger.Printf("[peer-egress-consumer] egress=%d refused flow code=%s", fromEgress, control.Code)
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
	c.sweepLocked(c.latest)
	return len(c.flows)
}

// How long a consumer remembers a flow it sent through an egress (protocol/spec/peer-egress.md,
// protocol/test-vectors/peer-egress-consumer-flows-v1.json). Until these, nothing but a revocation
// or a flow-reject removed an entry, so every flow ever made stayed in memory and the status's
// active flows only grew.
const (
	egressConsumerUDPIdle      = 180 * time.Second
	egressConsumerTCPIdle      = 7200 * time.Second
	egressConsumerClosedLinger = 120 * time.Second
	egressConsumerFlowCapacity = 65536
	// A full sweep walks every flow, so it runs at most this often; a flow looked up in between
	// is checked on its own.
	egressConsumerSweepInterval = 10 * time.Second
)

// forgetAt is when a flow stops being remembered.
func (flow *egressConsumerFlow) forgetAt() time.Time {
	switch {
	case flow.Key.protocol != ipv4ProtocolTCP:
		return flow.LastSeen.Add(egressConsumerUDPIdle)
	case !flow.closedAt.IsZero():
		return flow.closedAt.Add(egressConsumerClosedLinger)
	default:
		return flow.LastSeen.Add(egressConsumerTCPIdle)
	}
}

// noteTCPFlags records the close of a TCP flow: an RST either way, or FIN from both sides.
func (flow *egressConsumerFlow) noteTCPFlags(flags byte, outbound bool, now time.Time) {
	if flags&tcpFlagRST != 0 && flow.closedAt.IsZero() {
		flow.closedAt = now
	}
	if flags&tcpFlagFIN != 0 {
		if outbound {
			flow.finOut = true
		} else {
			flow.finIn = true
		}
	}
	if flow.finOut && flow.finIn && flow.closedAt.IsZero() {
		flow.closedAt = now
	}
}

// liveFlowLocked is the flow for key if it is still remembered at now, forgetting it otherwise.
func (c *egressConsumer) liveFlowLocked(key egressFlowKey, now time.Time) *egressConsumerFlow {
	c.noteTimeLocked(now)
	flow, known := c.flows[key]
	if !known {
		return nil
	}
	if !now.Before(flow.forgetAt()) {
		delete(c.flows, key)
		return nil
	}
	return flow
}

// registerFlowLocked adds a flow, making room first when the table is full: whatever has expired,
// then the flow that has been idle longest.
func (c *egressConsumer) registerFlowLocked(key egressFlowKey, egress int64, now time.Time) *egressConsumerFlow {
	if len(c.flows) >= c.flowCapacity {
		c.sweepLocked(now)
	}
	if len(c.flows) >= c.flowCapacity {
		var oldest *egressConsumerFlow
		for _, flow := range c.flows {
			if oldest == nil || flow.LastSeen.Before(oldest.LastSeen) ||
				(flow.LastSeen.Equal(oldest.LastSeen) && flow.registered < oldest.registered) {
				oldest = flow
			}
		}
		delete(c.flows, oldest.Key)
	}
	c.flowOrder++
	flow := &egressConsumerFlow{Key: key, Egress: egress, LastSeen: now, registered: c.flowOrder}
	c.flows[key] = flow
	return flow
}

// noteTimeLocked keeps the newest time seen and sweeps now and then, so a table nobody looks up
// still gives its memory back.
func (c *egressConsumer) noteTimeLocked(now time.Time) {
	if now.After(c.latest) {
		c.latest = now
	}
	if now.Sub(c.lastSweep) >= egressConsumerSweepInterval {
		c.sweepLocked(now)
	}
}

func (c *egressConsumer) sweepLocked(now time.Time) {
	c.lastSweep = now
	for key, flow := range c.flows {
		if !now.Before(flow.forgetAt()) {
			delete(c.flows, key)
		}
	}
}
