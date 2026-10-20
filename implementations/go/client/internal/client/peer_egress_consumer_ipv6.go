package client

import (
	"encoding/binary"
	"strings"
	"time"
)

// The consumer side of the IPv6 data plane (protocol/spec/peer-egress.md, IPv6 数据面, 消费端).
//
// The same rule as for IPv4 shapes it: a destination an egress rule claims never goes out locally.
// What IPv6 adds is a few checks before the rules are asked, because the TUN sees more of the
// system's own IPv6 than it ever saw of IPv4: neighbour discovery and multicast reports on every
// interface, and applications that bound some other address. Pinned by
// protocol/test-vectors/peer-egress-ipv6-v1.json (consumerOutbound, returnPath, failure).

// handleOutbound6 decides what happens to one IPv6 packet read from the TUN.
//
// In order, before the rules: a link-local source or a multicast destination is the system's own
// traffic and is dropped without a count; a source that is not this device's derived address would
// be refused by the egress, which checks it against the session, so it is not sent
// (ipv6-source-not-mesh); a destination inside the derived prefix is another device's, and
// device-to-device traffic stays IPv4 (ipv6-mesh-unsupported). Then the rules, as for IPv4, and
// for a packet that would be sent to an egress the effective MTU of the session to it: below 1280
// it cannot carry IPv6 at all (ipv6-path-mtu).
//
// The path check runs once the rules have named the egress rather than strictly before them, since
// the session whose MTU it reads is the one to the egress the rule names; a packet a block rule
// drops, or one to an egress that is not there, has no session to ask about. None of these drops is
// answered: they are not an egress being unavailable but traffic this data plane cannot carry.
func (c *egressConsumer) handleOutbound6(packet []byte, now time.Time) egressConsumerOutcome {
	if !c.carriesIPv6 || len(packet) < ipv6HeaderLen {
		// Without the data plane no IPv6 rule is in force, so nothing can claim the packet.
		return egressOutcomeNotMine
	}
	source, destination := [16]byte(packet[8:24]), [16]byte(packet[24:40])
	if egressIPv6LinkLocal(source) || egressIPv6Multicast(destination) {
		return egressOutcomeIgnored
	}

	c.mu.Lock()
	if !c.hasVirtual6 || source != c.virtualIP6 {
		c.recordBlockedLocked("ipv6-source-not-mesh")
		c.mu.Unlock()
		return egressOutcomeBlockedIPv6
	}
	if egressMeshCIDR6().contains(destination) {
		c.recordBlockedLocked("ipv6-mesh-unsupported")
		c.mu.Unlock()
		return egressOutcomeBlockedIPv6
	}
	steering := c.steer6Locked(destination)
	if !steering.claimed {
		c.mu.Unlock()
		return egressOutcomeNotMine
	}
	if steering.blocked != "" {
		// A block rule is a drop, as for IPv4.
		c.recordBlockedLocked(steering.blocked)
		c.mu.Unlock()
		return egressOutcomeBlockedByRule
	}
	// The next header is the protocol: TCP and UDP are carried, and anything else -- ICMPv6, an
	// extension header, a fragment header -- is dropped as ICMP is for IPv4.
	nextHeader := int(packet[6])
	if nextHeader != ipv4ProtocolTCP && nextHeader != ipv4ProtocolUDP {
		c.recordBlockedLocked("unsupported-protocol")
		c.mu.Unlock()
		return egressOutcomeUnsupported
	}
	unavailable := c.egressBlockLocked(steering.egress)
	if unavailable == "" && !c.capable6[steering.egress] {
		// Online and not ruled out by the catalogue, but not said to take IPv6 packets: sent anyway
		// it would be refused there with EGRESS_IPV6_UNSUPPORTED. Answered like an egress that is not
		// there, as egress-no-domain is, so the application fails now.
		unavailable = "egress-no-ipv6"
	}
	if unavailable != "" {
		c.recordBlockedLocked(unavailable)
		toTun := c.toTun
		c.mu.Unlock()
		if answer := egressFailurePacket6(packet, nextHeader); answer != nil && toTun != nil {
			_ = toTun(answer)
		}
		return egressOutcomeBlockedNoEgress
	}
	egress, pathMTU := steering.egress, c.pathMTU
	c.mu.Unlock()

	// Asked with no consumer lock held: the session belongs to the mesh, whose lock is taken here.
	if pathMTU != nil && pathMTU(egress) < egressIPv6MinimumMTU {
		c.mu.Lock()
		c.recordBlockedLocked("ipv6-path-mtu")
		c.mu.Unlock()
		return egressOutcomeBlockedIPv6
	}

	c.mu.Lock()
	if key, ok := consumerFlowKeyFor6(packet, nextHeader); ok {
		flow := c.liveFlowLocked(key, now)
		if flow != nil && nextHeader == ipv4ProtocolTCP && !flow.closedAt.IsZero() && tcpPacketIsOpening(packet) {
			// A new connection reusing the five-tuple of one that closed.
			delete(c.flows, key)
			flow = nil
		}
		if flow == nil {
			flow = c.registerFlowLocked(key, egress, now)
		}
		flow.LastSeen = now
		if nextHeader == ipv4ProtocolTCP {
			flow.noteApplicationProgress(packet)
			flow.noteTCPFlags(tcpPacketFlags(packet), true, now)
		}
	}
	send := c.send
	c.mu.Unlock()

	if send == nil {
		return egressOutcomeBlockedNoEgress
	}
	// The packet goes as it is: SPEG1 carries an IPv6 packet unchanged, its version telling the two
	// families apart. hop stays clear, as for IPv4.
	if err := send(egress, encodePeerEgressFrame(peerEgressTypeIPPacket, false, packet)); err != nil {
		c.mu.Lock()
		c.recordBlockedLocked("send-failed")
		c.mu.Unlock()
		return egressOutcomeBlockedNoEgress
	}
	return egressOutcomeForwarded
}

// steer6Locked decides an IPv6 destination by the IPv6 rules alone. There is no fake-IP pool in
// IPv6 -- names are answered with IPv4 fake addresses only -- so only address rules apply.
func (c *egressConsumer) steer6Locked(destination [16]byte) egressSteering {
	decision := matchEgressRulesFor(c.rules, formatEgressAddress6(destination), c.meshCIDR, c.fakeIPCIDR, c.carriesIPv6)
	if decision.Reason != egressReasonMatched ||
		(decision.Action != egressActionEgress && decision.Action != egressActionBlock) {
		return egressSteering{}
	}
	if decision.Action == egressActionBlock {
		return egressSteering{claimed: true, blocked: "rule"}
	}
	return egressSteering{claimed: true, egress: decision.EgressClientID}
}

// handleInbound6 takes an IPv6 packet an egress sent back (returnPath). A packet not addressed to
// this device's derived address is not the consumer's, and is left for the egress role of a device
// that is both. One whose source is inside the derived prefix would let an egress speak as another
// device, and one that matches no live flow this device opened through this egress was never asked
// for.
func (c *egressConsumer) handleInbound6(parsed peerEgressFrame, fromEgress int64, now time.Time) bool {
	packet := parsed.Body
	if len(packet) < ipv6HeaderLen {
		return false
	}
	source, destination := [16]byte(packet[8:24]), [16]byte(packet[24:40])
	c.mu.Lock()
	if !c.hasVirtual6 || destination != c.virtualIP6 {
		c.mu.Unlock()
		return false
	}
	if egressMeshCIDR6().contains(source) {
		c.recordBlockedLocked("return-mesh-source")
		c.mu.Unlock()
		return true
	}
	key := egressFlowKey{
		protocol:     parsed.Inner.Protocol,
		ipv6:         true,
		consumerIP6:  destination,
		consumerPort: uint16(parsed.Inner.DestinationPort),
		remoteIP6:    source,
		remotePort:   uint16(parsed.Inner.SourcePort),
	}
	flow := c.liveFlowLocked(key, now)
	if flow == nil || flow.Egress != fromEgress {
		c.recordBlockedLocked("return-no-flow")
		c.mu.Unlock()
		return true
	}
	flow.LastSeen = now
	flow.replied = true
	if parsed.Inner.Protocol == ipv4ProtocolTCP {
		flow.noteTCPFlags(tcpPacketFlags(packet), false, now)
	}
	toTun := c.toTun
	c.mu.Unlock()
	if toTun != nil {
		_ = toTun(packet)
	}
	return true
}

// consumerFlowKeyFor6 builds the five-tuple of an IPv6 packet as the consumer sees it, the mirror of
// what the egress records. Only a TCP or UDP header directly behind the fixed header is read: the
// data plane carries nothing else.
func consumerFlowKeyFor6(packet []byte, nextHeader int) (egressFlowKey, bool) {
	if len(packet) < ipv6HeaderLen+4 {
		return egressFlowKey{}, false
	}
	return egressFlowKey{
		protocol:     nextHeader,
		ipv6:         true,
		consumerIP6:  [16]byte(packet[8:24]),
		consumerPort: binary.BigEndian.Uint16(packet[ipv6HeaderLen : ipv6HeaderLen+2]),
		remoteIP6:    [16]byte(packet[24:40]),
		remotePort:   binary.BigEndian.Uint16(packet[ipv6HeaderLen+2 : ipv6HeaderLen+4]),
	}, true
}

// consumerFlowKeyForReject is the flow a flow-reject names: its source is the consumer's side and its
// destination the target's. An egress writes IPv6 addresses for an IPv6 flow, and both must then be
// IPv6; a family mix names no flow.
func consumerFlowKeyForReject(control peerEgressControl) (egressFlowKey, bool) {
	key := egressFlowKey{protocol: protocolNumberForEgressName(control.Protocol),
		consumerPort: uint16(control.SourcePort), remotePort: uint16(control.DestinationPort)}
	if strings.Contains(control.SourceIP, ":") || strings.Contains(control.DestinationIP, ":") {
		local, localOK := parseEgressAddress6(strings.TrimSpace(control.SourceIP))
		remote, remoteOK := parseEgressAddress6(strings.TrimSpace(control.DestinationIP))
		if !localOK || !remoteOK {
			return egressFlowKey{}, false
		}
		key.ipv6, key.consumerIP6, key.remoteIP6 = true, local, remote
		return key, true
	}
	local, localOK := parseEgressAddress(control.SourceIP)
	remote, remoteOK := parseEgressAddress(control.DestinationIP)
	if !localOK || !remoteOK {
		return egressFlowKey{}, false
	}
	key.consumerIP, key.remoteIP = local, remote
	return key, true
}

// egressIPv6LinkLocal reports an address in fe80::/10.
func egressIPv6LinkLocal(address [16]byte) bool {
	return address[0] == 0xfe && address[1]&0xc0 == 0x80
}

// egressIPv6Multicast reports an address in ff00::/8.
func egressIPv6Multicast(address [16]byte) bool {
	return address[0] == 0xff
}
