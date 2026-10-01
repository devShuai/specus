package client

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// The consumer's DNS responder (protocol/spec/peer-egress-dns.md, section 三; step four).
//
// It opens no socket. The pool's route already carries every packet for the pool into the TUN, the
// listen address -- the pool's first -- included, so the responder answers UDP and TCP port 53 of
// that address in the TUN read path and writes its answers back into the TUN. Nothing binds port 53
// on the system and the TUN needs no second address, and every way a system can be pointed at a
// resolver -- a per-link server, an NRPT rule, a network service's DNS -- reaches it by routing.
//
// What it answers itself is only what the rules decide: a name a domain rule claims gets its fake
// address (or NODATA for the types that would carry the real one past it), and a reverse name in
// the pool gets its mapping. Everything else goes to the upstream resolvers byte for byte, and what
// comes back goes to the application byte for byte. It never resolves anything itself: that would
// be one more way out of the machine that no rule governs.
//
// The bytes of every answer it builds are pinned by the wire cases of
// protocol/test-vectors/peer-egress-dns-v1.json.

const (
	dnsHeaderLen = 12
	dnsPort      = 53

	dnsTypeA     = 1
	dnsTypePTR   = 12
	dnsTypeAAAA  = 28
	dnsTypeOPT   = 41
	dnsTypeSVCB  = 64
	dnsTypeHTTPS = 65
	dnsTypeANY   = 255
	dnsClassIN   = 1

	dnsRcodeFormErr  = 1
	dnsRcodeServFail = 2
	dnsRcodeNXDomain = 3

	// egressDNSAnswerTTL is the TTL of every record the responder builds. A mapping lives far
	// longer (egressFakeIPMinLifetime); a short TTL only makes applications ask again, which is
	// what lets a rule change reach them.
	egressDNSAnswerTTL = 1
	// egressDNSEDNSPayload is the UDP payload size an echoed OPT offers: the DNS flag day's value,
	// which fits the tunnel without fragmenting.
	egressDNSEDNSPayload = 1232

	// egressDNSForwardTimeout is how long one upstream gets, connect included for TCP, before the
	// next one is asked.
	egressDNSForwardTimeout = 2 * time.Second
	// egressDNSMaxForwards bounds the forwards waiting on upstreams at once. Each holds a socket
	// for up to the timeout per upstream; past the bound a query is answered SERVFAIL rather than
	// letting a burst of lookups hold sockets without limit.
	egressDNSMaxForwards = 256
	// egressDNSLocalRefresh is how long the list of this device's own addresses is trusted before
	// it is read again.
	egressDNSLocalRefresh = 10 * time.Second
)

const egressDNSInAddrArpa = ".in-addr.arpa"

type egressDNSOutcome int

const (
	// egressDNSDrop: not a query, or too short to be one. Nothing is sent back.
	egressDNSDrop egressDNSOutcome = iota
	// egressDNSForward: not ours to answer; the query goes to the upstreams unchanged.
	egressDNSForward
	// egressDNSAnswer: answered here, with Response.
	egressDNSAnswer
)

// egressDNSResult is what the responder does with one query message.
type egressDNSResult struct {
	Outcome  egressDNSOutcome
	Response []byte
	// Exhausted marks the SERVFAIL of a full pool, which the status counts as failed rather than
	// answered.
	Exhausted bool
}

// egressDNSQueries are the responder's counters since start: answers it built (NODATA, NXDOMAIN and
// FORMERR included), upstream answers it relayed, and SERVFAILs for upstreams that all failed or a
// pool that was full. Dropped queries are not counted.
type egressDNSQueries struct {
	Answered  int64
	Forwarded int64
	Failed    int64
}

// readDNSName reads the labels of a name from pos, and where the name ends. Compression pointers
// are followed only when allowed; a question that uses one is not one this responder reads.
func readDNSName(message []byte, pos int, pointers bool) ([][]byte, int, bool) {
	var labels [][]byte
	end, hops := -1, 0
	for {
		if pos >= len(message) {
			return nil, 0, false
		}
		length := int(message[pos])
		if length == 0 {
			if end < 0 {
				end = pos + 1
			}
			return labels, end, true
		}
		if length&0xC0 == 0xC0 {
			if !pointers || pos+1 >= len(message) || hops > 16 {
				return nil, 0, false
			}
			if end < 0 {
				end = pos + 2
			}
			pos = (length&0x3F)<<8 | int(message[pos+1])
			hops++
			continue
		}
		if length&0xC0 != 0 || pos+1+length > len(message) {
			return nil, 0, false
		}
		labels = append(labels, message[pos+1:pos+1+length])
		pos += 1 + length
	}
}

// findDNSOpt reports whether one of count records from pos is an OPT. A record that cannot be read
// ends the search, and the query is then answered as one without EDNS.
func findDNSOpt(message []byte, pos, count int) bool {
	for ; count > 0; count-- {
		_, next, ok := readDNSName(message, pos, true)
		if !ok || next+10 > len(message) {
			return false
		}
		if binary.BigEndian.Uint16(message[next:next+2]) == dnsTypeOPT {
			return true
		}
		pos = next + 10 + int(binary.BigEndian.Uint16(message[next+8:next+10]))
	}
	return false
}

// usableDNSName is the name as rules see it, lower case and dotted, or false when no rule could
// match it: the root, or a label holding a dot or a byte outside printable ASCII. Such a query is
// forwarded, never answered.
func usableDNSName(labels [][]byte) (string, bool) {
	if len(labels) == 0 {
		return "", false
	}
	parts := make([]string, 0, len(labels))
	for _, label := range labels {
		for _, b := range label {
			if b < 0x21 || b > 0x7E || b == '.' {
				return "", false
			}
		}
		parts = append(parts, strings.ToLower(string(label)))
	}
	return strings.Join(parts, "."), true
}

// buildDNSReply builds a response from the query it answers: ID, opcode, RD and CD copied, QR and RA
// set, AA, TC and AD clear. The question is the query's own bytes, so the application's letter case
// survives (some resolvers randomise it against spoofing). With edns an OPT offering
// egressDNSEDNSPayload bytes goes last, with no extended code, version or flags; without it a
// resolver such as systemd-resolved decides this server does not do EDNS and stops sending it.
func buildDNSReply(query []byte, rcode int, question, answer []byte, ancount int, edns bool) []byte {
	flags := binary.BigEndian.Uint16(query[2:4])
	out := 0x8000 | flags&0x7800 | flags&0x0100 | 0x0080 | flags&0x0010 | uint16(rcode)
	reply := make([]byte, dnsHeaderLen, dnsHeaderLen+len(question)+len(answer)+11)
	copy(reply[0:2], query[0:2])
	binary.BigEndian.PutUint16(reply[2:4], out)
	if len(question) > 0 {
		binary.BigEndian.PutUint16(reply[4:6], 1)
	}
	binary.BigEndian.PutUint16(reply[6:8], uint16(ancount))
	reply = append(reply, question...)
	reply = append(reply, answer...)
	if edns {
		binary.BigEndian.PutUint16(reply[10:12], 1)
		reply = append(reply, 0, 0, dnsTypeOPT, byte(egressDNSEDNSPayload>>8), byte(egressDNSEDNSPayload&0xff),
			0, 0, 0, 0, 0, 0)
	}
	return reply
}

// dnsRecord is one answer record named by a pointer to the question, TTL egressDNSAnswerTTL.
func dnsRecord(recordType uint16, rdata []byte) []byte {
	record := []byte{0xC0, 0x0C, byte(recordType >> 8), byte(recordType), 0, dnsClassIN}
	record = binary.BigEndian.AppendUint32(record, egressDNSAnswerTTL)
	record = binary.BigEndian.AppendUint16(record, uint16(len(rdata)))
	return append(record, rdata...)
}

// encodeDNSName writes a dotted name as labels.
func encodeDNSName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(strings.TrimRight(name, "."), ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

// egressDNSFailure is the SERVFAIL for a query no upstream answered. Built like any other answer
// when the query has one question this responder can read; a query it could not read (which is why
// it was forwarded) gets a header with no question, since nothing else can be copied from it
// faithfully.
func egressDNSFailure(query []byte) []byte {
	if len(query) < dnsHeaderLen {
		return nil
	}
	var question []byte
	edns := false
	if binary.BigEndian.Uint16(query[4:6]) == 1 {
		if _, pos, ok := readDNSName(query, dnsHeaderLen, false); ok && pos+4 <= len(query) {
			question = query[dnsHeaderLen : pos+4]
			records := int(binary.BigEndian.Uint16(query[6:8])) + int(binary.BigEndian.Uint16(query[8:10])) +
				int(binary.BigEndian.Uint16(query[10:12]))
			edns = findDNSOpt(query, pos+4, records)
		}
	}
	return buildDNSReply(query, dnsRcodeServFail, question, nil, 0, edns)
}

// egressDNSDecision is what the rules say about a name and a type before the pool is involved:
// "fake" for an A the rules claim, "nodata" for the types that would carry a real address or
// endpoint past the fake one, and "forward" for everything else, a name claimed by a direct rule
// included. index is the rule that claims the name, or -1.
func egressDNSDecision(rules []egressRule, name string, qtype uint16, meshCIDR, fakeIPPool string) (string, int) {
	index := selectEgressDomainRule(rules, name, meshCIDR, fakeIPPool)
	if index < 0 || rules[index].Action == egressActionDirect {
		return "forward", index
	}
	switch qtype {
	case dnsTypeA:
		return "fake", index
	case dnsTypeAAAA, dnsTypeHTTPS, dnsTypeSVCB, dnsTypeANY:
		return "nodata", index
	}
	return "forward", index
}

// respondDNSLocked decides one query message against the rules and the pool. Called with the
// consumer's lock held and phase two running.
//
// Only one kind of message is interpreted: a query (QR clear, opcode 0) with exactly one question
// of class IN whose name rules could match. A response or anything shorter than a header is
// dropped; another opcode or question count, another class or an unusable name is forwarded, since
// the upstream's answer to something this responder does not understand is at least a real one. A
// header whose question cannot be read gets FORMERR with no question.
func (c *egressConsumer) respondDNSLocked(message []byte, now time.Time) egressDNSResult {
	if len(message) < dnsHeaderLen {
		return egressDNSResult{Outcome: egressDNSDrop}
	}
	flags := binary.BigEndian.Uint16(message[2:4])
	if flags&0x8000 != 0 {
		return egressDNSResult{Outcome: egressDNSDrop}
	}
	if (flags>>11)&0x0F != 0 || binary.BigEndian.Uint16(message[4:6]) != 1 {
		return egressDNSResult{Outcome: egressDNSForward}
	}
	labels, pos, ok := readDNSName(message, dnsHeaderLen, false)
	if !ok || pos+4 > len(message) {
		return egressDNSResult{Outcome: egressDNSAnswer, Response: buildDNSReply(message, dnsRcodeFormErr, nil, nil, 0, false)}
	}
	qtype := binary.BigEndian.Uint16(message[pos : pos+2])
	qclass := binary.BigEndian.Uint16(message[pos+2 : pos+4])
	question := message[dnsHeaderLen : pos+4]
	records := int(binary.BigEndian.Uint16(message[6:8])) + int(binary.BigEndian.Uint16(message[8:10])) +
		int(binary.BigEndian.Uint16(message[10:12]))
	edns := findDNSOpt(message, pos+4, records)
	name, usable := usableDNSName(labels)
	if qclass != dnsClassIN || !usable || c.fakeIP == nil {
		return egressDNSResult{Outcome: egressDNSForward}
	}
	answer := func(rcode int, record []byte) egressDNSResult {
		count := 0
		if record != nil {
			count = 1
		}
		return egressDNSResult{Outcome: egressDNSAnswer, Response: buildDNSReply(message, rcode, question, record, count, edns)}
	}

	if strings.HasSuffix(name, egressDNSInAddrArpa) {
		address, inPool := c.reverseDNSAddressLocked(strings.TrimSuffix(name, egressDNSInAddrArpa))
		if !inPool {
			return egressDNSResult{Outcome: egressDNSForward}
		}
		// A reverse lookup is not a use of the mapping, so it does not refresh it.
		mapped, known := c.fakeIP.nameFor(address, now, false)
		switch {
		case !known:
			return answer(dnsRcodeNXDomain, nil)
		case qtype != dnsTypePTR:
			return answer(0, nil)
		}
		return answer(0, dnsRecord(dnsTypePTR, encodeDNSName(mapped)))
	}

	switch decision, _ := egressDNSDecision(c.rules, name, qtype, c.meshCIDR, c.fakeIPCIDR); decision {
	case "forward":
		return egressDNSResult{Outcome: egressDNSForward}
	case "nodata":
		return answer(0, nil)
	}
	assignment := c.fakeIP.assign(name, now)
	c.logFakeIPAssignment(assignment)
	if assignment.Exhausted {
		result := answer(dnsRcodeServFail, nil)
		result.Exhausted = true
		return result
	}
	address := assignment.Address
	return answer(0, dnsRecord(dnsTypeA, []byte{byte(address >> 24), byte(address >> 16), byte(address >> 8), byte(address)}))
}

// reverseDNSAddressLocked reads the address of a reverse name (the part before .in-addr.arpa) and
// says whether it is in the pool. Only the spelling resolvers write is read: four decimal octets,
// least significant first, without leading zeros. Anything else -- `02`, three octets -- is some
// other name and goes upstream.
func (c *egressConsumer) reverseDNSAddressLocked(octets string) (uint32, bool) {
	parts := strings.Split(octets, ".")
	if len(parts) != 4 {
		return 0, false
	}
	var address uint32
	for index := 3; index >= 0; index-- {
		part := parts[index]
		if part == "" || len(part) > 3 || (len(part) > 1 && part[0] == '0') {
			return 0, false
		}
		value := 0
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return 0, false
			}
			value = value*10 + int(digit-'0')
		}
		if value > 255 {
			return 0, false
		}
		address = address<<8 | uint32(value)
	}
	return address, c.fakeIP.contains(address)
}

// countDNSAnswerLocked counts an answer built here: a full pool's SERVFAIL as failed, the rest as
// answered. Forwards are counted when the upstream answers or all of them fail.
func (c *egressConsumer) countDNSAnswerLocked(result egressDNSResult) {
	if result.Outcome != egressDNSAnswer {
		return
	}
	if result.Exhausted {
		c.dnsQueries.Failed++
	} else {
		c.dnsQueries.Answered++
	}
}

// isDNSQueryPacketLocked reports whether a packet read from the TUN is for the responder: UDP or TCP
// to port 53 of the listen address while phase two runs. Called with the consumer's lock held. Any
// other packet to the listen address is pool traffic like the rest and blocked as unmapped.
func (c *egressConsumer) isDNSQueryPacketLocked(packet []byte, destination uint32, protocol int) bool {
	if c.fakeIP == nil || destination != c.fakeIP.listen ||
		(protocol != ipv4ProtocolUDP && protocol != ipv4ProtocolTCP) {
		return false
	}
	ihl := int(packet[0]&0x0f) * 4
	return len(packet) >= ihl+4 && binary.BigEndian.Uint16(packet[ihl+2:ihl+4]) == dnsPort
}

// dnsSourceIsLocalLocked reports whether a query came from this device: its mesh address, or the
// address of one of its interfaces. A query from anywhere else means this machine is forwarding for
// another, and phase two does not resolve on anyone else's behalf.
func (c *egressConsumer) dnsSourceIsLocalLocked(source uint32, now time.Time) bool {
	if virtual, ok := parseEgressAddress(c.virtualIP); ok && virtual == source {
		return true
	}
	if c.dnsLocal == nil || now.Sub(c.dnsLocalAt) >= egressDNSLocalRefresh || now.Before(c.dnsLocalAt) {
		// Read under the lock, at most once per refresh: a query from a new address waits that
		// long to be recognised, and nothing waits on the enumeration more often than that.
		list := c.dnsLocalAddresses
		if list == nil {
			list = localInterfaceAddresses
		}
		c.dnsLocal = map[uint32]bool{}
		for _, address := range list() {
			c.dnsLocal[address] = true
		}
		c.dnsLocalAt = now
	}
	return c.dnsLocal[source]
}

// localInterfaceAddresses lists this device's own IPv4 addresses.
func localInterfaceAddresses() []uint32 {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	out := make([]uint32, 0, len(addresses))
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok {
			if v4 := network.IP.To4(); v4 != nil {
				out = append(out, binary.BigEndian.Uint32(v4))
			}
		}
	}
	return out
}

// handleDNSPacket answers one packet addressed to the responder. It is claimed whatever becomes of
// it: a query to the listen address is never pool traffic and never mesh traffic.
func (c *egressConsumer) handleDNSPacket(packet []byte, protocol int, now time.Time) {
	source := binary.BigEndian.Uint32(packet[12:16])
	c.mu.Lock()
	if !c.dnsSourceIsLocalLocked(source, now) {
		c.recordBlockedLocked("dns-not-local")
		c.mu.Unlock()
		return
	}
	toTun := c.toTun
	if protocol == ipv4ProtocolTCP {
		var packets [][]byte
		if segment, ok := parseTCPSegment(packet); ok {
			packets = c.dnsTCPSegmentLocked(segment, now)
		}
		c.mu.Unlock()
		writePackets(toTun, packets)
		return
	}
	datagram, ok := parseUDPDatagram(packet)
	if !ok {
		c.mu.Unlock()
		return
	}
	result := c.respondDNSLocked(datagram.Payload, now)
	c.countDNSAnswerLocked(result)
	// From the listen address and port the query went to, back to where it came from.
	reply := func(payload []byte) []byte {
		return buildUDPDatagram(udpDatagram{
			SourceIP: datagram.DestinationIP, DestinationIP: datagram.SourceIP,
			SourcePort: datagram.DestinationPort, DestinationPort: datagram.SourcePort, Payload: payload,
		})
	}
	switch result.Outcome {
	case egressDNSAnswer:
		c.mu.Unlock()
		writePackets(toTun, [][]byte{reply(result.Response)})
	case egressDNSForward:
		c.forwardDNSLocked("udp", datagram.Payload, func(answer []byte) {
			writePackets(toTun, [][]byte{reply(answer)})
		})
		c.mu.Unlock()
	default:
		c.mu.Unlock()
	}
}

// forwardDNSLocked hands a query to the upstreams on its own goroutine, and delivers what comes
// back -- the upstream's reply unchanged, or a SERVFAIL when none answered -- to deliver, with no
// lock held. Called with the consumer's lock held.
func (c *egressConsumer) forwardDNSLocked(network string, query []byte, deliver func([]byte)) {
	if c.dnsForwarding >= egressDNSMaxForwards {
		c.dnsQueries.Failed++
		failure := egressDNSFailure(query)
		go deliver(failure)
		return
	}
	c.dnsForwarding++
	upstreams := append([]string(nil), c.dnsUpstreams...)
	timeout := c.dnsForwardTimeout
	query = append([]byte(nil), query...)
	go func() {
		answer := forwardEgressDNSQuery(network, upstreams, query, timeout)
		c.mu.Lock()
		c.dnsForwarding--
		if answer != nil {
			c.dnsQueries.Forwarded++
		} else {
			c.dnsQueries.Failed++
		}
		c.mu.Unlock()
		if answer == nil {
			answer = egressDNSFailure(query)
		}
		deliver(answer)
	}()
}

// setDNSUpstreams gives the responder the resolvers it forwards to, in the order they are asked.
// Each is an address with an optional port (53 when absent). Step five supplies the ones the
// system used before the takeover; until something does, every forward is answered SERVFAIL.
func (c *egressConsumer) setDNSUpstreams(upstreams []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dnsUpstreams = append([]string(nil), upstreams...)
}

// egressDNSUpstreamAddress is an upstream as a dialable address: a bare address gets port 53.
func egressDNSUpstreamAddress(upstream string) string {
	upstream = strings.TrimSpace(upstream)
	if _, _, err := net.SplitHostPort(upstream); err == nil {
		return upstream
	}
	return net.JoinHostPort(strings.Trim(upstream, "[]"), strconv.Itoa(dnsPort))
}

// forwardEgressDNSQuery asks the upstreams in order, each for at most timeout, and returns the first
// reply that answers this query, or nil when none did. The query goes out and the reply comes back
// byte for byte: nothing is rewritten and nothing is cached.
func forwardEgressDNSQuery(network string, upstreams []string, query []byte, timeout time.Duration) []byte {
	if len(query) < 2 {
		return nil
	}
	for _, upstream := range upstreams {
		address := egressDNSUpstreamAddress(upstream)
		var answer []byte
		if network == "tcp" {
			answer = forwardEgressDNSOverTCP(address, query, timeout)
		} else {
			answer = forwardEgressDNSOverUDP(address, query, timeout)
		}
		if answer != nil {
			return answer
		}
	}
	return nil
}

// writePackets writes answers to the TUN, with no lock held.
func writePackets(toTun func([]byte) error, packets [][]byte) {
	if toTun == nil {
		return
	}
	for _, packet := range packets {
		_ = toTun(packet)
	}
}

// forwardEgressDNSOverUDP sends one query to one upstream and waits for the reply with its ID. The
// socket is connected, so the kernel already discards datagrams from any other source: a reply is
// matched by ID and by where it came from, and anything else is ignored until the time is up.
func forwardEgressDNSOverUDP(address string, query []byte, timeout time.Duration) []byte {
	deadline := time.Now().Add(timeout)
	conn, err := net.DialTimeout("udp", address, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(query); err != nil {
		return nil
	}
	buffer := make([]byte, 65535)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return nil
		}
		if n >= 2 && buffer[0] == query[0] && buffer[1] == query[1] {
			return append([]byte(nil), buffer[:n]...)
		}
	}
}

// forwardEgressDNSOverTCP sends one query to one upstream over TCP with its two-byte length, and
// reads replies until the one with its ID; the connect and the wait share the timeout.
func forwardEgressDNSOverTCP(address string, query []byte, timeout time.Duration) []byte {
	if len(query) > 0xFFFF {
		return nil
	}
	deadline := time.Now().Add(timeout)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	if _, err := conn.Write(append(framed, query...)); err != nil {
		return nil
	}
	for {
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return nil
		}
		answer := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(conn, answer); err != nil {
			return nil
		}
		if len(answer) >= 2 && answer[0] == query[0] && answer[1] == query[1] {
			return answer
		}
	}
}
