package client

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

// The DNS responder (step four): its wire format against the shared cases, and its packet path --
// UDP and TCP to the listen address in the TUN, the source check, and forwarding to upstreams --
// through the real consumer.

type dnsWireVector struct {
	MeshCIDR string       `json:"meshCidr"`
	Rules    []egressRule `json:"rules"`
	TTL      int          `json:"responderAnswerTtlSeconds"`
	Payload  int          `json:"responderEdnsPayload"`
	Answers  []struct {
		Name      string `json:"name"`
		Query     string `json:"query"`
		Type      string `json:"type"`
		Answer    string `json:"answer"`
		RuleIndex *int   `json:"ruleIndex"`
	} `json:"answers"`
	Wire []struct {
		Name   string `json:"name"`
		CIDR   string `json:"cidr"`
		Events []struct {
			Name  string `json:"name"`
			At    int64  `json:"at"`
			Query string `json:"query"`
		} `json:"events"`
		Results []struct {
			Result    string `json:"result"`
			Response  string `json:"response"`
			Exhausted bool   `json:"exhausted"`
		} `json:"results"`
	} `json:"wire"`
}

func loadDNSWireVector(t *testing.T) dnsWireVector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "protocol", "test-vectors", "peer-egress-dns-v1.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vector dnsWireVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	return vector
}

var dnsTypeNumbers = map[string]uint16{"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28,
	"SVCB": 64, "HTTPS": 65, "ANY": 255}

// Every wire case through the responder the consumer runs, byte for byte.
func TestEgressDNSWireMatchesTheSharedVector(t *testing.T) {
	vector := loadDNSWireVector(t)
	if vector.TTL != egressDNSAnswerTTL || vector.Payload != egressDNSEDNSPayload {
		t.Fatalf("the vector's TTL %d and EDNS payload %d are not this responder's", vector.TTL, vector.Payload)
	}
	if len(vector.Wire) == 0 {
		t.Fatal("the vector has no wire cases")
	}
	for _, c := range vector.Wire {
		consumer := newEgressConsumer(log.New(io.Discard, "", 0), nil, nil)
		consumer.configureIn(vector.Rules, vector.MeshCIDR, "100.96.0.1", c.CIDR, flowEpoch)
		for index, event := range c.Events {
			query, err := hex.DecodeString(event.Query)
			if err != nil {
				t.Fatalf("%s/%s: %v", c.Name, event.Name, err)
			}
			consumer.mu.Lock()
			result := consumer.respondDNSLocked(query, vectorAt(event.At))
			consumer.mu.Unlock()
			want := c.Results[index]
			got := map[egressDNSOutcome]string{egressDNSDrop: "drop", egressDNSForward: "forward", egressDNSAnswer: "answer"}[result.Outcome]
			if got != want.Result || hex.EncodeToString(result.Response) != want.Response || result.Exhausted != want.Exhausted {
				t.Errorf("%s/%s: %s %x exhausted=%v, want %s %s exhausted=%v", c.Name, event.Name,
					got, result.Response, result.Exhausted, want.Result, want.Response, want.Exhausted)
			}
		}
	}
}

func TestEgressDNSDecisionMatchesTheSharedAnswers(t *testing.T) {
	vector := loadDNSWireVector(t)
	for _, c := range vector.Answers {
		answer, index := egressDNSDecision(vector.Rules, c.Query, dnsTypeNumbers[c.Type], vector.MeshCIDR, egressDefaultFakeIPCIDR)
		want := -1
		if c.RuleIndex != nil {
			want = *c.RuleIndex
		}
		if answer != c.Answer || index != want {
			t.Errorf("%s: %s rule %d, want %s rule %d", c.Name, answer, index, c.Answer, want)
		}
	}
}

// dnsHarness is a consumer running phase two on the default pool, with the TUN written to under a
// lock (forwards answer from their own goroutines) and time in the test's hands.
type dnsHarness struct {
	t        *testing.T
	consumer *egressConsumer
	mu       sync.Mutex
	written  [][]byte
	now      time.Time
}

func newDNSHarness(t *testing.T) *dnsHarness {
	t.Helper()
	h := &dnsHarness{t: t, now: flowEpoch}
	h.consumer = newEgressConsumer(log.New(io.Discard, "", 0),
		func(int64, []byte) error { return nil },
		func(packet []byte) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.written = append(h.written, append([]byte(nil), packet...))
			return nil
		})
	h.consumer.dnsTickInterval = 0
	h.consumer.dnsForwardTimeout = 300 * time.Millisecond
	h.consumer.clock = func() time.Time {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.now
	}
	h.consumer.dnsLocalAddresses = func() []uint32 { return []uint32{testAddr(t, "192.168.1.20")} }
	h.consumer.configureIn(phaseTwoRules(), egressDefaultMeshCIDR, "100.96.0.1", egressDefaultFakeIPCIDR, flowEpoch)
	return h
}

func (h *dnsHarness) advance(by time.Duration) time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.now = h.now.Add(by)
	return h.now
}

func (h *dnsHarness) at() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *dnsHarness) packets() [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([][]byte(nil), h.written...)
}

// waitPackets waits until at least n packets were written to the TUN.
func (h *dnsHarness) waitPackets(n int) [][]byte {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if packets := h.packets(); len(packets) >= n {
			return packets
		}
		time.Sleep(2 * time.Millisecond)
	}
	h.t.Fatalf("timed out waiting for %d packets, have %d", n, len(h.packets()))
	return nil
}

func (h *dnsHarness) queries() egressDNSQueries {
	h.consumer.mu.Lock()
	defer h.consumer.mu.Unlock()
	return h.consumer.dnsQueries
}

// dnsQuery builds a query with one question, RD set, and an OPT when edns is set.
func dnsQuery(id uint16, name string, qtype uint16, edns bool) []byte {
	query := binary.BigEndian.AppendUint16(nil, id)
	query = append(query, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
	query = append(query, encodeDNSName(name)...)
	query = binary.BigEndian.AppendUint16(query, qtype)
	query = binary.BigEndian.AppendUint16(query, dnsClassIN)
	if edns {
		query[11] = 1
		query = append(query, 0, 0, dnsTypeOPT, 0x10, 0x00, 0, 0, 0, 0, 0, 0)
	}
	return query
}

func dnsUDPQueryPacket(t *testing.T, source string, sourcePort, destinationPort uint16, payload []byte) []byte {
	return buildUDPDatagram(udpDatagram{SourceIP: testAddr(t, source), DestinationIP: testAddr(t, "198.18.0.1"),
		SourcePort: sourcePort, DestinationPort: destinationPort, Payload: payload})
}

// A query over UDP is answered into the TUN from the listen address, as a complete IPv4 datagram
// whose headers and checksums a stack accepts.
func TestEgressDNSAnswersAUDPQueryThroughTheConsumer(t *testing.T) {
	h := newDNSHarness(t)
	query := dnsQuery(0x1234, "www.example.com", dnsTypeA, false)
	if outcome := h.consumer.handleOutbound(dnsUDPQueryPacket(t, "100.96.0.1", 53000, 53, query), h.at()); outcome != egressOutcomeDNS {
		t.Fatalf("outcome = %s, want dns", outcome)
	}
	packets := h.packets()
	if len(packets) != 1 {
		t.Fatalf("wrote %d packets, want the answer", len(packets))
	}
	packet := packets[0]
	if packet[0] != 0x45 || packet[9] != ipv4ProtocolUDP || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) || packet[8] == 0 {
		t.Errorf("the IPv4 header is not a plain UDP one: % x", packet[:20])
	}
	if peerPacketChecksum(packet[:20]) != 0 {
		t.Error("the IPv4 header checksum does not verify")
	}
	if binary.BigEndian.Uint16(packet[26:28]) == 0 {
		t.Error("the UDP checksum was left out")
	}
	datagram, ok := parseUDPDatagram(packet)
	if !ok {
		t.Fatal("the answer is not a UDP datagram that verifies")
	}
	if datagram.SourceIP != testAddr(t, "198.18.0.1") || datagram.SourcePort != 53 ||
		datagram.DestinationIP != testAddr(t, "100.96.0.1") || datagram.DestinationPort != 53000 {
		t.Errorf("answer from %s:%d to %s:%d", formatEgressAddress(datagram.SourceIP), datagram.SourcePort,
			formatEgressAddress(datagram.DestinationIP), datagram.DestinationPort)
	}
	want, _ := hex.DecodeString("12348180000100010000000003777777076578616d706c6503636f6d0000010001c00c00010001000000010004c6120002")
	if !bytes.Equal(datagram.Payload, want) {
		t.Errorf("answer %x, want %x", datagram.Payload, want)
	}
	if queries := h.queries(); queries != (egressDNSQueries{Answered: 1}) {
		t.Errorf("queries = %+v", queries)
	}
	// Traffic to the address handed out is steered by its name, as in step three.
	h.consumer.setEgressOnline(2, true, h.at())
	h.consumer.setDomainCapable(map[int64]bool{2: true}, h.at())
	if outcome := h.consumer.handleOutbound(buildTCPSegment(tcpSegment{SourceIP: testAddr(t, "100.96.0.1"),
		DestinationIP: testAddr(t, "198.18.0.2"), SourcePort: 40000, DestinationPort: 443, Seq: 1,
		Flags: tcpFlagSYN, Window: 65535}), h.at()); outcome != egressOutcomeForwarded {
		t.Errorf("traffic to the answered address: %s", outcome)
	}
}

// Only this device's own queries are answered: from its mesh address or one of its interfaces.
// Anything else is dropped and counted, and the listen address's other ports and protocols are pool
// traffic like the rest.
func TestEgressDNSAnswersOnlyThisDevice(t *testing.T) {
	h := newDNSHarness(t)
	query := dnsQuery(0x2222, "www.example.com", dnsTypeA, false)

	h.consumer.handleOutbound(dnsUDPQueryPacket(t, "10.9.9.9", 53000, 53, query), h.at())
	if len(h.packets()) != 0 || h.consumer.blockedCounts()["dns-not-local"] != 1 {
		t.Fatalf("a forwarded host's query: %d packets, blocked %v", len(h.packets()), h.consumer.blockedCounts())
	}
	h.consumer.handleOutbound(buildTCPSegment(tcpSegment{SourceIP: testAddr(t, "10.9.9.9"),
		DestinationIP: testAddr(t, "198.18.0.1"), SourcePort: 40000, DestinationPort: 53, Seq: 1,
		Flags: tcpFlagSYN, Window: 65535}), h.at())
	if len(h.packets()) != 0 || h.consumer.blockedCounts()["dns-not-local"] != 2 {
		t.Fatalf("a forwarded host's SYN: %d packets, blocked %v", len(h.packets()), h.consumer.blockedCounts())
	}

	h.consumer.handleOutbound(dnsUDPQueryPacket(t, "192.168.1.20", 53000, 53, query), h.at())
	if len(h.packets()) != 1 {
		t.Fatal("a query from one of this device's interface addresses was not answered")
	}

	if outcome := h.consumer.handleOutbound(dnsUDPQueryPacket(t, "100.96.0.1", 53000, 5353, query), h.at()); outcome != egressOutcomeBlockedFakeIP {
		t.Errorf("another port on the listen address: %s", outcome)
	}
	if h.consumer.blockedCounts()["fake-ip-unmapped"] != 1 {
		t.Errorf("blocked = %v, want the other port as unmapped", h.consumer.blockedCounts())
	}

	// Without phase two the listen address is nobody's.
	off := newConsumerHarness(t, phaseTwoRules(), nil)
	if outcome := off.consumer.handleOutbound(dnsUDPQueryPacket(t, "100.96.0.1", 53000, 53, query), flowEpoch); outcome != egressOutcomeNotMine {
		t.Errorf("without phase two: %s", outcome)
	}
}

// fakeUDPUpstream answers each query it receives with whatever respond returns.
func fakeUDPUpstream(t *testing.T, respond func(query []byte) [][]byte) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, from, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			for _, reply := range respond(append([]byte(nil), buffer[:n]...)) {
				_, _ = conn.WriteTo(reply, from)
			}
		}
	}()
	return conn.LocalAddr().String()
}

// fakeTCPUpstream answers each framed query on each connection with respond's reply; a nil reply
// leaves the connection open and silent.
func fakeTCPUpstream(t *testing.T, respond func(query []byte) []byte) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			go func() {
				for {
					var length [2]byte
					if _, err := io.ReadFull(conn, length[:]); err != nil {
						return
					}
					query := make([]byte, binary.BigEndian.Uint16(length[:]))
					if _, err := io.ReadFull(conn, query); err != nil {
						return
					}
					if reply := respond(query); reply != nil {
						framed := binary.BigEndian.AppendUint16(nil, uint16(len(reply)))
						_, _ = conn.Write(append(framed, reply...))
					}
				}
			}()
		}
	}()
	return listener.Addr().String()
}

// closedPort is an address nothing listens on.
func closedPort(t *testing.T, network string) string {
	t.Helper()
	if network == "udp" {
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := conn.LocalAddr().String()
		conn.Close()
		return address
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

// upstreamReply is what a fake upstream sends back: the query turned into a truncated response with
// a marker after it, so a relay that rewrote anything would show.
func upstreamReply(query []byte, id uint16) []byte {
	reply := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(reply[0:2], id)
	reply[2] |= 0x82 // QR and TC
	return append(reply, 0xde, 0xad, 0xbe, 0xef)
}

// A query no rule claims goes to the upstreams in order: one that says nothing is given the timeout,
// a reply with another ID is not taken, and the answer comes back into the TUN byte for byte, TC
// bit and all.
func TestEgressDNSForwardsOverUDPInOrder(t *testing.T) {
	h := newDNSHarness(t)
	silent := fakeUDPUpstream(t, func([]byte) [][]byte { return nil })
	answering := fakeUDPUpstream(t, func(query []byte) [][]byte {
		id := binary.BigEndian.Uint16(query[0:2])
		return [][]byte{upstreamReply(query, id+1), upstreamReply(query, id)}
	})
	h.consumer.setDNSUpstreams([]string{silent, answering})

	query := dnsQuery(0x3333, "example.org", dnsTypeA, true)
	started := time.Now()
	h.consumer.handleOutbound(dnsUDPQueryPacket(t, "100.96.0.1", 53001, 53, query), h.at())
	packets := h.waitPackets(1)
	if elapsed := time.Since(started); elapsed < h.consumer.dnsForwardTimeout {
		t.Errorf("answered after %s, before the silent upstream's time was up", elapsed)
	}
	datagram, ok := parseUDPDatagram(packets[0])
	if !ok || datagram.DestinationPort != 53001 || datagram.SourcePort != 53 {
		t.Fatalf("the relayed answer is not a datagram to the querier: %v", ok)
	}
	if want := upstreamReply(query, 0x3333); !bytes.Equal(datagram.Payload, want) {
		t.Errorf("relayed %x, want the upstream's reply %x unchanged", datagram.Payload, want)
	}
	h.waitQueries(t, egressDNSQueries{Forwarded: 1})
}

func (h *dnsHarness) waitQueries(t *testing.T, want egressDNSQueries) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.queries() == want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("queries = %+v, want %+v", h.queries(), want)
}

// When no upstream answers, or there are none, the application gets a SERVFAIL built like any
// other answer here.
func TestEgressDNSAnswersServFailWhenNoUpstreamAnswers(t *testing.T) {
	for _, upstreams := range [][]string{nil, {closedPort(t, "udp")}} {
		h := newDNSHarness(t)
		if upstreams != nil {
			silent := fakeUDPUpstream(t, func([]byte) [][]byte { return nil })
			upstreams = append(upstreams, silent)
		}
		h.consumer.setDNSUpstreams(upstreams)
		query := dnsQuery(0x4444, "www.example.com", 15, true)
		h.consumer.handleOutbound(dnsUDPQueryPacket(t, "100.96.0.1", 53002, 53, query), h.at())
		datagram, _ := parseUDPDatagram(h.waitPackets(1)[0])
		want := buildDNSReply(query, dnsRcodeServFail, query[dnsHeaderLen:len(query)-11], nil, 0, true)
		if !bytes.Equal(datagram.Payload, want) {
			t.Errorf("upstreams %v: answer %x, want SERVFAIL %x", upstreams, datagram.Payload, want)
		}
		if want[3]&0x0F != dnsRcodeServFail {
			t.Fatal("the expectation is not a SERVFAIL")
		}
		h.waitQueries(t, egressDNSQueries{Failed: 1})
	}
}

// Over TCP the same order: a refused upstream and one that accepts and says nothing are passed
// over, each within the timeout, and the answering one's reply is returned as it came.
func TestEgressDNSForwardsOverTCPInOrder(t *testing.T) {
	silent := fakeTCPUpstream(t, func([]byte) []byte { return nil })
	answering := fakeTCPUpstream(t, func(query []byte) []byte {
		return upstreamReply(query, binary.BigEndian.Uint16(query[0:2]))
	})
	query := dnsQuery(0x5555, "example.org", dnsTypeA, false)
	timeout := 300 * time.Millisecond
	started := time.Now()
	answer := forwardEgressDNSQuery("tcp", []string{closedPort(t, "tcp"), silent, answering}, query, timeout)
	if !bytes.Equal(answer, upstreamReply(query, 0x5555)) {
		t.Fatalf("answer %x", answer)
	}
	if elapsed := time.Since(started); elapsed > 4*timeout {
		t.Errorf("took %s: an upstream held the query past its time", elapsed)
	}
	if answer := forwardEgressDNSQuery("tcp", []string{silent}, query, timeout); answer != nil {
		t.Errorf("a silent upstream produced %x", answer)
	}
	if got := egressDNSUpstreamAddress("192.0.2.53"); got != "192.0.2.53:53" {
		t.Errorf("a bare upstream is %s, want port 53", got)
	}
	if got := egressDNSUpstreamAddress("192.0.2.53:5353"); got != "192.0.2.53:5353" {
		t.Errorf("an upstream with a port is %s", got)
	}
}

// dnsTCPClient is an application's end of a TCP connection to the responder, driven segment by
// segment.
type dnsTCPClient struct {
	h         *dnsHarness
	port      uint16
	seq, ack  uint32
	seen      int
	delivered map[uint32][]byte
}

func newDNSTCPClient(h *dnsHarness, port uint16) *dnsTCPClient {
	return &dnsTCPClient{h: h, port: port, seq: 1000, seen: len(h.packets()), delivered: map[uint32][]byte{}}
}

func (cl *dnsTCPClient) send(flags uint8, payload []byte, mss int) {
	cl.sendAt(cl.seq, flags, payload, mss)
	cl.seq += uint32(len(payload))
	if flags&(tcpFlagSYN|tcpFlagFIN) != 0 {
		cl.seq++
	}
}

func (cl *dnsTCPClient) sendAt(seq uint32, flags uint8, payload []byte, mss int) {
	outcome := cl.h.consumer.handleOutbound(buildTCPSegment(tcpSegment{
		SourceIP: testAddr(cl.h.t, "100.96.0.1"), DestinationIP: testAddr(cl.h.t, "198.18.0.1"),
		SourcePort: cl.port, DestinationPort: 53, Seq: seq, Ack: cl.ack, Flags: flags, Window: 65535,
		MSS: mss, Payload: payload,
	}), cl.h.at())
	if outcome != egressOutcomeDNS {
		cl.h.t.Fatalf("a segment to the responder: %s", outcome)
	}
}

// received returns the responder's segments to this client since the last call.
func (cl *dnsTCPClient) received() []tcpSegment {
	packets := cl.h.packets()
	var out []tcpSegment
	for _, packet := range packets[cl.seen:] {
		segment, ok := parseTCPSegment(packet)
		if !ok {
			cl.h.t.Fatal("the responder wrote a segment that does not verify")
		}
		if segment.DestinationPort == cl.port {
			out = append(out, segment)
		}
	}
	cl.seen = len(packets)
	return out
}

// handshake opens the connection and returns the SYN-ACK.
func (cl *dnsTCPClient) handshake(mss int) tcpSegment {
	cl.h.t.Helper()
	cl.send(tcpFlagSYN, nil, mss)
	segments := cl.received()
	if len(segments) != 1 || segments[0].Flags != tcpFlagSYN|tcpFlagACK || segments[0].Ack != cl.seq {
		cl.h.t.Fatalf("the answer to the SYN is %+v", segments)
	}
	cl.ack = segments[0].Seq + 1
	cl.send(tcpFlagACK, nil, 0)
	return segments[0]
}

// take records what the responder sent in order and acknowledges it; it returns the stream bytes
// that arrived, in sequence order.
func (cl *dnsTCPClient) take(segments []tcpSegment, acknowledge bool) []byte {
	var stream []byte
	sort.SliceStable(segments, func(i, j int) bool { return seqLess(segments[i].Seq, segments[j].Seq) })
	for _, segment := range segments {
		if segment.Seq != cl.ack {
			continue
		}
		stream = append(stream, segment.Payload...)
		cl.ack += segment.segmentLength()
	}
	if acknowledge {
		cl.send(tcpFlagACK, nil, 0)
	}
	return stream
}

func framedDNS(messages ...[]byte) []byte {
	var out []byte
	for _, message := range messages {
		out = binary.BigEndian.AppendUint16(out, uint16(len(message)))
		out = append(out, message...)
	}
	return out
}

// dnsMessagesIn cuts a stream into its length-prefixed messages.
func dnsMessagesIn(t *testing.T, stream []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(stream) > 0 {
		if len(stream) < 2 || len(stream) < 2+int(binary.BigEndian.Uint16(stream)) {
			t.Fatalf("a message is cut short: %x", stream)
		}
		size := int(binary.BigEndian.Uint16(stream))
		out = append(out, stream[2:2+size])
		stream = stream[2+size:]
	}
	return out
}

func (h *dnsHarness) respondTo(query []byte) []byte {
	h.consumer.mu.Lock()
	defer h.consumer.mu.Unlock()
	return h.consumer.respondDNSLocked(query, h.now).Response
}

// The handshake settles the MSS, one query is answered, two sent together are answered in the order
// they came, and an answer behind a forwarded one waits for it.
func TestEgressDNSTCPAnswersQueriesInArrivalOrder(t *testing.T) {
	h := newDNSHarness(t)
	upstream := fakeTCPUpstream(t, func(query []byte) []byte {
		time.Sleep(50 * time.Millisecond)
		return upstreamReply(query, binary.BigEndian.Uint16(query[0:2]))
	})
	h.consumer.setDNSUpstreams([]string{upstream})
	cl := newDNSTCPClient(h, 40000)
	if synAck := cl.handshake(1460); synAck.MSS != egressDNSTCPMaxMSS {
		t.Errorf("SYN-ACK MSS %d, want min(1460, %d)", synAck.MSS, egressDNSTCPMaxMSS)
	}

	one := dnsQuery(0x0101, "www.example.com", dnsTypeA, false)
	cl.send(tcpFlagACK|tcpFlagPSH, framedDNS(one), 0)
	messages := dnsMessagesIn(t, cl.take(cl.received(), true))
	if len(messages) != 1 || !bytes.Equal(messages[0], h.respondTo(one)) {
		t.Fatalf("answers %x", messages)
	}

	two, three := dnsQuery(0x0102, "a.example.com", dnsTypeA, false), dnsQuery(0x0103, "www.example.com", dnsTypeAAAA, false)
	cl.send(tcpFlagACK|tcpFlagPSH, framedDNS(two, three), 0)
	messages = dnsMessagesIn(t, cl.take(cl.received(), true))
	if len(messages) != 2 || binary.BigEndian.Uint16(messages[0]) != 0x0102 || binary.BigEndian.Uint16(messages[1]) != 0x0103 {
		t.Fatalf("pipelined answers %x, want 0102 then 0103", messages)
	}

	forwarded, local := dnsQuery(0x0104, "example.org", dnsTypeA, false), dnsQuery(0x0105, "b.example.com", dnsTypeA, false)
	cl.send(tcpFlagACK|tcpFlagPSH, framedDNS(forwarded, local), 0)
	if stream := cl.take(cl.received(), false); len(stream) != 0 {
		t.Fatalf("an answer went ahead of the forwarded query before it: %x", stream)
	}
	var segments []tcpSegment
	deadline := time.Now().Add(5 * time.Second)
	for len(segments) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
		segments = cl.received()
	}
	messages = dnsMessagesIn(t, cl.take(segments, true))
	if len(messages) != 2 || !bytes.Equal(messages[0], upstreamReply(forwarded, 0x0104)) || binary.BigEndian.Uint16(messages[1]) != 0x0105 {
		t.Fatalf("answers %x, want the forwarded one then the local one", messages)
	}
	h.waitQueries(t, egressDNSQueries{Answered: 4, Forwarded: 1})
}

// A forwarded answer the size of a truncated one is cut into segments of the MSS the peer asked for.
func TestEgressDNSTCPSplitsALargeAnswerByMSS(t *testing.T) {
	h := newDNSHarness(t)
	large := make([]byte, 3000)
	upstream := fakeTCPUpstream(t, func(query []byte) []byte {
		reply := append([]byte(nil), large...)
		copy(reply, query[:2])
		reply[2] = 0x81
		return reply
	})
	h.consumer.setDNSUpstreams([]string{upstream})
	cl := newDNSTCPClient(h, 40001)
	if synAck := cl.handshake(536); synAck.MSS != 536 {
		t.Errorf("SYN-ACK MSS %d, want the peer's 536", synAck.MSS)
	}
	query := dnsQuery(0x0201, "big.example.org", 16, false)
	cl.send(tcpFlagACK|tcpFlagPSH, framedDNS(query), 0)
	var segments []tcpSegment
	deadline := time.Now().Add(5 * time.Second)
	for len(segments) < 6 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
		segments = append(segments, cl.received()...)
	}
	data := 0
	for _, segment := range segments {
		if len(segment.Payload) > 536 {
			t.Errorf("a segment carries %d bytes, past the MSS", len(segment.Payload))
		}
		if len(segment.Payload) > 0 {
			data++
		}
	}
	if data != 6 {
		t.Errorf("%d data segments for a 3002-byte answer at MSS 536, want 6", data)
	}
	messages := dnsMessagesIn(t, cl.take(segments, true))
	if len(messages) != 1 || len(messages[0]) != 3000 || binary.BigEndian.Uint16(messages[0]) != 0x0201 {
		t.Fatalf("the large answer arrived as %d messages", len(messages))
	}
}

// An unacknowledged answer goes again every second, three times; still unacknowledged, the
// connection is reset and forgotten.
func TestEgressDNSTCPRetransmitsThenResets(t *testing.T) {
	h := newDNSHarness(t)
	cl := newDNSTCPClient(h, 40002)
	cl.handshake(1460)
	cl.send(tcpFlagACK|tcpFlagPSH, framedDNS(dnsQuery(0x0301, "www.example.com", dnsTypeA, false)), 0)
	first := cl.received()
	if len(first) != 1 || len(first[0].Payload) == 0 {
		t.Fatalf("the answer is %+v", first)
	}
	h.consumer.tickDNS(h.advance(999 * time.Millisecond))
	if again := cl.received(); len(again) != 0 {
		t.Fatalf("sent again before a second: %+v", again)
	}
	for retry := 1; retry <= egressDNSTCPMaxRetries; retry++ {
		h.consumer.tickDNS(h.advance(time.Second))
		again := cl.received()
		if len(again) != 1 || again[0].Seq != first[0].Seq || !bytes.Equal(again[0].Payload, first[0].Payload) {
			t.Fatalf("retransmission %d: %+v", retry, again)
		}
	}
	h.consumer.tickDNS(h.advance(time.Second))
	last := cl.received()
	if len(last) != 1 || !last[0].has(tcpFlagRST) || last[0].Seq != first[0].Seq {
		t.Fatalf("after three retransmissions: %+v, want a reset at the unacknowledged byte", last)
	}
	if len(h.consumer.dnsConns) != 0 {
		t.Error("the reset connection is still held")
	}
}

// A peer's FIN is answered once everything queued is written; a connection with nothing to do for
// ten seconds is closed from this end.
func TestEgressDNSTCPClosesOnFINAndWhenIdle(t *testing.T) {
	h := newDNSHarness(t)
	cl := newDNSTCPClient(h, 40003)
	cl.handshake(1460)
	cl.send(tcpFlagACK|tcpFlagPSH|tcpFlagFIN, framedDNS(dnsQuery(0x0401, "www.example.com", dnsTypeA, false)), 0)
	segments := cl.received()
	if len(segments) != 2 || len(segments[0].Payload) == 0 || !segments[1].has(tcpFlagFIN) {
		t.Fatalf("after the peer's FIN: %+v, want the answer then a FIN", segments)
	}
	cl.take(segments, true)
	if len(h.consumer.dnsConns) != 0 {
		t.Error("the connection outlived both FINs")
	}

	idle := newDNSTCPClient(h, 40004)
	idle.handshake(1460)
	idle.send(tcpFlagACK|tcpFlagPSH, framedDNS(dnsQuery(0x0402, "www.example.com", dnsTypeA, false)), 0)
	idle.take(idle.received(), true)
	h.consumer.tickDNS(h.advance(egressDNSTCPIdle - time.Millisecond))
	if early := idle.received(); len(early) != 0 {
		t.Fatalf("closed before ten idle seconds: %+v", early)
	}
	h.consumer.tickDNS(h.advance(time.Millisecond))
	fin := idle.received()
	if len(fin) != 1 || !fin[0].has(tcpFlagFIN) {
		t.Fatalf("after ten idle seconds: %+v, want a FIN", fin)
	}
	idle.take(fin, false)
	idle.send(tcpFlagACK|tcpFlagFIN, nil, 0)
	if len(h.consumer.dnsConns) != 0 {
		t.Error("the idle connection outlived both FINs")
	}
}

// Out of order is dropped with the current ACK; a segment for no connection is reset; a reset drops
// the connection; the sixty-fifth connection is refused.
func TestEgressDNSTCPGuardsItsEdges(t *testing.T) {
	h := newDNSHarness(t)
	cl := newDNSTCPClient(h, 40005)
	cl.handshake(1460)
	cl.sendAt(cl.seq+10, tcpFlagACK|tcpFlagPSH, framedDNS(dnsQuery(0x0501, "www.example.com", dnsTypeA, false)), 0)
	if dup := cl.received(); len(dup) != 1 || len(dup[0].Payload) != 0 || dup[0].Ack != cl.seq {
		t.Fatalf("out of order: %+v, want a bare ACK of %d", dup, cl.seq)
	}
	cl.send(tcpFlagRST, nil, 0)
	if len(h.consumer.dnsConns) != 0 {
		t.Fatal("a reset did not drop the connection")
	}

	stray := newDNSTCPClient(h, 40006)
	stray.ack = 777
	stray.send(tcpFlagACK, nil, 0)
	if reset := stray.received(); len(reset) != 1 || !reset[0].has(tcpFlagRST) || reset[0].Seq != 777 {
		t.Fatalf("a segment for no connection: %+v, want a reset", reset)
	}

	for port := uint16(41000); port < 41000+egressDNSTCPMaxConns; port++ {
		newDNSTCPClient(h, port).send(tcpFlagSYN, nil, 1460)
	}
	over := newDNSTCPClient(h, 41000+egressDNSTCPMaxConns)
	over.send(tcpFlagSYN, nil, 1460)
	if refused := over.received(); len(refused) != 1 || !refused[0].has(tcpFlagRST) {
		t.Fatalf("connection %d: %+v, want a reset", egressDNSTCPMaxConns+1, refused)
	}
	if len(h.consumer.dnsConns) != egressDNSTCPMaxConns {
		t.Errorf("%d connections held, want %d", len(h.consumer.dnsConns), egressDNSTCPMaxConns)
	}
}

// consumer.dns says where the responder listens, what it forwards to and what it has done; a query
// from elsewhere shows under blocked.
func TestEgressStatusReportsTheResponder(t *testing.T) {
	harness := newPhaseTwoHarness(t, nil, phaseTwoRules()...)
	harness.tick(0)
	harness.mesh.setEgressDNSUpstreams([]string{"192.0.2.53"})
	consumer := harness.consumer()
	consumer.dnsLocalAddresses = func() []uint32 { return nil }
	consumer.handleOutbound(dnsUDPQueryPacket(t, "100.96.0.1", 53000, 53, dnsQuery(1, "www.example.com", dnsTypeA, false)), flowEpoch)
	consumer.handleOutbound(dnsUDPQueryPacket(t, "10.9.9.9", 53000, 53, dnsQuery(2, "www.example.com", dnsTypeA, false)), flowEpoch)

	section := mapSection(t, harness.mesh.egressStatusJSON(), "consumer")
	dns, _ := section["dns"].(map[string]any)
	upstreams, _ := dns["upstreams"].([]string)
	queries, _ := dns["queries"].(map[string]int64)
	if dns["listen"] != "198.18.0.1" || len(upstreams) != 1 || upstreams[0] != "192.0.2.53" ||
		queries["answered"] != 1 || queries["forwarded"] != 0 || queries["failed"] != 0 {
		t.Errorf("dns = %v", dns)
	}
	if blocked, _ := section["blocked"].(map[string]int64); blocked["dns-not-local"] != 1 {
		t.Errorf("blocked = %v", section["blocked"])
	}
}
