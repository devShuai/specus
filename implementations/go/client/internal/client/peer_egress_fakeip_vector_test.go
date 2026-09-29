package client

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"testing"
	"time"
)

// Step three of phase two against peer-egress-dns-v1.json: when phase two runs, which rules are in
// force, which rule a name selects, how the pool hands addresses out, what a consumer keeps from
// egress-catalog, what the consumer does with each packet sent into the pool, and which flows a
// name-bind closes at the egress. Every case goes through the code the client runs.

type dnsPhaseTwoVector struct {
	MeshCIDR   string       `json:"meshCidr"`
	FakeIPCIDR string       `json:"fakeIpCidr"`
	Rules      []egressRule `json:"rules"`
	Validation []struct {
		Name     string     `json:"name"`
		Rule     egressRule `json:"rule"`
		Takeover bool       `json:"takeover"`
		Code     *string    `json:"code"`
	} `json:"validation"`
	PoolConfig []struct {
		Name string  `json:"name"`
		CIDR string  `json:"cidr"`
		Code *string `json:"code"`
	} `json:"poolConfig"`
	EgressCapability []struct {
		Name    string     `json:"name"`
		Rule    egressRule `json:"rule"`
		Capable bool       `json:"egressDomainTargetCapable"`
		Code    *string    `json:"code"`
	} `json:"egressCapability"`
	Selection []struct {
		Name      string `json:"name"`
		Query     string `json:"query"`
		RuleIndex *int   `json:"ruleIndex"`
	} `json:"selection"`
	Pool []struct {
		Name   string `json:"name"`
		CIDR   string `json:"cidr"`
		Events []struct {
			At      int64   `json:"at"`
			Query   *string `json:"query"`
			Traffic *string `json:"traffic"`
		} `json:"events"`
		Results []map[string]any `json:"results"`
	} `json:"pool"`
	PhaseTwo []struct {
		Name            string  `json:"name"`
		ConsumerEnabled bool    `json:"consumerEnabled"`
		Takeover        bool    `json:"takeover"`
		CIDR            string  `json:"cidr"`
		Active          bool    `json:"active"`
		Code            *string `json:"code"`
	} `json:"phaseTwo"`
	RuleStatus []struct {
		Name     string     `json:"name"`
		Rule     egressRule `json:"rule"`
		Takeover bool       `json:"takeover"`
		Online   bool       `json:"egressOnline"`
		Capable  bool       `json:"egressDomainTargetCapable"`
		Code     *string    `json:"code"`
	} `json:"ruleStatus"`
	Catalog []struct {
		Name       string  `json:"name"`
		JSON       *string `json:"json"`
		NewSession bool    `json:"newSession"`
		Accepted   *bool   `json:"accepted"`
		Capable    []int64 `json:"domainTargetCapable"`
	} `json:"catalog"`
	Steering []struct {
		Name    string           `json:"name"`
		CIDR    string           `json:"cidr"`
		Rules   []egressRule     `json:"rules"`
		Events  []steeringEvent  `json:"events"`
		Results []map[string]any `json:"results"`
	} `json:"steering"`
	NameBindClosesFlows struct {
		Events []struct {
			Open     *string `json:"open"`
			NameBind *string `json:"nameBind"`
			Consumer int64   `json:"consumer"`
			Address  string  `json:"address"`
		} `json:"events"`
		Results []map[string]any `json:"results"`
	} `json:"nameBindClosesFlows"`
}

type steeringPacket struct {
	Protocol        string `json:"protocol"`
	SourcePort      int    `json:"sourcePort"`
	Destination     string `json:"destination"`
	DestinationPort int    `json:"destinationPort"`
	Flags           string `json:"flags"`
}

type steeringEvent struct {
	At      int64            `json:"at"`
	Map     *string          `json:"map"`
	Packet  *steeringPacket  `json:"packet"`
	Reply   *steeringPacket  `json:"reply"`
	Rules   *[]egressRule    `json:"rules"`
	Online  map[string]bool  `json:"online"`
	Catalog *map[string]bool `json:"catalog"`
}

func loadDNSPhaseTwoVector(t *testing.T) dnsPhaseTwoVector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "protocol", "test-vectors", "peer-egress-dns-v1.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vector dnsPhaseTwoVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	return vector
}

func vectorCode(code *string) string {
	if code == nil {
		return ""
	}
	return *code
}

// takeoverPool is the pool a case's takeover flag means: the default pool when phase two runs.
func takeoverPool(vector dnsPhaseTwoVector, takeover bool) string {
	if takeover {
		return vector.FakeIPCIDR
	}
	return ""
}

func TestEgressPhaseTwoMatchesTheSharedVector(t *testing.T) {
	vector := loadDNSPhaseTwoVector(t)
	if len(vector.PhaseTwo) == 0 {
		t.Fatal("the vector has no phaseTwo cases")
	}
	for _, c := range vector.PhaseTwo {
		active, code := evaluateEgressPhaseTwo(c.ConsumerEnabled, c.Takeover, c.CIDR, vector.MeshCIDR)
		if active != c.Active || code != vectorCode(c.Code) {
			t.Errorf("%s: active=%v code=%q, want active=%v code=%q", c.Name, active, code, c.Active, vectorCode(c.Code))
		}
	}
	for _, c := range vector.PoolConfig {
		if code := validateEgressFakeIPPool(c.CIDR, vector.MeshCIDR); code != vectorCode(c.Code) {
			t.Errorf("pool %s: %q, want %q", c.Name, code, vectorCode(c.Code))
		}
	}
}

func TestEgressDomainRuleValidationMatchesTheSharedVector(t *testing.T) {
	vector := loadDNSPhaseTwoVector(t)
	for _, c := range vector.Validation {
		code := validateEgressRuleIn(c.Rule, vector.MeshCIDR, takeoverPool(vector, c.Takeover))
		if code != vectorCode(c.Code) {
			t.Errorf("%s: %q, want %q", c.Name, code, vectorCode(c.Code))
		}
	}
	// egressCapability is the status check with the egress online.
	for _, c := range vector.EgressCapability {
		code := egressRuleStatusCode(c.Rule, vector.MeshCIDR, vector.FakeIPCIDR,
			map[int64]bool{2: true}, map[int64]bool{2: c.Capable})
		if code != vectorCode(c.Code) {
			t.Errorf("capability %s: %q, want %q", c.Name, code, vectorCode(c.Code))
		}
	}
	for _, c := range vector.RuleStatus {
		code := egressRuleStatusCode(c.Rule, vector.MeshCIDR, takeoverPool(vector, c.Takeover),
			map[int64]bool{2: c.Online}, map[int64]bool{2: c.Capable})
		if code != vectorCode(c.Code) {
			t.Errorf("status %s: %q, want %q", c.Name, code, vectorCode(c.Code))
		}
	}
}

func TestEgressDomainRuleSelectionMatchesTheSharedVector(t *testing.T) {
	vector := loadDNSPhaseTwoVector(t)
	for _, c := range vector.Selection {
		want := -1
		if c.RuleIndex != nil {
			want = *c.RuleIndex
		}
		if index := selectEgressDomainRule(vector.Rules, c.Query, vector.MeshCIDR, vector.FakeIPCIDR); index != want {
			t.Errorf("%s: rule %d, want %d", c.Name, index, want)
		}
		// Without phase two no domain rule is in force, so none selects anything.
		if index := selectEgressDomainRule(vector.Rules, c.Query, vector.MeshCIDR, ""); index != -1 {
			t.Errorf("%s: rule %d selected with phase two off", c.Name, index)
		}
	}
}

func vectorAt(seconds int64) time.Time { return flowEpoch.Add(time.Duration(seconds) * time.Second) }

func assignmentResult(assignment egressFakeIPAssignment) map[string]any {
	evicted := make([]any, 0, len(assignment.Evicted))
	for _, entry := range assignment.Evicted {
		evicted = append(evicted, entry.Name)
	}
	if assignment.Exhausted {
		return map[string]any{"exhausted": true, "evicted": evicted}
	}
	return map[string]any{"address": formatEgressAddress(assignment.Address), "evicted": evicted}
}

func TestEgressFakeIPPoolMatchesTheSharedVector(t *testing.T) {
	vector := loadDNSPhaseTwoVector(t)
	if len(vector.Pool) == 0 {
		t.Fatal("the vector has no pool cases")
	}
	for _, c := range vector.Pool {
		cidr, ok := parseEgressCIDR(c.CIDR)
		if !ok {
			t.Fatalf("%s: pool %q", c.Name, c.CIDR)
		}
		pool := newEgressFakeIPPool(cidr)
		for index, event := range c.Events {
			var got map[string]any
			if event.Query != nil {
				got = assignmentResult(pool.assign(*event.Query, vectorAt(event.At)))
			} else {
				address, _ := parseEgressAddress(*event.Traffic)
				if name, mapped := pool.nameFor(address, vectorAt(event.At), true); mapped {
					got = map[string]any{"name": name}
				} else {
					got = map[string]any{"blocked": "fake-ip-unmapped"}
				}
			}
			if !reflect.DeepEqual(got, c.Results[index]) {
				t.Errorf("%s event %d: %v, want %v", c.Name, index, got, c.Results[index])
			}
		}
	}
}

// The counts the status reports are taken at the moment of asking.
func TestEgressFakeIPPoolCountsAreTakenAtTheTimeAsked(t *testing.T) {
	cidr, _ := parseEgressCIDR("198.18.0.0/30")
	pool := newEgressFakeIPPool(cidr)
	pool.assign("only.example", vectorAt(0))
	pool.assign("next.example", vectorAt(int64(egressFakeIPMinLifetime/time.Second)))
	if mappings, quarantined := pool.counts(vectorAt(int64(egressFakeIPMinLifetime / time.Second))); mappings != 0 || quarantined != 1 {
		t.Errorf("just after the eviction: %d mappings, %d quarantined; want 0 and 1", mappings, quarantined)
	}
	later := int64((egressFakeIPMinLifetime + egressFakeIPQuarantine) / time.Second)
	if mappings, quarantined := pool.counts(vectorAt(later)); mappings != 0 || quarantined != 0 {
		t.Errorf("after the quarantine: %d mappings, %d quarantined; want none", mappings, quarantined)
	}
}

// A pool whose every address is mapped or quarantined is known to be full without a walk; the one
// way out of that, a quarantine ending, is still found.
func TestEgressFakeIPPoolFindsAnAddressWhoseQuarantineEnded(t *testing.T) {
	cidr, _ := parseEgressCIDR("198.18.5.0/24")
	pool := newEgressFakeIPPool(cidr)
	held := pool.first + 7
	for address := pool.first; address <= pool.last; address++ {
		if address != held {
			pool.byAddress[address] = "taken.example"
		}
	}
	pool.quarantine[held] = vectorAt(10)
	if _, found := pool.scan(vectorAt(9)); found {
		t.Fatal("found a free address while the only candidate was quarantined")
	}
	if address, found := pool.scan(vectorAt(10)); !found || address != held {
		t.Fatalf("scan after the quarantine = %s, %v; want %s", formatEgressAddress(address), found, formatEgressAddress(held))
	}
}

func TestEgressCatalogMatchesTheSharedVector(t *testing.T) {
	vector := loadDNSPhaseTwoVector(t)
	if len(vector.Catalog) == 0 {
		t.Fatal("the vector has no catalog cases")
	}
	reader := newEgressCatalogReader()
	for _, c := range vector.Catalog {
		if c.NewSession {
			reader.newSession()
		} else {
			accepted := reader.read([]byte(*c.JSON))
			if c.Accepted == nil || accepted != *c.Accepted {
				t.Errorf("%s: accepted=%v, want %v", c.Name, accepted, c.Accepted)
			}
		}
		if ids := reader.capableIDs(); !reflect.DeepEqual(ids, append([]int64{}, c.Capable...)) {
			t.Errorf("%s: capable %v, want %v", c.Name, ids, c.Capable)
		}
	}
}

// steeringPacketBytes builds the IPv4 packet an application would send for a vector packet.
func steeringPacketBytes(t *testing.T, packet steeringPacket, fromConsumer bool) []byte {
	t.Helper()
	consumer, remote := testAddr(t, "100.96.0.1"), testAddr(t, packet.Destination)
	source, destination := consumer, remote
	sourcePort, destinationPort := uint16(packet.SourcePort), uint16(packet.DestinationPort)
	if !fromConsumer {
		source, destination = remote, consumer
		sourcePort, destinationPort = destinationPort, sourcePort
	}
	switch packet.Protocol {
	case "tcp":
		flags := tcpFlagsFromLetters(packet.Flags)
		segment := tcpSegment{SourceIP: source, DestinationIP: destination, SourcePort: sourcePort,
			DestinationPort: destinationPort, Seq: 1000, Flags: flags, Window: 65535}
		if flags&tcpFlagACK != 0 {
			segment.Seq, segment.Ack = 1001, 5001
		}
		return buildTCPSegment(segment)
	case "udp":
		return buildUDPDatagram(udpDatagram{SourceIP: source, DestinationIP: destination,
			SourcePort: sourcePort, DestinationPort: destinationPort, Payload: []byte("q")})
	default:
		icmp := make([]byte, 28)
		icmp[0] = 0x45
		icmp[3] = 28
		icmp[9] = ipv4ProtocolICMP
		copy(icmp[12:16], []byte{100, 96, 0, 1})
		copy(icmp[16:20], []byte{byte(remote >> 24), byte(remote >> 16), byte(remote >> 8), byte(remote)})
		return icmp
	}
}

func steeringFlowKey(packet steeringPacket) string {
	return fmt.Sprintf("%s|%d|%s|%d", packet.Protocol, packet.SourcePort, packet.Destination, packet.DestinationPort)
}

// purgeResult reads the flow-purge frames the mesh would send for a purge back into the vector's
// shape, so what is checked is what goes on the wire.
func purgeResult(t *testing.T, purge map[int64][]string) map[string]any {
	t.Helper()
	out := map[string]any{}
	for egress, frame := range egressFlowPurgeFrames(purge) {
		parsed, code := parsePeerEgressFrame(frame)
		control, ok := decodePeerEgressControl(parsed.Body)
		if code != "" || !ok || control.Type != peerEgressControlFlowPurge {
			t.Fatalf("egress %d: the purge is not a flow-purge frame (%s)", egress, code)
		}
		destinations := make([]any, 0, len(control.Destinations))
		for _, destination := range control.Destinations {
			destinations = append(destinations, destination)
		}
		out[strconv.FormatInt(egress, 10)] = destinations
	}
	return map[string]any{"purge": out}
}

func mergePurges(into, from map[int64][]string) {
	for egress, destinations := range from {
		into[egress] = sortedUniqueStrings(append(into[egress], destinations...))
	}
}

// The steering case through the real consumer: real IPv4 packets in, and out of it exactly what it
// sends to each egress, what it writes back to the TUN and what it counts.
func TestEgressConsumerSteeringMatchesTheSharedVector(t *testing.T) {
	vector := loadDNSPhaseTwoVector(t)
	if len(vector.Steering) == 0 {
		t.Fatal("the vector has no steering case")
	}
	for _, c := range vector.Steering {
		harness := newConsumerHarness(t, nil, nil)
		consumer := harness.consumer
		consumer.configureIn(c.Rules, vector.MeshCIDR, "100.96.0.1", c.CIDR, flowEpoch)
		carriedBy := map[string]int64{}
		for index, event := range c.Events {
			now := vectorAt(event.At)
			var got map[string]any
			switch {
			case event.Map != nil:
				assignment, running := consumer.assignFakeIP(*event.Map, now)
				if !running {
					t.Fatalf("%s event %d: phase two is not running in the consumer", c.Name, index)
				}
				got = assignmentResult(assignment)
			case event.Packet != nil:
				got = steerVectorPacket(t, harness, *event.Packet, now)
				if egress, forwarded := got["egressClientId"].(int64); forwarded {
					carriedBy[steeringFlowKey(*event.Packet)] = egress
				}
			case event.Reply != nil:
				before := len(harness.toTun)
				reply := steeringPacketBytes(t, *event.Reply, false)
				consumer.handleInbound(encodePeerEgressFrame(peerEgressTypeIPPacket, false, reply),
					carriedBy[steeringFlowKey(*event.Reply)], now)
				got = map[string]any{"accepted": len(harness.toTun) == before+1}
			default:
				purge := map[int64][]string{}
				if event.Rules != nil {
					mergePurges(purge, consumer.configureIn(*event.Rules, vector.MeshCIDR, "100.96.0.1", c.CIDR, now))
				}
				for id, up := range event.Online {
					egress, _ := strconv.ParseInt(id, 10, 64)
					mergePurges(purge, consumer.setEgressOnline(egress, up, now))
				}
				if event.Catalog != nil {
					capable := map[int64]bool{}
					for id, able := range *event.Catalog {
						egress, _ := strconv.ParseInt(id, 10, 64)
						capable[egress] = able
					}
					mergePurges(purge, consumer.setDomainCapable(capable, now))
				}
				got = purgeResult(t, purge)
			}
			want := c.Results[index]
			if !reflect.DeepEqual(normalizeJSON(t, got), want) {
				t.Errorf("%s event %d (at %d): %v, want %v", c.Name, index, event.At, got, want)
			}
		}
	}
}

// steerVectorPacket sends one packet through handleOutbound and describes what came out in the
// vector's terms, checking on the way that a name-bind goes before the packet it names and that a
// block is answered exactly when the vector says.
func steerVectorPacket(t *testing.T, harness *consumerHarness, packet steeringPacket, now time.Time) map[string]any {
	t.Helper()
	consumer := harness.consumer
	sentBefore, tunBefore := len(harness.sent), len(harness.toTun)
	blockedBefore := consumer.blockedCounts()
	raw := steeringPacketBytes(t, packet, true)
	outcome := consumer.handleOutbound(raw, now)
	sent, written := harness.sent[sentBefore:], harness.toTun[tunBefore:]
	blocked := map[string]int64{}
	for reason, count := range consumer.blockedCounts() {
		if delta := count - blockedBefore[reason]; delta != 0 {
			blocked[reason] = delta
		}
	}

	switch outcome {
	case egressOutcomeNotMine:
		if len(sent) != 0 || len(written) != 0 || len(blocked) != 0 {
			t.Errorf("%+v: not claimed, yet sent %d, wrote %d, counted %v", packet, len(sent), len(written), blocked)
		}
		return map[string]any{"outcome": "not-mine"}
	case egressOutcomeForwarded:
		if len(blocked) != 0 || len(written) != 0 {
			t.Errorf("%+v: forwarded, yet counted %v and wrote %d to the TUN", packet, blocked, len(written))
		}
		if len(sent) == 0 {
			t.Fatalf("%+v: forwarded with nothing sent", packet)
		}
		egress := sent[len(sent)-1].egress
		last, code := parsePeerEgressFrame(sent[len(sent)-1].frame)
		if code != "" || last.Type != peerEgressTypeIPPacket || string(last.Body) != string(raw) {
			t.Errorf("%+v: the last frame is not the packet itself (%s)", packet, code)
		}
		var nameBind any
		switch len(sent) {
		case 1:
		case 2:
			first, code := parsePeerEgressFrame(sent[0].frame)
			control, ok := decodePeerEgressControl(first.Body)
			if code != "" || first.Type != peerEgressTypeControl || !ok || control.Type != peerEgressControlNameBind {
				t.Fatalf("%+v: the frame before the packet is not a name-bind (%s)", packet, code)
			}
			if sent[0].egress != egress {
				t.Errorf("%+v: the name-bind went to %d and the packet to %d", packet, sent[0].egress, egress)
			}
			nameBind = map[string]any{"address": control.Address, "name": control.Name}
		default:
			t.Fatalf("%+v: %d frames for one packet", packet, len(sent))
		}
		return map[string]any{"outcome": "forwarded", "egressClientId": egress, "nameBind": nameBind}
	default:
		if len(sent) != 0 {
			t.Errorf("%+v: blocked, yet %d frames were sent", packet, len(sent))
		}
		if len(blocked) != 1 {
			t.Fatalf("%+v: blocked with counters %v, want exactly one reason", packet, blocked)
		}
		reason := ""
		for name, count := range blocked {
			reason = name
			if count != 1 {
				t.Errorf("%+v: %s counted %d times", packet, name, count)
			}
		}
		if len(written) > 1 {
			t.Errorf("%+v: %d answers written to the TUN", packet, len(written))
		}
		if len(written) == 1 {
			assertAnswers(t, packet, raw, written[0])
		}
		return map[string]any{"outcome": "blocked", "reason": reason, "answered": len(written) == 1}
	}
}

// assertAnswers checks an answer is the one the failure vector defines for the packet: a reset for
// TCP, a host-unreachable for UDP, from the address the application sent to.
func assertAnswers(t *testing.T, packet steeringPacket, raw, answer []byte) {
	t.Helper()
	want := egressFailurePacket(raw, peerPacketProtocol(raw))
	if string(answer) != string(want) {
		t.Errorf("%+v: the answer is not the failure packet for it", packet)
	}
	if packet.Protocol == "tcp" {
		if reset, ok := parseTCPSegment(answer); !ok || reset.Flags&tcpFlagRST == 0 || formatEgressAddress(reset.SourceIP) != packet.Destination {
			t.Errorf("%+v: the answer is not a reset from %s", packet, packet.Destination)
		}
	}
}

// normalizeJSON puts a result through JSON so it compares with what the vector decoded to.
func normalizeJSON(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Which flows a name-bind closes and which of those it resets, through the real egress runtime.
// Every flow is a TCP connection taken through its handshake, so each has a state machine that could
// send a reset: a flow is closed when its table entry and socket are gone, and reset when an RST
// went back to its consumer port.
func TestEgressNameBindClosesFlowsMatchesTheSharedVector(t *testing.T) {
	vector := loadDNSPhaseTwoVector(t)
	cases := vector.NameBindClosesFlows
	if len(cases.Events) == 0 {
		t.Fatal("the vector has no nameBindClosesFlows events")
	}
	harness := newEgressHarness(t, "198.18.0.0/15", "203.0.113.0/24")
	policy := testEgressPolicy("198.18.0.0/15", "203.0.113.0/24")
	consumers := map[int64]bool{}
	for _, event := range cases.Events {
		consumers[event.Consumer] = true
	}
	policy.AllowedConsumerClientIDs = nil
	for consumer := range consumers {
		policy.AllowedConsumerClientIDs = append(policy.AllowedConsumerClientIDs, consumer)
	}
	harness.runtime.applyPolicy(policy, newEgressContext(), flowEpoch)
	harness.runtime.resolve = resolvingTo("203.0.113.10")

	keys := map[string]egressFlowKey{}
	for index, event := range cases.Events {
		var got map[string]any
		if event.Open != nil {
			key := egressFlowKey{protocol: ipv4ProtocolTCP,
				consumerIP:   testAddr(t, fmt.Sprintf("100.96.0.%d", event.Consumer)),
				consumerPort: uint16(40000 + index), remoteIP: testAddr(t, event.Address), remotePort: 443}
			keys[*event.Open] = key
			openEstablishedEgressFlow(t, harness, event.Consumer, key)
			harness.runtime.mu.Lock()
			flow, opened := harness.runtime.flows.lookup(key)
			harness.runtime.mu.Unlock()
			if !opened {
				t.Fatalf("event %d: flow %s did not open", index, *event.Open)
			}
			var name any
			if flow.Name != "" {
				name = flow.Name
			}
			got = map[string]any{"name": name}
		} else {
			open := map[string]*egressFlow{}
			harness.runtime.mu.Lock()
			for id, key := range keys {
				if flow, present := harness.runtime.flows.lookup(key); present {
					open[id] = flow
				}
			}
			harness.runtime.mu.Unlock()
			segmentsBefore := len(harness.segments())
			bindName(t, harness, event.Consumer, event.Address, *event.NameBind)
			answered := harness.segments()[segmentsBefore:]
			closed, reset := []string{}, []string{}
			harness.runtime.mu.Lock()
			for id, flow := range open {
				if _, present := harness.runtime.flows.lookup(keys[id]); present {
					continue
				}
				closed = append(closed, id)
				if handle, ok := flow.Handle.(*egressTCPFlow); !ok || !handle.socket.(*fakeEgressConn).isClosed() {
					t.Errorf("event %d: flow %s left the table with its socket open", index, id)
				}
				for _, segment := range answered {
					if segment.has(tcpFlagRST) && segment.DestinationIP == keys[id].consumerIP &&
						segment.DestinationPort == keys[id].consumerPort {
						reset = append(reset, id)
						break
					}
				}
			}
			harness.runtime.mu.Unlock()
			sort.Strings(closed)
			sort.Strings(reset)
			got = map[string]any{"closed": closed, "reset": reset}
		}
		if want := cases.Results[index]; !reflect.DeepEqual(normalizeJSON(t, got), want) {
			t.Errorf("event %d: %v, want %v", index, got, want)
		}
	}
	// A closed flow is not refused: nothing tells the consumer to drop the flow it is reopening.
	if codes := harness.rejectCodes(); len(codes) != 0 {
		t.Errorf("closing flows for a name-bind sent flow-reject %v", codes)
	}
}

// openEstablishedEgressFlow opens a TCP flow at the egress and completes its handshake, answering
// the SYN-ACK sent to this flow's own consumer port.
func openEstablishedEgressFlow(t *testing.T, harness *egressHarness, consumer int64, key egressFlowKey) {
	t.Helper()
	syn := tcpSegment{SourceIP: key.consumerIP, DestinationIP: key.remoteIP, SourcePort: key.consumerPort,
		DestinationPort: key.remotePort, Seq: 1000, Flags: tcpFlagSYN, Window: 65535, MSS: 1360}
	harness.runtime.handleFrame(consumer, egressFrameFor(buildTCPSegment(syn)), flowEpoch)
	for _, segment := range harness.segments() {
		if segment.has(tcpFlagSYN) && segment.has(tcpFlagACK) && segment.DestinationPort == key.consumerPort &&
			segment.DestinationIP == key.consumerIP {
			harness.runtime.handleFrame(consumer, egressFrameFor(buildTCPSegment(tcpSegment{
				SourceIP: syn.SourceIP, DestinationIP: syn.DestinationIP,
				SourcePort: syn.SourcePort, DestinationPort: syn.DestinationPort,
				Seq: syn.Seq + 1, Ack: segment.Seq + 1, Flags: tcpFlagACK, Window: 65535,
			})), flowEpoch)
			return
		}
	}
	t.Fatalf("no SYN-ACK for consumer port %d", key.consumerPort)
}
