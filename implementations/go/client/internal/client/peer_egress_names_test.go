package client

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

type dnsVector struct {
	NameBind []struct {
		Name    string `json:"name"`
		Address string `json:"address"`
		Domain  string `json:"domain"`
		JSON    string `json:"json"`
	} `json:"nameBind"`
	EgressChoice []struct {
		Name              string            `json:"name"`
		A                 []string          `json:"a"`
		AAAA              []string          `json:"aaaa"`
		IPv6TargetCapable bool              `json:"ipv6TargetCapable"`
		Decisions         map[string]string `json:"decisions"`
		Address           *string           `json:"address"`
		Code              string            `json:"code"`
	} `json:"egressChoice"`
}

func loadDNSVector(t *testing.T) dnsVector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "protocol", "test-vectors", "peer-egress-dns-v1.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vector dnsVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	return vector
}

// name-bind is encoded byte for byte as the other runtimes encode it, with the name normalised.
func TestNameBindMatchesTheSharedVector(t *testing.T) {
	for _, c := range loadDNSVector(t).NameBind {
		body, err := encodePeerEgressControl(peerEgressControl{
			Type: peerEgressControlNameBind, Address: c.Address, Name: normalizeEgressName(c.Domain)})
		if err != nil || string(body) != c.JSON {
			t.Errorf("%s: %s (%v), want %s", c.Name, body, err, c.JSON)
		}
		if code := validatePeerEgressControlBody(body); code != "" {
			t.Errorf("%s: the encoded binding does not validate: %s", c.Name, code)
		}
	}
}

// The egress dials the first resolved address the policy allows: the A records, or the AAAA records
// for a name with none when the egress connects to IPv6 targets, which this build does.
func TestEgressAddressChoiceMatchesTheSharedVector(t *testing.T) {
	if !egressIPv6TargetCapable {
		t.Fatal("this build announces IPv6 targets, and the vector's AAAA cases depend on it")
	}
	for _, c := range loadDNSVector(t).EgressChoice {
		parse := func(texts []string) []netip.Addr {
			addresses := make([]netip.Addr, 0, len(texts))
			for _, text := range texts {
				addresses = append(addresses, testNetAddr(t, text))
			}
			return addresses
		}
		candidates := egressDialCandidates(parse(c.A), parse(c.AAAA), c.IPv6TargetCapable)
		chosen, code := chooseEgressAddress(candidates, func(address netip.Addr) string {
			return c.Decisions[formatEgressNetAddr(address)]
		})
		if code != c.Code {
			t.Errorf("%s: code %s, want %s", c.Name, code, c.Code)
		}
		if c.Address == nil && chosen.IsValid() || c.Address != nil && formatEgressNetAddr(chosen) != *c.Address {
			t.Errorf("%s: chose %v, want %v", c.Name, chosen, c.Address)
		}
	}
}

func testNetAddr(t *testing.T, text string) netip.Addr {
	t.Helper()
	address, err := netip.ParseAddr(text)
	if err != nil {
		t.Fatalf("%s did not parse: %v", text, err)
	}
	return address
}

func TestNameBindingsAreValidatedAndKeptByRecentUse(t *testing.T) {
	for name, valid := range map[string]bool{
		"example.com": true, "WWW.Example.COM.": true, "xn--fiqs8s.example": true,
		"localhost": false, "*.example.com": false, "a_b.example.com": false, "-a.example": false,
		"1.2.3.4": false, "": false, "中国.example": false,
	} {
		if validEgressName(name) != valid {
			t.Errorf("validEgressName(%q) = %v, want %v", name, !valid, valid)
		}
	}

	table := newEgressNameTable()
	for address := uint32(1); address <= egressNameCapacityPerConsumer; address++ {
		table.bind(7, address, "example.com")
	}
	table.lookup(7, 1)
	table.bind(7, egressNameCapacityPerConsumer+1, "late.example")
	if _, ok := table.lookup(7, 1); !ok {
		t.Error("the binding just used was evicted")
	}
	if _, ok := table.lookup(7, 2); ok {
		t.Error("the least recently used binding survived a full table")
	}
	table.bind(9, 1, "other.example")
	table.dropConsumer(7)
	if table.size() != 1 {
		t.Errorf("after dropping consumer 7, %d bindings remain, want the other consumer's one", table.size())
	}
}

func bindName(t *testing.T, harness *egressHarness, consumer int64, address, name string) {
	t.Helper()
	body, err := encodePeerEgressControl(peerEgressControl{Type: peerEgressControlNameBind, Address: address, Name: name})
	if err != nil {
		t.Fatal(err)
	}
	harness.runtime.handleFrame(consumer, encodePeerEgressFrame(peerEgressTypeControl, false, body), flowEpoch)
}

func resolvingTo(addresses ...string) egressResolveFunc {
	return func(string) ([]netip.Addr, error) {
		if len(addresses) == 0 {
			return nil, errors.New("no such host")
		}
		resolved := make([]netip.Addr, 0, len(addresses))
		for _, text := range addresses {
			resolved = append(resolved, netip.MustParseAddr(text))
		}
		return resolved, nil
	}
}

// A flow to a bound address is dialled to what the name resolves to, and the flow keeps the fake
// address, so the replies come back from the address the consumer's application connected to.
func TestEgressRuntimeDialsTheResolvedAddressOfABoundName(t *testing.T) {
	harness := newEgressHarness(t)
	harness.runtime.resolve = resolvingTo("127.0.0.1", "203.0.113.10")
	bindName(t, harness, 7, "198.18.0.5", "example.com")

	syn := egressSyn(t, "100.96.0.1", 40000, "198.18.0.5", 443)
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(syn)), flowEpoch)
	harness.waitFor("the flow to open", func() bool { return harness.runtime.flows.size() == 1 })

	harness.mu.Lock()
	dialed := append([]string(nil), harness.dialed...)
	harness.mu.Unlock()
	if len(dialed) != 1 || dialed[0] != "203.0.113.10:443" {
		t.Fatalf("dialled %v, want the first allowed address 203.0.113.10:443", dialed)
	}
	segments := harness.segments()
	if len(segments) == 0 || formatEgressAddress(segments[0].SourceIP) != "198.18.0.5" {
		t.Fatalf("the SYN-ACK did not come from the fake address: %+v", segments)
	}
}

// A name that resolves only to what the policy forbids is refused, which is where DNS rebinding is
// stopped: nothing is dialled.
func TestEgressRuntimeRefusesANameThatResolvesToAForbiddenAddress(t *testing.T) {
	harness := newEgressHarness(t)
	harness.runtime.resolve = resolvingTo("127.0.0.1")
	bindName(t, harness, 7, "198.18.0.5", "rebind.example")

	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(egressSyn(t, "100.96.0.1", 40000, "198.18.0.5", 443))), flowEpoch)
	harness.waitFor("a reset", harness.sawReset)
	if harness.dialCount() != 0 {
		t.Error("a name resolving to loopback was dialled")
	}
	if codes := harness.rejectCodes(); len(codes) == 0 || codes[len(codes)-1] != egressCodeForbiddenDestType {
		t.Errorf("refused with %v, want %s", codes, egressCodeForbiddenDestType)
	}
}

func TestEgressRuntimeRefusesANameThatDoesNotResolve(t *testing.T) {
	harness := newEgressHarness(t)
	harness.runtime.resolve = resolvingTo()
	bindName(t, harness, 7, "198.18.0.5", "nowhere.example")

	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(egressSyn(t, "100.96.0.1", 40000, "198.18.0.5", 443))), flowEpoch)
	harness.waitFor("a reset", harness.sawReset)
	if codes := harness.rejectCodes(); len(codes) == 0 || codes[len(codes)-1] != egressCodeNameUnresolved {
		t.Errorf("refused with %v, want %s", codes, egressCodeNameUnresolved)
	}
}

// Bindings are per consumer: one consumer's name for an address says nothing about another's flows
// to the same address.
func TestEgressRuntimeKeepsBindingsPerConsumer(t *testing.T) {
	harness := newEgressHarness(t)
	harness.runtime.policy.AllowedConsumerClientIDs = []int64{7, 9}
	harness.runtime.resolve = resolvingTo("203.0.113.10")
	bindName(t, harness, 9, "198.18.0.5", "example.com")

	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(egressSyn(t, "100.96.0.1", 40000, "198.18.0.5", 443))), flowEpoch)
	harness.waitFor("a reset", harness.sawReset)
	if harness.dialCount() != 0 {
		t.Error("consumer 7's flow used consumer 9's binding")
	}
}

func TestMalformedNameBindIsRefused(t *testing.T) {
	for _, body := range []string{
		`{"type":"name-bind"}`,
		`{"type":"name-bind","address":"198.18.0.5"}`,
		`{"type":"name-bind","address":"not-an-address","name":"example.com"}`,
		`{"type":"name-bind","address":"198.18.0.5","name":"*.example.com"}`,
	} {
		if code := validatePeerEgressControlBody([]byte(body)); code != egressCodeFrameMalformedControl {
			t.Errorf("%s: %q, want %s", body, code, egressCodeFrameMalformedControl)
		}
	}
	if code := validatePeerEgressControlBody([]byte(`{"type":"route-hint"}`)); code != egressCodeControlUnsupported {
		t.Errorf("an unknown control type: %q, want %s", code, egressCodeControlUnsupported)
	}
}
