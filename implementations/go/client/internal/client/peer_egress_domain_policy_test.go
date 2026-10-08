package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"testing"
	"time"
)

// Domain rules in the egress policy (protocol/spec/peer-egress.md, 按域名授权), bound to
// protocol/test-vectors/peer-egress-domain-policy-v1.json. The vector's management half is what a
// server stores and is not read here; the authorize half is what an egress decides for a pushed
// egress-config, and every case goes through the real decoder and the real judgment layer.

type egressDomainPolicyVector struct {
	Config    json.RawMessage `json:"config"`
	Authorize []struct {
		Name    string          `json:"name"`
		Config  json.RawMessage `json:"config"`
		Request struct {
			ConsumerClientID int64   `json:"consumerClientId"`
			DestinationIP    string  `json:"destinationIp"`
			DestinationPort  int     `json:"destinationPort"`
			Protocol         string  `json:"protocol"`
			Name             *string `json:"name"`
		} `json:"request"`
		Code string `json:"code"`
	} `json:"authorize"`
}

func TestEgressDomainPolicyMatchesSharedVector(t *testing.T) {
	var vector egressDomainPolicyVector
	readEgressVector(t, "peer-egress-domain-policy-v1.json", &vector)
	if len(vector.Authorize) == 0 {
		t.Fatal("the domain policy vector carried no authorize cases")
	}
	for _, testCase := range vector.Authorize {
		config := testCase.Config
		if len(config) == 0 {
			config = vector.Config
		}
		policy, _, ok := decodeEgressConfig(config)
		if !ok {
			t.Errorf("%s: the egress-config was refused", testCase.Name)
			continue
		}
		name := ""
		if testCase.Request.Name != nil {
			name = *testCase.Request.Name
		}

		// The judgment layer on its own.
		decision := authorizeEgressFlow(egressRequest{
			ConsumerClientID: testCase.Request.ConsumerClientID,
			DestinationIP:    testCase.Request.DestinationIP,
			DestinationPort:  testCase.Request.DestinationPort,
			Protocol:         testCase.Request.Protocol,
			Name:             name,
		}, policy, true, newEgressContext())
		if decision.Code != testCase.Code || decision.Allowed != (testCase.Code == egressCodeAllowed) {
			t.Errorf("%s: got %s/%v, want %s", testCase.Name, decision.Code, decision.Allowed, testCase.Code)
		}

		// And the way the runtime asks it, for each resolved address of a named flow and for the
		// address of a flow without one.
		protocol := ipv4ProtocolTCP
		if testCase.Request.Protocol == "udp" {
			protocol = ipv4ProtocolUDP
		}
		runtime := newEgressRuntime(log.New(io.Discard, "", 0), nil,
			func(string, string, time.Duration) (net.Conn, error) { return nil, errors.New("not dialled") })
		runtime.applyPolicy(policy, newEgressContext(), flowEpoch)
		runtime.mu.Lock()
		code := runtime.authorizeTo(testCase.Request.ConsumerClientID,
			egressFlowKey{protocol: protocol, remotePort: uint16(testCase.Request.DestinationPort)},
			testNetAddr(t, testCase.Request.DestinationIP), name)
		runtime.mu.Unlock()
		if code != testCase.Code {
			t.Errorf("%s: the runtime got %s, want %s", testCase.Name, code, testCase.Code)
		}
	}
}

// What the decoder keeps of domainRules: a field that is not an array is nothing, an entry it cannot
// read is skipped without costing the rest of the push, and a kept match is in the form names are
// compared in.
func TestEgressConfigDecodesDomainRules(t *testing.T) {
	cases := []struct {
		name        string
		domainRules string
		want        []egressDomainRule
	}{
		{"absent", ``, nil},
		{"null", `,"domainRules":null`, nil},
		{"an object", `,"domainRules":{"match":"example.com","protocols":["tcp"],"portRanges":[[443,443]]}`, nil},
		{"a string", `,"domainRules":"example.com"`, nil},
		{"empty", `,"domainRules":[]`, nil},
		{"spelling normalised", `,"domainRules":[{"match":" *.CDN.Example. ","protocols":["tcp"],"portRanges":[[443,443]]}]`,
			[]egressDomainRule{{Match: "*.cdn.example", Protocols: []string{"tcp"}, PortRanges: [][]int{{443, 443}}}}},
		{"absent lists", `,"domainRules":[{"match":"example.org"}]`,
			[]egressDomainRule{{Match: "example.org"}}},
		{"null lists", `,"domainRules":[{"match":"example.org","protocols":null,"portRanges":null}]`,
			[]egressDomainRule{{Match: "example.org"}}},
		{"unreadable entries skipped", `,"domainRules":[
			"example.com", null, 7, ["example.com"],
			{"match":"*","protocols":["tcp"],"portRanges":[[443,443]]},
			{"match":"*.com","protocols":["tcp"],"portRanges":[[443,443]]},
			{"match":"localhost","protocols":["tcp"],"portRanges":[[443,443]]},
			{"match":"203.0.113.5","protocols":["tcp"],"portRanges":[[443,443]]},
			{"match":"中国.example","protocols":["tcp"],"portRanges":[[443,443]]},
			{"match":"a.*.example.com","protocols":["tcp"],"portRanges":[[443,443]]},
			{"match":7,"protocols":["tcp"],"portRanges":[[443,443]]},
			{"protocols":["tcp"],"portRanges":[[443,443]]},
			{"match":"*. example.com","protocols":["tcp"],"portRanges":[[443,443]]},
			{"match":"example.com .","protocols":["tcp"],"portRanges":[[443,443]]},
			{"match":"shape.example","protocols":"tcp","portRanges":[[443,443]]},
			{"match":"shape.example","protocols":["tcp",null],"portRanges":[[443,443]]},
			{"match":"shape.example","protocols":[6],"portRanges":[[443,443]]},
			{"match":"shape.example","protocols":["tcp"],"portRanges":[[443.5,443]]},
			{"match":"shape.example","protocols":["tcp"],"portRanges":[[443.0,443.0]]},
			{"match":"shape.example","protocols":["tcp"],"portRanges":[[443]]},
			{"match":"shape.example","protocols":["tcp"],"portRanges":[[443,443,443]]},
			{"match":"shape.example","protocols":["tcp"],"portRanges":[[443,null]]},
			{"match":"shape.example","protocols":["tcp"],"portRanges":[null]},
			{"match":"shape.example","protocols":["tcp"],"portRanges":[[true,443]]},
			{"match":"shape.example","protocols":["tcp"],"portRanges":"443"},
			{"match":"EXAMPLE.com.","protocols":["tcp"],"portRanges":[[443,443]]}]`,
			[]egressDomainRule{{Match: "example.com", Protocols: []string{"tcp"}, PortRanges: [][]int{{443, 443}}}}},
	}
	for _, c := range cases {
		payload := `{"type":"egress-config","enabled":true,"revision":1,"scope":"PUBLIC","allowedConsumerClientIds":[1],
			"destinationRules":[{"cidr":"203.0.113.0/24","protocols":["tcp"],"portRanges":[[443,443]]}]` + c.domainRules + `}`
		policy, _, ok := decodeEgressConfig([]byte(payload))
		if !ok {
			t.Errorf("%s: the push was refused", c.name)
			continue
		}
		if len(policy.DestinationRules) != 1 {
			t.Errorf("%s: %d destination rules survived, want 1", c.name, len(policy.DestinationRules))
		}
		if got, want := fmt.Sprintf("%+v", policy.DomainRules), fmt.Sprintf("%+v", c.want); got != want {
			t.Errorf("%s: domain rules %s, want %s", c.name, got, want)
		}
	}
}

// A domain match is read as written once trimmed: space left inside it, beside the wildcard or
// before a trailing dot, makes it malformed, as the reference generator reads it. The same check
// serves a consumer's domain rule, which is refused for it too.
func TestEgressDomainMatchRefusesSpaceInsideTheName(t *testing.T) {
	for match, valid := range map[string]bool{
		"example.com": true, "*.example.com": true, "Example.COM.": true, "*.CDN.Example.": true,
		"*. example.com": false, "example.com .": false, "*.\texample.com": false, "exa mple.com": false,
		"example.com. .": false,
	} {
		if validEgressDomainMatch(match) != valid {
			t.Errorf("validEgressDomainMatch(%q) = %v, want %v", match, !valid, valid)
		}
	}
	rule := egressRule{Match: "*. example.com", Action: egressActionEgress, EgressClientID: 2}
	if code := validateEgressRuleIn(rule, egressDefaultMeshCIDR, egressDefaultFakeIPCIDR); code != egressCodeRuleMalformed {
		t.Errorf("a consumer rule %q is %q, want %s", rule.Match, code, egressCodeRuleMalformed)
	}
}

// egressDomainPolicy is a pushed policy for consumer 7 whose destination rules cover only
// 203.0.113.0/24, read through the real decoder.
func egressDomainPolicy(t *testing.T, domainRules string) egressPolicy {
	t.Helper()
	policy, _, ok := decodeEgressConfig([]byte(`{"type":"egress-config","enabled":true,"revision":1,
		"scope":"PUBLIC","allowedConsumerClientIds":[7],
		"destinationRules":[{"cidr":"203.0.113.0/24","protocols":["tcp","udp"],"portRanges":[[1,65535]]}],
		"domainRules":` + domainRules + `}`))
	if !ok {
		t.Fatal("the egress-config was refused")
	}
	return policy
}

// A TCP flow opened for a name reaches an address outside every destination rule only through a
// domain rule covering the name: refused without one, admitted with one, kept by a push that still
// has it and revoked by the push that drops it.
func TestEgressRuntimeGrantsANamedFlowThroughADomainRule(t *testing.T) {
	withRule := egressDomainPolicy(t, `[{"match":"*.example.com","protocols":["tcp"],"portRanges":[[443,443]]}]`)
	withoutRule := egressDomainPolicy(t, `[]`)
	key := egressFlowKey{protocol: ipv4ProtocolTCP, consumerIP: testAddr(t, "100.96.0.1"), consumerPort: 40000,
		remoteIP: testAddr(t, "198.18.0.5"), remotePort: 443}

	t.Run("refused without the rule", func(t *testing.T) {
		harness := newEgressHarness(t)
		harness.runtime.applyPolicy(withoutRule, newEgressContext(), flowEpoch)
		harness.runtime.resolve = resolvingTo("192.0.2.10")
		bindName(t, harness, 7, "198.18.0.5", "www.example.com")

		harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(egressSyn(t, "100.96.0.1", 40000, "198.18.0.5", 443))), flowEpoch)
		harness.waitFor("a reset", harness.sawReset)
		if harness.dialCount() != 0 {
			t.Error("a name no rule grants was dialled")
		}
		if codes := harness.rejectCodes(); len(codes) != 1 || codes[0] != egressCodeDestinationDenied {
			t.Errorf("refused with %v, want %s", codes, egressCodeDestinationDenied)
		}
	})

	t.Run("admitted by the rule until a push drops it", func(t *testing.T) {
		harness := newEgressHarness(t)
		harness.runtime.applyPolicy(withRule, newEgressContext(), flowEpoch)
		// The first address rebinds the name to loopback; the domain rule does not reach past the
		// forced-deny list, so the second address is the one dialled.
		harness.runtime.resolve = resolvingTo("127.0.0.1", "192.0.2.10")
		bindName(t, harness, 7, "198.18.0.5", "WWW.Example.com.")

		openEstablishedEgressFlow(t, harness, 7, key)
		harness.mu.Lock()
		dialed := append([]string(nil), harness.dialed...)
		harness.mu.Unlock()
		if len(dialed) != 1 || dialed[0] != "192.0.2.10:443" {
			t.Fatalf("dialled %v, want 192.0.2.10:443", dialed)
		}
		harness.runtime.mu.Lock()
		flow, open := harness.runtime.flows.lookup(key)
		harness.runtime.mu.Unlock()
		if !open || flow.Name != "www.example.com" || formatEgressNetAddr(flow.dialled()) != "192.0.2.10" {
			t.Fatalf("the flow is open=%v, want it open for www.example.com to 192.0.2.10", open)
		}

		// The address the name resolved to, reached without the name, is not granted by the rule.
		harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(egressSyn(t, "100.96.0.1", 40001, "192.0.2.10", 443))), flowEpoch)
		if codes := harness.rejectCodes(); len(codes) != 1 || codes[0] != egressCodeDestinationDenied {
			t.Errorf("the flow by address was refused with %v, want %s", codes, egressCodeDestinationDenied)
		}
		if harness.dialCount() != 1 {
			t.Error("the flow by address was dialled")
		}

		harness.reset()
		harness.runtime.applyPolicy(withRule, newEgressContext(), flowEpoch)
		harness.runtime.mu.Lock()
		_, open = harness.runtime.flows.lookup(key)
		harness.runtime.mu.Unlock()
		if !open || harness.socket(0).isClosed() {
			t.Fatal("a push that still grants the name closed the flow")
		}
		if codes := harness.rejectCodes(); len(codes) != 0 {
			t.Errorf("a push that still grants the name sent flow-reject %v", codes)
		}

		harness.runtime.applyPolicy(withoutRule, newEgressContext(), flowEpoch)
		harness.runtime.mu.Lock()
		_, open = harness.runtime.flows.lookup(key)
		harness.runtime.mu.Unlock()
		if open || !harness.socket(0).isClosed() {
			t.Fatal("the push that dropped the domain rule left the flow open")
		}
		if codes := harness.rejectCodes(); len(codes) != 1 || codes[0] != egressCodeDestinationDenied {
			t.Errorf("revoked with %v, want %s", codes, egressCodeDestinationDenied)
		}
		if !harness.sawReset() {
			t.Error("the revoked flow was not reset")
		}
	})
}

// A named flow is judged again by the address its socket went to, not by the fake address its key
// keeps: a push that still grants the resolved address leaves it open.
func TestEgressRuntimeReauthorizesANamedFlowByTheAddressItDialled(t *testing.T) {
	harness := newEgressHarness(t)
	harness.runtime.resolve = resolvingTo("203.0.113.10")
	bindName(t, harness, 7, "198.18.0.5", "example.com")
	key := egressFlowKey{protocol: ipv4ProtocolTCP, consumerIP: testAddr(t, "100.96.0.1"), consumerPort: 40000,
		remoteIP: testAddr(t, "198.18.0.5"), remotePort: 443}
	openEstablishedEgressFlow(t, harness, 7, key)

	harness.runtime.applyPolicy(testEgressPolicy("203.0.113.0/24"), newEgressContext(), flowEpoch)
	harness.runtime.mu.Lock()
	_, open := harness.runtime.flows.lookup(key)
	harness.runtime.mu.Unlock()
	if !open {
		t.Fatalf("a push that still grants 203.0.113.10 revoked the flow: %v", harness.rejectCodes())
	}

	harness.runtime.applyPolicy(testEgressPolicy("198.18.0.0/15"), newEgressContext(), flowEpoch)
	harness.runtime.mu.Lock()
	_, open = harness.runtime.flows.lookup(key)
	harness.runtime.mu.Unlock()
	if open {
		t.Error("a push granting only the fake address kept a flow dialled to 203.0.113.10")
	}
}
