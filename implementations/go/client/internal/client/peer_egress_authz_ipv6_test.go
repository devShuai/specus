package client

import "testing"

// Egress-side authorization of IPv6 destinations against the ipv6 section of
// peer-egress-authz-v1.json, which the Java, .NET, Go server and C server implementations read too.

type egressIPv6AuthzCase struct {
	Name           string `json:"name"`
	PolicyOverride *struct {
		Scope            string                  `json:"scope"`
		DestinationRules []egressDestinationRule `json:"destinationRules"`
	} `json:"policyOverride"`
	Request struct {
		ConsumerClientID    int64    `json:"consumerClientId"`
		DestinationIP       string   `json:"destinationIp"`
		DestinationPort     int      `json:"destinationPort"`
		Protocol            string   `json:"protocol"`
		LocalInterfaceCIDRs []string `json:"localInterfaceCidrs"`
	} `json:"request"`
	Expect struct {
		Allowed bool   `json:"allowed"`
		Code    string `json:"code"`
	} `json:"expect"`
}

type egressIPv6AuthzVector struct {
	IPv6 struct {
		ForcedDenyCIDRs    []string              `json:"forcedDenyCidrs"`
		CloudMetadataCIDRs []string              `json:"cloudMetadataCidrs"`
		LANCIDRs           []string              `json:"lanCidrs"`
		Policy             egressPolicy          `json:"policy"`
		Cases              []egressIPv6AuthzCase `json:"cases"`
		PolicyVariantCases []egressIPv6AuthzCase `json:"policyVariantCases"`
	} `json:"ipv6"`
}

func TestEgressIPv6AuthorizationMatchesSharedVector(t *testing.T) {
	var vector egressIPv6AuthzVector
	readEgressVector(t, "peer-egress-authz-v1.json", &vector)
	section := vector.IPv6
	if len(section.Cases) == 0 || len(section.PolicyVariantCases) == 0 {
		t.Fatal("authorization vector carried no IPv6 cases")
	}
	// The lists this build enforces are the ones the vector states, entry for entry.
	for _, pair := range []struct {
		name      string
		got, want []string
	}{
		{"forcedDenyCidrs", egressForcedDenyCIDRs6, section.ForcedDenyCIDRs},
		{"cloudMetadataCidrs", egressCloudMetadataCIDRs6, section.CloudMetadataCIDRs},
		{"lanCidrs", egressLANCIDRs6, section.LANCIDRs},
	} {
		if len(pair.got) != len(pair.want) {
			t.Fatalf("%s: %v, vector says %v", pair.name, pair.got, pair.want)
		}
		for index := range pair.got {
			if pair.got[index] != pair.want[index] {
				t.Errorf("%s[%d] = %s, vector says %s", pair.name, index, pair.got[index], pair.want[index])
			}
		}
	}
	context := newEgressContext()
	for _, testCase := range append(append([]egressIPv6AuthzCase{}, section.Cases...), section.PolicyVariantCases...) {
		policy := section.Policy
		if testCase.PolicyOverride != nil {
			policy.Scope = testCase.PolicyOverride.Scope
			policy.DestinationRules = testCase.PolicyOverride.DestinationRules
		}
		decision := authorizeEgressFlow(egressRequest{
			ConsumerClientID:    testCase.Request.ConsumerClientID,
			DestinationIP:       testCase.Request.DestinationIP,
			DestinationPort:     testCase.Request.DestinationPort,
			Protocol:            testCase.Request.Protocol,
			LocalInterfaceCIDRs: testCase.Request.LocalInterfaceCIDRs,
		}, policy, true, context)
		if decision.Code != testCase.Expect.Code || decision.Allowed != testCase.Expect.Allowed {
			t.Errorf("%s: got %s/%v, want %s/%v", testCase.Name, decision.Code, decision.Allowed,
				testCase.Expect.Code, testCase.Expect.Allowed)
		}
	}
	// Every forced-deny entry holds against the broad ::/0 rule in the vector's policy.
	for _, text := range append(append([]string{}, section.ForcedDenyCIDRs...), section.CloudMetadataCIDRs...) {
		cidr, _, ok := parseEgressCIDR6(text)
		if !ok {
			t.Fatalf("%s: not a prefix", text)
		}
		decision := authorizeEgressFlow(egressRequest{ConsumerClientID: 1,
			DestinationIP: formatEgressAddress6(cidr.network), DestinationPort: 443, Protocol: "tcp"},
			section.Policy, true, context)
		if decision.Code != egressCodeForbiddenDestType {
			t.Errorf("%s: code = %s, want %s", text, decision.Code, egressCodeForbiddenDestType)
		}
	}
}

// A name with no A record is dialled over IPv6 (peer-egress-dns.md): the egress's own socket goes to
// the first AAAA address the policy allows, while the consumer still sees the flow at its IPv4 fake
// address. The rebound loopback ahead of it is refused by the IPv6 forced-deny list.
func TestEgressRuntimeDialsAnIPv6OnlyName(t *testing.T) {
	harness := newEgressHarness(t, "::/0")
	harness.runtime.resolve = resolvingTo("::1", "2001:DB8::10")
	bindName(t, harness, 7, "198.18.0.5", "v6only.example")

	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(egressSyn(t, "100.96.0.1", 40000, "198.18.0.5", 443))), flowEpoch)
	harness.waitFor("the flow to open", func() bool { return harness.runtime.flows.size() == 1 })

	harness.mu.Lock()
	dialed := append([]string(nil), harness.dialed...)
	harness.mu.Unlock()
	if len(dialed) != 1 || dialed[0] != "[2001:db8::10]:443" {
		t.Fatalf("dialled %v, want [2001:db8::10]:443", dialed)
	}
	segments := harness.segments()
	if len(segments) == 0 || formatEgressAddress(segments[0].SourceIP) != "198.18.0.5" {
		t.Fatalf("the SYN-ACK did not come from the fake address: %+v", segments)
	}
}

// A name rebound to nothing but IPv6 loopback is refused before anything is dialled.
func TestEgressRuntimeRefusesANameThatResolvesToIPv6Loopback(t *testing.T) {
	harness := newEgressHarness(t, "::/0")
	harness.runtime.resolve = resolvingTo("::1")
	bindName(t, harness, 7, "198.18.0.5", "rebind.example")

	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(egressSyn(t, "100.96.0.1", 40000, "198.18.0.5", 443))), flowEpoch)
	harness.waitFor("a reset", harness.sawReset)
	if harness.dialCount() != 0 {
		t.Error("a name resolving to IPv6 loopback was dialled")
	}
	if codes := harness.rejectCodes(); len(codes) == 0 || codes[len(codes)-1] != egressCodeForbiddenDestType {
		t.Errorf("refused with %v, want %s", codes, egressCodeForbiddenDestType)
	}
}

// Only an IPv6 target is dialled unbound; an IPv4-mapped one goes through the IPv4 choice.
func TestEgressSocketsToIPv6TargetsAreLeftUnbound(t *testing.T) {
	for address, want := range map[string]bool{
		"[2001:db8::10]:443": true, "203.0.113.10:443": false, "[::ffff:203.0.113.10]:443": false, "nonsense": false,
	} {
		if got := egressLeftUnbound(address); got != want {
			t.Errorf("%s: unbound = %v, want %v", address, got, want)
		}
	}
}
