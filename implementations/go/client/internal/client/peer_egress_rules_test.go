package client

import "testing"

// Binds the consumer rule engine to the shared vector under protocol/test-vectors, the same fixture
// P4 will drive the Java and .NET consumers from.

type egressRulesVector struct {
	MeshCIDR string `json:"meshCidr"`
	Rules    []struct {
		Index          int    `json:"index"`
		Match          string `json:"match"`
		Action         string `json:"action"`
		EgressClientID int64  `json:"egressClientId"`
	} `json:"rules"`
	Cases []struct {
		Name        string `json:"name"`
		Destination string `json:"destination"`
		Expect      struct {
			Action           string `json:"action"`
			MatchedRuleIndex *int   `json:"matchedRuleIndex"`
			Reason           string `json:"reason"`
			EgressClientID   int64  `json:"egressClientId"`
		} `json:"expect"`
	} `json:"cases"`
	ConfigValidation []struct {
		Name string `json:"name"`
		Rule struct {
			Match          string `json:"match"`
			Action         string `json:"action"`
			EgressClientID int64  `json:"egressClientId"`
			Port           int    `json:"port"`
		} `json:"rule"`
		Code string `json:"code"`
	} `json:"configValidation"`
}

func loadEgressRulesVector(t *testing.T) (egressRulesVector, []egressRule) {
	t.Helper()
	var vector egressRulesVector
	readEgressVector(t, "peer-egress-rules-v1.json", &vector)
	if len(vector.Rules) == 0 {
		t.Fatal("rules vector carried no rules")
	}
	rules := make([]egressRule, 0, len(vector.Rules))
	for position, entry := range vector.Rules {
		// The vector states each rule's index; if it ever stops matching its position, the
		// expectations below would be pointing at a different rule than they name.
		if entry.Index != position {
			t.Fatalf("rule %d declares index %d", position, entry.Index)
		}
		rules = append(rules, egressRule{
			Match: entry.Match, Action: entry.Action, EgressClientID: entry.EgressClientID,
		})
	}
	return vector, rules
}

func TestEgressRulesMatchSharedVector(t *testing.T) {
	vector, rules := loadEgressRulesVector(t)
	if len(vector.Cases) == 0 {
		t.Fatal("rules vector carried no match cases")
	}
	for _, testCase := range vector.Cases {
		decision := matchEgressRules(rules, testCase.Destination, vector.MeshCIDR)

		wantIndex := -1
		if testCase.Expect.MatchedRuleIndex != nil {
			wantIndex = *testCase.Expect.MatchedRuleIndex
		}
		if decision.Action != testCase.Expect.Action || decision.MatchedRuleIndex != wantIndex ||
			decision.Reason != testCase.Expect.Reason {
			t.Errorf("%s: got %s/rule=%d/%s, want %s/rule=%d/%s", testCase.Name,
				decision.Action, decision.MatchedRuleIndex, decision.Reason,
				testCase.Expect.Action, wantIndex, testCase.Expect.Reason)
			continue
		}
		if decision.EgressClientID != testCase.Expect.EgressClientID {
			t.Errorf("%s: egress client = %d, want %d", testCase.Name,
				decision.EgressClientID, testCase.Expect.EgressClientID)
		}
	}
}

// The assertions check the returned code, not just that the rule was refused. An operator told only
// "invalid" cannot tell an unsupported feature from a typo.
func TestEgressRuleValidationMatchesSharedVector(t *testing.T) {
	vector, _ := loadEgressRulesVector(t)
	if len(vector.ConfigValidation) == 0 {
		t.Fatal("rules vector carried no validation cases")
	}
	for _, testCase := range vector.ConfigValidation {
		code := validateEgressRule(egressRule{
			Match:          testCase.Rule.Match,
			Action:         testCase.Rule.Action,
			EgressClientID: testCase.Rule.EgressClientID,
			Port:           testCase.Rule.Port,
		}, vector.MeshCIDR)
		if code != testCase.Code {
			t.Errorf("%s (%q): code = %q, want %q", testCase.Name, testCase.Rule.Match, code, testCase.Code)
		}
	}
}

// Every rule the vector configures has to survive validation, or the match cases above would be
// asserting against rules the engine quietly skips.
func TestEgressRulesFromTheVectorAllValidate(t *testing.T) {
	vector, rules := loadEgressRulesVector(t)
	if refused := validateEgressRuleSet(rules, vector.MeshCIDR); len(refused) != 0 {
		t.Errorf("the vector's own rules were refused: %+v", refused)
	}
}

// An operator fixing a rule list one refusal at a time learns about the second problem only after
// redeploying for the first.
func TestEgressRuleSetReportsEveryRefusal(t *testing.T) {
	refused := validateEgressRuleSet([]egressRule{
		{Match: "203.0.113.0/24", Action: egressActionDirect},
		{Match: "example.com", Action: egressActionEgress, EgressClientID: 2},
		{Match: "198.51.100.0/24", Action: egressActionEgress},
		{Match: "2001:db8::/32", Action: egressActionBlock},
	}, egressDefaultMeshCIDR)

	if len(refused) != 3 {
		t.Fatalf("reported %d refusals, want 3", len(refused))
	}
	want := []struct {
		index int
		code  string
	}{{1, egressCodeRuleDomainUnsupported}, {2, egressCodeRuleMissingTarget}, {3, egressCodeRuleIPv6Unsupported}}
	for position, expected := range want {
		if refused[position].Index != expected.index || refused[position].Code != expected.code {
			t.Errorf("refusal %d = rule %d/%s, want rule %d/%s", position,
				refused[position].Index, refused[position].Code, expected.index, expected.code)
		}
	}
}

// A rule can break several requirements at once, and the shared vector has no case that does. That
// gap is exactly where four implementations would drift, so the spec pins the order and these cases
// hold this one to it.
func TestEgressRuleValidationOrderIsFixed(t *testing.T) {
	cases := []struct {
		name string
		rule egressRule
		want string
	}{
		{"domain outranks port", egressRule{
			Match: "*.example.com", Action: egressActionEgress, EgressClientID: 2, Port: 443},
			egressCodeRuleDomainUnsupported},
		{"IPv6 outranks missing target", egressRule{
			Match: "2001:db8::/32", Action: egressActionEgress},
			egressCodeRuleIPv6Unsupported},
		{"an unreadable action outranks the default route", egressRule{
			Match: "0.0.0.0/0", Action: "forward"},
			egressCodeRuleMalformed},
		{"the default route outranks mesh overlap", egressRule{
			Match: "0.0.0.0/0", Action: egressActionEgress, EgressClientID: 2},
			egressCodeRuleDefaultRoute},
		{"mesh overlap outranks port", egressRule{
			Match: "100.96.0.0/11", Action: egressActionEgress, EgressClientID: 2, Port: 443},
			egressCodeRuleMeshOverlap},
		{"port outranks missing target", egressRule{
			Match: "203.0.113.0/24", Action: egressActionEgress, Port: 443},
			egressCodeRulePortUnsupported},
		{"host bits are malformed even with everything else right", egressRule{
			Match: "203.0.113.1/24", Action: egressActionEgress, EgressClientID: 2},
			egressCodeRuleMalformed},
	}
	for _, testCase := range cases {
		if code := validateEgressRule(testCase.rule, egressDefaultMeshCIDR); code != testCase.want {
			t.Errorf("%s: code = %q, want %q", testCase.name, code, testCase.want)
		}
	}
}

// A bare address is its own /32, and a /32 beats every prefix that contains it.
func TestEgressRuleAcceptsABareAddressAsAHostRoute(t *testing.T) {
	rules := []egressRule{
		{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2},
		{Match: "203.0.113.9", Action: egressActionBlock},
	}
	if code := validateEgressRule(rules[1], egressDefaultMeshCIDR); code != "" {
		t.Fatalf("a bare address was refused with %s", code)
	}
	decision := matchEgressRules(rules, "203.0.113.9", egressDefaultMeshCIDR)
	if decision.Action != egressActionBlock || decision.MatchedRuleIndex != 1 {
		t.Errorf("got %s/rule=%d", decision.Action, decision.MatchedRuleIndex)
	}
	// Its neighbour still takes the covering rule.
	if neighbour := matchEgressRules(rules, "203.0.113.10", egressDefaultMeshCIDR); neighbour.Action != egressActionEgress {
		t.Errorf("neighbour got %s", neighbour.Action)
	}
}

// A rule inside the mesh captures overlay traffic; a rule containing the mesh captures all of it.
// Both directions have to be refused, not only the one the vector happens to state.
func TestEgressRuleRefusesMeshOverlapInBothDirections(t *testing.T) {
	containing := egressRule{Match: "100.0.0.0/8", Action: egressActionEgress, EgressClientID: 2}
	if code := validateEgressRule(containing, egressDefaultMeshCIDR); code != egressCodeRuleMeshOverlap {
		t.Errorf("a rule containing the mesh got %q", code)
	}
	inside := egressRule{Match: "100.96.5.0/24", Action: egressActionEgress, EgressClientID: 2}
	if code := validateEgressRule(inside, egressDefaultMeshCIDR); code != egressCodeRuleMeshOverlap {
		t.Errorf("a rule inside the mesh got %q", code)
	}
	// A deployment that moved its mesh elsewhere must judge against that, not the default.
	if code := validateEgressRule(inside, "10.64.0.0/11"); code != "" {
		t.Errorf("a rule outside the deployment's own mesh was refused with %q", code)
	}
}

// One bad rule must not change what a good one does. The engine skips what validation would refuse
// rather than letting it match.
func TestEgressRulesSkipRefusedEntries(t *testing.T) {
	decision := matchEgressRules([]egressRule{
		{Match: "203.0.113.0/25", Action: egressActionEgress},
		{Match: "203.0.113.0/24", Action: egressActionBlock},
	}, "203.0.113.10", egressDefaultMeshCIDR)

	// The /25 is longer but has no target, so the /24 governs.
	if decision.Action != egressActionBlock || decision.MatchedRuleIndex != 1 {
		t.Errorf("got %s/rule=%d, want the valid rule to govern", decision.Action, decision.MatchedRuleIndex)
	}
}

// Unmatched traffic reports "direct" because that is what the user sees, but the reason has to say
// no rule matched: the routing installer keys off that to install nothing at all.
func TestEgressRulesDistinguishDefaultFromAnExplicitDirect(t *testing.T) {
	rules := []egressRule{{Match: "203.0.113.0/24", Action: egressActionDirect}}

	explicit := matchEgressRules(rules, "203.0.113.10", egressDefaultMeshCIDR)
	if explicit.Reason != egressReasonMatched || explicit.MatchedRuleIndex != 0 {
		t.Errorf("an explicit direct rule reported %s/rule=%d", explicit.Reason, explicit.MatchedRuleIndex)
	}

	fallthrough_ := matchEgressRules(rules, "8.8.8.8", egressDefaultMeshCIDR)
	if fallthrough_.Reason != egressReasonDefault || fallthrough_.MatchedRuleIndex != -1 {
		t.Errorf("an unmatched destination reported %s/rule=%d", fallthrough_.Reason, fallthrough_.MatchedRuleIndex)
	}
	if fallthrough_.Action != egressActionDirect {
		t.Errorf("an unmatched destination reported action %s", fallthrough_.Action)
	}
}
