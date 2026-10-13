package client

import "testing"

// Binds the IPv6 spelling and IPv6 rules to the ipv6Prefixes and ipv6 sections of
// peer-egress-rules-v1.json, the same sections the Java and .NET consumers read.

type egressIPv6Vector struct {
	IPv6Prefixes struct {
		Accept []struct {
			Text         string `json:"text"`
			Address      string `json:"address"`
			PrefixLength int    `json:"prefixLength"`
		} `json:"accept"`
		Reject []struct {
			Text string `json:"text"`
		} `json:"reject"`
	} `json:"ipv6Prefixes"`
	IPv6 struct {
		Rules []struct {
			Index          int    `json:"index"`
			Match          string `json:"match"`
			Action         string `json:"action"`
			EgressClientID int64  `json:"egressClientId"`
			Enabled        *bool  `json:"enabled"`
		} `json:"rules"`
		RefusedRules []struct {
			Index int    `json:"index"`
			Code  string `json:"code"`
		} `json:"refusedRules"`
		Cases            []egressIPv6MatchCase `json:"cases"`
		ConfigValidation []struct {
			Name string `json:"name"`
			Rule struct {
				Match          string `json:"match"`
				Action         string `json:"action"`
				EgressClientID int64  `json:"egressClientId"`
				Port           int    `json:"port"`
				Enabled        *bool  `json:"enabled"`
			} `json:"rule"`
			Code *string `json:"code"`
		} `json:"configValidation"`
		WithoutIPv6DataPlane struct {
			RuleCodes []struct {
				Index int     `json:"index"`
				Code  *string `json:"code"`
			} `json:"ruleCodes"`
			Cases []egressIPv6MatchCase `json:"cases"`
		} `json:"withoutIpv6DataPlane"`
	} `json:"ipv6"`
}

type egressIPv6MatchCase struct {
	Name        string `json:"name"`
	Destination string `json:"destination"`
	Expect      struct {
		Action           string `json:"action"`
		MatchedRuleIndex *int   `json:"matchedRuleIndex"`
		Reason           string `json:"reason"`
		EgressClientID   int64  `json:"egressClientId"`
	} `json:"expect"`
}

func loadEgressIPv6Vector(t *testing.T) (egressIPv6Vector, []egressRule) {
	t.Helper()
	var vector egressIPv6Vector
	readEgressVector(t, "peer-egress-rules-v1.json", &vector)
	if len(vector.IPv6Prefixes.Accept) == 0 || len(vector.IPv6Prefixes.Reject) == 0 || len(vector.IPv6.Rules) == 0 {
		t.Fatal("rules vector carried no IPv6 sections")
	}
	rules := make([]egressRule, 0, len(vector.IPv6.Rules))
	for position, entry := range vector.IPv6.Rules {
		if entry.Index != position {
			t.Fatalf("ipv6 rule %d declares index %d", position, entry.Index)
		}
		rules = append(rules, egressRule{Match: entry.Match, Action: entry.Action,
			EgressClientID: entry.EgressClientID, Enabled: entry.Enabled})
	}
	return vector, rules
}

func TestEgressIPv6SpellingMatchesSharedVector(t *testing.T) {
	vector, _ := loadEgressIPv6Vector(t)
	for _, testCase := range vector.IPv6Prefixes.Accept {
		cidr, _, ok := parseEgressCIDR6(testCase.Text)
		if !ok {
			t.Errorf("%q: refused, want %s/%d", testCase.Text, testCase.Address, testCase.PrefixLength)
			continue
		}
		if got := formatEgressAddress6(cidr.network); got != testCase.Address || cidr.prefixLen != testCase.PrefixLength {
			t.Errorf("%q: read as %s/%d, want %s/%d", testCase.Text, got, cidr.prefixLen, testCase.Address, testCase.PrefixLength)
		}
		// The canonical form has to read back as itself.
		if again, ok := parseEgressAddress6(testCase.Address); !ok || again != cidr.network {
			t.Errorf("%q: canonical %s does not read back", testCase.Text, testCase.Address)
		}
	}
	for _, testCase := range vector.IPv6Prefixes.Reject {
		if _, _, ok := parseEgressCIDR6(testCase.Text); ok {
			t.Errorf("%q: read, want refused", testCase.Text)
		}
	}
}

func TestEgressIPv6RulesMatchSharedVectorWithAnIPv6DataPlane(t *testing.T) {
	vector, rules := loadEgressIPv6Vector(t)
	refused := map[int]string{}
	for _, entry := range vector.IPv6.RefusedRules {
		refused[entry.Index] = entry.Code
	}
	for index, rule := range rules {
		if code := validateEgressRuleFor(rule, egressDefaultMeshCIDR, "", true); code != refused[index] {
			t.Errorf("ipv6 rule %d: code = %q, want %q", index, code, refused[index])
		}
	}
	for _, testCase := range vector.IPv6.Cases {
		checkEgressIPv6Match(t, testCase.Name, matchEgressRulesFor(rules, testCase.Destination, egressDefaultMeshCIDR, "", true), testCase)
	}
	for _, testCase := range vector.IPv6.ConfigValidation {
		want := ""
		if testCase.Code != nil {
			want = *testCase.Code
		}
		code := validateEgressRuleFor(egressRule{Match: testCase.Rule.Match, Action: testCase.Rule.Action,
			EgressClientID: testCase.Rule.EgressClientID, Port: testCase.Rule.Port, Enabled: testCase.Rule.Enabled},
			egressDefaultMeshCIDR, "", true)
		if code != want {
			t.Errorf("%s (%q): code = %q, want %q", testCase.Name, testCase.Rule.Match, code, want)
		}
	}
}

// What every client does today: the same list with no IPv6 data plane. The production entry points
// are the ones exercised, so a change to egressConsumerCarriesIPv6 without the data plane fails here.
func TestEgressIPv6RulesAreNotInForceWithoutAnIPv6DataPlane(t *testing.T) {
	vector, rules := loadEgressIPv6Vector(t)
	for _, entry := range vector.IPv6.WithoutIPv6DataPlane.RuleCodes {
		want := ""
		if entry.Code != nil {
			want = *entry.Code
		}
		if code := validateEgressRuleIn(rules[entry.Index], egressDefaultMeshCIDR, ""); code != want {
			t.Errorf("ipv6 rule %d: code = %q, want %q", entry.Index, code, want)
		}
	}
	for _, testCase := range vector.IPv6.WithoutIPv6DataPlane.Cases {
		checkEgressIPv6Match(t, testCase.Destination, matchEgressRules(rules, testCase.Destination, egressDefaultMeshCIDR), testCase)
	}
}

func checkEgressIPv6Match(t *testing.T, name string, decision egressRuleDecision, testCase egressIPv6MatchCase) {
	t.Helper()
	wantIndex := -1
	if testCase.Expect.MatchedRuleIndex != nil {
		wantIndex = *testCase.Expect.MatchedRuleIndex
	}
	if decision.Action != testCase.Expect.Action || decision.MatchedRuleIndex != wantIndex ||
		decision.Reason != testCase.Expect.Reason || decision.EgressClientID != testCase.Expect.EgressClientID {
		t.Errorf("%s: got %s/rule=%d/%s/%d, want %s/rule=%d/%s/%d", name,
			decision.Action, decision.MatchedRuleIndex, decision.Reason, decision.EgressClientID,
			testCase.Expect.Action, wantIndex, testCase.Expect.Reason, testCase.Expect.EgressClientID)
	}
}
