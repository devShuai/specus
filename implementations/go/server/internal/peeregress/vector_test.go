package peeregress

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Binds this implementation to the shared vectors under protocol/test-vectors. The assertions check
// the returned code, not just allow versus deny: a runtime that denies for the wrong reason still
// leaves an operator unable to tell a revoked ACL from a closed port.

type authzVector struct {
	EvaluationOrder    []string `json:"evaluationOrder"`
	ForcedDenyCIDRs    []string `json:"forcedDenyCidrs"`
	CloudMetadataCIDRs []string `json:"cloudMetadataCidrs"`
	LANCIDRs           []string `json:"lanCidrs"`
	Policy             Policy   `json:"policy"`
	Cases              []struct {
		Name    string  `json:"name"`
		Request Request `json:"request"`
		Expect  struct {
			Allowed bool   `json:"allowed"`
			Code    string `json:"code"`
		} `json:"expect"`
	} `json:"cases"`
	CrossLanguageCases []struct {
		Name    string  `json:"name"`
		Request Request `json:"request"`
		Expect  struct {
			Allowed bool   `json:"allowed"`
			Code    string `json:"code"`
		} `json:"expect"`
	} `json:"crossLanguageCases"`
	PolicyVariantCases []struct {
		Name           string `json:"name"`
		PolicyOverride struct {
			Enabled          *bool             `json:"enabled"`
			Scope            *string           `json:"scope"`
			DestinationRules []DestinationRule `json:"destinationRules"`
		} `json:"policyOverride"`
		PeerACLAllows *bool   `json:"peerAclAllows"`
		Request       Request `json:"request"`
		Expect        struct {
			Allowed bool   `json:"allowed"`
			Code    string `json:"code"`
		} `json:"expect"`
	} `json:"policyVariantCases"`
}

type rulesVector struct {
	MeshCIDR string `json:"meshCidr"`
	Rules    []Rule `json:"rules"`
	Cases    []struct {
		Name        string `json:"name"`
		Destination string `json:"destination"`
		Expect      struct {
			Action           string `json:"action"`
			MatchedRuleIndex *int   `json:"matchedRuleIndex"`
			EgressClientID   *int64 `json:"egressClientId"`
		} `json:"expect"`
	} `json:"cases"`
	ConfigValidation []struct {
		Name string `json:"name"`
		Rule Rule   `json:"rule"`
		Code string `json:"code"`
	} `json:"configValidation"`
}

func readVector(t *testing.T, name string, target any) {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for depth := 0; depth < 8; depth++ {
		candidate := filepath.Join(dir, "protocol", "test-vectors", name)
		if data, err := os.ReadFile(candidate); err == nil {
			if err := json.Unmarshal(data, target); err != nil {
				t.Fatalf("decode %s: %v", name, err)
			}
			return
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("cannot locate %s", name)
}

func contextFor(vector authzVector) Context {
	mesh := DefaultMeshCIDR
	for _, text := range vector.ForcedDenyCIDRs {
		if cidr, ok := ParseCIDR(text); ok && cidr.PrefixLen == 11 {
			mesh = text
		}
	}
	return Context{MeshCIDR: mesh}
}

func TestAuthorizationMatchesSharedVector(t *testing.T) {
	var vector authzVector
	readVector(t, "peer-egress-authz-v1.json", &vector)
	if len(vector.Cases) == 0 {
		t.Fatal("authorization vector carried no cases")
	}
	context := contextFor(vector)
	for _, testCase := range vector.Cases {
		decision := Authorize(testCase.Request, vector.Policy, true, context)
		if decision.Code != testCase.Expect.Code {
			t.Errorf("%s: code = %s, want %s", testCase.Name, decision.Code, testCase.Expect.Code)
		}
		if decision.Allowed != testCase.Expect.Allowed {
			t.Errorf("%s: allowed = %v, want %v", testCase.Name, decision.Allowed, testCase.Expect.Allowed)
		}
	}
}

func TestPolicyVariantsMatchSharedVector(t *testing.T) {
	var vector authzVector
	readVector(t, "peer-egress-authz-v1.json", &vector)
	if len(vector.PolicyVariantCases) == 0 {
		t.Fatal("authorization vector carried no policy variants")
	}
	context := contextFor(vector)
	for _, testCase := range vector.PolicyVariantCases {
		policy := vector.Policy
		if testCase.PolicyOverride.Enabled != nil {
			policy.Enabled = *testCase.PolicyOverride.Enabled
		}
		if testCase.PolicyOverride.Scope != nil {
			policy.Scope = *testCase.PolicyOverride.Scope
		}
		if testCase.PolicyOverride.DestinationRules != nil {
			policy.DestinationRules = testCase.PolicyOverride.DestinationRules
		}
		peerACLAllows := testCase.PeerACLAllows == nil || *testCase.PeerACLAllows
		decision := Authorize(testCase.Request, policy, peerACLAllows, context)
		if decision.Code != testCase.Expect.Code {
			t.Errorf("%s: code = %s, want %s", testCase.Name, decision.Code, testCase.Expect.Code)
		}
	}
}

// The vector's policy deliberately contains a 0.0.0.0/0 rule. Every address the vector declares as
// forced-deny must still be refused through it.
func TestForcedDenyDestinationsSurviveABroadAllowRule(t *testing.T) {
	var vector authzVector
	readVector(t, "peer-egress-authz-v1.json", &vector)
	broad := false
	for _, rule := range vector.Policy.DestinationRules {
		if rule.CIDR == "0.0.0.0/0" {
			broad = true
		}
	}
	if !broad {
		t.Fatal("vector policy must keep a broad rule, otherwise this test proves nothing")
	}

	context := contextFor(vector)
	denied := append(append([]string{}, vector.ForcedDenyCIDRs...), vector.CloudMetadataCIDRs...)
	if len(denied) == 0 {
		t.Fatal("vector declared no forced-deny ranges")
	}
	for _, text := range denied {
		cidr, ok := ParseCIDR(text)
		if !ok {
			t.Fatalf("%s: not a prefix", text)
		}
		decision := Authorize(Request{
			ConsumerClientID: 1,
			DestinationIP:    FormatAddress(cidr.Network),
			DestinationPort:  443,
			Protocol:         "tcp",
		}, vector.Policy, true, context)
		if decision.Code != CodeForbiddenDestType {
			t.Errorf("%s: code = %s, want %s", text, decision.Code, CodeForbiddenDestType)
		}
	}
}

func TestRuleMatchingMatchesSharedVector(t *testing.T) {
	var vector rulesVector
	readVector(t, "peer-egress-rules-v1.json", &vector)
	if len(vector.Rules) == 0 {
		t.Fatal("rules vector carried no rules")
	}
	for _, testCase := range vector.Cases {
		match := MatchRules(vector.Rules, testCase.Destination)
		if match.Action != testCase.Expect.Action {
			t.Errorf("%s: action = %s, want %s", testCase.Name, match.Action, testCase.Expect.Action)
		}
		if testCase.Expect.MatchedRuleIndex == nil {
			if match.Matched() {
				t.Errorf("%s: expected no match, got rule %d", testCase.Name, match.MatchedRuleIndex)
			}
			continue
		}
		if match.MatchedRuleIndex != *testCase.Expect.MatchedRuleIndex {
			t.Errorf("%s: matched rule %d, want %d",
				testCase.Name, match.MatchedRuleIndex, *testCase.Expect.MatchedRuleIndex)
		}
		if testCase.Expect.EgressClientID != nil {
			if match.EgressClientID == nil || *match.EgressClientID != *testCase.Expect.EgressClientID {
				t.Errorf("%s: egress client id mismatch", testCase.Name)
			}
		}
	}
}

func TestRuleValidationMatchesSharedVector(t *testing.T) {
	var vector rulesVector
	readVector(t, "peer-egress-rules-v1.json", &vector)
	mesh := vector.MeshCIDR
	if mesh == "" {
		mesh = DefaultMeshCIDR
	}
	for _, rule := range vector.Rules {
		if code := ValidateRule(rule, mesh); code != "" {
			t.Errorf("rule %s must pass validation, got %s", rule.Match, code)
		}
	}
	if len(vector.ConfigValidation) == 0 {
		t.Fatal("rules vector carried no configValidation cases")
	}
	for _, testCase := range vector.ConfigValidation {
		if code := ValidateRule(testCase.Rule, mesh); code != testCase.Code {
			t.Errorf("%s: code = %s, want %s", testCase.Name, code, testCase.Code)
		}
	}
}

// The hand-written cases document intent; this sweep exists to catch a runtime that agrees on the
// documented examples but diverges one address or one port away from a boundary. Every runtime runs
// the same sweep against the same policy, so a disagreement here is a disagreement about the rules.
func TestCrossLanguageBoundarySweepMatchesSharedVector(t *testing.T) {
	var vector authzVector
	readVector(t, "peer-egress-authz-v1.json", &vector)
	if len(vector.CrossLanguageCases) < 100 {
		t.Fatalf("cross-language sweep carried only %d cases", len(vector.CrossLanguageCases))
	}
	context := contextFor(vector)
	for _, testCase := range vector.CrossLanguageCases {
		decision := Authorize(testCase.Request, vector.Policy, true, context)
		if decision.Code != testCase.Expect.Code || decision.Allowed != testCase.Expect.Allowed {
			t.Errorf("%s: got %s/%v, want %s/%v", testCase.Name, decision.Code, decision.Allowed,
				testCase.Expect.Code, testCase.Expect.Allowed)
		}
	}
}
