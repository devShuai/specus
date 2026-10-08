package peeregress

import (
	"strings"
	"testing"
)

// The IPv6 spelling against the ipv6Prefixes section of peer-egress-rules-v1.json, which the
// clients, the other servers and the admin page read too. What a server stores for an IPv6
// destination rule is the canonical address checked here, with the length only when it was written.
func TestIPv6SpellingMatchesSharedVector(t *testing.T) {
	var vector struct {
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
	}
	readVector(t, "peer-egress-rules-v1.json", &vector)
	if len(vector.IPv6Prefixes.Accept) == 0 || len(vector.IPv6Prefixes.Reject) == 0 {
		t.Fatal("rules vector carried no ipv6Prefixes")
	}
	for _, testCase := range vector.IPv6Prefixes.Accept {
		cidr, hadLength, ok := ParseCIDR6(testCase.Text)
		if !ok {
			t.Errorf("%q: refused", testCase.Text)
			continue
		}
		if got := FormatAddress6(cidr.Network); got != testCase.Address || cidr.PrefixLen != testCase.PrefixLength {
			t.Errorf("%q: read as %s/%d, want %s/%d", testCase.Text, got, cidr.PrefixLen, testCase.Address, testCase.PrefixLength)
		}
		want := testCase.Address
		if hadLength {
			want += "/" + itoa(testCase.PrefixLength)
		}
		if stored, ok := StoredDestinationCIDR(testCase.Text); !ok || stored != want {
			t.Errorf("%q: stored as %q, want %q", testCase.Text, stored, want)
		}
	}
	for _, testCase := range vector.IPv6Prefixes.Reject {
		if _, _, ok := ParseCIDR6(testCase.Text); ok {
			t.Errorf("%q: read, want refused", testCase.Text)
		}
		if _, ok := StoredDestinationCIDR(testCase.Text); ok {
			t.Errorf("%q: stored, want refused", testCase.Text)
		}
	}
}

// Egress-side authorization of IPv6 destinations against the ipv6 section of
// peer-egress-authz-v1.json, which the clients and the C server read too.
func TestIPv6AuthorizationMatchesSharedVector(t *testing.T) {
	type authzCase struct {
		Name           string `json:"name"`
		PolicyOverride *struct {
			Scope            string            `json:"scope"`
			DestinationRules []DestinationRule `json:"destinationRules"`
		} `json:"policyOverride"`
		Request Request `json:"request"`
		Expect  struct {
			Allowed bool   `json:"allowed"`
			Code    string `json:"code"`
		} `json:"expect"`
	}
	var vector struct {
		IPv6 struct {
			ForcedDenyCIDRs    []string    `json:"forcedDenyCidrs"`
			CloudMetadataCIDRs []string    `json:"cloudMetadataCidrs"`
			LANCIDRs           []string    `json:"lanCidrs"`
			Policy             Policy      `json:"policy"`
			Cases              []authzCase `json:"cases"`
			PolicyVariantCases []authzCase `json:"policyVariantCases"`
		} `json:"ipv6"`
	}
	readVector(t, "peer-egress-authz-v1.json", &vector)
	section := vector.IPv6
	if len(section.Cases) == 0 {
		t.Fatal("authorization vector carried no IPv6 cases")
	}
	for name, pair := range map[string][2][]string{
		"forcedDenyCidrs":    {ForcedDenyCIDRs6, section.ForcedDenyCIDRs},
		"cloudMetadataCidrs": {CloudMetadataCIDRs6, section.CloudMetadataCIDRs},
		"lanCidrs":           {LANCIDRs6, section.LANCIDRs},
	} {
		if strings.Join(pair[0], ",") != strings.Join(pair[1], ",") {
			t.Errorf("%s: %v, vector says %v", name, pair[0], pair[1])
		}
	}
	for _, testCase := range append(append([]authzCase{}, section.Cases...), section.PolicyVariantCases...) {
		policy := section.Policy
		if testCase.PolicyOverride != nil {
			policy.Scope = testCase.PolicyOverride.Scope
			policy.DestinationRules = testCase.PolicyOverride.DestinationRules
		}
		decision := Authorize(testCase.Request, policy, true, DefaultContext())
		if decision.Code != testCase.Expect.Code || decision.Allowed != testCase.Expect.Allowed {
			t.Errorf("%s: got %s/%v, want %s/%v", testCase.Name, decision.Code, decision.Allowed,
				testCase.Expect.Code, testCase.Expect.Allowed)
		}
	}
}
