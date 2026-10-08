package peeregress

import "testing"

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
