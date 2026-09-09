package peeregress

import "testing"

// The address parser sits in front of every access decision, so its rejections matter as much as
// its accepts. Anything it accepts loosely here is a difference the other runtimes can disagree on.

func TestParseAddressAcceptsCanonicalForms(t *testing.T) {
	for _, text := range []string{"0.0.0.0", "255.255.255.255", "203.0.113.200", "0.1.2.3"} {
		if _, ok := ParseAddress(text); !ok {
			t.Errorf("%s should parse", text)
		}
	}
	value, _ := ParseAddress("203.0.113.200")
	if got := FormatAddress(value); got != "203.0.113.200" {
		t.Errorf("round trip = %s", got)
	}
}

func TestParseAddressRejectsLeadingZeroOctets(t *testing.T) {
	// Runtimes disagree on 010: decimal ten or octal eight. A rule must not be able to mean
	// different things in different implementations.
	for _, text := range []string{"010.1.1.1", "1.02.3.4", "1.2.3.00"} {
		if _, ok := ParseAddress(text); ok {
			t.Errorf("%s should be rejected", text)
		}
	}
}

func TestParseAddressRejectsMalformedInput(t *testing.T) {
	for _, text := range []string{
		"", "1.2.3", "1.2.3.4.5", "1.2.3.", ".1.2.3",
		"1.2.3.256", "1.2.3.4444", "1.2.3.-4", "1.2.3.4 ", "::1",
	} {
		if _, ok := ParseAddress(text); ok {
			t.Errorf("%q should be rejected", text)
		}
	}
}

func TestParseCIDRRejectsHostBitsAndBadPrefixes(t *testing.T) {
	if _, ok := ParseCIDR("203.0.113.0/24"); !ok {
		t.Error("203.0.113.0/24 should parse")
	}
	for _, text := range []string{"203.0.113.1/24", "203.0.113.0/33", "203.0.113.0/08", "203.0.113.0/"} {
		if _, ok := ParseCIDR(text); ok {
			t.Errorf("%s should be rejected", text)
		}
	}
}

func TestBareAddressBecomesAHostPrefix(t *testing.T) {
	cidr, ok := ParseCIDR("203.0.113.9")
	if !ok || cidr.PrefixLen != MaxPrefix {
		t.Fatalf("bare address = %v ok=%v", cidr, ok)
	}
	if cidr.String() != "203.0.113.9/32" {
		t.Errorf("String() = %s", cidr.String())
	}
}

func TestContainsAndOverlapsFollowPrefixLength(t *testing.T) {
	slash24, _ := ParseCIDR("203.0.113.0/24")
	slash25, _ := ParseCIDR("203.0.113.128/25")
	other, _ := ParseCIDR("198.51.100.0/24")
	everything, _ := ParseCIDR("0.0.0.0/0")

	broadcast, _ := ParseAddress("203.0.113.255")
	below, _ := ParseAddress("203.0.113.127")
	anywhere, _ := ParseAddress("8.8.8.8")

	if !slash24.Contains(broadcast) {
		t.Error("/24 should contain its broadcast address")
	}
	if slash25.Contains(below) {
		t.Error("/25 should not contain an address below its network")
	}
	if !slash24.Overlaps(slash25) || !slash25.Overlaps(slash24) {
		t.Error("overlap must be symmetric")
	}
	if slash24.Overlaps(other) {
		t.Error("disjoint prefixes must not overlap")
	}
	if !everything.Contains(anywhere) {
		t.Error("0.0.0.0/0 should contain everything")
	}
}
