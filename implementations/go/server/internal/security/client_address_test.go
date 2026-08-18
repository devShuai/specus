package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func addressRequest(remoteAddr string, headers map[string]string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = remoteAddr
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	return request
}

func TestDirectClientCannotSpoofAddressWithForwardedHeaders(t *testing.T) {
	// No trusted proxy configured: forwarded headers must be ignored entirely.
	resolver := NewClientAddressResolver(nil, nil)
	got := resolver.Resolve(addressRequest("203.0.113.50:44321", map[string]string{
		"X-Forwarded-For": "1.2.3.4",
		"X-Real-IP":       "5.6.7.8",
	}))
	if got != "203.0.113.50" {
		t.Fatalf("resolved = %q, want the connection peer 203.0.113.50", got)
	}
}

func TestUntrustedPeerIsUsedEvenWhenOtherProxiesAreTrusted(t *testing.T) {
	resolver := NewClientAddressResolver([]string{"10.0.0.0/8"}, nil)
	got := resolver.Resolve(addressRequest("203.0.113.50:44321", map[string]string{
		"X-Forwarded-For": "1.2.3.4",
		"X-Real-IP":       "5.6.7.8",
	}))
	if got != "203.0.113.50" {
		t.Fatalf("resolved = %q, want 203.0.113.50", got)
	}
}

func TestTrustedProxyResolvesForwardedClient(t *testing.T) {
	resolver := NewClientAddressResolver([]string{"10.0.0.0/8"}, nil)
	got := resolver.Resolve(addressRequest("10.1.2.3:5000", map[string]string{
		"X-Forwarded-For": "203.0.113.9",
	}))
	if got != "203.0.113.9" {
		t.Fatalf("resolved = %q, want 203.0.113.9", got)
	}
}

func TestMultiHopChainSkipsTrailingTrustedProxies(t *testing.T) {
	resolver := NewClientAddressResolver([]string{"10.0.0.0/8", "192.168.0.0/16"}, nil)
	// client, edge proxy, internal proxy — the two right-most hops are trusted infrastructure.
	got := resolver.Resolve(addressRequest("10.1.2.3:5000", map[string]string{
		"X-Forwarded-For": "203.0.113.9, 192.168.1.1, 10.9.9.9",
	}))
	if got != "203.0.113.9" {
		t.Fatalf("resolved = %q, want 203.0.113.9", got)
	}
}

func TestSpoofedLeadingHopsCannotEscapeTrustedChain(t *testing.T) {
	resolver := NewClientAddressResolver([]string{"10.0.0.0/8"}, nil)
	// The client prepended a fake hop; the right-most untrusted entry is still the real peer as
	// observed by our own trusted proxy.
	got := resolver.Resolve(addressRequest("10.1.2.3:5000", map[string]string{
		"X-Forwarded-For": "9.9.9.9, 203.0.113.9",
	}))
	if got != "203.0.113.9" {
		t.Fatalf("resolved = %q, want 203.0.113.9", got)
	}
}

func TestMalformedForwardedEntriesAreSkipped(t *testing.T) {
	resolver := NewClientAddressResolver([]string{"10.0.0.0/8"}, nil)
	got := resolver.Resolve(addressRequest("10.1.2.3:5000", map[string]string{
		"X-Forwarded-For": "203.0.113.9, not-an-ip, ",
	}))
	if got != "203.0.113.9" {
		t.Fatalf("resolved = %q, want 203.0.113.9", got)
	}
}

func TestRealIPUsedOnlyWhenWholeChainIsTrusted(t *testing.T) {
	resolver := NewClientAddressResolver([]string{"10.0.0.0/8"}, nil)
	got := resolver.Resolve(addressRequest("10.1.2.3:5000", map[string]string{
		"X-Forwarded-For": "10.9.9.9",
		"X-Real-IP":       "203.0.113.9",
	}))
	if got != "203.0.113.9" {
		t.Fatalf("resolved = %q, want 203.0.113.9", got)
	}
}

func TestFallsBackToPeerWhenTrustedProxySendsNothingUsable(t *testing.T) {
	resolver := NewClientAddressResolver([]string{"10.0.0.0/8"}, nil)
	got := resolver.Resolve(addressRequest("10.1.2.3:5000", map[string]string{
		"X-Forwarded-For": "not-an-ip",
	}))
	if got != "10.1.2.3" {
		t.Fatalf("resolved = %q, want 10.1.2.3", got)
	}
}

func TestSupportsIPv6PeersAndForwardedEntries(t *testing.T) {
	resolver := NewClientAddressResolver([]string{"2001:db8::/32"}, nil)
	// 2001:db8:1234::9 would still fall inside 2001:db8::/32, so use an address outside it.
	got := resolver.Resolve(addressRequest("[2001:db8::1]:5000", map[string]string{
		"X-Forwarded-For": "2001:dead:1234::9, 2001:db8::2",
	}))
	if got != "2001:dead:1234::9" {
		t.Fatalf("resolved = %q, want 2001:dead:1234::9", got)
	}

	untrusted := resolver.Resolve(addressRequest("[2001:dead::1]:5000", map[string]string{
		"X-Forwarded-For": "203.0.113.9",
	}))
	if untrusted != "2001:dead::1" {
		t.Fatalf("resolved = %q, want 2001:dead::1", untrusted)
	}
}

func TestInvalidTrustedProxyEntriesDoNotTrustEverything(t *testing.T) {
	resolver := NewClientAddressResolver([]string{"not-a-cidr", "10.0.0.0/99", ""}, nil)
	got := resolver.Resolve(addressRequest("10.1.2.3:5000", map[string]string{
		"X-Forwarded-For": "203.0.113.9",
	}))
	if got != "10.1.2.3" {
		t.Fatalf("resolved = %q, want 10.1.2.3", got)
	}
}

func TestMissingRequestResolvesToUnknown(t *testing.T) {
	resolver := NewClientAddressResolver(nil, nil)
	if got := resolver.Resolve(nil); got != UnknownClientAddress {
		t.Fatalf("resolved = %q, want %q", got, UnknownClientAddress)
	}
}
