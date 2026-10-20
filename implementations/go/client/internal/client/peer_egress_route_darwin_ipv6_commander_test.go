//go:build darwin

package client

import (
	"errors"
	"strings"
	"testing"
)

// The IPv6 half of the macOS routing table, driven for real under the same rules as the IPv4 tests:
// the reading anywhere, the install and withdrawal only with SPECUS_ROUTE_MUTATION_TEST=1 as root,
// with lo0 standing in for the tunnel.

// The documentation prefix these tests install (RFC 3849); nothing real routes through it.
const macosTestPrefix6 = "2001:db8:5ec5::/48"

func TestMacosCommanderRefusesAMalformedIPv6PrefixBeforeRunningAnything(t *testing.T) {
	commander := newEgressRouteCommanderForPlatform("lo0")
	for _, cidr := range []string{"2001:DB8::/32", "2001:db8::/129", "2001:db8::1/32", "2001:db8::", "-inet6"} {
		route := egressRoute{CIDR: cidr, Kind: egressRouteToTun, Origin: "rule:" + cidr}
		if err := commander.Install(route); !errors.Is(err, errEgressRouteArgument) {
			t.Errorf("%q install error = %v, want the argument refusal", cidr, err)
		}
	}
}

// Every Mac has the IPv6 loopback in its table, read from `netstat -rn -f inet6`.
func TestMacosCommanderFindsTheIPv6LoopbackAsAConflict(t *testing.T) {
	commander := newEgressRouteCommanderForPlatform("utun99")
	present, existing := commander.Conflict(egressRoute{CIDR: "::1/128", Kind: egressRouteToTun, Origin: "rule:::1/128"})
	if !present || !strings.HasPrefix(existing, "::1/128 ") {
		t.Errorf("the IPv6 loopback: %v %q", present, existing)
	}
	if present, existing := commander.Conflict(egressRoute{CIDR: macosTestPrefix6, Kind: egressRouteToTun}); present {
		t.Errorf("%s was reported as taken by %q", macosTestPrefix6, existing)
	}
}

func TestMacosCommanderInstallsAndWithdrawsARealIPv6Route(t *testing.T) {
	commander := requireMacosMutation(t)
	route := egressRoute{CIDR: macosTestPrefix6, Kind: egressRouteToTun, Origin: "rule:" + macosTestPrefix6}
	if present, existing := commander.Conflict(route); present {
		t.Fatalf("%s is already in this machine's table: %s", route.CIDR, existing)
	}
	if err := commander.Install(route); err != nil {
		t.Fatalf("install: %v", err)
	}
	present, existing := commander.Conflict(route)
	if !present || !strings.Contains(existing, "netif lo0") {
		t.Errorf("after the install the table says %v %q", present, existing)
	}
	table, tunnel, err := commander.Table6()
	if err != nil {
		t.Fatalf("Table6: %v", err)
	}
	if drifts := egressRouteDrifts([]egressRoute{route}, table, tunnel); len(drifts) != 0 {
		t.Errorf("the installed route reads as drifted: %+v", drifts)
	}
	if err := commander.Remove(route); err != nil {
		t.Errorf("remove: %v", err)
	}
	if present, existing := commander.Conflict(route); present {
		t.Errorf("the route is still there after the removal: %q", existing)
	}
}
