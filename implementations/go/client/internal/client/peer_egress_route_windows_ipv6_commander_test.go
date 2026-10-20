//go:build windows

package client

import (
	"errors"
	"strings"
	"testing"
)

// The IPv6 half of the Windows routing table, as far as it can be driven without administrator
// rights: the refusals before any process starts, and a real read of the IPv6 table.

func TestWindowsCommanderRefusesAnInjectedIPv6PrefixBeforeRunningAnything(t *testing.T) {
	commander := newEgressRouteCommanderForPlatform("specus0")
	for _, cidr := range []string{
		"2001:db8::/32';Remove-NetRoute -DestinationPrefix '::/0",
		"2001:DB8::/32", "2001:db8::/129", "2001:db8::1/32", "fe80::1%3/128",
	} {
		route := egressRoute{CIDR: cidr, Kind: egressRouteToTun, Origin: "rule:" + cidr}
		if err := commander.Install(route); !errors.Is(err, errEgressRouteArgument) {
			t.Errorf("%q install error = %v, want the argument refusal", cidr, err)
		}
		if err := commander.Remove(route); !errors.Is(err, errEgressRouteArgument) {
			t.Errorf("%q remove error = %v, want the argument refusal", cidr, err)
		}
	}
}

// Every Windows machine with an IPv6 stack routes multicast on-link: ff00::/8 is taken, read through
// PowerShell from the IPv6 table, with "::" read as on-link. A documentation prefix is free.
func TestWindowsCommanderReadsTheIPv6TableForConflicts(t *testing.T) {
	commander, ok := newEgressRouteCommanderForPlatform("specus0").(*windowsEgressRouteCommander)
	if !ok {
		t.Fatal("the Windows build did not produce the Windows commander")
	}
	present, existing := commander.Conflict(egressRoute{CIDR: "ff00::/8", Kind: egressRouteToTun, Origin: "rule:ff00::/8"})
	if !present {
		t.Skip("no ff00::/8 route: this machine has no IPv6 stack to read")
	}
	if !strings.HasPrefix(existing, "ff00::/8 on-link ifIndex ") {
		t.Errorf("conflict describes %q", existing)
	}
	readAt := commander.table6At
	if readAt.IsZero() || !commander.tableAt.IsZero() {
		t.Error("the IPv6 lookup did not use the IPv6 table alone")
	}
	if present, existing := commander.Conflict(egressRoute{CIDR: "2001:db8:ffff::/48", Kind: egressRouteToTun}); present {
		t.Errorf("2001:db8:ffff::/48 was reported as taken by %q", existing)
	}
	if !commander.table6At.Equal(readAt) {
		t.Error("the second IPv6 lookup read the table again")
	}
}
