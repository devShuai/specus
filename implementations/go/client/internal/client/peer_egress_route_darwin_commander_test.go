//go:build darwin

package client

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// The macOS routing table, driven for real.
//
// More of this runs than on the Windows side, where changing the table needs administrator rights
// and nothing but the query path could be exercised. Here the query path runs anywhere, the
// permission failure runs anywhere that is not root -- which is the more interesting half, because
// it is the one case where `route` fails and says so on stderr with nothing on stdout -- and the
// full install, verify and withdraw cycle runs wherever the caller asks for it.

// macosMutationEnv opts a run in to changing this machine's routing table.
//
// Gated rather than keyed on being root, because `sudo go test` should not quietly reroute the
// developer's machine. And once it is set, not being root is a failure rather than a skip: a run
// that was asked to exercise the install path and silently did not is worth less than no run.
const macosMutationEnv = "SPECUS_ROUTE_MUTATION_TEST"

// The prefix these tests install. Reserved for documentation by RFC 5737, so nothing real routes
// through it.
const macosTestPrefix = "203.0.113.0/24"

// An argument the builders would refuse has to be refused before a process starts.
//
// Asserted on the identity of the error rather than on how long the call took: `route` starts in
// about 3 ms, so elapsed time cannot tell a run that happened from one that did not.
func TestMacosCommanderRefusesAMalformedPrefixBeforeRunningAnything(t *testing.T) {
	commander := newEgressRouteCommanderForPlatform("lo0")
	for _, cidr := range []string{
		// The one that matters: `route` accepts this, prints a success line naming
		// 203.0.113.0, exits 0, and installs 128.0/1.
		"203.0.113.0/33",
		"203.0.113.0",
		"203.0.113.256/24",
		"010.0.113.0/24",
		"-net",
		"",
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

// A prefix that is certainly taken is reported as taken.
//
// Goes all the way to the operating system: it runs netstat, reads the whole table, normalises the
// destination column and finds the default route. Any machine with working networking has one, CI
// runners included; if this fails on a machine that has one, the reading is wrong rather than the
// assumption.
func TestMacosCommanderFindsTheDefaultRouteAsAConflict(t *testing.T) {
	commander := newEgressRouteCommanderForPlatform("lo0")
	present, existing := commander.Conflict(egressRoute{
		CIDR: "0.0.0.0/0", Kind: egressRouteToTun, Origin: "rule:0.0.0.0/0",
	})
	if !present {
		t.Fatal("the default route was not reported as a conflict")
	}
	if !strings.HasPrefix(existing, "0.0.0.0/0 ") {
		t.Errorf("conflict describes %q rather than the default route", existing)
	}
	if !strings.Contains(existing, "netif ") {
		t.Errorf("conflict description carries no interface: %q", existing)
	}
}

// And one nobody has is free, read from the same table.
func TestMacosCommanderReportsAnUnusedPrefixAsFree(t *testing.T) {
	commander := newEgressRouteCommanderForPlatform("lo0")
	present, existing := commander.Conflict(egressRoute{
		CIDR: macosTestPrefix, Kind: egressRouteToTun, Origin: "rule:" + macosTestPrefix,
	})
	if present {
		t.Errorf("%s was reported as taken by %q", macosTestPrefix, existing)
	}
}

// An install that cannot work reports that, rather than reporting success.
//
// The most useful thing here that needs no privileges. `route` answers a non-root caller with
// "must be root to alter routing table" on stderr, exit 77, and nothing at all on stdout -- so this
// exercises the real binary, the real streams and the real classification, and it is the one case
// where a classifier that read only stdout would call the failure a success.
func TestMacosCommanderReportsMissingRootRatherThanSucceeding(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, so a permission failure cannot be observed")
	}
	commander := newEgressRouteCommanderForPlatform("lo0")
	err := commander.Install(egressRoute{
		CIDR: macosTestPrefix, Kind: egressRouteToTun, Origin: "rule:" + macosTestPrefix,
	})
	if err == nil {
		t.Fatal("an install without root reported success")
	}
	if !strings.Contains(err.Error(), "needs root") {
		t.Errorf("install error = %v, want it to name the missing privilege", err)
	}
	// And the route is not there, which is the claim the error is making.
	if present, existing := commander.Conflict(egressRoute{CIDR: macosTestPrefix}); present {
		t.Errorf("%s was installed anyway: %s", macosTestPrefix, existing)
	}
}

// The whole cycle against the real table: free, installed, described, withdrawn, free again.
//
// Pointed at lo0 rather than at a tunnel. The argv is the one the feature uses for a rule's route,
// and lo0 is a real interface that accepts a route without an address being configured first --
// unlike a utun, which answers "Network is unreachable" until it has an IPv4 address.
func TestMacosCommanderInstallsAndWithdrawsARealRoute(t *testing.T) {
	commander := requireMacosMutation(t)
	route := egressRoute{CIDR: macosTestPrefix, Kind: egressRouteToTun,
		Origin: "rule:" + macosTestPrefix}

	if present, existing := commander.Conflict(route); present {
		t.Fatalf("%s is already in this machine's table: %s", macosTestPrefix, existing)
	}
	// Withdrawn even if an assertion below fails, so a failing run does not leave the machine
	// routing a prefix into the loopback.
	defer func() {
		if err := commander.Remove(route); err != nil {
			t.Errorf("cleanup of %s: %v", macosTestPrefix, err)
		}
	}()

	if err := commander.Install(route); err != nil {
		t.Fatalf("install %s: %v", macosTestPrefix, err)
	}
	// The second read of the table has to see it. Which is also the assertion that there is no
	// cache: the first read happened before the install, and a cached answer would still say
	// the prefix is free.
	present, existing := commander.Conflict(route)
	if !present {
		t.Fatalf("%s was installed but the table does not show it", macosTestPrefix)
	}
	if !strings.HasPrefix(existing, macosTestPrefix+" ") || !strings.Contains(existing, "lo0") {
		t.Errorf("the installed route is described as %q", existing)
	}

	if err := commander.Remove(route); err != nil {
		t.Fatalf("remove %s: %v", macosTestPrefix, err)
	}
	if present, existing := commander.Conflict(route); present {
		t.Errorf("%s survived its removal: %s", macosTestPrefix, existing)
	}
	// Withdrawing it again is not an error. `route` reports "not in table" and exits 0, and the
	// journal walked after a reboot is a list of prefixes that are all already gone.
	if err := commander.Remove(route); err != nil {
		t.Errorf("removing %s twice: %v", macosTestPrefix, err)
	}
}

// A bypass route, which is the other install form and the only one that reads `route -n get`.
//
// The next hop is resolved from the real table rather than supplied, so this is where the reading
// of "no gateway line means on-link" meets the machine.
func TestMacosCommanderInstallsABypassThroughTheRealNextHop(t *testing.T) {
	commander := requireMacosMutation(t)
	const address = "203.0.113.5/32"
	route := egressRoute{CIDR: address, Kind: egressRouteBypass, Origin: "bypass:" + address}

	if present, existing := commander.Conflict(route); present {
		t.Fatalf("%s is already in this machine's table: %s", address, existing)
	}
	defer func() {
		if err := commander.Remove(route); err != nil {
			t.Errorf("cleanup of %s: %v", address, err)
		}
	}()

	if err := commander.Install(route); err != nil {
		t.Fatalf("install bypass %s: %v", address, err)
	}
	if present, existing := commander.Conflict(route); !present {
		t.Errorf("the bypass for %s is not in the table", address)
	} else if !strings.HasPrefix(existing, "203.0.113.5/32 ") {
		t.Errorf("the bypass is described as %q", existing)
	}
}

func requireMacosMutation(t *testing.T) egressRouteCommander {
	t.Helper()
	if os.Getenv(macosMutationEnv) != "1" {
		t.Skipf("set %s=1 to let this change the machine's routing table", macosMutationEnv)
	}
	if os.Geteuid() != 0 {
		t.Fatalf("%s is set but this is not root, so the install path cannot be exercised",
			macosMutationEnv)
	}
	return newEgressRouteCommanderForPlatform("lo0")
}
