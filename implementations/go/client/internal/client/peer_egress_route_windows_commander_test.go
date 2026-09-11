//go:build windows

package client

import (
	"errors"
	"strings"
	"testing"
)

// The Windows routing table, as far as it can be driven without administrator rights.
//
// Installing a route needs elevation, so the install path is not exercised here beyond the refusals
// that happen before a process starts. The query path is, all the way to the operating system.

// An argument the script builder would refuse must be refused before a process starts. A prefix
// carrying a quote is a second PowerShell command, and paying half a second to look up an interface
// index before rejecting it would be the wrong way round.
//
// Asserted on the identity of the error rather than on how long the call took. Elapsed time cannot
// tell these apart: a second PowerShell process starts in well under the 175 ms the first one costs
// once its module is warm, so a run that happened can look exactly like one that did not.
func TestWindowsCommanderRefusesAnInjectedPrefixBeforeRunningAnything(t *testing.T) {
	commander := newEgressRouteCommanderForPlatform("specus0")
	injected := egressRoute{
		CIDR:   "10.0.0.0/8';Remove-NetRoute -DestinationPrefix '0.0.0.0/0",
		Kind:   egressRouteToTun,
		Origin: "rule:injected",
	}

	if err := commander.Install(injected); !errors.Is(err, errEgressRouteArgument) {
		t.Errorf("install error = %v, want the argument refusal", err)
	}
	if err := commander.Remove(injected); !errors.Is(err, errEgressRouteArgument) {
		t.Errorf("remove error = %v, want the argument refusal", err)
	}
}

func TestWindowsCommanderRefusesAMalformedPrefix(t *testing.T) {
	commander := newEgressRouteCommanderForPlatform("specus0")
	for _, cidr := range []string{"10.0.0.0", "10.0.0.0/33", "10.0.0.256/24", ""} {
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
// The one test here that goes all the way to the operating system: it starts PowerShell, reads the
// whole routing table, parses it and finds the default route. Any machine with working networking
// has one, CI runners included; if this fails on a machine that has one, the reading is wrong
// rather than the assumption.
func TestWindowsCommanderFindsTheDefaultRouteAsAConflict(t *testing.T) {
	commander := newEgressRouteCommanderForPlatform("specus0")
	present, existing := commander.Conflict(egressRoute{
		CIDR: "0.0.0.0/0", Kind: egressRouteToTun, Origin: "rule:0.0.0.0/0",
	})
	if !present {
		t.Fatal("the default route was not reported as a conflict")
	}
	if !strings.HasPrefix(existing, "0.0.0.0/0 ") {
		t.Errorf("conflict describes %q rather than the default route", existing)
	}
	if !strings.Contains(existing, "ifIndex ") {
		t.Errorf("conflict description carries no interface index: %q", existing)
	}
}

// A prefix nobody has is free, read from the same table.
func TestWindowsCommanderReportsAnUnusedPrefixAsFree(t *testing.T) {
	commander := newEgressRouteCommanderForPlatform("specus0")
	present, existing := commander.Conflict(egressRoute{
		CIDR: "203.0.113.0/24", Kind: egressRouteToTun, Origin: "rule:203.0.113.0/24",
	})
	if present {
		t.Errorf("203.0.113.0/24 was reported as taken by %q", existing)
	}
}

// The table is read once and then answers for a while.
//
// Without the cache every prefix in a plan would cost its own 419 ms read. Asserted on the
// timestamp the commander stamps the cache with, not on how long the second call took: two reads in
// a row are fast enough to be indistinguishable from one, which an earlier version of this test
// found out by passing with the cache switched off.
func TestWindowsCommanderCachesOneReadOfTheTable(t *testing.T) {
	commander, ok := newEgressRouteCommanderForPlatform("specus0").(*windowsEgressRouteCommander)
	if !ok {
		t.Fatal("the Windows build did not produce the Windows commander")
	}
	first := egressRoute{CIDR: "0.0.0.0/0", Kind: egressRouteToTun, Origin: "rule:first"}
	if present, _ := commander.Conflict(first); !present {
		t.Fatal("the first read found no default route")
	}
	readAt := commander.tableAt
	if readAt.IsZero() {
		t.Fatal("the first lookup did not record when it read the table")
	}

	second := egressRoute{CIDR: "127.0.0.1/32", Kind: egressRouteToTun, Origin: "rule:second"}
	if present, _ := commander.Conflict(second); !present {
		t.Error("the loopback route was not found in the cached table")
	}
	if !commander.tableAt.Equal(readAt) {
		t.Error("the second lookup read the table again instead of using the cached one")
	}
}
