//go:build linux

package client

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

// The Linux routing table itself, in a network namespace built for the test.
//
// These change the routing table and create devices, so they run only with
// SPECUS_ROUTE_MUTATION_TEST=1, and only in a namespace whose IPv4 main table is empty when they
// start -- which a fresh `unshare -n` is and no machine with networking is. Anywhere else they
// skip rather than rearrange the host's routes. CI runs them as
// `sudo unshare -n env SPECUS_ROUTE_MUTATION_TEST=1 client.test -test.run TestLinuxCommander`.

// linuxMutationSetup builds the namespace once per process; later tests reuse what it built.
var (
	linuxMutationSetup     sync.Once
	linuxMutationSkip      string
	linuxMutationSetupFail string
)

func linuxMutationNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv("SPECUS_ROUTE_MUTATION_TEST") != "1" {
		t.Skip("set SPECUS_ROUTE_MUTATION_TEST=1 and run inside `unshare -n` to let this build its own routing table")
	}
	linuxMutationSetup.Do(buildLinuxMutationNamespace)
	if linuxMutationSetupFail != "" {
		t.Fatal(linuxMutationSetupFail)
	}
	if linuxMutationSkip != "" {
		t.Skip(linuxMutationSkip)
	}
}

func buildLinuxMutationNamespace() {
	table, err := exec.Command("ip", "-4", "route", "show", "table", "main").CombinedOutput()
	if err != nil {
		linuxMutationSetupFail = "read the main table: " + err.Error() + ": " + string(table)
		return
	}
	if strings.TrimSpace(string(table)) != "" {
		linuxMutationSkip = "the main table is not empty, so this is not a namespace made for the test"
		return
	}
	for _, step := range [][]string{
		{"ip", "link", "set", "lo", "up"},
		{"ip", "link", "add", "eth0", "type", "dummy"},
		{"ip", "link", "set", "eth0", "up"},
		{"ip", "addr", "add", "192.168.64.7/24", "dev", "eth0"},
		{"ip", "route", "add", "default", "via", "192.168.64.1", "dev", "eth0"},
		{"ip", "tuntap", "add", "dev", "specus0", "mode", "tun"},
		{"ip", "link", "set", "specus0", "up"},
		{"ip", "addr", "add", "100.96.0.5/11", "dev", "specus0"},
		{"ip", "route", "add", "blackhole", "192.0.2.0/24"},
	} {
		if output, err := exec.Command(step[0], step[1:]...).CombinedOutput(); err != nil {
			linuxMutationSetupFail = strings.Join(step, " ") + ": " + err.Error() + ": " + string(output)
			return
		}
	}
}

func linuxRouteOutput(t *testing.T, args ...string) string {
	t.Helper()
	output, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

// A bypass for an address a rule has already routed into the tunnel goes out the physical gateway.
//
// This is the order a running consumer meets: the rule's route is in the table, and a peer or a
// relay turns up later at an address it covers. `ip route get` can then only answer with the
// tunnel -- asserted first, so the test cannot pass by never reaching the fallback -- and the bypass
// has to come from the table with the tunnel left out.
func TestLinuxCommanderInstallsABypassUnderItsOwnTunnelRoute(t *testing.T) {
	linuxMutationNamespace(t)
	commander := newLinuxEgressRouteCommander("specus0")
	rule := egressRoute{CIDR: "203.0.113.0/24", Kind: egressRouteToTun, Origin: "rule:203.0.113.0/24"}
	bypass := egressRoute{CIDR: "203.0.113.9/32", Kind: egressRouteBypass, Origin: "bypass"}

	if err := commander.Install(rule); err != nil {
		t.Fatalf("install the rule's route: %v", err)
	}
	if hop, ok := parseIPRouteGet(linuxRouteOutput(t, "route", "get", "203.0.113.9")); !ok || hop.Device != "specus0" {
		t.Fatalf("precondition: ip route get answered %+v (ok=%v), want the tunnel", hop, ok)
	}

	if err := commander.Install(bypass); err != nil {
		t.Fatalf("install the bypass: %v", err)
	}
	installed := linuxRouteOutput(t, "route", "show", "exact", "203.0.113.9/32")
	if !strings.Contains(installed, "via 192.168.64.1 dev eth0") {
		t.Errorf("bypass is %q, want via 192.168.64.1 dev eth0", strings.TrimSpace(installed))
	}
	if hop, ok := parseIPRouteGet(linuxRouteOutput(t, "route", "get", "203.0.113.9")); !ok || hop.Device != "eth0" {
		t.Errorf("after the bypass ip route get answers %+v, want eth0", hop)
	}

	if err := commander.Remove(bypass); err != nil {
		t.Errorf("remove the bypass: %v", err)
	}
	if err := commander.Remove(rule); err != nil {
		t.Errorf("remove the rule's route: %v", err)
	}
	if left := linuxRouteOutput(t, "route", "show", "exact", "203.0.113.9/32") +
		linuxRouteOutput(t, "route", "show", "exact", "203.0.113.0/24"); strings.TrimSpace(left) != "" {
		t.Errorf("routes left behind: %q", left)
	}
}

// Routes the kernel dropped -- as it does with every route through an interface that goes down --
// are found by reading the real table and put back through the real commands.
func TestLinuxCommanderRepairsARouteTheTableLost(t *testing.T) {
	linuxMutationNamespace(t)
	installer := newEgressRouteInstaller(newLinuxEgressRouteCommander("specus0"), journalPath(t))
	rule := egressRoute{CIDR: "203.0.113.0/24", Kind: egressRouteToTun, Origin: "rule:203.0.113.0/24"}
	bypass := egressRoute{CIDR: "203.0.113.9/32", Kind: egressRouteBypass, Origin: "bypass"}
	if result := installer.apply([]egressRoute{bypass, rule}); result.Err != nil || len(result.Added) != 2 {
		t.Fatalf("apply: %+v", result)
	}
	defer installer.withdrawAll()

	if healthy := installer.repair(); healthy.TableErr != nil || len(healthy.Repaired) != 0 {
		t.Fatalf("a table with everything in it: %+v", healthy)
	}
	linuxRouteOutput(t, "route", "del", "203.0.113.0/24")
	linuxRouteOutput(t, "route", "del", "203.0.113.9/32")

	result := installer.repair()
	if result.TableErr != nil || result.Err != nil || len(result.Repaired) != 2 || len(result.Lost) != 0 {
		t.Fatalf("repair: %+v", result)
	}
	if got := linuxRouteOutput(t, "route", "show", "exact", "203.0.113.0/24"); !strings.Contains(got, "dev specus0") {
		t.Errorf("the rule's route is %q after the repair, want it back in the tunnel", strings.TrimSpace(got))
	}
	if got := linuxRouteOutput(t, "route", "show", "exact", "203.0.113.9/32"); !strings.Contains(got, "via 192.168.64.1 dev eth0") {
		t.Errorf("the bypass is %q after the repair, want it back via the gateway", strings.TrimSpace(got))
	}
	if again := installer.repair(); len(again.Repaired) != 0 {
		t.Errorf("a second repair found more to do: %+v", again)
	}
}

// When the only route past the tunnel is a blackhole, the bypass is refused rather than pinned
// through the default route the blackhole deliberately overrides.
func TestLinuxCommanderRefusesABypassOnlyABlackholeWouldCarry(t *testing.T) {
	linuxMutationNamespace(t)
	commander := newLinuxEgressRouteCommander("specus0")
	rule := egressRoute{CIDR: "192.0.2.0/25", Kind: egressRouteToTun, Origin: "rule:192.0.2.0/25"}
	if err := commander.Install(rule); err != nil {
		t.Fatalf("install the rule's route: %v", err)
	}
	defer func() { _ = commander.Remove(rule) }()

	err := commander.Install(egressRoute{CIDR: "192.0.2.9/32", Kind: egressRouteBypass, Origin: "bypass"})
	if !errors.Is(err, errEgressNoPhysicalRoute) {
		t.Fatalf("install error = %v, want the no-physical-route refusal", err)
	}
	if left := linuxRouteOutput(t, "route", "show", "exact", "192.0.2.9/32"); strings.TrimSpace(left) != "" {
		t.Errorf("a bypass was installed anyway: %q", left)
	}
}
