package client

import (
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// Putting back what the routing table lost.
//
// The comparison is pinned by the shared vector; what is argued here is what the installer does
// with it -- which routes are taken out and put back, which are given up as somebody else's, and
// what happens to the journal in each case -- and that the mesh's tick runs it and backs off.

// loadEgressBindTables reads every sampled table in the vector as this runtime parses it.
func loadEgressBindTables(t *testing.T, vector egressBindVector) map[string]map[string][]egressBindRoute {
	t.Helper()
	tables := map[string]map[string][]egressBindRoute{"linux": {}, "macos": {}, "windows": {}}
	for name, text := range vector.Linux.Tables {
		tables["linux"][name] = parseIPRouteTable(text)
	}
	for name, text := range vector.Macos.Tables {
		tables["macos"][name] = macosBindRoutes(text)
	}
	var forward []windowsForwardRow
	var interfaces []windowsInterfaceRow
	for _, table := range vector.Windows.ForwardTables {
		if table.Name == vector.Windows.Routes.Forward {
			raw, _ := hex.DecodeString(table.Hex)
			forward, _ = parseWindowsForwardTable(raw)
		}
	}
	for _, table := range vector.Windows.InterfaceTables {
		if table.Name == vector.Windows.Routes.Interfaces {
			raw, _ := hex.DecodeString(table.Hex)
			interfaces, _ = parseWindowsInterfaceTable(raw)
		}
	}
	tables["windows"]["typical"] = windowsBindRoutes(forward, interfaces)
	return tables
}

func TestEgressRouteDriftVectors(t *testing.T) {
	vector := loadEgressBindVector(t)
	tables := loadEgressBindTables(t, vector)
	if len(vector.Drift.Cases) == 0 {
		t.Fatal("no drift cases")
	}
	for _, c := range vector.Drift.Cases {
		routes := tables[c.Platform][c.Table]
		if c.Platform == "inline" {
			routes = egressBindRoutesFromVector(c.Routes)
		}
		owned := make([]egressRoute, 0, len(c.Owned))
		for _, entry := range c.Owned {
			kind := egressRouteToTun
			if entry.Kind == "bypass" {
				kind = egressRouteBypass
			}
			owned = append(owned, egressRoute{CIDR: entry.CIDR, Kind: kind})
		}
		found := egressRouteDrifts(owned, routes, c.Tunnel)
		if len(found) != len(c.Expect) {
			t.Errorf("%s: found %+v, want %+v", c.Name, found, c.Expect)
			continue
		}
		for index, want := range c.Expect {
			got := found[index]
			if got.Route.CIDR != want.CIDR || string(got.Reason) != want.Reason || string(got.Action) != want.Action {
				t.Errorf("%s: drift %d = %s %s %s, want %s %s %s", c.Name, index,
					got.Route.CIDR, got.Reason, got.Action, want.CIDR, want.Reason, want.Action)
			}
		}
	}
}

// A bypass being put back after a network change has its stale row still in the table, naming the
// old gateway. It must not win the lookup for its own address.
func TestEgressBypassHopFromTableLeavesItsOwnRouteOut(t *testing.T) {
	read := func() ([]egressBindRoute, error) {
		return []egressBindRoute{
			{Prefix: "0.0.0.0/0", Interface: "wlan0", Gateway: "10.0.0.1", Metric: 600, Usable: true},
			{Prefix: "198.51.100.7/32", Interface: "eth0", Gateway: "192.168.64.1", Usable: true},
		}, nil
	}
	hop, err := egressBypassHopFromTable("198.51.100.7", "specus0", read)
	if err != nil || hop.Interface != "wlan0" || hop.Gateway != "10.0.0.1" {
		t.Fatalf("hop = %+v, %v; want wlan0 via 10.0.0.1, not the stale /32", hop, err)
	}
}

func repairFixture(t *testing.T) (*egressRouteInstaller, *fakeRouteCommander, string) {
	t.Helper()
	commander := newFakeRouteCommander()
	path := journalPath(t)
	installer := newEgressRouteInstaller(commander, path)
	result := installer.apply([]egressRoute{
		{CIDR: "203.0.113.7/32", Kind: egressRouteBypass, Origin: "bypass"},
		{CIDR: "203.0.113.0/24", Kind: egressRouteToTun, Origin: "rule:203.0.113.0/24"},
	})
	if result.Err != nil || len(result.Added) != 2 {
		t.Fatalf("apply: %+v", result)
	}
	return installer, commander, path
}

func countOf(list []string, want string) int {
	count := 0
	for _, entry := range list {
		if entry == want {
			count++
		}
	}
	return count
}

// A healthy table costs nothing: no removals, no installs, no conflict queries.
func TestEgressRouteInstallerRepairLeavesAHealthyTableAlone(t *testing.T) {
	installer, commander, _ := repairFixture(t)
	installs, queries := len(commander.installLog), len(commander.conflictLog)

	result := installer.repair()
	if result.TableErr != nil || result.Err != nil || len(result.Repaired) != 0 || len(result.Lost) != 0 {
		t.Fatalf("repair of a healthy table: %+v", result)
	}
	if len(commander.installLog) != installs || len(commander.conflictLog) != queries || len(commander.removeLog) != 0 {
		t.Errorf("a healthy table was touched: installs=%v removes=%v queries=%v",
			commander.installLog, commander.removeLog, commander.conflictLog)
	}
}

// A route the kernel dropped is put back, and stays in the journal throughout.
func TestEgressRouteInstallerPutsBackARouteTheTableLost(t *testing.T) {
	installer, commander, _ := repairFixture(t)
	commander.lose("203.0.113.0/24")

	result := installer.repair()
	if result.Err != nil || len(result.Repaired) != 1 || result.Repaired[0].Reason != egressDriftMissing {
		t.Fatalf("repair: %+v", result)
	}
	if countOf(commander.installLog, "203.0.113.0/24") != 2 {
		t.Errorf("installs = %v, want the route installed a second time", commander.installLog)
	}
	if !installer.owns("203.0.113.0/24") {
		t.Error("the route left the journal while it was being put back")
	}
	if again := installer.repair(); len(again.Repaired) != 0 {
		t.Errorf("a second repair found more to do: %+v", again)
	}
}

// Back from sleep on another network: the bypass still names the old gateway, so it is moved to
// the new one. The tunnel route, which did not move, is not touched.
func TestEgressRouteInstallerMovesABypassToTheNewGateway(t *testing.T) {
	installer, commander, _ := repairFixture(t)
	commander.physical = []egressBindRoute{
		{Prefix: "0.0.0.0/0", Interface: "wlan0", Gateway: "10.0.0.1", Metric: 600, Usable: true},
	}

	result := installer.repair()
	if result.Err != nil || len(result.Repaired) != 1 || result.Repaired[0].Reason != egressDriftMoved ||
		result.Repaired[0].Route.CIDR != "203.0.113.7/32" {
		t.Fatalf("repair: %+v", result)
	}
	if countOf(commander.removeLog, "203.0.113.7/32") != 1 || countOf(commander.removeLog, "203.0.113.0/24") != 0 {
		t.Errorf("removes = %v, want only the bypass taken out", commander.removeLog)
	}
	if hop := commander.hops["203.0.113.7/32"]; hop.Interface != "wlan0" || hop.Gateway != "10.0.0.1" {
		t.Errorf("the bypass now points at %+v, want wlan0 via 10.0.0.1", hop)
	}
	if again := installer.repair(); len(again.Repaired) != 0 {
		t.Errorf("a second repair found more to do: %+v", again)
	}
}

// A prefix somebody else took while ours was gone is theirs: reported, dropped from the journal,
// and not installed over.
func TestEgressRouteInstallerGivesUpAPrefixSomebodyElseTook(t *testing.T) {
	installer, commander, path := repairFixture(t)
	const existing = "203.0.113.0/24 via 192.0.2.1 dev eth0"
	commander.lose("203.0.113.0/24")
	commander.physical = append(commander.physical,
		egressBindRoute{Prefix: "203.0.113.0/24", Interface: "eth0", Gateway: "192.0.2.1", Usable: true})
	commander.foreign["203.0.113.0/24"] = existing
	installs := len(commander.installLog)

	result := installer.repair()
	if result.Err != nil || len(result.Repaired) != 0 || len(result.Lost) != 1 {
		t.Fatalf("repair: %+v", result)
	}
	if result.Lost[0].Route.CIDR != "203.0.113.0/24" || result.Lost[0].Existing != existing {
		t.Errorf("lost = %+v", result.Lost[0])
	}
	if len(commander.installLog) != installs || countOf(commander.removeLog, "203.0.113.0/24") != 0 {
		t.Errorf("the other route was touched: installs=%v removes=%v", commander.installLog, commander.removeLog)
	}
	if installer.owns("203.0.113.0/24") {
		t.Error("a prefix somebody else holds is still in the journal")
	}
	journal, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(journal), "203.0.113.0/24") {
		t.Errorf("the journal on disk still lists the prefix: %s (%v)", journal, err)
	}
}

// A reinstall that fails keeps the route owned, so the next repair tries again.
func TestEgressRouteInstallerKeepsARouteItCouldNotPutBack(t *testing.T) {
	installer, commander, _ := repairFixture(t)
	commander.lose("203.0.113.0/24")
	commander.installErr["203.0.113.0/24"] = errors.New("permission denied")

	result := installer.repair()
	if result.Err == nil || len(result.Repaired) != 0 {
		t.Fatalf("repair: %+v", result)
	}
	if !installer.owns("203.0.113.0/24") {
		t.Fatal("a route that could not be put back was dropped from the journal")
	}

	delete(commander.installErr, "203.0.113.0/24")
	if again := installer.repair(); again.Err != nil || len(again.Repaired) != 1 {
		t.Errorf("the retry: %+v", again)
	}
}

func TestEgressRouteInstallerReportsAnUnreadableTable(t *testing.T) {
	installer, commander, _ := repairFixture(t)
	commander.tableErr = errors.New("ip: not found")

	result := installer.repair()
	if result.TableErr == nil || len(result.Repaired) != 0 || len(result.Lost) != 0 {
		t.Fatalf("repair: %+v", result)
	}
}

// The tick puts routes back, and backs off when it cannot.
func TestMeshReconcilePutsBackRoutesTheTableLost(t *testing.T) {
	harness := newReconcileHarness(t,
		egressRule{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2})
	harness.tick(0)
	applied := harness.appliedAt()

	harness.commander.lose("203.0.113.0/24")
	harness.tick(5 * time.Second)
	if countOf(harness.commander.installLog, "203.0.113.0/24") != 2 {
		t.Fatalf("installs = %v, want the route put back on the tick", harness.commander.installLog)
	}
	if harness.appliedAt() != applied {
		t.Error("putting a route back counted as applying the plan")
	}

	harness.commander.lose("203.0.113.0/24")
	harness.commander.installErr["203.0.113.0/24"] = errors.New("permission denied")
	harness.tick(5 * time.Second)
	attempts := len(harness.commander.installLog)
	harness.tick(5 * time.Second)
	if len(harness.commander.installLog) != attempts {
		t.Error("a failed reinstall was retried on the next tick rather than after the interval")
	}
	delete(harness.commander.installErr, "203.0.113.0/24")
	harness.tick(egressRouteRetryInterval)
	if _, present := harness.commander.table["203.0.113.0/24"]; !present {
		t.Error("the route was not put back once the interval had passed")
	}
}

// A prefix another route took shows in the status as not installed, and the plan asks for it
// again after the interval.
func TestMeshReconcileReportsAPrefixLostToAnotherRoute(t *testing.T) {
	harness := newReconcileHarness(t,
		egressRule{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2})
	harness.tick(0)

	const existing = "203.0.113.0/24 via 192.0.2.1 dev eth0"
	harness.commander.lose("203.0.113.0/24")
	harness.commander.physical = append(harness.commander.physical,
		egressBindRoute{Prefix: "203.0.113.0/24", Interface: "eth0", Gateway: "192.0.2.1", Usable: true})
	harness.commander.foreign["203.0.113.0/24"] = existing
	harness.tick(5 * time.Second)

	section := mapSection(t, harness.mesh.egressStatusJSON(), "consumer")
	var reported map[string]any
	for _, route := range section["routes"].([]map[string]any) {
		if route["cidr"] == "203.0.113.0/24" {
			reported = route
		}
	}
	if reported == nil || reported["installed"] != false || reported["conflict"] != existing {
		t.Fatalf("status reports %v, want the prefix as not installed with what holds it", reported)
	}

	// The other route goes away; the plan, marked troubled, asks again after the interval.
	harness.commander.physical = harness.commander.physical[:1]
	delete(harness.commander.foreign, "203.0.113.0/24")
	harness.tick(5 * time.Second)
	if _, present := harness.commander.table["203.0.113.0/24"]; present {
		t.Fatal("the prefix was reinstalled before the interval")
	}
	harness.tick(egressRouteRetryInterval)
	if _, present := harness.commander.table["203.0.113.0/24"]; !present {
		t.Error("the prefix was not asked for again after the interval")
	}
}
