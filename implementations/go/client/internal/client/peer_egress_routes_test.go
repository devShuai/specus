package client

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Route planning and installation.
//
// The routing table is injected, so the paths that matter here -- a failed install halfway through,
// a prefix somebody else already owns, a journal left by a process that was killed -- are driven
// deterministically instead of waiting for a machine to be in the wrong state.

type fakeRouteCommander struct {
	table      map[string]egressRoute
	foreign    map[string]string
	installErr map[string]error
	removeErr  map[string]error
	installLog []string
	removeLog  []string
}

func newFakeRouteCommander() *fakeRouteCommander {
	return &fakeRouteCommander{
		table:      map[string]egressRoute{},
		foreign:    map[string]string{},
		installErr: map[string]error{},
		removeErr:  map[string]error{},
	}
}

func (c *fakeRouteCommander) Conflict(route egressRoute) (bool, string) {
	existing, ok := c.foreign[route.CIDR]
	return ok, existing
}

func (c *fakeRouteCommander) Install(route egressRoute) error {
	if err := c.installErr[route.CIDR]; err != nil {
		return err
	}
	c.table[route.CIDR] = route
	c.installLog = append(c.installLog, route.CIDR)
	return nil
}

func (c *fakeRouteCommander) Remove(route egressRoute) error {
	if err := c.removeErr[route.CIDR]; err != nil {
		return err
	}
	delete(c.table, route.CIDR)
	c.removeLog = append(c.removeLog, route.CIDR)
	return nil
}

func journalPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "egress-routes.json")
}

func egressTestRules() []egressRule {
	return []egressRule{
		{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2},
		{Match: "198.51.100.0/24", Action: egressActionDirect},
		{Match: "192.0.2.0/24", Action: egressActionBlock},
	}
}

// A direct rule installs nothing: traffic stays local by having no route, the same mechanism that
// makes unmatched traffic local. A block rule does install one, because the packet has to be
// captured before it can be dropped.
func TestEgressRoutePlanCoversEgressAndBlockButNotDirect(t *testing.T) {
	routes, refused := planEgressRoutes(egressTestRules(), nil, egressDefaultMeshCIDR)
	if len(refused) != 0 {
		t.Fatalf("valid rules were refused: %+v", refused)
	}
	byCIDR := map[string]egressRouteKind{}
	for _, route := range routes {
		byCIDR[route.CIDR] = route.Kind
	}
	if _, ok := byCIDR["203.0.113.0/24"]; !ok {
		t.Error("an egress rule installed no route")
	}
	if _, ok := byCIDR["192.0.2.0/24"]; !ok {
		t.Error("a block rule installed no route, so the packet could never be captured to drop it")
	}
	if _, ok := byCIDR["198.51.100.0/24"]; ok {
		t.Error("a direct rule installed a route")
	}
}

// The default route is never taken, and neither is the half-route pair that covers it while
// pretending not to.
func TestEgressRoutePlanNeverTakesTheDefaultRoute(t *testing.T) {
	routes, refused := planEgressRoutes([]egressRule{
		{Match: "0.0.0.0/0", Action: egressActionEgress, EgressClientID: 2},
	}, nil, egressDefaultMeshCIDR)
	if len(routes) != 0 {
		t.Errorf("a default route was planned: %+v", routes)
	}
	if len(refused) != 1 || refused[0].Code != egressCodeRuleDefaultRoute {
		t.Errorf("refusals = %+v", refused)
	}
	// The halves are ordinary prefixes as far as validation goes, so nothing refuses them; what
	// this asserts is that the planner never invents them on its own.
	planned, _ := planEgressRoutes(egressTestRules(), nil, egressDefaultMeshCIDR)
	for _, route := range planned {
		if route.CIDR == "0.0.0.0/1" || route.CIDR == "128.0.0.0/1" {
			t.Errorf("the planner produced a half-route: %s", route.CIDR)
		}
	}
}

// The addresses that carry the tunnel have to be in place before anything is pointed into it.
func TestEgressRoutePlanPutsBypassFirst(t *testing.T) {
	routes, _ := planEgressRoutes(egressTestRules(),
		[]string{"198.51.100.7", "192.0.2.99", "not-an-address"}, egressDefaultMeshCIDR)

	if len(routes) < 2 {
		t.Fatalf("planned %d routes", len(routes))
	}
	var bypassSeen, tunSeen int
	for _, route := range routes {
		if route.Kind == egressRouteBypass {
			if tunSeen > 0 {
				t.Error("a bypass route was ordered after a tunnel route")
			}
			bypassSeen++
			if route.CIDR != "198.51.100.7/32" && route.CIDR != "192.0.2.99/32" {
				t.Errorf("unexpected bypass route %s", route.CIDR)
			}
		} else {
			tunSeen++
		}
	}
	if bypassSeen != 2 {
		t.Errorf("planned %d bypass routes, want 2 with the unparseable one skipped", bypassSeen)
	}
}

// A bypass address inside a rule's prefix must keep its own /32, or the tunnel would be routing the
// transport that carries it.
func TestEgressRoutePlanKeepsBypassInsideACapturedPrefix(t *testing.T) {
	routes, _ := planEgressRoutes([]egressRule{
		{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2},
	}, []string{"203.0.113.7"}, egressDefaultMeshCIDR)

	var bypass, tun bool
	for _, route := range routes {
		if route.CIDR == "203.0.113.7/32" && route.Kind == egressRouteBypass {
			bypass = true
		}
		if route.CIDR == "203.0.113.0/24" && route.Kind == egressRouteToTun {
			tun = true
		}
	}
	if !bypass {
		t.Error("the bypass address lost its /32 to the covering rule")
	}
	if !tun {
		t.Error("the covering rule lost its route to the bypass address")
	}
}

func TestEgressRouteInstallerAppliesAndWithdraws(t *testing.T) {
	commander := newFakeRouteCommander()
	installer := newEgressRouteInstaller(commander, journalPath(t))

	routes, _ := planEgressRoutes(egressTestRules(), []string{"198.51.100.7"}, egressDefaultMeshCIDR)
	result := installer.apply(routes)
	if result.Err != nil || result.RolledBack {
		t.Fatalf("apply failed: %v rolledBack=%v", result.Err, result.RolledBack)
	}
	if len(result.Added) != 3 || len(commander.table) != 3 {
		t.Fatalf("added %d, table has %d", len(result.Added), len(commander.table))
	}

	// Applying the same plan again is a no-op rather than a reinstall.
	repeat := installer.apply(routes)
	if len(repeat.Added) != 0 || len(repeat.Removed) != 0 {
		t.Errorf("a repeated apply changed %d/%d routes", len(repeat.Added), len(repeat.Removed))
	}

	withdrawn := installer.withdrawAll()
	if len(withdrawn) != 3 || len(commander.table) != 0 {
		t.Errorf("withdrew %d, table still has %d", len(withdrawn), len(commander.table))
	}
}

// A failure halfway through a rule set must not leave the machine routing some traffic into a
// tunnel that was never finished being set up.
func TestEgressRouteInstallerRollsBackAPartialInstall(t *testing.T) {
	commander := newFakeRouteCommander()
	commander.installErr["192.0.2.0/24"] = errors.New("permission denied")
	installer := newEgressRouteInstaller(commander, journalPath(t))

	routes, _ := planEgressRoutes(egressTestRules(), []string{"198.51.100.7"}, egressDefaultMeshCIDR)
	result := installer.apply(routes)

	if !result.RolledBack || result.Err == nil {
		t.Fatalf("a failed install was not rolled back: %+v", result)
	}
	if len(commander.table) != 0 {
		t.Errorf("%d routes survived the rollback: %v", len(commander.table), commander.table)
	}
	if len(result.Added) != 0 {
		t.Errorf("the result still reported %d additions", len(result.Added))
	}
	if len(installer.installed) != 0 {
		t.Errorf("the journal still claims %d routes", len(installer.installed))
	}
}

// A failure now is not a reason to tear down a configuration that was working a minute ago.
func TestEgressRouteInstallerRollbackSparesEarlierRoutes(t *testing.T) {
	commander := newFakeRouteCommander()
	installer := newEgressRouteInstaller(commander, journalPath(t))

	first, _ := planEgressRoutes([]egressRule{
		{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2},
	}, nil, egressDefaultMeshCIDR)
	if result := installer.apply(first); result.Err != nil {
		t.Fatalf("first apply failed: %v", result.Err)
	}

	commander.installErr["192.0.2.0/24"] = errors.New("permission denied")
	second, _ := planEgressRoutes(egressTestRules(), nil, egressDefaultMeshCIDR)
	result := installer.apply(second)

	if !result.RolledBack {
		t.Fatal("the second apply was not rolled back")
	}
	if _, kept := commander.table["203.0.113.0/24"]; !kept {
		t.Error("a route from the earlier call was torn down by a later failure")
	}
	if !installer.owns("203.0.113.0/24") {
		t.Error("the journal lost the earlier route")
	}
}

// Phase one does not preempt and does not compare metrics. One contested prefix is refused and
// reported; every other rule still takes effect.
func TestEgressRouteInstallerRefusesConflictsAndKeepsGoing(t *testing.T) {
	commander := newFakeRouteCommander()
	commander.foreign["192.0.2.0/24"] = "192.0.2.0/24 via 10.0.0.1 dev eth0"
	installer := newEgressRouteInstaller(commander, journalPath(t))

	routes, _ := planEgressRoutes(egressTestRules(), nil, egressDefaultMeshCIDR)
	result := installer.apply(routes)

	if result.RolledBack {
		t.Fatal("a conflict rolled back the whole plan")
	}
	if len(result.Conflicts) != 1 || result.Conflicts[0].Route.CIDR != "192.0.2.0/24" {
		t.Fatalf("conflicts = %+v", result.Conflicts)
	}
	if result.Conflicts[0].Existing == "" {
		t.Error("the conflict carried no description of what is already there")
	}
	if _, installed := commander.table["203.0.113.0/24"]; !installed {
		t.Error("an unrelated rule was dropped because another prefix was contested")
	}
	if installer.owns("192.0.2.0/24") {
		t.Error("a refused prefix was recorded as ours")
	}
}

// A process that was killed leaves routes behind. The next run has to take back exactly its own.
func TestEgressRouteInstallerWithdrawsAJournalFromAPreviousRun(t *testing.T) {
	path := journalPath(t)
	commander := newFakeRouteCommander()

	previous := newEgressRouteInstaller(commander, path)
	routes, _ := planEgressRoutes(egressTestRules(), []string{"198.51.100.7"}, egressDefaultMeshCIDR)
	if result := previous.apply(routes); result.Err != nil {
		t.Fatalf("apply failed: %v", result.Err)
	}
	// Something the user installed, which the journal never mentions.
	commander.table["10.0.0.0/8"] = egressRoute{CIDR: "10.0.0.0/8"}

	restarted := newEgressRouteInstaller(commander, path)
	if err := restarted.load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(restarted.installed) != 3 {
		t.Fatalf("recovered %d routes, want 3", len(restarted.installed))
	}
	restarted.withdrawAll()

	if _, kept := commander.table["10.0.0.0/8"]; !kept {
		t.Error("a route this feature never installed was withdrawn")
	}
	if len(commander.table) != 1 {
		t.Errorf("%d routes left, want only the foreign one", len(commander.table))
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("the journal survived a full withdrawal")
	}
}

// A journal written by a version that recorded entries differently cannot be trusted to describe
// what is installed, and acting on it would mean removing prefixes by guess.
func TestEgressRouteJournalRefusesAnUnknownVersion(t *testing.T) {
	path := journalPath(t)
	raw, err := json.Marshal(map[string]any{
		"version": egressRouteJournalVersion + 1,
		"routes":  []egressRoute{{CIDR: "203.0.113.0/24"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	installer := newEgressRouteInstaller(newFakeRouteCommander(), path)
	if err := installer.load(); err == nil {
		t.Error("a journal from an unknown version was accepted")
	}
	if len(installer.installed) != 0 {
		t.Error("routes were adopted from a journal that could not be read")
	}
}

// A missing journal is the ordinary first run. Refusing to start gains nothing, and the alternative
// to an empty set is guessing which of the machine's routes might have been ours.
func TestEgressRouteJournalTreatsAMissingFileAsEmpty(t *testing.T) {
	installer := newEgressRouteInstaller(newFakeRouteCommander(), journalPath(t))
	if err := installer.load(); err != nil {
		t.Errorf("a missing journal was an error: %v", err)
	}
	if len(installer.installed) != 0 {
		t.Error("a missing journal produced routes")
	}
}

// A prefix that changes kind has to lose its old entry before the new one goes in.
func TestEgressRouteDiffReplacesAPrefixThatChangedKind(t *testing.T) {
	current := []egressRoute{{CIDR: "203.0.113.7/32", Kind: egressRouteToTun}}
	desired := []egressRoute{{CIDR: "203.0.113.7/32", Kind: egressRouteBypass}}

	remove, add := diffEgressRoutes(current, desired)
	if len(remove) != 1 || len(add) != 1 {
		t.Fatalf("remove=%d add=%d, want one of each", len(remove), len(add))
	}
	if remove[0].Kind != egressRouteToTun || add[0].Kind != egressRouteBypass {
		t.Errorf("remove=%s add=%s", remove[0].Kind, add[0].Kind)
	}
}
