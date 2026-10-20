package client

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Route takeover for IPv6 (protocol/spec/peer-egress.md, IPv6 数据面, 消费端): the plan, the journal,
// the repair against the IPv6 table, and each platform's commands and readings, against synthetic
// tables and against output sampled from the real tools. No route on this machine is touched.

func egressIPv6PlanRules() []egressRule {
	return []egressRule{
		{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2},
		{Match: "2001:DB8:1:0::/48", Action: egressActionEgress, EgressClientID: 2},
		{Match: "2001:db8:2::/48", Action: egressActionBlock},
		{Match: "2001:db8:3::/48", Action: egressActionDirect},
		{Match: "2001:db8:1::/48", Action: egressActionBlock},
		{Match: "fd53:7065:6375:7300::/96", Action: egressActionEgress, EgressClientID: 2},
		{Match: "::/0", Action: egressActionEgress, EgressClientID: 2},
		{Match: "::/1", Action: egressActionBlock},
	}
}

// Exact IPv6 prefixes, written canonically; nothing for a direct rule; a route for a block rule; one
// route for two rules over one prefix; the refusals returned; and a /128 bypass for an IPv6 endpoint
// an IPv6 rule covers, first.
func TestEgressIPv6RoutePlan(t *testing.T) {
	// fd00::1 is covered by no rule; everything in 2001::/16 is, by ::/1 at least.
	bypass := []string{"198.51.100.7", "2001:db8:1::9", "2001:db8:1:0::9", "2001:db8:9::1", "2001:db8:2::5", "203.0.113.4", "fd00::1"}
	routes, refused := planEgressRoutesFor(egressIPv6PlanRules(), bypass, egressDefaultMeshCIDR, "", true)
	want := []egressRoute{
		{CIDR: "203.0.113.4/32", Kind: egressRouteBypass, Origin: "bypass"},
		{CIDR: "2001:db8:1::9/128", Kind: egressRouteBypass, Origin: "bypass"},
		{CIDR: "2001:db8:2::5/128", Kind: egressRouteBypass, Origin: "bypass"},
		{CIDR: "2001:db8:9::1/128", Kind: egressRouteBypass, Origin: "bypass"},
		{CIDR: "203.0.113.0/24", Kind: egressRouteToTun, Origin: "rule:203.0.113.0/24"},
		// ::/1 is not invented; written by hand it is a rule like any other.
		{CIDR: "::/1", Kind: egressRouteToTun, Origin: "rule:::/1"},
		{CIDR: "2001:db8:1::/48", Kind: egressRouteToTun, Origin: "rule:2001:DB8:1:0::/48"},
		{CIDR: "2001:db8:2::/48", Kind: egressRouteToTun, Origin: "rule:2001:db8:2::/48"},
	}
	if !reflect.DeepEqual(routes, want) {
		t.Errorf("plan:\n got %+v\nwant %+v", routes, want)
	}
	wantRefused := map[int]string{5: egressCodeRuleMeshOverlap, 6: egressCodeRuleDefaultRoute}
	if len(refused) != len(wantRefused) {
		t.Fatalf("refused = %+v", refused)
	}
	for _, entry := range refused {
		if wantRefused[entry.Index] != entry.Code {
			t.Errorf("rule %d refused with %s", entry.Index, entry.Code)
		}
	}

	// Without the data plane the IPv6 rules are refused and the plan is the IPv4 one alone, exactly
	// what it was before IPv6.
	routes, refused = planEgressRoutesFor(egressIPv6PlanRules(), bypass, egressDefaultMeshCIDR, "", false)
	before, _ := planEgressRoutes([]egressRule{egressIPv6PlanRules()[0]}, bypass, egressDefaultMeshCIDR)
	if !reflect.DeepEqual(routes, before) {
		t.Errorf("without the data plane:\n got %+v\nwant %+v", routes, before)
	}
	for _, entry := range refused {
		if entry.Index != 0 && entry.Code != egressCodeRuleIPv6Unsupported && entry.Code != egressCodeRuleDefaultRoute {
			t.Errorf("rule %d refused with %s without the data plane", entry.Index, entry.Code)
		}
	}
}

// One order across both families: bypass first, IPv4 before IPv6, by value within a family. Sorted
// as text across families and by value within one, these three would each sort before the next.
func TestEgressRouteSortIsOneOrderAcrossFamilies(t *testing.T) {
	routes := []egressRoute{
		{CIDR: "2001:db8::/32", Kind: egressRouteToTun},
		{CIDR: "10.0.0.0/8", Kind: egressRouteToTun},
		{CIDR: "9.0.0.0/8", Kind: egressRouteToTun},
		{CIDR: "2001:db8::1/128", Kind: egressRouteBypass},
		{CIDR: "fd00::/8", Kind: egressRouteToTun},
		{CIDR: "::/1", Kind: egressRouteToTun},
		{CIDR: "9.0.0.9/32", Kind: egressRouteBypass},
	}
	sortEgressRoutes(routes)
	var got []string
	for _, route := range routes {
		got = append(got, route.CIDR)
	}
	want := []string{"9.0.0.9/32", "2001:db8::1/128", "9.0.0.0/8", "10.0.0.0/8", "::/1", "2001:db8::/32", "fd00::/8"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
}

// The journal carries IPv6 prefixes in the shared format, written first and read back, and a restart
// takes them back like any other.
func TestEgressIPv6RoutesJournalAndWithdraw(t *testing.T) {
	path := journalPath(t)
	commander := newFakeRouteCommander()
	installer := newEgressRouteInstaller(commander, path)
	plan, _ := planEgressRoutesFor(egressIPv6PlanRules(), []string{"2001:db8:1::9"}, egressDefaultMeshCIDR, "", true)
	if result := installer.apply(plan); result.Err != nil || len(result.Added) != len(plan) {
		t.Fatalf("apply: %+v", result)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var journal struct {
		Version int `json:"version"`
		Routes  []struct {
			CIDR   string `json:"cidr"`
			Kind   string `json:"kind"`
			Origin string `json:"origin"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(raw, &journal); err != nil || journal.Version != 1 {
		t.Fatalf("journal %s: %v", raw, err)
	}
	found := map[string]string{}
	for _, entry := range journal.Routes {
		found[entry.CIDR] = entry.Kind + "|" + entry.Origin
	}
	if found["2001:db8:1::9/128"] != "bypass|bypass" || found["2001:db8:1::/48"] != "tun|rule:2001:DB8:1:0::/48" {
		t.Errorf("journal routes = %v", found)
	}
	// The bypass went where the IPv6 table says, through the link-local gateway.
	if hop := commander.hops["2001:db8:1::9/128"]; hop.Interface != "eth0" || hop.Gateway != "fe80::1" {
		t.Errorf("bypass hop = %+v", hop)
	}

	restarted := newEgressRouteInstaller(commander, path)
	if err := restarted.load(); err != nil {
		t.Fatal(err)
	}
	if taken := restarted.withdrawAll(); len(taken) != len(plan) {
		t.Errorf("took back %d of %d", len(taken), len(plan))
	}
	if len(commander.table) != 0 {
		t.Errorf("left in the table: %v", commander.table)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the journal is still there: %v", err)
	}
}

// The IPv6 routes are checked against the IPv6 table: one gone is put back, a bypass whose gateway
// moved is re-pointed, and one on somebody else's interface is given up. A machine that owns no IPv6
// route never reads the IPv6 table.
func TestEgressIPv6RouteRepair(t *testing.T) {
	commander := newFakeRouteCommander()
	installer := newEgressRouteInstaller(commander, journalPath(t))
	ipv4Only, _ := planEgressRoutes([]egressRule{{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2}},
		[]string{"203.0.113.4"}, egressDefaultMeshCIDR)
	installer.apply(ipv4Only)
	if result := installer.repair(); result.TableErr != nil || len(result.Repaired) != 0 || commander.table6Reads != 0 {
		t.Fatalf("IPv4 only: %+v, IPv6 table read %d times", result, commander.table6Reads)
	}

	plan, _ := planEgressRoutesFor(egressIPv6PlanRules(), []string{"2001:db8:1::9", "203.0.113.4"}, egressDefaultMeshCIDR, "", true)
	installer.apply(plan)
	if healthy := installer.repair(); healthy.TableErr != nil || len(healthy.Repaired) != 0 || len(healthy.Lost) != 0 {
		t.Fatalf("a table with everything in it: %+v", healthy)
	}

	commander.lose("2001:db8:2::/48")
	commander.physical6 = []egressBindRoute{{Prefix: "::/0", Interface: "wlan0", Gateway: "fe80::9", Metric: 50, Usable: true}}
	result := installer.repair()
	if result.TableErr != nil || result.Err != nil || len(result.Repaired) != 2 {
		t.Fatalf("repair: %+v", result)
	}
	if hop := commander.hops["2001:db8:1::9/128"]; hop.Interface != "wlan0" || hop.Gateway != "fe80::9" {
		t.Errorf("the bypass was not re-pointed: %+v", hop)
	}
	if _, back := commander.table["2001:db8:2::/48"]; !back {
		t.Error("the lost route was not put back")
	}

	// Somebody else's route on one of ours is reported and given up.
	commander.lose("2001:db8:1::/48")
	commander.physical6 = append(commander.physical6, egressBindRoute{Prefix: "2001:db8:1::/48", Interface: "eth1", Usable: true})
	result = installer.repair()
	if len(result.Lost) != 1 || result.Lost[0].Route.CIDR != "2001:db8:1::/48" || installer.owns("2001:db8:1::/48") {
		t.Errorf("lost = %+v", result.Lost)
	}

	// The IPv6 table unreadable is said like the IPv4 one.
	commander.table6Err = errors.New("no ip -6")
	if result := installer.repair(); result.TableErr == nil {
		t.Error("an unreadable IPv6 table went unsaid")
	}
}

// The plan the mesh applies with the data plane: IPv6 rules routed, an IPv6 endpoint a rule covers
// bypassed, and the status listing the IPv6 route installed.
func TestMeshReconcilesIPv6Routes(t *testing.T) {
	harness := newReconcileHarness(t,
		egressRule{Match: "2001:db8:1::/48", Action: egressActionEgress, EgressClientID: 2},
		egressRule{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2})
	carries := true
	harness.mesh.egressIPv6 = &carries
	harness.mesh.config.ServerBaseURL = "https://[2001:db8:1::443]:8443"
	harness.tick(0)
	if !contains(harness.commander.installLog, "2001:db8:1::/48") ||
		!contains(harness.commander.installLog, "2001:db8:1::443/128") {
		t.Errorf("installed %v", harness.commander.installLog)
	}
	routes := mapSection(t, harness.mesh.egressStatusJSON(), "consumer")["routes"].([]map[string]any)
	found := false
	for _, route := range routes {
		if route["cidr"] == "2001:db8:1::/48" && route["installed"] == true {
			found = true
		}
	}
	if !found {
		t.Errorf("status routes = %v", routes)
	}

	// Without the data plane the same configuration routes no IPv6 at all.
	off := newReconcileHarness(t,
		egressRule{Match: "2001:db8:1::/48", Action: egressActionEgress, EgressClientID: 2})
	notCarried := false
	off.mesh.egressIPv6 = &notCarried
	off.mesh.config.ServerBaseURL = "https://[2001:db8:1::443]:8443"
	off.tick(0)
	if len(off.commander.installLog) != 0 {
		t.Errorf("installed %v without the data plane", off.commander.installLog)
	}
	rules := mapSection(t, off.mesh.egressStatusJSON(), "consumer")["rules"].([]map[string]any)
	if len(rules) != 1 || rules[0]["code"] != egressCodeRuleIPv6Unsupported {
		t.Errorf("status rules = %v", rules)
	}
}

// The status says which rule waits on an egress that does not take IPv6, and counts the new
// reasons under their own names.
func TestMeshStatusNamesTheIPv6Refusals(t *testing.T) {
	harness := newReconcileHarness(t, egressRule{Match: "2001:db8:1::/48", Action: egressActionEgress, EgressClientID: 2})
	carries := true
	harness.mesh.egressIPv6 = &carries
	harness.tick(0)
	harness.mesh.mu.Lock()
	consumer := harness.mesh.egressConsumer
	harness.mesh.mu.Unlock()
	if consumer == nil || !consumer.carriesIPv6 {
		t.Fatal("the consumer was built without the data plane")
	}
	consumer.setEgressOnline(2, true, flowEpoch)
	local, _ := egressDeviceAddress6("100.96.0.1")
	remote, _ := parseEgressAddress6("2001:db8:1::5")
	other, _ := parseEgressAddress6("2001:db8:ff::5")
	consumer.handleOutbound(buildTCPSegment(tcpSegment{IPv6: true, SourceIP6: local, DestinationIP6: remote,
		SourcePort: 40000, DestinationPort: 443, Flags: tcpFlagSYN, Window: 65535}), flowEpoch)
	consumer.handleOutbound(buildTCPSegment(tcpSegment{IPv6: true, SourceIP6: other, DestinationIP6: remote,
		SourcePort: 40000, DestinationPort: 443, Flags: tcpFlagSYN, Window: 65535}), flowEpoch)

	section := mapSection(t, harness.mesh.egressStatusJSON(), "consumer")
	rules := section["rules"].([]map[string]any)
	if len(rules) != 1 || rules[0]["inForce"] != false || rules[0]["code"] != egressCodeRuleEgressNoIPv6 {
		t.Errorf("rules = %v", rules)
	}
	if peers := section["peers"].([]map[string]any); len(peers) != 0 {
		t.Errorf("a rule out of force contributed a peer: %v", peers)
	}
	blocked := section["blocked"].(map[string]int64)
	if blocked["egress-no-ipv6"] != 1 || blocked["ipv6-source-not-mesh"] != 1 {
		t.Errorf("blocked = %v", blocked)
	}
}

// What `ip -6 route` says, sampled in a WSL 2 network namespace (iproute2 6.1.0) with a real TUN.
const linuxIPv6MainTableSample = "2001:db8:1::/48 dev specus0 metric 1024 linkdown pref medium\n" +
	"2001:db8:64::/64 dev eth0 proto kernel metric 256 pref medium\n" +
	"2001:db8:65::/64 dev eth1 proto kernel metric 256 pref medium\n" +
	"2001:db8:77::/48 metric 1024 pref medium\n" +
	"\tnexthop via fe80::1 dev eth0 weight 1 \n" +
	"\tnexthop via fe80::2 dev eth1 weight 1 \n" +
	"blackhole 2001:db8:dead::/48 dev lo metric 1024 pref medium\n" +
	"fd53:7065:6375:7300::6460:5 dev specus0 proto kernel metric 256 linkdown pref medium\n" +
	"fe80::/64 dev eth0 proto kernel metric 256 pref medium\n" +
	"fe80::/64 dev eth1 proto kernel metric 256 pref medium\n" +
	"default via fe80::1 dev eth0 metric 1024 pref medium\n"

func TestLinuxIPv6RouteReadings(t *testing.T) {
	routes := parseIPRouteTable6(linuxIPv6MainTableSample)
	want := []egressBindRoute{
		{Prefix: "2001:db8:1::/48", Interface: "specus0", Metric: 1024, Usable: true},
		{Prefix: "2001:db8:64::/64", Interface: "eth0", Metric: 256, Usable: true},
		{Prefix: "2001:db8:65::/64", Interface: "eth1", Metric: 256, Usable: true},
		{Prefix: "2001:db8:77::/48", Interface: "eth0", Gateway: "fe80::1", Metric: 1024, Usable: true},
		{Prefix: "2001:db8:dead::/48", Metric: 1024, Usable: true},
		{Prefix: "fd53:7065:6375:7300::6460:5/128", Interface: "specus0", Metric: 256, Usable: true},
		{Prefix: "fe80::/64", Interface: "eth0", Metric: 256, Usable: true},
		{Prefix: "fe80::/64", Interface: "eth1", Metric: 256, Usable: true},
		{Prefix: "::/0", Interface: "eth0", Gateway: "fe80::1", Metric: 1024, Usable: true},
	}
	if !reflect.DeepEqual(routes, want) {
		t.Errorf("table:\n got %+v\nwant %+v", routes, want)
	}
	// Each reader is only ever given its own family's table (ip -4, ip -6); an IPv4 prefix still
	// reads as nothing to the IPv6 one, and an IPv4 gateway is no gateway.
	if got := parseIPRouteTable6("10.0.0.0/8 dev eth0 \n2001:db8::/32 via 192.168.64.1 dev eth0 \n"); len(got) != 1 ||
		got[0].Prefix != "2001:db8::/32" || got[0].Gateway != "" {
		t.Errorf("the IPv6 reader read %+v", got)
	}

	// The fallback hop for an address the tunnel's own route covers: past the tunnel, the default
	// through the link-local gateway; behind the blackhole, nothing.
	if hop, ok := selectEgressBypassHop(routes, "specus0", nil, "2001:db8:1::9"); !ok || hop.Interface != "eth0" || hop.Gateway != "fe80::1" {
		t.Errorf("hop = %+v (%v)", hop, ok)
	}
	if _, ok := selectEgressBypassHop(routes, "specus0", nil, "2001:db8:dead::9"); ok {
		t.Error("a bypass behind a blackhole found a hop")
	}

	for output, want := range map[string]egressRouteHop{
		"2001:db8:1::9 from :: dev specus0 src fd53:7065:6375:7300::6460:5 metric 1024 pref medium\n": {Device: "specus0"},
		"2001:db8:5::9 from :: via fe80::1 dev eth0 src 2001:db8:64::7 metric 1024 pref medium\n":     {Gateway: "fe80::1", Device: "eth0"},
		"2001:db8:64::9 from :: dev eth0 proto kernel src 2001:db8:64::7 metric 256 pref medium\n":    {Device: "eth0"},
	} {
		if hop, ok := parseIPRouteGet(output); !ok || hop != want {
			t.Errorf("%q read as %+v (%v), want %+v", output, hop, ok, want)
		}
	}
	if conflict, existing := parseIPRouteShowExact("2001:db8:1::/48 dev specus0 metric 1024 linkdown pref medium\n"); !conflict ||
		existing != "2001:db8:1::/48 dev specus0 metric 1024 linkdown pref medium" {
		t.Errorf("exact = %v %q", conflict, existing)
	}

	// The commands: IPv4 exactly as before, IPv6 with -6, and the address the device is given.
	for _, testCase := range []struct {
		got  []string
		want string
	}{
		{linuxRouteArgs("203.0.113.0/24", "add", "203.0.113.0/24", "dev", "specus0"), "ip route add 203.0.113.0/24 dev specus0"},
		{linuxRouteArgs("2001:db8:1::/48", "add", "2001:db8:1::/48", "dev", "specus0"), "ip -6 route add 2001:db8:1::/48 dev specus0"},
		{linuxRouteArgs("2001:db8:1::9/128", "add", "2001:db8:1::9/128", "via", "fe80::1", "dev", "eth0"),
			"ip -6 route add 2001:db8:1::9/128 via fe80::1 dev eth0"},
		{linuxRouteArgs("2001:db8:1::9/128", "get", "2001:db8:1::9"), "ip -6 route get 2001:db8:1::9"},
		{linuxRouteArgs("2001:db8:1::/48", "show", "exact", "2001:db8:1::/48"), "ip -6 route show exact 2001:db8:1::/48"},
		{linuxRouteArgs("2001:db8:1::/48", "del", "2001:db8:1::/48"), "ip -6 route del 2001:db8:1::/48"},
		{linuxShowMainTableArgs6(), "ip -6 route show table main"},
		{linuxAssignAddress6Args("specus0", "fd53:7065:6375:7300::6460:1"), "ip -6 address add fd53:7065:6375:7300::6460:1/128 dev specus0"},
	} {
		if got := strings.Join(testCase.got, " "); got != testCase.want {
			t.Errorf("command %q, want %q", got, testCase.want)
		}
	}
}

func TestWindowsIPv6RouteScripts(t *testing.T) {
	script, err := windowsInstallRouteScript6("2001:db8:1::/48", 9, "")
	if err != nil || script != "try{New-NetRoute -AddressFamily IPv6 -DestinationPrefix '2001:db8:1::/48' -NextHop '::' "+
		"-InterfaceIndex 9 -PolicyStore ActiveStore -ErrorAction Stop|Out-Null}catch{ConvertTo-Json -Compress "+
		"-InputObject @{errorId=$_.FullyQualifiedErrorId};exit 1}" {
		t.Errorf("install on-link: %q %v", script, err)
	}
	script, err = windowsInstallRouteScript6("2001:db8:1::9/128", 3, "fe80::1")
	if err != nil || !strings.Contains(script, "-DestinationPrefix '2001:db8:1::9/128' -NextHop 'fe80::1' -InterfaceIndex 3 ") {
		t.Errorf("install via a gateway: %q %v", script, err)
	}
	script, err = windowsRemoveRouteScript6("2001:db8:1::/48")
	if err != nil || script != "try{Remove-NetRoute -AddressFamily IPv6 -DestinationPrefix '2001:db8:1::/48' -Confirm:$false "+
		"-PolicyStore ActiveStore -ErrorAction Stop|Out-Null}catch{ConvertTo-Json -Compress -InputObject "+
		"@{errorId=$_.FullyQualifiedErrorId};exit 1}" {
		t.Errorf("remove: %q %v", script, err)
	}
	script, err = windowsFindRoutesScript6([]string{"2001:db8:1::9"})
	if err != nil || script != "foreach($a in @('2001:db8:1::9')){ConvertTo-Json -Compress -InputObject "+
		"@(Find-NetRoute -RemoteIPAddress $a -ErrorAction SilentlyContinue|Select-Object "+
		"InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)}\nexit 0" {
		t.Errorf("find: %q %v", script, err)
	}
	if got := windowsShowAllRoutesScript6(); got != strings.Replace(windowsShowAllRoutesScript(), "IPv4", "IPv6", 1) {
		t.Errorf("show all: %q", got)
	}
	script, err = windowsAssignAddress6Script(17, "fd53:7065:6375:7300::6460:1", 1280)
	if err != nil || !strings.Contains(script, "New-NetIPAddress -AddressFamily IPv6 -IPAddress 'fd53:7065:6375:7300::6460:1' "+
		"-PrefixLength 128 -InterfaceIndex 17 -PolicyStore ActiveStore") ||
		!strings.Contains(script, "Set-NetIPInterface -AddressFamily IPv6 -InterfaceIndex 17 -NlMtuBytes 1280 -PolicyStore ActiveStore") {
		t.Errorf("assign: %q %v", script, err)
	}

	// Nothing but an IPv6 prefix in the canonical form reaches an IPv6 script, and nothing IPv6
	// reaches an IPv4 one.
	for _, bad := range []string{"2001:db8:1::/48';Remove-NetRoute -DestinationPrefix '::/0", "2001:DB8:1::/48",
		"2001:db8:1:0::/48", "2001:db8:1::", "203.0.113.0/24", "$(Get-NetRoute)", "fe80::1%3/128", ""} {
		if _, err := windowsInstallRouteScript6(bad, 9, ""); err == nil {
			t.Errorf("install accepted %q", bad)
		}
		if _, err := windowsRemoveRouteScript6(bad); err == nil {
			t.Errorf("remove accepted %q", bad)
		}
	}
	for _, bad := range []string{"fe80::1%3", "[2001:db8::1]", "::ffff:192.0.2.1", "2001:db8::1'", "203.0.113.9"} {
		if _, err := windowsFindRoutesScript6([]string{bad}); err == nil {
			t.Errorf("find accepted %q", bad)
		}
		if _, err := windowsInstallRouteScript6("2001:db8:1::9/128", 3, bad); err == nil {
			t.Errorf("install accepted the gateway %q", bad)
		}
	}
	if _, err := windowsInstallRouteScript("2001:db8:1::/48", 9, ""); err == nil {
		t.Error("the IPv4 install accepted an IPv6 prefix")
	}
	if _, err := windowsAssignAddress6Script(0, "fd53:7065:6375:7300::6460:1", 1280); err == nil {
		t.Error("the address was assigned to interface 0")
	}
}

// Get-NetRoute -AddressFamily IPv6 as it comes back (shape sampled on Windows 11, Windows PowerShell
// 5.1: on-link is "::"): the conflict check compares by value, and the find reads the route, not
// the source-address object.
func TestWindowsIPv6RouteReadings(t *testing.T) {
	table := `[{"InterfaceIndex":44,"DestinationPrefix":"ff00::/8","NextHop":"::","RouteMetric":256},` +
		`{"InterfaceIndex":3,"DestinationPrefix":"2001:db8:1::/48","NextHop":"fe80::1","RouteMetric":0},` +
		`{"InterfaceIndex":3,"DestinationPrefix":"2001:DB8:2:0::/48","NextHop":"::","RouteMetric":5}]`
	if conflict, existing := windowsConflictFromTable6(table, "2001:db8:1::/48"); !conflict ||
		existing != "2001:db8:1::/48 nexthop fe80::1 ifIndex 3 metric 0" {
		t.Errorf("conflict = %v %q", conflict, existing)
	}
	if conflict, existing := windowsConflictFromTable6(table, "2001:db8:2::/48"); !conflict ||
		existing != "2001:DB8:2:0::/48 on-link ifIndex 3 metric 5" {
		t.Errorf("a differently written prefix: %v %q", conflict, existing)
	}
	if conflict, _ := windowsConflictFromTable6(table, "2001:db8:3::/48"); conflict {
		t.Error("a prefix nobody holds conflicted")
	}
	if conflict, _ := windowsConflictFromTable6("[]", "2001:db8:1::/48"); conflict {
		t.Error("an empty table conflicted")
	}

	find := `[{"InterfaceIndex":3,"DestinationPrefix":null,"NextHop":null,"RouteMetric":null},` +
		`{"InterfaceIndex":3,"DestinationPrefix":"::/0","NextHop":"fe80::1","RouteMetric":0}]`
	if hop, ok := parseWindowsRouteFind(find); !ok || hop.InterfaceIndex != 3 || hop.Gateway != "fe80::1" {
		t.Errorf("find = %+v (%v)", hop, ok)
	}
	onLink := `[{"InterfaceIndex":3,"DestinationPrefix":"2001:db8:64::/64","NextHop":"::","RouteMetric":256}]`
	if hop, ok := parseWindowsRouteFind(onLink); !ok || hop.Gateway != "" {
		t.Errorf("on-link find = %+v (%v)", hop, ok)
	}
}

func TestMacosIPv6RouteCommandsAndReadings(t *testing.T) {
	for _, testCase := range []struct {
		got  func() ([]string, error)
		want string
	}{
		{func() ([]string, error) { return macosInstallInterfaceArgs6("2001:db8:1::/48", "utun4") },
			"route -n add -inet6 -net 2001:db8:1::/48 -interface utun4"},
		{func() ([]string, error) { return macosInstallGatewayArgs6("2001:db8:1::9/128", "fe80::1%en0") },
			"route -n add -inet6 -net 2001:db8:1::9/128 fe80::1%en0"},
		{func() ([]string, error) { return macosRemoveArgs6("2001:db8:1::/48") }, "route -n delete -inet6 -net 2001:db8:1::/48"},
		{func() ([]string, error) { return macosFindRouteArgs6("2001:db8:1::9") }, "route -n get -inet6 2001:db8:1::9"},
		{func() ([]string, error) { return macosAssignAddress6Args("utun4", "fd53:7065:6375:7300::6460:1") },
			"ifconfig utun4 inet6 fd53:7065:6375:7300::6460:1 prefixlen 128"},
	} {
		args, err := testCase.got()
		if got := strings.Join(args, " "); err != nil || got != testCase.want {
			t.Errorf("%q (%v), want %q", got, err, testCase.want)
		}
	}
	for _, bad := range []string{"2001:DB8:1::/48", "2001:db8:1::/129", "2001:db8:1::", "-net", "203.0.113.0/24"} {
		if _, err := macosInstallInterfaceArgs6(bad, "utun4"); err == nil {
			t.Errorf("install accepted %q", bad)
		}
	}
	for _, bad := range []string{"fe80::1%-x", "fe80::1%en0 extra", "[fe80::1]", "-inet6"} {
		if _, err := macosInstallGatewayArgs6("2001:db8:1::9/128", bad); err == nil {
			t.Errorf("install accepted the gateway %q", bad)
		}
	}
	if _, err := macosFindRouteArgs6("fe80::1%en0"); err == nil {
		t.Error("a zoned address was asked about")
	}
	if _, err := macosAssignAddress6Args("-utun4", "fd53:7065:6375:7300::6460:1"); err == nil {
		t.Error("an interface name reading as an option was accepted")
	}
	if _, err := macosInstallInterfaceArgs("2001:db8:1::/48", "utun4"); err == nil {
		t.Error("the IPv4 install accepted an IPv6 prefix")
	}

	get := "   route to: 2001:db8:1::9\ndestination: default\n       mask: default\n    gateway: fe80::1%en0\n" +
		"  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n"
	if hop, ok := parseMacosRouteGet6(get, ""); !ok || hop.Gateway != "fe80::1%en0" || hop.Device != "en0" {
		t.Errorf("route get = %+v (%v)", hop, ok)
	}
	if hop, ok := parseMacosRouteGet6("   route to: 2001:db8:64::9\n    gateway: link#6\n  interface: en0\n", ""); !ok || hop.Gateway != "" {
		t.Errorf("an on-link answer = %+v (%v)", hop, ok)
	}
	if _, ok := parseMacosRouteGet6("", "route: writing to routing socket: not in table\n"); ok {
		t.Error("a failed lookup read as a hop")
	}

	table := "Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\n" +
		"default            192.168.1.1        UGScg                 en0\n\nInternet6:\n" +
		"Destination                             Gateway                                 Flags               Netif Expire\n" +
		"default                                 fe80::1%en0                             UGcg                  en0\n" +
		"2001:db8:1::/48                         utun4                                   USc                 utun4\n" +
		"2001:db8:5::9                           fe80::1%en0                             UGHS                  en0\n" +
		"2001:db8:64::9                          a4:83:e7:0:0:1                          UHLWIi                en0\n"
	if conflict, existing := macosConflictFromTable6(table, "2001:db8:1::/48"); !conflict ||
		existing != "2001:db8:1::/48 gateway utun4 netif utun4 flags USc" {
		t.Errorf("conflict = %v %q", conflict, existing)
	}
	if conflict, _ := macosConflictFromTable6(table, "2001:db8:64::9/128"); conflict {
		t.Error("a kernel-generated neighbour entry conflicted")
	}
	if conflict, _ := macosConflictFromTable6(table, "::/0"); !conflict {
		t.Error("the IPv6 default route did not conflict with ::/0")
	}
	if conflict, _ := macosConflictFromTable(table, "0.0.0.0/0"); !conflict {
		t.Error("the IPv4 default lost its conflict")
	}
	routes := macosBypassRoutes6(table)
	if hop, ok := selectEgressBypassHop(routes, "utun4", nil, "2001:db8:1::9"); !ok || hop.Interface != "en0" || hop.Gateway != "fe80::1%en0" {
		t.Errorf("fallback hop = %+v (%v)", hop, ok)
	}
}

// The derived address goes to the TUN only for a consumer with the IPv6 data plane.
func TestPeerDeviceIPv6AddressFollowsTheConsumer(t *testing.T) {
	config := Config{PeerEgressEnabled: true, PeerMeshMTU: 1280}
	address, ok := peerDeviceAddress6(config, "100.96.0.1")
	if ok != egressPlatformCarriesIPv6 || (ok && address != "fd53:7065:6375:7300::6460:1") {
		t.Errorf("address = %q (%v)", address, ok)
	}
	for _, without := range []Config{{PeerMeshMTU: 1280}, {PeerEgressEnabled: true, PeerMeshMTU: 1200}} {
		if _, ok := peerDeviceAddress6(without, "100.96.0.1"); ok {
			t.Errorf("%+v was given an IPv6 address", without)
		}
	}
	if _, ok := peerDeviceAddress6(config, ""); ok {
		t.Error("no mesh address derived an IPv6 one")
	}
}

// The bypass resolver gives IPv6 answers and literals only through resolve6, in RFC 5952 form.
func TestEgressBypassResolverResolvesIPv6Apart(t *testing.T) {
	calls := 0
	resolver := newEgressBypassResolver(func(host string) ([]net.IP, error) {
		calls++
		if host == "stun.example.test" {
			return []net.IP{net.ParseIP("2001:DB8:0::1"), net.IPv4(203, 0, 113, 60)}, nil
		}
		return nil, errors.New("no such host")
	})
	entries := []string{"https://[2001:db8::443]:8443/login", "stun.example.test:3478", "[2001:db8::2]:3478",
		"2001:db8::3", "198.51.100.1", "[fe80::1%eth0]:3478", "::ffff:192.0.2.1"}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	addresses, _ := resolver.resolve(entries, now)
	if !reflect.DeepEqual(addresses, []string{"203.0.113.60", "198.51.100.1"}) {
		t.Errorf("resolve = %v", addresses)
	}
	got := resolver.resolve6(entries, now)
	if !reflect.DeepEqual(got, []string{"2001:db8::443", "2001:db8::1", "2001:db8::2", "2001:db8::3"}) {
		t.Errorf("resolve6 = %v", got)
	}
	if calls != 1 {
		t.Errorf("the name was looked up %d times for both families", calls)
	}
}
