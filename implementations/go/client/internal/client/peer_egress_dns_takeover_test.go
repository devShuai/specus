package client

import (
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// The takeover run against fake machines, one per platform: taking over, giving back, failing
// halfway, refusing, recovering a killed process's journal, and leaving somebody else's change alone.
// Nothing here runs a real command.

// fakeDNSHost is a machine that records every command and keeps its files and macOS services in
// memory. A command it has no output for succeeds and prints nothing.
type fakeDNSHost struct {
	mu       sync.Mutex
	files    map[string]string
	symlinks map[string]bool
	links    map[string]bool
	services map[string][]string
	outputs  map[string]string
	fail     map[string]string
	ran      []string
}

func newFakeDNSHost() *fakeDNSHost {
	return &fakeDNSHost{files: map[string]string{}, symlinks: map[string]bool{}, links: map[string]bool{"specus0": true},
		services: map[string][]string{}, outputs: map[string]string{}, fail: map[string]string{}}
}

func (h *fakeDNSHost) Run(argv []string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	line := strings.Join(argv, " ")
	h.ran = append(h.ran, line)
	if output, failing := h.fail[line]; failing {
		return "", &egressDNSCommandError{argv: argv, output: output, err: errors.New("exit status 1")}
	}
	if len(argv) >= 3 && argv[0] == "networksetup" && argv[1] == "-getdnsservers" {
		servers := h.services[argv[2]]
		if len(servers) == 0 || servers[0] == "Empty" {
			return "There aren't any DNS Servers set on " + argv[2] + ".\n", nil
		}
		return strings.Join(servers, "\n") + "\n", nil
	}
	if len(argv) >= 4 && argv[0] == "networksetup" && argv[1] == "-setdnsservers" {
		h.services[argv[2]] = append([]string(nil), argv[3:]...)
		return "", nil
	}
	return h.outputs[line], nil
}

func (h *fakeDNSHost) ReadFile(path string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	content, ok := h.files[path]
	if !ok {
		return "", os.ErrNotExist
	}
	return content, nil
}

func (h *fakeDNSHost) WriteFile(path, content string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.files[path] = content
	return nil
}

func (h *fakeDNSHost) IsSymlink(path string) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.symlinks[path], nil
}

func (h *fakeDNSHost) LinkExists(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.links[name]
}

func (h *fakeDNSHost) commands() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.ran...)
}

// since returns the commands run after the first n.
func (h *fakeDNSHost) since(n int) []string { return h.commands()[n:] }

func newTestTakeover(t *testing.T, host EgressDNSHost, platform string) *egressDNSTakeover {
	t.Helper()
	takeover := newEgressDNSTakeover(host, platform, filepath.Join(t.TempDir(), "egress-dns-journal.json"),
		log.New(io.Discard, "", 0))
	return takeover
}

func takeoverRequest() egressDNSTakeoverRequest {
	return egressDNSTakeoverRequest{Listen: "198.18.0.1", Tunnel: "specus0", Pool: egressDefaultFakeIPCIDR,
		Mesh: egressDefaultMeshCIDR, PoolRouteInstalled: true}
}

func readTestJournal(t *testing.T, takeover *egressDNSTakeover) *EgressDNSJournal {
	t.Helper()
	journal, err := ReadEgressDNSJournal(takeover.path)
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func linuxResolvedHost() *fakeDNSHost {
	host := newFakeDNSHost()
	host.outputs["resolvectl dns"] = "Global: 1.1.1.1\nLink 2 (eth0): 192.168.1.1\nLink 3 (specus0): 198.18.0.1\n"
	host.files[egressDNSResolvConf] = "nameserver 127.0.0.53\noptions edns0\n"
	host.symlinks[egressDNSResolvConf] = true
	return host
}

// systemd-resolved through its stub: the tunnel's link is set, the journal says so before anything
// runs and committed after, and giving back reverts the link.
func TestEgressDNSTakeoverLinuxResolved(t *testing.T) {
	host := linuxResolvedHost()
	takeover := newTestTakeover(t, host, "linux")
	upstreams, committed := takeover.engage(takeoverRequest(), flowEpoch)
	if !committed || !reflect.DeepEqual(upstreams, []string{"1.1.1.1", "192.168.1.1"}) {
		t.Fatalf("committed=%v upstreams=%q", committed, upstreams)
	}
	want := []string{"resolvectl dns", "resolvectl dns specus0 198.18.0.1", "resolvectl domain specus0 ~.", "resolvectl flush-caches"}
	if got := host.commands(); !reflect.DeepEqual(got, want) {
		t.Errorf("commands %q, want %q", got, want)
	}
	journal := readTestJournal(t, takeover)
	if journal == nil || journal.State != egressDNSJournalCommitted || journal.Platform != egressDNSPlatformResolved ||
		journal.Tunnel != "specus0" || journal.PID != os.Getpid() || !reflect.DeepEqual(journal.Upstreams, upstreams) {
		t.Fatalf("journal %+v", journal)
	}
	if status := takeover.statusSnapshot(); !status.Takeover || status.Journal != egressDNSJournalCommitted || status.Code != "" {
		t.Errorf("status %+v", status)
	}
	// Held: the next tick runs nothing.
	before := len(host.commands())
	takeover.engage(takeoverRequest(), flowEpoch.Add(time.Minute))
	if again := host.since(before); len(again) != 0 {
		t.Errorf("a held takeover ran %q", again)
	}

	takeover.release("test")
	if got := host.since(before); !reflect.DeepEqual(got, []string{"resolvectl revert specus0", "resolvectl flush-caches"}) {
		t.Errorf("give-back ran %q", got)
	}
	if readTestJournal(t, takeover) != nil {
		t.Error("the journal outlived the give-back")
	}
	if status := takeover.statusSnapshot(); status.Takeover || status.Journal != egressDNSJournalNone {
		t.Errorf("status after give-back %+v", status)
	}
}

func linuxResolvConfHost() *fakeDNSHost {
	host := newFakeDNSHost()
	host.fail["resolvectl dns"] = "Failed to get global data: Unit dbus-org.freedesktop.resolve1.service not found."
	host.files[egressDNSResolvConf] = "nameserver 192.168.1.1\nnameserver 2001:db8::53\n"
	return host
}

// Without systemd-resolved the file is rewritten, its original kept in the journal and put back --
// unless somebody else rewrote it meanwhile, whose version is kept.
func TestEgressDNSTakeoverLinuxResolvConf(t *testing.T) {
	for _, overwritten := range []bool{false, true} {
		host := linuxResolvConfHost()
		original := host.files[egressDNSResolvConf]
		takeover := newTestTakeover(t, host, "linux")
		upstreams, committed := takeover.engage(takeoverRequest(), flowEpoch)
		if !committed || !reflect.DeepEqual(upstreams, []string{"192.168.1.1"}) {
			t.Fatalf("committed=%v upstreams=%q", committed, upstreams)
		}
		if host.files[egressDNSResolvConf] != egressDNSResolvConfWritten {
			t.Fatalf("resolv.conf is %q", host.files[egressDNSResolvConf])
		}
		if journal := readTestJournal(t, takeover); journal.ResolvConf != original || journal.Platform != egressDNSPlatformResolvConf {
			t.Fatalf("journal %+v", journal)
		}
		theirs := "nameserver 10.0.0.1\n"
		if overwritten {
			host.files[egressDNSResolvConf] = theirs
		}
		takeover.release("test")
		want := original
		if overwritten {
			want = theirs
		}
		if host.files[egressDNSResolvConf] != want {
			t.Errorf("overwritten=%v: resolv.conf after give-back %q, want %q", overwritten, host.files[egressDNSResolvConf], want)
		}
		if readTestJournal(t, takeover) != nil {
			t.Errorf("overwritten=%v: the journal outlived the give-back", overwritten)
		}
	}
}

func macOSHost() *fakeDNSHost {
	host := newFakeDNSHost()
	host.outputs["networksetup -listallnetworkservices"] =
		"An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\nThunderbolt Bridge\n"
	host.services["Wi-Fi"] = []string{"Empty"}
	host.services["Thunderbolt Bridge"] = []string{"1.1.1.1", "8.8.8.8"}
	host.outputs["scutil --dns"] = "DNS configuration\n\nresolver #1\n  nameserver[0] : 192.168.1.1\n"
	return host
}

// macOS: every enabled service points at the responder, and each goes back to exactly what it had,
// `Empty` included -- except one somebody changed meanwhile, which is kept.
func TestEgressDNSTakeoverMacOS(t *testing.T) {
	host := macOSHost()
	takeover := newTestTakeover(t, host, "darwin")
	upstreams, committed := takeover.engage(takeoverRequest(), flowEpoch)
	if !committed || !reflect.DeepEqual(upstreams, []string{"192.168.1.1"}) {
		t.Fatalf("committed=%v upstreams=%q", committed, upstreams)
	}
	for _, service := range []string{"Wi-Fi", "Thunderbolt Bridge"} {
		if got := host.services[service]; !reflect.DeepEqual(got, []string{"198.18.0.1"}) {
			t.Errorf("%s points at %q", service, got)
		}
	}
	journal := readTestJournal(t, takeover)
	if !reflect.DeepEqual(journal.Services, []EgressDNSService{{Name: "Wi-Fi", Servers: []string{"Empty"}},
		{Name: "Thunderbolt Bridge", Servers: []string{"1.1.1.1", "8.8.8.8"}}}) {
		t.Fatalf("journal services %+v", journal.Services)
	}
	host.services["Thunderbolt Bridge"] = []string{"9.9.9.9"}
	takeover.release("test")
	if got := host.services["Wi-Fi"]; !reflect.DeepEqual(got, []string{"Empty"}) {
		t.Errorf("Wi-Fi went back to %q, want Empty", got)
	}
	if got := host.services["Thunderbolt Bridge"]; !reflect.DeepEqual(got, []string{"9.9.9.9"}) {
		t.Errorf("a service somebody changed was overwritten: %q", got)
	}
	commands := host.commands()
	if last := commands[len(commands)-1]; last != "killall -HUP mDNSResponder" {
		t.Errorf("the give-back did not end by flushing the cache: %q", commands)
	}
}

func windowsHost() *fakeDNSHost {
	host := newFakeDNSHost()
	host.outputs[strings.Join(windowsPowerShell(egressDNSWindowsReadNRPT), " ")] = ""
	host.outputs[strings.Join(windowsPowerShell(windowsInterfaceIndexScript("specus0")), " ")] = `[{"InterfaceIndex":17}]`
	host.outputs[strings.Join(windowsPowerShell(egressDNSWindowsReadServers), " ")] =
		`[{"InterfaceAlias":"Ethernet","InterfaceIndex":12,"ServerAddresses":["192.168.1.1"]},` +
			`{"InterfaceAlias":"specus0","InterfaceIndex":17,"ServerAddresses":["198.18.0.1"]}]`
	return host
}

// Windows: an NRPT rule for the root namespace, and its removal; the TUN's own server is not read
// back as an upstream. Somebody else's root rule refuses the takeover without a change.
func TestEgressDNSTakeoverWindows(t *testing.T) {
	host := windowsHost()
	takeover := newTestTakeover(t, host, "windows")
	upstreams, committed := takeover.engage(takeoverRequest(), flowEpoch)
	if !committed || !reflect.DeepEqual(upstreams, []string{"192.168.1.1"}) {
		t.Fatalf("committed=%v upstreams=%q", committed, upstreams)
	}
	plan, _ := egressDNSTakeoverPlan(egressDNSPlatformWindows, "198.18.0.1", "specus0", nil)
	commands := host.commands()
	if commands[len(commands)-1] != strings.Join(plan.Apply[0].Argv, " ") {
		t.Errorf("the last command is %q, want the NRPT rule", commands[len(commands)-1])
	}
	before := len(commands)
	takeover.release("test")
	if got := host.since(before); len(got) != 1 || got[0] != strings.Join(plan.Revert[0].Argv, " ") {
		t.Errorf("give-back ran %q", got)
	}

	occupied := windowsHost()
	occupied.outputs[strings.Join(windowsPowerShell(egressDNSWindowsReadNRPT), " ")] = `{"Namespace":".","Comment":"","NameServers":"10.0.0.1"}`
	refused := newTestTakeover(t, occupied, "windows")
	if _, committed := refused.engage(takeoverRequest(), flowEpoch); committed {
		t.Fatal("took over past somebody else's root NRPT rule")
	}
	if status := refused.statusSnapshot(); status.Code != egressCodeDNSTakeoverRefused || status.Reason != egressDNSRefusedNRPT {
		t.Errorf("status %+v", status)
	}
	if readTestJournal(t, refused) != nil {
		t.Error("a refused takeover wrote a journal")
	}
}

// A step that fails midway gives back everything, whatever happened, deletes the journal, and says
// what the failing command printed first.
func TestEgressDNSTakeoverFailureGivesBack(t *testing.T) {
	host := linuxResolvedHost()
	host.fail["resolvectl domain specus0 ~."] = "\nFailed to set domain configuration: Access denied\nmore detail"
	takeover := newTestTakeover(t, host, "linux")
	if _, committed := takeover.engage(takeoverRequest(), flowEpoch); committed {
		t.Fatal("a failed takeover committed")
	}
	want := []string{"resolvectl dns", "resolvectl dns specus0 198.18.0.1", "resolvectl domain specus0 ~.",
		"resolvectl revert specus0", "resolvectl flush-caches"}
	if got := host.commands(); !reflect.DeepEqual(got, want) {
		t.Errorf("commands %q, want %q", got, want)
	}
	status := takeover.statusSnapshot()
	if status.Takeover || status.Code != egressCodeDNSTakeoverFailed ||
		status.Error != "Failed to set domain configuration: Access denied" || status.Journal != egressDNSJournalNone {
		t.Errorf("status %+v", status)
	}
	if readTestJournal(t, takeover) != nil {
		t.Error("the journal outlived a give-back that succeeded")
	}
}

// Each refusal is said with its reason and changes nothing. Asked again within the minute it is
// not read again; after it, it is.
func TestEgressDNSTakeoverRefusals(t *testing.T) {
	loopback := newFakeDNSHost()
	loopback.fail["resolvectl dns"] = "no resolved"
	loopback.files[egressDNSResolvConf] = "nameserver 127.0.0.1\n"
	managed := newFakeDNSHost()
	managed.fail["resolvectl dns"] = "no resolved"
	managed.files[egressDNSResolvConf] = "nameserver 192.168.1.1\n"
	managed.symlinks[egressDNSResolvConf] = true
	vpn := newFakeDNSHost()
	vpn.fail["resolvectl dns"] = "no resolved"
	vpn.files[egressDNSResolvConf] = "nameserver 10.8.0.1\n"
	empty := newFakeDNSHost()
	empty.fail["resolvectl dns"] = "no resolved"
	empty.files[egressDNSResolvConf] = "nameserver 2001:db8::53\n"

	cases := []struct {
		name, platform, reason string
		host                   *fakeDNSHost
		request                egressDNSTakeoverRequest
	}{
		{"pool route", "linux", egressDNSRefusedPoolRoute, linuxResolvedHost(), egressDNSTakeoverRequest{Listen: "198.18.0.1", Tunnel: "specus0"}},
		{"loopback", "linux", egressDNSRefusedLoopback, loopback, takeoverRequest()},
		{"managed", "linux", egressDNSRefusedManaged, managed, takeoverRequest()},
		{"another VPN", "linux", egressDNSRefusedVirtual, vpn, takeoverRequest()},
		{"no upstream", "linux", egressDNSRefusedNoUpstream, empty, takeoverRequest()},
		{"platform", "plan9", egressDNSRefusedUnsupported, newFakeDNSHost(), takeoverRequest()},
	}
	for _, c := range cases {
		takeover := newTestTakeover(t, c.host, c.platform)
		takeover.tunnelAddresses = func(string) []string { return []string{"10.8.0.1"} }
		if _, committed := takeover.engage(c.request, flowEpoch); committed {
			t.Fatalf("%s: took over", c.name)
		}
		if status := takeover.statusSnapshot(); status.Code != egressCodeDNSTakeoverRefused || status.Reason != c.reason || status.Takeover {
			t.Errorf("%s: status %+v, want refused for %s", c.name, status, c.reason)
		}
		for _, command := range c.host.commands() {
			if strings.HasPrefix(command, "resolvectl dns specus0") || strings.HasPrefix(command, "resolvectl domain") {
				t.Errorf("%s: a refused takeover ran %q", c.name, command)
			}
		}
		if readTestJournal(t, takeover) != nil || c.host.files[egressDNSResolvConf] == egressDNSResolvConfWritten {
			t.Errorf("%s: a refused takeover left a mark", c.name)
		}
		if c.reason == egressDNSRefusedPoolRoute {
			if len(c.host.commands()) != 0 {
				t.Errorf("waiting for the pool's route ran %q", c.host.commands())
			}
			continue
		}
		before := len(c.host.commands())
		takeover.engage(c.request, flowEpoch.Add(30*time.Second))
		if again := c.host.since(before); len(again) != 0 {
			t.Errorf("%s: asked again within the minute: %q", c.name, again)
		}
		takeover.engage(c.request, flowEpoch.Add(egressDNSRetryInterval))
		if again := c.host.since(before); len(again) == 0 && c.platform == "linux" {
			t.Errorf("%s: not asked again after the minute", c.name)
		}
	}
}

// A journal a killed process left, pending or committed, is given back before anything else; one
// whose give-back fails is kept, and says which step failed.
func TestEgressDNSTakeoverRecoversAKilledProcess(t *testing.T) {
	for _, state := range []string{egressDNSJournalPending, egressDNSJournalCommitted} {
		host := newFakeDNSHost()
		host.files[egressDNSResolvConf] = egressDNSResolvConfWritten
		takeover := newTestTakeover(t, host, "linux")
		original := "nameserver 192.168.1.1\n"
		if err := writeEgressDNSJournal(takeover.path, EgressDNSJournal{Version: 1, State: state,
			Platform: egressDNSPlatformResolvConf, PID: 4242, Listen: "198.18.0.1", Tunnel: "specus0",
			Upstreams: []string{"192.168.1.1"}, ResolvConf: original}); err != nil {
			t.Fatal(err)
		}
		takeover.recoverLeftover()
		if host.files[egressDNSResolvConf] != original || readTestJournal(t, takeover) != nil {
			t.Errorf("%s: resolv.conf %q after recovery", state, host.files[egressDNSResolvConf])
		}
	}

	host := newFakeDNSHost()
	host.fail["resolvectl revert specus0"] = "Failed to revert interface configuration: Access denied"
	takeover := newTestTakeover(t, host, "linux")
	journal := EgressDNSJournal{Version: 1, State: egressDNSJournalCommitted, Platform: egressDNSPlatformResolved,
		PID: 4242, Listen: "198.18.0.1", Tunnel: "specus0", Upstreams: []string{"1.1.1.1"}}
	if err := writeEgressDNSJournal(takeover.path, journal); err != nil {
		t.Fatal(err)
	}
	err := revertEgressDNSJournal(host, takeover.path, &journal, log.New(io.Discard, "", 0))
	if err == nil || !strings.Contains(err.Error(), "resolvectl revert specus0") || !strings.Contains(err.Error(), "Access denied") {
		t.Errorf("give-back error %v, want the failing step and its output", err)
	}
	if readTestJournal(t, takeover) == nil {
		t.Error("the journal of a failed give-back was deleted")
	}
	if got := host.commands(); !reflect.DeepEqual(got, []string{"resolvectl revert specus0", "resolvectl flush-caches"}) {
		t.Errorf("a failed step stopped the rest: %q", got)
	}
	// A takeover asked for while that journal is still there gives it back first rather than
	// writing over the only record of what the system had.
	if _, committed := takeover.engage(takeoverRequest(), flowEpoch); committed {
		t.Error("took over on top of a journal still to be given back")
	}
	if kept := readTestJournal(t, takeover); kept == nil || kept.PID != 4242 {
		t.Errorf("the unrestored journal was written over: %+v", kept)
	}

	// With the tunnel gone its link settings went with it: nothing to revert, and the journal
	// does not linger.
	gone := newFakeDNSHost()
	gone.links = map[string]bool{}
	path := filepath.Join(t.TempDir(), "journal.json")
	if err := writeEgressDNSJournal(path, journal); err != nil {
		t.Fatal(err)
	}
	if err := revertEgressDNSJournal(gone, path, &journal, log.New(io.Discard, "", 0)); err != nil {
		t.Errorf("give-back with the tunnel gone: %v", err)
	}
	if got := gone.commands(); !reflect.DeepEqual(got, []string{"resolvectl flush-caches"}) {
		t.Errorf("with the tunnel gone ran %q", got)
	}
}

// The network is compared at most every ten seconds, the first reading being the baseline.
func TestEgressDNSNetworkChangeIsSeenEveryTenSeconds(t *testing.T) {
	takeover := newTestTakeover(t, newFakeDNSHost(), "linux")
	network := "eth0|192.168.1.20"
	takeover.fingerprint = func() (string, error) { return network, nil }
	if takeover.networkChanged(flowEpoch) {
		t.Error("the first reading counted as a change")
	}
	network = "wlan0|10.0.0.7"
	if takeover.networkChanged(flowEpoch.Add(9 * time.Second)) {
		t.Error("compared again before ten seconds")
	}
	if !takeover.networkChanged(flowEpoch.Add(10 * time.Second)) {
		t.Error("a new network was not seen")
	}
	if takeover.networkChanged(flowEpoch.Add(20 * time.Second)) {
		t.Error("the same network counted as a change twice")
	}
	routes := []egressBindRoute{
		{Prefix: "0.0.0.0/0", Interface: "specus0", Usable: true},
		{Prefix: "0.0.0.0/0", Interface: "wlan0", Metric: 600, Usable: true},
		{Prefix: "0.0.0.0/0", Interface: "eth0", Metric: 100, Usable: true},
	}
	if got := egressDNSNetworkFingerprint(routes, "specus0", []uint32{0x0a000007, 0xc0a80114}); got != "eth0|10.0.0.7,192.168.1.20" {
		t.Errorf("fingerprint %q", got)
	}
}

// phaseTwoTakeoverHarness is a reconcile harness running phase two on a fake Linux with
// systemd-resolved, whose network is whatever the test says.
func phaseTwoTakeoverHarness(t *testing.T, host *fakeDNSHost) (*reconcileHarness, *string, *[]string) {
	t.Helper()
	local := &[]string{}
	harness := newPhaseTwoHarness(t, nil, phaseTwoRules()...)
	harness.mesh.egressLocalNetworks = func() []string { return *local }
	network := "eth0|192.168.1.20"
	harness.mesh.egressDNSHost = host
	harness.mesh.egressDNSPlatform = "linux"
	harness.mesh.egressDNSJournalPath = filepath.Join(t.TempDir(), "egress-dns-journal.json")
	harness.mesh.egressDNSTunnelAddresses = func(string) []string { return nil }
	harness.mesh.egressDNSFingerprint = func() (string, error) { return network, nil }
	return harness, &network, local
}

// The mesh takes the system DNS over once the pool's route is in, gives the responder the upstreams,
// reports it, and gives it back when it stops.
func TestMeshTakesTheSystemDNSOverAndGivesItBack(t *testing.T) {
	host := linuxResolvedHost()
	harness, _, _ := phaseTwoTakeoverHarness(t, host)
	harness.tick(0)
	if !contains(host.commands(), "resolvectl dns specus0 198.18.0.1") {
		t.Fatalf("no takeover: %q", host.commands())
	}
	section := mapSection(t, harness.mesh.egressStatusJSON(), "consumer")
	dns, _ := section["dns"].(map[string]any)
	upstreams, _ := dns["upstreams"].([]string)
	if dns["active"] != true || dns["takeover"] != true || dns["journal"] != egressDNSJournalCommitted ||
		!reflect.DeepEqual(upstreams, []string{"1.1.1.1", "192.168.1.1"}) {
		t.Errorf("dns = %v", dns)
	}
	if _, present := dns["code"]; present {
		t.Errorf("a takeover that holds carries a code: %v", dns)
	}

	harness.mesh.withdrawEgressRoutes()
	if !contains(host.commands(), "resolvectl revert specus0") {
		t.Errorf("stopping did not give the system DNS back: %q", host.commands())
	}
	if journal, _ := ReadEgressDNSJournal(harness.mesh.egressDNSJournalPath); journal != nil {
		t.Error("the journal outlived stopping")
	}
}

// Without the pool's route the takeover waits, saying why, and runs nothing.
func TestMeshWaitsForThePoolRouteBeforeTakingOver(t *testing.T) {
	host := linuxResolvedHost()
	harness, _, _ := phaseTwoTakeoverHarness(t, host)
	harness.commander.foreign["198.18.0.0/15"] = "198.18.0.0/15 dev other0"
	harness.tick(0)
	if len(host.commands()) != 0 {
		t.Errorf("ran %q without the pool's route", host.commands())
	}
	dns, _ := mapSection(t, harness.mesh.egressStatusJSON(), "consumer")["dns"].(map[string]any)
	if dns["active"] != true || dns["takeover"] != false || dns["code"] != egressCodeDNSTakeoverRefused ||
		dns["reason"] != egressDNSRefusedPoolRoute {
		t.Errorf("dns = %v", dns)
	}
}

// A new network gives the system DNS back and takes it again, reading the new network's servers; a
// new network over the pool stops phase two and gives it back for good.
func TestMeshRetakesTheSystemDNSOnANewNetwork(t *testing.T) {
	host := linuxResolvedHost()
	harness, network, local := phaseTwoTakeoverHarness(t, host)
	harness.tick(0)
	harness.tick(egressDNSNetworkCheck)
	before := len(host.commands())

	*network = "wlan0|10.0.0.7"
	host.outputs["resolvectl dns"] = "Global:\nLink 5 (wlan0): 10.0.0.1\n"
	harness.tick(egressDNSNetworkCheck)
	got := host.since(before)
	revert, retake := indexOf(got, "resolvectl revert specus0"), indexOf(got, "resolvectl dns specus0 198.18.0.1")
	if revert < 0 || retake < revert {
		t.Fatalf("on a new network ran %q, want give-back then takeover", got)
	}
	upstreams, _ := mapSection(t, harness.mesh.egressStatusJSON(), "consumer")["dns"].(map[string]any)["upstreams"].([]string)
	if !reflect.DeepEqual(upstreams, []string{"10.0.0.1"}) {
		t.Errorf("upstreams after the new network %q", upstreams)
	}

	before = len(host.commands())
	*network = "eth1|198.18.4.9"
	*local = []string{"198.18.4.0/24"}
	harness.tick(egressDNSNetworkCheck)
	if !contains(host.since(before), "resolvectl revert specus0") {
		t.Errorf("a network over the pool did not give the system DNS back: %q", host.since(before))
	}
	dns, _ := mapSection(t, harness.mesh.egressStatusJSON(), "consumer")["dns"].(map[string]any)
	if dns["active"] != false || dns["takeover"] != false || dns["code"] != egressCodeFakeIPPoolInvalid {
		t.Errorf("dns = %v", dns)
	}
	if !contains(harness.commander.removeLog, "198.18.0.0/15") {
		t.Errorf("the pool's route stayed: %v", harness.commander.removeLog)
	}
}

// A journal a killed process left is given back on the first reconcile, before this run takes over.
func TestMeshGivesBackAKilledProcessJournalFirst(t *testing.T) {
	host := newFakeDNSHost()
	host.fail["resolvectl dns"] = "no resolved"
	host.files[egressDNSResolvConf] = egressDNSResolvConfWritten
	harness, _, _ := phaseTwoTakeoverHarness(t, host)
	harness.mesh.config.PeerEgressDNSTakeover = false
	if err := writeEgressDNSJournal(harness.mesh.egressDNSJournalPath, EgressDNSJournal{Version: 1,
		State: egressDNSJournalCommitted, Platform: egressDNSPlatformResolvConf, PID: 4242, Listen: "198.18.0.1",
		Tunnel: "specus0", Upstreams: []string{"192.168.1.1"}, ResolvConf: "nameserver 192.168.1.1\n"}); err != nil {
		t.Fatal(err)
	}
	harness.tick(0)
	if host.files[egressDNSResolvConf] != "nameserver 192.168.1.1\n" {
		t.Errorf("resolv.conf %q: the killed process's takeover was not given back", host.files[egressDNSResolvConf])
	}
	if journal, _ := ReadEgressDNSJournal(harness.mesh.egressDNSJournalPath); journal != nil {
		t.Error("the killed process's journal is still there")
	}
}

func indexOf(list []string, want string) int {
	for index, entry := range list {
		if entry == want {
			return index
		}
	}
	return -1
}
