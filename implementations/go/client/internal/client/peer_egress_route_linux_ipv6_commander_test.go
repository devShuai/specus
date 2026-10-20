//go:build linux

package client

import (
	"errors"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// The IPv6 counterparts of the Linux commander and device tests, in the same namespace and under the
// same gate (SPECUS_ROUTE_MUTATION_TEST=1 inside `unshare -n`): the IPv6 data plane's routes and the
// TUN's derived address, through the real `ip -6` and a real TUN.

var (
	linuxMutationSetup6     sync.Once
	linuxMutationSetup6Fail string
)

// linuxMutationNamespace6 adds IPv6 to the namespace: an address on eth0, a default route through a
// link-local gateway as a router advertisement would leave it, and a blackhole.
func linuxMutationNamespace6(t *testing.T) {
	t.Helper()
	linuxMutationNamespace(t)
	linuxMutationSetup6.Do(func() {
		for _, step := range [][]string{
			{"ip", "-6", "addr", "add", "2001:db8:64::7/64", "dev", "eth0", "nodad"},
			{"ip", "-6", "route", "add", "default", "via", "fe80::1", "dev", "eth0"},
			{"ip", "-6", "route", "add", "blackhole", "2001:db8:dead::/48"},
		} {
			if output, err := exec.Command(step[0], step[1:]...).CombinedOutput(); err != nil {
				linuxMutationSetup6Fail = strings.Join(step, " ") + ": " + err.Error() + ": " + string(output)
				return
			}
		}
	})
	if linuxMutationSetup6Fail != "" {
		t.Fatal(linuxMutationSetup6Fail)
	}
}

func TestLinuxCommanderInstallsAnIPv6BypassUnderItsOwnTunnelRoute(t *testing.T) {
	linuxMutationNamespace6(t)
	commander := newLinuxEgressRouteCommander("specus0")
	rule := egressRoute{CIDR: "2001:db8:1::/48", Kind: egressRouteToTun, Origin: "rule:2001:db8:1::/48"}
	bypass := egressRoute{CIDR: "2001:db8:1::9/128", Kind: egressRouteBypass, Origin: "bypass"}

	if err := commander.Install(rule); err != nil {
		t.Fatalf("install the rule's route: %v", err)
	}
	if hop, ok := parseIPRouteGet(linuxRouteOutput(t, "-6", "route", "get", "2001:db8:1::9")); !ok || hop.Device != "specus0" {
		t.Fatalf("precondition: ip -6 route get answered %+v (ok=%v), want the tunnel", hop, ok)
	}
	if err := commander.Install(bypass); err != nil {
		t.Fatalf("install the bypass: %v", err)
	}
	if installed := linuxRouteOutput(t, "-6", "route", "show", "exact", "2001:db8:1::9/128"); !strings.Contains(installed, "via fe80::1 dev eth0") {
		t.Errorf("bypass is %q, want via fe80::1 dev eth0", strings.TrimSpace(installed))
	}
	if hop, ok := parseIPRouteGet(linuxRouteOutput(t, "-6", "route", "get", "2001:db8:1::9")); !ok || hop.Device != "eth0" {
		t.Errorf("after the bypass ip -6 route get answers %+v, want eth0", hop)
	}

	// The table this feature reads sees both, written as it writes them.
	table, tunnel, err := commander.Table6()
	if err != nil || tunnel != "specus0" {
		t.Fatalf("Table6: %v %q", err, tunnel)
	}
	if drifts := egressRouteDrifts([]egressRoute{bypass, rule}, table, tunnel); len(drifts) != 0 {
		t.Errorf("drift in a table with both routes as installed: %+v", drifts)
	}

	if err := commander.Remove(bypass); err != nil {
		t.Errorf("remove the bypass: %v", err)
	}
	if err := commander.Remove(rule); err != nil {
		t.Errorf("remove the rule's route: %v", err)
	}
	if left := linuxRouteOutput(t, "-6", "route", "show", "exact", "2001:db8:1::9/128") +
		linuxRouteOutput(t, "-6", "route", "show", "exact", "2001:db8:1::/48"); strings.TrimSpace(left) != "" {
		t.Errorf("routes left behind: %q", left)
	}
}

func TestLinuxCommanderRepairsIPv6RoutesTheTableLost(t *testing.T) {
	linuxMutationNamespace6(t)
	installer := newEgressRouteInstaller(newLinuxEgressRouteCommander("specus0"), journalPath(t))
	rule := egressRoute{CIDR: "2001:db8:2::/48", Kind: egressRouteToTun, Origin: "rule:2001:db8:2::/48"}
	bypass := egressRoute{CIDR: "2001:db8:2::9/128", Kind: egressRouteBypass, Origin: "bypass"}
	rule4 := egressRoute{CIDR: "203.0.113.0/24", Kind: egressRouteToTun, Origin: "rule:203.0.113.0/24"}
	if result := installer.apply([]egressRoute{bypass, rule, rule4}); result.Err != nil || len(result.Added) != 3 {
		t.Fatalf("apply: %+v", result)
	}
	defer installer.withdrawAll()

	if healthy := installer.repair(); healthy.TableErr != nil || len(healthy.Repaired) != 0 {
		t.Fatalf("a table with everything in it: %+v", healthy)
	}
	linuxRouteOutput(t, "-6", "route", "del", "2001:db8:2::/48")
	linuxRouteOutput(t, "-6", "route", "del", "2001:db8:2::9/128")

	result := installer.repair()
	if result.TableErr != nil || result.Err != nil || len(result.Repaired) != 2 || len(result.Lost) != 0 {
		t.Fatalf("repair: %+v", result)
	}
	if got := linuxRouteOutput(t, "-6", "route", "show", "exact", "2001:db8:2::/48"); !strings.Contains(got, "dev specus0") {
		t.Errorf("the rule's route is %q after the repair", strings.TrimSpace(got))
	}
	if got := linuxRouteOutput(t, "-6", "route", "show", "exact", "2001:db8:2::9/128"); !strings.Contains(got, "via fe80::1 dev eth0") {
		t.Errorf("the bypass is %q after the repair", strings.TrimSpace(got))
	}
	if again := installer.repair(); len(again.Repaired) != 0 {
		t.Errorf("a second repair found more to do: %+v", again)
	}
}

func TestLinuxCommanderRefusesAnIPv6BypassOnlyABlackholeWouldCarry(t *testing.T) {
	linuxMutationNamespace6(t)
	commander := newLinuxEgressRouteCommander("specus0")
	rule := egressRoute{CIDR: "2001:db8:dead::/49", Kind: egressRouteToTun, Origin: "rule:2001:db8:dead::/49"}
	if err := commander.Install(rule); err != nil {
		t.Fatalf("install the rule's route: %v", err)
	}
	defer func() { _ = commander.Remove(rule) }()

	err := commander.Install(egressRoute{CIDR: "2001:db8:dead::9/128", Kind: egressRouteBypass, Origin: "bypass"})
	if !errors.Is(err, errEgressNoPhysicalRoute) {
		t.Fatalf("install error = %v, want the no-physical-route refusal", err)
	}
	if left := linuxRouteOutput(t, "-6", "route", "show", "exact", "2001:db8:dead::9/128"); strings.TrimSpace(left) != "" {
		t.Errorf("a bypass was installed anyway: %q", left)
	}
}

func TestLinuxCommanderReportsSomebodyElsesIPv6Route(t *testing.T) {
	linuxMutationNamespace6(t)
	linuxRouteOutput(t, "-6", "route", "add", "2001:db8:5::/48", "dev", "eth0")
	defer exec.Command("ip", "-6", "route", "del", "2001:db8:5::/48").Run()
	commander := newLinuxEgressRouteCommander("specus0")
	conflict, existing := commander.Conflict(egressRoute{CIDR: "2001:db8:5::/48", Kind: egressRouteToTun})
	if !conflict || !strings.HasPrefix(existing, "2001:db8:5::/48 dev eth0") {
		t.Errorf("conflict = %v %q", conflict, existing)
	}
	if conflict, existing := commander.Conflict(egressRoute{CIDR: "2001:db8:6::/48", Kind: egressRouteToTun}); conflict {
		t.Errorf("a free prefix conflicted: %q", existing)
	}
}

// The device takes its derived address, and a socket that sends to a destination routed into it
// leaves with that address as its source: what the data plane's source check expects.
func TestLinuxTunDeviceTakesItsDerivedIPv6Address(t *testing.T) {
	linuxMutationNamespace6(t)
	if !egressPlatformCarriesIPv6 {
		t.Skip("this build has no IPv6 data plane")
	}
	const virtual = "100.96.0.43"
	device := newPlatformPeerVirtualDevice(
		Config{PeerMeshTunName: "specustest6", PeerMeshMTU: 1280, PeerMeshDevice: "auto", PeerEgressEnabled: true},
		PeerMeshConfig{VirtualIP: virtual, CIDR: "100.96.0.0/11"},
		log.New(testLogWriter{t}, "", 0),
	)
	packets := make(chan []byte, 32)
	stop := make(chan struct{})
	if err := device.Start(stop, func(packet []byte) {
		select {
		case packets <- packet:
		default:
		}
	}); err != nil {
		t.Fatalf("start the device: %v", err)
	}
	defer func() {
		close(stop)
		_ = device.Close()
	}()

	if ready, reason := device.(peerVirtualDeviceIPv6).IPv6Ready(); !ready {
		t.Fatalf("the device does not report carrying IPv6: %s", reason)
	}
	derived, _ := egressDeviceAddress6(virtual)
	address := formatEgressAddress6(derived)
	if shown := linuxRouteOutput(t, "-6", "address", "show", "dev", device.Name()); !strings.Contains(shown, address+"/128") {
		t.Fatalf("the device's addresses are %q, want %s/128", shown, address)
	}
	if link := linuxRouteOutput(t, "link", "show", "dev", device.Name()); !strings.Contains(link, "mtu 1280") {
		t.Errorf("the device's link is %q, want mtu 1280", link)
	}
	commander := newLinuxEgressRouteCommander(device.Name())
	rule := egressRoute{CIDR: "2001:db8:7::/48", Kind: egressRouteToTun, Origin: "rule:2001:db8:7::/48"}
	if err := commander.Install(rule); err != nil {
		t.Fatalf("route the prefix into the device: %v", err)
	}
	defer func() { _ = commander.Remove(rule) }()

	destination := net.ParseIP("2001:db8:7::1")
	go func() {
		for range 3 {
			if conn, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: destination, Port: 9}); err == nil {
				_, _ = conn.Write([]byte("ipv6"))
				_ = conn.Close()
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case packet := <-packets:
			if len(packet) < ipv6HeaderLen || packet[0]>>4 != 6 || !net.IP(packet[24:40]).Equal(destination) {
				continue
			}
			if source := [16]byte(packet[8:24]); source != derived {
				t.Fatalf("the packet left with source %s, want the derived %s", net.IP(source[:]), address)
			}
			return
		case <-deadline:
			t.Fatalf("no IPv6 packet to %s came out of the device; status=%s err=%s", destination, device.Status(), device.Error())
		}
	}
}

// On a TUN where IPv6 is disabled the address cannot be assigned: the device stays up for IPv4 and
// reports no IPv6 data plane, with the kernel's reason.
func TestLinuxTunDeviceWithoutIPv6ReportsNoIPv6DataPlane(t *testing.T) {
	linuxMutationNamespace6(t)
	if !egressPlatformCarriesIPv6 {
		t.Skip("this build has no IPv6 data plane")
	}
	const sysctl = "/proc/sys/net/ipv6/conf/default/disable_ipv6"
	if err := os.WriteFile(sysctl, []byte("1"), 0o644); err != nil {
		t.Skipf("cannot disable IPv6 for new interfaces here: %v", err)
	}
	defer func() { _ = os.WriteFile(sysctl, []byte("0"), 0o644) }()

	device := newPlatformPeerVirtualDevice(
		Config{PeerMeshTunName: "specustest6x", PeerMeshMTU: 1280, PeerMeshDevice: "auto", PeerEgressEnabled: true},
		PeerMeshConfig{VirtualIP: "100.96.0.44", CIDR: "100.96.0.0/11"},
		log.New(testLogWriter{t}, "", 0),
	)
	stop := make(chan struct{})
	if err := device.Start(stop, func([]byte) {}); err != nil {
		t.Fatalf("the device did not come up for IPv4: %v", err)
	}
	defer func() {
		close(stop)
		_ = device.Close()
	}()
	if status := device.Status(); status != "UP" {
		t.Errorf("status = %s (%s)", status, device.Error())
	}
	ready, reason := device.(peerVirtualDeviceIPv6).IPv6Ready()
	if ready || !strings.Contains(reason, "could not be assigned") {
		t.Errorf("IPv6Ready = %v %q", ready, reason)
	}
	if shown := linuxRouteOutput(t, "-4", "address", "show", "dev", device.Name()); !strings.Contains(shown, "100.96.0.44/32") {
		t.Errorf("the IPv4 address is missing: %q", shown)
	}
}
