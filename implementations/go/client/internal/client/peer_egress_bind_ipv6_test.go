package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

// Binding egress sockets to IPv6 targets (protocol/spec/peer-egress.md, IPv6 数据面, 出站 socket), from
// synthetic tables on every platform. The choice and the option encodings are not in
// peer-egress-socket-binding-v1.json yet; the real-table and real-socket halves are in
// peer_egress_bind_windows_test.go and peer_egress_bind_socket_test.go.

// The IPv6 choice follows the IPv4 rules -- longest prefix, then metric, then the route listed
// first, the tunnel and unusable routes left out -- and never mixes the families.
func TestEgressBindSelectsIPv6RoutesByTheSameRules(t *testing.T) {
	routes := []egressBindRoute{
		{Prefix: "0.0.0.0/0", Interface: "4", Usable: true},
		{Prefix: "::/0", Interface: "3", Metric: 50, Usable: true},
		{Prefix: "::/0", Interface: "5", Metric: 20, Usable: true},
		{Prefix: "2001:db8::/32", Interface: "6", Metric: 99, Usable: true},
		{Prefix: "2001:db8:1::/48", Interface: "tun", Usable: true},
		{Prefix: "2001:db8:2::/48", Interface: "7", Usable: false},
		{Prefix: "2001:db8:3::/48", Interface: "8", Metric: 5, Usable: true},
		{Prefix: "2001:db8:3::/48", Interface: "9", Metric: 5, Usable: true},
	}
	for destination, want := range map[string]string{
		"2400:cb00::1":    "5", // the default with the lower metric
		"2001:db8:9::1":   "6", // a longer prefix beats a lower metric
		"2001:db8:1::c8":  "6", // the tunnel's /48 is left out
		"2001:db8:2::1":   "6", // so is an unusable route
		"2001:db8:3::1":   "8", // a full tie keeps the route listed first
		"203.0.113.10":    "4", // an IPv4 destination sees only IPv4 routes
		"::ffff:10.0.0.1": "",  // an IPv4-mapped destination is neither
		"fe80::1%eth0":    "",  // nor is a zoned one
	} {
		chosen, ok := selectEgressBindInterface(routes, "tun", destination)
		if want == "" {
			if ok {
				t.Errorf("%s: chose %s, want no route", destination, chosen)
			}
			continue
		}
		if !ok || chosen != want {
			t.Errorf("%s: chose %q (found %v), want %s", destination, chosen, ok, want)
		}
	}
	// ::/0 does not cover an IPv4 destination, nor 0.0.0.0/0 an IPv6 one.
	if _, ok := selectEgressBindInterface([]egressBindRoute{{Prefix: "::/0", Interface: "3", Usable: true}}, "", "203.0.113.10"); ok {
		t.Error("an IPv6 default route was chosen for an IPv4 destination")
	}
	if _, ok := selectEgressBindInterface([]egressBindRoute{{Prefix: "0.0.0.0/0", Interface: "4", Usable: true}}, "", "2001:db8::1"); ok {
		t.Error("an IPv4 default route was chosen for an IPv6 destination")
	}
}

// The binder reads the table of the target's family, and with nothing outside the tunnel refuses the
// dial as it does for IPv4, rather than leaving the socket unbound.
func TestEgressBinderChoosesFromTheTargetsFamily(t *testing.T) {
	binder := &egressSocketBinder{
		tunnel:    func() string { return "utun3" },
		tunnelKey: func(name string) string { return name },
		routes: func() ([]egressBindRoute, error) {
			return []egressBindRoute{{Prefix: "0.0.0.0/0", Interface: "en0", Usable: true}}, nil
		},
		routes6: func() ([]egressBindRoute, error) {
			return []egressBindRoute{
				{Prefix: "::/0", Interface: "en1", Usable: true},
				{Prefix: "2001:db8:1::/48", Interface: "utun3", Usable: true},
			}, nil
		},
	}
	for address, want := range map[string]string{
		"203.0.113.10:443":   "en0",
		"[2001:db8::10]:443": "en1",
		// The tunnel's own route covers it, so the default outside the tunnel is what is left.
		"[2001:db8:1::c8]:443": "en1",
	} {
		chosen, err := binder.choose(address)
		if err != nil || chosen != want {
			t.Errorf("%s: chose %q (%v), want %s", address, chosen, err, want)
		}
	}

	binder.routes6 = func() ([]egressBindRoute, error) {
		return []egressBindRoute{{Prefix: "::/0", Interface: "utun3", Usable: true}}, nil
	}
	if _, err := binder.choose("[2001:db8::10]:443"); !errors.Is(err, errEgressNoPhysicalRoute) {
		t.Errorf("only the tunnel leads there: err = %v, want the no-physical-route refusal", err)
	}
	// An IPv4-mapped target goes through the IPv4 table, where nothing contains it.
	if _, err := binder.choose("[::ffff:203.0.113.10]:443"); !errors.Is(err, errEgressNoPhysicalRoute) {
		t.Errorf("an IPv4-mapped target: err = %v, want the no-physical-route refusal", err)
	}
	binder.routes6 = nil
	if _, err := binder.choose("[2001:db8::10]:443"); err == nil {
		t.Error("a binder without an IPv6 table reader chose an interface for an IPv6 target")
	}
}

// windowsForwardRow6 writes one MIB_IPFORWARD_ROW2 the way GetIpForwardTable2(AF_INET6) lays it out.
func windowsForwardRow6(index uint32, prefix string, nextHop string, metric uint32) []byte {
	row := make([]byte, windowsForwardRowSize)
	parsed := netip.MustParsePrefix(prefix)
	binary.LittleEndian.PutUint32(row[windowsForwardInterfaceIndex:], index)
	binary.LittleEndian.PutUint16(row[windowsForwardPrefixFamily:], windowsAddressFamilyIPv6)
	address := parsed.Addr().As16()
	copy(row[windowsForwardPrefixAddress6:], address[:])
	row[windowsForwardPrefixLength] = byte(parsed.Bits())
	binary.LittleEndian.PutUint16(row[windowsForwardNextHopFamily:], windowsAddressFamilyIPv6)
	hop := netip.MustParseAddr(nextHop).As16()
	copy(row[windowsForwardNextHopAddress6:], hop[:])
	binary.LittleEndian.PutUint32(row[windowsForwardMetric:], metric)
	return row
}

func windowsInterfaceRow6(family uint16, index uint32, metric uint32, connected bool, disableDefault bool) []byte {
	row := make([]byte, windowsInterfaceRowSize)
	binary.LittleEndian.PutUint16(row[windowsInterfaceFamily:], family)
	binary.LittleEndian.PutUint32(row[windowsInterfaceIndex:], index)
	binary.LittleEndian.PutUint32(row[windowsInterfaceMetric:], metric)
	if connected {
		row[windowsInterfaceConnected] = 1
	}
	if disableDefault {
		row[windowsInterfaceDisableDefaultRoutes] = 1
	}
	return row
}

func windowsMibTable(rows ...[]byte) []byte {
	table := make([]byte, windowsMibTableHeader)
	binary.LittleEndian.PutUint32(table, uint32(len(rows)))
	for _, row := range rows {
		table = append(table, row...)
	}
	return table
}

// The IPv6 rows of the two Windows tables: the address eight bytes into its SOCKADDR_IN6, a length up
// to 128, each interface's IPv6 row on its own, and DisableDefaultRoutes applied to ::/0.
func TestWindowsIPv6BindTablesParse(t *testing.T) {
	ipv4Row := make([]byte, windowsForwardRowSize)
	binary.LittleEndian.PutUint16(ipv4Row[windowsForwardPrefixFamily:], windowsAddressFamilyIPv4)
	tooLong := windowsForwardRow6(3, "2001:db8::/64", "::", 0)
	tooLong[windowsForwardPrefixLength] = 129
	hostBits := windowsForwardRow6(3, "2001:db8:5::/64", "::", 7)
	hostBits[windowsForwardPrefixAddress6+15] = 1

	forward, ok := parseWindowsForwardTable6(windowsMibTable(
		windowsForwardRow6(3, "::/0", "fe80::1", 0),
		windowsForwardRow6(3, "2001:db8::/32", "::", 256),
		windowsForwardRow6(1, "::1/128", "::", 256),
		windowsForwardRow6(7, "2001:db8:7::/48", "::", 16),
		windowsForwardRow6(9, "::/0", "fe80::9", 0),
		windowsForwardRow6(11, "2001:db8:11::/48", "::", 0),
		ipv4Row, tooLong, hostBits,
	))
	if !ok {
		t.Fatal("the forward table did not parse")
	}
	interfaces, ok := parseWindowsInterfaceTable6(windowsMibTable(
		windowsInterfaceRow6(windowsAddressFamilyIPv4, 3, 99, true, false),
		windowsInterfaceRow6(windowsAddressFamilyIPv6, 3, 20, true, false),
		windowsInterfaceRow6(windowsAddressFamilyIPv6, 1, 75, true, false),
		windowsInterfaceRow6(windowsAddressFamilyIPv6, 7, 5, false, false),
		windowsInterfaceRow6(windowsAddressFamilyIPv6, 9, 1, true, true),
	))
	if !ok || len(interfaces) != 4 {
		t.Fatalf("the interface table did not parse to its four IPv6 rows: %+v", interfaces)
	}
	routes := windowsBindRoutes(forward, interfaces)
	want := []egressBindRoute{
		{Prefix: "::/0", Interface: "3", Gateway: "fe80::1", Metric: 20, Usable: true},
		{Prefix: "2001:db8::/32", Interface: "3", Metric: 276, Usable: true},
		{Prefix: "::1/128", Interface: "1", Metric: 331, Usable: true},
		{Prefix: "2001:db8:7::/48", Interface: "7", Metric: 21, Usable: false},
		{Prefix: "::/0", Interface: "9", Gateway: "fe80::9", Metric: 1, Usable: false},
		{Prefix: "2001:db8:11::/48", Interface: "11", Usable: false},
		{Prefix: "2001:db8:5::/64", Interface: "3", Metric: 27, Usable: true},
	}
	if len(routes) != len(want) {
		t.Fatalf("routes = %+v, want %+v", routes, want)
	}
	for index := range want {
		if routes[index] != want[index] {
			t.Errorf("route %d = %+v, want %+v", index, routes[index], want[index])
		}
	}
	if chosen, ok := selectEgressBindInterface(routes, "", "2400:cb00::1"); !ok || chosen != "3" {
		t.Errorf("a public target chose %q, want 3", chosen)
	}
	// The IPv4 reader of the same bytes finds nothing of its own.
	if rows, _ := parseWindowsForwardTable(windowsMibTable(windowsForwardRow6(3, "::/0", "::", 0))); len(rows) != 0 {
		t.Errorf("the IPv4 reader took an IPv6 row: %+v", rows)
	}
}

// IPV6_UNICAST_IF takes the index in host order, the opposite of IP_UNICAST_IF.
func TestWindowsIPv6UnicastOptionIsHostOrder(t *testing.T) {
	var host [4]byte
	binary.NativeEndian.PutUint32(host[:], 12)
	if got := windowsUnicastInterfaceOption6(12); !bytes.Equal(got, host[:]) {
		t.Errorf("IPV6_UNICAST_IF value = %x, want %x", got, host)
	}
	if bytes.Equal(windowsUnicastInterfaceOption6(12), windowsUnicastInterfaceOption(12)) &&
		binary.NativeEndian.Uint16([]byte{1, 0}) == 1 {
		t.Error("the IPv6 option is encoded like the IPv4 one, in network order")
	}
	if windowsIPv6UnicastIf != 31 || macosIPv6BoundIf != 125 {
		t.Errorf("option numbers = %d, %d, want 31 and 125", windowsIPv6UnicastIf, macosIPv6BoundIf)
	}
}

// netstat -rn on macOS, both sections. Only "Internet6:" is read, destinations normalised -- default,
// host routes without a length, zones dropped -- and a route scoped to its interface is not a
// candidate.
func TestMacosIPv6BindRoutes(t *testing.T) {
	table := `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
127                127.0.0.1          UCS                   lo0

Internet6:
Destination                             Gateway                                 Flags               Netif Expire
default                                 fe80::%utun0                            UGcIg               utun0
default                                 fe80::1%en0                             UGcg                  en0
::1                                     ::1                                     UHL                   lo0
2001:db8:1::/64                         link#6                                  UC                    en0
2001:db8:1::1                           a4:83:e7:0:0:1                          UHLWIi                en0
fe80::%lo0/64                           fe80::1%lo0                             UcI                   lo0
fe80::1%lo0                             link#1                                  UHLI                  lo0
ff00::/8                                ::1                                     UmCI                  lo0
2001:db8:2::/48                         utun4                                   USc                 utun4
`
	routes := macosBindRoutes6(table)
	want := []egressBindRoute{
		{Prefix: "::/0", Interface: "utun0", Usable: false},
		{Prefix: "::/0", Interface: "en0", Usable: true},
		{Prefix: "::1/128", Interface: "lo0", Usable: true},
		{Prefix: "2001:db8:1::/64", Interface: "en0", Usable: true},
		{Prefix: "2001:db8:1::1/128", Interface: "en0", Usable: false},
		{Prefix: "fe80::/64", Interface: "lo0", Usable: false},
		{Prefix: "fe80::1/128", Interface: "lo0", Usable: false},
		{Prefix: "ff00::/8", Interface: "lo0", Usable: false},
		{Prefix: "2001:db8:2::/48", Interface: "utun4", Usable: true},
	}
	if len(routes) != len(want) {
		t.Fatalf("routes = %+v, want %+v", routes, want)
	}
	for index := range want {
		if routes[index] != want[index] {
			t.Errorf("route %d = %+v, want %+v", index, routes[index], want[index])
		}
	}
	for destination, wantInterface := range map[string]string{
		"2400:cb00::1":   "en0",
		"2001:db8:2::10": "en0", // utun4 is this node's tunnel
		"::1":            "lo0",
	} {
		if chosen, ok := selectEgressBindInterface(routes, "utun4", destination); !ok || chosen != wantInterface {
			t.Errorf("%s: chose %q, want %s", destination, chosen, wantInterface)
		}
	}
	for text, want := range map[string]string{
		"default": "::/0", "2001:DB8::/32": "2001:db8::/32", "2001:db8::1/64": "2001:db8::/64",
		"fe80::%en0/64": "fe80::/64", "192.168.1": "", "2001:db8::/129": "", "2001:db8::/064": "", "link#6": "",
	} {
		if got := normaliseMacosPrefix6(text); got != want {
			t.Errorf("%q normalised to %q, want %q", text, got, want)
		}
	}
	if args := macosShowTableArgs6(); len(args) != 4 || args[3] != "inet6" {
		t.Errorf("the IPv6 table is read with %v", args)
	}
}
