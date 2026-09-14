package client

import (
	"net/netip"
	"strconv"
	"strings"
)

// Reading what the platform's routing tools say.
//
// Kept free of build tags on purpose. These parsers are the part most likely to be wrong, because
// they depend on output formats nobody controls, and a Linux-only file would leave them untested
// everywhere the developer and most of CI actually run.

// egressRouteHop is where a bypass address has to be sent to stay off the tunnel.
type egressRouteHop struct {
	// Gateway is empty for an on-link destination, which is normal on a directly attached
	// network and is not a failure to parse.
	Gateway string
	Device  string
}

// parseIPRouteGet reads one `ip route get <address>` line.
//
// Two shapes matter. Through a router: "1.2.3.4 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 1000".
// Directly attached: "10.0.0.5 dev eth0 src 10.0.0.5". The second has no via, and treating that as
// a parse failure would refuse to bypass anything on the local network.
func parseIPRouteGet(output string) (egressRouteHop, bool) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// A destination that cannot be reached is reported as unreachable rather than as an
		// error, so it has to be recognised here or it would be read as a route.
		if fields[0] == "unreachable" || fields[0] == "prohibit" || fields[0] == "blackhole" {
			return egressRouteHop{}, false
		}
		var hop egressRouteHop
		for index := 0; index+1 < len(fields); index++ {
			switch fields[index] {
			case "via":
				hop.Gateway = fields[index+1]
			case "dev":
				hop.Device = fields[index+1]
			}
		}
		if hop.Device != "" {
			return hop, true
		}
	}
	return egressRouteHop{}, false
}

// parseIPRouteShowExact reads `ip route show exact <cidr>`.
//
// Empty output means no route for that exact prefix, which is what lets one be installed. Anything
// else is described back to the operator verbatim, because a summary of somebody else's routing is
// less useful to them than the line they can go and look at.
func parseIPRouteShowExact(output string) (bool, string) {
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			return true, trimmed
		}
	}
	return false, ""
}

// egressRouteHopIsDevice reports whether a hop leads through the named interface.
//
// Used to refuse pinning a bypass address to the tunnel itself. That happens on a reapply, once a
// rule's route is already installed and covers the address: asking the system where to send it then
// answers "through the tunnel", and installing that would route the tunnel's own transport into
// the tunnel.
// linuxShowMainTableArgs reads the main table, for a bypass hop `ip route get` could not give.
func linuxShowMainTableArgs() []string { return []string{"ip", "-4", "route", "show", "table", "main"} }

// linuxRouteLeadsNowhere are the route types that drop or refuse a packet. They stay candidates,
// with no interface, so the address they cover is not reached some other way.
var linuxRouteLeadsNowhere = map[string]bool{"blackhole": true, "unreachable": true, "prohibit": true, "throw": true}

// linuxRouteNotForwarding are the route types that are not a path out of the machine.
var linuxRouteNotForwarding = map[string]bool{"local": true, "broadcast": true, "anycast": true, "multicast": true, "nat": true}

// parseIPRouteTable reads `ip -4 route show table main` into candidate routes.
//
// Sampled rather than assumed, in network namespaces with a real TUN: the output lists a
// multipath route as its destination alone followed by indented nexthop lines, prints the lower of
// two metrics on one prefix first but means the metric, and ends every line with a space. The first
// nexthop of a multipath route is the one taken; one whose next hops cannot be read is not usable.
// A dead route is not usable; linkdown is, as the kernel uses it too.
//
// Shared vector: protocol/test-vectors/peer-egress-socket-binding-v1.json, linux.
func parseIPRouteTable(output string) []egressBindRoute {
	routes := make([]egressBindRoute, 0, 8)
	pending := -1
	var deviceless []int
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if fields[0] == "nexthop" && pending >= 0 && routes[pending].Interface == "" {
				for index := 1; index+1 < len(fields); index++ {
					switch fields[index] {
					case "via":
						if _, ok := parseEgressAddress(fields[index+1]); ok {
							routes[pending].Gateway = fields[index+1]
						}
					case "dev":
						routes[pending].Interface = fields[index+1]
					}
				}
			}
			continue
		}
		pending = -1
		nowhere := linuxRouteLeadsNowhere[fields[0]]
		if linuxRouteNotForwarding[fields[0]] {
			continue
		}
		if nowhere {
			fields = fields[1:]
			if len(fields) == 0 {
				continue
			}
		}
		prefix, ok := linuxRoutePrefix(fields[0])
		if !ok {
			continue
		}
		route := egressBindRoute{Prefix: prefix, Usable: true}
		for index := 1; index < len(fields); index++ {
			if fields[index] == "dead" {
				route.Usable = false
			}
			if index+1 >= len(fields) {
				continue
			}
			switch fields[index] {
			case "via":
				if _, ok := parseEgressAddress(fields[index+1]); ok {
					route.Gateway = fields[index+1]
				}
			case "dev":
				route.Interface = fields[index+1]
			case "metric":
				if metric, err := strconv.ParseInt(fields[index+1], 10, 64); err == nil {
					route.Metric = metric
				}
			}
		}
		if nowhere {
			route.Interface, route.Gateway = "", ""
		} else if route.Interface == "" {
			pending = len(routes)
			deviceless = append(deviceless, pending)
		}
		routes = append(routes, route)
	}
	for _, index := range deviceless {
		if routes[index].Interface == "" {
			routes[index].Usable = false
		}
	}
	return routes
}

func linuxRoutePrefix(text string) (string, bool) {
	if text == "default" {
		return "0.0.0.0/0", true
	}
	if !strings.Contains(text, "/") {
		text += "/32"
	}
	prefix, err := netip.ParsePrefix(text)
	if err != nil || !prefix.Addr().Is4() {
		return "", false
	}
	return prefix.Masked().String(), true
}

func egressRouteHopIsDevice(hop egressRouteHop, device string) bool {
	return device != "" && strings.EqualFold(strings.TrimSpace(hop.Device), strings.TrimSpace(device))
}
