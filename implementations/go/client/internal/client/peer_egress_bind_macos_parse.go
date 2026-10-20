package client

import (
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Candidate routes for binding an egress socket on macOS, from the same `netstat -rn -f inet` the
// route commander reads.
//
// Not named _darwin.go, for the reason peer_egress_route_macos_parse.go gives: the shared vectors
// drive it on every platform.

// macosScopedFlag marks a route scoped to its interface. The kernel only uses such a route for a
// socket already bound to that interface, so for choosing one it is not a candidate.
const macosScopedFlag = "I"

// macosIPBoundIf is IP_BOUND_IF, at level IPPROTO_IP.
const macosIPBoundIf = 25

// macosIPv6BoundIf is IPV6_BOUND_IF, at level IPPROTO_IPV6. Its value is the index in host order,
// like IP_BOUND_IF's.
const macosIPv6BoundIf = 125

// macosBindTableLifetime is how long one read of the table answers for.
//
// The choice is made on every connect and a read costs 25 ms, so a page opening twenty connections
// would otherwise spend half a second asking. The tunnel's own routes are left out of the choice
// anyway, so the only change a cached table can miss is a physical one, and a connect that misses it
// fails rather than leaking.
const macosBindTableLifetime = 2 * time.Second

// macosGatewayFlag marks a route whose Gateway column is a gateway (RTF_GATEWAY). Without it the
// column says where the interface is: link#N, a MAC address, an interface name, or the address of a
// loopback or point-to-point peer -- 127 prints 127.0.0.1 there.
const macosGatewayFlag = "G"

func macosBindRoutes(table string) []egressBindRoute {
	rows := parseMacosRouteTable(table)
	routes := make([]egressBindRoute, 0, len(rows))
	for _, row := range rows {
		route := egressBindRoute{
			Prefix:    row.Prefix,
			Interface: row.Netif,
			Usable:    !strings.Contains(row.Flags, macosScopedFlag),
		}
		if strings.Contains(row.Flags, macosGatewayFlag) {
			if _, ok := parseEgressAddress(row.Gateway); ok {
				route.Gateway = row.Gateway
			}
		}
		routes = append(routes, route)
	}
	return routes
}

// macosShowTableArgs6 reads the IPv6 table, for a socket to an IPv6 target.
func macosShowTableArgs6() []string {
	return []string{"netstat", "-rn", "-f", "inet6"}
}

// macosBindRoutes6 reads the candidate routes of `netstat -rn -f inet6`, with the same rule as IPv4:
// a route scoped to its interface is not one an unbound socket would follow.
//
// No gateway is kept. Bypass routes, the only reader of it, are IPv4 for now, and an IPv6 gateway
// is usually link-local, meaningful only with the zone this reading drops.
func macosBindRoutes6(table string) []egressBindRoute {
	rows := parseMacosRouteTable6(table)
	routes := make([]egressBindRoute, 0, len(rows))
	for _, row := range rows {
		routes = append(routes, egressBindRoute{
			Prefix:    row.Prefix,
			Interface: row.Netif,
			Usable:    !strings.Contains(row.Flags, macosScopedFlag),
		})
	}
	return routes
}

// parseMacosRouteTable6 reads the rows under the "Internet6:" heading of `netstat -rn`, the IPv6
// counterpart of parseMacosRouteTable. Rows whose destination does not read as IPv6 are skipped.
func parseMacosRouteTable6(stdout string) []macosRoute {
	var routes []macosRoute
	inside := false
	for _, line := range strings.Split(stdout, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, " ") {
			inside = trimmed == "Internet6:"
			continue
		}
		if !inside || strings.HasPrefix(trimmed, "Destination") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 4 {
			continue
		}
		prefix := normaliseMacosPrefix6(fields[0])
		if prefix == "" {
			continue
		}
		routes = append(routes, macosRoute{
			Prefix:      prefix,
			Destination: fields[0],
			Gateway:     fields[1],
			Flags:       fields[2],
			Netif:       fields[3],
		})
	}
	return routes
}

// normaliseMacosPrefix6 turns a destination of the IPv6 table into a canonical prefix, or "" when it
// is not one. netstat writes "default" for ::/0, a host route without a length, and a link-local
// destination with its zone: fe80::%lo0/64, fe80::1%lo0. The zone goes; the interface is in the
// Netif column anyway.
func normaliseMacosPrefix6(text string) string {
	value := strings.TrimSpace(text)
	if value == "default" {
		return "::/0"
	}
	address, length, hasLength := strings.Cut(value, "/")
	if zone := strings.IndexByte(address, '%'); zone >= 0 {
		address = address[:zone]
	}
	parsed, err := netip.ParseAddr(address)
	if err != nil || !parsed.Is6() {
		return ""
	}
	bits := 128
	if hasLength {
		number, err := strconv.Atoi(length)
		if err != nil || number < 0 || number > 128 || strconv.Itoa(number) != length {
			return ""
		}
		bits = number
	}
	return netip.PrefixFrom(parsed, bits).Masked().String()
}

// macosBoundInterfaceOption is the IP_BOUND_IF value: the index as a host-order int.
func macosBoundInterfaceOption(index uint32) []byte {
	var value [4]byte
	binary.NativeEndian.PutUint32(value[:], index)
	return value[:]
}
