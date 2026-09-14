package client

import (
	"encoding/binary"
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

// macosBindTableLifetime is how long one read of the table answers for.
//
// The choice is made on every connect and a read costs 25 ms, so a page opening twenty connections
// would otherwise spend half a second asking. The tunnel's own routes are left out of the choice
// anyway, so the only change a cached table can miss is a physical one, and a connect that misses it
// fails rather than leaking.
const macosBindTableLifetime = 2 * time.Second

func macosBindRoutes(table string) []egressBindRoute {
	rows := parseMacosRouteTable(table)
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

// macosBoundInterfaceOption is the IP_BOUND_IF value: the index as a host-order int.
func macosBoundInterfaceOption(index uint32) []byte {
	var value [4]byte
	binary.NativeEndian.PutUint32(value[:], index)
	return value[:]
}
