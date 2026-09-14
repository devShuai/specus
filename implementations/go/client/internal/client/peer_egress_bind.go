package client

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Keeping the egress's own forwarded traffic off the tunnel.
//
// The egress opens a real socket to the target on a consumer's behalf. If that socket followed this
// node's own tunnel routes -- which a node that is also a consumer has, for its own rules -- the
// forwarded traffic would go back into the mesh instead of out of the machine.
//
// On Windows and macOS the socket is bound to the interface the operating system would have picked
// had the tunnel's routes not been there: IP_UNICAST_IF and IP_BOUND_IF. Neither needs elevation,
// and the stack enforces both -- bound to an interface with no route to the destination, connect
// fails rather than leaving by another one. That is also why the interface has to be chosen per
// destination: binding everything to the default route's interface would break every target
// reached through a second NIC or another VPN.
//
// On Linux the socket is marked instead, and a policy routing rule does the steering; see
// peer_egress_bind_linux.go.
//
// The choice and the table readings are pinned by protocol/test-vectors/peer-egress-socket-binding-v1.json.

// errEgressNoPhysicalRoute is returned when nothing but the tunnel leads to a destination.
//
// The dial is refused rather than left unbound, because an unbound socket is exactly the one that
// would follow the tunnel route.
var errEgressNoPhysicalRoute = errors.New("no route outside the tunnel")

// egressBindRoute is one route considered for the interface an egress socket is bound to.
type egressBindRoute struct {
	Prefix string
	// Interface is the decimal interface index on Windows and the interface name on macOS.
	Interface string
	// Metric is the effective metric: on Windows the route's plus its interface's, on macOS zero.
	Metric int64
	// Usable is false for a route the system would not use for an unbound socket: one on a
	// disconnected interface, a default route on an interface that disables default routes, or a
	// macOS route scoped to its interface.
	Usable bool
}

// selectEgressBindInterface picks the interface for a socket to destination, leaving out the
// tunnel's own routes.
//
// Longest prefix, then the lowest metric, then the route listed first. The tunnel is compared by
// exact equality -- utun30 is not utun3 -- and an empty tunnel leaves nothing out.
func selectEgressBindInterface(routes []egressBindRoute, tunnel string, destination string) (string, bool) {
	address, err := netip.ParseAddr(destination)
	if err != nil || !address.Is4() {
		return "", false
	}
	var best egressBindRoute
	bestBits := -1
	for _, route := range routes {
		if !route.Usable || (tunnel != "" && route.Interface == tunnel) {
			continue
		}
		prefix, err := netip.ParsePrefix(route.Prefix)
		if err != nil || !prefix.Addr().Is4() || !prefix.Masked().Contains(address) {
			continue
		}
		// Strictly better only, so a full tie keeps the route listed first.
		if bits := prefix.Bits(); bits > bestBits || (bits == bestBits && route.Metric < best.Metric) {
			best, bestBits = route, bits
		}
	}
	return best.Interface, bestBits >= 0
}

// egressSocketBinder chooses and applies the interface for each outbound socket.
type egressSocketBinder struct {
	// tunnel returns this node's own TUN interface name, or "" when it has none. Asked on every
	// dial, because the device can be replaced while the plane lives.
	tunnel func() string
	// routes reads the candidate routes. A field so the real-socket tests can hand the stack a
	// route it has to refuse.
	routes func() ([]egressBindRoute, error)
	// tunnelKey turns the tunnel's name into what egressBindRoute.Interface holds on this
	// platform, or "" when no such interface exists -- an interface that is not there carries no
	// routes to leave out.
	tunnelKey func(name string) string
}

// newEgressDialer is the dialer the egress plane uses outside tests.
func newEgressDialer(tunnel func() string) egressDialFunc {
	return newEgressSocketBinder(tunnel).dial
}

func (binder *egressSocketBinder) dial(protocol string, address string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout, Control: binder.control}
	return dialer.Dial(protocol, address)
}

// choose returns the interface a socket to address ("host:port") is bound to.
func (binder *egressSocketBinder) choose(address string) (string, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	if binder.routes == nil {
		return "", errors.New("no routing table reader on this platform")
	}
	routes, err := binder.routes()
	if err != nil {
		return "", fmt.Errorf("read the routing table: %w", err)
	}
	tunnel := ""
	if binder.tunnel != nil && binder.tunnelKey != nil {
		if name := binder.tunnel(); name != "" {
			tunnel = binder.tunnelKey(name)
		}
	}
	chosen, ok := selectEgressBindInterface(routes, tunnel, host)
	if !ok {
		return "", fmt.Errorf("bind egress socket for %s: %w", host, errEgressNoPhysicalRoute)
	}
	return chosen, nil
}
