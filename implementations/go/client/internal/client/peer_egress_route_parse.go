package client

import "strings"

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
func egressRouteHopIsDevice(hop egressRouteHop, device string) bool {
	return device != "" && strings.EqualFold(strings.TrimSpace(hop.Device), strings.TrimSpace(device))
}
