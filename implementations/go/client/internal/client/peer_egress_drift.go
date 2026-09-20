package client

import "strings"

// Finding the consumer's own routes gone or moved after the machine changed networks.
//
// A route installed into a routing table is not installed for good. An interface that goes down
// takes its routes with it; a machine that comes back from sleep on another network keeps a bypass
// that names a gateway which is no longer the way out. The journal still says the route is there,
// so nothing in the plan would notice. The table is read on the consumer's tick and compared with
// what it owns, and what has drifted is put back.
//
// The comparison is pinned by protocol/test-vectors/peer-egress-socket-binding-v1.json, drift.

type egressRouteDriftReason string

const (
	// egressDriftMissing: no row for the prefix that could be ours.
	egressDriftMissing egressRouteDriftReason = "missing"
	// egressDriftMoved: a row for the prefix exists but is not the one this feature would install
	// now.
	egressDriftMoved egressRouteDriftReason = "moved"
)

type egressRouteDriftAction string

const (
	// egressDriftReinstall: take the route out and put it back, resolving its hop afresh.
	egressDriftReinstall egressRouteDriftAction = "reinstall"
	// egressDriftConflict: the prefix is somebody else's now. Reported and given up, not taken.
	egressDriftConflict egressRouteDriftAction = "conflict"
)

// egressRouteDrift is one owned route the table no longer carries as installed.
type egressRouteDrift struct {
	Route  egressRoute
	Reason egressRouteDriftReason
	Action egressRouteDriftAction
	// Existing describes the row that holds the prefix now, for a conflict.
	Existing string
}

// egressRouteDrifts compares what this feature owns with the table.
//
// A tunnel route is present when a row for its prefix names the tunnel. It cannot change interface
// on its own, so a row on another interface is somebody else's: the prefix is theirs now, and it is
// reported rather than taken.
//
// A bypass is compared with where the table would send the address now, with this feature's own
// routes left out -- the tunnel's and every owned prefix, the bypass itself included, or it would
// choose itself and look right. Absent, or present with a different interface or gateway, it is
// reinstalled. Present with nothing better outside the tunnel, it is left: the route that is there
// is the best there is.
func egressRouteDrifts(owned []egressRoute, table []egressBindRoute, tunnel string) []egressRouteDrift {
	prefixes := make([]string, 0, len(owned))
	for _, route := range owned {
		prefixes = append(prefixes, route.CIDR)
	}
	var found []egressRouteDrift
	for _, route := range owned {
		var rows []egressBindRoute
		for _, row := range table {
			if row.Prefix == route.CIDR {
				rows = append(rows, row)
			}
		}
		if route.Kind == egressRouteToTun {
			present := false
			for _, row := range rows {
				if row.Interface == tunnel {
					present = true
					break
				}
			}
			switch {
			case present:
			case len(rows) > 0:
				found = append(found, egressRouteDrift{Route: route, Reason: egressDriftMoved,
					Action: egressDriftConflict, Existing: describeEgressBindRoute(rows[0])})
			default:
				found = append(found, egressRouteDrift{Route: route, Reason: egressDriftMissing,
					Action: egressDriftReinstall})
			}
			continue
		}
		address := strings.TrimSuffix(route.CIDR, "/32")
		hop, hasHop := selectEgressBypassHop(table, tunnel, prefixes, address)
		var present []egressBindRoute
		for _, row := range rows {
			if row.Interface != tunnel {
				present = append(present, row)
			}
		}
		switch {
		case len(present) == 0:
			found = append(found, egressRouteDrift{Route: route, Reason: egressDriftMissing,
				Action: egressDriftReinstall})
		case hasHop && (present[0].Interface != hop.Interface || present[0].Gateway != hop.Gateway):
			found = append(found, egressRouteDrift{Route: route, Reason: egressDriftMoved,
				Action: egressDriftReinstall})
		}
	}
	return found
}

// describeEgressBindRoute renders a row the way an operator would read it in a conflict.
func describeEgressBindRoute(row egressBindRoute) string {
	if row.Gateway != "" {
		return row.Prefix + " via " + row.Gateway + " dev " + row.Interface
	}
	return row.Prefix + " dev " + row.Interface
}
