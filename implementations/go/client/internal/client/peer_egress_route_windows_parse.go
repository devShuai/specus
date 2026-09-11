package client

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Reading what Windows says about its routing table.
//
// Kept free of build tags for the same reason the Linux parsers are: they depend on output nobody
// controls, and a Windows-only file would go untested on the machines where most of CI runs.
//
// Which is why this file is not called peer_egress_route_parse_windows.go. A _windows.go suffix is
// itself a build constraint, so that name would have compiled the parsers out everywhere but
// Windows while the test that exercises them kept compiling -- and the developer machine here is
// Windows, so only Linux CI would have said so.
//
// The table is read through PowerShell rather than netsh or route print, because those two are
// localised. The same `netsh interface ipv4 show route` prints English column headers under one
// console code page and Chinese ones under another on the very same machine. A parser written
// against the English table reads no routes at all on a Chinese machine, and no routes is exactly
// the answer that means "no conflict, install it" -- which would overwrite the operator's own
// routing while reporting success. `ip route` carries no translations, which is why parsing its
// text is safe on Linux and not here.
//
// The PowerShell layer is therefore as thin as it can be: it turns objects into JSON and decides
// nothing. Which object in the array is the route, what a missing next hop means, whether a failure
// was a permissions failure -- all of that is here, where peer-egress-windows-routes-v1.json pins
// the three implementations to one reading.

// windowsOnLinkNextHop is what Windows reports for a destination on a directly attached network.
// Linux says the same thing by leaving `via` out, so both become an empty gateway and nothing
// downstream has to know which platform answered.
const windowsOnLinkNextHop = "0.0.0.0"

// Classifications of a routing command that failed.
const (
	// windowsRouteFailureDenied is the one worth telling the operator about by name: the fix is
	// to run elevated, and no amount of retrying gets there.
	windowsRouteFailureDenied = "permission-denied"
	windowsRouteFailureOther  = "failed"
)

// windowsRouteErrorNotFound is what a removal reports when the prefix is not in the table. Not a
// failure: the outcome the caller asked for already holds.
const windowsRouteErrorNotFound = "CmdletizationQuery_NotFound"

// windowsEgressRouteHop is where a bypass address has to be sent to stay off the tunnel.
//
// Carries the interface index, not the interface name: names are localised -- the default adapter
// on a Chinese Windows is called 以太网 -- and the index is a number.
type windowsEgressRouteHop struct {
	// Gateway is empty for an on-link destination, which is normal on a directly attached
	// network and is not a failure to parse.
	Gateway        string
	InterfaceIndex int
}

// windowsNetRoute is one MSFT_NetRoute as the script serialises it.
//
// The nullable fields are nullable in the output: `Find-NetRoute` emits a source-address object
// alongside the route, and Select-Object fills the properties it does not have with null.
type windowsNetRoute struct {
	InterfaceIndex    int     `json:"InterfaceIndex"`
	DestinationPrefix *string `json:"DestinationPrefix"`
	NextHop           *string `json:"NextHop"`
	RouteMetric       *int    `json:"RouteMetric"`
}

// parseWindowsRouteFind reads the JSON from the find-route script.
//
// `Find-NetRoute` returns two objects: the source address it would use, then the route. Only the
// second carries a DestinationPrefix, and that is what picks it out -- taking element zero yields
// an interface index with no next hop, which would install a route to nowhere.
func parseWindowsRouteFind(output string) (windowsEgressRouteHop, bool) {
	routes, ok := decodeWindowsNetRoutes(output)
	if !ok {
		return windowsEgressRouteHop{}, false
	}
	for _, route := range routes {
		if windowsRoutePrefix(route) == "" {
			continue
		}
		if route.InterfaceIndex <= 0 {
			// Zero is not an interface. Installing against it would ask the system to send
			// through nothing, so skip it and keep looking rather than give up here.
			continue
		}
		return windowsEgressRouteHop{
			Gateway:        windowsRouteGateway(route),
			InterfaceIndex: route.InterfaceIndex,
		}, true
	}
	return windowsEgressRouteHop{}, false
}

// parseWindowsRouteShow reads the JSON from the show-route script.
//
// Unparseable output reports no conflict, matching the Linux reading: being unable to ask is not
// evidence of an empty table, and the install still refuses a prefix that already exists.
func parseWindowsRouteShow(output string) (bool, string) {
	return describeWindowsRoutes(windowsRoutesWithPrefix(output))
}

// windowsConflictFromTable answers the same question out of one read of the whole table.
//
// Exact string match on the prefix, not a longest-prefix lookup. What the conflict check asks is
// whether anything already owns this exact prefix, not whether the address can be routed -- under a
// default route the second question is always yes, and treating that as a conflict would refuse
// every rule on any machine that has one.
func windowsConflictFromTable(table string, prefix string) (bool, string) {
	wanted := strings.TrimSpace(prefix)
	var matching []windowsNetRoute
	for _, route := range windowsRoutesWithPrefix(table) {
		if windowsRoutePrefix(route) == wanted {
			matching = append(matching, route)
		}
	}
	return describeWindowsRoutes(matching)
}

// windowsRoutesWithPrefix keeps every entry that actually carries a prefix.
func windowsRoutesWithPrefix(output string) []windowsNetRoute {
	decoded, ok := decodeWindowsNetRoutes(output)
	if !ok {
		return nil
	}
	var routes []windowsNetRoute
	for _, route := range decoded {
		if windowsRoutePrefix(route) != "" {
			routes = append(routes, route)
		}
	}
	return routes
}

// describeWindowsRoutes turns the routes on one prefix into a presence and a description.
func describeWindowsRoutes(routes []windowsNetRoute) (bool, string) {
	if len(routes) == 0 {
		return false, ""
	}
	description := describeWindowsRoute(routes[0])
	if len(routes) > 1 {
		// The count matters to whoever has to clear the prefix: one removal is not going to
		// be enough, and finding that out by retrying is a worse way to learn it.
		description += " (+" + strconv.Itoa(len(routes)-1) + " more)"
	}
	return true, description
}

// parseWindowsCommandFailure classifies a routing command that did not succeed.
//
// Keyed on the id inside FullyQualifiedErrorId, never on the message: the message is localised,
// while the id is built from the error number and the cmdlet name and is not.
//
// A removal that found no such prefix is not a failure: the route is not in the table, which is
// what the caller asked for. That matters more here than on Linux, because these routes go into
// ActiveStore and do not survive a reboot -- so the first cleanup after every restart walks a
// journal of prefixes that are all already gone, and reporting each one would bury the failures
// that are real.
func parseWindowsCommandFailure(output string) string {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return ""
	}
	var failure struct {
		ErrorID string `json:"errorId"`
	}
	if err := json.Unmarshal([]byte(trimmed), &failure); err != nil {
		// Output that is neither empty nor JSON means something went wrong that the script
		// did not get to describe.
		return windowsRouteFailureOther
	}
	if strings.TrimSpace(failure.ErrorID) == "" {
		return ""
	}
	if strings.Contains(failure.ErrorID, "Windows System Error 5") {
		return windowsRouteFailureDenied
	}
	if strings.Contains(failure.ErrorID, windowsRouteErrorNotFound) {
		return ""
	}
	return windowsRouteFailureOther
}

// parseWindowsInterfaceIndex reads the adapter-index script's JSON.
//
// An adapter that is not there comes back as an empty array rather than an error, so the absence
// has to be recognised here: installing against index zero would ask the system to route through
// nothing.
func parseWindowsInterfaceIndex(output string) (int, bool) {
	routes, ok := decodeWindowsNetRoutes(output)
	if !ok {
		return 0, false
	}
	for _, route := range routes {
		if route.InterfaceIndex > 0 {
			return route.InterfaceIndex, true
		}
	}
	return 0, false
}

// describeWindowsRoute writes one line an operator can match against their own Get-NetRoute output.
func describeWindowsRoute(route windowsNetRoute) string {
	via := "on-link"
	if gateway := windowsRouteGateway(route); gateway != "" {
		via = "nexthop " + gateway
	}
	line := windowsRoutePrefix(route) + " " + via + " ifIndex " + strconv.Itoa(route.InterfaceIndex)
	if route.RouteMetric != nil {
		line += " metric " + strconv.Itoa(*route.RouteMetric)
	}
	return line
}

func decodeWindowsNetRoutes(output string) ([]windowsNetRoute, bool) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return nil, false
	}
	var routes []windowsNetRoute
	if err := json.Unmarshal([]byte(trimmed), &routes); err != nil {
		return nil, false
	}
	return routes, true
}

func windowsRoutePrefix(route windowsNetRoute) string {
	if route.DestinationPrefix == nil {
		return ""
	}
	return strings.TrimSpace(*route.DestinationPrefix)
}

func windowsRouteGateway(route windowsNetRoute) string {
	if route.NextHop == nil {
		return ""
	}
	gateway := strings.TrimSpace(*route.NextHop)
	if gateway == windowsOnLinkNextHop {
		return ""
	}
	return gateway
}
