package client

import (
	"strconv"
	"strings"
)

// Reading what macOS says about its routing table.
//
// Kept free of build tags for the same reason the Linux and Windows parsers are: they depend on
// output nobody controls, and a darwin-only file would go untested on the machines where most of CI
// runs. The commander next door is in peer_egress_route_darwin.go, where the suffix is correct
// because that file runs `route` and has nothing to say anywhere else.
//
// The table is read with `netstat -rn -f inet` and changed with `route`. Three things about those
// two, all of them sampled from a real machine rather than taken from the manual page, and all of
// them pinned by peer-egress-macos-routes-v1.json.
//
// `route` returns 0 when it fails. A prefix that already exists, a prefix that is not in the table,
// an interface with no address, a missing argument -- every one of those exits 0 and prints a line
// that begins exactly like a success. What separates them is that `route` writes nothing to stderr
// when it works, which is why classification is keyed there.
//
// netstat abbreviates the destination column, and the abbreviations are not guessable: 127.0.0.0/8
// prints as "127", 203.0.113.0/24 as "203.0.113", 100.64.0.0/10 as "100.64/10", the default route
// as "default". Reading them back is what normaliseMacosPrefix does.
//
// None of it is localised. The same commands under zh_CN, ja_JP and de_DE produce byte-identical
// output, so parsing the keys is safe here in a way it is not on Windows, where the same command
// prints Chinese column headers under one console code page and English under another.

// macosKernelGeneratedFlag marks a netstat entry the kernel made rather than one anybody configured.
//
// Excluded from the conflict answer. BSD keeps address resolution in the routing table, so every
// host that has been talked to recently has a /32 of its own, as do the subnet broadcast address
// and every multicast group that has been joined. Counting those as conflicts would refuse the
// bypass routes -- /32s for the control endpoint, STUN, TURN and the peer addresses, which are
// exactly the addresses most likely to have been talked to already -- and a refused bypass route is
// the leak this feature exists to prevent: the transport would fall under whichever rule covers it
// and be sent into the tunnel that carries it.
const macosKernelGeneratedFlag = "W"

// Classifications of a routing command that failed. Same two names as the Windows side, so the
// installer reads the same on both.
const (
	macosRouteFailureDenied = "permission-denied"
	macosRouteFailureOther  = "failed"
)

// The two failures that are not failures.
const (
	// macosRouteNotInTable is a removal of something already gone, which is the outcome the
	// caller asked for. It matters more than it looks: the journal is walked at startup, and on
	// a machine that has rebooted none of its routes are there any more, so every entry in it
	// reports this.
	macosRouteNotInTable = "not in table"
	// macosRouteMustBeRoot is the one worth naming, because the fix is to run elevated and no
	// amount of retrying gets there.
	macosRouteMustBeRoot = "must be root"
)

// macosRoute is one row of `netstat -rn`.
type macosRoute struct {
	// Prefix is the destination column normalised, so the same route is never described two
	// ways.
	Prefix      string
	Destination string
	Gateway     string
	Flags       string
	Netif       string
}

// parseMacosRouteGet reads `route -n get <address>`, which is how a bypass next hop is resolved.
//
// The gateway is empty for a destination that is on-link, where `route` prints no gateway line at
// all. Sampled rather than assumed: asked about the gateway's own address -- which has a cloned
// link-level entry carrying a MAC address -- it still prints no gateway line, so the field never
// holds something that is not an address.
func parseMacosRouteGet(stdout string, stderr string) (egressRouteHop, bool) {
	if strings.TrimSpace(stderr) != "" {
		return egressRouteHop{}, false
	}
	var hop egressRouteHop
	for _, line := range strings.Split(stdout, "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch strings.TrimSpace(key) {
		case "gateway":
			hop.Gateway = strings.TrimSpace(value)
		case "interface":
			hop.Device = strings.TrimSpace(value)
		}
	}
	if hop.Device == "" {
		return egressRouteHop{}, false
	}
	if hop.Gateway != "" && !validMacosAddress(hop.Gateway) {
		// Not an address, so it cannot be a next hop. The only thing done with this value is
		// to put it back on a `route add` command line, where a non-address is either another
		// argument or an error. Treating it as on-link asks for a route out of the interface,
		// which is what an entry without a usable gateway means anyway.
		hop.Gateway = ""
	}
	return hop, true
}

// normaliseMacosPrefix turns netstat's destination column, or a rule's CIDR, into one canonical
// form. Anything that is not IPv4 becomes empty, which is how the IPv6 half of the table is left
// alone.
//
// A destination with no length carries one octet per eight bits: "127" is 127.0.0.0/8 and
// "192.168.64" is 192.168.64.0/24. A destination with a length means what it says once the missing
// trailing octets are filled in with zeroes: "100.64/10" is 100.64.0.0/10.
//
// The address is then masked by the length. Two spellings of one prefix have to compare equal, or
// the conflict check is answering a different question than the one it was asked.
func normaliseMacosPrefix(text string) string {
	value := strings.TrimSpace(text)
	if value == "" {
		return ""
	}
	if value == "default" {
		return "0.0.0.0/0"
	}
	address, length, hasLength := strings.Cut(value, "/")
	octets := strings.Split(address, ".")
	if len(octets) < 1 || len(octets) > 4 {
		return ""
	}
	var numbers [4]uint32
	for index, octet := range octets {
		number, ok := macosDecimalValue(octet, 255)
		if !ok {
			return ""
		}
		numbers[index] = uint32(number)
	}
	bits := 8 * len(octets)
	if hasLength {
		parsed, ok := macosDecimalValue(length, 32)
		if !ok {
			return ""
		}
		bits = parsed
	}
	packed := numbers[0]<<24 | numbers[1]<<16 | numbers[2]<<8 | numbers[3]
	var mask uint32
	if bits > 0 {
		mask = ^uint32(0) << (32 - bits)
	}
	packed &= mask
	return strconv.FormatUint(uint64(packed>>24&0xFF), 10) + "." +
		strconv.FormatUint(uint64(packed>>16&0xFF), 10) + "." +
		strconv.FormatUint(uint64(packed>>8&0xFF), 10) + "." +
		strconv.FormatUint(uint64(packed&0xFF), 10) + "/" + strconv.Itoa(bits)
}

// parseMacosRouteTable reads the IPv4 rows of `netstat -rn`.
//
// Only the rows under the "Internet:" heading. The gate is load-bearing rather than tidy:
// "Internet6:" has default routes of its own -- four on the sampling machine, one per utun -- and
// "default" is the one destination whose IPv6 spelling is indistinguishable from its IPv4 spelling.
// Without the gate, asking whether anything owns 0.0.0.0/0 on a machine with IPv6 would find
// phantom routes and refuse the one rule that takes over everything.
//
// Rows carry four or five columns. The fifth is Expire, which holds a number, or "!", or nothing at
// all, so the parser must not require it.
func parseMacosRouteTable(stdout string) []macosRoute {
	var routes []macosRoute
	inside := false
	for _, line := range strings.Split(stdout, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasSuffix(trimmed, ":") {
			inside = trimmed == "Internet:"
			continue
		}
		if !inside || strings.HasPrefix(trimmed, "Destination") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 4 {
			continue
		}
		prefix := normaliseMacosPrefix(fields[0])
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

// macosConflictFromTable answers whether anything already owns this exact prefix.
//
// Exact prefix, not a longest-prefix lookup, for the same reason as on Windows: the question is
// ownership of this prefix, not reachability of an address, and under a default route everything is
// reachable. `route -n get` cannot answer it at all -- asked about an unrouted address it returns
// the default route -- which is why the whole table is read instead.
func macosConflictFromTable(table string, prefix string) (bool, string) {
	wanted := normaliseMacosPrefix(prefix)
	if wanted == "" {
		return false, ""
	}
	var matching []macosRoute
	for _, route := range parseMacosRouteTable(table) {
		if route.Prefix != wanted {
			continue
		}
		if strings.Contains(route.Flags, macosKernelGeneratedFlag) {
			continue
		}
		matching = append(matching, route)
	}
	return describeMacosRoutes(matching)
}

// describeMacosRoutes turns the routes on one prefix into a presence and a description.
func describeMacosRoutes(routes []macosRoute) (bool, string) {
	if len(routes) == 0 {
		return false, ""
	}
	description := describeMacosRoute(routes[0])
	if len(routes) > 1 {
		// The count matters to whoever has to clear the prefix: one removal is not going to be
		// enough, and retrying is a worse way to learn that. Reachable here because a scoped
		// route can share a prefix with an unscoped one.
		description += " (+" + strconv.Itoa(len(routes)-1) + " more)"
	}
	return true, description
}

// describeMacosRoute writes one line an operator can match against their own `netstat -rn` output.
//
// The columns are restated in netstat's own words, including calling the second one a gateway when
// it holds an interface name: that is what the table says, and an operator comparing this line
// against the table should not have to reconcile two vocabularies.
func describeMacosRoute(route macosRoute) string {
	return route.Prefix + " gateway " + route.Gateway +
		" netif " + route.Netif + " flags " + route.Flags
}

// parseMacosCommandFailure classifies a `route add` or `route delete` that may not have worked.
//
// The exit status is not consulted, because it is 0 for "File exists", for "not in table", for
// "Network is unreachable" and for "Invalid argument" -- every failure sampled except a malformed
// address returns success. What does separate them is stderr, which is empty for every successful
// mutation sampled and carries "route: writing to routing socket: <error>" for every failed one.
//
// Keyed on stderr being non-empty rather than on a list of error texts. Those errors are strerror
// of whatever the routing socket returned, so the list has no end, and an unrecognised error would
// otherwise read as success -- the direction that leaves a rule believed installed while its
// traffic goes out of the physical interface. Noise on stderr fails the other way: the install is
// reported failed, the installer withdraws a route it did install, and nothing leaks.
func parseMacosCommandFailure(stdout string, stderr string) string {
	combined := stdout + "\n" + stderr
	if strings.Contains(combined, macosRouteMustBeRoot) {
		return macosRouteFailureDenied
	}
	if strings.Contains(combined, macosRouteNotInTable) {
		return ""
	}
	if strings.TrimSpace(stderr) != "" {
		return macosRouteFailureOther
	}
	return ""
}

// macosDecimalValue reads a run of decimal digits, refusing a leading zero.
//
// Refused rather than skipped over. `route` parses addresses with inet_aton, which reads a leading
// zero as octal: to it, 010.0.0.1 is 8.0.0.1. Reading the same text as decimal here would mean the
// conflict check asking about one prefix while the install created another, and the way not to have
// two readings of one string is to accept only the spelling that has one.
func macosDecimalValue(digits string, limit int) (int, bool) {
	if digits == "" || len(digits) > 3 {
		return 0, false
	}
	if len(digits) > 1 && digits[0] == '0' {
		return 0, false
	}
	value := 0
	for index := 0; index < len(digits); index++ {
		character := digits[index]
		if character < '0' || character > '9' {
			return 0, false
		}
		value = value*10 + int(character-'0')
	}
	if value > limit {
		return 0, false
	}
	return value, true
}
