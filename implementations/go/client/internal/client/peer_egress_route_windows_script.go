package client

import (
	"errors"
	"strconv"
	"strings"
)

// Building the PowerShell this feature runs on Windows.
//
// The scripts are pinned by peer-egress-windows-routes-v1.json, not just what comes back from them.
// Three runtimes each embedding their own string is exactly how two of them end up writing to a
// different policy store than the third, and nothing about the parsed output would show it.
//
// No platform guard, same as the parsers: the text is worth testing everywhere -- which is also
// why the file is not named with a _windows.go suffix, since that suffix is a build constraint on
// its own and would have excluded exactly the code the shared vector exists to pin.

// errEgressRouteArgument is returned for an argument no amount of quoting makes safe to use.
//
// Shared with the macOS builders, which refuse different things for different reasons: there is
// no shell in an argv array, so what they are guarding against is a value that reads as an option
// or as a prefix `route` interprets differently than we do.
var errEgressRouteArgument = errors.New("refusing to build a route command from this argument")

// quoteWindowsArgument wraps a validated argument.
//
// No escaping, deliberately. The allowed character set has no quote in it, so an escape step here
// would be unreachable code that reads like a second line of defence -- and a defence that cannot
// fire is worse than none, because it invites the first one to be relaxed.
func quoteWindowsArgument(value string) string {
	return "'" + value + "'"
}

// validWindowsPrefix accepts a dotted-quad CIDR and nothing else.
//
// The prefix comes from operator configuration and the bypass addresses from runtime discovery. On
// Linux they reach `ip` as argv entries that no shell ever sees; here they are concatenated into
// one command string, and this whitelist is what keeps that from being a command injection.
func validWindowsPrefix(value string) bool {
	address, length, found := strings.Cut(value, "/")
	if !found || length == "" || len(length) > 2 {
		return false
	}
	for _, digit := range length {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	bits, err := strconv.Atoi(length)
	if err != nil || bits > 32 {
		return false
	}
	return validWindowsAddress(address)
}

// validWindowsAddress accepts a dotted-quad IPv4 address and nothing else.
func validWindowsAddress(value string) bool {
	octets := strings.Split(value, ".")
	if len(octets) != 4 {
		return false
	}
	for _, octet := range octets {
		if octet == "" || len(octet) > 3 {
			return false
		}
		for _, digit := range octet {
			if digit < '0' || digit > '9' {
				return false
			}
		}
		number, err := strconv.Atoi(octet)
		if err != nil || number > 255 {
			return false
		}
	}
	return true
}

// windowsShowRoutesScript asks about every prefix in one process.
//
// One line of JSON per prefix, in the order given. Batched because a PowerShell process costs about
// 175 ms to start and the first NetTCPIP cmdlet another 380 ms, after which queries in the same
// process are nearly free: twenty prefixes asked one at a time would take eleven seconds.
func windowsShowRoutesScript(prefixes []string) (string, error) {
	quoted := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		if !validWindowsPrefix(prefix) {
			return "", errEgressRouteArgument
		}
		quoted = append(quoted, quoteWindowsArgument(prefix))
	}
	return "foreach($p in @(" + strings.Join(quoted, ",") + ")){ConvertTo-Json -Compress " +
		"-InputObject @(Get-NetRoute -DestinationPrefix $p -AddressFamily IPv4 " +
		"-ErrorAction SilentlyContinue|Select-Object " +
		"InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)}\nexit 0", nil
}

// windowsFindRoutesScript resolves every bypass address in one process.
func windowsFindRoutesScript(addresses []string) (string, error) {
	quoted := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if !validWindowsAddress(address) {
			return "", errEgressRouteArgument
		}
		quoted = append(quoted, quoteWindowsArgument(address))
	}
	return "foreach($a in @(" + strings.Join(quoted, ",") + ")){ConvertTo-Json -Compress " +
		"-InputObject @(Find-NetRoute -RemoteIPAddress $a " +
		"-ErrorAction SilentlyContinue|Select-Object " +
		"InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)}\nexit 0", nil
}

// windowsInstallRouteScript adds one route.
//
// ActiveStore rather than PersistentStore: these routes do not survive a reboot, which is what this
// feature wants and what matches `ip route add` on Linux. A persistent route is the one that really
// does get left behind, and it would still be in the table after a restart that the journal no
// longer describes.
//
// An empty gateway leaves -NextHop off, which Windows reads as on-link. Passing 0.0.0.0 explicitly
// says the same thing at greater length.
func windowsInstallRouteScript(cidr string, interfaceIndex int, gateway string) (string, error) {
	if !validWindowsPrefix(cidr) || interfaceIndex <= 0 {
		return "", errEgressRouteArgument
	}
	hop := ""
	if gateway != "" {
		if !validWindowsAddress(gateway) {
			return "", errEgressRouteArgument
		}
		hop = " -NextHop " + quoteWindowsArgument(gateway)
	}
	return "try{New-NetRoute -DestinationPrefix " + quoteWindowsArgument(cidr) + hop +
		" -InterfaceIndex " + strconv.Itoa(interfaceIndex) +
		" -PolicyStore ActiveStore -ErrorAction Stop|Out-Null}catch{ConvertTo-Json -Compress " +
		"-InputObject @{errorId=$_.FullyQualifiedErrorId};exit 1}", nil
}

// windowsRemoveRouteScript withdraws one route.
//
// -Confirm:$false because Remove-NetRoute asks otherwise, and a non-interactive process has nobody
// to ask.
func windowsRemoveRouteScript(cidr string) (string, error) {
	if !validWindowsPrefix(cidr) {
		return "", errEgressRouteArgument
	}
	return "try{Remove-NetRoute -DestinationPrefix " + quoteWindowsArgument(cidr) +
		" -Confirm:$false -PolicyStore ActiveStore -ErrorAction Stop|Out-Null}catch{" +
		"ConvertTo-Json -Compress -InputObject @{errorId=$_.FullyQualifiedErrorId};exit 1}", nil
}

// quoteWindowsName wraps an interface name, escaping the one character that needs it.
//
// Unlike the addresses, this cannot be whitelisted: the TUN adapter's name comes from operator
// configuration and may legitimately contain spaces and non-ASCII characters. So here the escape is
// the defence rather than unreachable code, and it protects a value that really can carry a quote.
// PowerShell's single-quoted strings escape a quote by doubling it.
func quoteWindowsName(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// windowsInterfaceIndexScript resolves an adapter name to its index.
//
// Selects the index and nothing else, and that is a requirement rather than a convenience. The
// child process writes stdout in the console code page -- 936 on the machine this was sampled on,
// not UTF-8 -- and in GBK the low byte of a double-byte character can be 0x5C. Echoing a Chinese
// adapter name back into the JSON can therefore emit a bare backslash and break the document.
// Indexes, prefixes, next hops and metrics are all ASCII, so a script that selects only those is
// readable whatever the code page is.
func windowsInterfaceIndexScript(name string) string {
	return "ConvertTo-Json -Compress -InputObject @(Get-NetAdapter -Name " + quoteWindowsName(name) +
		" -ErrorAction SilentlyContinue|Select-Object InterfaceIndex)"
}

// windowsShowAllRoutesScript reads the whole table in one query.
//
// The conflict check asks about one prefix at a time, but the answers can all come from here: 29
// routes came back in 419 ms on the sampling machine, cheaper than one query per prefix and leaving
// the checking to happen in memory.
func windowsShowAllRoutesScript() string {
	return "ConvertTo-Json -Compress -InputObject @(Get-NetRoute -AddressFamily IPv4 " +
		"-ErrorAction SilentlyContinue|Select-Object " +
		"InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)"
}

// splitWindowsScriptLines cuts a batched query's output into one entry per input.
//
// Every query writes exactly one compressed JSON line, including an empty result, so the lines line
// up with the prefixes that were asked about.
func splitWindowsScriptLines(output string) []string {
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

// The IPv6 counterparts (protocol/spec/peer-egress.md, IPv6 数据面). Separate builders rather than a
// family argument on the IPv4 ones, so those stay exactly what the shared vector pins -- including
// refusing an IPv6 address -- and an IPv6 value can only reach a script written for IPv6.

// validWindowsPrefix6 accepts an IPv6 prefix in the form this feature writes it and nothing else:
// RFC 5952 hex groups and colons, a slash, and a decimal length. The same whitelist argument as for
// IPv4 -- no quote can be in it -- and the canonical form is required so the text checked is the text
// sent, never a second spelling of it.
func validWindowsPrefix6(value string) bool {
	cidr, hadLength, ok := parseEgressCIDR6(value)
	return ok && hadLength && formatEgressCIDR6(cidr) == value
}

// validWindowsAddress6 accepts an IPv6 address of hex groups and colons: what a next hop or a bypass
// address is. No zone, no brackets, no dotted tail -- parseEgressAddress6 refuses each of them -- so
// nothing but [0-9A-Fa-f:] can reach the script.
func validWindowsAddress6(value string) bool {
	_, ok := parseEgressAddress6(value)
	return ok
}

// windowsFindRoutesScript6 resolves IPv6 bypass addresses in one process, in the same shape as the
// IPv4 query.
func windowsFindRoutesScript6(addresses []string) (string, error) {
	quoted := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if !validWindowsAddress6(address) {
			return "", errEgressRouteArgument
		}
		quoted = append(quoted, quoteWindowsArgument(address))
	}
	return "foreach($a in @(" + strings.Join(quoted, ",") + ")){ConvertTo-Json -Compress " +
		"-InputObject @(Find-NetRoute -RemoteIPAddress $a " +
		"-ErrorAction SilentlyContinue|Select-Object " +
		"InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)}\nexit 0", nil
}

// windowsInstallRouteScript6 adds one IPv6 route to ActiveStore, for the same reason as IPv4. An
// empty gateway is on-link, written as -NextHop '::'.
func windowsInstallRouteScript6(cidr string, interfaceIndex int, gateway string) (string, error) {
	if !validWindowsPrefix6(cidr) || interfaceIndex <= 0 {
		return "", errEgressRouteArgument
	}
	if gateway == "" {
		// Named explicitly, as the spec's command does: "::" is how Windows writes on-link in IPv6.
		gateway = windowsOnLinkNextHop6
	}
	if !validWindowsAddress6(gateway) {
		return "", errEgressRouteArgument
	}
	return "try{New-NetRoute -AddressFamily IPv6 -DestinationPrefix " + quoteWindowsArgument(cidr) +
		" -NextHop " + quoteWindowsArgument(gateway) +
		" -InterfaceIndex " + strconv.Itoa(interfaceIndex) +
		" -PolicyStore ActiveStore -ErrorAction Stop|Out-Null}catch{ConvertTo-Json -Compress " +
		"-InputObject @{errorId=$_.FullyQualifiedErrorId};exit 1}", nil
}

// windowsRemoveRouteScript6 withdraws one IPv6 route, with -Confirm:$false as for IPv4.
func windowsRemoveRouteScript6(cidr string) (string, error) {
	if !validWindowsPrefix6(cidr) {
		return "", errEgressRouteArgument
	}
	return "try{Remove-NetRoute -AddressFamily IPv6 -DestinationPrefix " + quoteWindowsArgument(cidr) +
		" -Confirm:$false -PolicyStore ActiveStore -ErrorAction Stop|Out-Null}catch{" +
		"ConvertTo-Json -Compress -InputObject @{errorId=$_.FullyQualifiedErrorId};exit 1}", nil
}

// windowsShowAllRoutesScript6 reads the whole IPv6 table in one query, for the IPv6 conflict check.
func windowsShowAllRoutesScript6() string {
	return "ConvertTo-Json -Compress -InputObject @(Get-NetRoute -AddressFamily IPv6 " +
		"-ErrorAction SilentlyContinue|Select-Object " +
		"InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)"
}

// windowsAssignAddress6Script gives the TUN the device's derived IPv6 address, a /128 with no
// on-link route, and sets the interface's IPv6 MTU, which on Windows is separate from the IPv4 one
// netsh sets. Both go to ActiveStore: nothing here outlives a reboot.
//
// An address that is already there -- the adapter was reopened rather than created -- is not a
// failure: the outcome asked for holds. Anything else is written as {errorId} on stdout, as the
// route scripts write theirs. Only the index and the address go in, and nothing comes back but
// that JSON.
func windowsAssignAddress6Script(interfaceIndex int, address string, mtu int) (string, error) {
	if interfaceIndex <= 0 || mtu <= 0 || !validWindowsAddress6(address) {
		return "", errEgressRouteArgument
	}
	index, quoted := strconv.Itoa(interfaceIndex), quoteWindowsArgument(address)
	return "try{if(-not(Get-NetIPAddress -AddressFamily IPv6 -InterfaceIndex " + index + " -IPAddress " + quoted +
		" -PolicyStore ActiveStore -ErrorAction SilentlyContinue)){New-NetIPAddress -AddressFamily IPv6 -IPAddress " +
		quoted + " -PrefixLength 128 -InterfaceIndex " + index +
		" -PolicyStore ActiveStore -ErrorAction Stop|Out-Null};Set-NetIPInterface -AddressFamily IPv6 -InterfaceIndex " +
		index + " -NlMtuBytes " + strconv.Itoa(mtu) + " -PolicyStore ActiveStore -ErrorAction Stop}catch{" +
		"ConvertTo-Json -Compress -InputObject @{errorId=$_.FullyQualifiedErrorId};exit 1}", nil
}
