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
// No platform guard, same as the parsers: the text is worth testing everywhere.

// errEgressRouteArgument is returned for anything that would have to be escaped to be safe.
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
