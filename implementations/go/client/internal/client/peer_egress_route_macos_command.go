package client

import "strings"

// Building the macOS routing commands.
//
// No build tag, for the same reason as the parsers next door: what these produce is pinned by
// peer-egress-macos-routes-v1.json, and a darwin-only file would take the test with it on every
// machine that is not a Mac.
//
// Nothing here is quoted or escaped, and unlike the Windows side that is not a decision about
// character sets: these are argv arrays handed to exec, so there is no shell to reinterpret them. A
// prefix carrying a quote or a semicolon is not a second command here, it is just a prefix `route`
// will refuse.
//
// What is left to defend against is a value that reads as an option, and a value that reads as a
// valid prefix but is not one. The second is the one that matters. `route -n add -net
// 203.0.113.0/33 192.168.64.1` is accepted: it prints "add net 203.0.113.0: gateway 192.168.64.1",
// exits 0, and installs 128.0/1 -- half the IPv4 address space pointed at the gateway. Nothing in
// the output says so; only the routing table does. On Windows the same argument is refused by
// New-NetRoute, so validating first was defence in depth. Here it is the only defence there is.

// validMacosAddress reports whether this is an IPv4 address and nothing else.
func validMacosAddress(value string) bool {
	if value == "" || value != strings.TrimSpace(value) {
		return false
	}
	octets := strings.Split(value, ".")
	if len(octets) != 4 {
		return false
	}
	for _, octet := range octets {
		if _, ok := macosDecimalValue(octet, 255); !ok {
			return false
		}
	}
	return true
}

// validMacosPrefix reports whether this is an IPv4 prefix in full: four octets and a length.
//
// The length is required and 33 is refused, because `route` does neither -- see the note at the
// top of this file. A leading zero is refused too, in the octets and in the length, because
// inet_aton would read it as octal and we would not.
func validMacosPrefix(value string) bool {
	address, length, found := strings.Cut(value, "/")
	if !found || !validMacosAddress(address) {
		return false
	}
	_, ok := macosDecimalValue(length, 32)
	return ok
}

// validMacosInterfaceName reports whether a name can be read as anything but an interface.
//
// Must start with a letter, so it can never be taken for an option, and must stay inside the
// letters, digits, underscore and dot that real names use: en0, utun3, bridge0, vlan1. The length
// limit is the kernel's, where IFNAMSIZ is 16 including the terminator.
//
// Whitelisted rather than escaped, which is the opposite of what the same value gets on Windows.
// There the adapter name reaches PowerShell as part of a script and has to be escaped, because
// operators legitimately use spaces and non-ASCII in it. Here it is one element of an argv array,
// so there is nothing to escape, and the only thing that can go wrong is `route` reading the name
// as an address -- which it does: given an interface that does not exist it reports
// "route: bad address: utun99".
func validMacosInterfaceName(value string) bool {
	if len(value) < 1 || len(value) > 15 {
		return false
	}
	if !isMacosLetter(value[0]) {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if isMacosLetter(character) || (character >= '0' && character <= '9') ||
			character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

// macosShowTableArgs reads the whole table.
//
// IPv4 only: the IPv6 section has a different column layout and this feature does not route IPv6
// yet. The egress socket binder reads the IPv6 table with macosShowTableArgs6.
func macosShowTableArgs() []string {
	return []string{"netstat", "-rn", "-f", "inet"}
}

// macosFindRouteArgs asks where an address would go right now, which is how a bypass next hop is
// resolved.
//
// `-n` so no name lookup is attempted. It makes no difference to the output -- sampled both ways --
// but a resolver that does not answer would hold the process for as long as the resolver takes, and
// this runs while the tunnel is being brought up.
func macosFindRouteArgs(address string) ([]string, error) {
	if !validMacosAddress(address) {
		return nil, errEgressRouteArgument
	}
	return []string{"route", "-n", "get", address}, nil
}

// macosInstallInterfaceArgs sends a prefix out of an interface, which is how a rule's route reaches
// the TUN.
func macosInstallInterfaceArgs(prefix string, name string) ([]string, error) {
	if !validMacosPrefix(prefix) || !validMacosInterfaceName(name) {
		return nil, errEgressRouteArgument
	}
	return []string{"route", "-n", "add", "-net", prefix, "-interface", name}, nil
}

// macosInstallGatewayArgs sends a prefix to a next hop, which is how a bypass keeps the transport
// off the tunnel.
func macosInstallGatewayArgs(prefix string, gateway string) ([]string, error) {
	if !validMacosPrefix(prefix) || !validMacosAddress(gateway) {
		return nil, errEgressRouteArgument
	}
	return []string{"route", "-n", "add", "-net", prefix, gateway}, nil
}

// macosRemoveArgs withdraws a prefix.
//
// `-net` for every prefix including a /32, which is sampled as working. One form means the
// withdrawal cannot disagree with the install about what was installed.
//
// No -ifscope, matching the install. A withdrawal without it takes the unscoped route and leaves
// scoped ones alone, which is the right way round: this feature only ever installs unscoped routes,
// and a scoped route on the same prefix belongs to somebody else.
func macosRemoveArgs(prefix string) ([]string, error) {
	if !validMacosPrefix(prefix) {
		return nil, errEgressRouteArgument
	}
	return []string{"route", "-n", "delete", "-net", prefix}, nil
}

func isMacosLetter(character byte) bool {
	return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z')
}

// The IPv6 commands (protocol/spec/peer-egress.md, IPv6 数据面): `route -n ... -inet6`, read back from
// `netstat -rn -f inet6`. Separate builders, so the IPv4 ones stay what the shared vector pins.

// validMacosPrefix6 accepts an IPv6 prefix in the form this feature writes it: RFC 5952 address,
// slash, decimal length. Requiring the canonical form keeps the text checked the text sent: `route`
// has its own reading of an address, and one spelling leaves it nothing to read differently.
func validMacosPrefix6(value string) bool {
	cidr, hadLength, ok := parseEgressCIDR6(value)
	return ok && hadLength && formatEgressCIDR6(cidr) == value
}

// validMacosAddress6 accepts an IPv6 address, optionally with a zone naming an interface -- a
// link-local next hop means nothing without one -- and nothing else: no brackets, no dotted tail,
// and a zone that passes the same whitelist as an interface name.
func validMacosAddress6(value string) bool {
	address, zone, zoned := strings.Cut(value, "%")
	if zoned && !validMacosInterfaceName(zone) {
		return false
	}
	_, ok := parseEgressAddress6(address)
	return ok
}

// macosFindRouteArgs6 asks where an IPv6 address would go right now.
func macosFindRouteArgs6(address string) ([]string, error) {
	if !validMacosAddress6(address) || strings.Contains(address, "%") {
		return nil, errEgressRouteArgument
	}
	return []string{"route", "-n", "get", "-inet6", address}, nil
}

// macosInstallInterfaceArgs6 sends an IPv6 prefix out of an interface: a rule's route into the TUN,
// or an on-link bypass.
func macosInstallInterfaceArgs6(prefix string, name string) ([]string, error) {
	if !validMacosPrefix6(prefix) || !validMacosInterfaceName(name) {
		return nil, errEgressRouteArgument
	}
	return []string{"route", "-n", "add", "-inet6", "-net", prefix, "-interface", name}, nil
}

// macosInstallGatewayArgs6 sends an IPv6 prefix to a next hop, which for IPv6 is usually link-local
// and so carries its zone.
func macosInstallGatewayArgs6(prefix string, gateway string) ([]string, error) {
	if !validMacosPrefix6(prefix) || !validMacosAddress6(gateway) {
		return nil, errEgressRouteArgument
	}
	return []string{"route", "-n", "add", "-inet6", "-net", prefix, gateway}, nil
}

// macosRemoveArgs6 withdraws an IPv6 prefix, unscoped like the install.
func macosRemoveArgs6(prefix string) ([]string, error) {
	if !validMacosPrefix6(prefix) {
		return nil, errEgressRouteArgument
	}
	return []string{"route", "-n", "delete", "-inet6", "-net", prefix}, nil
}
