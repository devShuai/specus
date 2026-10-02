package client

import (
	"encoding/json"
	"net"
	"regexp"
	"strings"
)

// The pure half of the system DNS takeover (protocol/spec/peer-egress-dns.md, section 六; step five):
// reading each platform's DNS settings out of the text its tools print, deciding whether they can be
// taken over and which upstreams the responder forwards to, the exact commands that take over and
// give back, and what giving back does when someone else changed the setting in the meantime.
//
// Nothing here runs anything. Every function is pinned by a section of
// protocol/test-vectors/peer-egress-dns-takeover-v1.json, because these are the decisions the three
// clients must make identically; running the commands, the journal and the timing are each client's
// own and live in peer_egress_dns_takeover.go.

const (
	// egressDNSNRPTComment marks the one NRPT rule this feature adds, and is how it finds that rule
	// again and nothing else.
	egressDNSNRPTComment = "specus-peer-egress"
	egressDNSResolvConf  = "/etc/resolv.conf"
	// egressDNSResolvConfWritten is the whole of /etc/resolv.conf while the takeover holds it. Fixed
	// text rather than an edit, so that giving back can tell whether the file is still ours.
	egressDNSResolvConfWritten = "# Written by specus for peer egress DNS takeover. The original is kept in the journal\n" +
		"# and is put back when the client stops or when `egress dns restore` runs.\n" +
		"nameserver 198.18.0.1\n"

	// The platforms a journal names, one per way of taking over.
	egressDNSPlatformResolved   = "linux-resolved"
	egressDNSPlatformResolvConf = "linux-resolvconf"
	egressDNSPlatformMacOS      = "macos"
	egressDNSPlatformWindows    = "windows"
)

// egressDNSResolvedStubs are systemd-resolved's stub listeners. A resolv.conf naming only these sends
// every application through resolved.
var egressDNSResolvedStubs = []string{"127.0.0.53", "127.0.0.54"}

// The Windows readers, run as PowerShell scripts. Their JSON is read by parseWindowsDNSServers and
// parseWindowsNRPT.
const (
	egressDNSWindowsReadServers = "$up = @(Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected | " +
		"Select-Object -ExpandProperty InterfaceIndex); " +
		"ConvertTo-Json -Compress -Depth 3 -InputObject @(Get-DnsClientServerAddress -AddressFamily IPv4 | " +
		"Where-Object { $up -contains $_.InterfaceIndex } | " +
		"Select-Object InterfaceAlias,InterfaceIndex,ServerAddresses)"
	egressDNSWindowsReadNRPT = "ConvertTo-Json -Compress -Depth 3 -InputObject @(Get-DnsClientNrptRule | " +
		"Select-Object Namespace,Comment,NameServers)"
)

// The takeover's refusals, as the status names them.
const (
	egressDNSRefusedPoolRoute   = "pool-route-not-installed"
	egressDNSRefusedLoopback    = "system-dns-loopback"
	egressDNSRefusedVirtual     = "system-dns-virtual"
	egressDNSRefusedNoUpstream  = "no-upstream"
	egressDNSRefusedManaged     = "resolv-conf-managed"
	egressDNSRefusedNRPT        = "nrpt-root-occupied"
	egressDNSRefusedUnsupported = "unsupported-platform"
)

// stripDNSServer is a server as a tool prints it, without a DNS-over-TLS name (`1.1.1.1#name`) or an
// IPv6 zone (`fe80::1%eth0`).
func stripDNSServer(text string) string {
	text, _, _ = strings.Cut(text, "#")
	text, _, _ = strings.Cut(text, "%")
	return strings.TrimSpace(text)
}

// dnsTextLines splits a tool's output into lines, whatever it ended them with.
func dnsTextLines(text string) []string {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for index := range lines {
		lines[index] = strings.TrimSuffix(lines[index], "\r")
	}
	return lines
}

var resolvectlLinkLine = regexp.MustCompile(`^Link \d+ \(([^)]*)\):(.*)$`)

// parseResolvectlDNS reads `resolvectl dns`: a `Global:` line and a `Link N (name):` line each, the
// servers after the colon. Global first, then the links as printed, leaving out this client's own
// tunnel, whose server is the responder.
func parseResolvectlDNS(output, tunnel string) []string {
	servers := []string{}
	for _, line := range dnsTextLines(output) {
		line = strings.TrimSpace(line)
		var rest string
		if strings.HasPrefix(line, "Global:") {
			rest = strings.TrimPrefix(line, "Global:")
		} else {
			match := resolvectlLinkLine.FindStringSubmatch(line)
			if match == nil || match[1] == tunnel {
				continue
			}
			rest = match[2]
		}
		for _, item := range strings.Fields(rest) {
			if server := stripDNSServer(item); server != "" {
				servers = append(servers, server)
			}
		}
	}
	return servers
}

// parseResolvConfServers reads the `nameserver` lines of a resolv.conf in order. A comment starts
// with # or ; and runs to the end of the line.
func parseResolvConfServers(text string) []string {
	servers := []string{}
	for _, line := range dnsTextLines(text) {
		if cut := strings.IndexAny(line, "#;"); cut >= 0 {
			line = line[:cut]
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			servers = append(servers, stripDNSServer(fields[1]))
		}
	}
	return servers
}

// parseMacNetworkServices reads `networksetup -listallnetworkservices`. The first line explains the
// asterisk; a service whose name starts with one is disabled and is left alone.
func parseMacNetworkServices(output string) []string {
	services := []string{}
	lines := dnsTextLines(output)
	for index, line := range lines {
		if index == 0 || strings.TrimSpace(line) == "" || strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}
	return services
}

// parseMacDNSServers reads `networksetup -getdnsservers <service>`: an address per line, or a
// sentence saying there are none, which is kept as `Empty` -- the word networksetup takes back to
// mean "use what DHCP gives".
func parseMacDNSServers(output string) []string {
	servers := []string{}
	for _, line := range dnsTextLines(output) {
		text := strings.TrimSpace(line)
		if text == "" {
			continue
		}
		if net.ParseIP(stripDNSServer(text)) == nil {
			return []string{"Empty"}
		}
		servers = append(servers, text)
	}
	if len(servers) == 0 {
		return []string{"Empty"}
	}
	return servers
}

var (
	scutilResolverLine = regexp.MustCompile(`^resolver #\d+$`)
	scutilFieldLine    = regexp.MustCompile(`^(\w+)(?:\[(\d+)\])?\s*:\s*(.*)$`)
)

// parseScutilDNS reads `scutil --dns`: the servers of the first resolver in the unscoped section that
// has no `domain` line, the one every name without a more specific resolver goes to.
func parseScutilDNS(output string) []string {
	type resolver struct {
		domain  bool
		servers []string
	}
	var resolvers []*resolver
	var current *resolver
	for _, line := range dnsTextLines(output) {
		text := strings.TrimSpace(line)
		if strings.HasPrefix(text, "DNS configuration (for scoped queries)") {
			break
		}
		if scutilResolverLine.MatchString(text) {
			current = &resolver{}
			resolvers = append(resolvers, current)
			continue
		}
		if current == nil {
			continue
		}
		match := scutilFieldLine.FindStringSubmatch(text)
		if match == nil {
			continue
		}
		switch match[1] {
		case "domain":
			current.domain = true
		case "nameserver":
			current.servers = append(current.servers, stripDNSServer(match[3]))
		}
	}
	for _, candidate := range resolvers {
		if !candidate.domain && len(candidate.servers) > 0 {
			return candidate.servers
		}
	}
	return []string{}
}

// decodeWindowsJSONList reads what a Windows reader prints: nothing, one object, or an array of them.
func decodeWindowsJSONList(text string) ([]map[string]any, error) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	var document any
	if err := json.Unmarshal([]byte(text), &document); err != nil {
		return nil, err
	}
	var items []any
	switch typed := document.(type) {
	case map[string]any:
		items = []any{typed}
	case []any:
		items = typed
	}
	entries := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if entry, ok := item.(map[string]any); ok {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// stringOrStrings reads a PowerShell property that is a string when it holds one value and an array
// when it holds several.
func stringOrStrings(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	}
	return nil
}

// parseWindowsDNSServers reads egressDNSWindowsReadServers: the DNS servers of the connected IPv4
// interfaces in the order printed, leaving out this client's own TUN by its interface index.
func parseWindowsDNSServers(text string, tunnelIndex int) ([]string, error) {
	entries, err := decodeWindowsJSONList(text)
	if err != nil {
		return nil, err
	}
	servers := []string{}
	for _, entry := range entries {
		if index, ok := entry["InterfaceIndex"].(float64); ok && index == float64(tunnelIndex) {
			continue
		}
		for _, address := range stringOrStrings(entry["ServerAddresses"]) {
			if server := stripDNSServer(address); server != "" {
				servers = append(servers, server)
			}
		}
	}
	return servers, nil
}

// parseWindowsNRPT reads egressDNSWindowsReadNRPT and reports whether a rule for the root namespace
// that is not ours is already there: then every name already goes where somebody else decided.
func parseWindowsNRPT(text string) (bool, error) {
	entries, err := decodeWindowsJSONList(text)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		root := false
		for _, namespace := range stringOrStrings(entry["Namespace"]) {
			root = root || namespace == "."
		}
		comment, ok := entry["Comment"].(string)
		if root && (!ok || comment != egressDNSNRPTComment) {
			return true, nil
		}
	}
	return false, nil
}

// egressDNSLinuxMode picks how Linux is taken over: through systemd-resolved when it runs and
// applications reach it through its stub, otherwise by rewriting /etc/resolv.conf -- but only a plain
// file. A symlink belongs to some other program, which would overwrite what we wrote whenever it
// liked and leave no telling what to put back.
func egressDNSLinuxMode(resolvectlOK bool, resolvConfServers []string, resolvConfIsSymlink bool) (mode, reason string) {
	if resolvectlOK && len(resolvConfServers) > 0 {
		stubs := true
		for _, server := range resolvConfServers {
			stubs = stubs && (server == egressDNSResolvedStubs[0] || server == egressDNSResolvedStubs[1])
		}
		if stubs {
			return egressDNSPlatformResolved, ""
		}
	}
	if resolvConfIsSymlink {
		return "", egressDNSRefusedManaged
	}
	return egressDNSPlatformResolvConf, ""
}

// classifyEgressDNSUpstreams turns the servers the system uses into the upstreams the responder
// forwards to, or says why the takeover is refused.
//
// A server on loopback, in the pool or the mesh, or on one of this device's tunnel interfaces means
// something else already sits where the system sends its queries. Recording it as the value to put
// back would, on rollback, point the system at something that may no longer exist -- the rollback
// trap. IPv6 servers are not forwarded to in this version and are skipped, except ::1, which is a
// loopback like any other. Upstreams are IPv4, deduplicated, in the order read.
func classifyEgressDNSUpstreams(servers, virtualAddresses []string, pool, mesh string) ([]string, string) {
	poolCIDR, _ := parseEgressCIDR(pool)
	meshCIDR, _ := parseEgressCIDR(mesh)
	virtual := map[string]bool{}
	for _, address := range virtualAddresses {
		virtual[address] = true
	}
	upstreams := []string{}
	seen := map[string]bool{}
	for _, text := range servers {
		server := stripDNSServer(text)
		ip := net.ParseIP(server)
		if ip == nil {
			continue
		}
		if strings.Contains(server, ":") {
			// Written as IPv6: only its own loopback matters here.
			if ip.Equal(net.IPv6loopback) {
				return nil, egressDNSRefusedLoopback
			}
			continue
		}
		address, _ := parseEgressAddress(ip.To4().String())
		if ip.IsLoopback() {
			return nil, egressDNSRefusedLoopback
		}
		if ip.IsUnspecified() {
			continue
		}
		normalized := formatEgressAddress(address)
		if poolCIDR.prefixLen > 0 && poolCIDR.contains(address) || meshCIDR.prefixLen > 0 && meshCIDR.contains(address) ||
			virtual[normalized] {
			return nil, egressDNSRefusedVirtual
		}
		if !seen[normalized] {
			seen[normalized] = true
			upstreams = append(upstreams, normalized)
		}
	}
	if len(upstreams) == 0 {
		return nil, egressDNSRefusedNoUpstream
	}
	return upstreams, ""
}

// egressDNSStep is one step of taking over or giving back: a command line run without a shell, or,
// for the file and the macOS services, an action decided when it runs.
type egressDNSStep struct {
	Argv []string
	// Write replaces a file with Content.
	Write, Content string
	// Restore puts a file back as revertResolvConf decides.
	Restore string
	// RestoreService puts a macOS service's DNS back as revertMacService decides.
	RestoreService string
}

// egressDNSPlan is the steps that take over and the ones that give back. Giving back is safe to run
// in full whatever part of taking over happened, which is what lets a takeover that failed halfway
// and a journal left by a killed process be undone the same way.
type egressDNSPlan struct {
	Apply, Revert []egressDNSStep
}

func windowsPowerShell(script string) []string {
	return []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script}
}

// egressDNSTakeoverPlan is the plan for one platform. services are the macOS services taken over, in
// the order they were listed.
func egressDNSTakeoverPlan(platform, listen, tunnel string, services []string) (egressDNSPlan, bool) {
	command := func(argv ...string) egressDNSStep { return egressDNSStep{Argv: argv} }
	switch platform {
	case egressDNSPlatformResolved:
		return egressDNSPlan{
			Apply: []egressDNSStep{command("resolvectl", "dns", tunnel, listen), command("resolvectl", "domain", tunnel, "~."),
				command("resolvectl", "flush-caches")},
			Revert: []egressDNSStep{command("resolvectl", "revert", tunnel), command("resolvectl", "flush-caches")},
		}, true
	case egressDNSPlatformResolvConf:
		return egressDNSPlan{
			Apply:  []egressDNSStep{{Write: egressDNSResolvConf, Content: egressDNSResolvConfWritten}},
			Revert: []egressDNSStep{{Restore: egressDNSResolvConf}},
		}, true
	case egressDNSPlatformMacOS:
		var plan egressDNSPlan
		for _, service := range services {
			plan.Apply = append(plan.Apply, command("networksetup", "-setdnsservers", service, listen))
			plan.Revert = append(plan.Revert, egressDNSStep{RestoreService: service})
		}
		flush := []egressDNSStep{command("dscacheutil", "-flushcache"), command("killall", "-HUP", "mDNSResponder")}
		plan.Apply = append(plan.Apply, flush...)
		plan.Revert = append(plan.Revert, flush...)
		return plan, true
	case egressDNSPlatformWindows:
		return egressDNSPlan{
			Apply: []egressDNSStep{command(windowsPowerShell("Add-DnsClientNrptRule -Namespace '.' -NameServers '" +
				listen + "' -Comment '" + egressDNSNRPTComment + "'; Clear-DnsClientCache")...)},
			Revert: []egressDNSStep{command(windowsPowerShell("Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '" +
				egressDNSNRPTComment + "' } | Remove-DnsClientNrptRule -Force; Clear-DnsClientCache")...)},
		}, true
	}
	return egressDNSPlan{}, false
}

// revertResolvConf decides what giving back does to /etc/resolv.conf: the original goes back only if
// the file still holds what we wrote. Anything else was written by somebody after us, and theirs is
// kept, with a warning, rather than overwritten.
func revertResolvConf(current, original string) (restore bool, warning string) {
	if current == egressDNSResolvConfWritten {
		return true, ""
	}
	return false, "resolv-conf-changed"
}

// revertMacService decides the same for one macOS service: only a service still pointing at the
// responder alone is put back, to exactly what it had, `Empty` included.
func revertMacService(service string, current, original []string, listen string) (command []string, warning string) {
	if len(current) == 1 && current[0] == listen {
		return append([]string{"networksetup", "-setdnsservers", service}, original...), ""
	}
	return nil, "service-dns-changed"
}
