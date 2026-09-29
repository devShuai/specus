"""Generate peer-egress-dns-takeover-v1.json: the shared cases for step five of phase two (#52).

Step five points the system's DNS at the responder and puts it back. The parts that must come out
the same in three languages are all pure: reading each platform's DNS settings out of the text its
tools print, deciding whether those settings can be taken over and which upstreams to forward to,
the exact commands that take over and give back, and what a rollback does when someone else has
changed the setting in the meantime. Running the commands, the journal file and the timing are
per-language and tested there. See protocol/spec/peer-egress-dns.md, section 六.

Every expectation is produced by the reference implementation here and asserted against a
hand-checked value before writing.
"""
import ipaddress
import json
import re
from pathlib import Path

VECTORS = Path("protocol/test-vectors")
MESH_CIDR = "100.96.0.0/11"
POOL_CIDR = "198.18.0.0/15"
LISTEN = "198.18.0.1"
TUNNEL = "specus0"
NRPT_COMMENT = "specus-peer-egress"
RESOLV_CONF = "/etc/resolv.conf"
RESOLV_CONF_WRITTEN = (
    "# Written by specus for peer egress DNS takeover. The original is kept in the journal\n"
    "# and is put back when the client stops or when `egress dns restore` runs.\n"
    "nameserver 198.18.0.1\n"
)
RESOLVED_STUBS = ("127.0.0.53", "127.0.0.54")


# --------------------------------------------------------------------------------------------------
# Reading the platforms
# --------------------------------------------------------------------------------------------------

def strip_server(text):
    """A server as a tool prints it, without a DNS-over-TLS name (`1.1.1.1#one.one.one.one`) or an
    IPv6 zone (`fe80::1%eth0`)."""
    return text.split("#", 1)[0].split("%", 1)[0].strip()


def parse_resolvectl(output, tunnel):
    """`resolvectl dns`: a `Global:` line and one `Link N (name):` line each, servers after the colon.
    Global first, then the links in the order printed, skipping this client's own tunnel."""
    servers = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Global:"):
            rest = line[len("Global:"):]
        else:
            match = re.match(r"^Link \d+ \(([^)]*)\):(.*)$", line)
            if match is None or match.group(1) == tunnel:
                continue
            rest = match.group(2)
        servers.extend(strip_server(item) for item in rest.split() if strip_server(item))
    return servers


def parse_resolv_conf(text):
    """`nameserver` lines in order. A comment starts with # or ; and runs to the end of the line."""
    servers = []
    for line in text.splitlines():
        line = re.split(r"[#;]", line, maxsplit=1)[0].strip()
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "nameserver":
            servers.append(strip_server(fields[1]))
    return servers


def parse_mac_services(output):
    """`networksetup -listallnetworkservices`: the first line explains the asterisk; a service whose
    name starts with * is disabled and is not touched."""
    lines = output.splitlines()
    services = []
    for line in lines[1:]:
        name = line.rstrip("\r")
        if not name.strip() or name.startswith("*"):
            continue
        services.append(name)
    return services


def parse_mac_dns_servers(output):
    """`networksetup -getdnsservers <service>`: one address per line, or a sentence saying there
    are none, which is recorded as `Empty` -- the word networksetup takes back to mean "use DHCP"."""
    servers = []
    for line in output.splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            ipaddress.ip_address(strip_server(text))
        except ValueError:
            return ["Empty"]
        servers.append(text)
    return servers or ["Empty"]


def parse_scutil(output):
    """`scutil --dns`: the servers of the first resolver of the unscoped section that has no
    `domain` line -- the one every name without a more specific resolver goes to."""
    resolvers = []
    current = None
    for line in output.splitlines():
        text = line.strip()
        if text.startswith("DNS configuration (for scoped queries)"):
            break
        if re.match(r"^resolver #\d+$", text):
            current = {"domain": False, "servers": []}
            resolvers.append(current)
            continue
        if current is None:
            continue
        match = re.match(r"^(\w+)(?:\[(\d+)\])?\s*:\s*(.*)$", text)
        if match is None:
            continue
        key, _, value = match.groups()
        if key == "domain":
            current["domain"] = True
        elif key == "nameserver":
            current["servers"].append(strip_server(value))
    for resolver in resolvers:
        if not resolver["domain"] and resolver["servers"]:
            return resolver["servers"]
    return []


def parse_windows_servers(text, tunnel_index):
    """The JSON the Windows reader prints (see WINDOWS_READ_SERVERS): one object or an array of
    {InterfaceAlias, InterfaceIndex, ServerAddresses}. ServerAddresses is a string when there is one
    address, an array when there are several, null or absent when there are none."""
    document = json.loads(text) if text.strip() else []
    if isinstance(document, dict):
        document = [document]
    servers = []
    for entry in document:
        if not isinstance(entry, dict) or entry.get("InterfaceIndex") == tunnel_index:
            continue
        addresses = entry.get("ServerAddresses")
        if isinstance(addresses, str):
            addresses = [addresses]
        for address in addresses or []:
            if isinstance(address, str) and strip_server(address):
                servers.append(strip_server(address))
    return servers


def parse_windows_nrpt(text):
    """The JSON of the NRPT reader (see WINDOWS_READ_NRPT): whether a rule for the root namespace
    that is not ours is already there. Namespace is a string or an array of strings."""
    document = json.loads(text) if text.strip() else []
    if isinstance(document, dict):
        document = [document]
    for entry in document:
        if not isinstance(entry, dict):
            continue
        namespaces = entry.get("Namespace")
        if isinstance(namespaces, str):
            namespaces = [namespaces]
        if "." in (namespaces or []) and entry.get("Comment") != NRPT_COMMENT:
            return True
    return False


# --------------------------------------------------------------------------------------------------
# Deciding
# --------------------------------------------------------------------------------------------------

def linux_mode(resolvectl_ok, resolv_conf_servers, resolv_conf_is_symlink):
    """systemd-resolved is used only when it runs and applications reach it through its stub;
    otherwise /etc/resolv.conf is rewritten, but only when it is a plain file."""
    if resolvectl_ok and resolv_conf_servers and all(s in RESOLVED_STUBS for s in resolv_conf_servers):
        return {"mode": "resolved", "reason": None}
    if resolv_conf_is_symlink:
        return {"mode": None, "reason": "resolv-conf-managed"}
    return {"mode": "resolvconf", "reason": None}


def classify_upstreams(servers, virtual_addresses, pool=POOL_CIDR, mesh=MESH_CIDR):
    """The upstreams to forward to, or why the takeover is refused.

    A server on loopback, in the pool or the mesh, or on one of this host's tunnel interfaces means
    someone else already sits where the system sends its queries. Recording it as the value to put
    back would, on rollback, point the system at something that may no longer exist."""
    network_pool = ipaddress.IPv4Network(pool)
    network_mesh = ipaddress.IPv4Network(mesh)
    upstreams = []
    for text in servers:
        try:
            address = ipaddress.ip_address(strip_server(text))
        except ValueError:
            continue
        if address.is_loopback:
            return {"code": "EGRESS_DNS_TAKEOVER_REFUSED", "reason": "system-dns-loopback"}
        if address.version == 6:
            continue  # this version forwards over IPv4 only
        if address.is_unspecified:
            continue
        if address in network_pool or address in network_mesh or str(address) in virtual_addresses:
            return {"code": "EGRESS_DNS_TAKEOVER_REFUSED", "reason": "system-dns-virtual"}
        if str(address) not in upstreams:
            upstreams.append(str(address))
    if not upstreams:
        return {"code": "EGRESS_DNS_TAKEOVER_REFUSED", "reason": "no-upstream"}
    return {"code": None, "upstreams": upstreams}


# --------------------------------------------------------------------------------------------------
# Taking over and giving back
# --------------------------------------------------------------------------------------------------

WINDOWS_READ_SERVERS = (
    "$up = @(Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected | "
    "Select-Object -ExpandProperty InterfaceIndex); "
    "ConvertTo-Json -Compress -Depth 3 -InputObject @(Get-DnsClientServerAddress -AddressFamily IPv4 | "
    "Where-Object { $up -contains $_.InterfaceIndex } | "
    "Select-Object InterfaceAlias,InterfaceIndex,ServerAddresses)"
)
WINDOWS_READ_NRPT = (
    "ConvertTo-Json -Compress -Depth 3 -InputObject @(Get-DnsClientNrptRule | "
    "Select-Object Namespace,Comment,NameServers)"
)


def powershell(script):
    return ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script]


def plan(platform, listen=LISTEN, tunnel=TUNNEL, services=None):
    """The commands that take over and the ones that give back. Giving back is safe to run in full
    whatever part of taking over happened, which is what lets a failed takeover and a journal left
    by a killed process be undone the same way."""
    if platform == "linux-resolved":
        return {
            "apply": [["resolvectl", "dns", tunnel, listen], ["resolvectl", "domain", tunnel, "~."],
                      ["resolvectl", "flush-caches"]],
            "revert": [["resolvectl", "revert", tunnel], ["resolvectl", "flush-caches"]],
        }
    if platform == "linux-resolvconf":
        return {"apply": [{"write": RESOLV_CONF, "content": RESOLV_CONF_WRITTEN}],
                "revert": [{"restore": RESOLV_CONF}]}
    if platform == "macos":
        flush = [["dscacheutil", "-flushcache"], ["killall", "-HUP", "mDNSResponder"]]
        return {
            "apply": [["networksetup", "-setdnsservers", service, listen] for service in services] + flush,
            "revert": [{"restore-service": service} for service in services] + flush,
        }
    if platform == "windows":
        return {
            "apply": [powershell(f"Add-DnsClientNrptRule -Namespace '.' -NameServers '{listen}' "
                                 f"-Comment '{NRPT_COMMENT}'; Clear-DnsClientCache")],
            "revert": [powershell(f"Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{NRPT_COMMENT}' }} | "
                                  f"Remove-DnsClientNrptRule -Force; Clear-DnsClientCache")],
        }
    raise ValueError(platform)


def revert_resolv_conf(current, original):
    """Put the original back only if the file still holds what we wrote. Anything else was written
    by someone after us, and theirs is kept with a warning rather than overwritten."""
    if current == RESOLV_CONF_WRITTEN:
        return {"action": "restore", "content": original}
    return {"action": "keep", "warning": "resolv-conf-changed"}


def revert_mac_service(service, current, original, listen=LISTEN):
    """The same for one macOS network service: only a service still pointing at the responder alone
    is put back, to exactly what it had, `Empty` included."""
    if current == [listen]:
        return {"action": "restore", "command": ["networksetup", "-setdnsservers", service, *original]}
    return {"action": "keep", "warning": "service-dns-changed"}


# --------------------------------------------------------------------------------------------------
# Cases
# --------------------------------------------------------------------------------------------------

RESOLVECTL = [
    ("links-and-global",
     "Global: 1.1.1.1\nLink 2 (eth0): 192.168.1.1 fe80::1%eth0\nLink 3 (specus0): 198.18.0.1\nLink 4 (wlan0):\n",
     ["1.1.1.1", "192.168.1.1", "fe80::1"]),
    ("empty-global-and-tls-names",
     "Global:\nLink 2 (enp3s0): 9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net\n",
     ["9.9.9.9", "149.112.112.112"]),
    ("only-our-link", "Global:\nLink 7 (specus0): 198.18.0.1\n", []),
]

RESOLV_CONFS = [
    ("stub", "# This is /run/systemd/resolve/stub-resolv.conf\nnameserver 127.0.0.53\noptions edns0 trust-ad\n"
             "search lan\n", ["127.0.0.53"]),
    ("plain", "nameserver 192.168.1.1 ; router\n# nameserver 8.8.8.8\nnameserver 2001:db8::53\n",
     ["192.168.1.1", "2001:db8::53"]),
    ("tabs-and-junk", "domain lan\nnameserver\t10.0.0.2\nnameserver\n", ["10.0.0.2"]),
]

MAC_SERVICES = (
    "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\nThunderbolt Bridge\n"
    "USB 10/100/1000 LAN\n",
    ["Wi-Fi", "Thunderbolt Bridge", "USB 10/100/1000 LAN"],
)

MAC_DNS_SERVERS = [
    ("none-set", "There aren't any DNS Servers set on Wi-Fi.\n", ["Empty"]),
    ("two-set", "1.1.1.1\n2606:4700:4700::1111\n", ["1.1.1.1", "2606:4700:4700::1111"]),
]

SCUTIL = [
    ("default-resolver-first", """DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : 192.168.1.2
  if_index : 6 (en0)
  flags    : Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  order    : 300000

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 10.9.9.9
  if_index : 6 (en0)
""", ["192.168.1.1", "192.168.1.2"]),
    ("domain-resolver-skipped", """DNS configuration

resolver #1
  domain   : corp.example
  nameserver[0] : 10.1.1.1

resolver #2
  nameserver[0] : 8.8.8.8
""", ["8.8.8.8"]),
    ("nothing", "DNS configuration\n\nDNS configuration (for scoped queries)\n", []),
]

WINDOWS_SERVERS = [
    ("array", '[{"InterfaceAlias":"Ethernet","InterfaceIndex":12,"ServerAddresses":["192.168.1.1","8.8.8.8"]},'
              '{"InterfaceAlias":"specus","InterfaceIndex":17,"ServerAddresses":["198.18.0.1"]},'
              '{"InterfaceAlias":"Wi-Fi","InterfaceIndex":9,"ServerAddresses":"192.168.1.1"}]',
     ["192.168.1.1", "8.8.8.8", "192.168.1.1"]),
    ("single-object", '{"InterfaceAlias":"Ethernet","InterfaceIndex":12,"ServerAddresses":["10.0.0.53"]}',
     ["10.0.0.53"]),
    ("no-servers", '[{"InterfaceAlias":"Ethernet","InterfaceIndex":12,"ServerAddresses":null},'
                   '{"InterfaceAlias":"Wi-Fi","InterfaceIndex":9}]', []),
    ("nothing-connected", "", []),
]

WINDOWS_NRPT = [
    ("none", "", False),
    ("ours-only", '[{"Namespace":["."],"Comment":"specus-peer-egress","NameServers":["198.18.0.1"]}]', False),
    ("someone-else-owns-the-root", '{"Namespace":".","Comment":"","NameServers":"10.0.0.1"}', True),
    ("other-namespace-only", '[{"Namespace":[".corp.example"],"Comment":"","NameServers":["10.0.0.1"]}]', False),
]

LINUX_MODES = [
    ("resolved-through-its-stub", True, ["127.0.0.53"], True),
    ("resolved-running-but-bypassed", True, ["192.168.1.1"], False),
    ("resolved-uplink-mode-symlink", True, ["192.168.1.1"], True),
    ("no-resolved-plain-file", False, ["192.168.1.1"], False),
    ("no-resolved-symlink", False, ["192.168.1.1"], True),
]

UPSTREAMS = [
    ("plain", ["192.168.1.1", "8.8.8.8"], []),
    ("dedupe-keep-order", ["192.168.1.1", "8.8.8.8", "192.168.1.1"], []),
    ("ipv6-ignored", ["2001:db8::53", "9.9.9.9"], []),
    ("only-ipv6", ["2001:db8::53"], []),
    ("loopback-refused", ["127.0.0.1", "8.8.8.8"], []),
    ("ipv6-loopback-refused", ["::1"], []),
    ("pool-refused", ["8.8.8.8", "198.18.0.2"], []),
    ("mesh-refused", ["100.96.0.1"], []),
    ("tunnel-address-refused", ["10.8.0.1"], ["10.8.0.1"]),
    ("unspecified-ignored", ["0.0.0.0", "1.1.1.1"], []),
    ("nothing", [], []),
]

REVERT_RESOLV_CONF = [
    ("still-ours", RESOLV_CONF_WRITTEN, "nameserver 192.168.1.1\n"),
    ("rewritten-by-someone", "nameserver 10.0.0.1\n", "nameserver 192.168.1.1\n"),
]

REVERT_MAC = [
    ("still-ours-dhcp", "Wi-Fi", [LISTEN], ["Empty"]),
    ("still-ours-manual", "Wi-Fi", [LISTEN], ["1.1.1.1", "8.8.8.8"]),
    ("changed-by-someone", "Wi-Fi", ["9.9.9.9"], ["Empty"]),
]


def build():
    resolvectl = [{"name": n, "output": o, "tunnel": TUNNEL, "servers": parse_resolvectl(o, TUNNEL)}
                  for n, o, _ in RESOLVECTL]
    assert [c["servers"] for c in resolvectl] == [w for _, _, w in RESOLVECTL], resolvectl
    resolv_conf = [{"name": n, "text": t, "servers": parse_resolv_conf(t)} for n, t, _ in RESOLV_CONFS]
    assert [c["servers"] for c in resolv_conf] == [w for _, _, w in RESOLV_CONFS], resolv_conf
    mac_services = {"output": MAC_SERVICES[0], "services": parse_mac_services(MAC_SERVICES[0])}
    assert mac_services["services"] == MAC_SERVICES[1], mac_services
    mac_dns = [{"name": n, "output": o, "servers": parse_mac_dns_servers(o)} for n, o, _ in MAC_DNS_SERVERS]
    assert [c["servers"] for c in mac_dns] == [w for _, _, w in MAC_DNS_SERVERS], mac_dns
    scutil = [{"name": n, "output": o, "servers": parse_scutil(o)} for n, o, _ in SCUTIL]
    assert [c["servers"] for c in scutil] == [w for _, _, w in SCUTIL], scutil
    windows = [{"name": n, "json": j, "tunnelIndex": 17, "servers": parse_windows_servers(j, 17)}
               for n, j, _ in WINDOWS_SERVERS]
    assert [c["servers"] for c in windows] == [w for _, _, w in WINDOWS_SERVERS], windows
    nrpt = [{"name": n, "json": j, "foreignRoot": parse_windows_nrpt(j)} for n, j, _ in WINDOWS_NRPT]
    assert [c["foreignRoot"] for c in nrpt] == [w for _, _, w in WINDOWS_NRPT], nrpt
    modes = [{"name": n, "resolvectlOk": ok, "resolvConfServers": servers, "resolvConfIsSymlink": link,
              **linux_mode(ok, servers, link)} for n, ok, servers, link in LINUX_MODES]
    assert [(c["mode"], c["reason"]) for c in modes] == [
        ("resolved", None), ("resolvconf", None), (None, "resolv-conf-managed"), ("resolvconf", None),
        (None, "resolv-conf-managed")], modes
    upstreams = [{"name": n, "servers": s, "virtualAddresses": v, **classify_upstreams(s, v)}
                 for n, s, v in UPSTREAMS]
    assert [c.get("upstreams") or c["reason"] for c in upstreams] == [
        ["192.168.1.1", "8.8.8.8"], ["192.168.1.1", "8.8.8.8"], ["9.9.9.9"], "no-upstream",
        "system-dns-loopback", "system-dns-loopback", "system-dns-virtual", "system-dns-virtual",
        "system-dns-virtual", ["1.1.1.1"], "no-upstream"], upstreams
    plans = [
        {"platform": "linux-resolved", "listen": LISTEN, "tunnel": TUNNEL, **plan("linux-resolved")},
        {"platform": "linux-resolvconf", "listen": LISTEN, **plan("linux-resolvconf")},
        {"platform": "macos", "listen": LISTEN, "services": mac_services["services"],
         **plan("macos", services=mac_services["services"])},
        {"platform": "windows", "listen": LISTEN, **plan("windows")},
    ]
    assert plans[0]["apply"][1] == ["resolvectl", "domain", "specus0", "~."], plans[0]
    assert plans[3]["revert"][0][-1] == (
        "Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'specus-peer-egress' } | "
        "Remove-DnsClientNrptRule -Force; Clear-DnsClientCache"), plans[3]
    revert_conf = [{"name": n, "current": c, "original": o, **revert_resolv_conf(c, o)}
                   for n, c, o in REVERT_RESOLV_CONF]
    assert [c["action"] for c in revert_conf] == ["restore", "keep"], revert_conf
    revert_mac = [{"name": n, "service": s, "current": c, "original": o, **revert_mac_service(s, c, o)}
                  for n, s, c, o in REVERT_MAC]
    assert revert_mac[0]["command"] == ["networksetup", "-setdnsservers", "Wi-Fi", "Empty"], revert_mac
    assert [c["action"] for c in revert_mac] == ["restore", "restore", "keep"], revert_mac
    return {
        "description": "Phase two, step five: reading each platform's DNS settings, deciding whether "
                       "they can be taken over and which upstreams to forward to, the commands that "
                       "take over and give back, and rollback over someone else's change. See "
                       "protocol/spec/peer-egress-dns.md.",
        "meshCidr": MESH_CIDR,
        "fakeIpCidr": POOL_CIDR,
        "listen": LISTEN,
        "nrptComment": NRPT_COMMENT,
        "resolvConfWritten": RESOLV_CONF_WRITTEN,
        "resolvedStubs": list(RESOLVED_STUBS),
        "windowsReadServers": WINDOWS_READ_SERVERS,
        "windowsReadNrpt": WINDOWS_READ_NRPT,
        "parseResolvectl": resolvectl,
        "parseResolvConf": resolv_conf,
        "parseMacServices": mac_services,
        "parseMacDnsServers": mac_dns,
        "parseScutil": scutil,
        "parseWindowsServers": windows,
        "parseWindowsNrpt": nrpt,
        "linuxMode": modes,
        "upstreams": upstreams,
        "plan": plans,
        "revertResolvConf": revert_conf,
        "revertMacService": revert_mac,
    }


def main():
    document = build()
    path = VECTORS / "peer-egress-dns-takeover-v1.json"
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {path}: upstreams={len(document['upstreams'])} plans={len(document['plan'])}")


if __name__ == "__main__":
    main()
