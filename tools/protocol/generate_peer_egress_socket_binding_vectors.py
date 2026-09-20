"""Generate peer-egress-socket-binding-v1.json.

The egress opens a real socket to the target on a consumer's behalf. On a node that is also a
consumer, its own tunnel routes cover some of those targets, and a socket that followed them would
send the forwarded traffic back into the mesh. So on Windows and macOS the socket is bound to the
interface the operating system would have used had the tunnel's routes not been there:
IP_UNICAST_IF on Windows, IP_BOUND_IF on macOS.

Choosing that interface is a longest-prefix match over the IPv4 routing table with the tunnel's own
interface left out, which is what this file pins. Three things about it were measured rather than
assumed, on Windows 11 (build 26200). The macOS side of the first one is not sampled here; the macOS
CI job asserts it against a real socket instead.

First: the binding is enforced by the stack, not advisory. Bound to an interface that has no route to
the destination, connect fails straight away -- "A socket operation was attempted to an unreachable
network" on Windows -- rather than leaving by another interface. Bound to a physical interface,
a connect to 127.0.0.1 fails too. So the choice has to be made per destination: binding every socket
to the default route's interface would break every target reached through anything else, another
VPN's routes and a second NIC's subnet included.

Second: on Windows the index goes in network byte order. Passed in host order, setsockopt itself
refuses it ("The requested address is not valid in its context"), so the mistake is loud; the
encoding is still pinned here, because on macOS the same option takes host order and the two are
easy to cross.

Third: on Windows the table is read natively, with GetIpForwardTable2 and GetIpInterfaceTable, not
with Get-NetRoute. The choice is made on every connect, and a PowerShell query costs 419 ms; the two
native calls cost microseconds and need no cache, so a changed network is seen by the next connect.
The row layouts below are the SDK's, built with ctypes; the offsets were checked against
Get-NetRoute and Get-NetIPInterface on the machine above, and each runtime's test suite checks them
against the same two cmdlets again on every Windows CI run. On macOS the table comes from the same
`netstat -rn -f inet` the route commander already reads, at 25 ms.

The Windows effective metric of a route is its own metric plus its interface's metric, which is how
Windows ranks two routes of equal length. A route on an interface that is not connected is not used,
nor is a default route on an interface that has DisableDefaultRoutes set. On macOS a route carrying
the I flag is scoped to its interface and never chosen for a socket that is not already bound to it,
so it is not a candidate either.

The same reading answers a second question: where a consumer's bypass route should point. A bypass
keeps the tunnel's own transport -- the control connection, STUN, TURN, a peer -- off a rule that
covers it, and its next hop is asked of the platform (`ip route get`, Find-NetRoute, `route -n get`).
Once a rule's route is in the table that question answers with the tunnel, which is exactly when a
bypass is needed: sampled on Linux, `ip route get 203.0.113.9` said `dev specus0` in a namespace
where 203.0.113.0/24 had been routed into it. So when the platform answers with the tunnel, the hop
comes from the table instead, by the same choice with this feature's own bypass prefixes also left
out, and with a route that leads nowhere -- blackhole, prohibit, unreachable -- meaning no hop rather
than a reason to try the next route.

The expectations come from the reference implementation in this file, not from any of the three
runtimes. The macOS tables are copied verbatim from the sampled captures in
peer-egress-macos-routes-v1.json, and their normalised prefixes are taken from that file's
expectations rather than recomputed. The Linux tables are captures too, taken in network namespaces
built for the purpose; see the block that holds them.
"""
import ctypes
import ipaddress
import json
from pathlib import Path

VECTORS = Path("protocol/test-vectors")

AF_INET = 2
AF_INET6 = 23

# ---- reference selection ----------------------------------------------------------------------


def select_route(routes, tunnel, destination, owned=()):
    """The route a packet to destination would take with this feature's own routes left out.

    Longest prefix first, then the lowest metric, then the route listed first. Routes that are not
    usable, routes on the tunnel's own interface, and routes whose prefix this feature owns are not
    candidates. The tunnel is compared by exact equality: utun30 is not utun3.
    """
    address = ipaddress.IPv4Address(destination)
    owned = set(owned)
    best = None
    best_key = None
    for route in routes:
        if not route["usable"]:
            continue
        if tunnel and route["interface"] == tunnel:
            continue
        if route["prefix"] in owned:
            continue
        network = ipaddress.IPv4Network(route["prefix"])
        if address not in network:
            continue
        key = (network.prefixlen, -route["metric"])
        # Strictly greater, so a tie keeps the route listed first.
        if best_key is None or key > best_key:
            best, best_key = route, key
    return best


def select_interface(routes, tunnel, destination):
    """The interface a socket to destination is bound to, or None when nothing but the tunnel leads there."""
    chosen = select_route(routes, tunnel, destination)
    return None if chosen is None else chosen["interface"]


def select_hop(routes, tunnel, destination, owned=()):
    """Where a bypass route for destination points, or None.

    None both when nothing but the tunnel leads there and when the route that wins leads nowhere --
    a blackhole, prohibit or unreachable route has no interface. Pinning a bypass through some other
    route would reach an address the table deliberately does not.
    """
    chosen = select_route(routes, tunnel, destination, owned)
    if chosen is None or chosen["interface"] == "":
        return None
    return {"interface": chosen["interface"], "gateway": chosen["gateway"]}


def route(prefix, interface, metric=0, usable=True, gateway=""):
    return {"prefix": prefix, "interface": interface, "gateway": gateway, "metric": metric,
            "usable": usable}


SELECT_CASES = [
    {
        "name": "default-only",
        "note": "The common case: one physical default route and nothing else.",
        "routes": [route("0.0.0.0/0", "3", 20)],
        "tunnel": "42",
        "destination": "203.0.113.9",
    },
    {
        "name": "tunnel-route-is-left-out",
        "note": "The case the binding exists for. This node's own consumer rule sends 203.0.113.0/24 "
                "into the tunnel; the egress socket must take the default route instead.",
        "routes": [route("0.0.0.0/0", "3", 276), route("203.0.113.0/24", "42", 5)],
        "tunnel": "42",
        "destination": "203.0.113.9",
    },
    {
        "name": "without-a-tunnel-the-tunnel-route-would-win",
        "note": "The same table with no tunnel named, which is what makes the previous case "
                "load-bearing: leaving the tunnel out is the only thing that changes the answer.",
        "routes": [route("0.0.0.0/0", "3", 276), route("203.0.113.0/24", "42", 5)],
        "tunnel": "",
        "destination": "203.0.113.9",
    },
    {
        "name": "another-vpn-keeps-its-routes",
        "note": "A route on some other interface -- a corporate VPN, a second NIC -- is not the "
                "tunnel and is respected, which binding everything to the default interface would "
                "break.",
        "routes": [route("0.0.0.0/0", "3", 276), route("10.0.0.0/8", "7", 30),
                   route("10.1.0.0/16", "42", 5)],
        "tunnel": "42",
        "destination": "10.1.2.3",
    },
    {
        "name": "prefix-length-beats-metric",
        "note": "A longer prefix wins however large its metric is.",
        "routes": [route("10.0.0.0/8", "7", 5), route("10.1.0.0/16", "3", 9000)],
        "tunnel": "42",
        "destination": "10.1.2.3",
    },
    {
        "name": "equal-length-lower-metric-wins",
        "note": "Two default routes, as on a laptop with both Ethernet and Wi-Fi up.",
        "routes": [route("0.0.0.0/0", "15", 291), route("0.0.0.0/0", "3", 276)],
        "tunnel": "42",
        "destination": "198.51.100.1",
    },
    {
        "name": "equal-length-equal-metric-first-listed-wins",
        "note": "A full tie keeps table order, so every runtime reading the same table agrees.",
        "routes": [route("0.0.0.0/0", "15", 276), route("0.0.0.0/0", "3", 276)],
        "tunnel": "42",
        "destination": "198.51.100.1",
    },
    {
        "name": "unusable-route-is-left-out",
        "note": "A route on a disconnected interface, or a scoped route on macOS, is not a candidate "
                "however good it looks.",
        "routes": [route("0.0.0.0/0", "15", 1, usable=False), route("0.0.0.0/0", "3", 276)],
        "tunnel": "42",
        "destination": "198.51.100.1",
    },
    {
        "name": "only-the-tunnel-leads-there",
        "note": "No physical path. The dial is refused rather than left unbound, because unbound is "
                "exactly the socket that would follow the tunnel route.",
        "routes": [route("203.0.113.0/24", "42", 5)],
        "tunnel": "42",
        "destination": "203.0.113.9",
    },
    {
        "name": "no-route-at-all",
        "routes": [route("10.0.0.0/8", "3", 20)],
        "tunnel": "42",
        "destination": "203.0.113.9",
    },
    {
        "name": "last-address-in-prefix",
        "routes": [route("203.0.113.0/24", "3", 20), route("0.0.0.0/0", "15", 20)],
        "tunnel": "42",
        "destination": "203.0.113.255",
    },
    {
        "name": "first-address-past-prefix",
        "routes": [route("203.0.113.0/24", "3", 20), route("0.0.0.0/0", "15", 20)],
        "tunnel": "42",
        "destination": "203.0.114.0",
    },
    {
        "name": "tunnel-name-match-is-exact",
        "note": "utun30 is some other product's tunnel, not utun3.",
        "routes": [route("0.0.0.0/0", "en0"), route("203.0.113.0/24", "utun30")],
        "tunnel": "utun3",
        "destination": "203.0.113.9",
    },
    {
        "name": "host-route",
        "routes": [route("0.0.0.0/0", "3", 20), route("198.51.100.7/32", "7", 20)],
        "tunnel": "42",
        "destination": "198.51.100.7",
    },
    {
        "name": "loopback-destination",
        "note": "What the real-socket tests lean on: 127.0.0.1 resolves to the loopback interface, "
                "and a socket bound anywhere else cannot reach it.",
        "routes": [route("0.0.0.0/0", "3", 20), route("127.0.0.0/8", "1", 331)],
        "tunnel": "42",
        "destination": "127.0.0.1",
    },
    {
        "name": "tunnel-owns-a-default-route",
        "note": "Phase one refuses a 0.0.0.0/0 rule, but whatever routes the tunnel carries, they are "
                "left out the same way.",
        "routes": [route("0.0.0.0/0", "42", 5), route("0.0.0.0/0", "3", 276)],
        "tunnel": "42",
        "destination": "198.51.100.1",
    },
]

for case in SELECT_CASES:
    case["expect"] = {"interface": select_interface(case["routes"], case["tunnel"],
                                                    case["destination"])}

# ---- Windows native tables --------------------------------------------------------------------


class SOCKADDR_IN(ctypes.Structure):
    _fields_ = [("sin_family", ctypes.c_uint16), ("sin_port", ctypes.c_uint16),
                ("sin_addr", ctypes.c_uint8 * 4), ("sin_zero", ctypes.c_uint8 * 8)]


class SOCKADDR_IN6(ctypes.Structure):
    _fields_ = [("sin6_family", ctypes.c_uint16), ("sin6_port", ctypes.c_uint16),
                ("sin6_flowinfo", ctypes.c_uint32), ("sin6_addr", ctypes.c_uint8 * 16),
                ("sin6_scope_id", ctypes.c_uint32)]


class SOCKADDR_INET(ctypes.Union):
    _fields_ = [("Ipv4", SOCKADDR_IN), ("Ipv6", SOCKADDR_IN6), ("si_family", ctypes.c_uint16)]


class IP_ADDRESS_PREFIX(ctypes.Structure):
    _fields_ = [("Prefix", SOCKADDR_INET), ("PrefixLength", ctypes.c_uint8)]


class MIB_IPFORWARD_ROW2(ctypes.Structure):
    _fields_ = [
        ("InterfaceLuid", ctypes.c_uint64),
        ("InterfaceIndex", ctypes.c_uint32),
        ("DestinationPrefix", IP_ADDRESS_PREFIX),
        ("NextHop", SOCKADDR_INET),
        ("SitePrefixLength", ctypes.c_uint8),
        ("ValidLifetime", ctypes.c_uint32),
        ("PreferredLifetime", ctypes.c_uint32),
        ("Metric", ctypes.c_uint32),
        ("Protocol", ctypes.c_int32),
        ("Loopback", ctypes.c_uint8),
        ("AutoconfigureAddress", ctypes.c_uint8),
        ("Publish", ctypes.c_uint8),
        ("Immortal", ctypes.c_uint8),
        ("Age", ctypes.c_uint32),
        ("Origin", ctypes.c_int32),
    ]


class MIB_IPINTERFACE_ROW(ctypes.Structure):
    _fields_ = [
        ("Family", ctypes.c_uint16),
        ("InterfaceLuid", ctypes.c_uint64),
        ("InterfaceIndex", ctypes.c_uint32),
        ("MaxReassemblySize", ctypes.c_uint32),
        ("InterfaceIdentifier", ctypes.c_uint64),
        ("MinRouterAdvertisementInterval", ctypes.c_uint32),
        ("MaxRouterAdvertisementInterval", ctypes.c_uint32),
        ("AdvertisingEnabled", ctypes.c_uint8),
        ("ForwardingEnabled", ctypes.c_uint8),
        ("WeakHostSend", ctypes.c_uint8),
        ("WeakHostReceive", ctypes.c_uint8),
        ("UseAutomaticMetric", ctypes.c_uint8),
        ("UseNeighborUnreachabilityDetection", ctypes.c_uint8),
        ("ManagedAddressConfigurationSupported", ctypes.c_uint8),
        ("OtherStatefulConfigurationSupported", ctypes.c_uint8),
        ("AdvertiseDefaultRoute", ctypes.c_uint8),
        ("RouterDiscoveryBehavior", ctypes.c_int32),
        ("DadTransmits", ctypes.c_uint32),
        ("BaseReachableTime", ctypes.c_uint32),
        ("RetransmitTime", ctypes.c_uint32),
        ("PathMtuDiscoveryTimeout", ctypes.c_uint32),
        ("LinkLocalAddressBehavior", ctypes.c_int32),
        ("LinkLocalAddressTimeout", ctypes.c_uint32),
        ("ZoneIndices", ctypes.c_uint32 * 16),
        ("SitePrefixLength", ctypes.c_uint32),
        ("Metric", ctypes.c_uint32),
        ("NlMtu", ctypes.c_uint32),
        ("Connected", ctypes.c_uint8),
        ("SupportsWakeUpPatterns", ctypes.c_uint8),
        ("SupportsNeighborDiscovery", ctypes.c_uint8),
        ("SupportsRouterDiscovery", ctypes.c_uint8),
        ("ReachableTime", ctypes.c_uint32),
        ("TransmitOffload", ctypes.c_uint8),
        ("ReceiveOffload", ctypes.c_uint8),
        ("DisableDefaultRoutes", ctypes.c_uint8),
    ]


# The offsets the runtimes read at, as measured on Windows 11 against Get-NetRoute and
# Get-NetIPInterface. The ctypes layouts above have to land on exactly these, or one of the two is
# wrong.
LAYOUT = {
    "tableHeader": 8,
    "forwardRow": {
        "size": 104,
        "interfaceIndex": 8,
        "prefixFamily": 12,
        "prefixAddress": 16,
        "prefixLength": 40,
        "nextHopFamily": 44,
        "nextHopAddress": 48,
        "metric": 84,
    },
    "interfaceRow": {
        "size": 168,
        "family": 0,
        "interfaceIndex": 16,
        "metric": 148,
        "connected": 156,
        "disableDefaultRoutes": 166,
    },
}


def offset(structure, *path):
    total = 0
    current = structure
    for name in path:
        field = getattr(current, name)
        total += field.offset
        current = dict(current._fields_)[name]
    return total


assert ctypes.sizeof(MIB_IPFORWARD_ROW2) == LAYOUT["forwardRow"]["size"]
assert offset(MIB_IPFORWARD_ROW2, "InterfaceIndex") == LAYOUT["forwardRow"]["interfaceIndex"]
assert offset(MIB_IPFORWARD_ROW2, "DestinationPrefix", "Prefix") == LAYOUT["forwardRow"]["prefixFamily"]
assert offset(MIB_IPFORWARD_ROW2, "DestinationPrefix", "Prefix") + SOCKADDR_IN.sin_addr.offset \
    == LAYOUT["forwardRow"]["prefixAddress"]
assert offset(MIB_IPFORWARD_ROW2, "DestinationPrefix", "PrefixLength") == LAYOUT["forwardRow"]["prefixLength"]
assert offset(MIB_IPFORWARD_ROW2, "NextHop") == LAYOUT["forwardRow"]["nextHopFamily"]
assert offset(MIB_IPFORWARD_ROW2, "NextHop") + SOCKADDR_IN.sin_addr.offset \
    == LAYOUT["forwardRow"]["nextHopAddress"]
assert offset(MIB_IPFORWARD_ROW2, "Metric") == LAYOUT["forwardRow"]["metric"]
assert ctypes.sizeof(MIB_IPINTERFACE_ROW) == LAYOUT["interfaceRow"]["size"]
assert offset(MIB_IPINTERFACE_ROW, "Family") == LAYOUT["interfaceRow"]["family"]
assert offset(MIB_IPINTERFACE_ROW, "InterfaceIndex") == LAYOUT["interfaceRow"]["interfaceIndex"]
assert offset(MIB_IPINTERFACE_ROW, "Metric") == LAYOUT["interfaceRow"]["metric"]
assert offset(MIB_IPINTERFACE_ROW, "Connected") == LAYOUT["interfaceRow"]["connected"]
assert offset(MIB_IPINTERFACE_ROW, "DisableDefaultRoutes") == LAYOUT["interfaceRow"]["disableDefaultRoutes"]


def table_bytes(rows, row_size, declared=None):
    """A MIB table as the API returns it: a ULONG count, padding to eight, then the rows."""
    count = len(rows) if declared is None else declared
    header = count.to_bytes(4, "little") + b"\x00" * 4
    body = b"".join(bytes(row) for row in rows)
    assert all(len(bytes(row)) == row_size for row in rows)
    return header + body


def forward_row(index, prefix, metric, family=AF_INET, next_hop="0.0.0.0", luid=None,
                length=None, raw_address=None):
    row = MIB_IPFORWARD_ROW2()
    row.InterfaceLuid = luid if luid is not None else (0x0006000000000000 | index)
    row.InterfaceIndex = index
    address, _, bits = prefix.partition("/")
    row.DestinationPrefix.Prefix.si_family = family
    if family == AF_INET:
        packed = ipaddress.IPv4Address(raw_address or address).packed
        for i, byte in enumerate(packed):
            row.DestinationPrefix.Prefix.Ipv4.sin_addr[i] = byte
        hop = ipaddress.IPv4Address(next_hop).packed
        row.NextHop.si_family = AF_INET
        for i, byte in enumerate(hop):
            row.NextHop.Ipv4.sin_addr[i] = byte
    else:
        packed = ipaddress.IPv6Address(address).packed
        for i, byte in enumerate(packed):
            row.DestinationPrefix.Prefix.Ipv6.sin6_addr[i] = byte
        row.NextHop.si_family = AF_INET6
    row.DestinationPrefix.PrefixLength = int(bits) if length is None else length
    row.ValidLifetime = 0xFFFFFFFF
    row.PreferredLifetime = 0xFFFFFFFF
    row.Metric = metric
    row.Protocol = 3 if prefix == "0.0.0.0/0" else 2
    row.Immortal = 0
    row.Origin = 0
    return row


def interface_row(index, metric, connected, disable_default_routes=False, family=AF_INET):
    row = MIB_IPINTERFACE_ROW()
    row.Family = family
    row.InterfaceLuid = 0x0006000000000000 | index
    row.InterfaceIndex = index
    row.UseAutomaticMetric = 1
    row.Metric = metric
    row.NlMtu = 1500
    row.Connected = 1 if connected else 0
    row.DisableDefaultRoutes = 1 if disable_default_routes else 0
    # Fill the fields nobody reads with something other than zero, so a reader that is one field
    # off lands on a value it cannot mistake for the right one.
    row.MaxReassemblySize = 0xFFFF
    row.DadTransmits = 3
    row.SitePrefixLength = 64
    row.ReachableTime = 30000
    return row


def reference_forward_rows(raw):
    """Reference reading of a MIB_IPFORWARD_TABLE2. None when the buffer is shorter than it claims."""
    header = LAYOUT["tableHeader"]
    size = LAYOUT["forwardRow"]["size"]
    if len(raw) < header:
        return None
    count = int.from_bytes(raw[0:4], "little")
    if len(raw) < header + count * size:
        return None
    rows = []
    for i in range(count):
        row = MIB_IPFORWARD_ROW2.from_buffer_copy(raw[header + i * size: header + (i + 1) * size])
        if row.DestinationPrefix.Prefix.si_family != AF_INET:
            continue
        length = row.DestinationPrefix.PrefixLength
        if length > 32:
            continue
        network = ipaddress.IPv4Network(
            (bytes(row.DestinationPrefix.Prefix.Ipv4.sin_addr), length), strict=False)
        # The next hop is its own SOCKADDR_INET. 0.0.0.0 is how Windows writes on-link.
        next_hop = ""
        if row.NextHop.si_family == AF_INET:
            next_hop = str(ipaddress.IPv4Address(bytes(row.NextHop.Ipv4.sin_addr)))
        rows.append({"interfaceIndex": row.InterfaceIndex, "prefix": str(network),
                     "nextHop": next_hop, "metric": row.Metric})
    return rows


def reference_interface_rows(raw):
    header = LAYOUT["tableHeader"]
    size = LAYOUT["interfaceRow"]["size"]
    if len(raw) < header:
        return None
    count = int.from_bytes(raw[0:4], "little")
    if len(raw) < header + count * size:
        return None
    rows = []
    for i in range(count):
        row = MIB_IPINTERFACE_ROW.from_buffer_copy(raw[header + i * size: header + (i + 1) * size])
        if row.Family != AF_INET:
            continue
        rows.append({"interfaceIndex": row.InterfaceIndex, "metric": row.Metric,
                     "connected": row.Connected != 0,
                     "disableDefaultRoutes": row.DisableDefaultRoutes != 0})
    return rows


def reference_windows_routes(forward, interfaces):
    by_index = {row["interfaceIndex"]: row for row in interfaces}
    routes = []
    for row in forward:
        interface = by_index.get(row["interfaceIndex"])
        if interface is None:
            usable = False
            metric = row["metric"]
        else:
            usable = interface["connected"] and not (
                row["prefix"] == "0.0.0.0/0" and interface["disableDefaultRoutes"])
            metric = row["metric"] + interface["metric"]
        gateway = "" if row["nextHop"] in ("", "0.0.0.0") else row["nextHop"]
        routes.append({"prefix": row["prefix"], "interface": str(row["interfaceIndex"]),
                       "gateway": gateway, "metric": metric, "usable": usable})
    return routes


TYPICAL_FORWARD = [
    forward_row(3, "0.0.0.0/0", 0, next_hop="192.168.1.1"),
    forward_row(1, "127.0.0.0/8", 256),
    forward_row(1, "127.0.0.1/32", 256),
    forward_row(3, "192.168.1.0/24", 256),
    forward_row(42, "203.0.113.0/24", 5),
    forward_row(42, "100.96.0.0/11", 5),
    forward_row(15, "0.0.0.0/0", 0, next_hop="192.168.2.1"),
    forward_row(9, "0.0.0.0/0", 0, next_hop="10.9.0.1"),
    forward_row(9, "172.16.0.0/12", 0, next_hop="10.9.0.1"),
    forward_row(7, "10.0.0.0/8", 1, raw_address="10.1.2.3"),
    forward_row(3, "fe80::/64", 256, family=AF_INET6),
    forward_row(3, "198.51.100.0/24", 256, length=33),
    forward_row(99, "192.0.2.0/24", 1),
]
TYPICAL_INTERFACES = [
    interface_row(1, 75, True),
    interface_row(3, 20, True),
    interface_row(42, 5, True),
    interface_row(15, 25, False),
    interface_row(9, 1, True, disable_default_routes=True),
    interface_row(7, 50, True),
    interface_row(3, 20, True, family=AF_INET6),
]

forward_tables = [
    {
        "name": "typical",
        "note": "A physical default route, loopback, this node's tunnel carrying a rule prefix and "
                "the mesh network, a disconnected Wi-Fi with a stale default, a VPN interface that "
                "disables default routes, another VPN's 10/8, and three rows that must not be read: "
                "an IPv6 row, a prefix length of 33, and a row whose address has host bits set, "
                "which is read masked.",
        "raw": table_bytes(TYPICAL_FORWARD, LAYOUT["forwardRow"]["size"]),
    },
    {
        "name": "empty",
        "raw": table_bytes([], LAYOUT["forwardRow"]["size"]),
    },
    {
        "name": "truncated",
        "note": "The count says two rows and the buffer holds one. Reading the second would read "
                "past the allocation, so the whole table is refused.",
        "raw": table_bytes(TYPICAL_FORWARD[:1], LAYOUT["forwardRow"]["size"], declared=2),
    },
    {
        "name": "short-header",
        "raw": (1).to_bytes(4, "little"),
    },
]
interface_tables = [
    {
        "name": "typical",
        "note": "The interfaces of the typical forward table, plus an IPv6 row for an index that "
                "also has an IPv4 row; only the IPv4 one is read.",
        "raw": table_bytes(TYPICAL_INTERFACES, LAYOUT["interfaceRow"]["size"]),
    },
    {
        "name": "truncated",
        "raw": table_bytes(TYPICAL_INTERFACES[:1], LAYOUT["interfaceRow"]["size"], declared=3),
    },
]

for table in forward_tables:
    rows = reference_forward_rows(table["raw"])
    table["hex"] = table.pop("raw").hex()
    table["expect"] = {"parsed": rows is not None, "rows": rows or []}
for table in interface_tables:
    rows = reference_interface_rows(table["raw"])
    table["hex"] = table.pop("raw").hex()
    table["expect"] = {"parsed": rows is not None, "rows": rows or []}

typical_forward = reference_forward_rows(bytes.fromhex(forward_tables[0]["hex"]))
typical_interfaces = reference_interface_rows(bytes.fromhex(interface_tables[0]["hex"]))
typical_routes = reference_windows_routes(typical_forward, typical_interfaces)

windows_cases = [
    {
        "name": "rule-prefix-goes-out-the-physical-default",
        "note": "Interface 9's default route has the best metric of the three but its interface "
                "disables default routes, and interface 15's is on a disconnected adapter, so the "
                "answer is 3.",
        "tunnel": "42",
        "destination": "203.0.113.9",
    },
    {
        "name": "disable-default-routes-leaves-other-routes-usable",
        "note": "The flag rules out interface 9's default route only; its 172.16.0.0/12 still "
                "carries traffic.",
        "tunnel": "42",
        "destination": "172.16.5.5",
    },
    {
        "name": "mesh-network-route-is-left-out",
        "note": "The forced-deny list refuses a mesh address before any dial; were one to get this "
                "far, it still would not be sent into the tunnel.",
        "tunnel": "42",
        "destination": "100.96.0.5",
    },
    {
        "name": "masked-row-matches-its-network",
        "note": "The row for interface 7 carries 10.1.2.3 with a length of 8. Read masked it is "
                "10.0.0.0/8 and covers 10.200.0.1.",
        "tunnel": "42",
        "destination": "10.200.0.1",
    },
    {
        "name": "route-on-an-interface-with-no-interface-row-is-not-used",
        "tunnel": "42",
        "destination": "192.0.2.10",
    },
    {
        "name": "prefix-length-over-32-is-not-read",
        "tunnel": "42",
        "destination": "198.51.100.9",
    },
    {
        "name": "loopback",
        "tunnel": "42",
        "destination": "127.0.0.1",
    },
]
for case in windows_cases:
    case["expect"] = {"interface": select_interface(typical_routes, case["tunnel"],
                                                    case["destination"])}

assert [case["expect"]["interface"] for case in windows_cases] == ["3", "9", "3", "7", "3", "3", "1"]

# ---- macOS netstat tables ---------------------------------------------------------------------

macos_vector = json.loads((VECTORS / "peer-egress-macos-routes-v1.json").read_text(encoding="utf-8"))


def reference_macos_routes(capture):
    """Candidate routes from one sampled netstat capture.

    Prefixes are the macOS route vector's own expectations, in table order; the flags and the
    interface are the third and fourth columns of the same rows.
    """
    lines = []
    inside = False
    for line in capture["stdout"].splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith(":"):
            inside = stripped == "Internet:"
            continue
        if inside and not stripped.startswith("Destination"):
            lines.append(stripped.split())
    prefixes = capture["expect"]["prefixes"]
    assert len(lines) == len(prefixes) == capture["expect"]["rows"]
    return [{"prefix": prefix, "interface": fields[3], "gateway": macos_gateway(fields[1], fields[2]),
             "metric": 0, "usable": "I" not in fields[2]}
            for prefix, fields in zip(prefixes, lines)]


def macos_gateway(column, flags):
    """The Gateway column as a next hop: an IPv4 address on a route flagged G, or empty for on-link.

    Only G (RTF_GATEWAY) makes the column a gateway. Without it the column says where the interface
    is: link#N for a network on the interface, a MAC address for a cloned host entry, an interface
    name for a route installed with -interface, and an address for a loopback or point-to-point
    route -- 127 prints 127.0.0.1 there, and a utun host route prints its peer.
    """
    if "G" not in flags:
        return ""
    try:
        ipaddress.IPv4Address(column)
    except ValueError:
        return ""
    return column


macos_tables = {name: macos_vector[name]["stdout"] for name in ("table", "duplicates", "tunRoute")}
macos_routes = {name: reference_macos_routes(macos_vector[name])
                for name in ("table", "duplicates", "tunRoute")}

macos_cases = [
    {"name": "rule-prefix-in-utun-goes-out-en0", "table": "tunRoute", "tunnel": "utun3",
     "destination": "203.0.113.9"},
    {"name": "without-a-tunnel-utun3-would-win", "table": "tunRoute", "tunnel": "",
     "destination": "203.0.113.9"},
    {"name": "tunnel-host-route-is-left-out", "table": "tunRoute", "tunnel": "utun3",
     "destination": "10.255.0.2"},
    {"name": "scoped-duplicates-are-not-candidates", "table": "duplicates", "tunnel": "utun3",
     "destination": "203.0.113.9",
     "note": "Three routes for 203.0.113.0/24: an unscoped one via en0 and two scoped with I, one "
             "of them to lo0. Only the unscoped one is a candidate."},
    {"name": "nothing-left-when-the-physical-interface-is-named-as-the-tunnel",
     "table": "duplicates", "tunnel": "en0", "destination": "203.0.113.9",
     "note": "Every unscoped route to the destination is on en0, the scoped lo0 route does not "
             "count, and 127/8 does not cover it."},
    {"name": "unscoped-route-to-lo0-is-respected", "table": "table", "tunnel": "utun3",
     "destination": "198.51.100.200"},
    {"name": "same-destination-with-lo0-left-out", "table": "table", "tunnel": "lo0",
     "destination": "198.51.100.200"},
    {"name": "cloned-host-route-is-scoped-but-its-network-is-not", "table": "table",
     "tunnel": "utun3", "destination": "192.168.64.1",
     "note": "The link-level entry for the gateway carries I; the /32 link#7 entry and the /24 "
             "behind it are on the same interface anyway."},
    {"name": "loopback", "table": "table", "tunnel": "utun3", "destination": "127.0.0.1"},
]
for case in macos_cases:
    case["expect"] = {"interface": select_interface(macos_routes[case["table"]], case["tunnel"],
                                                    case["destination"])}

assert macos_cases[0]["expect"]["interface"] == "en0"
assert macos_cases[1]["expect"]["interface"] == "utun3"
assert macos_cases[4]["expect"]["interface"] is None
assert macos_cases[5]["expect"]["interface"] == "lo0"
assert macos_cases[6]["expect"]["interface"] == "en0"

# ---- Linux main table -------------------------------------------------------------------------
#
# Linux sockets are marked rather than bound, so the table is read only for a bypass hop, and only
# when `ip route get` answers with the tunnel. That query is kept as the first choice because it
# follows policy routing -- another VPN's rules and tables -- which a reading of the main table
# cannot; the table is what is left when the query can no longer see past this feature's own route.
#
# Captured under WSL 2 with iproute2 6.1.0, inside network namespaces made with `unshare -rn`, so the
# TUN device, the dummy interfaces and every route in them are real. The setup that built each table
# is kept with its capture.
#
# This block is machine-written from the capture records. Nothing here was retyped.
# BEGIN LINUX SAMPLED
LINUX_SAMPLED = {
    'provenance-uname': {
        "argv": ['uname', '-a'],
        "exit": 0,
        "stdout": 'Linux ShuaiWin 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux\n',
        "stderr": '',
    },
    'provenance-iproute2': {
        "argv": ['ip', '-V'],
        "exit": 0,
        "stdout": 'ip utility, iproute2-6.1.0, libbpf 1.3.0\n',
        "stderr": '',
    },
    'show-host': {
        "argv": ['ip', '-4', 'route', 'show', 'table', 'main'],
        "exit": 0,
        "stdout": 'default via 172.18.240.1 dev eth0 proto kernel \n172.18.240.0/20 dev eth0 proto kernel scope link src 172.18.245.210 \n',
        "stderr": '',
    },
    'show-rich': {
        "setup": [
            'set -e',
            'ip link set lo up',
            'ip link add eth0 type dummy; ip link set eth0 up; ip addr add 192.168.64.7/24 dev eth0',
            'ip link add eth1 type dummy; ip link set eth1 up; ip addr add 10.9.0.2/24 dev eth1',
            'ip tuntap add dev specus0 mode tun',
            'ip link set specus0 up; ip addr add 100.96.0.5/11 dev specus0',
            'ip route add default via 192.168.64.1 dev eth0 metric 100',
            'ip route add default via 10.9.0.1 dev eth1 metric 600',
            'ip route add 203.0.113.0/24 dev specus0',
            'ip route add 198.51.100.7 via 192.168.64.1 dev eth0',
            'ip route add blackhole 192.0.2.0/24',
            'ip route add unreachable 192.0.2.128/25',
            'ip route add prohibit 192.0.2.64/26',
            'ip route add 172.16.0.0/12 nexthop via 192.168.64.1 dev eth0 nexthop via 10.9.0.1 dev eth1',
            'ip route add 198.18.0.0/15 via 10.9.0.1 dev eth1 proto static metric 50',
            'ip route add 198.18.0.0/15 via 192.168.64.1 dev eth0 proto static metric 20',
            'ip route add 10.20.0.0/16 dev eth1 scope link',
        ],
        "argv": ['ip', '-4', 'route', 'show', 'table', 'main'],
        "exit": 0,
        "stdout": 'default via 192.168.64.1 dev eth0 metric 100 \ndefault via 10.9.0.1 dev eth1 metric 600 \n10.9.0.0/24 dev eth1 proto kernel scope link src 10.9.0.2 \n10.20.0.0/16 dev eth1 scope link \n100.96.0.0/11 dev specus0 proto kernel scope link src 100.96.0.5 linkdown \n172.16.0.0/12 \n\tnexthop via 192.168.64.1 dev eth0 weight 1 \n\tnexthop via 10.9.0.1 dev eth1 weight 1 \nblackhole 192.0.2.0/24 \nprohibit 192.0.2.64/26 \nunreachable 192.0.2.128/25 \n192.168.64.0/24 dev eth0 proto kernel scope link src 192.168.64.7 \n198.18.0.0/15 via 192.168.64.1 dev eth0 proto static metric 20 \n198.18.0.0/15 via 10.9.0.1 dev eth1 proto static metric 50 \n198.51.100.7 via 192.168.64.1 dev eth0 \n203.0.113.0/24 dev specus0 scope link linkdown \n',
        "stderr": '',
    },
    'get-covered-rich': {
        "setup": [
            'set -e',
            'ip link set lo up',
            'ip link add eth0 type dummy; ip link set eth0 up; ip addr add 192.168.64.7/24 dev eth0',
            'ip link add eth1 type dummy; ip link set eth1 up; ip addr add 10.9.0.2/24 dev eth1',
            'ip tuntap add dev specus0 mode tun',
            'ip link set specus0 up; ip addr add 100.96.0.5/11 dev specus0',
            'ip route add default via 192.168.64.1 dev eth0 metric 100',
            'ip route add default via 10.9.0.1 dev eth1 metric 600',
            'ip route add 203.0.113.0/24 dev specus0',
            'ip route add 198.51.100.7 via 192.168.64.1 dev eth0',
            'ip route add blackhole 192.0.2.0/24',
            'ip route add unreachable 192.0.2.128/25',
            'ip route add prohibit 192.0.2.64/26',
            'ip route add 172.16.0.0/12 nexthop via 192.168.64.1 dev eth0 nexthop via 10.9.0.1 dev eth1',
            'ip route add 198.18.0.0/15 via 10.9.0.1 dev eth1 proto static metric 50',
            'ip route add 198.18.0.0/15 via 192.168.64.1 dev eth0 proto static metric 20',
            'ip route add 10.20.0.0/16 dev eth1 scope link',
        ],
        "argv": ['ip', 'route', 'get', '203.0.113.9'],
        "exit": 0,
        "stdout": '203.0.113.9 dev specus0 src 100.96.0.5 uid 0 \n    cache \n',
        "stderr": '',
    },
    'get-host-rich': {
        "setup": [
            'set -e',
            'ip link set lo up',
            'ip link add eth0 type dummy; ip link set eth0 up; ip addr add 192.168.64.7/24 dev eth0',
            'ip link add eth1 type dummy; ip link set eth1 up; ip addr add 10.9.0.2/24 dev eth1',
            'ip tuntap add dev specus0 mode tun',
            'ip link set specus0 up; ip addr add 100.96.0.5/11 dev specus0',
            'ip route add default via 192.168.64.1 dev eth0 metric 100',
            'ip route add default via 10.9.0.1 dev eth1 metric 600',
            'ip route add 203.0.113.0/24 dev specus0',
            'ip route add 198.51.100.7 via 192.168.64.1 dev eth0',
            'ip route add blackhole 192.0.2.0/24',
            'ip route add unreachable 192.0.2.128/25',
            'ip route add prohibit 192.0.2.64/26',
            'ip route add 172.16.0.0/12 nexthop via 192.168.64.1 dev eth0 nexthop via 10.9.0.1 dev eth1',
            'ip route add 198.18.0.0/15 via 10.9.0.1 dev eth1 proto static metric 50',
            'ip route add 198.18.0.0/15 via 192.168.64.1 dev eth0 proto static metric 20',
            'ip route add 10.20.0.0/16 dev eth1 scope link',
        ],
        "argv": ['ip', 'route', 'get', '198.51.100.7'],
        "exit": 0,
        "stdout": '198.51.100.7 via 192.168.64.1 dev eth0 src 192.168.64.7 uid 0 \n    cache \n',
        "stderr": '',
    },
    'get-blackhole-rich': {
        "setup": [
            'set -e',
            'ip link set lo up',
            'ip link add eth0 type dummy; ip link set eth0 up; ip addr add 192.168.64.7/24 dev eth0',
            'ip link add eth1 type dummy; ip link set eth1 up; ip addr add 10.9.0.2/24 dev eth1',
            'ip tuntap add dev specus0 mode tun',
            'ip link set specus0 up; ip addr add 100.96.0.5/11 dev specus0',
            'ip route add default via 192.168.64.1 dev eth0 metric 100',
            'ip route add default via 10.9.0.1 dev eth1 metric 600',
            'ip route add 203.0.113.0/24 dev specus0',
            'ip route add 198.51.100.7 via 192.168.64.1 dev eth0',
            'ip route add blackhole 192.0.2.0/24',
            'ip route add unreachable 192.0.2.128/25',
            'ip route add prohibit 192.0.2.64/26',
            'ip route add 172.16.0.0/12 nexthop via 192.168.64.1 dev eth0 nexthop via 10.9.0.1 dev eth1',
            'ip route add 198.18.0.0/15 via 10.9.0.1 dev eth1 proto static metric 50',
            'ip route add 198.18.0.0/15 via 192.168.64.1 dev eth0 proto static metric 20',
            'ip route add 10.20.0.0/16 dev eth1 scope link',
        ],
        "argv": ['ip', 'route', 'get', '192.0.2.9'],
        "exit": 2,
        "stdout": '',
        "stderr": 'RTNETLINK answers: Invalid argument\n',
    },
    'show-tun-halves': {
        "setup": [
            'set -e',
            'ip link set lo up',
            'ip link add eth0 type dummy; ip link set eth0 up; ip addr add 192.168.64.7/24 dev eth0',
            'ip tuntap add dev specus0 mode tun',
            'ip link set specus0 up; ip addr add 100.96.0.5/11 dev specus0',
            'ip route add default via 192.168.64.1 dev eth0 proto dhcp src 192.168.64.7 metric 100',
            'ip route add 0.0.0.0/1 dev specus0',
            'ip route add 128.0.0.0/1 dev specus0',
        ],
        "argv": ['ip', '-4', 'route', 'show', 'table', 'main'],
        "exit": 0,
        "stdout": '0.0.0.0/1 dev specus0 scope link linkdown \ndefault via 192.168.64.1 dev eth0 proto dhcp src 192.168.64.7 metric 100 \n100.96.0.0/11 dev specus0 proto kernel scope link src 100.96.0.5 \n128.0.0.0/1 dev specus0 scope link linkdown \n192.168.64.0/24 dev eth0 proto kernel scope link src 192.168.64.7 \n',
        "stderr": '',
    },
    'get-covered-tun-halves': {
        "setup": [
            'set -e',
            'ip link set lo up',
            'ip link add eth0 type dummy; ip link set eth0 up; ip addr add 192.168.64.7/24 dev eth0',
            'ip tuntap add dev specus0 mode tun',
            'ip link set specus0 up; ip addr add 100.96.0.5/11 dev specus0',
            'ip route add default via 192.168.64.1 dev eth0 proto dhcp src 192.168.64.7 metric 100',
            'ip route add 0.0.0.0/1 dev specus0',
            'ip route add 128.0.0.0/1 dev specus0',
        ],
        "argv": ['ip', 'route', 'get', '203.0.113.9'],
        "exit": 0,
        "stdout": '203.0.113.9 dev specus0 src 100.96.0.5 uid 0 \n    cache \n',
        "stderr": '',
    },
}
# END LINUX SAMPLED

LINUX_NOWHERE = {"blackhole", "unreachable", "prohibit", "throw"}
LINUX_NOT_FORWARDING = {"local", "broadcast", "anycast", "multicast", "nat"}


def linux_prefix(text):
    if text == "default":
        return "0.0.0.0/0"
    try:
        return str(ipaddress.IPv4Network(text if "/" in text else text + "/32", strict=False))
    except ValueError:
        return ""


def reference_linux_routes(stdout):
    """Candidate routes from `ip -4 route show table main`.

    A line may start with a route type. blackhole, unreachable, prohibit and throw lead nowhere: they
    stay candidates, with no interface, so the address they cover is not reached another way. local,
    broadcast, anycast, multicast and nat are not forwarding paths and are not read. A multipath route
    prints its destination alone and its next hops on the indented lines after it; the first next hop
    is the one taken. A route marked dead is not usable; linkdown is, as the kernel uses it too.
    """
    routes = []
    pending = None
    deviceless = []
    for line in stdout.split("\n"):
        if not line.strip():
            continue
        fields = line.split()
        if line[0] in " \t":
            if fields[0] == "nexthop" and pending is not None and pending["interface"] == "":
                for key, value in zip(fields, fields[1:]):
                    if key == "via" and linux_address(value):
                        pending["gateway"] = value
                    elif key == "dev":
                        pending["interface"] = value
            continue
        pending = None
        kind = "unicast"
        if fields[0] in LINUX_NOWHERE or fields[0] in LINUX_NOT_FORWARDING:
            kind = fields.pop(0)
        if kind in LINUX_NOT_FORWARDING or not fields:
            continue
        prefix = linux_prefix(fields[0])
        if not prefix:
            continue
        entry = {"prefix": prefix, "interface": "", "gateway": "", "metric": 0, "usable": True}
        for key, value in zip(fields[1:], fields[2:]):
            if key == "via" and linux_address(value):
                entry["gateway"] = value
            elif key == "dev":
                entry["interface"] = value
            elif key == "metric" and value.isdigit():
                entry["metric"] = int(value)
        if "dead" in fields[1:]:
            entry["usable"] = False
        if kind in LINUX_NOWHERE:
            entry["interface"] = ""
            entry["gateway"] = ""
        elif entry["interface"] == "":
            # A destination with no device of its own: the next hops follow on indented lines.
            pending = entry
            deviceless.append(entry)
        routes.append(entry)
    for entry in deviceless:
        if entry["interface"] == "":
            # No next hop could be read. Leading nowhere is a claim only the nowhere types make, so
            # this one is dropped from the choice instead of blocking the addresses it covers.
            entry["usable"] = False
    return routes


def linux_address(text):
    try:
        ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return True


linux_tables = {name: LINUX_SAMPLED[name]["stdout"]
                for name in ("show-host", "show-rich", "show-tun-halves")}
linux_routes = {name: reference_linux_routes(text) for name, text in linux_tables.items()}

# ---- bypass hops ------------------------------------------------------------------------------

hop_cases = [
    # Linux, from the sampled tables.
    {"name": "linux-covered-address-goes-out-the-physical-default", "platform": "linux",
     "table": "show-rich", "tunnel": "specus0", "destination": "203.0.113.9",
     "note": "What `ip route get 203.0.113.9` could not answer: in the same namespace it said "
             "dev specus0. Of the two default routes the lower metric wins."},
    {"name": "linux-without-the-tunnel-left-out-the-tunnel-would-win", "platform": "linux",
     "table": "show-rich", "tunnel": "", "destination": "203.0.113.9"},
    {"name": "linux-host-route", "platform": "linux", "table": "show-rich", "tunnel": "specus0",
     "destination": "198.51.100.7"},
    {"name": "linux-on-link-network", "platform": "linux", "table": "show-rich", "tunnel": "specus0",
     "destination": "10.20.3.4"},
    {"name": "linux-lower-metric-wins-between-equal-prefixes", "platform": "linux",
     "table": "show-rich", "tunnel": "specus0", "destination": "198.18.1.1",
     "note": "Printed metric 20 first, but the metric decides, not the order."},
    {"name": "linux-multipath-takes-its-first-next-hop", "platform": "linux", "table": "show-rich",
     "tunnel": "specus0", "destination": "172.16.5.5"},
    {"name": "linux-blackhole-leads-nowhere", "platform": "linux", "table": "show-rich",
     "tunnel": "specus0", "destination": "192.0.2.9",
     "note": "The default routes cover it too. The table deliberately does not reach it, so no "
             "bypass is pinned through them."},
    {"name": "linux-prohibit-leads-nowhere", "platform": "linux", "table": "show-rich",
     "tunnel": "specus0", "destination": "192.0.2.70"},
    {"name": "linux-unreachable-leads-nowhere", "platform": "linux", "table": "show-rich",
     "tunnel": "specus0", "destination": "192.0.2.200"},
    {"name": "linux-mesh-network-is-left-out", "platform": "linux", "table": "show-rich",
     "tunnel": "specus0", "destination": "100.96.0.9"},
    {"name": "linux-halves-over-the-default", "platform": "linux", "table": "show-tun-halves",
     "tunnel": "specus0", "destination": "203.0.113.9",
     "note": "Two /1 routes into the tunnel cover everything; the /0 behind them is still there."},
    {"name": "linux-real-host-table", "platform": "linux", "table": "show-host", "tunnel": "specus0",
     "destination": "1.1.1.1"},
    # macOS, from the sampled netstat captures.
    {"name": "macos-covered-address-goes-out-en0", "platform": "macos", "table": "tunRoute",
     "tunnel": "utun3", "destination": "203.0.113.9"},
    {"name": "macos-on-link-network-has-no-gateway", "platform": "macos", "table": "tunRoute",
     "tunnel": "utun3", "destination": "192.168.64.20",
     "note": "The Gateway column says link#7, which is not a hop."},
    {"name": "macos-interface-route-has-no-gateway", "platform": "macos", "table": "table",
     "tunnel": "utun3", "destination": "198.51.100.200",
     "note": "The Gateway column names lo0, which is not a hop either."},
    {"name": "macos-scoped-duplicates-leave-the-unscoped-gateway", "platform": "macos",
     "table": "duplicates", "tunnel": "lo0", "destination": "203.0.113.9"},
    # Windows, from the typical table.
    {"name": "windows-covered-address-goes-out-the-default-gateway", "platform": "windows",
     "table": "typical", "tunnel": "42", "destination": "203.0.113.9"},
    {"name": "windows-on-link-network-has-no-gateway", "platform": "windows", "table": "typical",
     "tunnel": "42", "destination": "192.168.1.50",
     "note": "Windows writes on-link as a next hop of 0.0.0.0."},
    {"name": "windows-vpn-route-keeps-its-gateway", "platform": "windows", "table": "typical",
     "tunnel": "42", "destination": "172.16.5.5"},
    # Inline tables, for what the samples cannot show.
    {"name": "owned-bypass-is-left-out", "platform": "inline", "tunnel": "42",
     "destination": "198.51.100.7", "owned": ["198.51.100.7/32"],
     "routes": [route("0.0.0.0/0", "3", 20, gateway="192.168.1.1"),
                route("198.51.100.7/32", "3", 20, gateway="192.168.2.1")],
     "note": "A bypass this feature installed earlier still names the gateway it was resolved to. "
             "Resolving again has to look past it, or a network change would keep the old hop."},
    {"name": "owned-bypass-would-otherwise-win", "platform": "inline", "tunnel": "42",
     "destination": "198.51.100.7", "owned": [],
     "routes": [route("0.0.0.0/0", "3", 20, gateway="192.168.1.1"),
                route("198.51.100.7/32", "3", 20, gateway="192.168.2.1")]},
    {"name": "only-the-tunnel-leads-there", "platform": "inline", "tunnel": "42",
     "destination": "203.0.113.9", "owned": [],
     "routes": [route("203.0.113.0/24", "42", 5)]},
]

hop_tables = {
    "linux": linux_routes,
    "macos": macos_routes,
    "windows": {"typical": typical_routes},
}
for case in hop_cases:
    routes = case["routes"] if case["platform"] == "inline" else hop_tables[case["platform"]][case["table"]]
    case.setdefault("owned", [])
    case["expect"] = {"hop": select_hop(routes, case["tunnel"], case["destination"], case["owned"])}

expected_hops = {case["name"]: case["expect"]["hop"] for case in hop_cases}
assert expected_hops["linux-covered-address-goes-out-the-physical-default"] == \
    {"interface": "eth0", "gateway": "192.168.64.1"}
assert expected_hops["linux-without-the-tunnel-left-out-the-tunnel-would-win"] == \
    {"interface": "specus0", "gateway": ""}
assert expected_hops["linux-lower-metric-wins-between-equal-prefixes"] == \
    {"interface": "eth0", "gateway": "192.168.64.1"}
assert expected_hops["linux-multipath-takes-its-first-next-hop"] == \
    {"interface": "eth0", "gateway": "192.168.64.1"}
assert expected_hops["linux-on-link-network"] == {"interface": "eth1", "gateway": ""}
for nowhere in ("linux-blackhole-leads-nowhere", "linux-prohibit-leads-nowhere",
                "linux-unreachable-leads-nowhere", "only-the-tunnel-leads-there"):
    assert expected_hops[nowhere] is None, nowhere
assert expected_hops["macos-covered-address-goes-out-en0"] == {"interface": "en0", "gateway": "192.168.64.1"}
assert expected_hops["macos-on-link-network-has-no-gateway"] == {"interface": "en0", "gateway": ""}
assert expected_hops["windows-covered-address-goes-out-the-default-gateway"] == \
    {"interface": "3", "gateway": "192.168.1.1"}
assert expected_hops["windows-on-link-network-has-no-gateway"] == {"interface": "3", "gateway": ""}
assert expected_hops["owned-bypass-is-left-out"] == {"interface": "3", "gateway": "192.168.1.1"}
assert expected_hops["owned-bypass-would-otherwise-win"] == {"interface": "3", "gateway": "192.168.2.1"}

# ---- drift ---------------------------------------------------------------------------------------
#
# What the consumer's own routes look like in the table after the machine changed networks or came
# back from sleep, and what to do about each. The consumer reads the table on its tick and compares
# it with what the journal says it owns.


def drift(owned, routes, tunnel):
    """The owned routes the table no longer carries as installed, with the repair each one needs."""
    owned_prefixes = [entry["cidr"] for entry in owned]
    found = []
    for entry in owned:
        rows = [r for r in routes if r["prefix"] == entry["cidr"]]
        if entry["kind"] == "tun":
            if any(r["interface"] == tunnel for r in rows):
                continue
            # A route into the tunnel cannot change interface on its own, so a row on another one
            # is somebody else's: the prefix is theirs now, and it is reported rather than taken.
            found.append({"cidr": entry["cidr"], "reason": "moved" if rows else "missing",
                          "action": "conflict" if rows else "reinstall"})
            continue
        # A bypass is compared with where the table would send the address now, with this
        # feature's own routes left out: a network change leaves the old /32 in place naming a
        # gateway that is no longer the way out.
        address = entry["cidr"].removesuffix("/32")
        hop = select_hop(routes, tunnel, address, owned_prefixes)
        present = [r for r in rows if r["interface"] != tunnel]
        if not present:
            found.append({"cidr": entry["cidr"], "reason": "missing", "action": "reinstall"})
        elif hop is not None and (present[0]["interface"], present[0]["gateway"]) != (hop["interface"], hop["gateway"]):
            found.append({"cidr": entry["cidr"], "reason": "moved", "action": "reinstall"})
        # Present and nothing better outside the tunnel: the route that is there is the best there is.
    return found


def owned_tun(cidr):
    return {"cidr": cidr, "kind": "tun"}


def owned_bypass(cidr):
    return {"cidr": cidr, "kind": "bypass"}


drift_cases = [
    {"name": "linux-everything-is-where-it-was-put", "platform": "linux", "table": "show-rich",
     "tunnel": "specus0",
     "owned": [owned_bypass("198.51.100.7/32"), owned_tun("203.0.113.0/24")],
     "note": "The sampled table carries both: the /32 via the default's gateway, the /24 into the tunnel."},
    {"name": "linux-tunnel-route-gone", "platform": "linux", "table": "show-host", "tunnel": "specus0",
     "owned": [owned_tun("203.0.113.0/24")],
     "note": "A host table with no tunnel in it: the route this feature installed is not there."},
    {"name": "bypass-gone-with-its-interface", "platform": "inline", "tunnel": "specus0",
     "owned": [owned_bypass("203.0.113.7/32"), owned_tun("203.0.113.0/24")],
     "routes": [route("0.0.0.0/0", "wlan0", 600, gateway="10.0.0.1"),
                route("203.0.113.0/24", "specus0")],
     "note": "eth0 went down and the kernel dropped every route through it, the /32 included. The "
             "tunnel route survived; the bypass has to come back through wlan0."},
    {"name": "bypass-still-names-the-old-gateway", "platform": "inline", "tunnel": "specus0",
     "owned": [owned_bypass("203.0.113.7/32"), owned_tun("203.0.113.0/24")],
     "routes": [route("0.0.0.0/0", "wlan0", 600, gateway="10.0.0.1"),
                route("203.0.113.7/32", "eth0", gateway="192.168.64.1"),
                route("203.0.113.0/24", "specus0")],
     "note": "Back from sleep on a different network. The /32 is still there, via a gateway that is "
             "no longer the way out; left alone it would pin the control connection to a dead hop. "
             "Compared with the /32 itself left out, or it would choose itself and look right."},
    {"name": "bypass-moved-with-the-default-on-windows", "platform": "inline", "tunnel": "42",
     "owned": [owned_bypass("203.0.113.7/32"), owned_tun("203.0.113.0/24")],
     "routes": [route("0.0.0.0/0", "3", 20, usable=False, gateway="192.168.1.1"),
                route("0.0.0.0/0", "5", 25, gateway="10.0.0.1"),
                route("203.0.113.7/32", "3", 20, gateway="192.168.1.1"),
                route("203.0.113.0/24", "42", 5)],
     "note": "Windows keeps the routes of a disconnected interface, so the old default is still "
             "listed and unusable; the /32 next to it is what has to move."},
    {"name": "tunnel-prefix-taken-by-somebody-else", "platform": "inline", "tunnel": "specus0",
     "owned": [owned_tun("203.0.113.0/24")],
     "routes": [route("0.0.0.0/0", "eth0", 100, gateway="192.168.64.1"),
                route("203.0.113.0/24", "eth0", gateway="192.0.2.1")],
     "note": "Not taken back. A route into the tunnel does not change interface by itself, so this "
             "is another tool's route, and this feature does not preempt."},
    {"name": "bypass-present-and-nothing-better-outside-the-tunnel", "platform": "inline",
     "tunnel": "specus0",
     "owned": [owned_bypass("203.0.113.7/32"), owned_tun("203.0.113.0/24")],
     "routes": [route("203.0.113.7/32", "eth0", gateway="192.168.64.1"),
                route("203.0.113.0/24", "specus0")],
     "note": "No default route at all. The /32 that is there cannot be improved on, so it is left."},
    {"name": "macos-everything-is-where-it-was-put", "platform": "macos", "table": "tunRoute",
     "tunnel": "utun3", "owned": [owned_tun("203.0.113.0/24")]},
    {"name": "windows-everything-is-where-it-was-put", "platform": "windows", "table": "typical",
     "tunnel": "42", "owned": [owned_tun("203.0.113.0/24")]},
    {"name": "nothing-owned-nothing-to-repair", "platform": "linux", "table": "show-host",
     "tunnel": "specus0", "owned": []},
]

for case in drift_cases:
    routes = case["routes"] if case["platform"] == "inline" else hop_tables[case["platform"]][case["table"]]
    case["expect"] = drift(case["owned"], routes, case["tunnel"])

expected_drift = {case["name"]: case["expect"] for case in drift_cases}
assert expected_drift["linux-everything-is-where-it-was-put"] == []
assert expected_drift["linux-tunnel-route-gone"] == [
    {"cidr": "203.0.113.0/24", "reason": "missing", "action": "reinstall"}]
assert expected_drift["bypass-gone-with-its-interface"] == [
    {"cidr": "203.0.113.7/32", "reason": "missing", "action": "reinstall"}]
assert expected_drift["bypass-still-names-the-old-gateway"] == [
    {"cidr": "203.0.113.7/32", "reason": "moved", "action": "reinstall"}]
assert expected_drift["bypass-moved-with-the-default-on-windows"] == [
    {"cidr": "203.0.113.7/32", "reason": "moved", "action": "reinstall"}]
assert expected_drift["tunnel-prefix-taken-by-somebody-else"] == [
    {"cidr": "203.0.113.0/24", "reason": "moved", "action": "conflict"}]
assert expected_drift["bypass-present-and-nothing-better-outside-the-tunnel"] == []
assert expected_drift["macos-everything-is-where-it-was-put"] == []
assert expected_drift["windows-everything-is-where-it-was-put"] == []

# ---- socket options ---------------------------------------------------------------------------


def option_cases(indexes, order):
    return [{"index": index, "hex": index.to_bytes(4, order).hex()} for index in indexes]


socket_options = {
    "windows": {
        "level": 0,
        "name": 31,
        "constant": "IP_UNICAST_IF",
        "byteOrder": "network",
        "note": "A four-byte value holding the interface index in network byte order. In host "
                "order setsockopt refuses it with WSAEADDRNOTAVAIL (\"The requested address is "
                "not valid in its context\").",
        "cases": option_cases([1, 3, 258, 0x12345678], "big"),
    },
    "macos": {
        "level": 0,
        "name": 25,
        "constant": "IP_BOUND_IF",
        "byteOrder": "host",
        "note": "A four-byte int holding the interface index in host byte order, which is "
                "little-endian on every Mac this ships to.",
        "cases": option_cases([1, 4, 258], "little"),
    },
}

vector = {
    "name": "peer-egress-socket-binding",
    "version": 1,
    "notes": [
        "select: routes are candidates in table order; the answer is the interface of the route "
        "with the longest prefix containing the destination, then the lowest metric, then the "
        "first listed. Routes with usable false, and routes whose interface equals the tunnel, are "
        "not candidates. A null interface means the dial is refused.",
        "An empty tunnel name leaves nothing out. A node without a TUN device has no tunnel routes "
        "to avoid.",
        "windows: metric is the route's metric plus its interface's metric; usable is the "
        "interface having an IPv4 row that is connected, and not a 0.0.0.0/0 route on an interface "
        "with DisableDefaultRoutes. interface is the decimal interface index.",
        "windows tables: a ULONG count, padding to offset 8, then fixed-size rows. Rows whose "
        "family is not AF_INET are skipped, as are forward rows with a prefix length over 32. A "
        "forward prefix is masked by its length. A buffer shorter than the count claims is refused "
        "whole.",
        "macos: candidates are the rows of `netstat -rn -f inet` as the route vector normalises "
        "them; interface is the Netif column, metric is 0, and usable is the Flags column not "
        "containing I.",
        "gateway: the route's next hop as an IPv4 address, or empty for on-link. Windows writes "
        "on-link as 0.0.0.0. On macOS the Gateway column is a gateway only on a route whose Flags "
        "contain G; otherwise it holds link#N, a MAC address, an interface name, or the address of "
        "a loopback or point-to-point peer, none of which is a hop.",
        "linux: candidates are the lines of `ip -4 route show table main`. A leading blackhole, "
        "unreachable, prohibit or throw leads nowhere: the route stays a candidate with an empty "
        "interface. local, broadcast, anycast, multicast and nat lines are not read. A multipath "
        "route takes its first indented nexthop; one whose next hops cannot be read is not usable. "
        "dead is not usable; linkdown is. metric defaults to 0.",
        "hops: the same choice as select, with owned prefixes also left out; a chosen route with an "
        "empty interface means no hop. Used for a bypass route when the platform's own query "
        "answers with the tunnel.",
        "drift: what the consumer's own routes look like in the table after a network change, and "
        "the repair each needs. A tunnel route is present when a row for its prefix names the "
        "tunnel; a row on another interface is somebody else's and is reported, not taken. A "
        "bypass is compared with the hop the table would choose now with the owned prefixes left "
        "out: absent or different means reinstall; present with nothing better means leave it.",
    ],
    "select": {"cases": SELECT_CASES},
    "windows": {
        "layout": LAYOUT,
        "forwardTables": forward_tables,
        "interfaceTables": interface_tables,
        "routes": {"forward": "typical", "interfaces": "typical", "expect": typical_routes},
        "cases": windows_cases,
    },
    "macos": {
        "tables": macos_tables,
        "routes": [{"table": name, "expect": routes} for name, routes in macos_routes.items()],
        "cases": macos_cases,
    },
    "linux": {
        "provenance": {name: LINUX_SAMPLED[name]["stdout"]
                       for name in ("provenance-uname", "provenance-iproute2")},
        "captures": {name: {key: record.get(key) for key in ("setup", "argv", "exit", "stdout", "stderr")}
                     for name, record in LINUX_SAMPLED.items() if not name.startswith("provenance")},
        "tables": linux_tables,
        "routes": [{"table": name, "expect": routes} for name, routes in linux_routes.items()],
    },
    "hops": {"cases": hop_cases},
    "drift": {
        "description": "本功能拥有的路由在切网或休眠恢复后在真实路由表里的状态，以及各自需要的修复。"
                       "tun 路由：表里有指向隧道的行就是好的；行在别的接口上是别人的路由，报冲突、不抢占；"
                       "没有行就重装。旁路：与「去掉隧道和本功能自己的路由之后，表现在会把该地址送去哪」比较；"
                       "没有行就重装，有行但接口或网关不同就重装（先撤再装，重新解析下一跳）；"
                       "有行而隧道之外已无更好的路可走，就保留。",
        "cases": drift_cases,
    },
    "socketOptions": socket_options,
}

out = VECTORS / "peer-egress-socket-binding-v1.json"
out.write_text(json.dumps(vector, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"wrote {out}: select={len(SELECT_CASES)} windows={len(windows_cases)} macos={len(macos_cases)}")
