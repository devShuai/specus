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

The expectations come from the reference implementation in this file, not from any of the three
runtimes. The macOS tables are copied verbatim from the sampled captures in
peer-egress-macos-routes-v1.json, and their normalised prefixes are taken from that file's
expectations rather than recomputed.
"""
import ctypes
import ipaddress
import json
from pathlib import Path

VECTORS = Path("protocol/test-vectors")

AF_INET = 2
AF_INET6 = 23

# ---- reference selection ----------------------------------------------------------------------


def select_interface(routes, tunnel, destination):
    """The interface a socket to destination is bound to, or None when nothing but the tunnel leads there.

    Longest prefix first, then the lowest metric, then the route listed first. Routes that are not
    usable and routes on the tunnel's own interface are not candidates. The tunnel is compared by
    exact equality: utun30 is not utun3.
    """
    address = ipaddress.IPv4Address(destination)
    best = None
    best_key = None
    for route in routes:
        if not route["usable"]:
            continue
        if tunnel and route["interface"] == tunnel:
            continue
        network = ipaddress.IPv4Network(route["prefix"])
        if address not in network:
            continue
        key = (network.prefixlen, -route["metric"])
        # Strictly greater, so a tie keeps the route listed first.
        if best_key is None or key > best_key:
            best, best_key = route, key
    return None if best is None else best["interface"]


def route(prefix, interface, metric=0, usable=True):
    return {"prefix": prefix, "interface": interface, "metric": metric, "usable": usable}


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
        rows.append({"interfaceIndex": row.InterfaceIndex, "prefix": str(network),
                     "metric": row.Metric})
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
        routes.append({"prefix": row["prefix"], "interface": str(row["interfaceIndex"]),
                       "metric": metric, "usable": usable})
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
    return [{"prefix": prefix, "interface": fields[3], "metric": 0, "usable": "I" not in fields[2]}
            for prefix, fields in zip(prefixes, lines)]


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
    "socketOptions": socket_options,
}

out = VECTORS / "peer-egress-socket-binding-v1.json"
out.write_text(json.dumps(vector, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"wrote {out}: select={len(SELECT_CASES)} windows={len(windows_cases)} macos={len(macos_cases)}")
