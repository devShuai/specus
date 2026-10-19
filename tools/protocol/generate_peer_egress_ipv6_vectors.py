"""Generate protocol/test-vectors/peer-egress-ipv6-v1.json.

The consumer's IPv6 data plane (protocol/spec/peer-egress.md, IPv6 数据面; issue #245). The mesh
gives each device only an IPv4 virtual address, so a device's IPv6 address is derived from it: the
IPv4 address in the low 32 bits of the fixed ULA prefix fd53:7065:6375:7300::/96. The egress checks
an IPv6 packet's source against the address derived from the session peer's IPv4, the same check it
makes on IPv4. SPEG1 carries the IPv6 packet as it is (the IP version tells the two apart), only to
an egress that announced ipv6PacketCapable. AAAA queries still get NODATA.

Sections, each built here from the packet layout rather than recorded from any implementation:

- meshAddress: the derivation and its inverse.
- ruleValidation: what the data plane adds to IPv6 rule validation (the derived prefix is mesh, and
  a rule needs an egress that carries IPv6 packets).
- frames: SPEG1 type=1 bodies that are IPv6, for a parser with the data plane.
- consumerOutbound: what the consumer does with an IPv6 packet read from its TUN.
- returnPath: the consumer's checks on an IPv6 packet coming back.
- failure: the TCP reset and the ICMPv6 destination unreachable the consumer writes back.
"""
import ipaddress
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from peer_egress_ipv6 import format_address, parse_address  # noqa: E402

VECTORS = Path("protocol/test-vectors")

MESH_PREFIX = parse_address("fd53:7065:6375:7300::")
MESH_PREFIX_LENGTH = 96
MESH_CIDR_V4 = "100.64.0.0/10"

CONSUMER_V4 = "100.96.0.1"
OTHER_PEER_V4 = "100.96.0.2"
REMOTE = "2001:db8:1::c8"
REMOTE_UDP = "2001:db8:1::35"

NEXT_HOP_BY_HOP, NEXT_TCP, NEXT_UDP, NEXT_FRAGMENT, NEXT_ICMPV6 = 0, 6, 17, 44, 58
FLAG_FIN, FLAG_SYN, FLAG_RST, FLAG_PSH, FLAG_ACK = 0x01, 0x02, 0x04, 0x08, 0x10
ICMPV6_DESTINATION_UNREACHABLE, ICMPV6_ADDRESS_UNREACHABLE = 1, 3
IPV6_MINIMUM_MTU = 1280
HOP_LIMIT = 64


def derive(ipv4):
    """The device's IPv6 address: its mesh IPv4 in the low 32 bits of the mesh prefix."""
    return format_address(MESH_PREFIX | int(ipaddress.IPv4Address(ipv4)))


def underive(ipv6):
    """The mesh IPv4 an address was derived from, or None outside the prefix."""
    value = parse_address(ipv6)
    if value is None or value >> (128 - MESH_PREFIX_LENGTH) != MESH_PREFIX >> (128 - MESH_PREFIX_LENGTH):
        return None
    return str(ipaddress.IPv4Address(value & 0xFFFFFFFF))


def packed(address):
    return parse_address(address).to_bytes(16, "big")


def ones_complement_sum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return total


def checksum(data):
    return (~ones_complement_sum(data)) & 0xFFFF


def ipv6_header(src, dst, next_header, payload_length):
    """Traffic class 0, flow label 0, hop limit 64: what every consumer-built packet carries."""
    return struct.pack("!IHBB", 6 << 28, payload_length, next_header, HOP_LIMIT) + packed(src) + packed(dst)


def upper_checksum(src, dst, next_header, upper):
    """RFC 8200 8.1: the pseudo-header of source, destination, upper-layer length and next header."""
    pseudo = packed(src) + packed(dst) + struct.pack("!IxxxB", len(upper), next_header)
    return checksum(pseudo + upper)


def tcp_packet(src, dst, sport, dport, seq, ack, flags, window=65535, payload=b""):
    segment = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, window, 0, 0) + payload
    segment = segment[:16] + struct.pack("!H", upper_checksum(src, dst, NEXT_TCP, segment)) + segment[18:]
    return ipv6_header(src, dst, NEXT_TCP, len(segment)) + segment


def udp_packet(src, dst, sport, dport, payload):
    segment = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    # Over IPv6 a zero UDP checksum is not allowed (RFC 8200 8.1); a computed zero is sent as 0xffff.
    csum = upper_checksum(src, dst, NEXT_UDP, segment) or 0xFFFF
    segment = segment[:6] + struct.pack("!H", csum) + segment[8:]
    return ipv6_header(src, dst, NEXT_UDP, len(segment)) + segment


def raw_packet(src, dst, next_header, payload):
    return ipv6_header(src, dst, next_header, len(payload)) + payload


def icmpv6_echo(src, dst):
    body = struct.pack("!BBHHH", 128, 0, 0, 0x1234, 1) + b"ping"
    body = body[:2] + struct.pack("!H", upper_checksum(src, dst, NEXT_ICMPV6, body)) + body[4:]
    return raw_packet(src, dst, NEXT_ICMPV6, body)


def frame(body, frame_type=1):
    return b"SPEG1" + bytes([frame_type, 0, 0]) + body


def parse_tcp(packet):
    src = format_address(int.from_bytes(packet[8:24], "big"))
    dst = format_address(int.from_bytes(packet[24:40], "big"))
    sport, dport, seq, ack, offset, flags = struct.unpack("!HHIIBB", packet[40:54])
    return {"src": src, "dst": dst, "sport": sport, "dport": dport, "seq": seq, "ack": ack, "flags": flags,
            "payload": packet[40 + (offset >> 4) * 4:]}


def reset_for_segment(packet):
    """RFC 793, the rule the IPv4 failure vector uses: a segment carrying ACK is reset at that
    acknowledgement; otherwise RST|ACK acknowledging its whole sequence space."""
    seg = parse_tcp(packet)
    if seg["flags"] & FLAG_ACK:
        return tcp_packet(seg["dst"], seg["src"], seg["dport"], seg["sport"], seg["ack"], 0, FLAG_RST, window=0)
    length = len(seg["payload"]) + bool(seg["flags"] & FLAG_SYN) + bool(seg["flags"] & FLAG_FIN)
    return tcp_packet(seg["dst"], seg["src"], seg["dport"], seg["sport"], 0,
                      (seg["seq"] + length) & 0xFFFFFFFF, FLAG_RST | FLAG_ACK, window=0)


def address_unreachable_for(packet):
    """ICMPv6 destination unreachable, address unreachable (RFC 4443 3.1), from the datagram's
    destination back to its source, quoting as much of the datagram as keeps the error within the
    IPv6 minimum MTU."""
    src = format_address(int.from_bytes(packet[24:40], "big"))
    dst = format_address(int.from_bytes(packet[8:24], "big"))
    quoted = packet[:IPV6_MINIMUM_MTU - 40 - 8]
    body = struct.pack("!BBHI", ICMPV6_DESTINATION_UNREACHABLE, ICMPV6_ADDRESS_UNREACHABLE, 0, 0) + quoted
    body = body[:2] + struct.pack("!H", upper_checksum(src, dst, NEXT_ICMPV6, body)) + body[4:]
    return raw_packet(src, dst, NEXT_ICMPV6, body)


CONSUMER = derive(CONSUMER_V4)
OTHER_PEER = derive(OTHER_PEER_V4)


# ---- meshAddress -------------------------------------------------------------------------------

DERIVATIONS = ["100.96.0.1", "100.64.0.0", "100.127.255.255", "100.96.1.0", "10.0.0.1"]
INVERSES = [
    {"ipv6": derive("100.96.0.1"), "meshIpv4": "100.96.0.1"},
    {"ipv6": "fd53:7065:6375:7300::a00:1", "meshIpv4": "10.0.0.1"},
    {"ipv6": "FD53:7065:6375:7300:0:0:6460:0001", "meshIpv4": "100.96.0.1"},
    {"ipv6": "fd53:7065:6375:7301::6460:1", "meshIpv4": None},
    {"ipv6": "fd53:7065:6375:7300:1::6460:1", "meshIpv4": None},
    {"ipv6": "::ffff:6460:1", "meshIpv4": None},
    {"ipv6": "2001:db8::6460:1", "meshIpv4": None},
]
for inverse in INVERSES:
    assert underive(inverse["ipv6"]) == inverse["meshIpv4"], inverse

mesh_address = {
    "prefix": f"{format_address(MESH_PREFIX)}/{MESH_PREFIX_LENGTH}",
    "notes": [
        "每台设备的 IPv6 地址由它的 mesh IPv4 推出：IPv4 的 32 位填进前缀的低 32 位，写成 RFC 5952 规范形式。",
        "前缀固定，不随 peerMeshCidr 变；地址只在租户内唯一，与 IPv4 虚拟地址相同。",
        "反推只认前缀内的地址，比较按数值，写法不影响结果。",
    ],
    "derive": [{"meshIpv4": ipv4, "ipv6": derive(ipv4)} for ipv4 in DERIVATIONS],
    "underive": INVERSES,
}


# ---- ruleValidation ----------------------------------------------------------------------------

RULE_CASES = [
    {"name": "public-prefix-to-capable-egress", "match": "2001:db8:1::/48", "egressOnline": True,
     "egressIpv6PacketCapable": True, "code": None},
    {"name": "the-mesh-prefix", "match": "fd53:7065:6375:7300::/96", "egressOnline": True,
     "egressIpv6PacketCapable": True, "code": "EGRESS_RULE_MESH_OVERLAP"},
    {"name": "one-mesh-address", "match": derive(OTHER_PEER_V4), "egressOnline": True,
     "egressIpv6PacketCapable": True, "code": "EGRESS_RULE_MESH_OVERLAP"},
    {"name": "a-prefix-covering-the-mesh", "match": "fd00::/8", "egressOnline": True,
     "egressIpv6PacketCapable": True, "code": "EGRESS_RULE_MESH_OVERLAP"},
    {"name": "next-to-the-mesh", "match": "fd53:7065:6375:7301::/64", "egressOnline": True,
     "egressIpv6PacketCapable": True, "code": None},
    {"name": "online-egress-without-ipv6-packets", "match": "2001:db8:1::/48", "egressOnline": True,
     "egressIpv6PacketCapable": False, "code": "EGRESS_RULE_EGRESS_NO_IPV6"},
    {"name": "offline-egress", "match": "2001:db8:1::/48", "egressOnline": False,
     "egressIpv6PacketCapable": False, "code": None},
]
for case in RULE_CASES:
    case["rule"] = {"match": case.pop("match"), "action": "egress", "egressClientId": 2}

rule_validation = {
    "notes": [
        "只在有 IPv6 数据面的消费端适用；没有数据面的消费端仍按 peer-egress-rules-v1.json 报 EGRESS_RULE_IPV6_UNSUPPORTED。",
        "推出地址的前缀是 Peer Mesh 网段：与它重叠的 IPv6 规则报 EGRESS_RULE_MESH_OVERLAP，与 IPv4 规则覆盖 mesh 网段相同。",
        "出口能力只对在线的出口判：不在线时规则仍生效，流量计 egress-unavailable；在线而目录没有 ipv6PacketCapable，报 EGRESS_RULE_EGRESS_NO_IPV6，流量计 egress-no-ipv6。",
        "检查顺序沿用 peer-egress.md「规则语义」的编号，mesh 重叠先于出口能力。",
    ],
    "cases": RULE_CASES,
}


# ---- frames ------------------------------------------------------------------------------------

SYN = tcp_packet(CONSUMER, REMOTE, 54321, 443, 1, 0, FLAG_SYN)
DNS = udp_packet(CONSUMER, REMOTE_UDP, 51000, 53,
                 bytes.fromhex("abcd01000001000000000000") + b"\x07example\x03com\x00\x00\x1c\x00\x01")
SYN_ACK = tcp_packet(REMOTE, CONSUMER, 443, 54321, 7000, 2, FLAG_SYN | FLAG_ACK)

frames = {
    "notes": [
        "带 IPv6 数据面的解析器：type=1 的 body 按首字节高 4 位分流，4 走 peer-egress-frame-v1.json 的 IPv4 规则，6 按本节。",
        "没有数据面、或没有声明 ipv6PacketCapable 的出口仍按 peer-egress-frame-v1.json 的 ipv6-packet-in-v1 报 EGRESS_IPV6_UNSUPPORTED。",
        "解析顺序：body 短于 40 字节 → EGRESS_FRAME_TRUNCATED；40 + payloadLength 大于 body → EGRESS_FRAME_TRUNCATED，小于 → EGRESS_FRAME_TRAILING_BYTES。版本既不是 4 也不是 6 沿用一期的 EGRESS_IPV6_UNSUPPORTED。",
        "next header 不在解析时判：解析只取它与（TCP、UDP 时）端口；出口按协议处理时，TCP、UDP 以外（含任何扩展头、分片头、ICMPv6）以 EGRESS_PROTOCOL_DENIED 拒绝，与 IPv4 的 ICMP 相同。",
    ],
    "accept": [
        {"name": "ipv6-tcp-syn-outbound", "direction": "consumer-to-egress", "frameHex": frame(SYN).hex(),
         "innerSourceIp": CONSUMER, "innerDestinationIp": REMOTE, "innerNextHeader": NEXT_TCP,
         "innerSourcePort": 54321, "innerDestinationPort": 443},
        {"name": "ipv6-udp-outbound", "direction": "consumer-to-egress", "frameHex": frame(DNS).hex(),
         "innerSourceIp": CONSUMER, "innerDestinationIp": REMOTE_UDP, "innerNextHeader": NEXT_UDP,
         "innerSourcePort": 51000, "innerDestinationPort": 53},
        {"name": "ipv6-tcp-synack-return", "direction": "egress-to-consumer", "frameHex": frame(SYN_ACK).hex(),
         "innerSourceIp": REMOTE, "innerDestinationIp": CONSUMER, "innerNextHeader": NEXT_TCP,
         "innerSourcePort": 443, "innerDestinationPort": 54321},
        {"name": "ipv6-icmpv6-parses", "direction": "consumer-to-egress",
         "frameHex": frame(icmpv6_echo(CONSUMER, REMOTE)).hex(),
         "innerSourceIp": CONSUMER, "innerDestinationIp": REMOTE, "innerNextHeader": NEXT_ICMPV6,
         "innerSourcePort": 0, "innerDestinationPort": 0,
         "egressCode": "EGRESS_PROTOCOL_DENIED"},
        {"name": "ipv6-fragment-header-parses", "direction": "consumer-to-egress",
         "frameHex": frame(raw_packet(CONSUMER, REMOTE, NEXT_FRAGMENT,
                                      struct.pack("!BBHI", NEXT_TCP, 0, 1, 0x1234) + SYN[40:])).hex(),
         "innerSourceIp": CONSUMER, "innerDestinationIp": REMOTE, "innerNextHeader": NEXT_FRAGMENT,
         "innerSourcePort": 0, "innerDestinationPort": 0,
         "egressCode": "EGRESS_PROTOCOL_DENIED"},
        {"name": "ipv6-hop-by-hop-parses", "direction": "consumer-to-egress",
         "frameHex": frame(raw_packet(CONSUMER, REMOTE, NEXT_HOP_BY_HOP,
                                      struct.pack("!BB", NEXT_TCP, 0) + b"\x01\x04\x00\x00\x00\x00" + SYN[40:])).hex(),
         "innerSourceIp": CONSUMER, "innerDestinationIp": REMOTE, "innerNextHeader": NEXT_HOP_BY_HOP,
         "innerSourcePort": 0, "innerDestinationPort": 0,
         "egressCode": "EGRESS_PROTOCOL_DENIED"},
    ],
    "reject": [
        {"name": "ipv6-body-shorter-than-header", "frameHex": frame(SYN[:39]).hex(),
         "code": "EGRESS_FRAME_TRUNCATED", "reason": "IPv6 固定头 40 字节"},
        {"name": "ipv6-payload-length-beyond-body", "frameHex": frame(SYN[:-1]).hex(),
         "code": "EGRESS_FRAME_TRUNCATED", "reason": "40 + payloadLength 大于 body"},
        {"name": "ipv6-trailing-bytes", "frameHex": frame(SYN + b"\x00").hex(),
         "code": "EGRESS_FRAME_TRAILING_BYTES", "reason": "40 + payloadLength 必须精确等于 body 长度"},
        {"name": "ip-version-five", "frameHex": frame(bytes([0x50]) + SYN[1:]).hex(),
         "code": "EGRESS_IPV6_UNSUPPORTED", "reason": "版本既不是 4 也不是 6，沿用一期的码"},
        {"name": "jumbo-payload-length-zero", "frameHex": frame(SYN[:4] + b"\x00\x00" + SYN[6:]).hex(),
         "code": "EGRESS_FRAME_TRAILING_BYTES", "reason": "payloadLength 为 0 而 body 长于 40：不承载 jumbogram"},
    ],
}


# ---- consumerOutbound --------------------------------------------------------------------------

OUTBOUND = [
    {"name": "to-a-rule", "packet": SYN, "effectiveMtu": 1280, "expect": "forward"},
    {"name": "router-solicitation", "packet": raw_packet("fe80::1", "ff02::2", NEXT_ICMPV6, b"\x85\x00\x00\x00\x00\x00\x00\x00"),
     "effectiveMtu": 1280, "expect": "drop-silently",
     "note": "Link-local source: the system's own neighbour discovery on the TUN, not traffic. Not counted."},
    {"name": "multicast-listener-report", "packet": raw_packet(CONSUMER, "ff02::16", NEXT_HOP_BY_HOP, b"\x3a\x00\x05\x02\x00\x00\x01\x00"),
     "effectiveMtu": 1280, "expect": "drop-silently",
     "note": "Multicast destination: never routed into the TUN by a rule. Not counted."},
    {"name": "source-is-not-this-device", "packet": tcp_packet("2001:db8:ff::1", REMOTE, 54321, 443, 1, 0, FLAG_SYN),
     "effectiveMtu": 1280, "expect": "ipv6-source-not-mesh",
     "note": "An application bound to another address; the egress would refuse it, so it is not sent."},
    {"name": "to-another-mesh-device", "packet": tcp_packet(CONSUMER, OTHER_PEER, 54321, 22, 1, 0, FLAG_SYN),
     "effectiveMtu": 1280, "expect": "ipv6-mesh-unsupported",
     "note": "Mesh traffic between devices stays IPv4; no route sends this prefix into the TUN, so this is only stray traffic."},
    {"name": "path-below-the-ipv6-minimum", "packet": SYN, "effectiveMtu": 1200, "expect": "ipv6-path-mtu",
     "note": "IPv6 needs 1280 on every link; a peer path that probes lower cannot carry it, and a Packet Too Big below 1280 means nothing to an IPv6 stack."},
]
consumer_outbound = {
    "consumerMeshIpv4": CONSUMER_V4,
    "notes": [
        "消费端从 TUN 读到的 IPv6 包，在规则匹配之前按本节分流。forward 之后照常匹配规则，与 IPv4 相同。",
        "drop-silently 不计数：链路本地源与组播目的是系统自己的邻居发现与组播报告，不是流量。",
        "其余丢弃计进 blocked，原因名如 expect 所示，不回应应用。",
        "effectiveMtu 是对端会话的有效 MTU（peer-mesh.md SPMTU2）；TUN 的 MTU 为 1280，peerMeshMtu 低于 1280 的设备没有 IPv6 数据面。",
    ],
    "cases": [{"name": c["name"], "packetHex": c["packet"].hex(), "effectiveMtu": c["effectiveMtu"],
               "expect": c["expect"], **({"note": c["note"]} if "note" in c else {})} for c in OUTBOUND],
}


# ---- returnPath --------------------------------------------------------------------------------

RETURNS = [
    {"name": "reply-to-a-live-flow", "packet": SYN_ACK, "liveFlow": True, "expect": "deliver"},
    {"name": "reply-with-no-flow", "packet": SYN_ACK, "liveFlow": False, "expect": "return-no-flow"},
    {"name": "reply-from-a-mesh-address", "packet": tcp_packet(OTHER_PEER, CONSUMER, 443, 54321, 7000, 2, FLAG_SYN | FLAG_ACK),
     "liveFlow": True, "expect": "return-mesh-source"},
    {"name": "addressed-to-another-device", "packet": tcp_packet(REMOTE, OTHER_PEER, 443, 54321, 7000, 2, FLAG_SYN | FLAG_ACK),
     "liveFlow": True, "expect": "not-for-consumer"},
]
return_path = {
    "consumerMeshIpv4": CONSUMER_V4,
    "notes": [
        "出口 → 消费端的 IPv6 包：目的必须是本机推出地址，否则不归消费端（同时是出口的设备交给出口一侧处理），与 IPv4 相同。",
        "源在推出地址的前缀内拒收，计 return-mesh-source；找不到本机发起的存活流拒收，计 return-no-flow。",
        "liveFlow 表示本机对这个五元组、这个出口有存活流。",
    ],
    "cases": [{"name": c["name"], "packetHex": c["packet"].hex(), "liveFlow": c["liveFlow"], "expect": c["expect"]}
              for c in RETURNS],
}


# ---- failure -----------------------------------------------------------------------------------

RESET_CASES = [
    {"name": "syn-for-a-new-connection", "packet": tcp_packet(CONSUMER, REMOTE, 40000, 443, 1000, 0, FLAG_SYN)},
    {"name": "data-on-a-flow-that-was-purged",
     "packet": tcp_packet(CONSUMER, REMOTE, 40000, 443, 1001, 5001, FLAG_ACK | FLAG_PSH, payload=b"GET / ")},
]
BIG_QUERY = udp_packet(CONSUMER, REMOTE_UDP, 51002, 443, bytes(range(256)) * 6)
UNREACHABLE_CASES = [
    {"name": "dns-query", "packet": DNS,
     "note": "Small enough to quote whole."},
    {"name": "datagram-quoted-to-the-minimum-mtu", "packet": BIG_QUERY,
     "note": f"{len(BIG_QUERY)} bytes; the quote stops where the error would pass 1280 bytes (RFC 4443 2.4 c)."},
]
assert len(BIG_QUERY) > IPV6_MINIMUM_MTU

failure = {
    "notes": [
        "与 peer-egress-failure-v1.json 同一时机写回 TUN：出口不可用（离线、尚未在线、流被清掉）时，消费端拒绝转发的段与数据报。",
        "TCP 复位按 RFC 793，与 IPv4 同一条规则；IPv6 头：traffic class 0、flow label 0、hop limit 64；TCP 窗口 0，无选项。",
        "UDP 回 ICMPv6 目的不可达、地址不可达（类型 1 代码 3，对应 IPv4 的主机不可达），从原包的目的发回原包的源，引用原包直到整个错误报文不超过 1280 字节。",
        "resetOnPurge 的规则与 IPv4 相同，只换地址族，不另列用例。",
    ],
    "resetOnPacket": {"cases": [{"name": c["name"], "packetHex": c["packet"].hex(),
                                 "expect": {"packetHex": reset_for_segment(c["packet"]).hex()}} for c in RESET_CASES]},
    "unreachableOnDatagram": {"cases": [{"name": c["name"], "note": c["note"], "packetHex": c["packet"].hex(),
                                         "expect": {"packetHex": address_unreachable_for(c["packet"]).hex()}}
                                        for c in UNREACHABLE_CASES]},
}


def build():
    return {
        "name": "peer-egress-ipv6-v1",
        "version": 1,
        "spec": "protocol/spec/peer-egress.md#ipv6-数据面",
        "notes": [
            "消费端 IPv6 数据面（#245）：设备的 IPv6 地址由 mesh IPv4 推出；SPEG1 原样承载 IPv6 包，只发给声明了 ipv6PacketCapable 的出口；AAAA 仍回 NODATA。",
            "所有包都由生成器按报文结构造出，校验和按 RFC 8200 的伪首部计算；三端产出的字节必须完全一致。",
        ],
        "meshAddress": mesh_address,
        "ruleValidation": rule_validation,
        "frames": frames,
        "consumerOutbound": consumer_outbound,
        "returnPath": return_path,
        "failure": failure,
    }


if __name__ == "__main__":
    out = VECTORS / "peer-egress-ipv6-v1.json"
    out.write_text(json.dumps(build(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out}")
