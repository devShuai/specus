"""Generate protocol/test-vectors/peer-egress-frame-v1.json.

Builds real IPv4/TCP and IPv4/UDP packets with verified checksums, wraps them in
SPEG1 headers, and emits the canonical vector file.
"""
import json
import struct
import ipaddress
from pathlib import Path

MAGIC = b"SPEG1"
TYPE_IP = 1
TYPE_CONTROL = 2
FLAG_HOP = 0x01


def ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return total


def checksum(data: bytes) -> int:
    return (~ones_complement_sum(data)) & 0xFFFF


def ipv4_header(src, dst, proto, payload_len, ident=0x1234, ttl=64, flags_frag=0x4000):
    total_len = 20 + payload_len
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, total_len, ident, flags_frag, ttl, proto, 0,
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
    )
    csum = checksum(header)
    return header[:10] + struct.pack("!H", csum) + header[12:]


def transport_checksum(src, dst, proto, segment):
    pseudo = (
        ipaddress.IPv4Address(src).packed
        + ipaddress.IPv4Address(dst).packed
        + struct.pack("!BBH", 0, proto, len(segment))
    )
    return checksum(pseudo + segment)


def tcp_syn(src, dst, sport, dport, seq=1, window=0xFFFF):
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, 0x02, window, 0, 0)
    csum = transport_checksum(src, dst, 6, seg)
    seg = seg[:16] + struct.pack("!H", csum) + seg[18:]
    assert transport_checksum(src, dst, 6, seg) == 0, "tcp checksum does not verify"
    return ipv4_header(src, dst, 6, len(seg)) + seg


def udp_datagram(src, dst, sport, dport, payload):
    length = 8 + len(payload)
    seg = struct.pack("!HHHH", sport, dport, length, 0) + payload
    csum = transport_checksum(src, dst, 17, seg)
    if csum == 0:
        csum = 0xFFFF
    seg = seg[:6] + struct.pack("!H", csum) + seg[8:]
    assert transport_checksum(src, dst, 17, seg) == 0, "udp checksum does not verify"
    return ipv4_header(src, dst, 17, len(seg), ident=0x1235) + seg


def verify_ipv4(packet):
    assert checksum(packet[:20]) == 0, "ipv4 header checksum does not verify"


def speg1(msg_type, body, flags=0):
    return MAGIC + bytes([msg_type, flags, 0]) + body


def canonical_json(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


CONSUMER_VIP = "100.96.0.1"
TARGET = "203.0.113.200"
UDP_TARGET = "198.51.100.20"

syn = tcp_syn(CONSUMER_VIP, TARGET, 54321, 443)
verify_ipv4(syn)
udp = udp_datagram(CONSUMER_VIP, UDP_TARGET, 51000, 53, b"specus-egress-udp-probe")
verify_ipv4(udp)
# Return direction: source is the real target, destination is the consumer virtual IP.
synack_seg = struct.pack("!HHIIBBHHH", 443, 54321, 0x0A0B0C0D, 2, 0x50, 0x12, 0xFFFF, 0, 0)
synack_csum = transport_checksum(TARGET, CONSUMER_VIP, 6, synack_seg)
synack_seg = synack_seg[:16] + struct.pack("!H", synack_csum) + synack_seg[18:]
synack = ipv4_header(TARGET, CONSUMER_VIP, 6, len(synack_seg), ident=0x1236) + synack_seg
verify_ipv4(synack)

flow_reject = {
    "type": "flow-reject",
    "protocol": "tcp",
    "sourceIp": CONSUMER_VIP,
    "sourcePort": 54321,
    "destinationIp": "203.0.113.9",
    "destinationPort": 22,
    "code": "EGRESS_DEST_DENIED",
}
flow_purge = {
    "type": "flow-purge",
    "destinations": ["203.0.113.0/24", "198.51.100.50/32"],
    "code": "EGRESS_RULE_REVOKED",
}

accept = [
    {
        "name": "ip-tcp-syn-outbound",
        "direction": "consumer-to-egress",
        "description": "消费端把命中出口规则的 TCP SYN 交给出口；源为消费端虚拟 IP，目标为受控目标",
        "frameHex": speg1(TYPE_IP, syn).hex(),
        "frameLength": len(speg1(TYPE_IP, syn)),
        "type": TYPE_IP,
        "flags": 0,
        "innerPacketHex": syn.hex(),
        "innerSourceIp": CONSUMER_VIP,
        "innerDestinationIp": TARGET,
        "innerProtocol": "tcp",
        "innerSourcePort": 54321,
        "innerDestinationPort": 443,
    },
    {
        "name": "ip-udp-outbound",
        "direction": "consumer-to-egress",
        "description": "UDP 数据报走同一条数据面；QUIC 作为 UDP 转发是透明的，不单独处理",
        "frameHex": speg1(TYPE_IP, udp).hex(),
        "frameLength": len(speg1(TYPE_IP, udp)),
        "type": TYPE_IP,
        "flags": 0,
        "innerPacketHex": udp.hex(),
        "innerSourceIp": CONSUMER_VIP,
        "innerDestinationIp": UDP_TARGET,
        "innerProtocol": "udp",
        "innerSourcePort": 51000,
        "innerDestinationPort": 53,
    },
    {
        "name": "ip-tcp-synack-return",
        "direction": "egress-to-consumer",
        "description": "回程包源为真实目标、目标为消费端虚拟 IP；消费端必须能把它关联到本机发起的存活出口流",
        "frameHex": speg1(TYPE_IP, synack).hex(),
        "frameLength": len(speg1(TYPE_IP, synack)),
        "type": TYPE_IP,
        "flags": 0,
        "innerPacketHex": synack.hex(),
        "innerSourceIp": TARGET,
        "innerDestinationIp": CONSUMER_VIP,
        "innerProtocol": "tcp",
        "innerSourcePort": 443,
        "innerDestinationPort": 54321,
    },
    {
        "name": "control-flow-reject",
        "direction": "egress-to-consumer",
        "description": "拒绝原因仅用于诊断展示；应用侧以出口用户态栈生成的 RST 为准，控制消息丢失不影响正确性",
        "frameHex": speg1(TYPE_CONTROL, canonical_json(flow_reject)).hex(),
        "frameLength": len(speg1(TYPE_CONTROL, canonical_json(flow_reject))),
        "type": TYPE_CONTROL,
        "flags": 0,
        "controlJson": flow_reject,
        "controlCanonicalUtf8Hex": canonical_json(flow_reject).hex(),
    },
    {
        "name": "control-flow-purge",
        "direction": "consumer-to-egress",
        "description": "规则从 allow 变为 deny 或不再匹配时，消费端要求出口关闭匹配目标的已建流",
        "frameHex": speg1(TYPE_CONTROL, canonical_json(flow_purge)).hex(),
        "frameLength": len(speg1(TYPE_CONTROL, canonical_json(flow_purge))),
        "type": TYPE_CONTROL,
        "flags": 0,
        "controlJson": flow_purge,
        "controlCanonicalUtf8Hex": canonical_json(flow_purge).hex(),
    },
]

ipv6_packet = bytes([0x60, 0, 0, 0, 0, 0, 6, 64]) + b"\x00" * 32

reject = [
    {
        "name": "bad-magic",
        "frameHex": (b"SPEG0" + bytes([TYPE_IP, 0, 0]) + syn).hex(),
        "reason": "magic 必须为 ASCII SPEG1",
        "code": "EGRESS_FRAME_BAD_MAGIC",
    },
    {
        "name": "unknown-type",
        "frameHex": speg1(3, syn).hex(),
        "reason": "一期只定义 type 1 与 2；未知 type 丢弃，不猜测语义",
        "code": "EGRESS_FRAME_UNKNOWN_TYPE",
    },
    {
        "name": "reserved-byte-nonzero",
        "frameHex": (MAGIC + bytes([TYPE_IP, 0, 1]) + syn).hex(),
        "reason": "reserved 字节必须为 0，非 0 一律拒绝而不是忽略",
        "code": "EGRESS_FRAME_RESERVED_SET",
    },
    {
        "name": "reserved-flag-bits-set",
        "frameHex": speg1(TYPE_IP, syn, flags=0x02).hex(),
        "reason": "flags 只定义 bit0 hop；其余位保留必须为 0",
        "code": "EGRESS_FRAME_RESERVED_SET",
    },
    {
        "name": "hop-flag-set",
        "frameHex": speg1(TYPE_IP, syn, flags=FLAG_HOP).hex(),
        "reason": "已带 hop 标记的建流请求表示来自另一个出口；不支持多跳出口链",
        "code": "EGRESS_HOP_NOT_ALLOWED",
    },
    {
        "name": "truncated-header",
        "frameHex": MAGIC.hex() + "0100",
        "reason": "帧短于 8 字节固定头",
        "code": "EGRESS_FRAME_TRUNCATED",
    },
    {
        "name": "empty-ip-body",
        "frameHex": speg1(TYPE_IP, b"").hex(),
        "reason": "type=1 的 body 必须是完整 IPv4 packet",
        "code": "EGRESS_FRAME_TRUNCATED",
    },
    {
        "name": "ip-body-shorter-than-header",
        "frameHex": speg1(TYPE_IP, syn[:19]).hex(),
        "reason": "IPv4 header 至少 20 字节",
        "code": "EGRESS_FRAME_TRUNCATED",
    },
    {
        "name": "ip-total-length-mismatch",
        "frameHex": speg1(TYPE_IP, syn + b"\x00").hex(),
        "reason": "IPv4 totalLength 必须精确等于 body 长度，尾随字节拒绝",
        "code": "EGRESS_FRAME_TRAILING_BYTES",
    },
    {
        "name": "ipv6-packet-in-v1",
        "frameHex": speg1(TYPE_IP, ipv6_packet).hex(),
        "reason": "一期数据面只接受 IPv4；IPv6 明确拒绝而不是静默丢弃或回退本地",
        "code": "EGRESS_IPV6_UNSUPPORTED",
    },
    {
        "name": "control-not-json",
        "frameHex": speg1(TYPE_CONTROL, b"not-json").hex(),
        "reason": "type=2 的 body 必须是 UTF-8 JSON object",
        "code": "EGRESS_FRAME_MALFORMED_CONTROL",
    },
    {
        "name": "control-unknown-type",
        "frameHex": speg1(TYPE_CONTROL, canonical_json({"type": "name-bind"})).hex(),
        "reason": "name-bind 为二期域名分流保留；一期收到必须拒绝，不得当作已实现",
        "code": "EGRESS_CONTROL_UNSUPPORTED",
    },
]

vector = {
    "name": "peer-egress-frame-v1",
    "version": 1,
    "magicAscii": "SPEG1",
    "magicHex": MAGIC.hex(),
    "headerBytes": 8,
    "headerLayout": [
        {"field": "magic", "bytes": 5, "value": "ASCII SPEG1"},
        {"field": "type", "bytes": 1, "value": "1=ip-packet, 2=control"},
        {"field": "flags", "bytes": 1, "value": "bit0=hop, 其余保留必须为 0"},
        {"field": "reserved", "bytes": 1, "value": "必须为 0"},
    ],
    "notes": [
        "SPEG1 是 SPM2 解密后的第三种明文类型，与裸 IPv4 packet 和 STMSG2 应用消息并列。",
        "所有 frameHex 是 SPM2 密文解密后的明文，不含 SPM2 的 20 字节头和 16 字节 tag。",
        "type=1 的 body 是完整 IPv4 packet；一期不接受 IPv6。",
        "type=2 的 body 是 UTF-8 JSON object，键序按本文件 controlJson 给出的顺序，无空白。",
        "控制消息只用于诊断与撤销，不承载业务数据；丢失不得影响数据面正确性。",
    ],
    "accept": accept,
    "reject": reject,
}

out = Path("protocol/test-vectors/peer-egress-frame-v1.json")
out.write_text(json.dumps(vector, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print("wrote", out, out.stat().st_size, "bytes")
print("accept cases:", len(accept), "reject cases:", len(reject))
print("syn frame:", speg1(TYPE_IP, syn).hex())
