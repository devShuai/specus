"""Generate protocol/test-vectors/peer-egress-failure-v1.json.

What the consumer writes back into its own TUN when a flow a rule claims cannot go through the
egress: a TCP reset, or an ICMP host-unreachable for a datagram. Without these the application only
learns that the flow is dead from its own timeout -- a minute or more for TCP -- while the rule is
doing exactly what it should. With them it fails at once and can retry, which is what the spec means
by a flow that cannot be recovered failing explicitly.

Three shapes, each built here from the packet layout rather than recorded from any implementation:

- resetOnPurge: a flow the consumer closed itself (the egress went offline, a rule changed). The
  application sent nothing to answer, so the reset is built from what the consumer remembered about
  the flow: the application's last acknowledgement number is its receive-next, which is the only
  sequence number a modern stack accepts a reset at.
- resetOnPacket: a segment the consumer refused to forward, answered the RFC 793 way -- the same
  rule the egress's own user-space stack uses.
- unreachableOnDatagram: a datagram the consumer refused, answered with ICMP destination
  unreachable, host unreachable, quoting the datagram's header and first eight bytes.
"""
import ipaddress
import json
import struct
from pathlib import Path

VECTORS = Path("protocol/test-vectors")

CONSUMER_IP = "100.96.0.1"
REMOTE_IP = "203.0.113.10"

FLAG_FIN, FLAG_SYN, FLAG_RST, FLAG_PSH, FLAG_ACK = 0x01, 0x02, 0x04, 0x08, 0x10
PROTO_ICMP, PROTO_TCP, PROTO_UDP = 1, 6, 17
ICMP_DESTINATION_UNREACHABLE = 3
ICMP_HOST_UNREACHABLE = 1


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


def ipv4_header(src, dst, proto, payload_len):
    """The header every consumer-built packet carries: no identification, no flags, TTL 64."""
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + payload_len, 0, 0, 64, proto, 0,
                         ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:]


def transport_checksum(src, dst, proto, segment):
    pseudo = (ipaddress.IPv4Address(src).packed + ipaddress.IPv4Address(dst).packed
              + struct.pack("!BBH", 0, proto, len(segment)))
    return checksum(pseudo + segment)


def tcp_packet(src, dst, sport, dport, seq, ack, flags, window=65535, payload=b""):
    segment = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, window, 0, 0) + payload
    csum = transport_checksum(src, dst, PROTO_TCP, segment)
    segment = segment[:16] + struct.pack("!H", csum) + segment[18:]
    return ipv4_header(src, dst, PROTO_TCP, len(segment)) + segment


def udp_packet(src, dst, sport, dport, payload):
    segment = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    csum = transport_checksum(src, dst, PROTO_UDP, segment) or 0xFFFF
    segment = segment[:6] + struct.pack("!H", csum) + segment[8:]
    return ipv4_header(src, dst, PROTO_UDP, len(segment)) + segment


def parse_tcp(packet):
    ihl = (packet[0] & 0x0F) * 4
    sport, dport, seq, ack, offset, flags = struct.unpack("!HHIIBB", packet[ihl:ihl + 14])
    header = ihl + (offset >> 4) * 4
    return {"src": str(ipaddress.IPv4Address(packet[12:16])), "dst": str(ipaddress.IPv4Address(packet[16:20])),
            "sport": sport, "dport": dport, "seq": seq, "ack": ack, "flags": flags,
            "payload": packet[header:struct.unpack("!H", packet[2:4])[0]]}


def reset_for_purge(consumer_ip, consumer_port, remote_ip, remote_port, app_ack, app_seq_next):
    """The reset the consumer writes for a flow it closed. From the remote, to the application:
    RST|ACK, sequence at the application's receive-next, acknowledging what it sent."""
    return tcp_packet(remote_ip, consumer_ip, remote_port, consumer_port, app_ack, app_seq_next,
                      FLAG_RST | FLAG_ACK, window=0)


def reset_for_segment(packet):
    """RFC 793: a reset for a segment carrying ACK takes its sequence from that ACK; otherwise it
    acknowledges the incoming sequence space so the peer cannot dismiss it as out of window."""
    seg = parse_tcp(packet)
    if seg["flags"] & FLAG_ACK:
        return tcp_packet(seg["dst"], seg["src"], seg["dport"], seg["sport"], seg["ack"], 0, FLAG_RST, window=0)
    length = len(seg["payload"]) + bool(seg["flags"] & FLAG_SYN) + bool(seg["flags"] & FLAG_FIN)
    return tcp_packet(seg["dst"], seg["src"], seg["dport"], seg["sport"], 0,
                      (seg["seq"] + length) & 0xFFFFFFFF, FLAG_RST | FLAG_ACK, window=0)


def host_unreachable_for(packet):
    """ICMP destination unreachable, host unreachable, quoting the header and eight bytes."""
    ihl = (packet[0] & 0x0F) * 4
    total = struct.unpack("!H", packet[2:4])[0]
    quoted = packet[:min(total, ihl + 8)]
    icmp = struct.pack("!BBHI", ICMP_DESTINATION_UNREACHABLE, ICMP_HOST_UNREACHABLE, 0, 0) + quoted
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    src = str(ipaddress.IPv4Address(packet[16:20]))
    dst = str(ipaddress.IPv4Address(packet[12:16]))
    return ipv4_header(src, dst, PROTO_ICMP, len(icmp)) + icmp


PURGE_CASES = [
    {"name": "established-flow", "consumerPort": 40000, "remotePort": 443,
     "appAck": 700001, "appSeqNext": 1234,
     "note": "The application acknowledged up to 700001 and sent up to 1233; the reset's sequence "
             "is its receive-next, which RFC 5961 stacks accept without a challenge."},
    {"name": "flow-after-the-handshake-only", "consumerPort": 40001, "remotePort": 8080,
     "appAck": 1, "appSeqNext": 1001,
     "note": "Only the handshake happened: ISS 1000, so the SYN advanced seq to 1001; the egress's "
             "ISN 0 was acknowledged as 1."},
    {"name": "sequence-numbers-near-the-wrap", "consumerPort": 40002, "remotePort": 443,
     "appAck": 0xFFFFFFF0, "appSeqNext": 0xFFFFFFFE,
     "note": "Written as unsigned 32-bit values; a runtime that carries them signed writes the same bytes."},
]

purge_cases = []
for case in PURGE_CASES:
    packet = reset_for_purge(CONSUMER_IP, case["consumerPort"], REMOTE_IP, case["remotePort"],
                             case["appAck"], case["appSeqNext"])
    purge_cases.append({**case, "consumerIp": CONSUMER_IP, "remoteIp": REMOTE_IP,
                        "expect": {"packetHex": packet.hex()}})

PACKET_CASES = [
    {"name": "syn-for-a-new-connection",
     "packet": tcp_packet(CONSUMER_IP, REMOTE_IP, 40000, 443, 1000, 0, FLAG_SYN),
     "note": "The egress is unavailable when the application connects. RST|ACK acknowledging the "
             "SYN is what a SYN-SENT socket accepts; the application sees connection refused."},
    {"name": "data-on-a-flow-that-was-purged",
     "packet": tcp_packet(CONSUMER_IP, REMOTE_IP, 40000, 443, 1001, 5001, FLAG_ACK | FLAG_PSH, payload=b"GET / "),
     "note": "The segment carries ACK, so the reset's sequence is that acknowledgement: the "
             "application's own receive-next."},
    {"name": "fin-after-the-egress-went-away",
     "packet": tcp_packet(CONSUMER_IP, REMOTE_IP, 40000, 443, 2001, 5001, FLAG_ACK | FLAG_FIN),
     "note": "Same rule; the FIN's own sequence number does not enter into it."},
    {"name": "bare-syn-with-payload",
     "packet": tcp_packet(CONSUMER_IP, REMOTE_IP, 40003, 443, 1000, 0, FLAG_SYN, payload=b"\x16\x03\x01"),
     "note": "TCP Fast Open puts data on the SYN; the acknowledgement covers the SYN and the data."},
]

packet_cases = []
for case in PACKET_CASES:
    packet_cases.append({"name": case["name"], "note": case["note"], "packetHex": case["packet"].hex(),
                         "expect": {"packetHex": reset_for_segment(case["packet"]).hex()}})

DATAGRAM_CASES = [
    {"name": "dns-query",
     "packet": udp_packet(CONSUMER_IP, REMOTE_IP, 51000, 53, bytes.fromhex("abcd01000001000000000000") + b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"),
     "note": "The quoted part is the header plus the first eight bytes of the datagram: the UDP "
             "header, which is what lets the stack match the error to the socket."},
    {"name": "short-datagram",
     "packet": udp_packet(CONSUMER_IP, REMOTE_IP, 51001, 3478, b"\x00\x01"),
     "note": "Ten bytes of UDP in all. The quote is still the header plus eight bytes, which is "
             "exactly the UDP header; the two payload bytes are not quoted."},
]

datagram_cases = []
for case in DATAGRAM_CASES:
    datagram_cases.append({"name": case["name"], "note": case["note"], "packetHex": case["packet"].hex(),
                           "expect": {"packetHex": host_unreachable_for(case["packet"]).hex()}})

vector = {
    "name": "peer-egress-failure-v1",
    "version": 1,
    "notes": [
        "消费端在命中 egress 规则的流走不通时写回本机 TUN 的包。不写，应用只能等自己的超时——TCP 要一分钟以上——"
        "而规则其实在正常工作；写了，应用立刻失败、自行重试，这就是规范里「不能无缝恢复的流明确失败」。",
        "resetOnPurge：消费端自己清掉的流（出口离线、规则改动），应用没有发来可以回应的段，"
        "复位从消费端记住的东西造出来：应用最后一次的确认号就是它的接收窗口起点，"
        "现代协议栈（RFC 5961）只在这个序号上接受复位而不发质询 ACK。RST|ACK，确认号为应用发到的位置。",
        "resetOnPacket：消费端拒绝转发的段，按 RFC 793 回应，与出口用户态栈同一条规则："
        "带 ACK 的段，复位的序号取它的确认号；不带 ACK 的段（新连接的 SYN），复位带 ACK，"
        "确认号覆盖它的序号空间（SYN、FIN 各占一个）。",
        "unreachableOnDatagram：消费端拒绝转发的数据报，回 ICMP 目的不可达、主机不可达（类型 3 代码 1），"
        "引用原包的 IP 头和前 8 字节——正是 UDP 头，协议栈靠它把错误对到 socket 上。",
        "只在「出口不可用」时写回：出口离线、尚未在线、流被清掉。发送失败（会话正在重建）不写，"
        "那条流可能还能恢复；block 规则不写，它是丢弃；不承载的协议不写。",
        "IPv4 头固定：无标识、无标志、TTL 64；TCP 窗口 0，无选项。三端产出的字节必须完全一致。",
    ],
    "resetOnPurge": {"cases": purge_cases},
    "resetOnPacket": {"cases": packet_cases},
    "unreachableOnDatagram": {"cases": datagram_cases},
}

out = VECTORS / "peer-egress-failure-v1.json"
out.write_text(json.dumps(vector, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"wrote {out}: purge={len(purge_cases)} packet={len(packet_cases)} datagram={len(datagram_cases)}")
