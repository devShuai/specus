"""Generate peer-egress-rules-v1.json and peer-egress-authz-v1.json.

Both files carry a reference matcher/evaluator implemented here. Every expectation
in the emitted vectors is asserted against that reference before writing, so the
files cannot ship internally inconsistent cases.
"""
import json
import ipaddress
from pathlib import Path

import peer_egress_ipv6 as ipv6

# --------------------------------------------------------------------------
# Consumer-side rule matching
#
# Consumer rules are address-only by construction: the consumer steers traffic
# by installing routes, and a route selects on destination address alone. Ports
# and protocols therefore live on the egress policy, where they are enforced at
# connect time. See protocol/spec/peer-egress.md.
# --------------------------------------------------------------------------

RULES = [
    {"index": 0, "match": "203.0.113.0/24", "action": "direct"},
    {"index": 1, "match": "203.0.113.128/25", "action": "egress", "egressClientId": 2},
    {"index": 2, "match": "198.51.100.0/24", "action": "egress", "egressClientId": 3},
    {"index": 3, "match": "198.51.100.50/32", "action": "block"},
    {"index": 4, "match": "192.0.2.0/24", "action": "egress", "egressClientId": 2},
    {"index": 5, "match": "192.0.2.0/24", "action": "block"},
    # Rules that fail validation, kept in the list on purpose. A rule the operator has been told
    # is refused must not go on steering traffic, and both of these carry a prefix long enough to
    # beat a valid rule if a matcher only parsed `match`. Appended so indices 0..5 stay stable.
    {"index": 6, "match": "192.0.2.128/25", "action": "block", "port": 443},
    {"index": 7, "match": "172.16.0.0/16", "action": "egress", "egressClientId": 3},
    {"index": 8, "match": "172.16.5.0/24", "action": "egress", "egressClientId": 0},
    # Switched off by the user rather than refused. Kept in the list, and with a prefix that beats
    # rule 2 for half its range, so a matcher that ignored `enabled` would send those addresses to
    # the block instead of the egress.
    {"index": 9, "match": "198.51.100.0/25", "action": "block", "enabled": False},
]

MESH_NETWORK = ipaddress.IPv4Network("100.96.0.0/11")

# Which of RULES are refused, and with which code. Published in the vector so a runtime asserts
# the premise of the two skip cases instead of trusting a comment: a runtime that read rule 6 as
# valid would fail here rather than quietly passing the match case for the wrong reason.
REFUSED_RULES = [
    {"index": 6, "code": "EGRESS_RULE_PORT_UNSUPPORTED",
     "reason": "携带端口维度；消费端按路由分流，路由选不了端口"},
    {"index": 8, "code": "EGRESS_RULE_MISSING_TARGET",
     "reason": "egressClientId 为 0，不是有效标识"},
    {"index": 9, "code": "EGRESS_RULE_DISABLED",
     "reason": "用户停用；停用的规则留在列表里，不参与匹配、不安装路由"},
]


def parse_rule_match(match):
    """A rule's match as (family, network, length): 6 for anything with a colon, 4 otherwise.
    None when it does not read as an address or prefix of that family."""
    if ":" in match:
        parsed = ipv6.parse_prefix(match)
        return None if parsed is None else (6, parsed[0], parsed[1])
    try:
        # strict by default, so host bits are a refusal rather than something to normalise
        network = ipaddress.IPv4Network(match)
    except ValueError:
        return None
    return 4, int(network.network_address), network.prefixlen


def validate_rule(rule, ipv6_data_plane=False):
    """The fixed validation order from protocol/spec/peer-egress.md.

    Here so the codes in CONFIG_REJECT are checked against a reference rather than only
    against each other, and so match_rule can skip what it refuses. ipv6_data_plane says whether
    the consumer carries IPv6; none of the clients does yet, so the default is the codes they give.
    """
    # Only an explicit false switches a rule off; an absent field is the rule as written.
    if rule.get("enabled") is False:
        return "EGRESS_RULE_DISABLED"
    match = (rule.get("match") or "").strip()
    if not match:
        return "EGRESS_RULE_MALFORMED"
    # A colon is unambiguous: the match is an IPv6 address or prefix, or it is malformed. An
    # IPv4-mapped prefix reads but can never match a packet, so it is refused as malformed too.
    if ":" in match:
        parsed = parse_rule_match(match)
        if parsed is None or ipv6.is_mapped(parsed[1]):
            return "EGRESS_RULE_MALFORMED"
    elif match.startswith("*") or any(c.isalpha() for c in match):
        return "EGRESS_RULE_DOMAIN_UNSUPPORTED"
    parsed = parse_rule_match(match)
    if parsed is None:
        return "EGRESS_RULE_MALFORMED"
    family, network, length = parsed
    if length == 0:
        return "EGRESS_RULE_DEFAULT_ROUTE"
    # The mesh is IPv4, so only an IPv4 rule can overlap it.
    if family == 4 and ipaddress.IPv4Network((network, length)).overlaps(MESH_NETWORK):
        return "EGRESS_RULE_MESH_OVERLAP"
    if rule.get("port") is not None:
        return "EGRESS_RULE_PORT_UNSUPPORTED"
    if rule.get("action") not in ("egress", "direct", "block"):
        return "EGRESS_RULE_MALFORMED"
    if rule["action"] == "egress" and int(rule.get("egressClientId") or 0) <= 0:
        return "EGRESS_RULE_MISSING_TARGET"
    # Last: everything about the rule is right, and what is missing is this device's ability to
    # carry IPv6 at all.
    if family == 6 and not ipv6_data_plane:
        return "EGRESS_RULE_IPV6_UNSUPPORTED"
    return None


def match_rule(destination):
    addr = ipaddress.IPv4Address(destination)
    best = None
    for rule in RULES:
        if validate_rule(rule) is not None:
            # Skipped here rather than left to the caller to pre-filter, so that one bad rule
            # cannot change what a good one decides no matter who assembled the list.
            continue
        net = ipaddress.IPv4Network(rule["match"])
        if addr not in net:
            continue
        if best is None:
            best = rule
            continue
        best_len = ipaddress.IPv4Network(best["match"]).prefixlen
        if net.prefixlen > best_len:
            best = rule
        # equal prefix length: the earlier index already won, keep it
    if best is None:
        return {"action": "direct", "matchedRuleIndex": None, "reason": "default"}
    result = {"action": best["action"], "matchedRuleIndex": best["index"], "reason": "matched"}
    if best["action"] == "egress":
        result["egressClientId"] = best["egressClientId"]
    return result


RULE_CASES = [
    ("longest-prefix-beats-order", "203.0.113.200",
     "更长前缀 /25 胜出，尽管 /24 规则排在前面"),
    ("shorter-prefix-when-no-longer-match", "203.0.113.10",
     "不在 /25 范围内，落到 /24 的 direct"),
    ("host-route-beats-covering-block", "198.51.100.50",
     "/32 胜过覆盖它的 /24，与配置顺序无关"),
    ("covering-rule-for-sibling-address", "198.51.100.51",
     "同网段其它地址仍由 /24 决定"),
    ("equal-prefix-first-wins", "192.0.2.5",
     "前缀长度相同时先匹配者胜，后面的同前缀规则不生效"),
    ("unmatched-falls-through-to-direct", "8.8.8.8",
     "未匹配即本地直连；这是路由表本身的结果，不是兜底分支"),
    ("network-address-is-in-range", "203.0.113.128",
     "网络地址属于该前缀，正常匹配"),
    ("broadcast-address-is-in-range", "203.0.113.255",
     "/24 的广播地址落在 /25 内，仍按最长前缀匹配"),
    ("refused-rule-does-not-steer-traffic", "192.0.2.200",
     "覆盖它的 /25 因携带端口被拒，落回 /24；被拒的规则若仍参与匹配，运维看到「已拒绝」的规则依然在改变流量走向"),
    ("refused-target-does-not-steer-traffic", "172.16.5.10",
     "更长的 /24 因 egressClientId 为 0 被拒，落回 /16"),
    ("disabled-rule-does-not-steer-traffic", "198.51.100.20",
     "覆盖它的 /25 已被用户停用，落回 /24 的 egress；停用与被拒一样不参与匹配"),
]

rule_cases = []
for name, destination, description in RULE_CASES:
    expect = match_rule(destination)
    rule_cases.append({
        "name": name,
        "destination": destination,
        "description": description,
        "expect": expect,
    })

CONFIG_REJECT = [
    {"name": "exact-domain", "rule": {"match": "example.com", "action": "egress", "egressClientId": 2},
     "code": "EGRESS_RULE_DOMAIN_UNSUPPORTED",
     "reason": "一期不支持域名规则。必须在配置校验阶段拒绝，不得忽略，更不得在启动时解析成静态 IP"},
    {"name": "domain-suffix", "rule": {"match": "*.example.com", "action": "egress", "egressClientId": 2},
     "code": "EGRESS_RULE_DOMAIN_UNSUPPORTED",
     "reason": "域名后缀同样属于二期范围"},
    {"name": "ipv6-cidr", "rule": {"match": "2001:db8::/32", "action": "egress", "egressClientId": 2},
     "code": "EGRESS_RULE_IPV6_UNSUPPORTED",
     "reason": "写法合法的 IPv6 规则，但消费端还没有 IPv6 数据面；拒绝而不是静默忽略，否则会静默走本地形成泄漏"},
    {"name": "ipv6-single", "rule": {"match": "2001:db8::1", "action": "block"},
     "code": "EGRESS_RULE_IPV6_UNSUPPORTED",
     "reason": "同上"},
    {"name": "ipv6-host-bits-set", "rule": {"match": "2001:db8::1/32", "action": "block"},
     "code": "EGRESS_RULE_MALFORMED",
     "reason": "IPv6 与 IPv4 同一条：主机位非零拒绝，不做隐式掩码。写错的规则先报写错，而不是笼统的「不支持」"},
    {"name": "ipv6-dotted-tail", "rule": {"match": "::ffff:192.0.2.1", "action": "block"},
     "code": "EGRESS_RULE_MALFORMED",
     "reason": "不接受末尾内嵌点分 IPv4 的写法；IPv6 只写十六进制"},
    {"name": "ipv6-mapped", "rule": {"match": "::ffff:cb00:7100/120", "action": "egress", "egressClientId": 2},
     "code": "EGRESS_RULE_MALFORMED",
     "reason": "IPv4 映射段 ::ffff:0:0/96 是 IPv4 目标在 IPv6 接口里的写法，线上不出现，这条规则永远不会命中；写成 IPv4"},
    {"name": "ipv6-default-route", "rule": {"match": "::/0", "action": "egress", "egressClientId": 2},
     "code": "EGRESS_RULE_DEFAULT_ROUTE",
     "reason": "与 0.0.0.0/0 同理，不接管 IPv6 默认路由"},
    {"name": "ipv6-port-outranks-ipv6-unsupported", "rule": {"match": "2001:db8::/32", "action": "egress", "egressClientId": 2, "port": 443},
     "code": "EGRESS_RULE_PORT_UNSUPPORTED",
     "reason": "规则本身的问题先于本机能力：IPv6 不受支持排在全部内容检查之后"},
    {"name": "ipv6-missing-target-outranks-ipv6-unsupported", "rule": {"match": "2001:db8::/32", "action": "egress"},
     "code": "EGRESS_RULE_MISSING_TARGET",
     "reason": "同上"},
    {"name": "malformed-prefix-length", "rule": {"match": "203.0.113.0/33", "action": "block"},
     "code": "EGRESS_RULE_MALFORMED",
     "reason": "IPv4 前缀长度必须为 0..32"},
    {"name": "host-bits-set", "rule": {"match": "203.0.113.1/24", "action": "block"},
     "code": "EGRESS_RULE_MALFORMED",
     "reason": "主机位非零一律拒绝，不做隐式掩码归一化——各语言的归一化行为不一致，拒绝比兼容更安全"},
    {"name": "egress-action-without-target", "rule": {"match": "203.0.113.0/24", "action": "egress"},
     "code": "EGRESS_RULE_MISSING_TARGET",
     "reason": "action=egress 必须指定 egressClientId"},
    {"name": "overlaps-mesh-cidr", "rule": {"match": "100.96.0.0/11", "action": "egress", "egressClientId": 2},
     "code": "EGRESS_RULE_MESH_OVERLAP",
     "reason": "规则不得覆盖 Peer Mesh 虚拟网段，否则组网自身流量会被卷进出口"},
    {"name": "default-route-not-allowed", "rule": {"match": "0.0.0.0/0", "action": "egress", "egressClientId": 2},
     "code": "EGRESS_RULE_DEFAULT_ROUTE",
     "reason": "一期不接管默认路由。抢默认路由会覆盖用户既有配置，且与「未匹配即本地直连」冲突"},
    {"name": "port-on-consumer-rule", "rule": {"match": "203.0.113.0/24", "action": "egress", "egressClientId": 2, "port": 443},
     "code": "EGRESS_RULE_PORT_UNSUPPORTED",
     "reason": "消费端按路由分流，路由只能选目的地址。端口与协议限制只存在于出口策略，在建流时执行"},
    # 同时违反多项的用例。规范固定了校验顺序，但在补这几条之前向量里没有任何一条规则同时踩两个坑，
    # 于是各语言可以各返回一个码而向量抓不到——这正是四端实现最容易漂开的地方。
    {"name": "colon-outranks-domain", "rule": {"match": "*.example.com:443", "action": "egress", "egressClientId": 2},
     "code": "EGRESS_RULE_MALFORMED",
     "reason": "冒号是无歧义信号，先于域名判断：带冒号的就按 IPv6 读，读不出即写错，否则带冒号的通配串在各实现里会被归成不同类"},
    {"name": "domain-outranks-port", "rule": {"match": "*.example.com", "action": "egress", "egressClientId": 2, "port": 443},
     "code": "EGRESS_RULE_DOMAIN_UNSUPPORTED",
     "reason": "先判断 match 是什么，再判断它带了什么维度"},
    {"name": "default-route-outranks-unreadable-action", "rule": {"match": "0.0.0.0/0", "action": "forward"},
     "code": "EGRESS_RULE_DEFAULT_ROUTE",
     "reason": "match 是规则主体，作为前缀被拒的两种排在 action 之前"},
    {"name": "mesh-overlap-outranks-port", "rule": {"match": "100.96.0.0/11", "action": "egress", "egressClientId": 2, "port": 443},
     "code": "EGRESS_RULE_MESH_OVERLAP",
     "reason": "同上，覆盖 mesh 网段比携带端口更靠前"},
    {"name": "port-outranks-unreadable-action", "rule": {"match": "203.0.113.0/24", "action": "forward", "port": 443},
     "code": "EGRESS_RULE_PORT_UNSUPPORTED",
     "reason": "端口维度先于 action 判定，与三个先落地的实现一致"},
    {"name": "unreadable-action-outranks-missing-target", "rule": {"match": "203.0.113.0/24", "action": "forward"},
     "code": "EGRESS_RULE_MALFORMED",
     "reason": "action 读不懂时不再追问它缺什么字段"},
    {"name": "host-bits-outrank-everything-after", "rule": {"match": "203.0.113.1/24", "action": "egress", "egressClientId": 2, "port": 443},
     "code": "EGRESS_RULE_MALFORMED",
     "reason": "前缀本身不合法时，后面的策略判断都建立在读不出的前缀上"},
    {"name": "zero-egress-client-id", "rule": {"match": "203.0.113.0/24", "action": "egress", "egressClientId": 0},
     "code": "EGRESS_RULE_MISSING_TARGET",
     "reason": "0 是本项目里「没有消费端」的哨兵值。接受它等于让规则过校验、路由照常安装，然后每个包都找不到出口对端——配置期能报出的错被推迟成运行期的黑洞"},
    {"name": "disabled-rule", "rule": {"match": "203.0.113.0/24", "action": "egress", "egressClientId": 2, "enabled": False},
     "code": "EGRESS_RULE_DISABLED",
     "reason": "用户停用的规则。留在配置里，不参与匹配、不安装路由；状态里以 inForce=false 列出"},
    {"name": "disabled-outranks-everything", "rule": {"match": "example.com", "action": "forward", "enabled": False},
     "code": "EGRESS_RULE_DISABLED",
     "reason": "停用是用户的明确选择，排在所有内容检查之前：一条停用的规则不必先修好才能留在列表里"},
    {"name": "negative-egress-client-id", "rule": {"match": "203.0.113.0/24", "action": "egress", "egressClientId": -1},
     "code": "EGRESS_RULE_MISSING_TARGET",
     "reason": "同上：标识必须是正整数，字段在场不等于字段有效"},
]

# The hand-written codes above and the reference must agree. Without this the reference could
# drift from the cases it is supposed to be checking, and the file would still look consistent.
for case in CONFIG_REJECT:
    produced = validate_rule(case["rule"])
    assert produced == case["code"], f"{case['name']}: reference says {produced}, case says {case['code']}"

expected_refusals = {entry["index"]: entry["code"] for entry in REFUSED_RULES}
for rule in RULES:
    assert validate_rule(rule) == expected_refusals.get(rule["index"]), f"rule {rule['index']}"

# The consumer's master switch. Off, nothing is in force and nothing matches, whatever the rules
# say; each rule still reports why it is not in force, with a rule's own switch taking precedence
# because that is the more specific statement. Clients read this section; servers have no switch.
CONSUMER_DISABLED = {
    "description": "peerEgressEnabled=false：规则只保存不接管。每条规则 inForce=false，错误码 EGRESS_CONSUMER_DISABLED；本身停用的规则仍报 EGRESS_RULE_DISABLED。任何目的地址都不命中规则，按未匹配处理——没有安装路由的目标本来就不进 TUN。",
    "ruleCodes": [
        {"index": rule["index"],
         "code": "EGRESS_RULE_DISABLED" if rule.get("enabled") is False else "EGRESS_CONSUMER_DISABLED"}
        for rule in RULES
    ],
    "cases": [
        {"destination": destination,
         "expect": {"action": "direct", "matchedRuleIndex": None, "reason": "default"}}
        for _, destination, _ in RULE_CASES
    ],
}

# --------------------------------------------------------------------------
# IPv6 spelling, shared by consumer rules and egress policies
#
# One grammar for both, written out in tools/protocol/peer_egress_ipv6.py. Each accepted case gives
# the address in RFC 5952 form and the length; a server stores the former, with the length only if
# it was written. The refused spellings are the ones a runtime's own parser tends to let through.
# --------------------------------------------------------------------------

IPV6_ACCEPT = [
    ("2001:db8::/32", "前缀"),
    ("2001:DB8:0:0::/32", "大小写与零组只是写法，按数值读"),
    ("2001:0db8:0000:0000:0000:0000:0000:0001", "完整写法；每组前导零可写可不写"),
    ("2001:db8::7/128", "带 /128 的单地址"),
    ("::", "全零地址"),
    ("::/0", "全零前缀；作为消费端规则是默认路由，另行拒绝"),
    ("::1", "回环"),
    ("1::", "压缩在末尾"),
    ("1:2:3:4:5:6:7::", "压缩只代表一组零也合法；规范形式不压缩单组零"),
    ("1:0:0:2:0:0:0:3", "规范形式压缩最长的一段零"),
    ("1:0:0:2:0:0:3:4", "等长时压缩靠左的一段"),
    ("fe80::/10", "链路本地"),
    ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "最大地址"),
    ("::ffff:0:0/96", "IPv4 映射段写法本身合法；消费端规则另行拒绝"),
    ("64:ff9b::/96", "NAT64 前缀"),
]

IPV6_REJECT = [
    ("2001:db8::1/32", "主机位非零"),
    ("2001:db8::/129", "前缀长度越界"),
    ("2001:db8::/032", "前缀长度有前导零"),
    ("2001:db8::/", "斜杠后为空"),
    ("2001:db8::/-1", "前缀长度带符号"),
    ("2001:db8::/32/64", "两个斜杠"),
    ("2001:db8::/\uff13\uff12", "全角数字不是数字"),
    ("\uff12001:db8::1", "同上，在地址里"),
    ("::ffff:192.0.2.1", "末尾内嵌点分 IPv4"),
    ("64:ff9b::192.0.2.1/120", "同上，带前缀"),
    ("fe80::1%eth0", "区域标识"),
    ("[2001:db8::1]", "方括号"),
    ("2001:db8::12345", "一组超过四位"),
    ("2001:db8:::1", "三个冒号"),
    ("2001::db8::1", "两处压缩"),
    ("1:2:3:4:5:6:7:8:9", "九组"),
    ("1:2:3:4:5:6:7", "不压缩时不足八组"),
    ("1:2:3:4:5:6:7:8::", "压缩之外已有八组"),
    ("::1:2:3:4:5:6:7:8", "同上，压缩在开头"),
    (":1:2:3:4:5:6:7:8", "单冒号开头"),
    ("1:2:3:4:5:6:7:8:", "单冒号结尾"),
    ("2001:db8 ::1", "中间有空白"),
    ("g::1", "非十六进制字符"),
    (":", "单个冒号"),
]


def ipv6_prefix_cases():
    accept = []
    for text, reason in IPV6_ACCEPT:
        ipv6.cross_check(text)
        parsed = ipv6.parse_prefix(text)
        assert parsed is not None, text
        accept.append({"text": text, "address": ipv6.format_address(parsed[0]), "prefixLength": parsed[1],
                       "reason": reason})
    reject = []
    for text, reason in IPV6_REJECT:
        assert ipv6.parse_prefix(text) is None, text
        reject.append({"text": text, "reason": reason})
    # Hand-checked, so the reference itself is pinned.
    by_text = {case["text"]: case["address"] for case in accept}
    assert by_text["1:2:3:4:5:6:7::"] == "1:2:3:4:5:6:7:0"
    assert by_text["1:0:0:2:0:0:0:3"] == "1:0:0:2::3"
    assert by_text["1:0:0:2:0:0:3:4"] == "1::2:0:0:3:4"
    assert by_text["::ffff:0:0/96"] == "::ffff:0:0"
    return {
        "description": "IPv6 地址与前缀的写法，消费端规则的 match 与出口策略的目的规则共用。address 为 RFC 5952 规范形式，"
                       "prefixLength 为前缀长度（单地址为 128）。reject 中的写法一律读不出：消费端规则报 EGRESS_RULE_MALFORMED，"
                       "服务端保存策略以 400 拒绝。",
        "accept": accept,
        "reject": reject,
    }


# --------------------------------------------------------------------------
# IPv6 rules on a consumer that carries IPv6
#
# None does yet: every client refuses a well-formed IPv6 rule with EGRESS_RULE_IPV6_UNSUPPORTED, and
# the sections above are what they do. This one pins how IPv6 rules read and match once a consumer
# has an IPv6 data plane, so the three clients agree before that data plane exists.
# --------------------------------------------------------------------------

IPV6_RULES = [
    {"index": 0, "match": "2001:db8::/32", "action": "direct"},
    {"index": 1, "match": "2001:db8:8000::/33", "action": "egress", "egressClientId": 2},
    # Written in upper case with a zero group spelled out: matched by value, not by text.
    {"index": 2, "match": "2001:DB8:1:0::/48", "action": "egress", "egressClientId": 3},
    {"index": 3, "match": "2001:db8:1::50", "action": "block"},
    # An IPv4 rule in the same list: the families never compete.
    {"index": 4, "match": "203.0.113.0/24", "action": "egress", "egressClientId": 2},
    {"index": 5, "match": "2001:db8:2::/48", "action": "egress", "egressClientId": 2},
    {"index": 6, "match": "2001:db8:2::/48", "action": "block"},
    # Refused, with prefixes long enough to win if a matcher only parsed the match.
    {"index": 7, "match": "2001:db8:3::1/48", "action": "block"},
    {"index": 8, "match": "::ffff:cb00:7100/120", "action": "block"},
    {"index": 9, "match": "2001:db8:4::/48", "action": "block", "enabled": False},
    {"index": 10, "match": "2000::/3", "action": "egress", "egressClientId": 3},
]

IPV6_REFUSED = [
    {"index": 7, "code": "EGRESS_RULE_MALFORMED", "reason": "主机位非零"},
    {"index": 8, "code": "EGRESS_RULE_MALFORMED", "reason": "IPv4 映射段，永远不会命中"},
    {"index": 9, "code": "EGRESS_RULE_DISABLED", "reason": "用户停用"},
]


def match_rule_in(rules, destination, ipv6_data_plane):
    """Longest prefix within the destination's family; the earlier rule among equals."""
    if ":" in destination:
        address = ipv6.parse_address(destination)
        family = 6
    else:
        address = int(ipaddress.IPv4Address(destination))
        family = 4
    best, best_length = None, -1
    for rule in rules:
        if validate_rule(rule, ipv6_data_plane) is not None:
            continue
        rule_family, network, length = parse_rule_match(rule["match"].strip())
        if rule_family != family:
            continue
        width = 128 if family == 6 else 32
        if network >> (width - length) != address >> (width - length):
            continue
        if length > best_length:
            best, best_length = rule, length
    if best is None:
        return {"action": "direct", "matchedRuleIndex": None, "reason": "default"}
    result = {"action": best["action"], "matchedRuleIndex": best["index"], "reason": "matched"}
    if best["action"] == "egress":
        result["egressClientId"] = best["egressClientId"]
    return result


IPV6_CASES = [
    ("longest-prefix-beats-order", "2001:db8:8000::1", "更长的 /33 胜出，尽管 /32 排在前面"),
    ("shorter-prefix-when-no-longer-match", "2001:db8::1", "不在 /33 内，落到 /32 的 direct"),
    ("host-route-beats-covering-rule", "2001:db8:1::50", "/128 胜过覆盖它的 /48"),
    ("rule-matches-by-value-not-spelling", "2001:db8:1::51", "规则写作 2001:DB8:1:0::/48，按数值与目的地址比较"),
    ("destination-spelling-is-read-by-value", "2001:0DB8:0001:0000:0000:0000:0000:0050", "目的地址的写法同样按数值读"),
    ("equal-prefix-first-wins", "2001:db8:2::9", "前缀长度相同时先匹配者胜"),
    ("refused-host-bits-does-not-steer", "2001:db8:3::1", "覆盖它的 /48 因主机位非零被拒，落回 /32"),
    ("disabled-rule-does-not-steer", "2001:db8:4::1", "覆盖它的 /48 已停用，落回 /32"),
    ("broad-rule-for-other-global-addresses", "2001:db9::1", "落在 2000::/3 内"),
    ("unmatched-falls-through-to-direct", "fd00::1", "不在任何规则内，本地直连"),
    ("mapped-destination-is-not-an-ipv4-destination", "::ffff:cb00:7109",
     "IPv4 映射写法的目的地址按 IPv6 读，IPv4 规则 203.0.113.0/24 不覆盖它；线上的 IPv4 包按 IPv4 规则走"),
    ("ipv4-destination-ignores-ipv6-rules", "203.0.113.9", "IPv4 目的只看 IPv4 规则，两族规则从不竞争"),
]


# Validation cases that only mean something on a consumer that carries IPv6: the same rule is in force
# there and refused with EGRESS_RULE_IPV6_UNSUPPORTED everywhere else.
IPV6_ONLY_VALIDATION = [
    {"name": "ipv6-in-force", "rule": {"match": "2001:db8::/32", "action": "egress", "egressClientId": 2}},
    {"name": "ipv6-direct-in-force", "rule": {"match": "2001:db8::1", "action": "direct"}},
]


def ipv6_section():
    refused = {entry["index"]: entry["code"] for entry in IPV6_REFUSED}
    for rule in IPV6_RULES:
        assert validate_rule(rule, True) == refused.get(rule["index"]), f"ipv6 rule {rule['index']}"
    cases = []
    without = []
    for name, destination, description in IPV6_CASES:
        cases.append({"name": name, "destination": destination, "description": description,
                      "expect": match_rule_in(IPV6_RULES, destination, True)})
        without.append({"destination": destination, "expect": match_rule_in(IPV6_RULES, destination, False)})
    by_name = {case["name"]: case["expect"] for case in cases}
    assert by_name["longest-prefix-beats-order"]["matchedRuleIndex"] == 1
    assert by_name["refused-host-bits-does-not-steer"]["matchedRuleIndex"] == 0
    assert by_name["mapped-destination-is-not-an-ipv4-destination"]["matchedRuleIndex"] is None
    assert by_name["ipv4-destination-ignores-ipv6-rules"]["matchedRuleIndex"] == 4
    validation = []
    for case in CONFIG_REJECT + IPV6_ONLY_VALIDATION:
        if ":" not in (case["rule"].get("match") or ""):
            continue
        validation.append({"name": case["name"], "rule": case["rule"], "code": validate_rule(case["rule"], True)})
    return {
        "description": "有 IPv6 数据面的消费端如何校验与匹配 IPv6 规则。三个客户端目前都没有 IPv6 数据面，"
                       "按上面各节的结果执行（合法的 IPv6 规则报 EGRESS_RULE_IPV6_UNSUPPORTED，不参与匹配）；"
                       "本节钉住数据面交付之后的语义，供实现在测试里以「承载 IPv6」运行。code 为 null 即生效。",
        "notes": [
            "地址族分开匹配：IPv4 目的只看 IPv4 规则，IPv6 目的只看 IPv6 规则；族内最长前缀优先，等长先配置者胜。两族规则从不竞争，也不与域名规则竞争（fake-IP 池是 IPv4）。",
            "规则与目的地址都按数值比较，写法（大小写、前导零、:: 的位置）不影响结果。",
            "IPv6 规则不与 Peer Mesh 网段或 fake-IP 池比较重叠：两者都是 IPv4。",
            "校验失败与停用的规则同样不参与匹配。",
        ],
        "ipv6DataPlane": True,
        "rules": IPV6_RULES,
        "refusedRules": IPV6_REFUSED,
        "cases": cases,
        "configValidation": validation,
        "withoutIpv6DataPlane": {
            "description": "同一份规则在没有 IPv6 数据面的消费端（三个客户端目前都是）：IPv6 规则全部不生效，"
                           "IPv6 目的地址一律未匹配；IPv4 规则照常。code 为 null 即生效。",
            "ruleCodes": [{"index": rule["index"], "code": validate_rule(rule, False)} for rule in IPV6_RULES],
            "cases": without,
        },
    }


rules_vector = {
    "name": "peer-egress-rules-v1",
    "version": 1,
    "notes": [
        "消费端规则只有目的地址一种匹配维度。消费端靠安装路由把流量引入 TUN，而路由只能按目的地址选择；端口和协议限制属于出口策略，在出口侧建流时执行。",
        "优先级：前缀更长者优先；前缀长度相同时按用户配置顺序，先匹配者胜。",
        "默认动作：未匹配即本地直连。这是路由表本身的结果——没有安装路由的目标根本不会进入 TUN，实现不得再加一条兜底放行分支。",
        "规则变更对已建流：已建流不受影响，除非规则从 allow 变为 deny 或不再匹配，此时立即断开并向出口发送 flow-purge 控制消息。",
        "meshCidr 取默认 100.96.0.0/11；部署使用其它网段时按实际值判定重叠。",
        "校验失败的规则不参与匹配，实现必须在匹配前跳过它们。否则一条被拒的长前缀规则仍会压过合法的短前缀规则，运维读到的「已拒绝」与流量实际走向不符。",
        "egressClientId 必须是正整数：缺失、0 与负数都返回 EGRESS_RULE_MISSING_TARGET。字段在场不等于字段有效。",
        "enabled 缺省为 true；显式 false 的规则返回 EGRESS_RULE_DISABLED，排在所有校验之前。它与被拒的规则一样不参与匹配、不安装路由，但它是用户的选择而不是配置错误，config validate 不为它告警。",
    ],
    "meshCidr": "100.96.0.0/11",
    "rules": RULES,
    "refusedRules": REFUSED_RULES,
    "cases": rule_cases,
    "configValidation": CONFIG_REJECT,
    "consumerDisabled": CONSUMER_DISABLED,
    "ipv6Prefixes": ipv6_prefix_cases(),
    "ipv6": ipv6_section(),
}

# --------------------------------------------------------------------------
# Egress-side authorization
# --------------------------------------------------------------------------

FORCED_DENY = [
    "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    "255.255.255.255/32", "100.96.0.0/11",
]
CLOUD_METADATA = ["169.254.169.254/32", "100.100.100.200/32"]
LAN_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"]

POLICY = {
    "egressClientId": 2,
    "enabled": True,
    "allowedConsumerClientIds": [1, 5],
    "scope": "PUBLIC",
    "destinationRules": [
        {"cidr": "203.0.113.0/24", "protocols": ["tcp"], "portRanges": [[80, 80], [443, 443]]},
        {"cidr": "198.51.100.0/24", "protocols": ["udp"], "portRanges": [[53, 53]]},
        {"cidr": "0.0.0.0/0", "protocols": ["tcp"], "portRanges": [[443, 443]]},
    ],
    "limits": {"maxConcurrentFlows": 256, "maxFlowsPerConsumer": 64, "idleTimeoutSeconds": 60},
}

EVALUATION_ORDER = [
    "hop", "enabled", "peerAcl", "consumer", "forcedDeny", "scope",
    "destination", "protocol", "port", "limits",
]


def in_any(addr, cidrs):
    a = ipaddress.IPv4Address(addr)
    return any(a in ipaddress.IPv4Network(c) for c in cidrs)


def classify_scope(addr):
    return "LAN" if in_any(addr, LAN_RANGES) else "PUBLIC"


def evaluate(req, policy=POLICY, peer_acl_allows=True):
    if req.get("hop"):
        return {"allowed": False, "code": "EGRESS_HOP_NOT_ALLOWED"}
    if not policy["enabled"]:
        return {"allowed": False, "code": "EGRESS_DISABLED"}
    if not peer_acl_allows:
        return {"allowed": False, "code": "EGRESS_PEER_ACL_DENIED"}
    if req["consumerClientId"] not in policy["allowedConsumerClientIds"]:
        return {"allowed": False, "code": "EGRESS_CONSUMER_DENIED"}
    dst = req["destinationIp"]
    try:
        # Strict on purpose, like every runtime: a leading-zero octet or a short address is refused
        # rather than reinterpreted. ipaddress rejects both, so this mirrors them.
        ipaddress.IPv4Address(dst)
    except ipaddress.AddressValueError:
        return {"allowed": False, "code": "EGRESS_DEST_DENIED"}
    if in_any(dst, FORCED_DENY) or in_any(dst, CLOUD_METADATA) or in_any(dst, req.get("localInterfaceCidrs", [])):
        return {"allowed": False, "code": "EGRESS_FORBIDDEN_DESTINATION"}
    if classify_scope(dst) != policy["scope"]:
        return {"allowed": False, "code": "EGRESS_SCOPE_DENIED"}
    address_matches = [r for r in policy["destinationRules"]
                       if ipaddress.IPv4Address(dst) in ipaddress.IPv4Network(r["cidr"])]
    if not address_matches:
        return {"allowed": False, "code": "EGRESS_DEST_DENIED"}
    protocol_matches = [r for r in address_matches if req["protocol"] in r["protocols"]]
    if not protocol_matches:
        return {"allowed": False, "code": "EGRESS_PROTOCOL_DENIED"}
    port = req["destinationPort"]
    if not any(lo <= port <= hi for r in protocol_matches for lo, hi in r["portRanges"]):
        return {"allowed": False, "code": "EGRESS_PORT_DENIED"}
    if req.get("activeFlowsForConsumer", 0) >= policy["limits"]["maxFlowsPerConsumer"]:
        return {"allowed": False, "code": "EGRESS_LIMIT_EXCEEDED"}
    if req.get("activeFlowsTotal", 0) >= policy["limits"]["maxConcurrentFlows"]:
        return {"allowed": False, "code": "EGRESS_LIMIT_EXCEEDED"}
    return {"allowed": True, "code": "EGRESS_ALLOWED"}


def build_cross_language_cases():
    """Exhaustive boundary sweep, expectations computed by the reference evaluate() above.

    The hand-written cases document intent; these exist to catch a runtime that agrees on the
    documented examples but diverges one address or one port away from a boundary. Every case runs
    against the same POLICY, so a disagreement between implementations is a disagreement about the
    rules rather than about the fixture.
    """
    cases = []
    seen = set()

    def add(name, request):
        req = dict(request)
        req.setdefault("consumerClientId", 1)
        req.setdefault("protocol", "tcp")
        req.setdefault("destinationPort", 443)
        key = json.dumps(req, sort_keys=True)
        if key in seen:
            return
        seen.add(key)
        cases.append({"name": name, "request": req, "expect": evaluate(req)})

    def edges(cidr):
        net = ipaddress.IPv4Network(cidr)
        out = [net.network_address, net.broadcast_address]
        if net.num_addresses > 2:
            out.append(net.network_address + 1)
            out.append(net.broadcast_address - 1)
        if int(net.network_address) > 0:
            out.append(net.network_address - 1)
        if int(net.broadcast_address) < 0xFFFFFFFF:
            out.append(net.broadcast_address + 1)
        return [str(a) for a in out]

    # Destination rule boundaries, each swept across both protocols the policy mentions.
    for rule in POLICY["destinationRules"]:
        for address in edges(rule["cidr"]):
            for protocol in ("tcp", "udp"):
                add(f"rule-{rule['cidr'].replace('/', '_')}-{address}-{protocol}",
                    {"destinationIp": address, "protocol": protocol})

    # Port boundaries: one below, both ends, one above, for every declared range.
    for rule in POLICY["destinationRules"]:
        address = str(ipaddress.IPv4Network(rule["cidr"]).network_address + 1)
        for low, high in rule["portRanges"]:
            for port in {low - 1, low, high, high + 1}:
                if not 0 <= port <= 65535:
                    continue
                for protocol in ("tcp", "udp"):
                    add(f"port-{rule['cidr'].replace('/', '_')}-{port}-{protocol}",
                        {"destinationIp": address, "destinationPort": port, "protocol": protocol})

    # Forced-deny and metadata ranges must lose to nothing, including the broad 0.0.0.0/0 rule.
    for cidr in FORCED_DENY + CLOUD_METADATA:
        for address in edges(cidr):
            add(f"forced-{cidr.replace('/', '_')}-{address}", {"destinationIp": address})

    # LAN ranges under a PUBLIC policy: scope is decided before any destination rule.
    for cidr in LAN_RANGES:
        for address in edges(cidr):
            add(f"lan-{cidr.replace('/', '_')}-{address}", {"destinationIp": address})

    # A protocol the policy never mentions.
    for address in ("203.0.113.10", "198.51.100.20", "192.0.2.10"):
        add(f"protocol-icmp-{address}", {"destinationIp": address, "protocol": "icmp"})

    # Consumer allowlist membership, including the second permitted id.
    for consumer in (0, 1, 2, 5, 9):
        add(f"consumer-{consumer}", {"consumerClientId": consumer, "destinationIp": "203.0.113.10"})

    # hop wins over everything, even an otherwise perfect request.
    add("hop-over-an-allowed-request", {"destinationIp": "203.0.113.10", "hop": True})
    add("hop-over-a-denied-request",
        {"destinationIp": "127.0.0.1", "hop": True, "consumerClientId": 9})

    # Limit boundaries: at the cap is refused, one below is not.
    limits = POLICY["limits"]
    for active in (limits["maxFlowsPerConsumer"] - 1, limits["maxFlowsPerConsumer"]):
        add(f"per-consumer-flows-{active}",
            {"destinationIp": "203.0.113.10", "activeFlowsForConsumer": active})
    for total in (limits["maxConcurrentFlows"] - 1, limits["maxConcurrentFlows"]):
        add(f"total-flows-{total}", {"destinationIp": "203.0.113.10", "activeFlowsTotal": total})

    # A local interface range is a per-request extension of the forced-deny list.
    add("local-interface-hit",
        {"destinationIp": "203.0.113.10", "localInterfaceCidrs": ["203.0.113.0/24"]})
    add("local-interface-miss",
        {"destinationIp": "203.0.113.10", "localInterfaceCidrs": ["198.18.0.0/15"]})

    # Malformed destinations are refused rather than parsed loosely.
    for address in ("010.1.1.1", "1.2.3", "1.2.3.256", "", "2001:db8::1"):
        add(f"malformed-{address or 'empty'}", {"destinationIp": address})

    return cases


AUTHZ_CASES = [
    ({"consumerClientId": 1, "destinationIp": "203.0.113.10", "destinationPort": 443, "protocol": "tcp"},
     {}, "允许：消费端在白名单内，目标、协议和端口都命中出口策略"),
    ({"consumerClientId": 1, "destinationIp": "203.0.113.10", "destinationPort": 22, "protocol": "tcp"},
     {}, "端口不在允许区间"),
    ({"consumerClientId": 1, "destinationIp": "203.0.113.10", "destinationPort": 443, "protocol": "udp"},
     {}, "协议不允许；地址命中但 UDP 未授权"),
    ({"consumerClientId": 9, "destinationIp": "203.0.113.10", "destinationPort": 443, "protocol": "tcp"},
     {}, "消费设备不在出口的允许列表内"),
    ({"consumerClientId": 1, "destinationIp": "198.51.100.20", "destinationPort": 53, "protocol": "udp"},
     {}, "允许：UDP 规则命中"),
    ({"consumerClientId": 1, "destinationIp": "127.0.0.1", "destinationPort": 443, "protocol": "tcp"},
     {}, "回环属于强制拒绝清单。注意策略里有 0.0.0.0/0 的 tcp/443 规则，强制清单仍然胜出"),
    ({"consumerClientId": 1, "destinationIp": "169.254.169.254", "destinationPort": 443, "protocol": "tcp"},
     {}, "云元数据端点。同样被宽泛的 0.0.0.0/0 规则覆盖，但强制清单不受其影响"),
    ({"consumerClientId": 1, "destinationIp": "169.254.10.5", "destinationPort": 443, "protocol": "tcp"},
     {}, "链路本地"),
    ({"consumerClientId": 1, "destinationIp": "224.0.0.1", "destinationPort": 443, "protocol": "tcp"},
     {}, "组播"),
    ({"consumerClientId": 1, "destinationIp": "255.255.255.255", "destinationPort": 443, "protocol": "tcp"},
     {}, "广播"),
    ({"consumerClientId": 1, "destinationIp": "100.96.0.7", "destinationPort": 443, "protocol": "tcp"},
     {}, "Peer Mesh 虚拟网段，防止出口流量绕回组网自身"),
    ({"consumerClientId": 1, "destinationIp": "10.7.0.9", "destinationPort": 443, "protocol": "tcp",
      "localInterfaceCidrs": ["10.7.0.0/24"]},
     {}, "落在出口本机某个接口网段内。这是防回环规则的延伸；二期引入 fake-IP 后，出口本机的池段同样加入此清单"),
    ({"consumerClientId": 1, "destinationIp": "192.168.1.10", "destinationPort": 443, "protocol": "tcp"},
     {}, "目标属于 LAN，但策略只授权 PUBLIC。公网访问与对端局域网访问分开授权，互不隐含"),
    ({"consumerClientId": 1, "destinationIp": "192.0.2.10", "destinationPort": 80, "protocol": "tcp"},
     {}, "地址只被宽泛的 0.0.0.0/0 规则覆盖，而该规则仅开放 443，因此在端口一步被拒。判定按固定顺序执行，错误码必须是 PORT 而不是 DEST"),
    ({"consumerClientId": 1, "destinationIp": "203.0.113.10", "destinationPort": 443, "protocol": "tcp",
      "hop": True},
     {}, "已带 hop 标记，来自另一个出口；不支持多跳出口链"),
    ({"consumerClientId": 1, "destinationIp": "203.0.113.10", "destinationPort": 443, "protocol": "tcp",
      "activeFlowsForConsumer": 64},
     {}, "单消费端并发上限已满"),
]

authz_cases = []
for req, opts, description in AUTHZ_CASES:
    expect = evaluate(req, **opts)
    authz_cases.append({
        "name": f"{req['protocol']}-{req['destinationIp']}-{req['destinationPort']}"
                + ("-hop" if req.get("hop") else "")
                + ("-at-limit" if req.get("activeFlowsForConsumer") else "")
                + ("-consumer9" if req["consumerClientId"] == 9 else ""),
        "request": req,
        "description": description,
        "expect": expect,
    })

disabled_policy = dict(POLICY, enabled=False)
empty_policy = dict(POLICY, destinationRules=[])
lan_policy = dict(POLICY, scope="LAN")

special_cases = [
    {
        "name": "egress-disabled",
        "policyOverride": {"enabled": False},
        "request": {"consumerClientId": 1, "destinationIp": "203.0.113.10", "destinationPort": 443, "protocol": "tcp"},
        "description": "出口总开关关闭，默认即为关闭状态",
        "expect": evaluate({"consumerClientId": 1, "destinationIp": "203.0.113.10", "destinationPort": 443, "protocol": "tcp"}, policy=disabled_policy),
    },
    {
        "name": "empty-destination-rules-deny-all",
        "policyOverride": {"destinationRules": []},
        "request": {"consumerClientId": 1, "destinationIp": "203.0.113.10", "destinationPort": 443, "protocol": "tcp"},
        "description": "destinationRules 为空即全拒绝；不存在「未配置即放行」",
        "expect": evaluate({"consumerClientId": 1, "destinationIp": "203.0.113.10", "destinationPort": 443, "protocol": "tcp"}, policy=empty_policy),
    },
    {
        "name": "peer-acl-denies",
        "peerAclAllows": False,
        "request": {"consumerClientId": 1, "destinationIp": "203.0.113.10", "destinationPort": 443, "protocol": "tcp"},
        "description": "基础 Peer ACL 不允许时直接拒绝。allowed = 基础 Peer ACL ∩ 出口策略，基础组网授权不自动等于出口授权",
        "expect": evaluate({"consumerClientId": 1, "destinationIp": "203.0.113.10", "destinationPort": 443, "protocol": "tcp"}, peer_acl_allows=False),
    },
    {
        "name": "address-not-covered",
        "policyOverride": {"destinationRules": POLICY["destinationRules"][:2]},
        "request": {"consumerClientId": 1, "destinationIp": "192.0.2.10", "destinationPort": 443, "protocol": "tcp"},
        "description": "去掉宽泛的 0.0.0.0/0 规则后，地址不再被任何网段覆盖，在目标一步被拒",
        "expect": evaluate(
            {"consumerClientId": 1, "destinationIp": "192.0.2.10", "destinationPort": 443, "protocol": "tcp"},
            policy=dict(POLICY, destinationRules=POLICY["destinationRules"][:2]),
        ),
    },
    {
        "name": "lan-scope-allows-private-target",
        "policyOverride": {"scope": "LAN", "destinationRules": [{"cidr": "192.168.1.0/24", "protocols": ["tcp"], "portRanges": [[443, 443]]}]},
        "request": {"consumerClientId": 1, "destinationIp": "192.168.1.10", "destinationPort": 443, "protocol": "tcp"},
        "description": "显式授予 LAN scope 后同一目标才被允许",
        "expect": evaluate(
            {"consumerClientId": 1, "destinationIp": "192.168.1.10", "destinationPort": 443, "protocol": "tcp"},
            policy=dict(POLICY, scope="LAN", destinationRules=[{"cidr": "192.168.1.0/24", "protocols": ["tcp"], "portRanges": [[443, 443]]}]),
        ),
    },
]

authz_vector = {
    "name": "peer-egress-authz-v1",
    "version": 1,
    "notes": [
        "出口端在实际 connect() 前必须完整跑一遍本判定，即使服务端下发时已经取过交集。目录不可见与数据面不可达必须同时成立。",
        "判定按固定顺序执行，这样各实现返回的错误码可以逐条比对，而不只是 allow/deny 一致。",
        "强制拒绝清单不受任何宽泛公网规则影响。本文件的策略故意包含 0.0.0.0/0 的 tcp/443 规则，用来证明回环、云元数据等目标仍然被拒。",
        "scope 分类：LAN 为 RFC1918 与 RFC6598 共享地址空间；其余可路由地址为 PUBLIC。",
    ],
    "evaluationOrder": EVALUATION_ORDER,
    "forcedDenyCidrs": FORCED_DENY,
    "cloudMetadataCidrs": CLOUD_METADATA,
    "lanCidrs": LAN_RANGES,
    "additionalForcedDeny": [
        "本部署的控制连接、STUN 与 TURN 端点地址",
        "出口本机任何 TUN 或虚拟接口的网段（由 request.localInterfaceCidrs 表示）",
    ],
    "policy": POLICY,
    "cases": authz_cases,
    "policyVariantCases": special_cases,
}

authz_vector["crossLanguageCases"] = build_cross_language_cases()

# --------------------------------------------------------------------------
# Egress-side authorization of IPv6 destinations
#
# The same order and codes as for IPv4, with the IPv6 counterparts of the forced-deny list and of
# the LAN scope. Destination rules of one family never cover an address of the other: 0.0.0.0/0 is
# not every IPv6 address and ::/0 is not every IPv4 one. The IPv4 entries above are unchanged.
# --------------------------------------------------------------------------

IPV6_FORCED_DENY = [
    "::/128",
    "::1/128",
    # A socket connected to an IPv4-mapped address reaches the IPv4 address; letting it through
    # would bypass every IPv4 entry above.
    "::ffff:0:0/96",
    # Prefixes that embed an IPv4 address the network translates or tunnels to: through a NAT64
    # gateway or a 6to4 relay they reach any IPv4 address, metadata and private ranges included.
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "2002::/16",
    "fe80::/10",
    "fec0::/10",
    "ff00::/8",
]
IPV6_CLOUD_METADATA = ["fd00:ec2::254/128"]
IPV6_LAN = ["fc00::/7"]


def address_of(text):
    """(family, value) for a destination as the egress reads it, or None."""
    if ":" in text:
        value = ipv6.parse_address(text)
        return None if value is None else (6, value)
    try:
        return 4, int(ipaddress.IPv4Address(text))
    except ipaddress.AddressValueError:
        return None


def covered(address, cidrs):
    """Whether any prefix of the address's family in cidrs contains it; the other family's are skipped."""
    family, value = address
    for text in cidrs:
        if family == 6:
            parsed = ipv6.parse_prefix(text.strip()) if ":" in text else None
            if parsed is not None and ipv6.contains(parsed[0], parsed[1], value):
                return True
        elif ":" not in text and ipaddress.IPv4Address(value) in ipaddress.IPv4Network(text):
            return True
    return False


def evaluate_any(req, policy, peer_acl_allows=True):
    """evaluate() for either family. Gives evaluate()'s answer for every IPv4 request."""
    if req.get("hop"):
        return {"allowed": False, "code": "EGRESS_HOP_NOT_ALLOWED"}
    if not policy["enabled"]:
        return {"allowed": False, "code": "EGRESS_DISABLED"}
    if not peer_acl_allows:
        return {"allowed": False, "code": "EGRESS_PEER_ACL_DENIED"}
    if req["consumerClientId"] not in policy["allowedConsumerClientIds"]:
        return {"allowed": False, "code": "EGRESS_CONSUMER_DENIED"}
    address = address_of(req["destinationIp"])
    if address is None:
        return {"allowed": False, "code": "EGRESS_DEST_DENIED"}
    denied = FORCED_DENY + CLOUD_METADATA + IPV6_FORCED_DENY + IPV6_CLOUD_METADATA + req.get("localInterfaceCidrs", [])
    if covered(address, denied):
        return {"allowed": False, "code": "EGRESS_FORBIDDEN_DESTINATION"}
    scope = "LAN" if covered(address, LAN_RANGES + IPV6_LAN) else "PUBLIC"
    if scope != policy["scope"]:
        return {"allowed": False, "code": "EGRESS_SCOPE_DENIED"}
    address_matches = [r for r in policy["destinationRules"] if covered(address, [r["cidr"]])]
    if not address_matches:
        return {"allowed": False, "code": "EGRESS_DEST_DENIED"}
    protocol_matches = [r for r in address_matches if req["protocol"] in r["protocols"]]
    if not protocol_matches:
        return {"allowed": False, "code": "EGRESS_PROTOCOL_DENIED"}
    port = req["destinationPort"]
    if not any(lo <= port <= hi for r in protocol_matches for lo, hi in r["portRanges"]):
        return {"allowed": False, "code": "EGRESS_PORT_DENIED"}
    if req.get("activeFlowsForConsumer", 0) >= policy["limits"]["maxFlowsPerConsumer"]:
        return {"allowed": False, "code": "EGRESS_LIMIT_EXCEEDED"}
    if req.get("activeFlowsTotal", 0) >= policy["limits"]["maxConcurrentFlows"]:
        return {"allowed": False, "code": "EGRESS_LIMIT_EXCEEDED"}
    return {"allowed": True, "code": "EGRESS_ALLOWED"}


# The generalisation must not move a single IPv4 answer.
for case in authz_vector["cases"] + authz_vector["crossLanguageCases"]:
    assert evaluate_any(case["request"], POLICY) == case["expect"], case["name"]

IPV6_POLICY = dict(POLICY, destinationRules=[
    {"cidr": "2001:db8:10::/48", "protocols": ["tcp"], "portRanges": [[80, 80], [443, 443]]},
    {"cidr": "2001:db8:20::/48", "protocols": ["udp"], "portRanges": [[53, 53]]},
    {"cidr": "::/0", "protocols": ["tcp"], "portRanges": [[443, 443]]},
    {"cidr": "203.0.113.0/24", "protocols": ["tcp"], "portRanges": [[22, 22]]},
])

IPV6_AUTHZ_CASES = [
    ("allowed", "2001:db8:10::5", 443, "tcp", {}, "允许：地址、协议与端口都命中 2001:db8:10::/48"),
    ("port-denied", "2001:db8:10::5", 22, "tcp", {}, "/48 只开 80 与 443，::/0 只开 443"),
    ("protocol-denied", "2001:db8:10::5", 443, "udp", {}, "覆盖它的两条规则都只允许 tcp"),
    ("udp-allowed", "2001:db8:20::1", 53, "udp", {}, "允许：UDP 规则命中"),
    ("broad-rule", "2001:db8:99::1", 443, "tcp", {}, "只被宽泛的 ::/0 覆盖"),
    ("read-by-value", "2001:DB8:10:0:0:0:0:5", 443, "tcp", {}, "目的地址按数值读，写法不影响判定"),
    ("loopback", "::1", 443, "tcp", {}, "回环；::/0 也覆盖它，强制清单仍然胜出"),
    ("unspecified", "::", 443, "tcp", {}, "未指定地址"),
    ("mapped-loopback", "::ffff:7f00:1", 443, "tcp", {}, "IPv4 映射的 127.0.0.1，连上去就是 IPv4 回环"),
    ("mapped-public", "::ffff:cb00:710a", 22, "tcp", {},
     "IPv4 映射的 203.0.113.10：即使 IPv4 规则允许它，映射写法也一律拒绝，IPv4 目标只能以 IPv4 授权"),
    ("nat64-metadata", "64:ff9b::a9fe:a9fe", 443, "tcp", {}, "NAT64 前缀嵌着 169.254.169.254，经 NAT64 网关就到了元数据端点"),
    ("nat64-local-use", "64:ff9b:1::a00:1", 443, "tcp", {}, "NAT64 本地前缀，同上"),
    ("six-to-four", "2002:c000:204::1", 443, "tcp", {}, "6to4 嵌着 IPv4 地址"),
    ("link-local", "fe80::1", 443, "tcp", {}, "链路本地"),
    ("site-local", "fec0::1", 443, "tcp", {}, "已废弃的站点本地"),
    ("multicast", "ff02::1", 443, "tcp", {}, "组播"),
    ("cloud-metadata", "fd00:ec2::254", 443, "tcp", {}, "云元数据端点（AWS IMDS 的 IPv6 地址），先于 scope 被拒"),
    ("ula-under-public", "fd12:3456::1", 443, "tcp", {}, "ULA 属于 LAN，策略只授权 PUBLIC"),
    ("local-interface", "2001:db8:30::7", 443, "tcp", {"localInterfaceCidrs": ["2001:db8:30::/64"]},
     "落在出口本机接口的 IPv6 网段内"),
    ("ipv4-not-covered-by-ipv6-default", "192.0.2.10", 443, "tcp", {}, "::/0 不覆盖任何 IPv4 地址，两族规则互不覆盖"),
    ("ipv4-rule-in-mixed-policy", "203.0.113.10", 22, "tcp", {}, "同一份策略里的 IPv4 规则照常生效"),
    ("dotted-tail-is-malformed", "::ffff:192.0.2.1", 443, "tcp", {}, "点分尾的写法读不出，与写错的 IPv4 一样拒绝"),
    ("zone-is-malformed", "fe80::1%eth0", 443, "tcp", {}, "带区域标识的写法读不出"),
]


def ipv6_authz_section():
    cases = []
    for name, destination, port, protocol, extra, description in IPV6_AUTHZ_CASES:
        request = dict({"consumerClientId": 1, "destinationIp": destination, "destinationPort": port,
                        "protocol": protocol}, **extra)
        cases.append({"name": name, "request": request, "description": description,
                      "expect": evaluate_any(request, IPV6_POLICY)})
    by_name = {case["name"]: case["expect"]["code"] for case in cases}
    assert by_name["allowed"] == "EGRESS_ALLOWED"
    assert by_name["mapped-public"] == "EGRESS_FORBIDDEN_DESTINATION"
    assert by_name["ipv4-not-covered-by-ipv6-default"] == "EGRESS_DEST_DENIED"
    assert by_name["ula-under-public"] == "EGRESS_SCOPE_DENIED"
    lan_rules = [{"cidr": "fd00::/8", "protocols": ["tcp"], "portRanges": [[443, 443]]}]
    lan_policy = dict(IPV6_POLICY, scope="LAN", destinationRules=lan_rules)
    variants = []
    for name, destination, description in [
        ("lan-scope-allows-ula", "fd12:3456::1", "显式授予 LAN scope 并覆盖该网段后，ULA 目标才被允许"),
        ("lan-scope-still-refuses-metadata", "fd00:ec2::254", "LAN 策略覆盖了元数据地址，强制清单仍然先拒绝"),
        ("lan-scope-refuses-global", "2001:db8:10::5", "LAN 策略不放行公网 IPv6 地址"),
    ]:
        request = {"consumerClientId": 1, "destinationIp": destination, "destinationPort": 443, "protocol": "tcp"}
        variants.append({"name": name, "policyOverride": {"scope": "LAN", "destinationRules": lan_rules},
                         "request": request, "description": description,
                         "expect": evaluate_any(request, lan_policy)})
    assert [v["expect"]["code"] for v in variants] == [
        "EGRESS_ALLOWED", "EGRESS_FORBIDDEN_DESTINATION", "EGRESS_SCOPE_DENIED"]
    return {
        "description": "IPv6 目的地址的出口授权：判定顺序与错误码同 IPv4，强制拒绝清单与 LAN scope 换成 IPv6 的对应项。"
                       "目的规则只覆盖同一族的地址（0.0.0.0/0 不含任何 IPv6 地址，::/0 不含任何 IPv4 地址）。"
                       "上面各节的 IPv4 清单不变，一个实现两族的清单都要检查。",
        "forcedDenyCidrs": IPV6_FORCED_DENY,
        "cloudMetadataCidrs": IPV6_CLOUD_METADATA,
        "lanCidrs": IPV6_LAN,
        "policy": IPV6_POLICY,
        "cases": cases,
        "policyVariantCases": variants,
    }


authz_vector["ipv6"] = ipv6_authz_section()

for path, payload in [
    ("protocol/test-vectors/peer-egress-rules-v1.json", rules_vector),
    ("protocol/test-vectors/peer-egress-authz-v1.json", authz_vector),
]:
    out = Path(path)
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote", out, out.stat().st_size, "bytes")

print("rule cases:", len(rule_cases), "config rejects:", len(CONFIG_REJECT),
      "refused rules:", len(REFUSED_RULES))
print("authz cases:", len(authz_cases), "policy variants:", len(special_cases))
print("cross-language cases:", len(authz_vector["crossLanguageCases"]))
allowed = sum(1 for c in authz_cases if c["expect"]["allowed"])
print("authz allow/deny:", allowed, "/", len(authz_cases) - allowed)
for c in authz_cases:
    print("  ", c["name"], "->", c["expect"]["code"])
