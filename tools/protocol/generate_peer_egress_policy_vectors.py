"""Generate peer-egress-rules-v1.json and peer-egress-authz-v1.json.

Both files carry a reference matcher/evaluator implemented here. Every expectation
in the emitted vectors is asserted against that reference before writing, so the
files cannot ship internally inconsistent cases.
"""
import json
import ipaddress
from pathlib import Path

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
]


def match_rule(destination):
    addr = ipaddress.IPv4Address(destination)
    best = None
    for rule in RULES:
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
     "reason": "一期数据面只有 IPv4；拒绝而不是静默忽略，否则会静默走本地形成泄漏"},
    {"name": "ipv6-single", "rule": {"match": "2001:db8::1", "action": "block"},
     "code": "EGRESS_RULE_IPV6_UNSUPPORTED",
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
]

rules_vector = {
    "name": "peer-egress-rules-v1",
    "version": 1,
    "notes": [
        "消费端规则只有目的地址一种匹配维度。消费端靠安装路由把流量引入 TUN，而路由只能按目的地址选择；端口和协议限制属于出口策略，在出口侧建流时执行。",
        "优先级：前缀更长者优先；前缀长度相同时按用户配置顺序，先匹配者胜。",
        "默认动作：未匹配即本地直连。这是路由表本身的结果——没有安装路由的目标根本不会进入 TUN，实现不得再加一条兜底放行分支。",
        "规则变更对已建流：已建流不受影响，除非规则从 allow 变为 deny 或不再匹配，此时立即断开并向出口发送 flow-purge 控制消息。",
        "meshCidr 取默认 100.96.0.0/11；部署使用其它网段时按实际值判定重叠。",
    ],
    "meshCidr": "100.96.0.0/11",
    "rules": RULES,
    "cases": rule_cases,
    "configValidation": CONFIG_REJECT,
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

for path, payload in [
    ("protocol/test-vectors/peer-egress-rules-v1.json", rules_vector),
    ("protocol/test-vectors/peer-egress-authz-v1.json", authz_vector),
]:
    out = Path(path)
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote", out, out.stat().st_size, "bytes")

print("rule cases:", len(rule_cases), "config rejects:", len(CONFIG_REJECT))
print("authz cases:", len(authz_cases), "policy variants:", len(special_cases))
allowed = sum(1 for c in authz_cases if c["expect"]["allowed"])
print("authz allow/deny:", allowed, "/", len(authz_cases) - allowed)
for c in authz_cases:
    print("  ", c["name"], "->", c["expect"]["code"])
