"""Generate peer-egress-control-v1.json.

The `egress-config` push is produced by three server implementations and read by three clients.
What a client makes of it is therefore a contract, and the parts most likely to drift are the ones
a JSON library decides rather than the protocol: what an absent field becomes, and whether a value
is normalised before it is compared.

The expectations come from a reference decoder written here rather than recorded from any
implementation. Two cases exist because the C server really emits them: a disabled push carries
neither `scope` nor `limits`, and every enabled push carries both.
"""
import json
from pathlib import Path

VECTORS = Path("protocol/test-vectors")

DEFAULT_MAX_CONCURRENT_FLOWS = 256
DEFAULT_MAX_FLOWS_PER_CONSUMER = 64
DEFAULT_IDLE_TIMEOUT_SECONDS = 60


def decode(text):
    """The reference decoder: message text to the policy a client enforces, or None."""
    try:
        message = json.loads(text)
    except ValueError:
        return None
    if not isinstance(message, dict) or message.get("type") != "egress-config":
        return None

    limits = message.get("limits")
    if not isinstance(limits, dict):
        limits = {}

    rules = []
    for raw in message.get("destinationRules") or []:
        if not isinstance(raw, dict):
            continue
        rules.append({
            "cidr": raw.get("cidr") or "",
            "protocols": list(raw.get("protocols") or []),
            "portRanges": [list(pair) for pair in (raw.get("portRanges") or [])],
        })

    return {
        "revision": int(message.get("revision") or 0),
        "policy": {
            "enabled": bool(message.get("enabled")),
            # Uppercased and trimmed before it is compared. The judgment layer tests the scope for
            # equality against a value it computes itself, so a push that said "public" would be
            # refused by an implementation that compared the raw string.
            "scope": str(message.get("scope") or "").strip().upper(),
            "allowedConsumerClientIds": [int(value) for value in
                                         (message.get("allowedConsumerClientIds") or [])],
            "destinationRules": rules,
            "limits": {
                "maxConcurrentFlows": int(limits.get("maxConcurrentFlows") or 0),
                "maxFlowsPerConsumer": int(limits.get("maxFlowsPerConsumer") or 0),
                "idleTimeoutSeconds": int(limits.get("idleTimeoutSeconds") or 0),
            },
        },
    }


ACCEPT = [
    (
        "full-push",
        {
            "type": "egress-config",
            "enabled": True,
            "revision": 7,
            "scope": "PUBLIC",
            "allowedConsumerClientIds": [1, 5],
            "destinationRules": [
                {"cidr": "203.0.113.0/24", "protocols": ["tcp"], "portRanges": [[80, 80], [443, 443]]}
            ],
            "limits": {"maxConcurrentFlows": 256, "maxFlowsPerConsumer": 64, "idleTimeoutSeconds": 60},
        },
        "规范里的例子，字段齐全",
    ),
    (
        "disabled-carries-neither-scope-nor-limits",
        {
            "type": "egress-config",
            "revision": 8,
            "enabled": False,
            "allowedConsumerClientIds": [],
            "destinationRules": [],
        },
        "C server 关闭出口时逐字发出的形状。缺失的 limits 不能让解码失败，"
        "也不能变成一份看起来配置过的策略",
    ),
    (
        "scope-is-uppercased",
        {
            "type": "egress-config", "enabled": True, "revision": 9, "scope": "public",
            "allowedConsumerClientIds": [1], "destinationRules": [],
            "limits": {"maxConcurrentFlows": 8, "maxFlowsPerConsumer": 4, "idleTimeoutSeconds": 30},
        },
        "判定层拿自己算出的 scope 去做相等比较，所以小写的推送必须先归一化，否则会被判成不匹配",
    ),
    (
        "scope-is-trimmed",
        {
            "type": "egress-config", "enabled": True, "revision": 10, "scope": "  LAN  ",
            "allowedConsumerClientIds": [1], "destinationRules": [],
            "limits": {"maxConcurrentFlows": 8, "maxFlowsPerConsumer": 4, "idleTimeoutSeconds": 30},
        },
        "同上，两侧空白同样要去掉",
    ),
    (
        "enabled-without-scope-denies",
        {
            "type": "egress-config", "enabled": True, "revision": 11,
            "allowedConsumerClientIds": [1],
            "destinationRules": [{"cidr": "203.0.113.0/24", "protocols": ["tcp"], "portRanges": [[443, 443]]}],
            "limits": {"maxConcurrentFlows": 8, "maxFlowsPerConsumer": 4, "idleTimeoutSeconds": 30},
        },
        "scope 是授权维度，缺省必须落到拒绝而不是 PUBLIC。"
        "把缺失的授权字段默认成许可值，正是「未配置即放行」——本功能明确不接受这一条",
    ),
    (
        "unknown-fields-are-ignored",
        {
            "type": "egress-config", "enabled": True, "revision": 12, "scope": "PUBLIC",
            "allowedConsumerClientIds": [1], "destinationRules": [],
            "limits": {"maxConcurrentFlows": 8, "maxFlowsPerConsumer": 4, "idleTimeoutSeconds": 30},
            "createdAtMillis": 1800000000000,
            "somethingFromALaterVersion": {"nested": True},
        },
        "服务端会带上 createdAtMillis 等字段。旧客户端必须忽略不认识的键，而不是拒绝整条消息",
    ),
]

REJECT = [
    ("wrong-type", json.dumps({"type": "egress-catalog", "revision": 1}),
     "类型不对的消息不属于这个解码器。当成 egress-config 读会把一份目录当成策略装上去"),
    ("no-type", json.dumps({"enabled": True, "revision": 1}),
     "没有 type 就没法判断这是什么，不能猜"),
    ("not-json", "{ this is not json",
     "半条消息、被截断的消息，都从这里退出"),
    ("not-an-object", json.dumps([1, 2, 3]),
     "JSON 合法但不是对象，同样不是一条控制消息"),
]

accept_cases = []
for name, message, reason in ACCEPT:
    text = json.dumps(message, ensure_ascii=False)
    decoded = decode(text)
    assert decoded is not None, name
    accept_cases.append({
        "name": name,
        "reason": reason,
        "message": text,
        "expect": decoded,
    })

reject_cases = []
for name, text, reason in REJECT:
    assert decode(text) is None, name
    reject_cases.append({"name": name, "reason": reason, "message": text})

# --------------------------------------------------------------------------
# This deployment's own endpoints.
#
# The forced-deny list has to include the control connection, STUN, TURN and the relay, or a
# consumer could reach the infrastructure through the egress it is only supposed to reach the
# internet through. Three clients holding the same configuration must derive the same list: one that
# missed an endpoint would forward to it while the others refused.
# --------------------------------------------------------------------------


def strip_port(host):
    """Removes a :port suffix, leaving an IPv6 literal in brackets alone."""
    host = (host or "").strip()
    if host.startswith("["):
        return host
    if host.count(":") == 1:
        return host.rsplit(":", 1)[0]
    return host


def is_ipv4_literal(text):
    parts = text.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or (len(part) > 1 and part[0] == "0") or int(part) > 255:
            return False
    return True


def deny_cidrs(base_url, stun_host, turn_host, relay_address):
    """The reference derivation: literal IPv4 endpoints only, each as a /32."""
    hosts = []
    url = (base_url or "").strip()
    if "://" in url:
        authority = url.split("://", 1)[1].split("/", 1)[0]
        # Strip any userinfo, which is not part of the host.
        hosts.append(authority.rsplit("@", 1)[-1])
    for host in (stun_host, turn_host, relay_address):
        hosts.append(host)

    denied = []
    for host in hosts:
        # Only literal addresses. A hostname would have to be resolved here, and a resolution taken
        # at policy time can differ from the one the connect uses, which would make the block look
        # enforced when it is not.
        candidate = strip_port(host)
        if is_ipv4_literal(candidate):
            denied.append(candidate + "/32")
    return denied


ENDPOINT_CASES = [
    ("all-four-literal",
     "https://203.0.113.5:8443", "198.51.100.7:3478", "198.51.100.8:3478", "192.0.2.9:3478",
     "四个端点都是字面地址，全部进入强制拒绝清单"),
    ("hostnames-are-skipped",
     "https://api.example.com", "stun.example.com:3478", "turn.example.com:3478", "",
     "域名不解析。在策略期解析出的地址可能和实际 connect 用的不一样，"
     "那会让这条阻断看起来生效而实际上没有"),
    ("ports-are-optional",
     "https://203.0.113.5", "198.51.100.7", "", "",
     "不带端口的写法同样要认出来"),
    ("empty-configuration",
     "", "", "", "",
     "什么都没配置就没有端点可拒绝，不是错误"),
    ("mixed-literal-and-name",
     "https://203.0.113.5:8443", "stun.example.com:3478", "198.51.100.8:3478", "",
     "字面地址进清单，域名跳过，两者不互相影响"),
    ("ipv6-literal-is-skipped",
     "https://[2001:db8::1]:8443", "", "", "",
     "一期数据面只有 IPv4，IPv6 端点没有可以拒绝的 IPv4 前缀"),
]

endpoint_cases = []
for name, base_url, stun_host, turn_host, relay, reason in ENDPOINT_CASES:
    endpoint_cases.append({
        "name": name,
        "reason": reason,
        "input": {
            "serverBaseUrl": base_url,
            "stunHost": stun_host,
            "turnHost": turn_host,
            "relayAddress": relay,
        },
        "expect": deny_cidrs(base_url, stun_host, turn_host, relay),
    })

vector = {
    "name": "peer-egress-control-v1",
    "version": 1,
    "notes": [
        "egress-config 由三个服务端实现产生、由三个客户端读取，所以「客户端从中读出什么」是一份契约。"
        "最容易漂开的不是字段名，而是 JSON 库替协议做的决定：缺失字段变成什么，以及值在比较之前有没有被归一化。",
        "scope 在比较之前必须去空白并转大写。判定层拿自己算出的 PUBLIC 或 LAN 去做相等比较，"
        "一条写着小写 public 的推送在不归一化的实现里会被判成不匹配，于是整条策略静默失效。",
        "scope 缺失必须落到拒绝。把缺失的授权字段默认成许可值就是「未配置即放行」，"
        "而本功能对 destinationRules 已经明确写了不接受这一条，scope 没有理由例外。",
        "limits 缺失时三个字段都为 0，由使用方按自己的默认值兜底；解码器不替它编造数值。",
        "不认识的键一律忽略。服务端会带上 createdAtMillis，未来还会带别的，"
        "旧客户端拒绝整条消息等于一次协议升级就让所有旧设备停止接受配置。",
        "revision 的单调守卫不在解码器里：它是运行时的状态，解码器对同一条消息必须每次给出相同结果。",
        "本文件的期望值出自 tools/protocol/generate_peer_egress_control_vectors.py 里的独立参考解码器，"
        "不是从任何一个实现录下来的。",
    ],
    "deploymentEndpoints": {
        "description": "本部署自身的端点，进入强制拒绝清单。只收字面 IPv4 地址：域名在策略期解析出的结果"
                       "可能和实际 connect 用的不一样，那会让阻断看起来生效而实际没有。"
                       "三个客户端拿同一份配置必须导出同一份清单，漏掉一个端点的那个会把流量转发过去。",
        "cases": endpoint_cases,
    },
    "egressConfig": {
        "accept": accept_cases,
        "reject": reject_cases,
        "limitDefaults": {
            "maxConcurrentFlows": DEFAULT_MAX_CONCURRENT_FLOWS,
            "maxFlowsPerConsumer": DEFAULT_MAX_FLOWS_PER_CONSUMER,
            "idleTimeoutSeconds": DEFAULT_IDLE_TIMEOUT_SECONDS,
            "description": "limits 缺失或为 0 时使用方各自的兜底值。解码器只报告 0，"
                           "由运行时决定 0 代表「用默认」还是「无限制」。",
        },
    },
}

out = VECTORS / "peer-egress-control-v1.json"
out.write_text(json.dumps(vector, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print("wrote", out, out.stat().st_size, "bytes")
print("egress-config accept:", len(accept_cases), "reject:", len(reject_cases),
      "deployment endpoints:", len(endpoint_cases))
for case in accept_cases:
    print("  ", case["name"], "-> scope=", repr(case["expect"]["policy"]["scope"]),
          "revision=", case["expect"]["revision"])
