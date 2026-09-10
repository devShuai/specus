"""Generate peer-egress-routes-v1.json.

The consumer turns its rule list into the set of routes it wants to own, and three runtimes have
to arrive at the same set: a Java consumer that installed a different prefix than the Go one for
the same configuration would send different traffic through the tunnel while reporting the same
rules.

The expectations here come from a reference planner written in this file rather than recorded from
any implementation, so agreement with it is independent agreement rather than a shared mistake.
The rule validator below is a second statement of the order in protocol/spec/peer-egress.md; it is
checked against every case in peer-egress-rules-v1.json before anything is written, so the two
cannot drift apart quietly.
"""
import ipaddress
import json
from pathlib import Path

VECTORS = Path("protocol/test-vectors")
MESH_CIDR = "100.96.0.0/11"


def validate_rule(rule, mesh_cidr=MESH_CIDR):
    """Returns the failing code, or None. The fixed order from the spec."""
    match = (rule.get("match") or "").strip()
    if not match:
        return "EGRESS_RULE_MALFORMED"
    if ":" in match:
        return "EGRESS_RULE_IPV6_UNSUPPORTED"
    if match.startswith("*") or any(c.isalpha() for c in match):
        return "EGRESS_RULE_DOMAIN_UNSUPPORTED"
    try:
        network = ipaddress.IPv4Network(match)
    except ValueError:
        return "EGRESS_RULE_MALFORMED"
    if network.prefixlen == 0:
        return "EGRESS_RULE_DEFAULT_ROUTE"
    if network.overlaps(ipaddress.IPv4Network(mesh_cidr)):
        return "EGRESS_RULE_MESH_OVERLAP"
    if rule.get("port") is not None:
        return "EGRESS_RULE_PORT_UNSUPPORTED"
    if rule.get("action") not in ("egress", "direct", "block"):
        return "EGRESS_RULE_MALFORMED"
    if rule["action"] == "egress" and int(rule.get("egressClientId") or 0) <= 0:
        return "EGRESS_RULE_MISSING_TARGET"
    return None


# This validator and the one in generate_peer_egress_policy_vectors.py are separate statements of
# the same order. Checking it against the shared vector is what keeps them from drifting apart.
_rules_vector = json.loads((VECTORS / "peer-egress-rules-v1.json").read_text(encoding="utf-8"))
for _case in _rules_vector["configValidation"]:
    _produced = validate_rule(_case["rule"], _rules_vector["meshCidr"])
    assert _produced == _case["code"], _case["name"] + ": route generator says " + str(_produced)


def sort_key(route):
    # Bypass first, so the addresses that keep the tunnel's own transport working are installed
    # before anything is pointed into the tunnel. Then by prefix, for a deterministic journal.
    network = ipaddress.IPv4Network(route["cidr"])
    return (0 if route["kind"] == "bypass" else 1, int(network.network_address), network.prefixlen)


def plan(rules, bypass, mesh_cidr=MESH_CIDR):
    """The reference planner: which routes a rule set and a bypass set need."""
    refused = []
    for index, rule in enumerate(rules):
        code = validate_rule(rule, mesh_cidr)
        if code is not None:
            refused.append({"index": index, "match": rule.get("match", ""), "code": code})
    skip = {entry["index"] for entry in refused}

    seen = set()
    routes = []
    # Bypass first, so a rule naming the same prefix cannot displace one of these.
    for endpoint in bypass:
        try:
            address = ipaddress.IPv4Address((endpoint or "").strip())
        except ValueError:
            continue
        cidr = str(address) + "/32"
        if cidr in seen:
            continue
        seen.add(cidr)
        routes.append({"cidr": cidr, "kind": "bypass", "origin": "bypass"})

    for index, rule in enumerate(rules):
        if index in skip:
            continue
        # A direct rule installs nothing: traffic stays local by having no route, the same
        # mechanism that makes unmatched traffic local. A block rule does install one, because
        # the packet has to be captured before the data plane can drop it.
        if rule.get("action") not in ("egress", "block"):
            continue
        network = ipaddress.IPv4Network((rule.get("match") or "").strip())
        cidr = str(network)
        if cidr in seen:
            # Two rules over one prefix need one route; the engine decides between them per
            # packet, and installing the prefix twice would make removal ambiguous.
            continue
        seen.add(cidr)
        routes.append({"cidr": cidr, "kind": "tun", "origin": "rule:" + rule["match"]})

    routes.sort(key=sort_key)
    return routes, refused


def diff(current, desired):
    """Withdrawals first, so a prefix that changed kind loses its old entry before the new one."""
    desired_by_cidr = {route["cidr"]: route for route in desired}
    current_by_cidr = {route["cidr"]: route for route in current}
    remove = [route for route in current
              if route["cidr"] not in desired_by_cidr
              or desired_by_cidr[route["cidr"]]["kind"] != route["kind"]]
    add = [route for route in desired
           if route["cidr"] not in current_by_cidr
           or current_by_cidr[route["cidr"]]["kind"] != route["kind"]]
    remove.sort(key=sort_key)
    add.sort(key=sort_key)
    return remove, add


PLAN_CASES = [
    {
        "name": "egress-and-block-install-direct-does-not",
        "description": "direct 不装路由：流量靠「没有路由」留在本地，与未匹配流量是同一个机制。"
                       "block 要装，包必须先被捕获，数据面才谈得上丢弃它",
        "rules": [
            {"match": "203.0.113.0/24", "action": "egress", "egressClientId": 2},
            {"match": "198.51.100.0/24", "action": "direct"},
            {"match": "192.0.2.0/24", "action": "block"},
        ],
        "bypass": [],
    },
    {
        "name": "default-route-is-refused-but-its-halves-are-ordinary-prefixes",
        "description": "/0 被拒。0.0.0.0/1 被拒的原因是它覆盖了 mesh 网段，不是因为它太宽；"
                       "128.0.0.0/1 是一条普通前缀，一期校验放行它。两条 /1 合起来等于接管一切，"
                       "而校验只挡住 /0——这是记在案的已知缺口，不是这条用例写漏了",
        "rules": [
            {"match": "0.0.0.0/0", "action": "egress", "egressClientId": 2},
            {"match": "0.0.0.0/1", "action": "egress", "egressClientId": 2},
            {"match": "128.0.0.0/1", "action": "egress", "egressClientId": 2},
        ],
        "bypass": [],
    },
    {
        "name": "bypass-comes-first",
        "description": "旁路条目排在最前：先让承载隧道的传输保持可达，再把任何流量指进隧道",
        "rules": [
            {"match": "10.0.0.0/8", "action": "egress", "egressClientId": 2},
        ],
        "bypass": ["203.0.113.7", "198.51.100.9"],
    },
    {
        "name": "bypass-inside-a-captured-prefix",
        "description": "旁路地址落在某条规则的前缀内时仍要单独装 /32，否则控制连接会被卷进它自己承载的隧道",
        "rules": [
            {"match": "203.0.113.0/24", "action": "egress", "egressClientId": 2},
        ],
        "bypass": ["203.0.113.7"],
    },
    {
        "name": "duplicate-prefixes-yield-one-route",
        "description": "同一前缀的两条规则只需要一条路由；装两次会让撤销失去定论。旁路重复同理",
        "rules": [
            {"match": "192.0.2.0/24", "action": "egress", "egressClientId": 2},
            {"match": "192.0.2.0/24", "action": "block"},
        ],
        "bypass": ["203.0.113.7", "203.0.113.7"],
    },
    {
        "name": "bypass-outranks-a-rule-for-the-same-address",
        "description": "旁路先入表，因此同地址的 /32 规则不会把它顶掉，origin 仍然是 bypass",
        "rules": [
            {"match": "203.0.113.7/32", "action": "egress", "egressClientId": 2},
        ],
        "bypass": ["203.0.113.7"],
    },
    {
        "name": "unreadable-bypass-entries-are-skipped",
        "description": "旁路来自运行期发现的对端与端点，不是用户配置。读不出的条目跳过即可，"
                       "整体拒绝会因为一个失联对端停掉全部分流",
        "rules": [
            {"match": "10.0.0.0/8", "action": "egress", "egressClientId": 2},
        ],
        "bypass": ["not-an-address", "203.0.113.7", "", "203.0.113.7:443"],
    },
    {
        "name": "refused-rules-are-reported-and-install-nothing",
        "description": "被拒的规则逐条返回而不是静默跳过：运维写了一条而本功能忽略了它，"
                       "他们没有任何途径发现这个泄漏",
        "rules": [
            {"match": "203.0.113.0/24", "action": "egress", "egressClientId": 2},
            {"match": "example.com", "action": "egress", "egressClientId": 2},
            {"match": "100.96.0.0/11", "action": "block"},
            {"match": "198.51.100.0/24", "action": "egress"},
            {"match": "192.0.2.0/24", "action": "block", "port": 443},
        ],
        "bypass": [],
    },
    {
        "name": "a-single-address-rule-becomes-a-host-route",
        "description": "单地址等价于 /32，并按规范形式写回，避免同一条路由在两次运行里被写成两种样子",
        "rules": [
            {"match": "203.0.113.7", "action": "egress", "egressClientId": 2},
        ],
        "bypass": [],
    },
    {
        "name": "empty-configuration-installs-nothing",
        "description": "没有规则就没有路由。这不是边界情况，而是关掉分流之后应有的状态",
        "rules": [],
        "bypass": [],
    },
]

plan_cases = []
for case in PLAN_CASES:
    routes, refused = plan(case["rules"], case["bypass"])
    plan_cases.append({
        "name": case["name"],
        "description": case["description"],
        "rules": case["rules"],
        "bypass": case["bypass"],
        "expect": {"routes": routes, "refused": refused},
    })


def tun(cidr):
    return {"cidr": cidr, "kind": "tun", "origin": "rule:" + cidr}


def bypass_route(cidr):
    return {"cidr": cidr, "kind": "bypass", "origin": "bypass"}


DIFF_CASES = [
    {
        "name": "first-apply-adds-everything",
        "description": "当前集合为空：全部是新增，顺序仍然是旁路在前",
        "current": [],
        "desired": [tun("10.0.0.0/8"), bypass_route("203.0.113.7/32")],
    },
    {
        "name": "unchanged-plan-does-nothing",
        "description": "重复下发同一份配置不应该动路由表",
        "current": [bypass_route("203.0.113.7/32"), tun("10.0.0.0/8")],
        "desired": [bypass_route("203.0.113.7/32"), tun("10.0.0.0/8")],
    },
    {
        "name": "dropped-rule-is-withdrawn",
        "description": "规则删掉后对应路由必须撤销，否则流量继续进隧道而配置里已经没有它",
        "current": [tun("10.0.0.0/8"), tun("192.0.2.0/24")],
        "desired": [tun("10.0.0.0/8")],
    },
    {
        "name": "prefix-that-changed-kind-is-replaced",
        "description": "同一前缀改变了种类：必须先撤旧的再装新的，否则平台要么拒绝重复条目，"
                       "要么静默保留先看到的那条",
        "current": [tun("203.0.113.7/32")],
        "desired": [bypass_route("203.0.113.7/32")],
    },
    {
        "name": "withdrawals-and-additions-in-one-apply",
        "description": "一次下发里既有撤销又有新增；两个列表各自排序，调用方先执行撤销",
        "current": [tun("192.0.2.0/24"), tun("198.51.100.0/24")],
        "desired": [bypass_route("203.0.113.7/32"), tun("198.51.100.0/24"), tun("10.0.0.0/8")],
    },
]

diff_cases = []
for case in DIFF_CASES:
    remove, add = diff(case["current"], case["desired"])
    diff_cases.append({
        "name": case["name"],
        "description": case["description"],
        "current": case["current"],
        "desired": case["desired"],
        "expect": {"remove": remove, "add": add},
    })

# The journal is the on-disk record of what the consumer installed, and it is a contract between
# the three of them: a user who switches implementations on one machine has to have their routes
# adopted and withdrawn rather than left behind by a reader that did not recognise the file.
#
# What is pinned is that each runtime can read this text and produces something that reads back the
# same, not that all three emit identical bytes. Demanding identical whitespace would fail over
# formatting that no reader cares about.
JOURNAL_ROUTES = [
    {"cidr": "198.51.100.7/32", "kind": "bypass", "origin": "bypass"},
    {"cidr": "203.0.113.0/24", "kind": "tun", "origin": "rule:203.0.113.0/24"},
]

journal = {
    "version": 1,
    "description": "消费端安装记录的磁盘格式。三个实现必须能互相读懂：同一台机器上换实现之后，"
                   "上一次装下的路由要被接管并撤销，而不是因为读不懂文件被留在表里。"
                   "钉住的是「读得出、写回去还能读成同一份」，不是三端输出的字节完全一致——"
                   "为没有任何读取方在意的空白差异而失败没有意义。",
    "text": json.dumps({"version": 1, "routes": JOURNAL_ROUTES}, indent=2, ensure_ascii=False),
    "routes": JOURNAL_ROUTES,
    "rejects": [
        {
            "name": "unknown-version",
            "text": json.dumps({"version": 2, "routes": JOURNAL_ROUTES}, indent=2, ensure_ascii=False),
            "reason": "另一个版本记录条目的方式可能不同，照它撤销就是在猜哪条前缀是自己装的",
        },
        {
            "name": "unknown-kind",
            "text": json.dumps(
                {"version": 1, "routes": [{"cidr": "203.0.113.0/24", "kind": "onlink", "origin": "rule"}]},
                indent=2, ensure_ascii=False),
            "reason": "读不懂的种类要拒绝而不是取默认值：猜错就会去撤销一条上次按另一种方式装下的前缀",
        },
        {
            "name": "not-json",
            "text": "this is not a journal",
            "reason": "半个文件、被别的东西覆盖的文件，都从这里退出，而不是被当成空记录接受——"
                      "空记录意味着上次装下的路由永远不会被撤销",
        },
    ],
}


# Reading what the platform's routing tools say.
#
# These parsers depend on output formats nobody controls, which makes them the part most likely to
# be wrong, and each runtime would otherwise write its own fixtures from its own reading of the man
# page. Kept free of any platform guard on all three sides on purpose, so they are covered on the
# machines where development and most of CI actually happen rather than only on Linux.
NL = chr(10)

ROUTE_GET = [
    ("through-a-router",
     "1.2.3.4 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 1000 " + NL + "    cache " + NL,
     {"parsed": True, "gateway": "10.0.0.1", "device": "eth0"},
     "常见形态：经网关送出"),
    ("directly-attached-carries-no-via",
     "10.0.0.5 dev eth0 src 10.0.0.5 uid 1000 " + NL + "    cache " + NL,
     {"parsed": True, "gateway": "", "device": "eth0"},
     "同网段目标没有 via。把它当解析失败会导致本地网络上的地址一律无法旁路"),
    ("interface-name-with-a-dash",
     "198.51.100.7 via 192.168.1.1 dev wlp3s0-1 src 192.168.1.44 " + NL,
     {"parsed": True, "gateway": "192.168.1.1", "device": "wlp3s0-1"},
     "接口名可以带连字符与数字，不能按纯字母切"),
    ("unreachable",
     "unreachable 203.0.113.9 dev lo src 127.0.0.1 uid 1000 " + NL,
     {"parsed": False},
     "不可达是作为一条路由报出来的，不是错误。认不出它就会装一条指向空处的旁路"),
    ("prohibit", "prohibit 203.0.113.9 dev lo " + NL, {"parsed": False}, "同上"),
    ("blackhole", "blackhole 203.0.113.9 " + NL, {"parsed": False}, "同上"),
    ("empty-output", "", {"parsed": False}, "没有输出就是没有可用的下一跳"),
    ("blank-lines", "   " + NL + NL, {"parsed": False}, "只有空白同样不构成一条路由"),
    ("error-text-on-stdout",
     "RTNETLINK answers: Network is unreachable" + NL,
     {"parsed": False},
     "错误文本里没有 dev，不能被当成一行路由读进去"),
]

SHOW_EXACT = [
    ("an-existing-route",
     "192.0.2.0/24 via 10.0.0.1 dev eth0 metric 100 " + NL,
     {"present": True, "description": "192.0.2.0/24 via 10.0.0.1 dev eth0 metric 100"},
     "原样报给运维：把别人的路由概括一遍，不如给他们那一行可以自己去看"),
    ("no-route-for-that-exact-prefix", "", {"present": False, "description": ""},
     "空输出意味着这条精确前缀上没有路由，可以安装"),
    ("blank-lines-are-not-a-route", NL + "  " + NL, {"present": False, "description": ""},
     "同上"),
]

route_commands = {
    "description": "ip route 输出的解析。这两个解析器依赖的是没人控制的输出格式，"
                   "三端各自照着 man page 写会得到三份不同的读法，而读错的代价是装一条指向空处的旁路。"
                   "因此它们在三个实现里都不带平台守卫，在开发机与大部分 CI 上照常被覆盖。",
    "routeGet": [
        {"name": name, "output": output, "expect": expect, "reason": reason}
        for name, output, expect, reason in ROUTE_GET
    ],
    "showExact": [
        {"name": name, "output": output, "expect": expect, "reason": reason}
        for name, output, expect, reason in SHOW_EXACT
    ],
    "tunnelDevice": {
        "description": "重新下发时，规则的路由已经覆盖了旁路地址，再问系统「这个地址往哪送」"
                       "得到的答案就是「经隧道」。照它安装等于把承载隧道的传输送进隧道自身，必须拒绝。",
        "cases": [
            {"device": "specus0", "tun": "specus0", "expect": True},
            {"device": " specus0 ", "tun": "specus0", "expect": True,
             "reason": "两侧空白不能让这道检查失效"},
            {"device": "eth0", "tun": "specus0", "expect": False},
            {"device": "eth0", "tun": "", "expect": False,
             "reason": "没有隧道名时不能匹配上任意接口"},
        ],
    },
}

vector = {
    "name": "peer-egress-routes-v1",
    "version": 1,
    "notes": [
        "只安装精确前缀，计划器不会自己造出 0.0.0.0/0 或它的两个 /1 半区。接管一切的工具没法被运行它的人"
        "推理，「未匹配即本地」也会在那一刻不再成立。",
        "已知缺口：校验只拒绝 /0。运维手写 0.0.0.0/1 与 128.0.0.0/1 两条规则仍然可以覆盖全部地址，"
        "其中下半区目前只是因为覆盖 mesh 网段才被拒。设一个最小前缀长度属于策略决定，"
        "不在本次移植的范围内，见 planCases 里的 default-route-is-refused-but-its-halves-are-ordinary-prefixes。",
        "旁路条目排在最前，安装也按此顺序：承载隧道的传输（控制连接、STUN 与 TURN、对端端点）先保持可达，"
        "再把流量指进隧道。",
        "action=direct 不安装路由。流量靠「没有路由」留在本地，与未匹配流量是同一个机制，"
        "而不是两处需要彼此保持一致的行为。action=block 要安装：包必须先被捕获，数据面才谈得上丢弃它。",
        "计划是纯函数：它只说应该存在哪些路由，执行与回滚由安装器负责。这样回滚、冲突拒绝与归属判定"
        "都能脱离真实路由表被测试。",
        "origin 是运维会读到的字符串，因此也被固定：旁路为 bypass，规则为 rule: 加上规则里原样的 match。",
        "被拒的规则逐条返回而不是静默跳过：运维写了一条而本功能忽略了它，他们没有任何途径发现这个泄漏。",
        "bypass 列表来自运行期发现的对端与端点，不是用户配置，因此读不出的条目跳过即可；"
        "为它整体拒绝一份计划会因为一个失联对端而停掉全部分流。",
        "本文件的期望值出自 tools/protocol/generate_peer_egress_route_vectors.py 里的独立参考实现，"
        "不是从任何一个实现录下来的：对上它意味着各自独立正确，而不是共享同一个错误。",
    ],
    "meshCidr": MESH_CIDR,
    "planCases": plan_cases,
    "diffCases": diff_cases,
    "journal": journal,
    "routeCommands": route_commands,
}

out = VECTORS / "peer-egress-routes-v1.json"
out.write_text(json.dumps(vector, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print("wrote", out, out.stat().st_size, "bytes")
print("plan cases:", len(plan_cases), "diff cases:", len(diff_cases),
      "journal rejects:", len(journal["rejects"]),
      "route-get:", len(ROUTE_GET), "show-exact:", len(SHOW_EXACT))
for case in plan_cases:
    print("  ", case["name"], "->", len(case["expect"]["routes"]), "routes",
          len(case["expect"]["refused"]), "refused")
