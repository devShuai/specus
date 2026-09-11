"""Generate peer-egress-windows-routes-v1.json.

Windows route takeover reads the routing table through PowerShell, and the fixtures below were
sampled from a real Windows 11 machine rather than copied out of documentation.

Why PowerShell rather than netsh or route print: their output is localised. The same
`netsh interface ipv4 show route` on the sampling machine printed English column headers under one
console code page and Chinese ones ("发布  类型  跃点数  前缀  索引  网关/接口名称") under another.
A parser written against the English table would read no routes at all on a Chinese machine, and
"no routes" is exactly the answer that says "no conflict, go ahead and install" -- the failure would
overwrite the operator's own routing while reporting success. `ip route` on Linux carries no
translations, which is why parsing its text is safe there and not here.

So the PowerShell layer is kept as thin as it can be: it turns objects into JSON and does nothing
else. Every decision -- which object in the array is the route, what an absent next hop means,
whether a failure was a permissions failure -- lives in the parsers, where this vector pins all
three implementations to the same reading. Filtering inside the PowerShell string would move that
logic into three separately embedded snippets that no test covers.

The expectations come from the reference parsers in this file, not from any implementation.
"""
import json
from pathlib import Path

VECTORS = Path("protocol/test-vectors")

# The next hop Windows reports for a destination on a directly attached network. Linux says this by
# leaving `via` out altogether, so both are normalised to an empty gateway and the rest of the
# installer does not need to know which platform answered.
ON_LINK = "0.0.0.0"


def parse_route_find(output):
    """Reference reading of the find-route script's JSON.

    Returns (gateway, interface_index) or None.

    `Find-NetRoute` emits two objects: the source address it would use, then the route. Only the
    second carries a DestinationPrefix, and that is what picks it out -- taking element zero would
    yield an interface index with no next hop.
    """
    try:
        parsed = json.loads(output)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, list):
        return None
    for entry in parsed:
        if not isinstance(entry, dict):
            continue
        prefix = entry.get("DestinationPrefix")
        if not isinstance(prefix, str) or not prefix.strip():
            continue
        index = entry.get("InterfaceIndex")
        if not isinstance(index, int) or index <= 0:
            # Zero is not an interface. Installing against it would ask the system to route
            # through nothing, and the add would either fail or land somewhere unintended.
            continue
        hop = entry.get("NextHop")
        gateway = "" if not isinstance(hop, str) or hop.strip() in ("", ON_LINK) else hop.strip()
        return gateway, index
    return None


def describe_route(entry):
    """One line an operator can match against their own `Get-NetRoute` output."""
    prefix = entry.get("DestinationPrefix") or ""
    hop = entry.get("NextHop")
    via = "on-link" if not isinstance(hop, str) or hop.strip() in ("", ON_LINK) \
        else "nexthop " + hop.strip()
    line = "{} {} ifIndex {}".format(prefix, via, entry.get("InterfaceIndex"))
    metric = entry.get("RouteMetric")
    if isinstance(metric, int):
        line += " metric {}".format(metric)
    return line


def parse_route_show(output):
    """Reference reading of the show-route script's JSON.

    Returns (present, description). Unparseable output reports no conflict, matching Linux: being
    unable to ask is not evidence of an empty table, and the install itself still refuses an
    existing prefix.
    """
    try:
        parsed = json.loads(output)
    except (ValueError, TypeError):
        return False, ""
    if not isinstance(parsed, list):
        return False, ""
    routes = [e for e in parsed
              if isinstance(e, dict) and isinstance(e.get("DestinationPrefix"), str)
              and e["DestinationPrefix"].strip()]
    if not routes:
        return False, ""
    description = describe_route(routes[0])
    if len(routes) > 1:
        # The count matters to whoever has to clear the prefix: they need to know one removal is
        # not going to be enough.
        description += " (+{} more)".format(len(routes) - 1)
    return True, description


def parse_command_failure(output):
    """Reference classification of a failed routing command.

    Returns "permission-denied", "failed", or "" when nothing failed.

    Keyed on the numeric Windows error inside FullyQualifiedErrorId, never on the message. The
    message is localised -- "Access is denied." on the sampling machine, a translation elsewhere --
    while the id is constructed from the error number and is not.
    """
    try:
        parsed = json.loads(output)
    except (ValueError, TypeError):
        return "failed" if (output or "").strip() else ""
    if not isinstance(parsed, dict):
        return ""
    error_id = parsed.get("errorId")
    if not isinstance(error_id, str) or not error_id.strip():
        return ""
    if "Windows System Error 5" in error_id:
        return "permission-denied"
    return "failed"


# ------------------------------------------------------------------ fixtures ----
# Everything marked "sampled" below is the literal output of the script shape this feature runs,
# captured on Windows 11 26200, Windows PowerShell 5.1.26100.9444, zh-CN system locale.

SAMPLED_DEFAULT = ('[{"InterfaceIndex":3,"DestinationPrefix":"0.0.0.0/0","NextHop":"192.168.1.111"'
                   ',"RouteMetric":256,"InterfaceMetric":20}]')
SAMPLED_ON_LINK = ('[{"InterfaceIndex":3,"DestinationPrefix":"192.168.1.0/24","NextHop":"0.0.0.0"'
                   ',"RouteMetric":256,"InterfaceMetric":20}]')
SAMPLED_LOOPBACK = ('[{"InterfaceIndex":1,"DestinationPrefix":"127.0.0.1/32","NextHop":"0.0.0.0"'
                    ',"RouteMetric":256,"InterfaceMetric":75}]')
SAMPLED_MULTICAST = (
    '[{"InterfaceIndex":44,"DestinationPrefix":"224.0.0.0/4","NextHop":"0.0.0.0","RouteMetric":256'
    ',"InterfaceMetric":5000},{"InterfaceIndex":14,"DestinationPrefix":"224.0.0.0/4"'
    ',"NextHop":"0.0.0.0","RouteMetric":256,"InterfaceMetric":25},{"InterfaceIndex":17'
    ',"DestinationPrefix":"224.0.0.0/4","NextHop":"0.0.0.0","RouteMetric":256'
    ',"InterfaceMetric":25},{"InterfaceIndex":15,"DestinationPrefix":"224.0.0.0/4"'
    ',"NextHop":"0.0.0.0","RouteMetric":256,"InterfaceMetric":25}]')
SAMPLED_FIND_GATEWAY = (
    '[{"InterfaceIndex":3,"DestinationPrefix":null,"NextHop":null,"RouteMetric":null'
    ',"InterfaceMetric":null},{"InterfaceIndex":3,"DestinationPrefix":"0.0.0.0/0"'
    ',"NextHop":"192.168.1.111","RouteMetric":256,"InterfaceMetric":20}]')
SAMPLED_FIND_ON_LINK = (
    '[{"InterfaceIndex":3,"DestinationPrefix":null,"NextHop":null,"RouteMetric":null'
    ',"InterfaceMetric":null},{"InterfaceIndex":3,"DestinationPrefix":"192.168.1.0/24"'
    ',"NextHop":"0.0.0.0","RouteMetric":256,"InterfaceMetric":20}]')
SAMPLED_DENIED = '{"errorId":"Windows System Error 5,New-NetRoute"}'

ROUTE_FIND = [
    {
        "name": "through-a-router",
        "output": SAMPLED_FIND_GATEWAY,
        "sampled": True,
        "reason": "采样：8.8.8.8 经默认网关。第一个对象是源地址而不是路由，取 [0] 会拿到接口号却没有下一跳",
    },
    {
        "name": "on-link",
        "output": SAMPLED_FIND_ON_LINK,
        "sampled": True,
        "reason": "采样：同网段目标。Windows 用 0.0.0.0 表示直连，Linux 是省略 via；两者都归一成空网关，"
                  "否则会装出一条指向 0.0.0.0 的路由",
    },
    {
        "name": "loopback",
        "output": ('[{"InterfaceIndex":1,"DestinationPrefix":"127.0.0.1/32","NextHop":"0.0.0.0"'
                   ',"RouteMetric":256,"InterfaceMetric":75}]'),
        "sampled": True,
        "reason": "采样：回环接口索引为 1，同样是直连",
    },
    {
        "name": "address-object-only",
        "output": ('[{"InterfaceIndex":3,"DestinationPrefix":null,"NextHop":null'
                   ',"RouteMetric":null,"InterfaceMetric":null}]'),
        "reason": "只有源地址没有路由：查不到路由时必须判为失败，而不是拿着接口号去装",
    },
    {
        "name": "empty-array",
        "output": "[]",
        "reason": "没有任何对象",
    },
    {
        "name": "not-json",
        "output": "New-NetRoute : 拒绝访问。\r\n",
        "reason": "cmdlet 直接报错而不是输出 JSON。注意这段消息是中文的——这正是不解析人类可读输出的理由",
    },
    {
        "name": "null-next-hop",
        "output": ('[{"InterfaceIndex":7,"DestinationPrefix":"10.0.0.0/8","NextHop":null'
                   ',"RouteMetric":256,"InterfaceMetric":25}]'),
        "reason": "有前缀但下一跳为 null：按直连处理，与 Linux 缺 via 的读法一致",
    },
    {
        "name": "zero-interface-index",
        "output": ('[{"InterfaceIndex":0,"DestinationPrefix":"10.0.0.0/8"'
                   ',"NextHop":"10.0.0.1","RouteMetric":256,"InterfaceMetric":25}]'),
        "reason": "0 不是接口索引。照它安装等于让系统往不存在的接口送",
    },
    {
        "name": "first-usable-wins",
        "output": ('[{"InterfaceIndex":0,"DestinationPrefix":"10.0.0.0/8","NextHop":"10.0.0.1"'
                   ',"RouteMetric":256,"InterfaceMetric":25},{"InterfaceIndex":9'
                   ',"DestinationPrefix":"10.0.0.0/8","NextHop":"10.0.0.9","RouteMetric":256'
                   ',"InterfaceMetric":25}]'),
        "reason": "跳过不可用的条目继续找，而不是在第一条上放弃",
    },
]

ROUTE_SHOW = [
    {
        "name": "an-existing-route",
        "output": SAMPLED_DEFAULT,
        "sampled": True,
        "reason": "采样：默认路由。描述给运维原样核对用",
    },
    {
        "name": "an-on-link-route",
        "output": SAMPLED_ON_LINK,
        "sampled": True,
        "reason": "采样：直连网段在描述里写 on-link，不写 nexthop 0.0.0.0",
    },
    {
        "name": "a-loopback-route",
        "output": SAMPLED_LOOPBACK,
        "sampled": True,
        "reason": "采样：回环",
    },
    {
        "name": "the-same-prefix-on-four-interfaces",
        "output": SAMPLED_MULTICAST,
        "sampled": True,
        "reason": "采样：多播前缀每个接口一条。条数要报出来，否则运维以为删掉一条就腾出了这个前缀",
    },
    {
        "name": "no-route",
        "output": "[]",
        "sampled": True,
        "reason": "采样：Get-NetRoute 查不到前缀时是报错而不是输出空，所以脚本用 -ErrorAction "
                  "SilentlyContinue 把它压成空数组",
    },
    {
        "name": "not-json",
        "output": "Get-NetRoute : 无法识别参数\r\n",
        "reason": "问不出来不等于表是空的，但也不报冲突：安装本身仍会拒绝已存在的前缀，失败方向是安全的",
    },
    {
        "name": "route-without-prefix",
        "output": ('[{"InterfaceIndex":3,"DestinationPrefix":null,"NextHop":"192.168.1.111"'
                   ',"RouteMetric":256,"InterfaceMetric":20}]'),
        "reason": "没有前缀的条目不算冲突",
    },
]

COMMAND_ERRORS = [
    {
        "name": "access-denied",
        "output": SAMPLED_DENIED,
        "sampled": True,
        "reason": "采样：非管理员执行 New-NetRoute。认错误号 5 而不是认「Access is denied」，"
                  "后者在中文系统上是「拒绝访问」",
    },
    {
        "name": "another-windows-error",
        "output": '{"errorId":"Windows System Error 87,New-NetRoute"}',
        "reason": "别的系统错误不能被当成权限问题，否则会让运维去提权解决一个不是权限的问题",
    },
    {
        "name": "a-cmdlet-error",
        "output": '{"errorId":"InvalidParameter,New-NetRoute"}',
        "reason": "不带错误号的失败",
    },
    {
        "name": "empty-error-id",
        "output": '{"errorId":""}',
        "reason": "空的错误 id 不算失败",
    },
    {
        "name": "success",
        "output": "",
        "reason": "命令成功时脚本什么都不输出",
    },
    {
        "name": "unparseable-output",
        "output": "something went wrong\r\n",
        "reason": "输出不是 JSON 但也不是空：失败，只是分不出原因",
    },
]

for case in ROUTE_FIND:
    hop = parse_route_find(case["output"])
    case["expect"] = {"parsed": hop is not None}
    if hop is not None:
        case["expect"]["gateway"], case["expect"]["interfaceIndex"] = hop

for case in ROUTE_SHOW:
    present, description = parse_route_show(case["output"])
    case["expect"] = {"present": present, "description": description}

for case in COMMAND_ERRORS:
    case["expect"] = {"failure": parse_command_failure(case["output"])}

# The parsers only earn their place if some case would notice them being removed. A list where no
# case needs the on-link normalisation, or where every route sits at element zero, would pass
# against an implementation that dropped both.
assert any(c["expect"].get("parsed") and c["expect"]["gateway"] == ""
           and ON_LINK in c["output"] for c in ROUTE_FIND), "no case exercises the on-link rewrite"
assert any(c["expect"].get("parsed") and json.loads(c["output"])[0].get("DestinationPrefix") is None
           for c in ROUTE_FIND if c["output"].startswith("[{")), "no case needs the route picked out"
assert any(c["expect"]["failure"] == "permission-denied" for c in COMMAND_ERRORS)
assert any(c["expect"]["failure"] == "failed" for c in COMMAND_ERRORS)
assert any("(+" in c["expect"]["description"] for c in ROUTE_SHOW), "no case reports a route count"
assert sum(1 for c in ROUTE_FIND + ROUTE_SHOW + COMMAND_ERRORS if c.get("sampled")) >= 9

vector = {
    "name": "peer-egress-windows-routes-v1",
    "version": 1,
    "notes": [
        "Windows 侧读路由表的三个解析器。标了 sampled 的 output 是真机抓下来的原样输出，"
        "机器为 Windows 11 26200、Windows PowerShell 5.1.26100.9444、系统区域 zh-CN。",
        "不解析 netsh 与 route print：它们的输出是本地化的。同一条 netsh interface ipv4 show route "
        "在采样机上，一个控制台代码页下打印英文表头，另一个下打印中文表头。照英文表头写的解析器在中文机器上"
        "一条路由都读不出来，而「读不出路由」恰好等于「没有冲突，装吧」——失败方向是覆盖掉运维自己的路由。"
        "Linux 的 ip route 不带翻译，所以那边解析文本是安全的，这边不是。",
        "PowerShell 那层只把对象转成 JSON，不做判断。挑哪个对象、缺失的下一跳是什么意思、"
        "失败是不是权限问题，全部在解析器里，由本向量钉住三端。写进 PowerShell 字符串里的过滤逻辑"
        "是三份各自嵌的片段，没有任何测试覆盖得到。",
        "权限失败认 FullyQualifiedErrorId 里的错误号 5，不认消息文本：消息在中文系统上是「拒绝访问」。",
        "Windows 用 0.0.0.0 表示直连，Linux 用「没有 via」。两者都归一成空网关，"
        "安装器不需要知道是哪个平台回答的。",
        "hop 里带的是接口索引不是接口名：接口名是本地化的（采样机上默认网卡叫「以太网」），索引是数字。",
        "本文件的期望值出自 tools/protocol/generate_peer_egress_windows_route_vectors.py 里的"
        "独立参考解析器，不是从任何一个实现录下来的。",
    ],
    "onLinkNextHop": ON_LINK,
    "routeFind": ROUTE_FIND,
    "routeShow": ROUTE_SHOW,
    "commandErrors": COMMAND_ERRORS,
}

out = VECTORS / "peer-egress-windows-routes-v1.json"
out.write_text(json.dumps(vector, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print("wrote", out, out.stat().st_size, "bytes")
print("routeFind:", len(ROUTE_FIND), "routeShow:", len(ROUTE_SHOW),
      "commandErrors:", len(COMMAND_ERRORS),
      "sampled:", sum(1 for c in ROUTE_FIND + ROUTE_SHOW + COMMAND_ERRORS if c.get("sampled")))
for case in ROUTE_FIND:
    print("   find", case["name"], "->", case["expect"])
for case in ROUTE_SHOW:
    print("   show", case["name"], "->", case["expect"])
