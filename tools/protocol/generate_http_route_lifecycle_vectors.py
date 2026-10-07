"""Generate protocol/test-vectors/http-route-lifecycle-v1.json.

An HTTP route stops being reachable the moment the server no longer has an enabled record of it,
and the client is told so on the next NAT_CONTROL it receives. See protocol/spec/http-route.md,
sections 1 and 2. What the four servers and four clients must agree on, and what this vector fixes:

- the public entry /http/{clientName}/{route}/** fails closed: a route the server has no record of
  (never created, deleted, no route segment), a disabled route, or a missing or disabled client is
  a no-store 404 before the body is read, a NAT stream is opened or a WebSocket is upgraded,
  whatever the client still forwards;
- every NAT_CONTROL carries the client's full list of enabled routes, an empty array included,
  on every change while the client is online and on every control login. A client that reconnects
  with its access token gets no new HTTP login snapshot, so the login push is the only way it
  learns that its last route was deleted while it was away;
- disabling, renaming or deleting a client account closes its online connections, so no session
  keeps serving under a name or a route set the server no longer has;
- a client replaces its whole route table with every NAT_CONTROL. An empty array, null or a
  missing field all mean "no routes": no client defines routes locally any more, so there is
  nothing a missing field could keep.

Every expectation is produced by the reference model below and checked against a hand-written
table before the file is written, so the vector cannot ship contradicting itself.
"""
import json
from pathlib import Path

VECTORS = Path("protocol/test-vectors")

USERNAME = "route-user"
PASSWORD = "route-password"
TARGET_BASE_URL = "http://127.0.0.1:18080"
FORWARDED_BODY = "forwarded"


class Model:
    """The server's view of one client account and its routes, and of one fake client."""

    def __init__(self):
        self.client_exists = True
        self.client_enabled = True
        self.online = False
        self.renamed = False
        self.former_exists = False      # an account still answers to the name before a rename
        self.routes = {}                # name -> {"enabled", "auth"}, in creation (id) order

    def enabled_routes(self):
        return [name for name, route in self.routes.items() if route["enabled"]]

    def push(self):
        return self.enabled_routes() if self.online else None

    def request(self, route, credentials, websocket, client):
        if client == "former":
            exists, enabled, routes = self.former_exists, False, {}
        else:
            exists, enabled, routes = self.client_exists, self.client_enabled, self.routes
        not_found = {"status": 404, "noStore": True, "forwarded": False}
        if route is None:
            # No route segment: there is nothing to look up. Frameworks answer this path before
            # the entry runs, so only the status and "nothing forwarded" are portable.
            return {"status": 404, "forwarded": False}
        if not exists or not enabled or route not in routes or not routes[route]["enabled"]:
            return not_found
        if routes[route]["auth"] and credentials != "valid":
            return {"status": 401, "basicChallenge": True, "forwarded": False}
        if not self.online:
            return {"statusAnyOf": [502, 503], "forwarded": False}
        if websocket:
            raise AssertionError("an accepted WebSocket needs SWS2; the vector only refuses upgrades")
        return {"status": 200, "body": FORWARDED_BODY, "forwarded": True}


def server_scenario(scenario_id, title, ops):
    """Runs the ops through a fresh model and fills in each step's expectations."""
    model = Model()
    steps = []
    for op in ops:
        kind = op["op"]
        step = dict(op)
        if kind == "createRoute":
            assert op["route"] not in model.routes
            model.routes[op["route"]] = {"enabled": True, "auth": op["auth"]}
            step["expectPush"] = model.push()
        elif kind == "setRouteEnabled":
            model.routes[op["route"]]["enabled"] = op["enabled"]
            step["expectPush"] = model.push()
        elif kind == "deleteRoute":
            del model.routes[op["route"]]
            step["expectPush"] = model.push()
        elif kind == "connect":
            assert model.client_exists and model.client_enabled and not model.online
            model.online = True
            step["expectLoginPush"] = model.enabled_routes()
        elif kind == "disconnect":
            assert model.online
            model.online = False
        elif kind == "setClientEnabled":
            step["expectSessionClosed"] = model.online and not op["enabled"]
            model.client_enabled = op["enabled"]
            if not op["enabled"]:
                model.online = False
        elif kind == "renameClient":
            step["expectSessionClosed"] = model.online
            model.online = False
            model.renamed = True
        elif kind == "deleteClient":
            step["expectSessionClosed"] = model.online
            model.online = False
            model.client_exists = False
            model.routes = {}
        elif kind == "createClient":
            assert not model.client_exists
            model.client_exists = True
            model.client_enabled = True
        elif kind == "request":
            step.setdefault("path", "/secret")
            step.setdefault("credentials", "none")
            step.setdefault("websocket", False)
            step.setdefault("client", "current")
            step["expect"] = model.request(step["route"], step["credentials"], step["websocket"],
                                           step["client"])
        else:
            raise AssertionError(f"unknown op {kind}")
        steps.append(step)
    return {"id": scenario_id, "title": title, "steps": steps}


def request(route, **kwargs):
    return {"op": "request", "route": route, **kwargs}


def server_scenarios():
    return [
        server_scenario(
            "delete-last-protected-route-while-online",
            "删除在线客户端最后一条受保护 route：推送空数组，入口 404，即使客户端仍在转发",
            [
                {"op": "createRoute", "route": "web", "auth": True},
                {"op": "connect"},
                request("web"),
                request("web", credentials="wrong"),
                request("web", credentials="valid"),
                {"op": "deleteRoute", "route": "web"},
                request("web"),
                request("web", credentials="valid"),
                request("web", credentials="valid", websocket=True),
            ]),
        server_scenario(
            "delete-last-route-while-offline",
            "客户端离线时删除最后一条 route：凭 token 重连后的登录推送带空数组",
            [
                {"op": "createRoute", "route": "web", "auth": False},
                {"op": "connect"},
                request("web"),
                {"op": "disconnect"},
                {"op": "deleteRoute", "route": "web"},
                {"op": "connect"},
                request("web"),
            ]),
        server_scenario(
            "disable-and-enable-one-of-two-routes",
            "停用两条 route 中的一条：推送只剩另一条，被停用的 404；重新启用后恢复",
            [
                {"op": "createRoute", "route": "web", "auth": False},
                {"op": "createRoute", "route": "api", "auth": False},
                {"op": "connect"},
                {"op": "setRouteEnabled", "route": "web", "enabled": False},
                request("web"),
                request("api"),
                {"op": "setRouteEnabled", "route": "web", "enabled": True},
                request("web"),
            ]),
        server_scenario(
            "unknown-route-and-missing-segment",
            "从未创建的 route 与缺少 route 段的路径都是 404，不转发",
            [
                {"op": "createRoute", "route": "web", "auth": False},
                {"op": "connect"},
                request("never-created"),
                request("never-created", websocket=True),
                request(None),
            ]),
        server_scenario(
            "disabled-client",
            "停用客户端：断开在线连接，route 404",
            [
                {"op": "createRoute", "route": "web", "auth": False},
                {"op": "connect"},
                {"op": "setClientEnabled", "enabled": False},
                request("web"),
                request("web", websocket=True),
            ]),
        server_scenario(
            "renamed-client",
            "改名客户端：断开在线连接；旧名下的 route 404，新名下离线",
            [
                {"op": "createRoute", "route": "web", "auth": False},
                {"op": "connect"},
                {"op": "renameClient", "suffix": "-renamed"},
                request("web", client="former"),
                request("web"),
            ]),
        server_scenario(
            "deleted-client-name-reused",
            "删除客户端后用同名新建：旧连接已断开，新客户端的 route 不会转发到旧连接",
            [
                {"op": "createRoute", "route": "web", "auth": False},
                {"op": "connect"},
                {"op": "deleteClient"},
                request("web"),
                {"op": "createClient"},
                {"op": "createRoute", "route": "web", "auth": False},
                request("web"),
            ]),
    ]


def nat_control(routes=None, *, omit=False, null=False):
    """A NAT_CONTROL body shaped like a real push, carrying the given HTTP route list."""
    body = {
        "clientName": "route-lifecycle",
        "remoteAddress": "127.0.0.1",
        "remotePort": 7010,
        "specusConfigList": [],
    }
    if null:
        body["httpSpecusConfigList"] = None
    elif not omit:
        body["httpSpecusConfigList"] = routes
    return json.dumps(body, ensure_ascii=False, separators=(",", ":"))


def route_entry(route, target, insecure=False):
    return {"route": route, "targetBaseUrl": target, "insecureSkipVerify": insecure}


def client_case(case_id, title, login_snapshot, pushes):
    """Each push replaces the whole table; a missing or null list is the empty table."""
    steps = []
    for push in pushes:
        body = json.loads(push)
        listed = body.get("httpSpecusConfigList") or []
        steps.append({
            "natControl": push,
            "expectRoutes": {entry["route"]: entry["targetBaseUrl"] for entry in listed},
        })
    return {"id": case_id, "title": title, "loginSnapshot": login_snapshot, "steps": steps}


def client_cases():
    web = route_entry("web", "http://127.0.0.1:8080")
    web_moved = route_entry("web", "http://127.0.0.1:8081")
    api = route_entry("api", "https://127.0.0.1:9443", insecure=True)
    return [
        client_case("list-replaces-the-login-snapshot", "完整列表整体替换登录快照",
                    [web], [nat_control([web_moved, api])]),
        client_case("empty-list-clears", "空数组清空全部 route", [web], [nat_control([])]),
        client_case("missing-list-clears", "字段缺省同样清空：客户端没有本地 route 可保留",
                    [web], [nat_control(omit=True)]),
        client_case("null-list-clears", "字段为 null 同样清空", [web], [nat_control(null=True)]),
        client_case("routes-come-and-go", "route 先下发、再缺省、再换成另一条",
                    [], [nat_control([web]), nat_control(omit=True), nat_control([api]),
                         nat_control([])]),
    ]


# Hand-written expectations the model must reproduce; the vector is not written otherwise.
EXPECTED = {
    ("delete-last-protected-route-while-online", 1): {"expectLoginPush": ["web"]},
    ("delete-last-protected-route-while-online", 2): {"status": 401, "basicChallenge": True, "forwarded": False},
    ("delete-last-protected-route-while-online", 4): {"status": 200, "body": "forwarded", "forwarded": True},
    ("delete-last-protected-route-while-online", 5): {"expectPush": []},
    ("delete-last-protected-route-while-online", 7): {"status": 404, "noStore": True, "forwarded": False},
    ("delete-last-route-while-offline", 4): {"expectPush": None},
    ("delete-last-route-while-offline", 5): {"expectLoginPush": []},
    ("delete-last-route-while-offline", 6): {"status": 404, "noStore": True, "forwarded": False},
    ("disable-and-enable-one-of-two-routes", 3): {"expectPush": ["api"]},
    ("disable-and-enable-one-of-two-routes", 5): {"status": 200, "body": "forwarded", "forwarded": True},
    ("disable-and-enable-one-of-two-routes", 6): {"expectPush": ["web", "api"]},
    ("unknown-route-and-missing-segment", 4): {"status": 404, "forwarded": False},
    ("disabled-client", 2): {"expectSessionClosed": True},
    ("disabled-client", 3): {"status": 404, "noStore": True, "forwarded": False},
    ("renamed-client", 2): {"expectSessionClosed": True},
    ("renamed-client", 3): {"status": 404, "noStore": True, "forwarded": False},
    ("renamed-client", 4): {"statusAnyOf": [502, 503], "forwarded": False},
    ("deleted-client-name-reused", 2): {"expectSessionClosed": True},
    ("deleted-client-name-reused", 3): {"status": 404, "noStore": True, "forwarded": False},
    ("deleted-client-name-reused", 5): {"expectPush": None},
    ("deleted-client-name-reused", 6): {"statusAnyOf": [502, 503], "forwarded": False},
}


def check(scenarios, cases):
    by_id = {scenario["id"]: scenario for scenario in scenarios}
    for (scenario_id, index), expected in EXPECTED.items():
        step = by_id[scenario_id]["steps"][index]
        actual = step["expect"] if step["op"] == "request" else {key: step.get(key) for key in expected}
        assert actual == expected, f"{scenario_id}[{index}]: {actual} != {expected}"
    for scenario in scenarios:
        assert scenario["steps"][0]["op"] == "createRoute", scenario["id"]
    clears = [case for case in cases if case["id"].endswith("-clears")]
    assert all(case["steps"][-1]["expectRoutes"] == {} for case in clears)
    assert cases[0]["steps"][0]["expectRoutes"] == {"web": "http://127.0.0.1:8081",
                                                    "api": "https://127.0.0.1:9443"}


def build():
    scenarios = server_scenarios()
    cases = client_cases()
    check(scenarios, cases)
    return {
        "name": "http-route-lifecycle-v1",
        "version": 1,
        "description": "When an HTTP route stops being reachable, and how the client learns it: the "
                       "fail-closed public entry, the full route list on every NAT_CONTROL (login "
                       "included), connections closed with a disabled, renamed or deleted client, "
                       "and clients replacing their route table on every push. See "
                       "protocol/spec/http-route.md.",
        "notes": [
            "server.scenarios：每个 scenario 在一台全新服务端上用一个新客户端账户（或种子客户端）从空 route 开始顺序重放 "
            "steps。createRoute/setRouteEnabled/deleteRoute/setClientEnabled/renameClient/deleteClient/"
            "createClient 走各实现的管理 API；connect 用一个假客户端完成控制与数据连接的登录（凭已有 token 或"
            "重新 HTTP 登录均可），disconnect 关闭这两条连接并等服务端确认离线。",
            "假客户端对每个 HTTP OPEN 都回 200、Content-Type:text/plain、body 为 forwarded，模拟仍持有旧 route "
            "列表、对任何 route 名都继续转发的客户端；它记录收到的 OPEN，expect.forwarded 断言该请求是否到达它。",
            "expectLoginPush：connect 后控制连接上的第一条 NAT_CONTROL 必须带 httpSpecusConfigList 数组（空数组也必须"
            "出现），按集合比较 route 名。expectPush：该管理操作之后客户端在线时收到的下一条 NAT_CONTROL，比较方式相同；"
            "为 null 表示客户端离线，无需断言。",
            "expectSessionClosed 为 true 时服务端必须在 5 秒内关闭假客户端的控制与数据连接；为 false 时不断言。",
            "request：GET /http/{client}/{route}{path}，client 默认是当前账户名（URL 段按百分号编码），former 指"
            "最近一次 renameClient 之前的名字；route 为 null 时请求 /http/{client}/。credentials 为 none（不带 "
            "Authorization）、valid（Basic route-user:route-password）或 wrong（Basic route-user:wrong）。"
            "websocket 为 true 时带 Upgrade: websocket 与合法的 Sec-WebSocket-Key/Version 头。",
            "expect：status 或 statusAnyOf 比较状态码；noStore 为 true 时 Cache-Control 必须含 no-store；"
            "basicChallenge 为 true 时 WWW-Authenticate 必须以 Basic 开头；body 存在时比较响应体；forwarded 见上。"
            "WebSocket 被拒绝时不得返回 101。",
            "createRoute 的 targetBaseUrl 用 targetBaseUrl 字段，auth 为 true 时启用 Basic，凭据见 basicCredentials。"
            "renameClient 把当前账户名改为原名加 suffix。deleteClient 连同其 route 一起删除；createClient 用被删"
            "账户的原名新建账户，之后的 createRoute 属于新账户。",
            "client.cases：客户端先以 loginSnapshot 作为 HTTP 登录快照，再依次处理 natControl（真实推送的 JSON 原文），"
            "每步之后的 route 表（route 名到 targetBaseUrl）必须等于 expectRoutes。",
        ],
        "basicCredentials": {"username": USERNAME, "password": PASSWORD},
        "targetBaseUrl": TARGET_BASE_URL,
        "fakeClientResponse": {"status": 200, "headers": ["Content-Type:text/plain"], "body": FORWARDED_BODY},
        "server": {"scenarios": scenarios},
        "client": {"cases": cases},
    }


def render(value, level=0):
    """json.dumps(indent=2), except that an object or array holding only scalars stays on one line."""
    pad = "  " * (level + 1)

    def scalar(v):
        return not isinstance(v, (dict, list))

    if isinstance(value, (dict, list)) and value and all(scalar(v) for v in (
            value.values() if isinstance(value, dict) else value)):
        line = json.dumps(value, ensure_ascii=False)
        if len(line) <= 160:
            return line
    if isinstance(value, dict):
        if not value:
            return "{}"
        items = [f"{pad}{json.dumps(k, ensure_ascii=False)}: {render(v, level + 1)}" for k, v in value.items()]
        return "{\n" + ",\n".join(items) + "\n" + "  " * level + "}"
    if isinstance(value, list):
        if not value:
            return "[]"
        return "[\n" + ",\n".join(pad + render(v, level + 1) for v in value) + "\n" + "  " * level + "]"
    return json.dumps(value, ensure_ascii=False)


def main():
    document = build()
    path = VECTORS / "http-route-lifecycle-v1.json"
    text = render(document) + "\n"
    assert json.loads(text) == document
    path.write_text(text, encoding="utf-8", newline="\n")
    steps = sum(len(scenario["steps"]) for scenario in document["server"]["scenarios"])
    print(f"wrote {path}: scenarios={len(document['server']['scenarios'])} steps={steps} "
          f"clientCases={len(document['client']['cases'])}")


if __name__ == "__main__":
    main()
