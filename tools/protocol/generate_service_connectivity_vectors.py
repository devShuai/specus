"""Generate protocol/test-vectors/service-connectivity-check-v1.json.

What `POST /api/admin/http-routes/{id}/connectivity-check` answers for one route the owner chose:
the HTTP status of the API, and for a check that ran, the four stages in their fixed order --
configured, device online, target reachable, access succeeded -- each with its result, its stable
code and the elapsed milliseconds at which it was decided, stopping at the first stage that did not
pass. See protocol/spec/service-connectivity-check.md.

The point of the reference is the line between what the server knows and what it does not. Before
this contract every client answered an unreachable target with a NAT RST whose numeric value means
something different in each language and whose reason is free text; no server reads the value. No
client ever makes up a response head, so a server can tell "the device relayed the target's response
head" from "it did not" -- for any client version -- but not "the target refused the connection"
from "the device does not have the route". A client that announces
clientHttpRouteCapabilities.version >= 1 classifies the RST in metadata.failure; for an older one
the target stage is unverified, never passed.

Every expectation is produced by the reference below and checked against a hand-written table before
the file is written, so the vector cannot ship contradicting itself.
"""
import json
from pathlib import Path

VECTORS = Path("protocol/test-vectors")

CHECK_BUDGET_MS = 10_000
STAGES = ("configured", "device-online", "target-reachable", "access-succeeded")

# RST metadata.failure values a capable client sends for an HTTP stream it could not answer with a
# response head, and the stage and code the server reports for each.
FAILURES = {
    "route-not-loaded": ("device-online", "DEVICE_ROUTE_NOT_LOADED"),
    "target-invalid": ("target-reachable", "TARGET_ADDRESS_INVALID"),
    "connect-refused": ("target-reachable", "TARGET_CONNECT_REFUSED"),
    "connect-timeout": ("target-reachable", "TARGET_CONNECT_TIMEOUT"),
    "dns-failed": ("target-reachable", "TARGET_DNS_FAILED"),
    "tls-failed": ("target-reachable", "TARGET_TLS_FAILED"),
    "unreachable": ("target-reachable", "TARGET_UNREACHABLE"),
    "protocol-error": ("target-reachable", "TARGET_PROTOCOL_ERROR"),
}

# Rate limits: GCRA, one theoretical arrival time per key, integer milliseconds. A check must pass
# both keys; a refused check changes neither.
ROUTE_INTERVAL_MS = 10_000      # per (tenant, routeId): one check per 10 s, no burst
USER_INTERVAL_MS = 30_000       # per (tenant, username): one check per 30 s sustained ...
USER_BURST = 10                 # ... after a burst of 10
MAX_CONCURRENT_PER_ROUTE = 1
MAX_CONCURRENT_PER_SERVER = 32


def access_code(status):
    if 200 <= status <= 399:
        return "passed", "ACCESS_OK"
    if status in (401, 403, 407):
        # The target answered but wants its own credentials; the check never sends any.
        return "unverified", "ACCESS_AUTH_REQUIRED"
    if status in (404, 410):
        return "failed", "ACCESS_NOT_FOUND"
    if 400 <= status <= 499:
        return "failed", "ACCESS_CLIENT_ERROR"
    if 500 <= status <= 599:
        return "failed", "ACCESS_SERVER_ERROR"
    raise AssertionError(f"a response head with status {status} is a protocol error, not an answer")


def status_class(status):
    return f"{status // 100}xx"


def refuse(http_status, code, retry_after_ms=None):
    out = {"httpStatus": http_status}
    if code is not None:
        out["code"] = code
    if retry_after_ms is not None:
        out["retryAfterSeconds"] = max(1, -(-retry_after_ms // 1000))
    return out


def check(case):
    """The reference state machine. `case` holds only inputs; the result is what the API returns."""
    if not case.get("authenticated", True):
        return refuse(401, None)
    if not case.get("requestValid", True):
        return refuse(400, "CHECK_REQUEST_INVALID")
    if not case.get("configReadable", True):
        return refuse(503, "CHECK_UNAVAILABLE")
    if not case.get("routeVisible", True):
        return refuse(404, "CHECK_TARGET_NOT_FOUND")
    admission = case.get("admission", "admitted")
    if admission == "route-in-progress":
        return refuse(429, "CHECK_IN_PROGRESS", 1000)
    if admission == "server-busy":
        return refuse(503, "CHECK_BUSY", 1000)
    if admission != "admitted":
        raise AssertionError(admission)

    stages = []

    def decide(stage, result, code, at_ms):
        stages.append({"stage": stage, "result": result, "code": code, "atMs": at_ms})

    def finish(total_ms, requests, answered_status=None):
        decided = {entry["stage"] for entry in stages}
        for stage in STAGES:
            if stage not in decided:
                stages.append({"stage": stage, "result": "skipped"})
        last = [entry for entry in stages if entry["result"] != "skipped"][-1]
        outcome = {"passed": "succeeded", "failed": "failed", "unverified": "unverified"}[last["result"]]
        body = {
            "schemaVersion": 1,
            "kind": "http-route",
            "outcome": outcome,
            "stoppedAt": None if outcome == "succeeded" else last["stage"],
            "code": last["code"],
            "totalMs": total_ms,
            "requests": requests,
            "stages": stages,
        }
        if answered_status is not None:
            body["statusClass"] = status_class(answered_status)
        return {"httpStatus": 200, "body": body}

    route = case["route"]
    device = case["device"]

    # Stage 1: configured -- server records only.
    if not route.get("enabled", True):
        decide("configured", "failed", "ROUTE_DISABLED", 0)
        return finish(0, [])
    if not device.get("enabled", True):
        decide("configured", "failed", "CLIENT_DISABLED", 0)
        return finish(0, [])
    if not route.get("targetValid", True):
        decide("configured", "failed", "ROUTE_TARGET_INVALID", 0)
        return finish(0, [])
    decide("configured", "passed", "CONFIGURED", 0)

    # Stage 2 precondition: an authenticated control session and its data connection.
    if not device.get("controlOnline", True):
        decide("device-online", "failed", "DEVICE_OFFLINE", 0)
        return finish(0, [])
    if not device.get("dataOnline", True):
        decide("device-online", "failed", "DEVICE_DATA_CHANNEL_DOWN", 0)
        return finish(0, [])

    capable = (device.get("httpRouteCapability") or 0) >= 1
    answers = list(case["answers"])
    requests = []

    def ask(method):
        requests.append(method)
        answer = answers.pop(0)
        at_ms = answer.get("atMs")
        if answer["kind"] != "none" and (at_ms is None or at_ms >= CHECK_BUDGET_MS):
            raise AssertionError("an answer at or after the budget is not an answer; use kind none")
        return answer

    head = ask("HEAD")
    kind = head["kind"]
    if kind == "open-failed":
        # The stream could not even be handed to the device: the connection was not writable, or
        # it already carries as many streams as this server allows.
        code = {"write-failed": "DEVICE_LINK_LOST", "stream-limit": "DEVICE_BUSY"}[head["cause"]]
        decide("device-online", "failed", code, head["atMs"])
        return finish(head["atMs"], requests)
    if kind == "none":
        decide("device-online", "passed", "DEVICE_ONLINE", CHECK_BUDGET_MS)
        decide("target-reachable", "failed", "TARGET_TIMEOUT", CHECK_BUDGET_MS)
        return finish(CHECK_BUDGET_MS, requests)
    at = head["atMs"]
    if kind == "link-lost":
        decide("device-online", "failed", "DEVICE_LINK_LOST", at)
        return finish(at, requests)
    if kind == "rst":
        failure = head.get("failure")
        if capable and failure in FAILURES:
            stage, code = FAILURES[failure]
            if stage == "device-online":
                decide("device-online", "failed", code, at)
                return finish(at, requests)
            decide("device-online", "passed", "DEVICE_ONLINE", at)
            decide("target-reachable", "failed", code, at)
            return finish(at, requests)
        # An older client, or a classification this server does not know: the device answered,
        # but nothing says whether the target was ever reached.
        decide("device-online", "passed", "DEVICE_ONLINE", at)
        decide("target-reachable", "unverified", "TARGET_UNVERIFIED", at)
        return finish(at, requests)
    if kind != "response":
        raise AssertionError(kind)

    status = head["status"]
    decide("device-online", "passed", "DEVICE_ONLINE", at)
    decide("target-reachable", "passed", "TARGET_ANSWERED", at)
    if status in (405, 501):
        get = ask("GET")
        if get["kind"] == "response":
            result, code = access_code(get["status"])
            decide("access-succeeded", result, code, get["atMs"])
            return finish(get["atMs"], requests, get["status"])
        # No head for the GET: the target answered HEAD, so it is reachable; the access itself did
        # not complete. statusClass describes the request that decided the access stage, and that
        # request has no status, so it is absent.
        if get["kind"] == "none":
            decide("access-succeeded", "failed", "ACCESS_NO_ANSWER", CHECK_BUDGET_MS)
            return finish(CHECK_BUDGET_MS, requests)
        decide("access-succeeded", "failed", "ACCESS_NO_ANSWER", get["atMs"])
        return finish(get["atMs"], requests)
    result, code = access_code(status)
    decide("access-succeeded", result, code, at)
    return finish(at, requests, status)


def device(**overrides):
    base = {"enabled": True, "controlOnline": True, "dataOnline": True, "httpRouteCapability": 1}
    base.update(overrides)
    return base


ROUTE = {"enabled": True, "targetValid": True}


def response(status, at_ms):
    return {"kind": "response", "status": status, "atMs": at_ms}


def rst(failure, at_ms):
    answer = {"kind": "rst", "atMs": at_ms}
    if failure is not None:
        answer["failure"] = failure
    return answer


NONE = {"kind": "none"}

CASES = [
    # name, inputs, note
    ("head-200", {"route": ROUTE, "device": device(), "answers": [response(200, 42)]},
     "The common case: HEAD answered 2xx. One request, every stage passed at the moment the head arrived."),
    ("head-redirect-not-followed", {"route": ROUTE, "device": device(), "answers": [response(302, 30)]},
     "A redirect is an answer. It is not followed: the Location may point anywhere."),
    ("head-405-get-200", {"route": ROUTE, "device": device(), "answers": [response(405, 25), response(200, 61)]},
     "HEAD refused by method: one GET follows, its body is never read. The target stage is decided by "
     "the HEAD answer, the access stage by the GET."),
    ("head-501-get-404", {"route": ROUTE, "device": device(), "answers": [response(501, 25), response(404, 50)]},
     "Only 405 and 501 trigger the fallback; the GET status decides the access stage."),
    ("head-405-get-timeout", {"route": ROUTE, "device": device(), "answers": [response(405, 9000), NONE]},
     "The GET shares the one budget with the HEAD: it has what is left."),
    ("head-405-get-reset", {"route": ROUTE, "device": device(), "answers": [response(405, 20), rst("connect-refused", 40)]},
     "The target answered the HEAD, so it is reachable; the access did not complete."),
    ("head-404", {"route": ROUTE, "device": device(), "answers": [response(404, 18)]},
     "404 on HEAD does not trigger GET: the path is the problem, not the method."),
    ("head-401", {"route": ROUTE, "device": device(), "answers": [response(401, 18)]},
     "The target asks for its own credentials. The check never sends any."),
    ("head-400", {"route": ROUTE, "device": device(), "answers": [response(400, 18)]}, ""),
    ("head-502-from-target", {"route": ROUTE, "device": device(), "answers": [response(502, 18)]},
     "A capable client never makes up a response head, so a 502 here came from the target (a proxy in "
     "front of a dead backend): reachable, access failed."),
    ("route-disabled", {"route": {"enabled": False, "targetValid": True}, "device": device(), "answers": []},
     "Stops at the first stage; nothing is sent to the device."),
    ("client-disabled", {"route": ROUTE, "device": device(enabled=False), "answers": []}, ""),
    ("target-invalid", {"route": {"enabled": True, "targetValid": False}, "device": device(), "answers": []},
     "Defensive: management rejects such a target on save, but a stored row may predate that check."),
    ("device-offline", {"route": ROUTE, "device": device(controlOnline=False, dataOnline=False), "answers": []}, ""),
    ("data-channel-down", {"route": ROUTE, "device": device(dataOnline=False), "answers": []},
     "Control session present, no data connection: the device cannot carry a stream."),
    ("route-not-loaded", {"route": ROUTE, "device": device(), "answers": [rst("route-not-loaded", 3)]},
     "The device has not applied the route yet (configuration push lagging or failed)."),
    ("link-lost", {"route": ROUTE, "device": device(), "answers": [{"kind": "link-lost", "atMs": 700}]},
     "The data connection closed before any answer: the device stage fails, the target is unknown."),
    ("open-write-failed", {"route": ROUTE, "device": device(), "answers": [{"kind": "open-failed", "cause": "write-failed", "atMs": 0}]},
     "Writing the OPEN failed: the connection went away between the online check and the write."),
    ("open-stream-limit", {"route": ROUTE, "device": device(), "answers": [{"kind": "open-failed", "cause": "stream-limit", "atMs": 0}]},
     "The device's data connection already carries as many streams as this server allows. The probe "
     "shares that limit with public requests and does not get a reserved slot."),
    ("connect-refused", {"route": ROUTE, "device": device(), "answers": [rst("connect-refused", 4)]}, ""),
    ("connect-timeout", {"route": ROUTE, "device": device(), "answers": [rst("connect-timeout", 5004)]},
     "The client's own connect timeout fired inside the budget."),
    ("dns-failed", {"route": ROUTE, "device": device(), "answers": [rst("dns-failed", 80)]}, ""),
    ("tls-failed", {"route": ROUTE, "device": device(), "answers": [rst("tls-failed", 33)]}, ""),
    ("unreachable", {"route": ROUTE, "device": device(), "answers": [rst("unreachable", 2)]}, ""),
    ("target-invalid-on-device", {"route": ROUTE, "device": device(), "answers": [rst("target-invalid", 1)]},
     "The device has the route but cannot build a usable target from it, e.g. its parser is stricter "
     "than the server's validation."),
    ("protocol-error", {"route": ROUTE, "device": device(), "answers": [rst("protocol-error", 15)]},
     "Connected, but no HTTP response head came back: typically http:// pointed at a TLS port, or a "
     "port that is not HTTP at all."),
    ("budget-expired", {"route": ROUTE, "device": device(), "answers": [NONE]},
     "No answer within the budget. The device was online and the stream was written; the target did "
     "not produce a response head in time."),
    ("capable-unknown-failure", {"route": ROUTE, "device": device(), "answers": [rst("something-newer", 9)]},
     "A classification this server does not know is not a success and not a guess: unverified."),
    ("capable-unclassified", {"route": ROUTE, "device": device(), "answers": [rst(None, 9)]},
     "A capable client resetting for a reason outside the closed set (internal error, local limit)."),
    ("legacy-client-reset", {"route": ROUTE, "device": device(httpRouteCapability=0), "answers": [rst(None, 4)]},
     "An older client: its reset carries only free text, so the target stage is unverified, never passed."),
    ("legacy-client-reset-ignores-failure", {"route": ROUTE, "device": device(httpRouteCapability=0),
                                             "answers": [rst("connect-refused", 4)]},
     "A failure value from a session that did not announce the capability is not trusted."),
    ("legacy-client-answer", {"route": ROUTE, "device": device(httpRouteCapability=None), "answers": [response(204, 12)]},
     "An older client relays a real response head unchanged; a head is proof the target answered."),
    ("unauthenticated", {"authenticated": False}, ""),
    ("bad-request", {"requestValid": False}, "Unknown fields, a body that is not a JSON object, or a probe path that breaks the rules."),
    ("not-visible", {"routeVisible": False},
     "A route that does not exist and a route of another tenant or owner answer alike."),
    ("config-unreadable", {"configReadable": False},
     "A read failure is not reported as 'not configured'."),
    ("route-in-progress", {"admission": "route-in-progress"}, ""),
    ("server-busy", {"admission": "server-busy"}, ""),
]

# Hand-written expectations: (httpStatus, outcome or API code, stoppedAt, code, totalMs, requests)
EXPECTED = {
    "head-200": (200, "succeeded", None, "ACCESS_OK", 42, ["HEAD"]),
    "head-redirect-not-followed": (200, "succeeded", None, "ACCESS_OK", 30, ["HEAD"]),
    "head-405-get-200": (200, "succeeded", None, "ACCESS_OK", 61, ["HEAD", "GET"]),
    "head-501-get-404": (200, "failed", "access-succeeded", "ACCESS_NOT_FOUND", 50, ["HEAD", "GET"]),
    "head-405-get-timeout": (200, "failed", "access-succeeded", "ACCESS_NO_ANSWER", 10000, ["HEAD", "GET"]),
    "head-405-get-reset": (200, "failed", "access-succeeded", "ACCESS_NO_ANSWER", 40, ["HEAD", "GET"]),
    "head-404": (200, "failed", "access-succeeded", "ACCESS_NOT_FOUND", 18, ["HEAD"]),
    "head-401": (200, "unverified", "access-succeeded", "ACCESS_AUTH_REQUIRED", 18, ["HEAD"]),
    "head-400": (200, "failed", "access-succeeded", "ACCESS_CLIENT_ERROR", 18, ["HEAD"]),
    "head-502-from-target": (200, "failed", "access-succeeded", "ACCESS_SERVER_ERROR", 18, ["HEAD"]),
    "route-disabled": (200, "failed", "configured", "ROUTE_DISABLED", 0, []),
    "client-disabled": (200, "failed", "configured", "CLIENT_DISABLED", 0, []),
    "target-invalid": (200, "failed", "configured", "ROUTE_TARGET_INVALID", 0, []),
    "device-offline": (200, "failed", "device-online", "DEVICE_OFFLINE", 0, []),
    "data-channel-down": (200, "failed", "device-online", "DEVICE_DATA_CHANNEL_DOWN", 0, []),
    "route-not-loaded": (200, "failed", "device-online", "DEVICE_ROUTE_NOT_LOADED", 3, ["HEAD"]),
    "link-lost": (200, "failed", "device-online", "DEVICE_LINK_LOST", 700, ["HEAD"]),
    "open-write-failed": (200, "failed", "device-online", "DEVICE_LINK_LOST", 0, ["HEAD"]),
    "open-stream-limit": (200, "failed", "device-online", "DEVICE_BUSY", 0, ["HEAD"]),
    "connect-refused": (200, "failed", "target-reachable", "TARGET_CONNECT_REFUSED", 4, ["HEAD"]),
    "connect-timeout": (200, "failed", "target-reachable", "TARGET_CONNECT_TIMEOUT", 5004, ["HEAD"]),
    "dns-failed": (200, "failed", "target-reachable", "TARGET_DNS_FAILED", 80, ["HEAD"]),
    "tls-failed": (200, "failed", "target-reachable", "TARGET_TLS_FAILED", 33, ["HEAD"]),
    "unreachable": (200, "failed", "target-reachable", "TARGET_UNREACHABLE", 2, ["HEAD"]),
    "target-invalid-on-device": (200, "failed", "target-reachable", "TARGET_ADDRESS_INVALID", 1, ["HEAD"]),
    "protocol-error": (200, "failed", "target-reachable", "TARGET_PROTOCOL_ERROR", 15, ["HEAD"]),
    "budget-expired": (200, "failed", "target-reachable", "TARGET_TIMEOUT", 10000, ["HEAD"]),
    "capable-unknown-failure": (200, "unverified", "target-reachable", "TARGET_UNVERIFIED", 9, ["HEAD"]),
    "capable-unclassified": (200, "unverified", "target-reachable", "TARGET_UNVERIFIED", 9, ["HEAD"]),
    "legacy-client-reset": (200, "unverified", "target-reachable", "TARGET_UNVERIFIED", 4, ["HEAD"]),
    "legacy-client-reset-ignores-failure": (200, "unverified", "target-reachable", "TARGET_UNVERIFIED", 4, ["HEAD"]),
    "legacy-client-answer": (200, "succeeded", None, "ACCESS_OK", 12, ["HEAD"]),
    "unauthenticated": (401, None),
    "bad-request": (400, "CHECK_REQUEST_INVALID"),
    "not-visible": (404, "CHECK_TARGET_NOT_FOUND"),
    "config-unreadable": (503, "CHECK_UNAVAILABLE"),
    "route-in-progress": (429, "CHECK_IN_PROGRESS"),
    "server-busy": (503, "CHECK_BUSY"),
}


class Gcra:
    """Generic cell rate algorithm: one theoretical arrival time (TAT) per key, integer ms.
    A request at `now` conforms when now >= TAT - tolerance; conforming moves TAT to
    max(TAT, now) + interval. tolerance = (burst - 1) * interval."""

    def __init__(self, interval_ms, burst):
        self.interval = interval_ms
        self.tolerance = (burst - 1) * interval_ms
        self.tat = {}

    def wait_ms(self, key, now):
        tat = self.tat.get(key, now)
        return max(0, tat - self.tolerance - now)

    def take(self, key, now):
        tat = self.tat.get(key, now)
        self.tat[key] = max(tat, now) + self.interval


def rate_events():
    """A check must conform on both keys; a refusal consumes neither. Retry-After is the larger
    wait, rounded up to whole seconds (at least 1)."""
    per_route = Gcra(ROUTE_INTERVAL_MS, 1)
    per_user = Gcra(USER_INTERVAL_MS, USER_BURST)
    script = [
        (0, "alice", 1), (1, "alice", 1), (9_999, "alice", 1), (10_000, "alice", 1),
        # The route key belongs to the route, not the caller: a tenant admin checking the same
        # route right after the owner waits as well, so two people cannot double the probe rate.
        (10_000, "admin", 1),
        # Alice spreads over routes 2..9: the per-route key never binds, the per-user burst does.
        *[(10_000 + i, "alice", route) for i, route in enumerate(range(2, 10))],
        (10_008, "alice", 10),
        (20_000, "admin", 1),
        (40_000, "alice", 10),
        (40_000, "alice", 11),
    ]
    assert [at for at, _, _ in script] == sorted(at for at, _, _ in script), "events must replay in time order"
    events = []
    for at_ms, user, route in script:
        route_wait = per_route.wait_ms(route, at_ms)
        user_wait = per_user.wait_ms(user, at_ms)
        wait = max(route_wait, user_wait)
        if wait == 0:
            per_route.take(route, at_ms)
            per_user.take(user, at_ms)
            events.append({"atMs": at_ms, "username": user, "routeId": route, "admitted": True})
        else:
            events.append({"atMs": at_ms, "username": user, "routeId": route, "admitted": False,
                           "httpStatus": 429, "code": "CHECK_RATE_LIMITED",
                           "limitedBy": "route" if route_wait >= user_wait else "user",
                           "retryAfterSeconds": max(1, -(-wait // 1000))})
    return events


RATE_EXPECTED = [
    (True, None, None), (False, "route", 10), (False, "route", 1), (True, None, None),
    (False, "route", 10),
    *[(True, None, None)] * 8,
    # Ten admitted for alice by 10_007: her TAT is 300_000, tolerance 270_000.
    (False, "user", 20),
    (True, None, None),
    (True, None, None), (False, "user", 20),
]


def summarize(expected_out):
    if expected_out["httpStatus"] != 200:
        return (expected_out["httpStatus"], expected_out.get("code"))
    body = expected_out["body"]
    return (200, body["outcome"], body["stoppedAt"], body["code"], body["totalMs"], body["requests"])


def build():
    cases = []
    for name, inputs, note in CASES:
        out = check(inputs)
        assert summarize(out) == EXPECTED[name], (name, summarize(out), EXPECTED[name])
        if out["httpStatus"] == 200:
            body = out["body"]
            # Stages appear in the fixed order; nothing after the first non-passed stage is decided.
            assert [entry["stage"] for entry in body["stages"]] == list(STAGES), name
            results = [entry["result"] for entry in body["stages"]]
            first_stop = next((i for i, r in enumerate(results) if r != "passed"), len(results))
            assert all(r == "skipped" for r in results[first_stop + 1:]), name
            assert all(r == "passed" for r in results[:first_stop]), name
            times = [entry["atMs"] for entry in body["stages"] if "atMs" in entry]
            assert times == sorted(times) and times[-1] == body["totalMs"] <= CHECK_BUDGET_MS, name
            # Never a success without a response head relayed by the device.
            if body["outcome"] == "succeeded":
                assert "statusClass" in body and body["requests"], name
        case = {"name": name}
        if note:
            case["note"] = note
        case["input"] = inputs
        case["expect"] = out
        cases.append(case)
    assert set(EXPECTED) == {case["name"] for case in cases}

    codes_used = {case["expect"]["body"]["code"] for case in cases if case["expect"]["httpStatus"] == 200}
    stage_codes = {
        "configured": ["CONFIGURED", "ROUTE_DISABLED", "CLIENT_DISABLED", "ROUTE_TARGET_INVALID"],
        "device-online": ["DEVICE_ONLINE", "DEVICE_OFFLINE", "DEVICE_DATA_CHANNEL_DOWN", "DEVICE_BUSY",
                          "DEVICE_ROUTE_NOT_LOADED", "DEVICE_LINK_LOST"],
        "target-reachable": ["TARGET_ANSWERED", "TARGET_CONNECT_REFUSED", "TARGET_CONNECT_TIMEOUT",
                             "TARGET_DNS_FAILED", "TARGET_TLS_FAILED", "TARGET_UNREACHABLE",
                             "TARGET_ADDRESS_INVALID", "TARGET_PROTOCOL_ERROR", "TARGET_TIMEOUT",
                             "TARGET_UNVERIFIED"],
        "access-succeeded": ["ACCESS_OK", "ACCESS_AUTH_REQUIRED", "ACCESS_NOT_FOUND", "ACCESS_CLIENT_ERROR",
                             "ACCESS_SERVER_ERROR", "ACCESS_NO_ANSWER"],
    }
    pass_codes = {"CONFIGURED", "DEVICE_ONLINE", "TARGET_ANSWERED"}
    every_code = {code for codes in stage_codes.values() for code in codes}
    # Every terminal code in the table is exercised by at least one case, and no case uses a code
    # outside the table.
    assert codes_used <= every_code, codes_used - every_code
    assert every_code - pass_codes <= codes_used, (every_code - pass_codes) - codes_used
    for case in cases:
        if case["expect"]["httpStatus"] != 200:
            continue
        for entry in case["expect"]["body"]["stages"]:
            if entry["result"] != "skipped":
                assert entry["code"] in stage_codes[entry["stage"]], (case["name"], entry)

    events = rate_events()
    got = [(e["admitted"], e.get("limitedBy"), e.get("retryAfterSeconds")) for e in events]
    assert got == RATE_EXPECTED, got

    # The API refusals, in the order the server evaluates them; each earlier refusal hides the
    # later ones and none of them consumes rate. Every one except the rate limit is a case above.
    api_refusals = [
        {"order": 1, "when": "no valid management session", "httpStatus": 401},
        {"order": 2, "when": "body or path invalid", "httpStatus": 400, "code": "CHECK_REQUEST_INVALID"},
        {"order": 3, "when": "route, client or online state cannot be read", "httpStatus": 503, "code": "CHECK_UNAVAILABLE"},
        {"order": 4, "when": "route absent or not visible to the caller", "httpStatus": 404, "code": "CHECK_TARGET_NOT_FOUND"},
        {"order": 5, "when": "a check of the same route is running", "httpStatus": 429, "code": "CHECK_IN_PROGRESS"},
        {"order": 6, "when": "the process runs its maximum of concurrent checks", "httpStatus": 503, "code": "CHECK_BUSY"},
        {"order": 7, "when": "rate limit (see rate)", "httpStatus": 429, "code": "CHECK_RATE_LIMITED"},
    ]
    refused = {(c["expect"]["httpStatus"], c["expect"].get("code")) for c in cases if c["expect"]["httpStatus"] != 200}
    assert refused == {(r["httpStatus"], r.get("code")) for r in api_refusals if r["order"] != 7}, refused
    assert check({"authenticated": False, "requestValid": False, "configReadable": False, "routeVisible": False})["httpStatus"] == 401
    assert check({"requestValid": False, "routeVisible": False})["httpStatus"] == 400
    assert check({"configReadable": False, "routeVisible": False})["httpStatus"] == 503
    assert check({"routeVisible": False, "admission": "route-in-progress"})["httpStatus"] == 404

    return {
        "name": "service-connectivity-check-v1",
        "version": 1,
        "description": "What POST /api/admin/http-routes/{id}/connectivity-check returns for one explicitly "
                       "selected route: the API status, and for a check that ran, four stages in fixed order "
                       "with result, stable code and the elapsed ms at which each was decided, stopping at the "
                       "first stage that did not pass. See protocol/spec/service-connectivity-check.md.",
        "notes": [
            "input.answers 是设备对每个探测请求的回应，按发送顺序：response（设备转来的响应头，status 为状态码）、"
            "rst（响应头之前的 RST，failure 为 metadata.failure，缺省表示没有分类）、link-lost（回应之前数据连接断开）、"
            "open-failed（探测流没能交给设备：cause 为 write-failed 或 stream-limit）、"
            "none（预算内没有回应）。atMs 是自检查开始的毫秒数，由测试注入的单调时钟给出。",
            "device.httpRouteCapability 是该会话登录时声明的 environment.clientHttpRouteCapabilities.version；"
            "缺省或 0 表示旧客户端，此时 RST 一律不可信分类，目标阶段为 unverified。",
            "HEAD 只在 405 或 501 时追加一次 GET；两次请求共用一个预算。GET 的响应体从不读取：收到响应头立即 RST。",
            "stages[].atMs 是该阶段结论确定的时刻；skipped 的阶段没有 code 与 atMs。totalMs 等于最后一个已决阶段的 atMs。",
            "rate.events 按时间顺序重放，同一个限流器实例贯穿全部事件；两个键都放行才算放行，被拒的请求不消耗任何一个键。",
            "expect.body 不含运行时字段 routeId 与 checkedAt；实现返回它们，其余字段逐一相等。",
        ],
        "checkBudgetMs": CHECK_BUDGET_MS,
        "stages": list(STAGES),
        "stageCodes": stage_codes,
        "rstFailures": {failure: {"stage": stage, "code": code} for failure, (stage, code) in FAILURES.items()},
        "headFallbackStatuses": [405, 501],
        "apiRefusals": api_refusals,
        "cases": cases,
        "rate": {
            "algorithm": "gcra",
            "perRoute": {"key": "tenantId+routeId", "intervalMs": ROUTE_INTERVAL_MS, "burst": 1},
            "perUser": {"key": "tenantId+username", "intervalMs": USER_INTERVAL_MS, "burst": USER_BURST},
            "maxConcurrentPerRoute": MAX_CONCURRENT_PER_ROUTE,
            "maxConcurrentPerServer": MAX_CONCURRENT_PER_SERVER,
            "events": events,
        },
    }


def main():
    document = build()
    path = VECTORS / "service-connectivity-check-v1.json"
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {path}: cases={len(document['cases'])} rateEvents={len(document['rate']['events'])}")


if __name__ == "__main__":
    main()
