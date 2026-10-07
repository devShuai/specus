"""Generate protocol/test-vectors/product-metrics-v1.json: the opt-in product metrics contract.

Issue #38 asks four questions -- how long first-time onboarding takes, where people drop out of it,
transfer success by file size range and path, and whether retrying a failed transfer helps -- under
a hard privacy line: off by default, no credentials, file names, text or internal addresses, a stated
retention and a way to delete everything. See protocol/spec/product-metrics.md.

The contract answers the questions with as little as possible:

* Onboarding milestones are observed by the server on its own write paths (account created, first
  sign-in, first credential, first client login, first published service). The browser reports
  nothing about onboarding. A per-user progress row exists only for the 14-day onboarding window and
  is folded into a daily cohort counter when the user completes or the window ends.
* Transfer outcomes are known only to the sending browser. It reports one event per finished attempt
  with five closed-enum fields; the server validates the closed schema and only increments a daily
  counter. No raw event is ever stored.
* Everything is per tenant, switched on by a tenant ADMIN after acknowledging the disclosure.

Every server replays the scenarios with its own store and a fixed clock and compares the observable
responses and the store contents at each checkpoint. The reference below produces every expectation
and is checked against hand-computed numbers before the file is written.
"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

VECTORS = Path("protocol/test-vectors")
MIB = 1 << 20
WINDOW = timedelta(days=14)
RETENTION_DAYS = 180
MAX_BODY_BYTES = 4096
MAX_EVENTS = 20
MAX_RANGE_DAYS = 180
DISCLOSURE_VERSION = 1
DEFAULT_LIMITS = {"perUserEventsPerMinute": 120, "perTenantEventsPerMinute": 3000}

STEPS = ("account_created", "signed_in", "credential_created", "client_online", "service_published")
MODES = ("device", "link")
PATHS = ("direct", "turn", "cloud", "unestablished")
ATTEMPTS = ("first", "retry_after_failure", "retry_after_cancel")
OUTCOMES = ("success", "failure", "cancelled")
# (name, smallest size in bytes, largest size in bytes or None)
SIZE_BUCKETS = (
    ("lt1m", 1, MIB - 1),
    ("1m-16m", MIB, 16 * MIB - 1),
    ("16m-128m", 16 * MIB, 128 * MIB),
    ("128m-512m", 128 * MIB + 1, 512 * MIB),
    ("gt512m", 512 * MIB + 1, None),
)
# (name, lower bound inclusive, upper bound exclusive) in seconds
DURATION_BUCKETS = (
    ("lt10m", 0, 600),
    ("10m-30m", 600, 1800),
    ("30m-2h", 1800, 7200),
    ("2h-24h", 7200, 86400),
    ("1d-3d", 86400, 259200),
    ("3d-14d", 259200, int(WINDOW.total_seconds())),
)
EVENT_KEYS = {"mode", "path", "sizeBucket", "attempt", "outcome"}
SIZE_NAMES = tuple(name for name, _, _ in SIZE_BUCKETS)
DURATION_NAMES = tuple(name for name, _, _ in DURATION_BUCKETS)


def instant(text):
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def stamp(value):
    return None if value is None else value.strftime("%Y-%m-%dT%H:%M:%SZ")


def day_of(value):
    return value.strftime("%Y-%m-%d")


def parse_day(text):
    return datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc)


def size_bucket(size):
    """The bucket of a file size, or None: an empty or negative size never produces an event."""
    if type(size) is not int or size < 1:
        return None
    for name, low, high in SIZE_BUCKETS:
        if size >= low and (high is None or size <= high):
            return name
    raise AssertionError(size)


def duration_bucket(seconds):
    """Completion time bucket. Skew between instances can make it negative: clamp to zero."""
    seconds = max(0, seconds)
    for name, low, high in DURATION_BUCKETS:
        if low <= seconds < high:
            return name
    return None  # at or past the window: not a completion


def rate_bp(numerator, denominator):
    """Basis points rounded half up; null without a denominator."""
    if denominator == 0:
        return None
    return (20000 * numerator + denominator) // (2 * denominator)


def valid_event(event):
    if not isinstance(event, dict) or set(event) != EVENT_KEYS:
        return False
    if any(not isinstance(value, str) for value in event.values()):
        return False
    if (event["mode"] not in MODES or event["path"] not in PATHS or event["sizeBucket"] not in SIZE_NAMES
            or event["attempt"] not in ATTEMPTS or event["outcome"] not in OUTCOMES):
        return False
    if event["mode"] == "link" and event["path"] not in ("cloud", "unestablished"):
        return False
    if event["outcome"] == "success" and event["path"] == "unestablished":
        return False
    return True


def parse_ingest(body_text):
    """(error status, code) or the list of events. Size is checked on the raw bytes before parsing."""
    if len(body_text.encode("utf-8")) > MAX_BODY_BYTES:
        return (413, "PRODUCT_METRICS_TOO_LARGE")
    try:
        document = json.loads(body_text)
    except ValueError:
        return (400, "PRODUCT_METRICS_INVALID")
    if not isinstance(document, dict) or set(document) != {"schemaVersion", "events"}:
        return (400, "PRODUCT_METRICS_INVALID")
    if type(document["schemaVersion"]) is not int or document["schemaVersion"] != 1:
        return (400, "PRODUCT_METRICS_INVALID")
    events = document["events"]
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        return (400, "PRODUCT_METRICS_INVALID")
    if not all(valid_event(event) for event in events):
        return (400, "PRODUCT_METRICS_INVALID")
    return events


def reached_step(row):
    """The furthest milestone recorded; later milestones imply the earlier ones (section 4.1)."""
    reached = 0
    for index, step in enumerate(STEPS):
        if step == "account_created" or step in row["steps"]:
            reached = index
    return STEPS[reached]


class Engine:
    """Single-instance reference of the server side: switch, hooks, ingest, sweep, purge and summary."""

    def __init__(self, limits):
        self.limits = limits
        self.clock = None
        self.switches = {}     # tenant -> {"enabled", "updatedBy", "updatedAt", "purgedAt"}
        self.progress = {}     # (tenant, username) -> {"startedAt", "steps": {step: instant}}
        self.onboarding = {}   # (tenant, cohortDay, reachedStep, durationBucket) -> users
        self.transfers = {}    # (tenant, day, mode, path, sizeBucket, attempt, outcome) -> count
        self.windows = {}      # limiter key -> events used in the current minute

    # -- state -----------------------------------------------------------------------------------
    def load(self, state):
        for row in state.get("switches", []):
            self.switches[row["tenantId"]] = {"enabled": row["enabled"], "updatedBy": row["updatedBy"],
                                              "updatedAt": row["updatedAt"], "purgedAt": row["purgedAt"]}
        for row in state.get("progress", []):
            steps = {}
            for step, field in (("signed_in", "signedInAt"), ("credential_created", "credentialCreatedAt"),
                                ("client_online", "clientOnlineAt")):
                if row[field] is not None:
                    steps[step] = instant(row[field])
            self.progress[(row["tenantId"], row["username"])] = {"startedAt": instant(row["startedAt"]),
                                                                 "steps": steps}
        for row in state.get("onboardingDaily", []):
            self.onboarding[(row["tenantId"], row["cohortDay"], row["reachedStep"], row["durationBucket"])] = row["users"]
        for row in state.get("transferDaily", []):
            key = (row["tenantId"], row["day"], row["mode"], row["path"], row["sizeBucket"], row["attempt"], row["outcome"])
            self.transfers[key] = row["count"]

    def state(self):
        def step_at(row, step):
            return stamp(row["steps"].get(step))
        return {
            "switches": [{"tenantId": tenant, "enabled": row["enabled"], "updatedBy": row["updatedBy"],
                          "updatedAt": row["updatedAt"], "purgedAt": row["purgedAt"]}
                         for tenant, row in sorted(self.switches.items())],
            "progress": [{"tenantId": tenant, "username": user, "startedAt": stamp(row["startedAt"]),
                          "signedInAt": step_at(row, "signed_in"),
                          "credentialCreatedAt": step_at(row, "credential_created"),
                          "clientOnlineAt": step_at(row, "client_online")}
                         for (tenant, user), row in sorted(self.progress.items())],
            "onboardingDaily": [{"tenantId": k[0], "cohortDay": k[1], "reachedStep": k[2], "durationBucket": k[3],
                                 "users": v} for k, v in sorted(self.onboarding.items())],
            "transferDaily": [{"tenantId": k[0], "day": k[1], "mode": k[2], "path": k[3], "sizeBucket": k[4],
                               "attempt": k[5], "outcome": k[6], "count": v} for k, v in sorted(self.transfers.items())],
        }

    def enabled(self, tenant):
        return self.switches.get(tenant, {}).get("enabled", False)

    # -- settings --------------------------------------------------------------------------------
    def settings_view(self, tenant, admin):
        row = self.switches.get(tenant, {"enabled": False, "updatedBy": None, "updatedAt": None})
        view = {"schemaVersion": 1, "enabled": row["enabled"], "disclosureVersion": DISCLOSURE_VERSION,
                "retentionDays": RETENTION_DAYS, "onboardingWindowDays": WINDOW.days, "updatedAt": row["updatedAt"]}
        if admin:
            view["updatedBy"] = row["updatedBy"]
        return view

    def get_settings(self, at, actor):
        if actor is None:
            return {"status": 401}
        return {"status": 200, "body": self.settings_view(actor["tenantId"], actor["role"] == "ADMIN")}

    def put_settings(self, at, actor, body):
        if actor is None:
            return {"status": 401}
        if actor["role"] != "ADMIN":
            return {"status": 403}
        if (not isinstance(body, dict) or not set(body) <= {"enabled", "disclosureVersion"}
                or type(body.get("enabled")) is not bool
                or ("disclosureVersion" in body and type(body["disclosureVersion"]) is not int)):
            return {"status": 400, "body": {"code": "PRODUCT_METRICS_INVALID"}}
        if body["enabled"] and body.get("disclosureVersion") != DISCLOSURE_VERSION:
            return {"status": 400, "body": {"code": "PRODUCT_METRICS_DISCLOSURE_REQUIRED"}}
        tenant = actor["tenantId"]
        row = self.switches.setdefault(tenant, {"enabled": False, "updatedBy": None, "updatedAt": None, "purgedAt": None})
        if row["enabled"] != body["enabled"]:
            row.update(enabled=body["enabled"], updatedBy=actor["username"], updatedAt=stamp(at))
            if body["enabled"]:
                row["purgedAt"] = None
        if not body["enabled"]:
            self.drop_progress(tenant)
        return {"status": 200, "body": self.settings_view(tenant, True)}

    def purge(self, at, actor):
        if actor is None:
            return {"status": 401}
        if actor["role"] != "ADMIN":
            return {"status": 403}
        tenant = actor["tenantId"]
        self.delete_tenant_rows(tenant)
        row = self.switches.setdefault(tenant, {"enabled": False, "updatedBy": None, "updatedAt": None, "purgedAt": None})
        row["purgedAt"] = stamp(at)
        return {"status": 200, "body": {"purged": True, "enabled": row["enabled"]}}

    def drop_progress(self, tenant):
        for key in [key for key in self.progress if key[0] == tenant]:
            del self.progress[key]

    def delete_tenant_rows(self, tenant):
        self.drop_progress(tenant)
        for table in (self.onboarding, self.transfers):
            for key in [key for key in table if key[0] == tenant]:
                del table[key]

    # -- onboarding hooks ------------------------------------------------------------------------
    def close(self, key, completed_at=None):
        row = self.progress.pop(key)
        bucket = "none"
        if completed_at is not None:
            bucket = duration_bucket(int((completed_at - row["startedAt"]).total_seconds()))
            assert bucket is not None
        reached = "service_published" if completed_at is not None else reached_step(row)
        counter = (key[0], day_of(row["startedAt"]), reached, bucket)
        self.onboarding[counter] = self.onboarding.get(counter, 0) + 1

    def milestone(self, at, tenant, user, step):
        if not self.enabled(tenant):
            return "ignored"
        key = (tenant, user)
        row = self.progress.get(key)
        if step == "account_created":
            if row is None:
                self.progress[key] = {"startedAt": at, "steps": {}}
                return "started"
            return "ignored"
        if row is None:
            return "ignored"
        if at >= row["startedAt"] + WINDOW:
            self.close(key)
            return "expired"
        if step in row["steps"]:
            return "ignored"
        row["steps"][step] = at
        if step == "service_published":
            self.close(key, completed_at=at)
            return "completed"
        return "recorded"

    def user_deleted(self, at, tenant, user):
        return "deleted" if self.progress.pop((tenant, user), None) is not None else "ignored"

    # -- transfer ingest -------------------------------------------------------------------------
    def ingest(self, at, actor, body_text):
        if actor is None:
            return {"status": 401}
        parsed = parse_ingest(body_text)
        if isinstance(parsed, tuple):
            return {"status": parsed[0], "body": {"code": parsed[1]}}
        tenant, user = actor["tenantId"], actor["username"]
        if not self.enabled(tenant):
            return {"status": 200, "body": {"collecting": False, "accepted": 0}}
        minute = int(at.timestamp()) // 60
        user_key, tenant_key = ("user", tenant, user, minute), ("tenant", tenant, minute)
        count = len(parsed)
        if (self.windows.get(user_key, 0) + count > self.limits["perUserEventsPerMinute"]
                or self.windows.get(tenant_key, 0) + count > self.limits["perTenantEventsPerMinute"]):
            return {"status": 429, "body": {"code": "PRODUCT_METRICS_RATE_LIMITED"}}
        self.windows[user_key] = self.windows.get(user_key, 0) + count
        self.windows[tenant_key] = self.windows.get(tenant_key, 0) + count
        for event in parsed:
            key = (tenant, day_of(at), event["mode"], event["path"], event["sizeBucket"], event["attempt"], event["outcome"])
            self.transfers[key] = self.transfers.get(key, 0) + 1
        return {"status": 200, "body": {"collecting": True, "accepted": count}}

    # -- sweep -----------------------------------------------------------------------------------
    def sweep(self, at):
        for key in sorted(self.progress):
            if not self.enabled(key[0]):
                del self.progress[key]
            elif at >= self.progress[key]["startedAt"] + WINDOW:
                self.close(key)
        cutoff = day_of(at - timedelta(days=RETENTION_DAYS - 1))
        for table in (self.onboarding, self.transfers):
            for key in [key for key in table if key[1] < cutoff]:
                del table[key]
        for tenant, row in self.switches.items():
            if not row["enabled"] and row["purgedAt"] is not None:
                self.delete_tenant_rows(tenant)

    # -- summary ---------------------------------------------------------------------------------
    def summary(self, at, actor, query):
        if actor is None:
            return {"status": 401}
        if actor["role"] != "ADMIN":
            return {"status": 403}
        today = parse_day(day_of(at))
        to_day = parse_day(query["to"]) if "to" in query else today
        from_day = parse_day(query["from"]) if "from" in query else to_day - timedelta(days=29)
        if (from_day > to_day or (to_day - from_day).days + 1 > MAX_RANGE_DAYS or to_day > today
                or from_day < today - timedelta(days=RETENTION_DAYS - 1)):
            return {"status": 400, "body": {"code": "PRODUCT_METRICS_RANGE"}}
        tenant, low, high = actor["tenantId"], day_of(from_day), day_of(to_day)

        reached = {step: 0 for step in STEPS}
        durations = {name: 0 for name in DURATION_NAMES}
        pending = 0
        for (row_tenant, cohort, step, bucket), users in self.onboarding.items():
            if row_tenant == tenant and low <= cohort <= high:
                reached[step] += users
                if bucket != "none":
                    durations[bucket] += users
        for (row_tenant, _), row in self.progress.items():
            if row_tenant == tenant and low <= day_of(row["startedAt"]) <= high:
                reached[reached_step(row)] += 1
                if at < row["startedAt"] + WINDOW:
                    pending += 1
        steps, previous = [], None
        for index, step in enumerate(STEPS):
            users = sum(reached[later] for later in STEPS[index:])
            steps.append({"step": step, "users": users,
                          "fromPreviousRateBp": None if previous is None else rate_bp(users, previous)})
            previous = users
        cohort_users, completed = steps[0]["users"], steps[-1]["users"]
        ordered = [name for name in DURATION_NAMES for _ in range(durations[name])]
        onboarding = {
            "windowDays": WINDOW.days, "cohortUsers": cohort_users, "pendingUsers": pending, "final": pending == 0,
            "steps": steps, "completed": completed, "completionRateBp": rate_bp(completed, cohort_users),
            "durations": [{"bucket": name, "users": durations[name]} for name in DURATION_NAMES],
            "medianDurationBucket": ordered[(len(ordered) + 1) // 2 - 1] if ordered else None,
        }

        def tally(match):
            counts = {outcome: 0 for outcome in OUTCOMES}
            for key, count in self.transfers.items():
                if key[0] == tenant and low <= key[1] <= high and match(key):
                    counts[key[6]] += count
            counts["successRateBp"] = rate_bp(counts["success"], counts["success"] + counts["failure"])
            return counts

        cells = []
        for path in PATHS:
            for size in SIZE_NAMES:
                counts = tally(lambda key: key[3] == path and key[4] == size)
                if counts["success"] + counts["failure"] + counts["cancelled"]:
                    cells.append({"path": path, "sizeBucket": size, **counts})
        transfers = {
            "cells": cells,
            "byMode": [{"mode": mode, **tally(lambda key: key[2] == mode)} for mode in MODES],
            "byAttempt": [{"attempt": attempt, **tally(lambda key: key[5] == attempt)} for attempt in ATTEMPTS],
            "total": tally(lambda key: True),
        }
        return {"status": 200, "body": {"schemaVersion": 1, "enabled": self.enabled(tenant), "from": low, "to": high,
                                         "generatedAt": stamp(at), "onboarding": onboarding, "transfers": transfers}}

    # -- replay ----------------------------------------------------------------------------------
    def run(self, op):
        at = instant(op["at"])
        assert self.clock is None or at >= self.clock, op
        self.clock = at
        kind, actor = op["op"], op.get("actor")
        if kind == "putSettings":
            return self.put_settings(at, actor, op["body"])
        if kind == "getSettings":
            return self.get_settings(at, actor)
        if kind == "purge":
            return self.purge(at, actor)
        if kind == "milestone":
            return {"effect": self.milestone(at, op["tenantId"], op["username"], op["step"])}
        if kind == "userDeleted":
            return {"effect": self.user_deleted(at, op["tenantId"], op["username"])}
        if kind == "ingest":
            return self.ingest(at, actor, op["bodyText"])
        if kind == "sweep":
            self.sweep(at)
            return {}
        if kind == "summary":
            return self.summary(at, actor, op.get("query", {}))
        if kind == "checkpoint":
            return {"state": self.state()}
        raise AssertionError(kind)


# -- builders --------------------------------------------------------------------------------------
def ev(mode, path, size, attempt, outcome):
    return {"mode": mode, "path": path, "sizeBucket": size, "attempt": attempt, "outcome": outcome}


def body(events, **extra):
    return json.dumps({"schemaVersion": 1, "events": events, **extra}, separators=(",", ":"))


def actor(tenant, user, role="USER"):
    return {"tenantId": tenant, "username": user, "role": role}


ENABLE = {"enabled": True, "disclosureVersion": DISCLOSURE_VERSION}
DISABLE = {"enabled": False}
SAMPLE = ev("device", "direct", "lt1m", "first", "success")


def m(at, tenant, user, step):
    return {"op": "milestone", "at": at, "tenantId": tenant, "username": user, "step": step}


def journey(tenant, user, times):
    """Milestones in step order at the given times (a prefix of STEPS)."""
    return [m(at, tenant, user, step) for step, at in zip(STEPS, times)]


ROOT1, ROOT3 = actor("t1", "root", "ADMIN"), actor("t3", "root3", "ADMIN")

ONBOARDING_OPS = [
    m("2026-08-31T12:00:00Z", "t1", "mallory", "account_created"),  # before opt-in: never in a cohort
    {"op": "putSettings", "at": "2026-09-01T00:00:00Z", "actor": actor("t1", "alice"), "body": ENABLE},
    {"op": "putSettings", "at": "2026-09-01T00:00:00Z", "actor": ROOT1, "body": {"enabled": True}},
    {"op": "putSettings", "at": "2026-09-01T00:00:00Z", "actor": ROOT1, "body": {"enabled": True, "disclosureVersion": 2}},
    {"op": "putSettings", "at": "2026-09-01T00:00:00Z", "actor": ROOT1, "body": {"enabled": "true", "disclosureVersion": 1}},
    {"op": "putSettings", "at": "2026-09-01T00:00:00Z", "actor": ROOT1, "body": {**ENABLE, "retentionDays": 365}},
    {"op": "putSettings", "at": "2026-09-01T00:00:00Z", "actor": ROOT1, "body": ENABLE},
    {"op": "putSettings", "at": "2026-09-01T00:00:00Z", "actor": ROOT3, "body": ENABLE},
    {"op": "getSettings", "at": "2026-09-01T00:00:00Z", "actor": actor("t2", "grace")},  # never enabled
    *journey("t1", "alice", ["2026-09-01T08:00:00Z", "2026-09-01T08:01:00Z", "2026-09-01T08:05:00Z",
                             "2026-09-01T08:20:00Z", "2026-09-01T08:40:00Z"]),
    m("2026-09-01T08:41:00Z", "t1", "alice", "credential_created"),  # after completion: no row
    *journey("t1", "bob", ["2026-09-01T09:00:00Z", "2026-09-01T09:05:00Z", "2026-09-01T09:10:00Z"]),
    m("2026-09-01T10:00:00Z", "t1", "carol", "account_created"),
    m("2026-09-02T00:00:00Z", "t1", "mallory", "service_published"),
    m("2026-09-02T00:00:00Z", "t3", "kate", "account_created"),
    m("2026-09-02T09:30:00Z", "t1", "bob", "credential_created"),  # first occurrence is kept
    m("2026-09-02T10:00:00Z", "t1", "carol", "credential_created"),  # created for her before she signs in
    *journey("t1", "dave", ["2026-09-02T12:00:00Z", "2026-09-02T12:01:00Z", "2026-09-02T12:02:00Z",
                            "2026-09-02T12:03:00Z"]),
    m("2026-09-02T12:03:00Z", "t2", "grace", "account_created"),  # t2 never opted in
    *journey("t1", "erin", ["2026-09-03T00:00:00Z", "2026-09-03T00:00:30Z", "2026-09-03T00:02:00Z",
                            "2026-09-03T00:05:00Z", "2026-09-03T00:09:59Z"]),
    {"op": "putSettings", "at": "2026-09-03T00:10:00Z", "actor": ROOT3, "body": DISABLE},  # drops kate's row
    *journey("t1", "frank", ["2026-09-03T01:00:00Z", "2026-09-03T01:01:00Z", "2026-09-03T01:02:00Z",
                             "2026-09-03T01:03:00Z", "2026-09-03T01:10:00Z"]),
    m("2026-09-03T10:00:00Z", "t1", "carol", "client_online"),
    m("2026-09-03T12:00:00Z", "t3", "leo", "account_created"),  # t3 is off
    *journey("t1", "heidi", ["2026-09-04T00:00:00Z", "2026-09-04T00:10:00Z"]),
    {"op": "putSettings", "at": "2026-09-04T00:10:00Z", "actor": ROOT3, "body": ENABLE},
    {"op": "userDeleted", "at": "2026-09-05T00:00:00Z", "tenantId": "t1", "username": "heidi"},
    m("2026-09-05T00:00:00Z", "t3", "kate", "signed_in"),  # her row was dropped when t3 switched off
    *journey("t3", "nina", ["2026-09-06T00:00:00Z", "2026-09-06T00:01:00Z", "2026-09-06T00:02:00Z",
                            "2026-09-06T00:03:00Z", "2026-09-06T00:30:00Z"]),
    {"op": "checkpoint", "at": "2026-09-06T00:30:00Z"},
    m("2026-09-15T09:59:59Z", "t1", "carol", "service_published"),  # one second inside her window
    {"op": "sweep", "at": "2026-09-16T00:00:00Z"},  # bob's window ended 2026-09-15T09:00:00Z
    m("2026-09-16T12:00:00Z", "t1", "dave", "service_published"),  # exactly at the window end: expired
    *journey("t1", "ivan", ["2026-09-20T00:00:00Z", "2026-09-20T01:00:00Z"]),
    {"op": "purge", "at": "2026-09-20T02:00:00Z", "actor": actor("t3", "nina")},
    {"op": "purge", "at": "2026-09-20T02:00:00Z", "actor": ROOT3},
    {"op": "summary", "at": "2026-09-21T00:00:00Z", "actor": ROOT1, "query": {"from": "2026-09-01", "to": "2026-09-21"}},
    {"op": "summary", "at": "2026-09-21T00:00:00Z", "actor": ROOT1, "query": {"from": "2026-09-02", "to": "2026-09-03"}},
    {"op": "summary", "at": "2026-09-21T00:00:00Z", "actor": ROOT3, "query": {"from": "2026-09-01", "to": "2026-09-21"}},
    {"op": "summary", "at": "2026-09-21T00:00:00Z", "actor": actor("t1", "alice"), "query": {}},
    {"op": "summary", "at": "2026-09-21T00:00:00Z", "actor": ROOT1, "query": {"from": "2026-09-05", "to": "2026-09-04"}},
    {"op": "summary", "at": "2026-09-21T00:00:00Z", "actor": ROOT1, "query": {"from": "2026-09-01", "to": "2026-09-22"}},
    {"op": "summary", "at": "2026-09-21T00:00:00Z", "actor": ROOT1, "query": {"from": "2026-03-25", "to": "2026-09-21"}},
    {"op": "summary", "at": "2026-09-21T00:00:00Z", "actor": ROOT1, "query": {"from": "2026-03-26", "to": "2026-09-21"}},
    {"op": "getSettings", "at": "2026-09-21T00:00:00Z", "actor": actor("t1", "alice")},
    {"op": "getSettings", "at": "2026-09-21T00:00:00Z", "actor": ROOT1},
    {"op": "checkpoint", "at": "2026-09-21T00:00:00Z"},
]

R1 = [SAMPLE, SAMPLE, SAMPLE, ev("device", "direct", "16m-128m", "first", "failure"),
      ev("device", "turn", "1m-16m", "first", "success"), ev("device", "unestablished", "lt1m", "first", "failure")]
R2 = [ev("device", "direct", "16m-128m", "retry_after_failure", "success"), ev("device", "cloud", "16m-128m", "first", "success"),
      ev("link", "cloud", "128m-512m", "first", "success"), ev("link", "cloud", "gt512m", "first", "failure"),
      ev("device", "turn", "1m-16m", "first", "cancelled"), ev("device", "turn", "1m-16m", "retry_after_cancel", "success")]
R3 = [ev("device", "direct", "lt1m", "retry_after_failure", "failure"), ev("device", "turn", "lt1m", "retry_after_failure", "success"),
      ev("device", "unestablished", "lt1m", "retry_after_failure", "failure")]

TRANSFER_OPS = [
    {"op": "putSettings", "at": "2026-09-01T00:00:00Z", "actor": ROOT1, "body": ENABLE},
    {"op": "putSettings", "at": "2026-09-01T00:00:00Z", "actor": ROOT3, "body": ENABLE},
    {"op": "ingest", "at": "2026-09-10T10:00:00Z", "actor": actor("t1", "alice"), "bodyText": body(R1)},
    {"op": "ingest", "at": "2026-09-10T10:00:05Z", "actor": actor("t1", "alice"),
     "bodyText": body([SAMPLE, {**SAMPLE, "fileName": "a.txt"}])},
    {"op": "ingest", "at": "2026-09-10T10:00:06Z", "actor": None, "bodyText": body([SAMPLE])},
    {"op": "ingest", "at": "2026-09-10T11:00:00Z", "actor": actor("t2", "grace"), "bodyText": body([SAMPLE])},
    {"op": "ingest", "at": "2026-09-10T23:59:59Z", "actor": actor("t1", "bob"), "bodyText": body(R2)},
    {"op": "ingest", "at": "2026-09-11T00:00:00Z", "actor": actor("t1", "alice"), "bodyText": body(R3)},
    {"op": "ingest", "at": "2026-09-12T00:00:00Z", "actor": actor("t3", "nina"), "bodyText": body([SAMPLE, SAMPLE])},
    {"op": "putSettings", "at": "2026-09-13T00:00:00Z", "actor": ROOT3, "body": DISABLE},
    {"op": "ingest", "at": "2026-09-13T00:00:01Z", "actor": actor("t3", "nina"), "bodyText": body([SAMPLE])},
    {"op": "checkpoint", "at": "2026-09-13T00:00:01Z"},
    {"op": "purge", "at": "2026-09-13T00:01:00Z", "actor": ROOT3},
    {"op": "summary", "at": "2026-09-21T00:00:00Z", "actor": ROOT1, "query": {"from": "2026-09-01", "to": "2026-09-21"}},
    {"op": "summary", "at": "2026-09-21T00:00:00Z", "actor": ROOT1, "query": {"from": "2026-09-11", "to": "2026-09-21"}},
    {"op": "summary", "at": "2026-09-21T00:00:00Z", "actor": ROOT3, "query": {}},
    {"op": "putSettings", "at": "2026-09-21T00:00:00Z", "actor": ROOT3, "body": ENABLE},  # clears purgedAt
    {"op": "checkpoint", "at": "2026-09-21T00:00:00Z"},
]

RATE_OPS = [
    {"op": "putSettings", "at": "2026-09-01T00:00:00Z", "actor": ROOT1, "body": ENABLE},
    *[{"op": "ingest", "at": "2026-09-10T12:00:00Z", "actor": actor("t1", "alice"), "bodyText": body([SAMPLE] * 20)}
      for _ in range(5)],
    {"op": "ingest", "at": "2026-09-10T12:00:10Z", "actor": actor("t1", "alice"), "bodyText": body([SAMPLE] * 10)},
    {"op": "ingest", "at": "2026-09-10T12:00:20Z", "actor": actor("t1", "alice"), "bodyText": body([SAMPLE] * 20)},
    {"op": "ingest", "at": "2026-09-10T12:00:25Z", "actor": actor("t1", "alice"),
     "bodyText": body([{**SAMPLE, "path": "Direct"}])},  # validation precedes the limiter
    {"op": "ingest", "at": "2026-09-10T12:00:30Z", "actor": actor("t1", "alice"), "bodyText": body([SAMPLE] * 10)},
    {"op": "ingest", "at": "2026-09-10T12:00:40Z", "actor": actor("t1", "bob"), "bodyText": body([SAMPLE] * 20)},
    {"op": "ingest", "at": "2026-09-10T12:00:59Z", "actor": actor("t1", "alice"), "bodyText": body([SAMPLE])},
    {"op": "ingest", "at": "2026-09-10T12:01:00Z", "actor": actor("t1", "alice"), "bodyText": body([SAMPLE] * 20)},
    {"op": "checkpoint", "at": "2026-09-10T12:01:00Z"},
]

TENANT_RATE_OPS = [
    {"op": "putSettings", "at": "2026-09-01T00:00:00Z", "actor": ROOT1, "body": ENABLE},
    {"op": "ingest", "at": "2026-09-10T12:00:00Z", "actor": actor("t1", "alice"), "bodyText": body([SAMPLE] * 20)},
    {"op": "ingest", "at": "2026-09-10T12:00:01Z", "actor": actor("t1", "alice"), "bodyText": body([SAMPLE] * 10)},
    {"op": "ingest", "at": "2026-09-10T12:00:02Z", "actor": actor("t1", "alice"), "bodyText": body([SAMPLE])},
    {"op": "ingest", "at": "2026-09-10T12:00:03Z", "actor": actor("t1", "bob"), "bodyText": body([SAMPLE] * 20)},
    {"op": "ingest", "at": "2026-09-10T12:00:04Z", "actor": actor("t1", "carol"), "bodyText": body([SAMPLE])},
    {"op": "ingest", "at": "2026-09-10T12:00:05Z", "actor": actor("t2", "grace"), "bodyText": body([SAMPLE])},
    {"op": "checkpoint", "at": "2026-09-10T12:00:05Z"},
]


def switch(tenant, enabled, purged=None):
    return {"tenantId": tenant, "enabled": enabled, "updatedBy": "root", "updatedAt": "2026-03-01T00:00:00Z",
            "purgedAt": purged}


def transfer_row(tenant, day, count=1):
    return {"tenantId": tenant, "day": day, **SAMPLE, "count": count}


def progress_row(tenant, user, started, signed=None, credential=None, online=None):
    return {"tenantId": tenant, "username": user, "startedAt": started, "signedInAt": signed,
            "credentialCreatedAt": credential, "clientOnlineAt": online}


RETENTION_STATE = {
    "switches": [switch("t1", True), switch("t2", False), switch("t3", False, purged="2026-09-20T23:00:00Z")],
    "progress": [
        progress_row("t1", "olga", "2026-09-07T00:30:00Z", "2026-09-07T00:31:00Z", "2026-09-07T00:40:00Z"),
        progress_row("t1", "pavel", "2026-09-07T00:30:01Z", "2026-09-07T00:31:00Z"),
        progress_row("t2", "quinn", "2026-09-20T00:00:00Z"),  # left behind by a race with switching off
    ],
    "onboardingDaily": [
        {"tenantId": "t1", "cohortDay": "2026-03-25", "reachedStep": "service_published", "durationBucket": "lt10m", "users": 2},
        {"tenantId": "t1", "cohortDay": "2026-03-26", "reachedStep": "signed_in", "durationBucket": "none", "users": 1},
        {"tenantId": "t2", "cohortDay": "2026-09-01", "reachedStep": "signed_in", "durationBucket": "none", "users": 4},
        {"tenantId": "t3", "cohortDay": "2026-09-01", "reachedStep": "signed_in", "durationBucket": "none", "users": 3},
    ],
    "transferDaily": [transfer_row("t1", "2026-03-25", 7), transfer_row("t1", "2026-03-26", 5),
                      transfer_row("t1", "2026-09-21", 1), transfer_row("t2", "2026-09-20", 6),
                      transfer_row("t3", "2026-09-20", 9)],  # t3: a straggler written after the purge
}

SCENARIOS = [
    {"name": "onboarding-funnel", "limits": DEFAULT_LIMITS, "initialState": {}, "ops": ONBOARDING_OPS},
    {"name": "transfer-outcomes", "limits": DEFAULT_LIMITS, "initialState": {}, "ops": TRANSFER_OPS},
    {"name": "per-user-rate-limit", "limits": DEFAULT_LIMITS, "initialState": {}, "ops": RATE_OPS},
    {"name": "per-tenant-rate-limit", "limits": {"perUserEventsPerMinute": 30, "perTenantEventsPerMinute": 50},
     "initialState": {}, "ops": TENANT_RATE_OPS},
    {"name": "retention-sweep", "limits": DEFAULT_LIMITS, "initialState": RETENTION_STATE,
     "ops": [{"op": "sweep", "at": "2026-09-21T00:30:00Z"}, {"op": "checkpoint", "at": "2026-09-21T00:30:00Z"}]},
]


def pad(text, total):
    return text + " " * (total - len(text.encode("utf-8")))


VALID20 = body([SAMPLE] * 20)
VALIDATION = [
    ("accept-one", body([SAMPLE]), 1),
    ("accept-twenty", VALID20, 20),
    ("accept-reordered-keys-and-whitespace",
     '{ "events" : [ {"outcome":"cancelled", "attempt":"first", "sizeBucket":"gt512m", "path":"unestablished", '
     '"mode":"link"} ], "schemaVersion" : 1 }', 1),
    ("accept-device-falling-back-to-cloud", body([ev("device", "cloud", "16m-128m", "first", "success")]), 1),
    ("accept-cancel-before-a-path", body([ev("device", "unestablished", "lt1m", "retry_after_cancel", "cancelled")]), 1),
    ("accept-exactly-4096-bytes", pad(VALID20, MAX_BODY_BYTES), 20),
    ("reject-4097-bytes", pad(VALID20, MAX_BODY_BYTES + 1), (413, "PRODUCT_METRICS_TOO_LARGE")),
    ("reject-oversize-before-parsing", "x" * 5000, (413, "PRODUCT_METRICS_TOO_LARGE")),
    ("reject-not-json", "not json", None),
    ("reject-top-level-array", json.dumps([SAMPLE]), None),
    ("reject-empty-events", body([]), None),
    ("reject-21-events", body([SAMPLE] * 21), None),
    ("reject-events-not-array", json.dumps({"schemaVersion": 1, "events": SAMPLE}), None),
    ("reject-schema-version-2", json.dumps({"schemaVersion": 2, "events": [SAMPLE]}), None),
    ("reject-schema-version-string", json.dumps({"schemaVersion": "1", "events": [SAMPLE]}), None),
    ("reject-schema-version-boolean", json.dumps({"schemaVersion": True, "events": [SAMPLE]}), None),
    ("reject-missing-schema-version", json.dumps({"events": [SAMPLE]}), None),
    ("reject-tenant-in-body", body([SAMPLE], tenantId="t2"), None),
    ("reject-visitor-id-in-body", body([SAMPLE], visitorId="v-123"), None),
    ("reject-event-not-object", body(["direct"]), None),
    ("reject-file-name", body([{**SAMPLE, "fileName": "report.pdf"}]), None),
    ("reject-exact-size", body([{**SAMPLE, "sizeBytes": 1234}]), None),
    ("reject-mime-type", body([{**SAMPLE, "mimeType": "image/png"}]), None),
    ("reject-text-content", body([{**SAMPLE, "text": "hello"}]), None),
    ("reject-room-id", body([{**SAMPLE, "roomId": "r1"}]), None),
    ("reject-peer-id", body([{**SAMPLE, "peerId": "p1"}]), None),
    ("reject-client-ip", body([{**SAMPLE, "clientIp": "192.168.1.10"}]), None),
    ("reject-ice-candidate-address", body([{**SAMPLE, "candidate": "10.0.0.5:51234"}]), None),
    ("reject-user-agent", body([{**SAMPLE, "userAgent": "Mozilla/5.0"}]), None),
    ("reject-error-text", body([{**SAMPLE, "outcome": "failure", "error": "ICE failed"}]), None),
    ("reject-client-timestamp", body([{**SAMPLE, "at": "2026-09-10T10:00:00Z"}]), None),
    ("reject-event-id", body([{**SAMPLE, "eventId": "8c3e"}]), None),
    ("reject-duration", body([{**SAMPLE, "durationMs": 5300}]), None),
    ("reject-missing-outcome", body([{k: v for k, v in SAMPLE.items() if k != "outcome"}]), None),
    ("reject-unknown-size-bucket", body([{**SAMPLE, "sizeBucket": "2m-4m"}]), None),
    ("reject-numeric-size-bucket", body([{**SAMPLE, "sizeBucket": 1048576}]), None),
    ("reject-wrong-case", body([{**SAMPLE, "path": "Direct"}]), None),
    ("reject-null-path", body([{**SAMPLE, "path": None}]), None),
    ("reject-numeric-attempt", body([{**SAMPLE, "attempt": 2}]), None),
    ("reject-unknown-mode", body([{**SAMPLE, "mode": "relay"}]), None),
    ("reject-link-over-direct", body([ev("link", "direct", "lt1m", "first", "success")]), None),
    ("reject-link-over-turn", body([ev("link", "turn", "lt1m", "first", "failure")]), None),
    ("reject-success-without-a-path", body([ev("device", "unestablished", "lt1m", "first", "success")]), None),
    ("reject-whole-batch-for-one-bad-event", body([SAMPLE, {**SAMPLE, "fileName": "a.txt"}]), None),
]

SIZE_CASES = [-1, 0, 1, MIB - 1, MIB, 16 * MIB - 1, 16 * MIB, 128 * MIB, 128 * MIB + 1, 512 * MIB, 512 * MIB + 1, 4 << 30]
DURATION_CASES = [-5, 0, 599, 600, 1799, 1800, 7199, 7200, 86399, 86400, 259199, 259200, 1209599, 1209600]
RATE_CASES = [(0, 0), (0, 4), (4, 4), (1, 3), (2, 3), (5, 6), (6, 7), (1, 32), (3, 32)]

EXPECTED_SIZE = [None, None, "lt1m", "lt1m", "1m-16m", "1m-16m", "16m-128m", "16m-128m", "128m-512m", "128m-512m",
                 "gt512m", "gt512m"]
EXPECTED_DURATION = ["lt10m", "lt10m", "lt10m", "10m-30m", "10m-30m", "30m-2h", "30m-2h", "2h-24h", "2h-24h", "1d-3d",
                     "1d-3d", "3d-14d", "3d-14d", None]
EXPECTED_RATE = [None, 0, 10000, 3333, 6667, 8333, 8571, 313, 938]


def check_onboarding(results):
    statuses = [r.get("status") for r in results if "status" in r][:7]
    assert statuses == [403, 400, 400, 400, 400, 200, 200], statuses
    full = results[ONBOARDING_OPS.index(next(op for op in ONBOARDING_OPS if op["op"] == "summary"))]["body"]["onboarding"]
    assert [s["users"] for s in full["steps"]] == [7, 7, 6, 5, 4], full
    assert [s["fromPreviousRateBp"] for s in full["steps"]] == [None, 10000, 8571, 8333, 8000], full
    assert (full["cohortUsers"], full["pendingUsers"], full["final"], full["completionRateBp"]) == (7, 1, False, 5714)
    assert [d["users"] for d in full["durations"]] == [1, 1, 1, 0, 0, 1] and full["medianDurationBucket"] == "10m-30m"
    narrow = [r for r in results if r.get("status") == 200 and "onboarding" in r.get("body", {})][1]["body"]["onboarding"]
    assert [s["users"] for s in narrow["steps"]] == [3, 3, 3, 3, 2] and narrow["final"] is True
    assert narrow["completionRateBp"] == 6667 and narrow["medianDurationBucket"] == "lt10m"
    t3 = [r for r in results if r.get("status") == 200 and "onboarding" in r.get("body", {})][2]["body"]["onboarding"]
    assert t3["cohortUsers"] == 0 and t3["medianDurationBucket"] is None
    tail = [r.get("status") for r in results if "status" in r][-7:]
    assert tail == [403, 400, 400, 400, 200, 200, 200], tail
    final = results[-1]["state"]
    assert final["progress"] == [progress_row("t1", "ivan", "2026-09-20T00:00:00Z", "2026-09-20T01:00:00Z")]
    assert [(r["tenantId"], r["cohortDay"], r["reachedStep"], r["durationBucket"]) for r in final["onboardingDaily"]] == [
        ("t1", "2026-09-01", "credential_created", "none"), ("t1", "2026-09-01", "service_published", "30m-2h"),
        ("t1", "2026-09-01", "service_published", "3d-14d"), ("t1", "2026-09-02", "client_online", "none"),
        ("t1", "2026-09-03", "service_published", "10m-30m"), ("t1", "2026-09-03", "service_published", "lt10m")]


def check_transfers(results):
    assert [r.get("status") for r in results[2:9]] == [200, 400, 401, 200, 200, 200, 200]
    assert results[5]["body"] == {"collecting": False, "accepted": 0}
    full = results[13]["body"]["transfers"]
    cells = {(c["path"], c["sizeBucket"]): (c["success"], c["failure"], c["cancelled"], c["successRateBp"]) for c in full["cells"]}
    assert cells == {
        ("direct", "lt1m"): (3, 1, 0, 7500), ("direct", "16m-128m"): (1, 1, 0, 5000),
        ("turn", "lt1m"): (1, 0, 0, 10000), ("turn", "1m-16m"): (2, 0, 1, 10000),
        ("cloud", "16m-128m"): (1, 0, 0, 10000), ("cloud", "128m-512m"): (1, 0, 0, 10000),
        ("cloud", "gt512m"): (0, 1, 0, 0), ("unestablished", "lt1m"): (0, 2, 0, 0)}, cells
    assert [(x["success"], x["failure"], x["cancelled"], x["successRateBp"]) for x in full["byMode"]] == [
        (8, 4, 1, 6667), (1, 1, 0, 5000)]
    assert [(x["success"], x["failure"], x["successRateBp"]) for x in full["byAttempt"]] == [
        (6, 3, 6667), (2, 2, 5000), (1, 0, 10000)]
    assert (full["total"]["success"], full["total"]["failure"], full["total"]["cancelled"]) == (9, 5, 1)
    later = results[14]["body"]["transfers"]["total"]
    assert (later["success"], later["failure"]) == (1, 2)  # only R3 lands on 2026-09-11
    purged = results[15]["body"]
    assert purged["enabled"] is False and purged["transfers"]["cells"] == []
    assert results[-1]["state"]["switches"][1]["purgedAt"] is None


def check_rates(results):
    statuses = [r.get("status") for r in results[1:-1]]
    assert statuses == [200] * 6 + [429, 400, 200, 200, 429, 200], statuses
    total = sum(row["count"] for row in results[-1]["state"]["transferDaily"])
    assert total == 120 + 20 + 20, total


def check_tenant_rates(results):
    assert [r.get("status") for r in results[1:-1]] == [200, 200, 429, 200, 429, 200]
    assert results[6]["body"] == {"collecting": False, "accepted": 0}


def check_retention(results):
    state = results[-1]["state"]
    assert state["progress"] == [progress_row("t1", "pavel", "2026-09-07T00:30:01Z", "2026-09-07T00:31:00Z")]
    assert [(r["tenantId"], r["cohortDay"], r["reachedStep"], r["users"]) for r in state["onboardingDaily"]] == [
        ("t1", "2026-03-26", "signed_in", 1), ("t1", "2026-09-07", "credential_created", 1),
        ("t2", "2026-09-01", "signed_in", 4)]
    assert [(r["tenantId"], r["day"], r["count"]) for r in state["transferDaily"]] == [
        ("t1", "2026-03-26", 5), ("t1", "2026-09-21", 1), ("t2", "2026-09-20", 6)]


CHECKS = {"onboarding-funnel": check_onboarding, "transfer-outcomes": check_transfers,
          "per-user-rate-limit": check_rates, "per-tenant-rate-limit": check_tenant_rates,
          "retention-sweep": check_retention}


def build():
    assert [size_bucket(n) for n in SIZE_CASES] == EXPECTED_SIZE
    assert [duration_bucket(n) for n in DURATION_CASES] == EXPECTED_DURATION
    assert [rate_bp(n, d) for n, d in RATE_CASES] == EXPECTED_RATE

    validation = []
    for name, text, expect in VALIDATION:
        engine = Engine(DEFAULT_LIMITS)
        engine.switches["t1"] = {"enabled": True, "updatedBy": "root", "updatedAt": "2026-09-01T00:00:00Z", "purgedAt": None}
        result = engine.ingest(instant("2026-09-10T00:00:00Z"), actor("t1", "alice"), text)
        if isinstance(expect, int):
            assert result == {"status": 200, "body": {"collecting": True, "accepted": expect}}, (name, result)
        else:
            status, code = expect or (400, "PRODUCT_METRICS_INVALID")
            assert result == {"status": status, "body": {"code": code}}, (name, result)
            assert not engine.transfers, name
        validation.append({"name": name, "bodyText": text, "bodyBytes": len(text.encode("utf-8")), "expect": result})

    scenarios = []
    for scenario in SCENARIOS:
        engine = Engine(scenario["limits"])
        engine.load(scenario["initialState"])
        ops = []
        results = []
        for op in scenario["ops"]:
            result = engine.run(op)
            results.append(result)
            ops.append({**op, "expect": result})
        CHECKS[scenario["name"]](results)
        scenarios.append({"name": scenario["name"], "limits": scenario["limits"],
                          "initialState": scenario["initialState"], "ops": ops})

    return {
        "description": "Opt-in product metrics v1: closed transfer-outcome schema, buckets, rates, per-tenant switch, "
                       "server-observed onboarding progress folded into daily cohorts, daily transfer counters, "
                       "rate limits, retention sweep, purge and the summary read API. Replay each scenario on the "
                       "server's own store with its clock fixed at each op's `at`; compare every response marked "
                       "with `status`, and the store contents at every `checkpoint`. `effect` on milestone ops is "
                       "informative only. See protocol/spec/product-metrics.md.",
        "constants": {
            "disclosureVersion": DISCLOSURE_VERSION, "retentionDays": RETENTION_DAYS,
            "onboardingWindowDays": WINDOW.days, "maxBodyBytes": MAX_BODY_BYTES, "maxEventsPerRequest": MAX_EVENTS,
            "maxRangeDays": MAX_RANGE_DAYS, "defaultLimits": DEFAULT_LIMITS,
        },
        "vocabulary": {
            "steps": list(STEPS), "modes": list(MODES), "paths": list(PATHS), "attempts": list(ATTEMPTS),
            "outcomes": list(OUTCOMES), "eventKeys": sorted(EVENT_KEYS),
            "sizeBuckets": [{"name": n, "minBytes": lo, "maxBytes": hi} for n, lo, hi in SIZE_BUCKETS],
            "durationBuckets": [{"name": n, "minSeconds": lo, "maxSecondsExclusive": hi} for n, lo, hi in DURATION_BUCKETS],
        },
        "sizeBuckets": [{"sizeBytes": n, "bucket": size_bucket(n)} for n in SIZE_CASES],
        "durationBuckets": [{"seconds": n, "bucket": duration_bucket(n)} for n in DURATION_CASES],
        "rates": [{"numerator": n, "denominator": d, "rateBp": rate_bp(n, d)} for n, d in RATE_CASES],
        "ingestValidation": {
            "context": {"actor": actor("t1", "alice"), "tenantEnabled": True, "at": "2026-09-10T00:00:00Z"},
            "cases": validation,
        },
        "scenarios": scenarios,
    }


def main():
    document = build()
    path = VECTORS / "product-metrics-v1.json"
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {path}: validation={len(document['ingestValidation']['cases'])} scenarios={len(document['scenarios'])}")


if __name__ == "__main__":
    main()
