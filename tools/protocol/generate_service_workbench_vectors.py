"""Generate protocol/test-vectors/service-workbench-v1.json.

The service workbench keeps two short lists per management identity -- favourite services and
recently opened services -- on the server, so they follow the person across browsers and devices
and never leak to the next person on a shared browser. Each list belongs to exactly one
(tenantId, username); no API reads or clears another identity's lists, administrators included.
See protocol/spec/service-workbench.md.

What the four servers must agree on, and what this vector fixes:

- bounds: at most 50 favourites (adding one more is refused, never silently evicted) and at most
  20 recent entries (the oldest is evicted);
- retention: a recent entry is visible while now - visitedAt < 30 days, strictly; expired entries
  are deleted by the identity's next write and by a sweep, never returned;
- ordering: favourites by addedAt ascending, recents by visitedAt descending, ties broken by the
  fixed kind order and then by id;
- dedupe: adding a favourite twice changes nothing; opening a service again moves it to the front
  and never moves its time backwards;
- isolation: rows are keyed by tenantId + username, exactly as authenticated; growth needs the
  object to be visible to the caller right now, removal never does;
- cascades: deleting an object removes every reference to it, so a reused id never inherits a
  favourite; deleting an account removes its rows, so a new account with the same name starts empty;
- failures: a store that cannot be read answers 503, never an empty list; growth is rate limited
  per identity, removal never is.

Every expectation is produced by the reference below and checked against a hand-written table
before the file is written, so the vector cannot ship contradicting itself.

The vector also carries the frontend-only rule that derives "pending problems" from state the
admin web already reads (devices, HTTP routes, TCP mappings, Peer services). The servers do not
implement it; the admin web tests read that section.
"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

VECTORS = Path("protocol/test-vectors")

BASE = datetime(2026, 10, 6, 0, 0, 0, tzinfo=timezone.utc)
DAY_MS = 24 * 3600 * 1000

MAX_FAVORITES = 50
MAX_RECENTS = 20
RECENT_RETENTION_DAYS = 30
RECENT_RETENTION_MS = RECENT_RETENTION_DAYS * DAY_MS
MAX_OBJECT_ID = (1 << 53) - 1      # the largest id a browser holds exactly as a JSON number
KINDS = ("http-route", "tcp-mapping", "peer-service")   # also the tie-break order
SHORT = {"http-route": "r", "tcp-mapping": "m", "peer-service": "p"}

# Growth (adding a favourite, recording an open) is rate limited per identity with GCRA; removal
# and clearing never are.
WRITE_INTERVAL_MS = 1_000
WRITE_BURST = 30

PREFIX = "/api/admin/workbench"


def stamp(at_ms):
    """RFC 3339 UTC with exactly three fractional digits."""
    value = BASE + timedelta(milliseconds=at_ms)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def ref_key(kind, object_id):
    return (KINDS.index(kind), object_id)


def short(kind, object_id):
    return f"{SHORT[kind]}{object_id}"


def parse_id(text):
    """Decimal ASCII digits, no sign, no leading zero, 1..2^53-1."""
    if not text or not text.isascii() or not text.isdigit():
        return None
    if text[0] == "0":
        return None
    value = int(text)
    if value > MAX_OBJECT_ID:
        return None
    return value


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


class Server:
    """The reference: one shared store (every instance reads the same database) plus one
    in-memory rate limiter."""

    def __init__(self, users, objects, rows):
        self.users = {(u["tenantId"], u["username"]): dict(u) for u in users}
        # Object ids come from one sequence per kind across the whole database, as they do today.
        self.objects = {(o["kind"], o["id"]): dict(o) for o in objects}
        self.rows = {}
        for row in rows:
            key = (row["tenantId"], row["username"], row["list"], row["kind"], row["id"])
            assert key not in self.rows, key
            self.rows[key] = row["atMs"]
        self.store_up = True
        self.limiter = Gcra(WRITE_INTERVAL_MS, WRITE_BURST)

    # -- visibility -------------------------------------------------------------------------
    def visible(self, identity, kind, object_id):
        user = self.users.get(identity)
        obj = self.objects.get((kind, object_id))
        if user is None or obj is None:
            return False
        if obj["tenantId"] != user["tenantId"]:
            return False
        return user.get("admin", False) or obj["ownerUsername"] == user["username"]

    # -- reads ------------------------------------------------------------------------------
    def entries(self, identity, which):
        tenant, username = identity
        return [(kind, object_id, at) for (t, u, lst, kind, object_id), at in self.rows.items()
                if t == tenant and u == username and lst == which]

    def favorites(self, identity):
        rows = self.entries(identity, "favorite")
        rows.sort(key=lambda r: (r[2], ref_key(r[0], r[1])))
        return rows

    def recents(self, identity, now):
        rows = [r for r in self.entries(identity, "recent") if now - r[2] < RECENT_RETENTION_MS]
        rows.sort(key=lambda r: (-r[2], ref_key(r[0], r[1])))
        return rows[:MAX_RECENTS]

    def document(self, identity, now):
        return {
            "schemaVersion": 1,
            "limits": {"maxFavorites": MAX_FAVORITES, "maxRecents": MAX_RECENTS,
                       "recentRetentionDays": RECENT_RETENTION_DAYS},
            "favorites": [{"kind": k, "id": i, "addedAt": stamp(at)} for k, i, at in self.favorites(identity)],
            "recents": [{"kind": k, "id": i, "visitedAt": stamp(at)} for k, i, at in self.recents(identity, now)],
        }

    # -- writes -----------------------------------------------------------------------------
    def normalize(self, identity, now):
        """Every successful write of an identity leaves its recents within retention and bound."""
        tenant, username = identity
        keep = {(k, i) for k, i, _ in self.recents(identity, now)}
        for kind, object_id, _ in self.entries(identity, "recent"):
            if (kind, object_id) not in keep:
                del self.rows[(tenant, username, "recent", kind, object_id)]

    def handle(self, identity, method, path, now):
        if identity is None:
            return {"httpStatus": 401}
        if identity not in self.users:
            # A token naming an account that no longer exists (or is disabled): refused by the
            # authentication layer every management endpoint already shares -- 401 or 403 depending
            # on the server -- before anything of the workbench runs. It must not write.
            return {"sessionRejected": True}
        route = self.match(method, path)
        if route is None:
            raise AssertionError(f"not a workbench route: {method} {path}")
        op, kind, raw_id = route
        object_id = None
        if kind is not None:
            object_id = parse_id(raw_id)
            if kind not in KINDS or object_id is None:
                return {"httpStatus": 400, "body": {"code": "WORKBENCH_REQUEST_INVALID"}}
        if op in ("add-favorite", "record-visit"):
            wait = self.limiter.wait_ms(identity, now)
            if wait > 0:
                return {"httpStatus": 429, "retryAfterSeconds": max(1, -(-wait // 1000)),
                        "body": {"code": "WORKBENCH_RATE_LIMITED"}}
            self.limiter.take(identity, now)
        if not self.store_up:
            return {"httpStatus": 503, "body": {"code": "WORKBENCH_UNAVAILABLE"}}
        tenant, username = identity
        if op == "get":
            return {"httpStatus": 200, "body": self.document(identity, now)}
        if op in ("add-favorite", "record-visit") and not self.visible(identity, kind, object_id):
            return {"httpStatus": 404, "body": {"code": "WORKBENCH_TARGET_NOT_FOUND"}}
        if op == "add-favorite":
            key = (tenant, username, "favorite", kind, object_id)
            if key not in self.rows:
                if len(self.entries(identity, "favorite")) >= MAX_FAVORITES:
                    return {"httpStatus": 409, "body": {"code": "WORKBENCH_FAVORITES_FULL"}}
                self.rows[key] = now
        elif op == "remove-favorite":
            self.rows.pop((tenant, username, "favorite", kind, object_id), None)
        elif op == "clear-favorites":
            for k, i, _ in self.entries(identity, "favorite"):
                del self.rows[(tenant, username, "favorite", k, i)]
        elif op == "record-visit":
            key = (tenant, username, "recent", kind, object_id)
            # A clock behind the stored time (another instance) never moves an entry back.
            self.rows[key] = max(now, self.rows.get(key, now))
        elif op == "remove-recent":
            self.rows.pop((tenant, username, "recent", kind, object_id), None)
        elif op == "clear-recents":
            for k, i, _ in self.entries(identity, "recent"):
                del self.rows[(tenant, username, "recent", k, i)]
        else:
            raise AssertionError(op)
        self.normalize(identity, now)
        return {"httpStatus": 200, "body": self.document(identity, now)}

    @staticmethod
    def match(method, path):
        assert path.startswith(PREFIX), path
        parts = path[len(PREFIX):].split("/")[1:] if path != PREFIX else []
        if method == "GET" and parts == []:
            return ("get", None, None)
        if len(parts) == 1 and method == "DELETE":
            return {"favorites": ("clear-favorites", None, None),
                    "recents": ("clear-recents", None, None)}.get(parts[0])
        if len(parts) == 3:
            table = {("favorites", "PUT"): "add-favorite", ("favorites", "DELETE"): "remove-favorite",
                     ("recents", "POST"): "record-visit", ("recents", "DELETE"): "remove-recent"}
            op = table.get((parts[0], method))
            if op is not None:
                return (op, parts[1], parts[2])
        return None

    # -- events from outside the workbench API ---------------------------------------------
    def event(self, step):
        name = step["event"]
        if name == "delete-object":
            # Deleting a route, mapping or Peer service (or the client that carries it) removes
            # every reference to it in the same transaction, for every identity.
            kind, object_id = step["kind"], step["id"]
            del self.objects[(kind, object_id)]
            for key in [k for k in self.rows if k[3] == kind and k[4] == object_id]:
                del self.rows[key]
        elif name == "create-object":
            key = (step["kind"], step["id"])
            assert key not in self.objects, key
            self.objects[key] = {"kind": step["kind"], "id": step["id"], "tenantId": step["tenantId"],
                                 "ownerUsername": step["ownerUsername"]}
        elif name == "change-owner":
            self.objects[(step["kind"], step["id"])]["ownerUsername"] = step["ownerUsername"]
        elif name == "set-admin":
            self.users[(step["tenantId"], step["username"])]["admin"] = step["admin"]
        elif name == "delete-user":
            identity = (step["tenantId"], step["username"])
            del self.users[identity]
            for key in [k for k in self.rows if (k[0], k[1]) == identity]:
                del self.rows[key]
        elif name == "create-user":
            identity = (step["tenantId"], step["username"])
            assert identity not in self.users, identity
            self.users[identity] = {"tenantId": step["tenantId"], "username": step["username"],
                                    "admin": step.get("admin", False)}
        elif name == "store-down":
            self.store_up = False
        elif name == "store-up":
            self.store_up = True
        elif name == "sweep":
            # The periodic retention sweep: deletes every expired recent entry of every identity.
            for key in [k for k, at in self.rows.items()
                        if k[2] == "recent" and step["atMs"] - at >= RECENT_RETENTION_MS]:
                del self.rows[key]
        else:
            raise AssertionError(name)

    def dump_rows(self):
        out = [{"tenantId": t, "username": u, "list": lst, "kind": k, "id": i, "atMs": at}
               for (t, u, lst, k, i), at in self.rows.items()]
        out.sort(key=lambda r: (r["tenantId"], r["username"], r["list"], KINDS.index(r["kind"]), r["id"]))
        return out


# ---------------------------------------------------------------------------------------------
# Scenario helpers

def user(tenant, username, admin=False):
    return {"tenantId": tenant, "username": username, "admin": admin}


def obj(kind, object_id, tenant="t1", owner="alice"):
    return {"kind": kind, "id": object_id, "tenantId": tenant, "ownerUsername": owner}


def row(lst, kind, object_id, at_ms, tenant="t1", username="alice"):
    return {"tenantId": tenant, "username": username, "list": lst, "kind": kind, "id": object_id, "atMs": at_ms}


def call(at_ms, method, path, as_user=("t1", "alice")):
    step = {"atMs": at_ms, "method": method, "path": PREFIX + path}
    step["as"] = None if as_user is None else {"tenantId": as_user[0], "username": as_user[1]}
    return step


def get(at_ms, as_user=("t1", "alice")):
    return call(at_ms, "GET", "", as_user)


def fav(at_ms, kind, object_id, as_user=("t1", "alice")):
    return call(at_ms, "PUT", f"/favorites/{kind}/{object_id}", as_user)


def unfav(at_ms, kind, object_id, as_user=("t1", "alice")):
    return call(at_ms, "DELETE", f"/favorites/{kind}/{object_id}", as_user)


def visit(at_ms, kind, object_id, as_user=("t1", "alice")):
    return call(at_ms, "POST", f"/recents/{kind}/{object_id}", as_user)


def forget(at_ms, kind, object_id, as_user=("t1", "alice")):
    return call(at_ms, "DELETE", f"/recents/{kind}/{object_id}", as_user)


def event(at_ms, name, **fields):
    return {"atMs": at_ms, "event": name, **fields}


R, M, P = KINDS

ALICE = ("t1", "alice")
BOB = ("t1", "bob")
ROOT = ("t1", "root")          # a tenant administrator
ALICE_T2 = ("t2", "alice")     # the same name in another tenant is another identity
CAROL = ("t1", "carol")

SCENARIOS = []


def scenario(name, note, users, objects, steps, rows=()):
    SCENARIOS.append({"name": name, "note": note, "users": users, "objects": objects,
                      "rows": list(rows), "steps": steps})


scenario(
    "favorites-order-and-dedupe",
    "Favourites keep the order they were added in; adding one again changes nothing, its addedAt "
    "included. Two added in the same millisecond are ordered by kind (http-route, tcp-mapping, "
    "peer-service), then id. Removing is idempotent.",
    [user("t1", "alice")],
    [obj(R, 1), obj(R, 2), obj(R, 3), obj(M, 5), obj(P, 9)],
    [
        get(0),
        fav(1_000, R, 2),
        fav(2_000, M, 5),
        fav(3_000, R, 2),
        fav(3_000, R, 1),
        fav(4_000, P, 9),
        fav(4_000, R, 3),
        unfav(5_000, M, 5),
        unfav(6_000, M, 5),
        get(7_000),
    ],
)

scenario(
    "favorites-bound",
    "The fiftieth favourite is accepted, the fifty-first refused with 409 and nothing evicted. "
    "Adding one that is already there stays a no-op even when the list is full; after a removal "
    "there is room again.",
    [user("t1", "alice")],
    [obj(R, n) for n in range(101, 152)],
    [
        fav(10_000, R, 150),
        fav(11_000, R, 151),
        fav(12_000, R, 101),
        unfav(13_000, R, 101),
        fav(14_000, R, 151),
    ],
    rows=[row("favorite", R, n, n) for n in range(101, 150)],
)

scenario(
    "favorites-overflow-is-shown",
    "Two concurrent adds on a store that cannot serialize them may leave 51 favourites. A read "
    "returns every one of them -- an explicit choice is never hidden -- and adding stays refused "
    "until the list is below the bound.",
    [user("t1", "alice")],
    [obj(R, n) for n in range(201, 254)],
    [
        get(100_000),
        fav(101_000, R, 252),
        unfav(102_000, R, 201),
        fav(103_000, R, 252),
        unfav(104_000, R, 202),
        fav(105_000, R, 252),
    ],
    rows=[row("favorite", R, n, n) for n in range(201, 252)],
)

scenario(
    "recents-order-dedupe-and-bound",
    "Recents are newest first. Opening a service again moves it to the front instead of adding a "
    "second entry. The twenty-first distinct service evicts the oldest; the evicted row is deleted, "
    "not hidden. Two opens in the same millisecond are ordered by kind, then id.",
    [user("t1", "alice")],
    [obj(R, n) for n in range(1, 23)] + [obj(M, 1)],
    [
        get(19_500),
        visit(20_000, R, 20),
        visit(21_000, R, 21),
        visit(22_000, R, 5),
        visit(23_000, M, 1),
        visit(23_000, R, 22),
        get(24_000),
    ],
    rows=[row("recent", R, n, n * 1_000) for n in range(1, 20)],
)

scenario(
    "recents-retention-boundary",
    "An entry is returned while now - visitedAt < 30 days. Exactly 30 days old is expired. A read "
    "only filters; the identity's next write deletes its expired rows, and the sweep deletes "
    "everyone's.",
    [user("t1", "alice"), user("t1", "bob")],
    [obj(R, 1), obj(R, 2), obj(R, 3), obj(R, 4)],
    [
        get(RECENT_RETENTION_MS),
        get(RECENT_RETENTION_MS + 1),
        visit(RECENT_RETENTION_MS + 2, R, 3),
        event(RECENT_RETENTION_MS + 3, "sweep"),
        get(RECENT_RETENTION_MS + 4, BOB),
    ],
    rows=[
        row("recent", R, 1, 0),
        row("recent", R, 2, 1),
        row("recent", R, 4, 0, username="bob"),
        row("favorite", R, 1, 0),
    ],
)

scenario(
    "recents-over-bound-rows",
    "Rows beyond the bound (a race between instances) are never returned; the next write of the "
    "identity deletes them, and a removal counts as a write.",
    [user("t1", "alice")],
    [obj(R, n) for n in range(1, 23)],
    [
        get(100_000),
        forget(101_000, R, 22),
    ],
    rows=[row("recent", R, n, n * 1_000) for n in range(1, 23)],
)

scenario(
    "clock-behind-never-moves-a-visit-back",
    "An instance whose clock is behind records an open that is older than the stored one: the "
    "stored time stays, so the entry does not drop down the list.",
    [user("t1", "alice")],
    [obj(R, 1), obj(R, 2)],
    [
        visit(10_000, R, 1),
        visit(11_000, R, 2),
        visit(9_000, R, 1),
        get(12_000),
    ],
)

scenario(
    "identity-isolation",
    "Lists belong to tenantId + username. Growth needs the object to be visible to the caller now "
    "(same tenant, and administrator or owner of the client); another owner's object and another "
    "tenant's object answer 404 alike. The same username in another tenant is another identity. An "
    "administrator sees only their own lists; clearing one identity's list touches no other.",
    [user("t1", "alice"), user("t1", "bob"), user("t1", "root", admin=True), user("t2", "alice")],
    [obj(R, 1), obj(R, 2, owner="bob"), obj(R, 3, tenant="t2"), obj(M, 4, owner="bob")],
    [
        fav(1_000, R, 1),
        fav(2_000, R, 2),
        fav(3_000, R, 3),
        fav(4_000, R, 2, ROOT),
        fav(5_000, R, 1, ROOT),
        visit(6_000, M, 4, BOB),
        fav(7_000, R, 3, ALICE_T2),
        fav(8_000, R, 1, ALICE_T2),
        get(9_000),
        get(9_000, ROOT),
        get(9_000, BOB),
        get(9_000, ALICE_T2),
        call(10_000, "DELETE", "/favorites", ROOT),
        call(11_000, "DELETE", "/recents", BOB),
        get(12_000),
        get(12_000, ROOT),
        get(12_000, BOB),
    ],
)

scenario(
    "removal-needs-no-visibility",
    "An administrator favourites another owner's route and later loses the role. The reference "
    "stays and is still listed (kind and id only, no name), but it cannot be added or opened "
    "again; removing it always works.",
    [user("t1", "carol", admin=True), user("t1", "bob")],
    [obj(R, 2, owner="bob"), obj(P, 7, owner="bob")],
    [
        fav(1_000, R, 2, CAROL),
        visit(2_000, P, 7, CAROL),
        event(3_000, "set-admin", tenantId="t1", username="carol", admin=False),
        get(4_000, CAROL),
        fav(5_000, R, 2, CAROL),
        visit(6_000, P, 7, CAROL),
        unfav(7_000, R, 2, CAROL),
        forget(8_000, P, 7, CAROL),
    ],
)

scenario(
    "object-deletion-cascades",
    "Deleting an object removes every identity's references to it, so an id handed out again later "
    "(a random id that collides, a restored backup) does not inherit them. An object that changes "
    "owner keeps the old owner's reference: it is still listed, no longer resolves in the lists that "
    "person can read, and cannot be added again.",
    [user("t1", "alice"), user("t1", "root", admin=True)],
    [obj(R, 1), obj(M, 2), obj(R, 3)],
    [
        fav(1_000, R, 1),
        visit(2_000, R, 1),
        fav(3_000, R, 1, ROOT),
        fav(4_000, M, 2),
        fav(4_500, R, 3),
        event(5_000, "delete-object", kind=R, id=1),
        event(6_000, "create-object", kind=R, id=1, tenantId="t1", ownerUsername="alice"),
        event(6_500, "change-owner", kind=R, id=3, ownerUsername="bob"),
        get(7_000),
        get(7_000, ROOT),
        fav(8_000, R, 3),
    ],
)

scenario(
    "account-deletion-cascades",
    "Deleting an account deletes its rows. A token issued before the deletion is refused by the "
    "shared authentication layer (sessionRejected: 401 or 403 depending on the server), so it cannot "
    "write rows back. An account created later under the same name starts with empty lists.",
    [user("t1", "alice"), user("t1", "bob")],
    [obj(R, 1), obj(R, 2, owner="bob")],
    [
        fav(1_000, R, 1),
        visit(2_000, R, 1),
        visit(3_000, R, 2, BOB),
        event(4_000, "delete-user", tenantId="t1", username="alice"),
        visit(4_500, R, 1),
        get(4_600),
        event(5_000, "create-user", tenantId="t1", username="alice"),
        get(6_000),
        get(6_000, BOB),
    ],
)

scenario(
    "request-validation",
    "kind is one of three lowercase names; id is a decimal integer 1..2^53-1 without sign or leading "
    "zero. Invalid requests answer 400 and consume no rate. A request without a session answers 401 "
    "before anything else is looked at.",
    [user("t1", "alice")],
    [obj(R, 1), obj(R, MAX_OBJECT_ID)],
    [
        call(1_000, "PUT", "/favorites/HTTP-ROUTE/1"),
        call(1_000, "PUT", "/favorites/route/1"),
        call(1_000, "PUT", "/favorites/http-route/0"),
        call(1_000, "PUT", "/favorites/http-route/01"),
        call(1_000, "PUT", "/favorites/http-route/-1"),
        call(1_000, "PUT", "/favorites/http-route/1e3"),
        call(1_000, "PUT", f"/favorites/http-route/{MAX_OBJECT_ID + 1}"),
        call(1_000, "POST", "/recents/http-route/abc"),
        call(1_000, "DELETE", "/recents/tcp_mapping/1"),
        call(1_000, "DELETE", "/favorites/peer-service/00"),
        call(2_000, "PUT", f"/favorites/http-route/{MAX_OBJECT_ID}"),
        call(2_000, "PUT", "/favorites/HTTP-ROUTE/1", as_user=None),
        call(2_000, "GET", "", as_user=None),
        call(2_000, "DELETE", "/recents", as_user=None),
    ],
)

scenario(
    "store-unavailable",
    "A store that cannot be read or written answers 503 for reads and writes alike; it never "
    "reports empty lists. When it comes back the lists are as they were.",
    [user("t1", "alice")],
    [obj(R, 1), obj(R, 2)],
    [
        fav(1_000, R, 1),
        event(2_000, "store-down"),
        get(3_000),
        fav(4_000, R, 2),
        call(5_000, "DELETE", "/favorites"),
        event(6_000, "store-up"),
        get(7_000),
    ],
)

scenario(
    "kind-without-object",
    "No object of that kind exists for the caller (here: no Peer service at all). Growth answers 404 "
    "like any invisible object -- the API does not reveal whether a kind is served -- and removal "
    "stays a no-op.",
    [user("t1", "alice")],
    [obj(R, 1)],
    [
        fav(1_000, P, 1),
        visit(2_000, P, 1),
        unfav(3_000, P, 1),
        get(4_000),
    ],
)


def rate_steps():
    steps = [visit(n, R, 1 + n % 3) for n in range(0, 30)]       # thirty opens in 30 ms: the burst
    steps += [
        visit(30, R, 1),                     # the thirty-first is refused
        fav(31, R, 2),                       # favourites share the key
        call(32, "PUT", "/favorites/http-route/0"),   # invalid: 400 before the limiter
        unfav(33, R, 2),                     # removal is never limited
        call(34, "DELETE", "/recents"),      # neither is clearing
        visit(35, R, 1_001, BOB),            # another identity has a key of its own
        visit(1_000, R, 3),                  # one interval later there is room for one
        visit(1_001, R, 3),
        fav(2_000, R, 99),                   # admitted by the limiter, then 404: it still costs
        fav(2_500, R, 2),
        visit(3_000, R, 1),
    ]
    return steps


scenario(
    "rate-limit",
    "Adding a favourite and recording an open share one GCRA key per identity: interval 1000 ms, "
    "burst 30. A refused request consumes nothing; an admitted one costs even when it then fails "
    "with 404, 409 or 503. Removal and clearing are never limited. Retry-After is the wait in whole "
    "seconds, rounded up, at least 1.",
    [user("t1", "alice"), user("t1", "bob")],
    [obj(R, 1), obj(R, 2), obj(R, 3), obj(R, 1_001, owner="bob")],
    rate_steps(),
)


# ---------------------------------------------------------------------------------------------
# Hand-written expectations, one line per API step:
#   (httpStatus, code)                         for a refusal
#   (200, [favourites], [recents])             short refs, in order; a long list as (count, first, last)

def L(count, first, last):
    return (count, first, last)


EXPECTED = {
    "favorites-order-and-dedupe": [
        (200, [], []),
        (200, ["r2"], []),
        (200, ["r2", "m5"], []),
        (200, ["r2", "m5"], []),
        (200, ["r2", "m5", "r1"], []),
        (200, ["r2", "m5", "r1", "p9"], []),
        (200, ["r2", "m5", "r1", "r3", "p9"], []),
        (200, ["r2", "r1", "r3", "p9"], []),
        (200, ["r2", "r1", "r3", "p9"], []),
        (200, ["r2", "r1", "r3", "p9"], []),
    ],
    "favorites-bound": [
        (200, L(50, "r101", "r150"), []),
        (409, "WORKBENCH_FAVORITES_FULL"),
        (200, L(50, "r101", "r150"), []),
        (200, L(49, "r102", "r150"), []),
        (200, L(50, "r102", "r151"), []),
    ],
    "favorites-overflow-is-shown": [
        (200, L(51, "r201", "r251"), []),
        (409, "WORKBENCH_FAVORITES_FULL"),
        (200, L(50, "r202", "r251"), []),
        (409, "WORKBENCH_FAVORITES_FULL"),
        (200, L(49, "r203", "r251"), []),
        (200, L(50, "r203", "r252"), []),
    ],
    "recents-order-dedupe-and-bound": [
        (200, [], L(19, "r19", "r1")),       # r1 .. r19 opened one second apart: newest first
        (200, [], L(20, "r20", "r1")),
        (200, [], L(20, "r21", "r2")),       # the 21st distinct service evicts r1
        (200, [], L(20, "r5", "r2")),        # opening r5 again moves it to the front
        (200, [], L(20, "m1", "r3")),        # m1 evicts r2
        (200, [], L(20, "r22", "r4")),       # same millisecond as m1: http-route sorts first; r3 evicted
        (200, [], L(20, "r22", "r4")),
    ],
    "recents-retention-boundary": [
        (200, ["r1"], ["r2"]),
        (200, ["r1"], []),
        (200, ["r1"], ["r3"]),
        (200, [], []),
    ],
    "recents-over-bound-rows": [
        (200, [], L(20, "r22", "r3")),
        (200, [], L(20, "r21", "r2")),
    ],
    "clock-behind-never-moves-a-visit-back": [
        (200, [], ["r1"]),
        (200, [], ["r2", "r1"]),
        (200, [], ["r2", "r1"]),
        (200, [], ["r2", "r1"]),
    ],
    "identity-isolation": [
        (200, ["r1"], []),
        (404, "WORKBENCH_TARGET_NOT_FOUND"),
        (404, "WORKBENCH_TARGET_NOT_FOUND"),
        (200, ["r2"], []),
        (200, ["r2", "r1"], []),
        (200, [], ["m4"]),
        (200, ["r3"], []),
        (404, "WORKBENCH_TARGET_NOT_FOUND"),
        (200, ["r1"], []),
        (200, ["r2", "r1"], []),
        (200, [], ["m4"]),
        (200, ["r3"], []),
        (200, [], []),
        (200, [], []),
        (200, ["r1"], []),
        (200, [], []),
        (200, [], []),
    ],
    "removal-needs-no-visibility": [
        (200, ["r2"], []),
        (200, ["r2"], ["p7"]),
        (200, ["r2"], ["p7"]),
        (404, "WORKBENCH_TARGET_NOT_FOUND"),
        (404, "WORKBENCH_TARGET_NOT_FOUND"),
        (200, [], ["p7"]),
        (200, [], []),
    ],
    "object-deletion-cascades": [
        (200, ["r1"], []),
        (200, ["r1"], ["r1"]),
        (200, ["r1"], []),
        (200, ["r1", "m2"], ["r1"]),
        (200, ["r1", "m2", "r3"], ["r1"]),
        (200, ["m2", "r3"], []),
        (200, [], []),
        (404, "WORKBENCH_TARGET_NOT_FOUND"),
    ],
    "account-deletion-cascades": [
        (200, ["r1"], []),
        (200, ["r1"], ["r1"]),
        (200, [], ["r2"]),
        ("session-rejected",),
        ("session-rejected",),
        (200, [], []),
        (200, [], ["r2"]),
    ],
    "request-validation": [
        *[(400, "WORKBENCH_REQUEST_INVALID")] * 10,
        (200, [f"r{MAX_OBJECT_ID}"], []),
        (401, None),
        (401, None),
        (401, None),
    ],
    "store-unavailable": [
        (200, ["r1"], []),
        (503, "WORKBENCH_UNAVAILABLE"),
        (503, "WORKBENCH_UNAVAILABLE"),
        (503, "WORKBENCH_UNAVAILABLE"),
        (200, ["r1"], []),
    ],
    "kind-without-object": [
        (404, "WORKBENCH_TARGET_NOT_FOUND"),
        (404, "WORKBENCH_TARGET_NOT_FOUND"),
        (200, [], []),
        (200, [], []),
    ],
    "rate-limit": [
        # Opens at 0..29 ms cycle through r1, r2, r3: the newest three, newest first.
        (200, [], ["r1"]),
        (200, [], ["r2", "r1"]),
        *[(200, [], [f"r{1 + n % 3}", f"r{1 + (n - 1) % 3}", f"r{1 + (n - 2) % 3}"]) for n in range(2, 30)],
        (429, "WORKBENCH_RATE_LIMITED", 1),
        (429, "WORKBENCH_RATE_LIMITED", 1),
        (400, "WORKBENCH_REQUEST_INVALID"),
        (200, [], ["r3", "r2", "r1"]),
        (200, [], []),
        (200, [], ["r1001"]),
        (200, [], ["r3"]),
        (429, "WORKBENCH_RATE_LIMITED", 1),
        (404, "WORKBENCH_TARGET_NOT_FOUND"),
        (429, "WORKBENCH_RATE_LIMITED", 1),
        (200, [], ["r1", "r3"]),
    ],
}

EXPECTED_ROWS = {
    # Final store contents that matter: what was deleted must be gone, not hidden.
    "recents-retention-boundary": [
        row("favorite", R, 1, 0),
        row("recent", R, 3, RECENT_RETENTION_MS + 2),
    ],
    "recents-over-bound-rows": [row("recent", R, n, n * 1_000) for n in range(2, 22)],
    "object-deletion-cascades": [
        row("favorite", M, 2, 4_000),
        row("favorite", R, 3, 4_500),
    ],
    "account-deletion-cascades": [row("recent", R, 2, 3_000, username="bob")],
    "identity-isolation": [
        row("favorite", R, 1, 1_000),
        row("favorite", R, 3, 7_000, tenant="t2"),
    ],
}


def summarize(result):
    if result.get("sessionRejected"):
        return ("session-rejected",)
    status = result["httpStatus"]
    if status != 200:
        code = result.get("body", {}).get("code")
        if status == 429:
            return (status, code, result["retryAfterSeconds"])
        return (status, code)

    def refs(entries):
        names = [short(e["kind"], e["id"]) for e in entries]
        return names if len(names) <= 6 else (len(names), names[0], names[-1])

    body = result["body"]
    return (200, refs(body["favorites"]), refs(body["recents"]))


def normalize_expected(line):
    if line[0] != 200 or len(line) != 3:
        return line
    _, favs, recents = line
    fix = lambda v: v if isinstance(v, tuple) or len(v) <= 6 else (len(v), v[0], v[-1])
    return (200, fix(favs), fix(recents))


def check_document(name, body, now):
    """Invariants every 200 body satisfies, independent of the hand-written table."""
    assert body["schemaVersion"] == 1, name
    favorites, recents = body["favorites"], body["recents"]
    fav_keys = [(parse_ms(e["addedAt"]), ref_key(e["kind"], e["id"])) for e in favorites]
    assert fav_keys == sorted(fav_keys), (name, "favourites out of order")
    rec_keys = [(-parse_ms(e["visitedAt"]), ref_key(e["kind"], e["id"])) for e in recents]
    assert rec_keys == sorted(rec_keys), (name, "recents out of order")
    assert len({(e["kind"], e["id"]) for e in favorites}) == len(favorites), (name, "duplicate favourite")
    assert len({(e["kind"], e["id"]) for e in recents}) == len(recents), (name, "duplicate recent")
    assert len(recents) <= MAX_RECENTS, name
    for e in recents:
        assert now - parse_ms(e["visitedAt"]) < RECENT_RETENTION_MS, (name, "expired entry returned")
    for e in favorites + recents:
        assert set(e) <= {"kind", "id", "addedAt", "visitedAt"}, (name, "a reference carries only kind, id and time")


def parse_ms(text):
    """Milliseconds since baseTime of a stamp() string."""
    value = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    return (value - BASE) // timedelta(milliseconds=1)


def build_scenarios():
    out = []
    for sc in SCENARIOS:
        server = Server(sc["users"], sc["objects"], sc["rows"])
        steps = []
        produced = []
        for step in sc["steps"]:
            step = dict(step)
            if "event" in step:
                server.event(step)
                steps.append(step)
                continue
            identity = None if step["as"] is None else (step["as"]["tenantId"], step["as"]["username"])
            result = server.handle(identity, step["method"], step["path"], step["atMs"])
            if result.get("httpStatus") == 200:
                check_document(sc["name"], result["body"], step["atMs"])
            produced.append(summarize(result))
            step["expect"] = result
            steps.append(step)
        expected = [normalize_expected(line) for line in EXPECTED[sc["name"]]]
        assert produced == expected, (sc["name"], [(i, p, e) for i, (p, e) in enumerate(zip(produced, expected)) if p != e],
                                      len(produced), len(expected))
        rows_after = server.dump_rows()
        if sc["name"] in EXPECTED_ROWS:
            want = sorted(EXPECTED_ROWS[sc["name"]],
                          key=lambda r: (r["tenantId"], r["username"], r["list"], KINDS.index(r["kind"]), r["id"]))
            assert rows_after == want, (sc["name"], rows_after)
        # Isolation: every stored row belongs to an identity that exists, and every reference a
        # row holds was visible to that identity when it was written (checked by construction in
        # handle); no row survives the deletion of its object.
        for r in rows_after:
            assert (r["tenantId"], r["username"]) in server.users, (sc["name"], r)
            assert (r["kind"], r["id"]) in server.objects, (sc["name"], r)
        out.append({"name": sc["name"], "note": sc["note"], "users": sc["users"], "objects": sc["objects"],
                    "rows": sc["rows"], "steps": steps, "rowsAfter": rows_after})
    assert set(EXPECTED) == {sc["name"] for sc in SCENARIOS}
    return out


# ---------------------------------------------------------------------------------------------
# Frontend-only: pending problems derived from state the admin web already reads.

PROBLEM_CODES = [
    # code, severity: blocking = certainly cannot be used through specus right now;
    # attention = not listed for peers, cause not determined from the state alone
    ("DEVICE_DISABLED", "blocking"),
    ("DEVICE_OFFLINE", "blocking"),
    ("PEER_SHARING_OFF", "blocking"),
    ("PEER_NOT_REPORTED", "attention"),
    ("PEER_DIRECTORY_EXPIRED", "attention"),
    ("PEER_NOT_ADVERTISED", "attention"),
]
CODE_ORDER = {code: i for i, (code, _) in enumerate(PROBLEM_CODES)}
SEVERITY = dict(PROBLEM_CODES)
SOURCES = ("clients", "httpRoutes", "tcpMappings", "peerServices")


def problems(state):
    """The rule the admin web applies. Input mirrors what GET /clients, /http-routes,
    /specus-mappings, /peer-mesh/service-sharing and /peer-mesh/services already return; every
    source is 'ok', 'failed' or 'unsupported' (404/405: the server has no such kind)."""
    sources = state["sources"]
    unread = [s for s in SOURCES if sources[s] == "failed"]
    clients = {c["id"]: c for c in state.get("clients", [])} if sources["clients"] == "ok" else None

    services = []
    if sources["httpRoutes"] == "ok":
        services += [(R, s) for s in state.get("httpRoutes", [])]
    if sources["tcpMappings"] == "ok":
        services += [(M, s) for s in state.get("tcpMappings", [])]
    if sources["peerServices"] == "ok":
        services += [(P, s) for s in state.get("peerServices", [])]

    sharing = state.get("peerSharing") or {}
    sharing_on = bool(sharing.get("deploymentEnabled")) and bool(sharing.get("configuredEnabled"))

    found = {}
    for kind, svc in services:
        if not svc["enabled"]:
            continue                                  # a choice, not a problem
        code = None
        client = None if clients is None else clients.get(svc["clientId"])
        if client is not None and not client["enabled"]:
            code = "DEVICE_DISABLED"
        elif client is not None and not client["online"]:
            code = "DEVICE_OFFLINE"
        elif kind == P:
            instance = svc.get("instance")
            if not sharing_on:
                code = "PEER_SHARING_OFF"
            elif instance is None or not instance["online"]:
                code = "PEER_NOT_REPORTED"
            elif instance["expired"]:
                code = "PEER_DIRECTORY_EXPIRED"
            elif not instance["advertised"] or not instance["hasAddress"]:
                code = "PEER_NOT_ADVERTISED"
        if code is None:
            continue
        group = None if code == "PEER_SHARING_OFF" else svc["clientId"]
        found.setdefault((code, group), []).append({"kind": kind, "id": svc["id"]})

    out = []
    for (code, group), refs in found.items():
        refs.sort(key=lambda r: ref_key(r["kind"], r["id"]))
        entry = {"code": code, "severity": SEVERITY[code]}
        if group is not None:
            entry["clientId"] = group
        entry["services"] = refs
        out.append(entry)
    out.sort(key=lambda p: (0 if p["severity"] == "blocking" else 1, CODE_ORDER[p["code"]], p.get("clientId", 0)))
    return {"complete": not unread, "unreadSources": unread, "problems": out}


def ok_sources(**overrides):
    base = {s: "ok" for s in SOURCES}
    base.update(overrides)
    return base


def client(cid, online=True, enabled=True):
    return {"id": cid, "enabled": enabled, "online": online}


def svc(sid, cid, enabled=True):
    return {"id": sid, "clientId": cid, "enabled": enabled}


def peer(sid, cid, enabled=True, instance=None):
    return {"id": sid, "clientId": cid, "enabled": enabled, "instance": instance}


def inst(online=True, expired=False, advertised=True, has_address=True):
    return {"online": online, "expired": expired, "advertised": advertised, "hasAddress": has_address}


SHARING_ON = {"deploymentEnabled": True, "configuredEnabled": True}

PROBLEM_CASES = [
    ("nothing-known",
     "Online devices and no report against any service: no known problem. The page still says this "
     "does not mean any service is reachable.",
     {"sources": ok_sources(), "clients": [client(1)], "httpRoutes": [svc(10, 1)], "tcpMappings": [svc(20, 1)],
      "peerSharing": SHARING_ON, "peerServices": [peer(30, 1, instance=inst())]}),
    ("offline-device-with-services",
     "An offline device makes every enabled service on it unusable through specus. Disabled services "
     "are a choice and are not listed; an offline device with nothing enabled is not a problem.",
     {"sources": ok_sources(), "clients": [client(1, online=False), client(2, online=False)],
      "httpRoutes": [svc(10, 1), svc(11, 1, enabled=False), svc(12, 2, enabled=False)],
      "tcpMappings": [svc(20, 1)], "peerSharing": SHARING_ON, "peerServices": [peer(30, 1, instance=inst(online=False))]}),
    ("disabled-device-wins",
     "Each service appears under its most fundamental cause only: a disabled device, then an offline "
     "one, then the sharing switch, then the Peer report.",
     {"sources": ok_sources(), "clients": [client(1, online=False, enabled=False)],
      "httpRoutes": [svc(10, 1)], "tcpMappings": [], "peerSharing": {"deploymentEnabled": True, "configuredEnabled": False},
      "peerServices": [peer(30, 1)]}),
    ("sharing-off",
     "The tenant sharing switch is off (or the deployment has no Peer Mesh): enabled Peer services "
     "are not offered to anyone. One problem for the tenant.",
     {"sources": ok_sources(), "clients": [client(1), client(2)], "httpRoutes": [], "tcpMappings": [],
      "peerSharing": {"deploymentEnabled": True, "configuredEnabled": False},
      "peerServices": [peer(31, 2, instance=inst()), peer(30, 1, instance=inst())]}),
    ("peer-attention",
     "Device online but the Peer directory does not list the service. The publisher reports only "
     "while an authorized peer is online, and only services its local probe found, so the cause is "
     "not determined: attention, not blocking.",
     {"sources": ok_sources(), "clients": [client(1), client(2)], "httpRoutes": [], "tcpMappings": [],
      "peerSharing": SHARING_ON,
      "peerServices": [peer(30, 1), peer(31, 1, instance=inst(expired=True)), peer(32, 2, instance=inst(advertised=False)),
                       peer(33, 2, instance=inst(has_address=False)), peer(34, 2, instance=inst())]}),
    ("clients-unreadable",
     "Without the device list no device problem can be derived, and the list is marked incomplete -- "
     "never shown as 'no problems'.",
     {"sources": ok_sources(clients="failed"), "httpRoutes": [svc(10, 1)], "tcpMappings": [],
      "peerSharing": SHARING_ON, "peerServices": [peer(30, 1, instance=inst(advertised=False))]}),
    ("peer-unsupported",
     "A server that answers 404/405 for Peer services (older, or Peer Mesh not offered) is not a "
     "failure: there is simply no such service, and the list stays complete.",
     {"sources": ok_sources(peerServices="unsupported"), "clients": [client(1, online=False)],
      "httpRoutes": [svc(10, 1)], "tcpMappings": []}),
    ("unknown-client",
     "A service whose device is missing from a list that did load (a race between reads) is not "
     "reported as offline.",
     {"sources": ok_sources(), "clients": [], "httpRoutes": [svc(10, 9)], "tcpMappings": [], "peerSharing": SHARING_ON,
      "peerServices": []}),
]

PROBLEM_EXPECTED = {
    "nothing-known": (True, [], []),
    "offline-device-with-services": (True, [], [("DEVICE_OFFLINE", 1, ["r10", "m20", "p30"])]),
    "disabled-device-wins": (True, [], [("DEVICE_DISABLED", 1, ["r10", "p30"])]),
    "sharing-off": (True, [], [("PEER_SHARING_OFF", None, ["p30", "p31"])]),
    "peer-attention": (True, [], [("PEER_NOT_REPORTED", 1, ["p30"]), ("PEER_DIRECTORY_EXPIRED", 1, ["p31"]),
                                  ("PEER_NOT_ADVERTISED", 2, ["p32", "p33"])]),
    "clients-unreadable": (False, ["clients"], [("PEER_NOT_ADVERTISED", 1, ["p30"])]),
    "peer-unsupported": (True, [], [("DEVICE_OFFLINE", 1, ["r10"])]),
    "unknown-client": (True, [], []),
}


def build_problems():
    cases = []
    for name, note, state in PROBLEM_CASES:
        result = problems(state)
        got = (result["complete"], result["unreadSources"],
               [(p["code"], p.get("clientId"), [short(r["kind"], r["id"]) for r in p["services"]])
                for p in result["problems"]])
        assert got == PROBLEM_EXPECTED[name], (name, got)
        # A service is listed under one problem at most.
        listed = [(r["kind"], r["id"]) for p in result["problems"] for r in p["services"]]
        assert len(listed) == len(set(listed)), name
        # Blocking problems come first.
        severities = [p["severity"] for p in result["problems"]]
        assert severities == sorted(severities, key=lambda s: s != "blocking"), name
        cases.append({"name": name, "note": note, "input": state, "expect": result})
    assert set(PROBLEM_EXPECTED) == {name for name, _, _ in PROBLEM_CASES}
    used = {p["code"] for case in cases for p in case["expect"]["problems"]}
    assert used == set(CODE_ORDER), set(CODE_ORDER) - used
    return cases


def build():
    scenarios = build_scenarios()

    # The API refusals, in the order the server evaluates them; an earlier refusal hides the later
    # ones. Each appears in at least one scenario.
    refusals = [
        {"order": 1, "when": "no valid management session", "httpStatus": 401},
        {"order": 1, "when": "a valid token whose account no longer exists or is disabled: the existing "
                             "authentication layer's answer (401 or 403 depending on the server)",
         "sessionRejected": True},
        {"order": 2, "when": "kind or id in the path invalid", "httpStatus": 400, "code": "WORKBENCH_REQUEST_INVALID"},
        {"order": 3, "when": "growth only: the identity's rate limit refuses (consumes nothing)", "httpStatus": 429,
         "code": "WORKBENCH_RATE_LIMITED"},
        {"order": 4, "when": "the store cannot be read or written", "httpStatus": 503, "code": "WORKBENCH_UNAVAILABLE"},
        {"order": 5, "when": "growth only: the object does not exist or is not visible to the caller now",
         "httpStatus": 404, "code": "WORKBENCH_TARGET_NOT_FOUND"},
        {"order": 6, "when": "adding a favourite that is not there while 50 are stored", "httpStatus": 409,
         "code": "WORKBENCH_FAVORITES_FULL"},
    ]
    seen = {(s["expect"]["httpStatus"], s["expect"].get("body", {}).get("code"))
            for sc in scenarios for s in sc["steps"]
            if "expect" in s and s["expect"].get("httpStatus", 200) != 200}
    assert seen == {(r["httpStatus"], r.get("code")) for r in refusals if "httpStatus" in r}, seen
    assert any(s["expect"].get("sessionRejected") for sc in scenarios for s in sc["steps"] if "expect" in s)

    # Order checks the scenarios do not spell out: an earlier refusal hides every later one.
    probe = Server([user("t1", "alice")], [obj(R, 1)], [row("favorite", R, n, n) for n in range(1, 51)])
    assert probe.handle(None, "PUT", PREFIX + "/favorites/bad/0", 0)["httpStatus"] == 401
    probe.store_up = False
    assert probe.handle(("t1", "alice"), "PUT", PREFIX + "/favorites/bad/0", 0)["httpStatus"] == 400
    assert probe.handle(("t1", "alice"), "PUT", PREFIX + "/favorites/http-route/77", 0)["httpStatus"] == 503
    probe.store_up = True
    assert probe.handle(("t1", "alice"), "PUT", PREFIX + "/favorites/http-route/77", 1)["httpStatus"] == 404
    assert probe.handle(("t1", "alice"), "PUT", PREFIX + "/favorites/http-route/1", 2)["httpStatus"] == 200
    probe.objects[(R, 51)] = obj(R, 51)
    assert probe.handle(("t1", "alice"), "PUT", PREFIX + "/favorites/http-route/51", 3)["httpStatus"] == 409

    return {
        "name": "service-workbench-v1",
        "version": 1,
        "description": "Per-identity favourites and recently opened services of the admin web's service workbench: "
                       "bounds, retention, ordering, dedupe, isolation, cascades and refusals every server must "
                       "reproduce, plus the frontend-only rule deriving pending problems from existing state. "
                       "See protocol/spec/service-workbench.md.",
        "notes": [
            "时间：所有 atMs 是相对 baseTime 的毫秒数，由测试注入的时钟给出；响应里的 addedAt/visitedAt 是对应时刻的 "
            "RFC 3339 UTC 字符串，精确到毫秒（三位小数）。实现按时刻比较，不按字符串比较。",
            "每个 scenario 独立：先建 users、objects，再把 rows 直接写入存储（可以超出上限，用来模拟并发竞争留下的行），"
            "限流器从空开始；然后按顺序重放 steps。带 event 的一步不是工作台接口，而是由其他管理操作或测试夹具造成的状态变化："
            "delete-object 走现有删除接口（或删除承载它的客户端），set-admin/change-owner/create-user/delete-user 走现有账号与客户端管理，"
            "store-down/store-up 由测试让存储读写失败或恢复，sweep 触发一次全局保留期清理。",
            "users[].admin 表示租户管理员；objects[].ownerUsername 是承载该服务的客户端的 owner_username。"
            "可见规则：同租户，且是管理员或该客户端的所有者。objects 的 id 在整个库内按 kind 唯一，与现有自增主键一致。",
            "带 method/path 的一步是工作台接口调用；as 为 null 表示没有有效的管理会话。expect 是完整响应：httpStatus、"
            "可选的 retryAfterSeconds（对应 Retry-After 头）与 body；实现逐字段相等，错误响应只比较 body.code。"
            "expect 为 {\"sessionRejected\": true} 表示 token 有效但账号已删除或停用：按各服务端现有鉴权层的口径拒绝"
            "（401 或 403），断言不是 2xx 且没有写入任何行。",
            "rowsAfter 是整个 scenario 结束后存储里应当剩下的全部工作台行，用来证明过期、超限、级联删除的行是被删除而不是被隐藏。",
            "problems 一节只由管理前端读取：输入是前端已经从现有列表接口读到的状态，期望是待处理问题列表。服务端不实现它。",
        ],
        "baseTime": stamp(0).replace(".000Z", "Z"),
        "limits": {"maxFavorites": MAX_FAVORITES, "maxRecents": MAX_RECENTS,
                   "recentRetentionDays": RECENT_RETENTION_DAYS, "recentRetentionMs": RECENT_RETENTION_MS,
                   "maxObjectId": MAX_OBJECT_ID},
        "kinds": list(KINDS),
        "rate": {"algorithm": "gcra", "key": "tenantId+username", "intervalMs": WRITE_INTERVAL_MS,
                 "burst": WRITE_BURST, "limited": ["PUT favorites/{kind}/{id}", "POST recents/{kind}/{id}"]},
        "apiRefusals": refusals,
        "scenarios": scenarios,
        "problems": {
            "codes": [{"code": code, "severity": severity} for code, severity in PROBLEM_CODES],
            "cases": build_problems(),
        },
    }


def render(value, level=0):
    """json.dumps(indent=2), except that an object or array holding only scalars stays on one line:
    store rows and list entries repeat many times and read better that way."""
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
    path = VECTORS / "service-workbench-v1.json"
    text = render(document) + "\n"
    assert json.loads(text) == document
    path.write_text(text, encoding="utf-8", newline="\n")
    steps = sum(len(sc["steps"]) for sc in document["scenarios"])
    print(f"wrote {path}: scenarios={len(document['scenarios'])} steps={steps} "
          f"problemCases={len(document['problems']['cases'])}")


if __name__ == "__main__":
    main()
