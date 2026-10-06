"""Generate protocol/test-vectors/temporary-http-share-v1.json.

A temporary HTTP share is a separate grant for ONE existing, protected HTTP route: it expires, it can
be revoked, it may narrow the route to a path prefix and to read-only methods, and it never changes
the route itself. Visitors reach the route under /http-share/{shareId}/ with an HttpOnly cookie that
holds the share token; the token travels in a URL fragment exactly once (never in a path or query
that reverse proxies log) and the server stores only its SHA-256. See
protocol/spec/temporary-http-share.md.

The reference below decides, for each case, what a server answers: share creation, the token
exchange that sets the cookie, every request under /http-share/, revocation, the lifecycle events
that end shares as a side effect (route disabled, made public or deleted; client disabled or
deleted; the creator losing the right to manage the route), the expiry sweep, the audit entries all
of these write, the header rewriting on the way to the device and back, and the rate limits.

Every expectation is produced by the reference and checked against a hand-written table before the
file is written, so the vector cannot ship contradicting itself.
"""
import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

VECTORS = Path("protocol/test-vectors")

TOKEN_VERSION = "hs1"
SHARE_ID_BYTES = 12            # 16 base64url characters, public, unguessable so ids cannot be enumerated
SECRET_BYTES = 32              # 43 base64url characters, the bearer secret
TOKEN_RE = re.compile(r"hs1\.([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{43})")
SHARE_ID_RE = re.compile(r"[A-Za-z0-9_-]{16}")
COOKIE_NAME = "__Secure-specus_http_share"
MAX_COOKIE_CANDIDATES = 4
SHARE_ROOT = "/http-share/"
LINK_ROOT = "/#/http-share/"

MIN_EXPIRES_SECONDS = 300
MAX_EXPIRES_SECONDS = 604_800
MAX_ACTIVE_PER_ROUTE = 20
LABEL_MAX_CODE_POINTS = 60
PREFIX_MAX_BYTES = 256
READ_METHODS = ("GET", "HEAD")

EXCHANGE_INTERVAL_MS = 6_000   # per source address: 10 at once, then one every 6 s
EXCHANGE_BURST = 10
SHARE_INTERVAL_MS = 50         # per share: 200 at once (a page load), then 20 per second
SHARE_BURST = 200
MAX_CONCURRENT_PER_SHARE = 64

SHARE_RETENTION_DAYS = 30
AUDIT_RETENTION_DAYS = 180
SWEEP_INTERVAL_MAX_SECONDS = 60
STREAM_RECHECK_MAX_SECONDS = 5

REVOKE_REASONS = ("revoked-by-user", "route-disabled", "route-made-public", "route-deleted",
                  "client-disabled", "client-deleted", "creator-lost-access")
AUDIT_ACTIONS = ("share.created", "share.revoked", "share.expired", "route.created",
                 "route.exposure-changed", "route.credentials-changed", "route.deleted")

UNRESERVED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
# RFC 3986 pchar without ";": a servlet container treats ";" as the start of path parameters, so
# "/docs/..;/admin" would leave the prefix after the container has normalised it.
PATH_CHARS = UNRESERVED | set("!$&'()*+,=:@/")
HEX = set("0123456789abcdefABCDEF")


# --------------------------------------------------------------------------------------------------
# Time and encoding helpers


def instant(text):
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def stamp(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def make_token(share_id_hex, secret_hex):
    share_id = b64url(bytes.fromhex(share_id_hex))
    secret = b64url(bytes.fromhex(secret_hex))
    assert len(share_id) == 16 and len(secret) == 43
    token = f"{TOKEN_VERSION}.{share_id}.{secret}"
    return share_id, token


def parse_token(text):
    """The share id embedded in a well-formed token, or None. The hash covers the whole string, so a
    non-canonical base64url tail is not a second spelling of the same secret: it simply never
    matches a stored hash."""
    if not isinstance(text, str):
        return None
    match = TOKEN_RE.fullmatch(text)   # whole string: a trailing newline is not tolerated
    return match.group(1) if match else None


# --------------------------------------------------------------------------------------------------
# Paths


def normalize_path(raw):
    """RFC 3986 6.2.2 syntax normalisation of an already percent-encoded path: escapes of unreserved
    characters are decoded and every other escape gets upper-case hex. Returns None for a path that
    is not plain ASCII pchar/"/"/escapes, or that has a malformed escape. The result is used only to
    decide the scope; the request is forwarded with its original raw path."""
    out = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "%":
            pair = raw[i + 1:i + 3]
            if len(pair) != 2 or not set(pair) <= HEX:
                return None
            decoded = chr(int(pair, 16))
            out.append(decoded if decoded in UNRESERVED else "%" + pair.upper())
            i += 3
            continue
        if ch not in PATH_CHARS:
            return None
        out.append(ch)
        i += 1
    return "".join(out)


FORBIDDEN_ESCAPES = {"%2F", "%5C"} | {f"%{code:02X}" for code in list(range(0x20)) + [0x7F]}


def unsafe_for_prefix(normalized):
    """A normalized path that could step outside a prefix once the target decodes it: a dot
    segment, or an escaped slash, backslash or control character."""
    escapes = re.findall(r"%[0-9A-F]{2}", normalized)
    if any(e in FORBIDDEN_ESCAPES for e in escapes):
        return True
    segments = normalized.split("/")[1:]
    return any(segment in (".", "..") for segment in segments)


def canonical_prefix(value):
    """The stored form of a pathPrefix, or None when it must be rejected with 400."""
    if not isinstance(value, str):
        return None
    if not value.startswith("/") or value.startswith("//"):
        return None
    normalized = normalize_path(value)
    if normalized is None or unsafe_for_prefix(normalized):
        return None
    inner = normalized[1:-1] if normalized.endswith("/") else normalized[1:]
    if inner and any(segment == "" for segment in inner.split("/")):
        return None
    canonical = normalized if normalized.endswith("/") else normalized + "/"
    if len(canonical.encode("ascii")) > PREFIX_MAX_BYTES:
        return None
    return canonical


def path_in_scope(prefix, relative_path):
    if prefix == "/":
        return True   # the whole route: no rule beyond the route's own
    normalized = normalize_path(relative_path)
    if normalized is None or unsafe_for_prefix(normalized):
        return False
    return normalized == prefix[:-1] or normalized.startswith(prefix)


def scope_decision(share, method, relative_path, upgrade):
    """None when the request is inside the share's scope, else the refusal."""
    if share["access"] == "read":
        if method not in READ_METHODS:
            return {"httpStatus": 405, "code": "SHARE_METHOD_NOT_ALLOWED", "allow": "GET, HEAD"}
        if upgrade:
            return {"httpStatus": 403, "code": "SHARE_SCOPE_DENIED"}
    if not path_in_scope(share["pathPrefix"], relative_path):
        return {"httpStatus": 403, "code": "SHARE_SCOPE_DENIED"}
    return None


# --------------------------------------------------------------------------------------------------
# Who may manage a route, and whether a share's route still allows it


def exposure(route):
    if not route["enabled"]:
        return "disabled"
    return "protected" if route["authEnabled"] else "public"


def can_manage(user, route, client):
    """The rule the route management API already applies, evaluated for the user now."""
    if user is None or not user.get("enabled", True):
        return False
    if user["tenantId"] != route["tenantId"]:
        return False
    return user["role"] == "ADMIN" or (client is not None and client["owner"] == user["username"])


def lapse_reason(share, store):
    """Why a share that is neither revoked nor expired can no longer be honoured, or None."""
    route = store["routes"].get(share["routeId"])
    if route is None or route["tenantId"] != share["tenantId"]:
        return "route-deleted"
    client = store["clients"].get(route["clientId"])
    if client is None:
        return "client-deleted"
    if not client["enabled"]:
        return "client-disabled"
    state = exposure(route)
    if state == "disabled":
        return "route-disabled"
    if state == "public":
        return "route-made-public"
    if not can_manage(store["users"].get(share["createdBy"]), route, client):
        return "creator-lost-access"
    return None


def status_of(share, now):
    if share.get("revokedAt") is not None:
        return "revoked"
    if now >= instant(share["expiresAt"]):
        return "expired"
    return "active"


def view(share, now):
    return {
        "shareId": share["shareId"],
        "routeId": share["routeId"],
        "label": share.get("label"),
        "access": share["access"],
        "pathPrefix": share["pathPrefix"],
        "sharePath": SHARE_ROOT + share["shareId"] + "/",
        "createdAt": share["createdAt"],
        "createdBy": share["createdBy"],
        "expiresAt": share["expiresAt"],
        "status": status_of(share, now),
        "revokedAt": share.get("revokedAt"),
        "revokedBy": share.get("revokedBy"),
        "revokeReason": share.get("revokeReason"),
    }


# --------------------------------------------------------------------------------------------------
# Cookies and headers


def cookie_pairs(cookie_headers):
    pairs = []
    for header in cookie_headers:
        for part in header.split(";"):
            part = part.strip(" \t")
            if part:
                pairs.append(part)
    return pairs


def pair_name(pair):
    return pair.split("=", 1)[0].strip(" \t")


def pair_value(pair):
    return pair.split("=", 1)[1].strip(" \t") if "=" in pair else ""


def credential_candidates(cookie_headers, share_id):
    """Values of the share cookie that name this share, in order, at most MAX_COOKIE_CANDIDATES.
    A page on the same origin can plant a second cookie of the same name with a longer Path; it is
    sent first, so the server tries a few values instead of only the first one."""
    out = []
    for pair in cookie_pairs(cookie_headers):
        if pair_name(pair) != COOKIE_NAME:
            continue
        value = pair_value(pair)
        if parse_token(value) == share_id:
            out.append(value)
    return out[:MAX_COOKIE_CANDIDATES]


def forwarded_cookie(cookie_headers):
    """The single Cookie header sent to the device: every pair except the share cookie, in order."""
    kept = [pair for pair in cookie_pairs(cookie_headers) if pair_name(pair) != COOKIE_NAME]
    return "; ".join(kept) if kept else None


CACHE_HEADERS = {"cache-control", "cdn-cache-control", "surrogate-control", "expires", "pragma"}


def scope_set_cookie(value, share_id):
    """An upstream Set-Cookie value confined to the share path, or None when it is dropped.
    Every route and share lives on one origin; a cookie set with Path=/ or a Domain by the target of
    share A would otherwise be sent to every other route and share the visitor opens, i.e. to other
    owners' devices. The reserved share cookie and __Host- cookies (which require Path=/) are
    dropped; Domain is removed; a Path starting with "/" is moved under the share path. A missing
    or relative Path already defaults to the request directory, which is under the share path."""
    parts = value.split(";")
    name = parts[0].split("=", 1)[0].strip(" \t")
    if name == COOKIE_NAME or name.lower().startswith("__host-"):
        return None
    out = [parts[0].strip(" \t")]
    for part in parts[1:]:
        attribute = part.strip(" \t")
        if not attribute:
            continue
        key = attribute.split("=", 1)[0].strip(" \t").lower()
        if key == "domain":
            continue
        if key == "path":
            path = attribute.split("=", 1)[1].strip(" \t") if "=" in attribute else ""
            if path.startswith("/"):
                attribute = "Path=" + SHARE_ROOT + share_id + path
        out.append(attribute)
    return "; ".join(out)


def response_headers(status, headers, share_id):
    """Headers relayed to a share visitor, after the route's own response rules. Set-Cookie is
    confined to the share path; Clear-Site-Data is dropped because it would wipe the whole origin
    (the admin console and every other share); cache headers are replaced so that no shared cache
    keeps a copy and the browser revalidates every reuse -- a revoked share then stops serving even
    what the browser cached. A 101 keeps its other headers: only the cookie and Clear-Site-Data
    rules apply to it."""
    no_store = False
    out = []
    for header in headers:
        name, _, value = header.partition(":")
        lowered = name.strip().lower()
        if lowered == "clear-site-data":
            continue
        if lowered == "set-cookie":
            scoped = scope_set_cookie(value.strip(" \t"), share_id)
            if scoped is not None:
                out.append(name.strip() + ":" + scoped)
            continue
        if status != 101 and lowered in CACHE_HEADERS:
            if lowered == "cache-control":
                directives = [d.strip().split("=", 1)[0].lower() for d in value.split(",")]
                no_store = no_store or "no-store" in directives
            continue
        out.append(header)
    if status != 101:
        out.append("Cache-Control:" + ("private, no-store" if no_store else "private, no-cache"))
    return out


def set_cookie(share_id, token, expires_at, now):
    max_age = int((instant(expires_at) - now).total_seconds())
    assert max_age >= 1
    return {"name": COOKIE_NAME, "value": token, "path": SHARE_ROOT + share_id + "/", "maxAge": max_age,
            "httpOnly": True, "secure": True, "sameSite": "Strict", "domain": None}


def clear_cookie(share_id):
    return {"name": COOKIE_NAME, "value": "", "path": SHARE_ROOT + share_id + "/", "maxAge": 0,
            "httpOnly": True, "secure": True, "sameSite": "Strict", "domain": None}


# --------------------------------------------------------------------------------------------------
# The fixture world: one tenant with an admin and two owners, a second tenant, routes and shares


NOW = "2026-10-06T08:00:00Z"
T0 = instant(NOW)


def at(seconds):
    return stamp(T0 + timedelta(seconds=seconds))


SHARE_A_ID, TOKEN_A = make_token("1f8b3c5d7e9a0b2c4d6e8f10",
                                 "a3c5e7f90b1d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a")
SHARE_B_ID, TOKEN_B = make_token("00ff00ff00ff00ff00ff00ff",
                                 "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
SHARE_C_ID, TOKEN_C = make_token("fbefbefbefbefbefbefbefbe",
                                 "0000000000000000000000000000000000000000000000000000000000000000")
NEW_SHARE_ID, NEW_TOKEN = make_token("5a5a5a5a5a5a5a5a5a5a5a5a",
                                     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")


def world():
    return {
        "users": {
            "admin": {"username": "admin", "tenantId": "t1", "role": "ADMIN", "enabled": True},
            "carol": {"username": "carol", "tenantId": "t1", "role": "ADMIN", "enabled": True},
            "alice": {"username": "alice", "tenantId": "t1", "role": "USER", "enabled": True},
            "bob": {"username": "bob", "tenantId": "t1", "role": "USER", "enabled": True},
            "eve": {"username": "eve", "tenantId": "t2", "role": "ADMIN", "enabled": True},
        },
        "clients": {
            7: {"clientId": 7, "tenantId": "t1", "owner": "alice", "enabled": True},
            8: {"clientId": 8, "tenantId": "t1", "owner": "bob", "enabled": True},
        },
        "routes": {
            42: {"routeId": 42, "tenantId": "t1", "clientId": 7, "name": "api", "enabled": True, "authEnabled": True},
            43: {"routeId": 43, "tenantId": "t1", "clientId": 7, "name": "blog", "enabled": True, "authEnabled": False},
            44: {"routeId": 44, "tenantId": "t1", "clientId": 7, "name": "old", "enabled": False, "authEnabled": True},
            50: {"routeId": 50, "tenantId": "t1", "clientId": 8, "name": "nas", "enabled": True, "authEnabled": True},
        },
        "shares": {},
    }


def share_row(share_id, token, route_id=42, created_by="alice", access="read", prefix="/",
              created_at=-3600, expires_in=86_400, label=None, revoked=None):
    row = {"shareId": share_id, "tenantId": "t1", "routeId": route_id, "tokenSha256": token_hash(token),
           "access": access, "pathPrefix": prefix, "label": label, "createdBy": created_by,
           "createdAt": at(created_at), "expiresAt": at(created_at + expires_in),
           "revokedAt": None, "revokedBy": None, "revokeReason": None}
    if revoked:
        row.update(revoked)
    return row


def store_with(*rows, mutate=None):
    store = world()
    for row in rows:
        store["shares"][row["shareId"]] = row
    if mutate:
        mutate(store)
    return store


# --------------------------------------------------------------------------------------------------
# 1. Creation


def validate_create_body(body):
    """The normalized fields, or None for 400."""
    if not isinstance(body, dict) or set(body) - {"expiresInSeconds", "access", "pathPrefix", "label"}:
        return None
    seconds = body.get("expiresInSeconds")
    if isinstance(seconds, bool) or not isinstance(seconds, int):
        return None
    if not MIN_EXPIRES_SECONDS <= seconds <= MAX_EXPIRES_SECONDS:
        return None
    access = body.get("access", "read")
    if access not in ("read", "full"):
        return None
    prefix = canonical_prefix(body.get("pathPrefix", "/"))
    if prefix is None:
        return None
    label = body.get("label")
    if label is not None:
        if not isinstance(label, str):
            return None
        label = label.strip(" ")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in label):
            return None
        if len(label) > LABEL_MAX_CODE_POINTS:
            return None
        label = label or None
    return {"expiresInSeconds": seconds, "access": access, "pathPrefix": prefix, "label": label}


def create(case):
    if not case.get("authenticated", True):
        return {"httpStatus": 401}
    fields = validate_create_body(case["body"])
    if fields is None:
        return {"httpStatus": 400, "code": "SHARE_REQUEST_INVALID"}
    if not case.get("readable", True):
        return {"httpStatus": 503, "code": "SHARE_UNAVAILABLE"}
    store = store_with(*case.get("shares", []), mutate=case.get("mutate"))
    now = instant(case.get("now", NOW))
    user = store["users"].get(case["caller"])
    route = store["routes"].get(case["routeId"])
    client = store["clients"].get(route["clientId"]) if route else None
    if route is None or not can_manage(user, route, client):
        return {"httpStatus": 404, "code": "SHARE_ROUTE_NOT_FOUND"}
    if not route["enabled"]:
        return {"httpStatus": 409, "code": "SHARE_ROUTE_DISABLED"}
    if client is None or not client["enabled"]:
        return {"httpStatus": 409, "code": "SHARE_CLIENT_DISABLED"}
    if not route["authEnabled"]:
        return {"httpStatus": 409, "code": "SHARE_ROUTE_PUBLIC"}
    active = [s for s in store["shares"].values()
              if s["routeId"] == route["routeId"] and status_of(s, now) == "active"]
    if len(active) >= MAX_ACTIVE_PER_ROUTE:
        return {"httpStatus": 409, "code": "SHARE_LIMIT_REACHED"}
    row = {"shareId": NEW_SHARE_ID, "tenantId": route["tenantId"], "routeId": route["routeId"],
           "tokenSha256": token_hash(NEW_TOKEN), "access": fields["access"],
           "pathPrefix": fields["pathPrefix"], "label": fields["label"], "createdBy": user["username"],
           "createdAt": stamp(now), "expiresAt": stamp(now + timedelta(seconds=fields["expiresInSeconds"])),
           "revokedAt": None, "revokedBy": None, "revokeReason": None}
    return {
        "httpStatus": 201,
        "body": {"share": view(row, now), "token": NEW_TOKEN, "linkPath": LINK_ROOT + NEW_TOKEN},
        "audit": [{"action": "share.created", "at": stamp(now), "actor": user["username"],
                   "routeId": route["routeId"], "shareId": NEW_SHARE_ID,
                   "detail": {"access": fields["access"], "pathPrefix": fields["pathPrefix"],
                              "expiresAt": row["expiresAt"]}}],
    }


def many_active(count, route_id=42):
    rows = []
    for i in range(count):
        share_id, token = make_token(f"{i + 1:024x}", f"{i + 1:064x}")
        rows.append(share_row(share_id, token, route_id=route_id))
    return rows


CREATE_BODY = {"expiresInSeconds": 86_400}

CREATE_CASES = [
    ("owner-creates-read-share", {"caller": "alice", "routeId": 42, "body": CREATE_BODY},
     "Defaults: read-only, the whole route, no label."),
    ("admin-creates-full-share-with-prefix",
     {"caller": "admin", "routeId": 42,
      "body": {"expiresInSeconds": 3600, "access": "full", "pathPrefix": "/docs", "label": "  周报评审  "}},
     "A tenant admin may share any route of the tenant. The prefix gets its trailing slash; the label "
     "is trimmed of spaces."),
    ("minimum-expiry", {"caller": "alice", "routeId": 42, "body": {"expiresInSeconds": MIN_EXPIRES_SECONDS}}, ""),
    ("maximum-expiry", {"caller": "alice", "routeId": 42, "body": {"expiresInSeconds": MAX_EXPIRES_SECONDS}}, ""),
    ("expiry-below-minimum", {"caller": "alice", "routeId": 42, "body": {"expiresInSeconds": MIN_EXPIRES_SECONDS - 1}}, ""),
    ("expiry-above-maximum", {"caller": "alice", "routeId": 42, "body": {"expiresInSeconds": MAX_EXPIRES_SECONDS + 1}},
     "There is no unbounded share: a long-lived grant is what a protected route with its own password is for."),
    ("expiry-missing", {"caller": "alice", "routeId": 42, "body": {}}, "The expiry is mandatory; there is no default."),
    ("expiry-not-integer", {"caller": "alice", "routeId": 42, "body": {"expiresInSeconds": "3600"}}, ""),
    ("expiry-fractional", {"caller": "alice", "routeId": 42, "body": {"expiresInSeconds": 3600.5}}, ""),
    ("expiry-boolean", {"caller": "alice", "routeId": 42, "body": {"expiresInSeconds": True}}, ""),
    ("unknown-access", {"caller": "alice", "routeId": 42, "body": {"expiresInSeconds": 3600, "access": "write"}}, ""),
    ("unknown-field", {"caller": "alice", "routeId": 42, "body": {"expiresInSeconds": 3600, "maxUses": 1}},
     "Unknown fields are rejected, so a client cannot believe a limit is enforced when it is not."),
    ("bad-prefix", {"caller": "alice", "routeId": 42, "body": {"expiresInSeconds": 3600, "pathPrefix": "/a/../b"}}, ""),
    ("label-too-long", {"caller": "alice", "routeId": 42,
                        "body": {"expiresInSeconds": 3600, "label": "x" * (LABEL_MAX_CODE_POINTS + 1)}}, ""),
    ("label-control-character", {"caller": "alice", "routeId": 42, "body": {"expiresInSeconds": 3600, "label": "a\nb"}}, ""),
    ("body-not-object", {"caller": "alice", "routeId": 42, "body": [3600]}, ""),
    ("unauthenticated", {"authenticated": False, "caller": None, "routeId": 42, "body": CREATE_BODY}, ""),
    ("store-unreadable", {"caller": "alice", "routeId": 42, "body": CREATE_BODY, "readable": False},
     "A read failure is not reported as a missing route."),
    ("other-owner", {"caller": "bob", "routeId": 42, "body": CREATE_BODY},
     "Not the owner and not an admin: indistinguishable from a route that does not exist."),
    ("other-tenant-admin", {"caller": "eve", "routeId": 42, "body": CREATE_BODY}, ""),
    ("route-absent", {"caller": "admin", "routeId": 99, "body": CREATE_BODY}, ""),
    ("route-disabled", {"caller": "alice", "routeId": 44, "body": CREATE_BODY}, ""),
    ("route-public", {"caller": "alice", "routeId": 43, "body": CREATE_BODY},
     "A public route is reachable by anyone already; a share on it would suggest that revoking the share "
     "stops access. Protect the route first."),
    ("client-disabled", {"caller": "alice", "routeId": 42, "body": CREATE_BODY,
                         "mutate": lambda s: s["clients"][7].update(enabled=False)}, ""),
    ("limit-reached", {"caller": "alice", "routeId": 42, "body": CREATE_BODY,
                       "shares": many_active(MAX_ACTIVE_PER_ROUTE)}, ""),
    ("ended-shares-do-not-count", {"caller": "alice", "routeId": 42, "body": CREATE_BODY,
                                   "shares": many_active(MAX_ACTIVE_PER_ROUTE - 1) + [
                                       share_row(SHARE_B_ID, TOKEN_B, created_at=-90_000, expires_in=3600),
                                       share_row(SHARE_C_ID, TOKEN_C,
                                                 revoked={"revokedAt": at(-60), "revokedBy": "alice",
                                                          "revokeReason": "revoked-by-user"})]},
     "Expired and revoked shares do not count against the limit of active shares per route."),
    ("other-route-shares-do-not-count", {"caller": "alice", "routeId": 42, "body": CREATE_BODY,
                                         "shares": many_active(MAX_ACTIVE_PER_ROUTE, route_id=50)}, ""),
]

CREATE_EXPECTED = {
    "owner-creates-read-share": (201, "read", "/", None, at(86_400)),
    "admin-creates-full-share-with-prefix": (201, "full", "/docs/", "周报评审", at(3600)),
    "minimum-expiry": (201, "read", "/", None, at(300)),
    "maximum-expiry": (201, "read", "/", None, at(604_800)),
    "expiry-below-minimum": (400, "SHARE_REQUEST_INVALID"),
    "expiry-above-maximum": (400, "SHARE_REQUEST_INVALID"),
    "expiry-missing": (400, "SHARE_REQUEST_INVALID"),
    "expiry-not-integer": (400, "SHARE_REQUEST_INVALID"),
    "expiry-fractional": (400, "SHARE_REQUEST_INVALID"),
    "expiry-boolean": (400, "SHARE_REQUEST_INVALID"),
    "unknown-access": (400, "SHARE_REQUEST_INVALID"),
    "unknown-field": (400, "SHARE_REQUEST_INVALID"),
    "bad-prefix": (400, "SHARE_REQUEST_INVALID"),
    "label-too-long": (400, "SHARE_REQUEST_INVALID"),
    "label-control-character": (400, "SHARE_REQUEST_INVALID"),
    "body-not-object": (400, "SHARE_REQUEST_INVALID"),
    "unauthenticated": (401, None),
    "store-unreadable": (503, "SHARE_UNAVAILABLE"),
    "other-owner": (404, "SHARE_ROUTE_NOT_FOUND"),
    "other-tenant-admin": (404, "SHARE_ROUTE_NOT_FOUND"),
    "route-absent": (404, "SHARE_ROUTE_NOT_FOUND"),
    "route-disabled": (409, "SHARE_ROUTE_DISABLED"),
    "route-public": (409, "SHARE_ROUTE_PUBLIC"),
    "client-disabled": (409, "SHARE_CLIENT_DISABLED"),
    "limit-reached": (409, "SHARE_LIMIT_REACHED"),
    "ended-shares-do-not-count": (201, "read", "/", None, at(86_400)),
    "other-route-shares-do-not-count": (201, "read", "/", None, at(86_400)),
}


# --------------------------------------------------------------------------------------------------
# 2. Exchange: the landing page posts the token from the fragment, the server sets the cookie


def exchange(case):
    content_type = case.get("contentType", "application/json")
    if content_type.split(";", 1)[0].strip().lower() != "application/json":
        return {"httpStatus": 415, "code": "SHARE_REQUEST_INVALID"}
    body = case["body"]
    if not isinstance(body, dict) or set(body) != {"token"} or not isinstance(body["token"], str):
        return {"httpStatus": 400, "code": "SHARE_REQUEST_INVALID"}
    if case.get("rateLimitedMs"):
        return {"httpStatus": 429, "code": "SHARE_RATE_LIMITED",
                "retryAfterSeconds": max(1, -(-case["rateLimitedMs"] // 1000))}
    # From here on the request has been charged to the source address.
    share_id = parse_token(body["token"])
    if share_id is None:
        return {"httpStatus": 404, "code": "SHARE_NOT_FOUND"}
    if not case.get("readable", True):
        return {"httpStatus": 503, "code": "SHARE_UNAVAILABLE"}
    store = store_with(*case.get("shares", []), mutate=case.get("mutate"))
    now = instant(case.get("now", NOW))
    share = store["shares"].get(share_id)
    if share is None or share["tokenSha256"] != token_hash(body["token"]):
        return {"httpStatus": 404, "code": "SHARE_NOT_FOUND"}
    ended = ended_response(share, store, now)
    if ended is not None:
        return ended
    location = SHARE_ROOT + share_id + share["pathPrefix"]
    return {"httpStatus": 200,
            "body": {"shareId": share_id, "location": location, "expiresAt": share["expiresAt"],
                     "access": share["access"], "pathPrefix": share["pathPrefix"]},
            "setCookie": set_cookie(share_id, body["token"], share["expiresAt"], now)}


def ended_response(share, store, now, clear=False):
    """For a caller who proved the token: the share has ended, say so. A share that has lapsed
    (its route, client or creator no longer allows it) is revoked on the spot, so it can never come
    back to life when the route is enabled again."""
    status = status_of(share, now)
    out = None
    if status == "revoked":
        out = {"httpStatus": 410, "code": "SHARE_REVOKED"}
    elif status == "expired":
        out = {"httpStatus": 410, "code": "SHARE_EXPIRED"}
    else:
        reason = lapse_reason(share, store)
        if reason is not None:
            out = {"httpStatus": 410, "code": "SHARE_REVOKED",
                   "revoke": {"reason": reason, "revokedBy": None},
                   "audit": [{"action": "share.revoked", "at": stamp(now), "actor": None,
                              "routeId": share["routeId"], "shareId": share["shareId"],
                              "detail": {"reason": reason}}]}
    if out is not None and clear:
        out["setCookie"] = clear_cookie(share["shareId"])
    return out


SHARE_A = share_row(SHARE_A_ID, TOKEN_A, access="read", prefix="/docs/")
SHARE_A_FULL = share_row(SHARE_A_ID, TOKEN_A, access="full", prefix="/")

EXCHANGE_CASES = [
    ("valid", {"body": {"token": TOKEN_A}, "shares": [SHARE_A]},
     "The cookie is scoped to the share path and lives exactly as long as the share; the landing page "
     "then replaces itself with location."),
    ("valid-with-charset", {"contentType": "application/json; charset=utf-8", "body": {"token": TOKEN_A},
                            "shares": [SHARE_A]}, ""),
    ("last-second", {"now": at(86_400 - 3600 - 1), "body": {"token": TOKEN_A}, "shares": [SHARE_A]},
     "One second before expiry: Max-Age is the one second left."),
    ("at-expiry", {"now": at(86_400 - 3600), "body": {"token": TOKEN_A}, "shares": [SHARE_A]},
     "Expiry is strict: at expiresAt the share has ended."),
    ("form-post", {"contentType": "application/x-www-form-urlencoded", "body": {"token": TOKEN_A},
                   "shares": [SHARE_A]},
     "Only JSON: another site cannot submit the exchange with a plain form."),
    ("extra-field", {"body": {"token": TOKEN_A, "remember": True}, "shares": [SHARE_A]}, ""),
    ("token-not-string", {"body": {"token": 7}, "shares": [SHARE_A]}, ""),
    ("malformed-token", {"body": {"token": "hs1." + SHARE_A_ID}, "shares": [SHARE_A]},
     "Charged to the source address like any attempt, answered like an unknown token."),
    ("wrong-secret", {"body": {"token": TOKEN_A[:-1] + ("A" if TOKEN_A[-1] != "A" else "B")}, "shares": [SHARE_A]},
     "Same share id, different secret: indistinguishable from a share that does not exist."),
    ("unknown-share", {"body": {"token": TOKEN_B}, "shares": [SHARE_A]}, ""),
    ("revoked", {"body": {"token": TOKEN_A}, "shares": [
        share_row(SHARE_A_ID, TOKEN_A, revoked={"revokedAt": at(-10), "revokedBy": "alice",
                                                "revokeReason": "revoked-by-user"})]},
     "Only someone holding the token learns that the share ended."),
    ("lapsed-route-public", {"body": {"token": TOKEN_A}, "shares": [SHARE_A],
                             "mutate": lambda s: s["routes"][42].update(authEnabled=False)},
     "The route was made public by a path that did not revoke its shares; the share is revoked now."),
    ("rate-limited", {"body": {"token": TOKEN_A}, "shares": [SHARE_A], "rateLimitedMs": 4500}, ""),
    ("store-unreadable", {"body": {"token": TOKEN_A}, "shares": [SHARE_A], "readable": False}, ""),
]

EXCHANGE_EXPECTED = {
    "valid": (200, None, SHARE_ROOT + SHARE_A_ID + "/docs/", 82_800),
    "valid-with-charset": (200, None, SHARE_ROOT + SHARE_A_ID + "/docs/", 82_800),
    "last-second": (200, None, SHARE_ROOT + SHARE_A_ID + "/docs/", 1),
    "at-expiry": (410, "SHARE_EXPIRED"),
    "form-post": (415, "SHARE_REQUEST_INVALID"),
    "extra-field": (400, "SHARE_REQUEST_INVALID"),
    "token-not-string": (400, "SHARE_REQUEST_INVALID"),
    "malformed-token": (404, "SHARE_NOT_FOUND"),
    "wrong-secret": (404, "SHARE_NOT_FOUND"),
    "unknown-share": (404, "SHARE_NOT_FOUND"),
    "revoked": (410, "SHARE_REVOKED"),
    "lapsed-route-public": (410, "SHARE_REVOKED", "route-made-public"),
    "rate-limited": (429, "SHARE_RATE_LIMITED"),
    "store-unreadable": (503, "SHARE_UNAVAILABLE"),
}


# --------------------------------------------------------------------------------------------------
# 3. Requests under /http-share/


def access(case):
    request = case["request"]
    path = request["path"]
    query = request.get("rawQuery", "")
    if not path.startswith(SHARE_ROOT):
        raise AssertionError("not a share path")
    rest = path[len(SHARE_ROOT):]
    share_id, slash, tail = rest.partition("/")
    if not SHARE_ID_RE.fullmatch(share_id):
        return {"httpStatus": 404, "code": "SHARE_NOT_FOUND"}
    if not slash:
        # The cookie path ends with a slash; without it the browser would not send the cookie.
        location = SHARE_ROOT + share_id + "/" + ("?" + query if query else "")
        return {"httpStatus": 308, "location": location}
    relative_path = "/" + tail
    if not case.get("readable", True):
        return {"httpStatus": 503, "code": "SHARE_UNAVAILABLE"}
    store = store_with(*case.get("shares", []), mutate=case.get("mutate"))
    now = instant(case.get("now", NOW))
    share = store["shares"].get(share_id)
    if share is None:
        return {"httpStatus": 404, "code": "SHARE_NOT_FOUND"}
    cookies = request.get("cookies", [])
    candidates = credential_candidates(cookies, share_id)
    if not any(token_hash(value) == share["tokenSha256"] for value in candidates):
        return {"httpStatus": 404, "code": "SHARE_NOT_FOUND"}
    ended = ended_response(share, store, now, clear=True)
    if ended is not None:
        return ended
    refusal = scope_decision(share, request["method"], relative_path, request.get("upgrade", False))
    if refusal is not None:
        return refusal
    admission = case.get("admission", "admitted")
    if admission == "share-busy":
        return {"httpStatus": 429, "code": "SHARE_BUSY", "retryAfterSeconds": 1}
    if admission == "rate-limited":
        return {"httpStatus": 429, "code": "SHARE_RATE_LIMITED", "retryAfterSeconds": 1}
    if admission != "admitted":
        raise AssertionError(admission)
    route = store["routes"][share["routeId"]]
    return {"httpStatus": "forwarded",
            "forward": {"route": route["name"], "method": request["method"], "relativePath": relative_path,
                        "rawQuery": query, "cookie": forwarded_cookie(cookies)}}


def get(path, cookies=None, method="GET", **extra):
    request = {"method": method, "path": path, "cookies": cookies if cookies is not None else []}
    request.update(extra)
    return request


A_ROOT = SHARE_ROOT + SHARE_A_ID
A_COOKIE = f"{COOKIE_NAME}={TOKEN_A}"

ACCESS_CASES = [
    ("in-scope-get", {"request": get(A_ROOT + "/docs/guide.html", ["theme=dark; " + A_COOKIE + "; sid=abc"],
                                     rawQuery="v=%2F2"), "shares": [SHARE_A]},
     "The share cookie is removed from the Cookie header; every other cookie and the raw query go to "
     "the device unchanged."),
    ("prefix-itself", {"request": get(A_ROOT + "/docs", [A_COOKIE]), "shares": [SHARE_A]},
     "The prefix without its trailing slash is in scope; the target may redirect to the slash form."),
    ("only-share-cookie", {"request": get(A_ROOT + "/docs/", [A_COOKIE]), "shares": [SHARE_A]},
     "No other cookies: the device receives no Cookie header at all."),
    ("missing-trailing-slash", {"request": get(A_ROOT, [], rawQuery="a=1"), "shares": [SHARE_A]},
     "Decided before any lookup, the same for every well-formed id."),
    ("malformed-share-id", {"request": get(SHARE_ROOT + "short/x", [A_COOKIE]), "shares": [SHARE_A]}, ""),
    ("no-cookie", {"request": get(A_ROOT + "/docs/"), "shares": [SHARE_A]},
     "No credential: the same answer as a share that does not exist."),
    ("unknown-share", {"request": get(SHARE_ROOT + SHARE_B_ID + "/", [f"{COOKIE_NAME}={TOKEN_B}"]),
                       "shares": [SHARE_A]}, ""),
    ("cookie-of-another-share", {"request": get(A_ROOT + "/docs/", [f"{COOKIE_NAME}={TOKEN_B}"]),
                                 "shares": [SHARE_A, share_row(SHARE_B_ID, TOKEN_B)]},
     "A valid token of share B never opens share A."),
    ("planted-cookie-first", {"request": get(A_ROOT + "/docs/", [f"{COOKIE_NAME}=hs1.{SHARE_A_ID}.{'x' * 43}; " + A_COOKIE]),
                              "shares": [SHARE_A]},
     "A same-origin page planted a cookie of the same name with a longer Path, so the browser sends it "
     "first. The server tries up to four values that name this share."),
    ("token-in-authorization-header", {"request": get(A_ROOT + "/docs/", [], authorization="Bearer " + TOKEN_A),
                                       "shares": [SHARE_A]},
     "The token is accepted only from the cookie; Authorization belongs to the target and is relayed "
     "unchanged."),
    ("revoked", {"request": get(A_ROOT + "/docs/", [A_COOKIE]), "shares": [
        share_row(SHARE_A_ID, TOKEN_A, prefix="/docs/",
                  revoked={"revokedAt": at(-10), "revokedBy": "alice", "revokeReason": "revoked-by-user"})]},
     "The cookie is cleared so the browser stops presenting it."),
    ("expired", {"now": at(86_400 - 3600), "request": get(A_ROOT + "/docs/", [A_COOKIE]), "shares": [SHARE_A]}, ""),
    ("expired-and-lapsed", {"now": at(86_400 - 3600), "request": get(A_ROOT + "/docs/", [A_COOKIE]), "shares": [SHARE_A],
                            "mutate": lambda s: s["routes"][42].update(enabled=False)},
     "An expired share is not revoked afterwards: expiry wins and nothing is written."),
    ("lapsed-route-disabled", {"request": get(A_ROOT + "/docs/", [A_COOKIE]), "shares": [SHARE_A],
                               "mutate": lambda s: s["routes"][42].update(enabled=False)}, ""),
    ("lapsed-route-deleted", {"request": get(A_ROOT + "/docs/", [A_COOKIE]), "shares": [SHARE_A],
                              "mutate": lambda s: s["routes"].pop(42)}, ""),
    ("lapsed-client-disabled", {"request": get(A_ROOT + "/docs/", [A_COOKIE]), "shares": [SHARE_A],
                                "mutate": lambda s: s["clients"][7].update(enabled=False)}, ""),
    ("lapsed-client-deleted", {"request": get(A_ROOT + "/docs/", [A_COOKIE]), "shares": [SHARE_A],
                               "mutate": lambda s: s["clients"].pop(7)}, ""),
    ("lapsed-creator-disabled", {"request": get(A_ROOT + "/docs/", [A_COOKIE]), "shares": [SHARE_A],
                                 "mutate": lambda s: s["users"]["alice"].update(enabled=False)}, ""),
    ("lapsed-creator-deleted", {"request": get(A_ROOT + "/docs/", [A_COOKIE]), "shares": [SHARE_A],
                                "mutate": lambda s: s["users"].pop("alice")}, ""),
    ("admin-share-survives-owner-disabled",
     {"request": get(A_ROOT + "/docs/", [A_COOKIE]),
      "shares": [share_row(SHARE_A_ID, TOKEN_A, prefix="/docs/", created_by="admin")],
      "mutate": lambda s: s["users"]["alice"].update(enabled=False)},
     "The share belongs to whoever created it: an admin's share does not depend on the owner's account."),
    ("lapsed-admin-demoted",
     {"request": get(A_ROOT + "/docs/", [A_COOKIE]),
      "shares": [share_row(SHARE_A_ID, TOKEN_A, prefix="/docs/", created_by="admin")],
      "mutate": lambda s: s["users"]["admin"].update(role="USER")}, ""),
    ("read-share-refuses-post", {"request": get(A_ROOT + "/docs/form", [A_COOKIE], method="POST"), "shares": [SHARE_A]}, ""),
    ("read-share-refuses-options", {"request": get(A_ROOT + "/docs/", [A_COOKIE], method="OPTIONS"), "shares": [SHARE_A]}, ""),
    ("read-share-allows-head", {"request": get(A_ROOT + "/docs/a.pdf", [A_COOKIE], method="HEAD"), "shares": [SHARE_A]}, ""),
    ("read-share-refuses-websocket", {"request": get(A_ROOT + "/docs/live", [A_COOKIE], upgrade=True), "shares": [SHARE_A]},
     "A WebSocket is a GET that can carry data to the target: not read-only."),
    ("full-share-allows-post", {"request": get(A_ROOT + "/api/items", [A_COOKIE], method="POST"), "shares": [SHARE_A_FULL]}, ""),
    ("full-share-allows-websocket", {"request": get(A_ROOT + "/live", [A_COOKIE], upgrade=True), "shares": [SHARE_A_FULL]}, ""),
    ("outside-prefix", {"request": get(A_ROOT + "/admin/", [A_COOKIE]), "shares": [SHARE_A]}, ""),
    ("prefix-is-a-segment", {"request": get(A_ROOT + "/docsecret/", [A_COOKIE]), "shares": [SHARE_A]},
     "The prefix /docs/ does not cover /docsecret."),
    ("dot-dot-escape", {"request": get(A_ROOT + "/docs/%2e%2E/admin/", [A_COOKIE]), "shares": [SHARE_A]},
     "Encoded dot segments are dot segments."),
    ("literal-dot-dot", {"request": get(A_ROOT + "/docs/../admin/", [A_COOKIE]), "shares": [SHARE_A]},
     "Browsers remove dot segments before sending; a client that does not is refused."),
    ("encoded-slash", {"request": get(A_ROOT + "/docs/..%2Fadmin", [A_COOKIE]), "shares": [SHARE_A]}, ""),
    ("semicolon", {"request": get(A_ROOT + "/docs/..;/admin", [A_COOKIE]), "shares": [SHARE_A]},
     "Servlet containers strip ;parameters and then normalise: refused under a prefix."),
    ("encoded-unreserved-in-scope", {"request": get(A_ROOT + "/%64ocs/guide.html", [A_COOKIE]), "shares": [SHARE_A]},
     "Escapes of unreserved characters are decoded before matching, as the target will decode them; "
     "the raw path is forwarded unchanged."),
    ("whole-route-share-has-no-path-rules", {"request": get(A_ROOT + "/a/..%2Fb;c", [A_COOKIE]), "shares": [SHARE_A_FULL]},
     "With the prefix / the share covers exactly what the route covers, so the route's own path rules "
     "apply and nothing more."),
    ("share-busy", {"request": get(A_ROOT + "/docs/", [A_COOKIE]), "shares": [SHARE_A], "admission": "share-busy"}, ""),
    ("rate-limited", {"request": get(A_ROOT + "/docs/", [A_COOKIE]), "shares": [SHARE_A], "admission": "rate-limited"}, ""),
    ("store-unreadable", {"request": get(A_ROOT + "/docs/", [A_COOKIE]), "shares": [SHARE_A], "readable": False}, ""),
]

FWD = "forwarded"
ACCESS_EXPECTED = {
    "in-scope-get": (FWD, "/docs/guide.html", "theme=dark; sid=abc"),
    "prefix-itself": (FWD, "/docs", None),
    "only-share-cookie": (FWD, "/docs/", None),
    "missing-trailing-slash": (308, A_ROOT + "/?a=1"),
    "malformed-share-id": (404, "SHARE_NOT_FOUND"),
    "no-cookie": (404, "SHARE_NOT_FOUND"),
    "unknown-share": (404, "SHARE_NOT_FOUND"),
    "cookie-of-another-share": (404, "SHARE_NOT_FOUND"),
    "planted-cookie-first": (FWD, "/docs/", None),
    "token-in-authorization-header": (404, "SHARE_NOT_FOUND"),
    "revoked": (410, "SHARE_REVOKED"),
    "expired": (410, "SHARE_EXPIRED"),
    "expired-and-lapsed": (410, "SHARE_EXPIRED"),
    "lapsed-route-disabled": (410, "SHARE_REVOKED", "route-disabled"),
    "lapsed-route-deleted": (410, "SHARE_REVOKED", "route-deleted"),
    "lapsed-client-disabled": (410, "SHARE_REVOKED", "client-disabled"),
    "lapsed-client-deleted": (410, "SHARE_REVOKED", "client-deleted"),
    "lapsed-creator-disabled": (410, "SHARE_REVOKED", "creator-lost-access"),
    "lapsed-creator-deleted": (410, "SHARE_REVOKED", "creator-lost-access"),
    "admin-share-survives-owner-disabled": (FWD, "/docs/", None),
    "lapsed-admin-demoted": (410, "SHARE_REVOKED", "creator-lost-access"),
    "read-share-refuses-post": (405, "SHARE_METHOD_NOT_ALLOWED"),
    "read-share-refuses-options": (405, "SHARE_METHOD_NOT_ALLOWED"),
    "read-share-allows-head": (FWD, "/docs/a.pdf", None),
    "read-share-refuses-websocket": (403, "SHARE_SCOPE_DENIED"),
    "full-share-allows-post": (FWD, "/api/items", None),
    "full-share-allows-websocket": (FWD, "/live", None),
    "outside-prefix": (403, "SHARE_SCOPE_DENIED"),
    "prefix-is-a-segment": (403, "SHARE_SCOPE_DENIED"),
    "dot-dot-escape": (403, "SHARE_SCOPE_DENIED"),
    "literal-dot-dot": (403, "SHARE_SCOPE_DENIED"),
    "encoded-slash": (403, "SHARE_SCOPE_DENIED"),
    "semicolon": (403, "SHARE_SCOPE_DENIED"),
    "encoded-unreserved-in-scope": (FWD, "/%64ocs/guide.html", None),
    "whole-route-share-has-no-path-rules": (FWD, "/a/..%2Fb;c", None),
    "share-busy": (429, "SHARE_BUSY"),
    "rate-limited": (429, "SHARE_RATE_LIMITED"),
    "store-unreadable": (503, "SHARE_UNAVAILABLE"),
}


# --------------------------------------------------------------------------------------------------
# 4. Path prefix canonicalisation


PREFIX_CASES = [
    ("/", "/"), ("/docs", "/docs/"), ("/docs/", "/docs/"), ("/a/b/c", "/a/b/c/"),
    ("/%e6%96%87%e6%a1%a3", "/%E6%96%87%E6%A1%A3/"), ("/%7Euser/", "/~user/"), ("/v1:beta@x/", "/v1:beta@x/"),
    ("", None), ("docs/", None), ("//docs/", None), ("/a//b/", None), ("/./", None), ("/a/../b", None),
    ("/a/%2E%2e/b/", None), ("/a%2Fb/", None), ("/a%5cb/", None), ("/a\\b/", None), ("/a;b/", None),
    ("/a?b", None), ("/a#b", None), ("/a b/", None), ("/%zz/", None), ("/%4/", None), ("/%00/", None),
    ("/文档/", None), ("/" + "a" * 254, "/" + "a" * 254 + "/"), ("/" + "a" * 255, None), (7, None),
]


# --------------------------------------------------------------------------------------------------
# 5. Header rewriting


REQUEST_COOKIE_CASES = [
    ([f"{COOKIE_NAME}={TOKEN_A}"], None),
    ([f"a=1; {COOKIE_NAME}={TOKEN_A}; b=2"], "a=1; b=2"),
    (["a=1", f"{COOKIE_NAME}={TOKEN_A}", "b=2"], "a=1; b=2"),
    ([f"{COOKIE_NAME}=junk; {COOKIE_NAME}={TOKEN_A}"], None),
    ([f"__secure-specus_http_share=x; {COOKIE_NAME}={TOKEN_A}"], "__secure-specus_http_share=x"),
    (["a=1;;b=2"], "a=1; b=2"),
    ([], None),
]

A_BASE = SHARE_ROOT + SHARE_A_ID
RESPONSE_HEADER_CASES = [
    ("plain", 200, ["Content-Type:text/html", "Cache-Control:public, max-age=3600", 'ETag:"x"'],
     ["Content-Type:text/html", 'ETag:"x"', "Cache-Control:private, no-cache"]),
    ("no-store-kept", 200, ["Cache-Control:no-store, max-age=0", "Pragma:no-cache"],
     ["Cache-Control:private, no-store"]),
    ("cdn-headers-removed", 200, ["CDN-Cache-Control:max-age=600", "Surrogate-Control:max-age=600",
                                  "Expires:Wed, 21 Oct 2026 07:28:00 GMT"],
     ["Cache-Control:private, no-cache"]),
    ("not-modified", 304, ['ETag:"x"', "Cache-Control:max-age=60"], ['ETag:"x"', "Cache-Control:private, no-cache"]),
    ("cookies-scoped", 200,
     [f"Set-Cookie:{COOKIE_NAME}=evil; Path=/", "Set-Cookie:sid=abc; path=/; Domain=example.com; HttpOnly",
      "Set-Cookie:pref=1; Path=/app/; Max-Age=60", "Set-Cookie:rel=1; Path=app", "Set-Cookie:bare=1",
      "Set-Cookie:__Host-csrf=x; Path=/; Secure", "Set-Cookie:__Secure-t=y; Path=/; Secure; SameSite=Lax"],
     ["Set-Cookie:sid=abc; Path=" + A_BASE + "/; HttpOnly", "Set-Cookie:pref=1; Path=" + A_BASE + "/app/; Max-Age=60",
      "Set-Cookie:rel=1; Path=app", "Set-Cookie:bare=1",
      "Set-Cookie:__Secure-t=y; Path=" + A_BASE + "/; Secure; SameSite=Lax", "Cache-Control:private, no-cache"]),
    ("clear-site-data-dropped", 200, ['Clear-Site-Data:"cookies", "storage"', "Content-Type:text/plain"],
     ["Content-Type:text/plain", "Cache-Control:private, no-cache"]),
    ("upgrade", 101, [f"Set-Cookie:{COOKIE_NAME}=evil", "Set-Cookie:ws=1; Path=/", "Sec-WebSocket-Protocol:chat",
                      "Cache-Control:no-cache"],
     ["Set-Cookie:ws=1; Path=" + A_BASE + "/", "Sec-WebSocket-Protocol:chat", "Cache-Control:no-cache"]),
]


# --------------------------------------------------------------------------------------------------
# 6. Revocation, lifecycle events, expiry sweep and audit


def apply_events(initial_shares, events):
    """Replays management events against one store. Returns the audit entries and the final state
    of every share, both in the order the reference writes them."""
    store = store_with(*initial_shares)
    audit = []
    responses = []

    def revoke(share, now, actor, reason):
        share.update(revokedAt=stamp(now), revokedBy=actor, revokeReason=reason)
        audit.append({"action": "share.revoked", "at": stamp(now), "actor": actor, "routeId": share["routeId"],
                      "shareId": share["shareId"], "detail": {"reason": reason}})

    def active_shares(now, predicate):
        return sorted((s for s in store["shares"].values() if status_of(s, now) == "active" and predicate(s)),
                      key=lambda s: (s["createdAt"], s["shareId"]))

    for event in events:
        now = instant(event["at"])
        kind = event["kind"]
        actor = event.get("actor")
        if kind == "revoke":
            share = store["shares"].get(event["shareId"])
            route = store["routes"].get(event["routeId"])
            user = store["users"].get(actor)
            client = store["clients"].get(route["clientId"]) if route else None
            if route is None or not can_manage(user, route, client):
                responses.append({"httpStatus": 404, "code": "SHARE_ROUTE_NOT_FOUND"})
                continue
            if share is None or share["routeId"] != route["routeId"]:
                responses.append({"httpStatus": 404, "code": "SHARE_NOT_FOUND"})
                continue
            if status_of(share, now) == "active":
                revoke(share, now, actor, "revoked-by-user")
            responses.append({"httpStatus": 200, "status": status_of(share, now)})
        elif kind == "route-created":
            route = dict(event["route"])
            store["routes"][route["routeId"]] = route
            audit.append({"action": "route.created", "at": stamp(now), "actor": actor, "routeId": route["routeId"],
                          "shareId": None, "detail": {"exposure": exposure(route)}})
        elif kind == "route-updated":
            route = store["routes"][event["routeId"]]
            before = exposure(route)
            route.update({k: event[k] for k in ("enabled", "authEnabled") if k in event})
            after = exposure(route)
            if before != after:
                audit.append({"action": "route.exposure-changed", "at": stamp(now), "actor": actor,
                              "routeId": route["routeId"], "shareId": None, "detail": {"from": before, "to": after}})
            if event.get("credentialsChanged"):
                audit.append({"action": "route.credentials-changed", "at": stamp(now), "actor": actor,
                              "routeId": route["routeId"], "shareId": None, "detail": {}})
            if after != "protected":
                reason = "route-disabled" if after == "disabled" else "route-made-public"
                for share in active_shares(now, lambda s: s["routeId"] == route["routeId"]):
                    revoke(share, now, actor, reason)
        elif kind == "route-deleted":
            route = store["routes"].pop(event["routeId"])
            audit.append({"action": "route.deleted", "at": stamp(now), "actor": actor, "routeId": route["routeId"],
                          "shareId": None, "detail": {"exposure": exposure(route)}})
            for share in active_shares(now, lambda s: s["routeId"] == route["routeId"]):
                revoke(share, now, actor, "route-deleted")
        elif kind in ("client-disabled", "client-deleted"):
            client_id = event["clientId"]
            route_ids = sorted(r for r, route in store["routes"].items() if route["clientId"] == client_id)
            if kind == "client-disabled":
                store["clients"][client_id]["enabled"] = False
            else:
                store["clients"].pop(client_id)
                for route_id in route_ids:
                    route = store["routes"].pop(route_id)
                    audit.append({"action": "route.deleted", "at": stamp(now), "actor": actor, "routeId": route_id,
                                  "shareId": None, "detail": {"exposure": exposure(route)}})
            for share in active_shares(now, lambda s: s["routeId"] in route_ids):
                revoke(share, now, actor, kind)
        elif kind in ("user-updated", "user-deleted"):
            if kind == "user-updated":
                store["users"][event["username"]].update({k: event[k] for k in ("enabled", "role") if k in event})
            else:
                store["users"].pop(event["username"])
            for share in active_shares(now, lambda s: lapse_reason(s, store) == "creator-lost-access"):
                revoke(share, now, actor, "creator-lost-access")
        elif kind == "sweep":
            # Expiry first, in expiry order: each share's end is recorded once, at its expiresAt.
            for share in sorted(store["shares"].values(), key=lambda s: (s["expiresAt"], s["shareId"])):
                if share.get("revokedAt") is None and instant(share["expiresAt"]) <= now \
                        and not share.get("expiryRecorded"):
                    share["expiryRecorded"] = True
                    audit.append({"action": "share.expired", "at": share["expiresAt"], "actor": None,
                                  "routeId": share["routeId"], "shareId": share["shareId"], "detail": {}})
            # Then the safety net: an active share whose route, client or creator no longer allows
            # it is revoked even if no request arrived and no hook ran.
            for share in active_shares(now, lambda s: lapse_reason(s, store) is not None):
                revoke(share, now, None, lapse_reason(share, store))
        elif kind == "silent-change":
            # A change made by a path that did not run the share hooks (e.g. direct database edit, or
            # an older instance during a rolling upgrade). Only the sweep or a request can catch it.
            target = store[event["table"]][event["key"]]
            target.update(event["set"])
        else:
            raise AssertionError(kind)

    final = {share_id: {"status": status_of(share, instant(events[-1]["at"])),
                        "revokeReason": share.get("revokeReason"), "revokedBy": share.get("revokedBy")}
             for share_id, share in sorted(store["shares"].items())}
    return audit, final, responses


def S(n):
    return make_token(f"{0xabc000 + n:024x}", f"{0xdef000 + n:064x}")[0]


def lifecycle_share(n, **kw):
    share_id, token = make_token(f"{0xabc000 + n:024x}", f"{0xdef000 + n:064x}")
    return share_row(share_id, token, **kw)


LIFECYCLE_CASES = [
    ("owner-revokes-then-revokes-again",
     [lifecycle_share(1)],
     [{"kind": "revoke", "at": at(0), "actor": "alice", "routeId": 42, "shareId": S(1)},
      {"kind": "revoke", "at": at(5), "actor": "admin", "routeId": 42, "shareId": S(1)},
      {"kind": "revoke", "at": at(6), "actor": "bob", "routeId": 42, "shareId": S(1)},
      {"kind": "revoke", "at": at(7), "actor": "admin", "routeId": 50, "shareId": S(1)}],
     "Revocation is idempotent: the second call answers 200 and writes nothing. Someone who cannot manage "
     "the route gets 404, and a share id under a route it does not belong to is not found."),
    ("route-disabled-ends-every-active-share",
     [lifecycle_share(1), lifecycle_share(2, created_by="admin", created_at=-1800),
      lifecycle_share(3, created_at=-90_000, expires_in=3600)],
     [{"kind": "route-updated", "at": at(0), "actor": "alice", "routeId": 42, "enabled": False},
      {"kind": "route-updated", "at": at(60), "actor": "alice", "routeId": 42, "enabled": True}],
     "Disabling revokes; enabling again does not bring the shares back. The already-expired share is not "
     "touched."),
    ("route-made-public",
     [lifecycle_share(1)],
     [{"kind": "route-updated", "at": at(0), "actor": "alice", "routeId": 42, "authEnabled": False}],
     "A public route needs no share; keeping one would mislead the owner into thinking revoking it stops "
     "access."),
    ("credentials-changed-keeps-shares",
     [lifecycle_share(1)],
     [{"kind": "route-updated", "at": at(0), "actor": "alice", "routeId": 42, "credentialsChanged": True}],
     "Changing the Basic password is audited but does not touch shares: they never used it."),
    ("route-deleted",
     [lifecycle_share(1), lifecycle_share(2, route_id=50, created_by="bob")],
     [{"kind": "route-deleted", "at": at(0), "actor": "admin", "routeId": 42}], ""),
    ("client-disabled",
     [lifecycle_share(1), lifecycle_share(2, route_id=50, created_by="bob")],
     [{"kind": "client-disabled", "at": at(0), "actor": "admin", "clientId": 7}], ""),
    ("client-deleted",
     [lifecycle_share(1)],
     [{"kind": "client-deleted", "at": at(0), "actor": "admin", "clientId": 7}],
     "Deleting a client deletes its routes: each gets a route.deleted entry, then the shares end."),
    ("creator-disabled",
     [lifecycle_share(1), lifecycle_share(2, created_by="admin", created_at=-1800)],
     [{"kind": "user-updated", "at": at(0), "actor": "admin", "username": "alice", "enabled": False}],
     "Only the disabled user's own shares end; the admin's share of the same route stays."),
    ("admin-demoted",
     [lifecycle_share(1, created_by="admin"), lifecycle_share(2, route_id=50, created_by="admin", created_at=-1800)],
     [{"kind": "user-updated", "at": at(0), "actor": "carol", "username": "admin", "role": "USER"}],
     "An admin who is demoted and owns neither client loses every share it created."),
    ("owner-promoted-then-demoted-keeps-own-route",
     [lifecycle_share(1, created_by="alice")],
     [{"kind": "user-updated", "at": at(0), "actor": "admin", "username": "alice", "role": "ADMIN"},
      {"kind": "user-updated", "at": at(5), "actor": "admin", "username": "alice", "role": "USER"}],
     "Still the owner of the client after the demotion: nothing to end."),
    ("creator-deleted",
     [lifecycle_share(1)],
     [{"kind": "user-deleted", "at": at(0), "actor": "admin", "username": "alice"}], ""),
    ("route-created",
     [],
     [{"kind": "route-created", "at": at(0), "actor": "alice",
       "route": {"routeId": 60, "tenantId": "t1", "clientId": 7, "name": "wiki", "enabled": True,
                 "authEnabled": False}},
      {"kind": "route-updated", "at": at(30), "actor": "alice", "routeId": 60, "authEnabled": True,
       "credentialsChanged": True}],
     "Creating a route is an exposure change too. Turning on Basic for the first time records both the "
     "exposure change and the new credentials."),
    ("sweep-records-expiry-once",
     [lifecycle_share(1, created_at=-3600, expires_in=3000), lifecycle_share(2, created_at=-3600, expires_in=1800),
      lifecycle_share(3, created_at=-3600, expires_in=7200),
      lifecycle_share(4, created_at=-3600, expires_in=600,
                      revoked={"revokedAt": at(-3500), "revokedBy": "alice", "revokeReason": "revoked-by-user"})],
     [{"kind": "sweep", "at": at(0)}, {"kind": "sweep", "at": at(60)}, {"kind": "sweep", "at": at(3600)}],
     "Each expiry is written once, stamped with expiresAt rather than the sweep time, in expiry order. "
     "A share revoked before it expired gets no expiry entry."),
    ("missed-hook-undone-before-sweep",
     [lifecycle_share(1)],
     [{"kind": "silent-change", "at": at(0), "table": "routes", "key": 42, "set": {"enabled": False}},
      {"kind": "silent-change", "at": at(10), "table": "routes", "key": 42, "set": {"enabled": True}},
      {"kind": "sweep", "at": at(20)}],
     "If a change bypassed the hooks and was undone before any request or sweep saw it, the share "
     "survives -- the window is one sweep interval. Here the sweep runs after the undo: nothing to do."),
    ("sweep-revokes-a-lapsed-share",
     [lifecycle_share(1)],
     [{"kind": "silent-change", "at": at(0), "table": "routes", "key": 42, "set": {"authEnabled": False}},
      {"kind": "sweep", "at": at(30)},
      {"kind": "silent-change", "at": at(40), "table": "routes", "key": 42, "set": {"authEnabled": True}}],
     "The sweep revokes with no actor; protecting the route again does not revive the share."),
]

LIFECYCLE_EXPECTED = {
    "owner-revokes-then-revokes-again": (
        [("share.revoked", "alice", 1, "revoked-by-user")],
        {1: ("revoked", "revoked-by-user")},
        [(200, "revoked"), (200, "revoked"), (404, "SHARE_ROUTE_NOT_FOUND"), (404, "SHARE_NOT_FOUND")]),
    "route-disabled-ends-every-active-share": (
        [("route.exposure-changed", "alice", None, {"from": "protected", "to": "disabled"}),
         ("share.revoked", "alice", 1, "route-disabled"), ("share.revoked", "alice", 2, "route-disabled"),
         ("route.exposure-changed", "alice", None, {"from": "disabled", "to": "protected"})],
        {1: ("revoked", "route-disabled"), 2: ("revoked", "route-disabled"), 3: ("expired", None)}, []),
    "route-made-public": (
        [("route.exposure-changed", "alice", None, {"from": "protected", "to": "public"}),
         ("share.revoked", "alice", 1, "route-made-public")],
        {1: ("revoked", "route-made-public")}, []),
    "credentials-changed-keeps-shares": (
        [("route.credentials-changed", "alice", None, {})], {1: ("active", None)}, []),
    "route-deleted": (
        [("route.deleted", "admin", None, {"exposure": "protected"}), ("share.revoked", "admin", 1, "route-deleted")],
        {1: ("revoked", "route-deleted"), 2: ("active", None)}, []),
    "client-disabled": (
        [("share.revoked", "admin", 1, "client-disabled")],
        {1: ("revoked", "client-disabled"), 2: ("active", None)}, []),
    "client-deleted": (
        [("route.deleted", "admin", None, {"exposure": "protected"}),
         ("route.deleted", "admin", None, {"exposure": "public"}),
         ("route.deleted", "admin", None, {"exposure": "disabled"}),
         ("share.revoked", "admin", 1, "client-deleted")],
        {1: ("revoked", "client-deleted")}, []),
    "creator-disabled": (
        [("share.revoked", "admin", 1, "creator-lost-access")],
        {1: ("revoked", "creator-lost-access"), 2: ("active", None)}, []),
    "admin-demoted": (
        [("share.revoked", "carol", 1, "creator-lost-access"), ("share.revoked", "carol", 2, "creator-lost-access")],
        {1: ("revoked", "creator-lost-access"), 2: ("revoked", "creator-lost-access")}, []),
    "owner-promoted-then-demoted-keeps-own-route": ([], {1: ("active", None)}, []),
    "creator-deleted": (
        [("share.revoked", "admin", 1, "creator-lost-access")], {1: ("revoked", "creator-lost-access")}, []),
    "route-created": (
        [("route.created", "alice", None, {"exposure": "public"}),
         ("route.exposure-changed", "alice", None, {"from": "public", "to": "protected"}),
         ("route.credentials-changed", "alice", None, {})], {}, []),
    "sweep-records-expiry-once": (
        [("share.expired", None, 2, at(-1800)), ("share.expired", None, 1, at(-600)), ("share.expired", None, 3, at(3600))],
        {1: ("expired", None), 2: ("expired", None), 3: ("expired", None), 4: ("revoked", "revoked-by-user")}, []),
    "missed-hook-undone-before-sweep": ([], {1: ("active", None)}, []),
    "sweep-revokes-a-lapsed-share": (
        [("share.revoked", None, 1, "route-made-public")], {1: ("revoked", "route-made-public")}, []),
}


def summarize_audit(entries, ids):
    out = []
    for entry in entries:
        if entry["action"] == "share.revoked":
            out.append((entry["action"], entry["actor"], ids[entry["shareId"]], entry["detail"]["reason"]))
        elif entry["action"] == "share.expired":
            out.append((entry["action"], entry["actor"], ids[entry["shareId"]], entry["at"]))
        else:
            out.append((entry["action"], entry["actor"], None, entry["detail"]))
    return out


# --------------------------------------------------------------------------------------------------
# 7. Rate limits


class Gcra:
    """Generic cell rate algorithm, identical to service-connectivity-check: one theoretical arrival
    time (TAT) per key in integer ms. A request at `now` conforms when now >= TAT - tolerance;
    conforming moves TAT to max(TAT, now) + interval. tolerance = (burst - 1) * interval."""

    def __init__(self, interval_ms, burst):
        self.interval = interval_ms
        self.tolerance = (burst - 1) * interval_ms
        self.tat = {}

    def wait_ms(self, key, now):
        return max(0, self.tat.get(key, now) - self.tolerance - now)

    def take(self, key, now):
        self.tat[key] = max(self.tat.get(key, now), now) + self.interval


def replay(limiter, script):
    """script: (atMs, key, repeat). Each request in a batch is decided in turn; refusals consume
    nothing. Returns per batch the number admitted and the Retry-After of the first refusal."""
    assert [s[0] for s in script] == sorted(s[0] for s in script)
    events = []
    for at_ms, key, repeat in script:
        admitted, retry = 0, None
        for _ in range(repeat):
            wait = limiter.wait_ms(key, at_ms)
            if wait == 0:
                limiter.take(key, at_ms)
                admitted += 1
            elif retry is None:
                retry = max(1, -(-wait // 1000))
        event = {"atMs": at_ms, "key": key, "requests": repeat, "admitted": admitted}
        if retry is not None:
            event["retryAfterSeconds"] = retry
        events.append(event)
    return events


EXCHANGE_SCRIPT = [(0, "203.0.113.7", 10), (0, "203.0.113.7", 1), (5_999, "203.0.113.7", 1),
                   (6_000, "203.0.113.7", 1), (6_000, "198.51.100.2", 1), (60_000, "203.0.113.7", 12)]
EXCHANGE_RATE_EXPECTED = [(10, None), (0, 6), (0, 1), (1, None), (1, None), (9, 6)]

SHARE_SCRIPT = [(0, SHARE_A_ID, 200), (0, SHARE_A_ID, 1), (49, SHARE_A_ID, 1), (50, SHARE_A_ID, 1),
                (50, SHARE_B_ID, 1), (1_050, SHARE_A_ID, 25)]
SHARE_RATE_EXPECTED = [(200, None), (0, 1), (0, 1), (1, None), (1, None), (20, 1)]


# --------------------------------------------------------------------------------------------------
# Build


def summarize(out):
    if out["httpStatus"] == "forwarded":
        assert out["forward"]["route"] == "api"
        return (FWD, out["forward"]["relativePath"], out["forward"]["cookie"])
    if out["httpStatus"] == 308:
        return (308, out["location"])
    if "revoke" in out:
        return (out["httpStatus"], out["code"], out["revoke"]["reason"])
    if out["httpStatus"] == 401:
        return (401, None)
    return (out["httpStatus"], out["code"])


def serializable(inputs):
    """Case inputs without the Python callables used to build them."""
    return {k: v for k, v in inputs.items() if k != "mutate"}


def mutation_note(case_inputs):
    """The world change a case applies, written out for the JSON reader."""
    mutate = case_inputs.get("mutate")
    if mutate is None:
        return None
    before = world()
    after = world()
    mutate(after)
    changes = []
    for table in ("users", "clients", "routes"):
        for key in sorted(set(before[table]) | set(after[table]), key=str):
            if key not in after[table]:
                changes.append({"table": table, "key": key, "deleted": True})
            elif before[table].get(key) != after[table][key]:
                diff = {k: v for k, v in after[table][key].items() if before[table][key].get(k) != v}
                changes.append({"table": table, "key": key, "set": diff})
    return changes


def emit(name, note, inputs, expect):
    case = {"name": name}
    if note:
        case["note"] = note
    data = serializable(inputs)
    changes = mutation_note(inputs)
    if changes:
        data["worldChanges"] = changes
    case["input"] = data
    case["expect"] = expect
    return case


def build():
    # Token construction and parsing.
    assert len(TOKEN_A) == 64 and token_hash(TOKEN_A) == hashlib.sha256(TOKEN_A.encode()).hexdigest()
    token_examples = []
    for share_id_hex, secret_hex in [("1f8b3c5d7e9a0b2c4d6e8f10", "a3c5e7f90b1d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a"),
                                     ("00ff00ff00ff00ff00ff00ff", "ff" * 32), ("fbefbefbefbefbefbefbefbe", "00" * 32)]:
        share_id, token = make_token(share_id_hex, secret_hex)
        assert parse_token(token) == share_id
        token_examples.append({"shareIdBytesHex": share_id_hex, "secretBytesHex": secret_hex, "shareId": share_id,
                               "token": token, "tokenSha256": token_hash(token),
                               "sharePath": SHARE_ROOT + share_id + "/", "linkPath": LINK_ROOT + token})
    assert token_examples[2]["shareId"] == "-" * 16   # every character of the alphabet is legal, even a leading "-"
    parse_cases = [
        (TOKEN_A, SHARE_A_ID), (TOKEN_B, SHARE_B_ID), (TOKEN_C, SHARE_C_ID),
        (TOKEN_A.upper(), None), ("HS1" + TOKEN_A[3:], None), ("hs2" + TOKEN_A[3:], None),
        (TOKEN_A + "=", None), (TOKEN_A[:-1], None), (TOKEN_A + "A", None), (" " + TOKEN_A, None),
        (TOKEN_A + "\n", None), (TOKEN_A.replace(".", "_", 1), None), ("hs1." + SHARE_A_ID, None),
        ("hs1.." + TOKEN_A[21:], None), (TOKEN_A[:5] + "+" + TOKEN_A[6:], None), ("", None), (None, None),
    ]
    token_parse = []
    for text, expected in parse_cases:
        assert parse_token(text) == expected, (text, parse_token(text), expected)
        token_parse.append({"input": text, "shareId": expected})

    # Prefix canonicalisation.
    prefix_vectors = []
    for raw, expected in PREFIX_CASES:
        assert canonical_prefix(raw) == expected, (raw, canonical_prefix(raw), expected)
        prefix_vectors.append({"input": raw, "canonical": expected})

    create_cases = []
    for name, inputs, note in CREATE_CASES:
        out = create(inputs)
        if out["httpStatus"] == 201:
            share = out["body"]["share"]
            got = (201, share["access"], share["pathPrefix"], share["label"], share["expiresAt"])
            assert share["status"] == "active" and share["revokedAt"] is None, name
            assert out["body"]["linkPath"] == LINK_ROOT + out["body"]["token"], name
            assert out["body"]["share"]["sharePath"] == SHARE_ROOT + parse_token(out["body"]["token"]) + "/", name
            assert len(out["audit"]) == 1 and out["audit"][0]["action"] == "share.created", name
            # The audit entry never carries the token, its hash or the label.
            text = json.dumps(out["audit"])
            assert NEW_TOKEN not in text and token_hash(NEW_TOKEN) not in text, name
            assert share["label"] is None or share["label"] not in json.dumps(out["audit"], ensure_ascii=False), name
        else:
            got = summarize(out)
        assert got == CREATE_EXPECTED[name], (name, got, CREATE_EXPECTED[name])
        create_cases.append(emit(name, note, inputs, out))
    assert set(CREATE_EXPECTED) == {c["name"] for c in create_cases}

    exchange_cases = []
    for name, inputs, note in EXCHANGE_CASES:
        out = exchange(inputs)
        if out["httpStatus"] == 200:
            got = (200, None, out["body"]["location"], out["setCookie"]["maxAge"])
            cookie = out["setCookie"]
            assert cookie["httpOnly"] and cookie["secure"] and cookie["sameSite"] == "Strict" and cookie["domain"] is None
            assert cookie["path"] == SHARE_ROOT + out["body"]["shareId"] + "/"
            assert out["body"]["location"].startswith(cookie["path"]), name
            assert "token" not in out["body"], name   # the token never comes back from the server
        else:
            got = summarize(out)
        assert got == EXCHANGE_EXPECTED[name], (name, got, EXCHANGE_EXPECTED[name])
        exchange_cases.append(emit(name, note, inputs, out))
    assert set(EXCHANGE_EXPECTED) == {c["name"] for c in exchange_cases}

    access_cases = []
    for name, inputs, note in ACCESS_CASES:
        out = access(inputs)
        got = summarize(out)
        assert got == ACCESS_EXPECTED[name], (name, got, ACCESS_EXPECTED[name])
        if out["httpStatus"] == "forwarded":
            # The token never reaches the device: not in the path, the query or any cookie.
            assert TOKEN_A not in json.dumps(out["forward"]), name
        if out["httpStatus"] == 410:
            assert out["setCookie"]["maxAge"] == 0, name
        if out["httpStatus"] == 404:
            assert "setCookie" not in out, name
        access_cases.append(emit(name, note, inputs, out))
    assert set(ACCESS_EXPECTED) == {c["name"] for c in access_cases}

    request_cookie_vectors = []
    for headers, expected in REQUEST_COOKIE_CASES:
        assert forwarded_cookie(headers) == expected, (headers, forwarded_cookie(headers), expected)
        request_cookie_vectors.append({"cookieHeaders": headers, "forwardedCookie": expected})
    response_header_vectors = []
    for name, status, headers, expected in RESPONSE_HEADER_CASES:
        got = response_headers(status, headers, SHARE_A_ID)
        assert got == expected, (name, got)
        response_header_vectors.append({"name": name, "shareId": SHARE_A_ID, "status": status,
                                        "upstream": headers, "relayed": expected})

    lifecycle_cases = []
    for name, shares, events, note in LIFECYCLE_CASES:
        audit, final, responses = apply_events(shares, events)
        ids = {S(n): n for n in range(1, 10)}
        expected_audit, expected_final, expected_responses = LIFECYCLE_EXPECTED[name]
        assert summarize_audit(audit, ids) == expected_audit, (name, summarize_audit(audit, ids))
        got_final = {ids[k]: (v["status"], v["revokeReason"]) for k, v in final.items()}
        assert got_final == expected_final, (name, got_final)
        got_responses = [(r["httpStatus"], r.get("status") or r.get("code")) for r in responses]
        assert got_responses == expected_responses, (name, got_responses)
        for entry in audit:
            assert entry["action"] in AUDIT_ACTIONS, entry
            if entry["action"] == "share.revoked":
                assert entry["detail"]["reason"] in REVOKE_REASONS, entry
        case = {"name": name}
        if note:
            case["note"] = note
        case["input"] = {"shares": shares, "events": events}
        case["expect"] = {"audit": audit, "shares": final}
        if responses:
            case["expect"]["responses"] = responses
        lifecycle_cases.append(case)
    assert set(LIFECYCLE_EXPECTED) == {c["name"] for c in lifecycle_cases}

    # Every revoke reason and every audit action is exercised somewhere.
    reasons_seen = set()
    actions_seen = set()
    for case in lifecycle_cases:
        for entry in case["expect"]["audit"]:
            actions_seen.add(entry["action"])
            if entry["action"] == "share.revoked":
                reasons_seen.add(entry["detail"]["reason"])
    for case in access_cases + exchange_cases:
        if "revoke" in case["expect"]:
            reasons_seen.add(case["expect"]["revoke"]["reason"])
    for case in create_cases:
        for entry in case["expect"].get("audit", []):
            actions_seen.add(entry["action"])
    assert reasons_seen == set(REVOKE_REASONS), set(REVOKE_REASONS) - reasons_seen
    assert actions_seen == set(AUDIT_ACTIONS), set(AUDIT_ACTIONS) - actions_seen

    exchange_events = replay(Gcra(EXCHANGE_INTERVAL_MS, EXCHANGE_BURST), EXCHANGE_SCRIPT)
    assert [(e["admitted"], e.get("retryAfterSeconds")) for e in exchange_events] == EXCHANGE_RATE_EXPECTED, exchange_events
    share_events = replay(Gcra(SHARE_INTERVAL_MS, SHARE_BURST), SHARE_SCRIPT)
    assert [(e["admitted"], e.get("retryAfterSeconds")) for e in share_events] == SHARE_RATE_EXPECTED, share_events

    codes = {
        "create": ["SHARE_REQUEST_INVALID", "SHARE_UNAVAILABLE", "SHARE_ROUTE_NOT_FOUND", "SHARE_ROUTE_DISABLED",
                   "SHARE_CLIENT_DISABLED", "SHARE_ROUTE_PUBLIC", "SHARE_LIMIT_REACHED"],
        "exchange": ["SHARE_REQUEST_INVALID", "SHARE_RATE_LIMITED", "SHARE_NOT_FOUND", "SHARE_UNAVAILABLE",
                     "SHARE_REVOKED", "SHARE_EXPIRED"],
        "access": ["SHARE_NOT_FOUND", "SHARE_UNAVAILABLE", "SHARE_REVOKED", "SHARE_EXPIRED",
                   "SHARE_METHOD_NOT_ALLOWED", "SHARE_SCOPE_DENIED", "SHARE_BUSY", "SHARE_RATE_LIMITED"],
    }
    for section, cases in (("create", create_cases), ("exchange", exchange_cases), ("access", access_cases)):
        used = {c["expect"].get("code") for c in cases} - {None}
        assert used == set(codes[section]), (section, used ^ set(codes[section]))

    return {
        "name": "temporary-http-share-v1",
        "version": 1,
        "description": "Temporary HTTP shares: a revocable, expiring grant for one protected HTTP route, reached "
                       "under /http-share/{shareId}/ with an HttpOnly cookie that holds the share token. Covers "
                       "creation, the fragment-to-cookie exchange, the decision for every request under the share "
                       "path, revocation, the lifecycle events that end shares, the expiry sweep, audit entries, "
                       "header rewriting and rate limits. See protocol/spec/temporary-http-share.md.",
        "notes": [
            "now 未给出时为 " + NOW + "；所有时刻精确到秒，expiresAt 严格：now >= expiresAt 即已过期。",
            "共享的初始世界见 world：租户 t1 有管理员 admin 与 carol、普通用户 alice 与 bob；alice 拥有客户端 7（路由 42 "
            "名为 api 且受保护、43 公开、44 停用），bob 拥有客户端 8（路由 50 受保护）；租户 t2 有管理员 eve。"
            "input.worldChanges 是用例在此基础上的改动（deleted 表示该行被删除）。",
            "input.shares 是存储中的分享行；tokenSha256 是完整 token 字符串 UTF-8 的 SHA-256 小写十六进制，明文 token 不入库。",
            "create 用例中新分享的 shareId 与 token 由测试注入的随机源决定，取 newShare 中的固定值；实现应注入同样的字节。",
            "access 用例的 expect.httpStatus 为 forwarded 时表示请求按 route 语义转发给设备，forward 给出 NAT OPEN 中的 "
            "route（route 当前的名字）、method、relativePath、rawQuery 与转发的 Cookie 头（null 表示不带 Cookie 头）。"
            "其余请求头按 http-route.md 处理，Authorization 原样转发。",
            "headers.response 是分享响应在 route 自身响应规则之后追加的改写：relayed 为发给访客的头，顺序有意义；"
            "Cache-Control 追加在末尾。",
            "expect.revoke 表示该请求把分享就地撤销（revokedBy 为 null）并写入 expect.audit；之后同一分享的任何请求都是 410。",
            "expect.setCookie 为结构化 cookie：属性顺序不限，不得带 Domain；maxAge 为 0 表示清除。",
            "lifecycle 用例按顺序重放 events；expect.audit 逐条比较 action、at、actor、routeId、shareId 与 detail；"
            "auditId 由实现分配，不在向量里。",
            "rate 的每个事件是同一时刻、同一键上连续的 requests 个请求；admitted 是其中放行的个数，retryAfterSeconds 是第一个"
            "被拒请求的 Retry-After。被拒请求不消耗额度。",
        ],
        "constants": {
            "tokenVersion": TOKEN_VERSION, "shareIdBytes": SHARE_ID_BYTES, "secretBytes": SECRET_BYTES,
            "tokenPattern": TOKEN_RE.pattern, "cookieName": COOKIE_NAME, "maxCookieCandidates": MAX_COOKIE_CANDIDATES,
            "sharePathRoot": SHARE_ROOT, "linkRoot": LINK_ROOT,
            "minExpiresInSeconds": MIN_EXPIRES_SECONDS, "maxExpiresInSeconds": MAX_EXPIRES_SECONDS,
            "maxActiveSharesPerRoute": MAX_ACTIVE_PER_ROUTE, "labelMaxCodePoints": LABEL_MAX_CODE_POINTS,
            "pathPrefixMaxBytes": PREFIX_MAX_BYTES, "readMethods": list(READ_METHODS),
            "maxConcurrentPerShare": MAX_CONCURRENT_PER_SHARE,
            "sweepIntervalMaxSeconds": SWEEP_INTERVAL_MAX_SECONDS,
            "streamRecheckMaxSeconds": STREAM_RECHECK_MAX_SECONDS,
            "shareRetentionDays": SHARE_RETENTION_DAYS, "auditRetentionDays": AUDIT_RETENTION_DAYS,
            "revokeReasons": list(REVOKE_REASONS), "auditActions": list(AUDIT_ACTIONS),
        },
        "codes": codes,
        "world": world(),
        "newShare": {"shareIdBytesHex": "5a5a5a5a5a5a5a5a5a5a5a5a",
                     "secretBytesHex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                     "shareId": NEW_SHARE_ID, "token": NEW_TOKEN},
        "token": {"examples": token_examples, "parse": token_parse},
        "pathPrefix": prefix_vectors,
        "create": create_cases,
        "exchange": exchange_cases,
        "access": access_cases,
        "headers": {"requestCookie": request_cookie_vectors, "response": response_header_vectors},
        "lifecycle": lifecycle_cases,
        "rate": {
            "algorithm": "gcra",
            "exchange": {"key": "sourceAddress", "intervalMs": EXCHANGE_INTERVAL_MS, "burst": EXCHANGE_BURST,
                         "events": exchange_events},
            "share": {"key": "shareId", "intervalMs": SHARE_INTERVAL_MS, "burst": SHARE_BURST,
                      "events": share_events},
        },
    }


def main():
    document = build()
    path = VECTORS / "temporary-http-share-v1.json"
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {path}: create={len(document['create'])} exchange={len(document['exchange'])} "
          f"access={len(document['access'])} lifecycle={len(document['lifecycle'])}")


if __name__ == "__main__":
    main()
