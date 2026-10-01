"""Generate peer-egress-dns-v1.json: the shared cases for phase two of peer egress (#52).

Covers what the three clients must decide identically: which domain rules are valid, which rule a
name selects, how the DNS responder answers, how the fake-IP pool allocates, refreshes, evicts and
quarantines, how name-bind is encoded, and which resolved address an egress connects to. Step three
adds the consumer's side: when phase two runs at all, what it reads from egress-catalog, which
rules the status reports in force, and what happens to each packet sent into the pool.

Every expectation is produced by the reference implementation here and asserted against the case
before writing, so the file cannot ship internally inconsistent cases. See
protocol/spec/peer-egress-dns.md.
"""
import ipaddress
import json
import re
from pathlib import Path

VECTORS = Path("protocol/test-vectors")
MESH_CIDR = "100.96.0.0/11"
DEFAULT_POOL = "198.18.0.0/15"
MIN_LIFETIME = 6 * 3600
QUARANTINE = 30 * 60

LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


# --------------------------------------------------------------------------------------------------
# Names and rules
# --------------------------------------------------------------------------------------------------

def normalize_name(name):
    """Trailing dot removed, lower case. A query name and a rule match are compared this way."""
    return (name or "").strip().rstrip(".").lower()


def looks_like_domain(match):
    """The phase-one test: a leading * or any ASCII letter. Non-ASCII also counts, so that a
    Unicode name is refused as malformed rather than read as an address."""
    return match.startswith("*") or any(c.isalpha() or ord(c) > 127 for c in match)


def valid_domain_match(match):
    """A match that is a domain is either `name` or `*.name`, with punycode for IDN."""
    if any(ord(c) > 127 for c in match):
        return False
    text = match.rstrip(".").lower()
    if text.startswith("*."):
        text = text[2:]
    if not text or len(text) > 253 or "*" in text:
        return False
    labels = text.split(".")
    if len(labels) < 2:
        return False
    if all(label.isdigit() for label in labels):
        return False
    return all(LABEL.match(label) for label in labels)


def validate_rule(rule, takeover, pool=DEFAULT_POOL, mesh=MESH_CIDR):
    """The phase-one order with phase two's additions; None when the rule is in force."""
    if rule.get("enabled") is False:
        return "EGRESS_RULE_DISABLED"
    match = (rule.get("match") or "").strip()
    if not match:
        return "EGRESS_RULE_MALFORMED"
    if ":" in match:
        return "EGRESS_RULE_IPV6_UNSUPPORTED"
    if looks_like_domain(match):
        if not takeover:
            return "EGRESS_RULE_DOMAIN_UNSUPPORTED"
        if not valid_domain_match(match):
            return "EGRESS_RULE_MALFORMED"
    else:
        try:
            network = ipaddress.IPv4Network(match)
        except ValueError:
            return "EGRESS_RULE_MALFORMED"
        if network.prefixlen == 0:
            return "EGRESS_RULE_DEFAULT_ROUTE"
        if network.overlaps(ipaddress.IPv4Network(mesh)):
            return "EGRESS_RULE_MESH_OVERLAP"
        if takeover and network.overlaps(ipaddress.IPv4Network(pool)):
            return "EGRESS_RULE_FAKE_IP_OVERLAP"
    if rule.get("port") is not None:
        return "EGRESS_RULE_PORT_UNSUPPORTED"
    if rule.get("action") not in ("egress", "direct", "block"):
        return "EGRESS_RULE_MALFORMED"
    if rule["action"] == "egress" and int(rule.get("egressClientId") or 0) <= 0:
        return "EGRESS_RULE_MISSING_TARGET"
    return None


def pool_problem(cidr, mesh=MESH_CIDR):
    """None when `peerEgressFakeIpCidr` is usable: IPv4, host bits zero, /8 to /24, clear of the mesh.
    Overlap with this device's own interface addresses is checked at startup and is not in a vector."""
    try:
        network = ipaddress.IPv4Network((cidr or "").strip())
    except ValueError:
        return "EGRESS_FAKE_IP_POOL_INVALID"
    if not 8 <= network.prefixlen <= 24 or network.overlaps(ipaddress.IPv4Network(mesh)):
        return "EGRESS_FAKE_IP_POOL_INVALID"
    return None


def rule_in_force(rule, takeover, egress_domain_capable):
    """validate_rule, then the capability check for an egress that is online: a domain rule sent to
    one that does not announce domainTargetCapable is out of force rather than resolved locally."""
    code = validate_rule(rule, takeover)
    if code is not None:
        return code
    match = (rule.get("match") or "").strip()
    if looks_like_domain(match) and rule["action"] == "egress" and not egress_domain_capable:
        return "EGRESS_RULE_EGRESS_NO_DOMAIN"
    return None


def name_bind_at_egress(domain_target_capable):
    """What an egress that knows phase two answers a well-formed name-bind with. A phase-one build
    does not know the type at all and answers EGRESS_CONTROL_UNSUPPORTED (peer-egress.md)."""
    return None if domain_target_capable else "EGRESS_NAME_UNSUPPORTED"


def domain_rank(match, qname):
    """None when the rule does not cover the name; otherwise a sort key, smaller wins:
    exact before suffix, and among suffixes the one with more labels."""
    base = normalize_name(match)
    if base.startswith("*."):
        base = base[2:]
        if qname.endswith("." + base):
            return (1, -len(base.split(".")))
        return None
    return (0, 0) if qname == base else None


def select_domain_rule(rules, qname, takeover=True):
    qname = normalize_name(qname)
    best = None
    for index, rule in enumerate(rules):
        match = (rule.get("match") or "").strip()
        if not looks_like_domain(match) or validate_rule(rule, takeover) is not None:
            continue
        rank = domain_rank(match, qname)
        if rank is None:
            continue
        key = (rank, index)
        if best is None or key < best[0]:
            best = (key, index)
    return None if best is None else best[1]


def dns_answer(rules, qname, qtype):
    """What the responder does before the pool is involved: fake, nodata or forward."""
    index = select_domain_rule(rules, qname)
    if index is None or rules[index]["action"] == "direct":
        return {"answer": "forward", "ruleIndex": index}
    if qtype == "A":
        return {"answer": "fake", "ruleIndex": index}
    if qtype in ("AAAA", "HTTPS", "SVCB"):
        return {"answer": "nodata", "ruleIndex": index}
    return {"answer": "forward", "ruleIndex": index}


# --------------------------------------------------------------------------------------------------
# The fake-IP pool
# --------------------------------------------------------------------------------------------------

class Pool:
    def __init__(self, cidr):
        network = ipaddress.IPv4Network(cidr)
        self.listen = network.network_address + 1
        self.first = int(network.network_address) + 2
        self.last = int(network.broadcast_address) - 1
        self.cursor = self.first
        self.by_name = {}
        self.by_address = {}
        self.quarantine = {}  # address -> free again at

    def _free(self, address, now):
        until = self.quarantine.get(address)
        if until is not None and now >= until:
            del self.quarantine[address]
            until = None
        return address not in self.by_address and until is None

    def _scan(self, now):
        span = self.last - self.first + 1
        for step in range(span):
            candidate = self.first + (self.cursor - self.first + step) % span
            if self._free(candidate, now):
                self.cursor = self.first + (candidate - self.first + 1) % span
                return candidate
        return None

    def query(self, name, now):
        name = normalize_name(name)
        entry = self.by_name.get(name)
        if entry is not None:
            entry["lastUsed"] = now
            return {"address": str(ipaddress.IPv4Address(entry["address"])), "evicted": []}
        address = self._scan(now)
        evicted = []
        if address is None:
            for other, mapping in sorted(self.by_name.items(), key=lambda item: item[1]["address"]):
                if now - mapping["lastUsed"] >= MIN_LIFETIME:
                    evicted.append(other)
            for other in evicted:
                mapping = self.by_name.pop(other)
                del self.by_address[mapping["address"]]
                self.quarantine[mapping["address"]] = now + QUARANTINE
            address = self._scan(now)
        if address is None:
            return {"exhausted": True, "evicted": evicted}
        self.by_name[name] = {"address": address, "lastUsed": now}
        self.by_address[address] = name
        return {"address": str(ipaddress.IPv4Address(address)), "evicted": evicted}

    def traffic(self, address_text, now):
        address = int(ipaddress.IPv4Address(address_text))
        name = self.by_address.get(address)
        if name is None:
            return {"blocked": "fake-ip-unmapped"}
        self.by_name[name]["lastUsed"] = now
        return {"name": name}


def run_pool(cidr, events):
    pool = Pool(cidr)
    results = []
    for event in events:
        if "query" in event:
            results.append(pool.query(event["query"], event["at"]))
        else:
            results.append(pool.traffic(event["traffic"], event["at"]))
    return results


# --------------------------------------------------------------------------------------------------
# Step three: the consumer's data plane
# --------------------------------------------------------------------------------------------------

def phase_two(consumer_enabled, takeover, cidr, mesh=MESH_CIDR):
    """Whether phase two runs: asked for, on top of phase one, with a usable pool. An unusable pool
    stops phase two alone; phase one carries on, and domain rules read as if takeover were off."""
    if not consumer_enabled or not takeover:
        return {"active": False, "code": None}
    code = pool_problem(cidr, mesh)
    return {"active": code is None, "code": code}


def rule_status(rule, takeover, online, capable):
    """The code the status gives a rule; None is in force.

    The capability only counts for an egress that is online. The catalogue reads false for an
    offline egress, and an offline egress is phase one's egress-unavailable -- the rule is right and
    waiting -- not a rule pointed at a device that can never take it."""
    code = validate_rule(rule, takeover)
    if code is not None:
        return code
    match = (rule.get("match") or "").strip()
    if looks_like_domain(match) and rule["action"] == "egress":
        egress = int(rule["egressClientId"])
        if online.get(egress, False) and not capable.get(egress, False):
            return "EGRESS_RULE_EGRESS_NO_DOMAIN"
    return None


def positive_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


class CatalogReader:
    """What a consumer keeps from egress-catalog: which egress resolves names.

    The revision works as for egress-config: rising within one control session, a snapshot at or
    below the last accepted one ignored, the floor reset by a new session. What was learned stays
    until the next accepted catalogue replaces it."""

    def __init__(self):
        self.floor = None
        self.capable = {}

    def new_session(self):
        self.floor = None

    def read(self, text):
        try:
            message = json.loads(text)
        except ValueError:
            return False
        if not isinstance(message, dict) or message.get("type") != "egress-catalog":
            return False
        revision = message.get("revision")
        if not positive_int(revision):
            return False
        egresses = message.get("egresses", [])
        if not isinstance(egresses, list):
            return False
        if self.floor is not None and revision <= self.floor:
            return False
        self.floor = revision
        capable = {}
        for entry in egresses:
            if not isinstance(entry, dict) or not positive_int(entry.get("clientId")):
                continue
            capable[entry["clientId"]] = entry.get("domainTargetCapable") is True
        self.capable = capable
        return True

    def capable_ids(self):
        return sorted(client for client, able in self.capable.items() if able)


def in_pool(network, destination):
    return ipaddress.IPv4Address(destination) in network


class Steering:
    """The consumer's decision for one packet, with phase two running.

    A destination inside the pool is steered by the name it was handed out for, never by address
    rules (validation keeps address rules out of the pool). Outside the pool phase one decides."""

    def __init__(self, rules, cidr):
        self.rules = rules
        self.network = ipaddress.IPv4Network(cidr)
        self.pool = Pool(cidr)
        self.online = {}
        self.capable = {}
        # (protocol, sourcePort, destination, destinationPort) -> {"egress", "replied"}
        self.flows = {}

    def decide(self, destination, now, touch):
        if in_pool(self.network, destination):
            name = self.pool.by_address.get(int(ipaddress.IPv4Address(destination)))
            if name is None:
                return {"outcome": "blocked", "reason": "fake-ip-unmapped", "answered": True}
            if touch:
                self.pool.by_name[name]["lastUsed"] = now
            index = select_domain_rule(self.rules, name)
            if index is None or self.rules[index]["action"] == "direct":
                # The name was handed out under a rule that no longer claims it. Its real address is
                # unknown here, so the only choices are block or guess; the answer makes the
                # application ask again, and the fresh query goes wherever the rules now say.
                return {"outcome": "blocked", "reason": "fake-ip-stale", "answered": True}
            rule = self.rules[index]
            if rule["action"] == "block":
                return {"outcome": "blocked", "reason": "rule", "answered": False}
            return {"egress": int(rule["egressClientId"]), "name": name}
        address = ipaddress.IPv4Address(destination)
        best = None
        for rule in self.rules:
            match = (rule.get("match") or "").strip()
            if looks_like_domain(match) or validate_rule(rule, True) is not None:
                continue
            network = ipaddress.IPv4Network(match)
            if address in network and (best is None or network.prefixlen > best[0].prefixlen):
                best = (network, rule)
        if best is None or best[1]["action"] == "direct":
            return {"outcome": "not-mine"}
        if best[1]["action"] == "block":
            return {"outcome": "blocked", "reason": "rule", "answered": False}
        return {"egress": int(best[1]["egressClientId"]), "name": None}

    def packet(self, event, now):
        destination = event["destination"]
        decision = self.decide(destination, now, touch=True)
        if "outcome" in decision:
            return decision
        protocol = event["protocol"]
        if protocol not in ("tcp", "udp"):
            return {"outcome": "blocked", "reason": "unsupported-protocol", "answered": False}
        egress = decision["egress"]
        if not self.online.get(egress, False):
            return {"outcome": "blocked", "reason": "egress-unavailable", "answered": True}
        if decision["name"] is not None and not self.capable.get(egress, False):
            return {"outcome": "blocked", "reason": "egress-no-domain", "answered": True}
        key = (protocol, event["sourcePort"], destination, event["destinationPort"])
        flags = event.get("flags", "")
        opening = protocol == "tcp" and "S" in flags and "A" not in flags
        new = key not in self.flows
        if new:
            self.flows[key] = {"egress": egress, "replied": False}
        # A lost name-bind has to be recoverable. TCP recovers on the SYN the application
        # retransmits; UDP has nothing of its own, so until the egress has answered the flow at all,
        # every datagram carries one.
        unanswered_udp = protocol == "udp" and not self.flows[key]["replied"]
        name_bind = None
        if decision["name"] is not None and (new or opening or unanswered_udp):
            name_bind = {"address": destination, "name": decision["name"]}
        return {"outcome": "forwarded", "egressClientId": egress, "nameBind": name_bind}

    def reply(self, event):
        """A return packet from the flow's egress: the consumer's flow as the reply sees it."""
        key = (event["protocol"], event["sourcePort"], event["destination"], event["destinationPort"])
        flow = self.flows.get(key)
        if flow is None:
            return {"accepted": False}
        flow["replied"] = True
        return {"accepted": True}

    def purge(self, now):
        """Flows whose destination no longer goes to the egress carrying them, as flow-purge
        destinations per egress. The decision is re-run without touching the mapping: a rule
        change is not traffic."""
        out = {}
        for key, flow in sorted(self.flows.items()):
            egress = flow["egress"]
            decision = self.decide(key[2], now, touch=False)
            still = ("egress" in decision and decision["egress"] == egress
                     and self.online.get(egress, False)
                     and (decision["name"] is None or self.capable.get(egress, False)))
            if still:
                continue
            del self.flows[key]
            out.setdefault(str(egress), set()).add(key[2] + "/32")
        return {"purge": {egress: sorted(destinations) for egress, destinations in sorted(out.items())}}


class EgressBindings:
    """An egress's name bindings and the flows it opened, for one question: which flows a name-bind
    closes, and which of them the application is told about.

    A flow opened before its name arrived went to the fake address itself and will never work; once
    the name is known it is closed, so the consumer's next packet opens it properly. It is closed
    silently: that next packet is usually the application's own retransmitted SYN, and a reset sent
    now would refuse the connection the name-bind came to rescue. A flow opened for another name was
    a real connection to somewhere the address no longer means, and is reset like a revoked one."""

    def __init__(self):
        self.names = {}
        self.flows = {}  # id -> {"consumer", "address", "name"}

    def open(self, flow_id, consumer, address):
        name = self.names.get((consumer, address))
        self.flows[flow_id] = {"consumer": consumer, "address": address, "name": name}
        return {"name": name}

    def bind(self, consumer, address, name):
        name = normalize_name(name)
        self.names[(consumer, address)] = name
        closed = sorted(flow_id for flow_id, flow in self.flows.items()
                        if flow["consumer"] == consumer and flow["address"] == address and flow["name"] != name)
        reset = [flow_id for flow_id in closed if self.flows[flow_id]["name"] is not None]
        for flow_id in closed:
            del self.flows[flow_id]
        return {"closed": closed, "reset": reset}


def run_egress_binds(events):
    egress = EgressBindings()
    results = []
    for event in events:
        if "open" in event:
            results.append(egress.open(event["open"], event["consumer"], event["address"]))
        else:
            results.append(egress.bind(event["consumer"], event["address"], event["nameBind"]))
    return results


def run_steering(case):
    steering = Steering(case["rules"], case["cidr"])
    results = []
    for event in case["events"]:
        now = event["at"]
        if "map" in event:
            results.append(steering.pool.query(event["map"], now))
        elif "packet" in event:
            results.append(steering.packet(event["packet"], now))
        elif "reply" in event:
            results.append(steering.reply(event["reply"]))
        else:
            if "rules" in event:
                steering.rules = event["rules"]
            if "online" in event:
                steering.online.update({int(k): v for k, v in event["online"].items()})
            if "catalog" in event:
                steering.capable = {int(k): v for k, v in event["catalog"].items()}
            results.append(steering.purge(now))
    return results


# --------------------------------------------------------------------------------------------------
# name-bind and the egress's choice of address
# --------------------------------------------------------------------------------------------------

def encode_name_bind(address, name):
    return json.dumps({"type": "name-bind", "address": address, "name": normalize_name(name)},
                      separators=(",", ":"), ensure_ascii=True)


def choose_address(a_records, aaaa_records, ipv6_capable, decisions):
    """The egress resolves, then authorizes every address, then connects to the first allowed.
    `decisions` maps an address to its phase-one authorization code."""
    candidates = list(a_records) or (list(aaaa_records) if ipv6_capable else [])
    if not candidates:
        return {"address": None, "code": "EGRESS_NAME_UNRESOLVED"}
    for address in candidates:
        if decisions[address] == "EGRESS_ALLOWED":
            return {"address": address, "code": "EGRESS_ALLOWED"}
    return {"address": None, "code": decisions[candidates[0]]}


# --------------------------------------------------------------------------------------------------
# Cases
# --------------------------------------------------------------------------------------------------

RULES = [
    {"match": "example.com", "action": "egress", "egressClientId": 2},
    {"match": "*.example.com", "action": "egress", "egressClientId": 3},
    {"match": "*.cdn.example.com", "action": "block"},
    {"match": "direct.example.com", "action": "direct"},
    {"match": "*.example.com", "action": "block"},
    {"match": "*.corp.test", "action": "egress", "egressClientId": 2, "enabled": False},
    {"match": "203.0.113.0/24", "action": "egress", "egressClientId": 2},
]

VALIDATION = [
    ("exact-name", {"match": "example.com", "action": "egress", "egressClientId": 2}, True, None),
    ("suffix", {"match": "*.example.com", "action": "block"}, True, None),
    ("trailing-dot-and-case", {"match": "Example.COM.", "action": "direct"}, True, None),
    ("punycode", {"match": "xn--fiqs8s.example", "action": "direct"}, True, None),
    ("off-without-takeover", {"match": "example.com", "action": "direct"}, False, "EGRESS_RULE_DOMAIN_UNSUPPORTED"),
    ("unicode-refused", {"match": "中国.example", "action": "direct"}, True, "EGRESS_RULE_MALFORMED"),
    ("wildcard-inside", {"match": "a.*.example.com", "action": "direct"}, True, "EGRESS_RULE_MALFORMED"),
    ("bare-wildcard", {"match": "*", "action": "direct"}, True, "EGRESS_RULE_MALFORMED"),
    ("single-label", {"match": "localhost", "action": "direct"}, True, "EGRESS_RULE_MALFORMED"),
    ("label-too-long", {"match": ("a" * 64) + ".example", "action": "direct"}, True, "EGRESS_RULE_MALFORMED"),
    ("leading-hyphen", {"match": "-bad.example", "action": "direct"}, True, "EGRESS_RULE_MALFORMED"),
    ("underscore", {"match": "_srv.example.com", "action": "direct"}, True, "EGRESS_RULE_MALFORMED"),
    ("domain-with-port", {"match": "example.com", "action": "egress", "egressClientId": 2, "port": 443}, True,
     "EGRESS_RULE_PORT_UNSUPPORTED"),
    ("domain-missing-target", {"match": "example.com", "action": "egress"}, True, "EGRESS_RULE_MISSING_TARGET"),
    ("disabled-first", {"match": "中国.example", "action": "forward", "enabled": False}, True, "EGRESS_RULE_DISABLED"),
    ("cidr-overlaps-pool", {"match": "198.18.0.0/16", "action": "direct"}, True, "EGRESS_RULE_FAKE_IP_OVERLAP"),
    ("cidr-overlaps-pool-only-with-takeover", {"match": "198.18.0.0/16", "action": "direct"}, False, None),
    ("ipv6-still-refused", {"match": "2001:db8::/32", "action": "direct"}, True, "EGRESS_RULE_IPV6_UNSUPPORTED"),
]

POOL_CONFIG = [
    ("default", "198.18.0.0/15", None),
    ("narrowest", "198.18.5.0/24", None),
    ("widest", "10.0.0.0/8", None),
    ("too-narrow", "198.18.0.0/25", "EGRESS_FAKE_IP_POOL_INVALID"),
    ("too-wide", "198.0.0.0/7", "EGRESS_FAKE_IP_POOL_INVALID"),
    ("host-bits-set", "198.18.0.1/15", "EGRESS_FAKE_IP_POOL_INVALID"),
    ("ipv6", "fd00::/64", "EGRESS_FAKE_IP_POOL_INVALID"),
    ("overlaps-mesh", "100.96.0.0/16", "EGRESS_FAKE_IP_POOL_INVALID"),
    ("not-a-cidr", "fake-ip", "EGRESS_FAKE_IP_POOL_INVALID"),
]

EGRESS_CAPABILITY = [
    ("domain-to-capable-egress", {"match": "example.com", "action": "egress", "egressClientId": 2}, True, None),
    ("domain-to-incapable-egress", {"match": "example.com", "action": "egress", "egressClientId": 2}, False,
     "EGRESS_RULE_EGRESS_NO_DOMAIN"),
    ("suffix-to-incapable-egress", {"match": "*.example.com", "action": "egress", "egressClientId": 2}, False,
     "EGRESS_RULE_EGRESS_NO_DOMAIN"),
    ("domain-block-needs-no-egress", {"match": "example.com", "action": "block"}, False, None),
    ("address-rule-to-incapable-egress", {"match": "203.0.113.0/24", "action": "egress", "egressClientId": 2},
     False, None),
    ("disabled-still-first", {"match": "example.com", "action": "egress", "egressClientId": 2, "enabled": False},
     False, "EGRESS_RULE_DISABLED"),
]

SELECTION = [
    ("exact-beats-suffix", "example.com", 0),
    ("suffix-covers-subdomain", "www.example.com", 1),
    ("suffix-not-apex", "example.com", 0),
    ("longer-suffix-wins", "img.cdn.example.com", 2),
    ("exact-direct-beats-suffix", "direct.example.com", 3),
    ("earlier-of-equal-suffixes", "a.b.example.com", 1),
    ("trailing-dot-and-case", "WWW.Example.com.", 1),
    ("switched-off-rule-ignored", "host.corp.test", None),
    ("unrelated", "example.org", None),
    ("suffix-needs-a-dot", "badexample.com", None),
]

ANSWERS = [
    ("egress-a", "www.example.com", "A"),
    ("egress-aaaa-nodata", "www.example.com", "AAAA"),
    ("egress-https-nodata", "www.example.com", "HTTPS"),
    ("egress-svcb-nodata", "www.example.com", "SVCB"),
    ("egress-mx-forwarded", "www.example.com", "MX"),
    ("block-a", "img.cdn.example.com", "A"),
    ("direct-forwarded", "direct.example.com", "A"),
    ("unmatched-forwarded", "example.org", "A"),
]

POOL_CASES = [
    {
        "name": "same-name-same-address-and-refresh",
        "cidr": "198.18.0.0/29",
        "events": [
            {"at": 0, "query": "a.example.com"},
            {"at": 5, "query": "b.example.com"},
            {"at": 10, "query": "A.example.com."},
            {"at": 20, "traffic": "198.18.0.3"},
            {"at": 30, "traffic": "198.18.0.6"},
        ],
    },
    {
        "name": "exhausted-while-every-mapping-is-recent",
        "cidr": "198.18.0.0/29",
        "events": [
            {"at": 0, "query": "n1.example"},
            {"at": 1, "query": "n2.example"},
            {"at": 2, "query": "n3.example"},
            {"at": 3, "query": "n4.example"},
            {"at": 4, "query": "n5.example"},
            {"at": 5, "query": "n6.example"},
        ],
    },
    {
        "name": "idle-mappings-evicted-and-quarantined",
        "cidr": "198.18.0.0/29",
        "events": [
            {"at": 0, "query": "n1.example"},
            {"at": 0, "query": "n2.example"},
            {"at": 0, "query": "n3.example"},
            {"at": 0, "query": "n4.example"},
            {"at": 0, "query": "n5.example"},
            {"at": 3 * 3600, "traffic": "198.18.0.3"},
            {"at": 6 * 3600 + 1, "query": "n6.example"},
            {"at": 6 * 3600 + 2, "traffic": "198.18.0.2"},
            {"at": 6 * 3600 + 10 * 60, "query": "n7.example"},
            {"at": 6 * 3600 + 31 * 60, "query": "n7.example"},
        ],
    },
    {
        "name": "quarantine-ends",
        "cidr": "198.18.0.0/30",
        "events": [
            {"at": 0, "query": "only.example"},
            {"at": MIN_LIFETIME, "query": "next.example"},
            {"at": MIN_LIFETIME + QUARANTINE, "query": "next.example"},
            {"at": MIN_LIFETIME + QUARANTINE + 1, "traffic": "198.18.0.2"},
        ],
    },
]

PHASE_TWO = [
    ("off-by-default", True, False, DEFAULT_POOL),
    ("on", True, True, DEFAULT_POOL),
    ("needs-phase-one", False, True, DEFAULT_POOL),
    ("unusable-pool-stops-phase-two", True, True, "198.18.0.0/25"),
    ("pool-over-the-mesh", True, True, "100.96.0.0/16"),
]

RULE_STATUS = [
    ("domain-to-online-capable", {"match": "example.com", "action": "egress", "egressClientId": 2}, True, True, True),
    ("domain-to-online-incapable", {"match": "example.com", "action": "egress", "egressClientId": 2}, True, True,
     False),
    ("suffix-to-online-incapable", {"match": "*.example.com", "action": "egress", "egressClientId": 2}, True, True,
     False),
    # Offline, the catalogue says false; the rule is right and waiting, as any rule to an offline egress.
    ("domain-to-offline-egress", {"match": "example.com", "action": "egress", "egressClientId": 2}, True, False,
     False),
    ("domain-block-with-incapable-egress", {"match": "example.com", "action": "block"}, True, True, False),
    ("address-to-online-incapable", {"match": "203.0.113.0/24", "action": "egress", "egressClientId": 2}, True, True,
     False),
    ("domain-without-phase-two", {"match": "example.com", "action": "egress", "egressClientId": 2}, False, True, True),
    ("disabled-first", {"match": "example.com", "action": "egress", "egressClientId": 2, "enabled": False}, True,
     True, False),
]


def catalog_text(revision, egresses, **extra):
    message = {"type": "egress-catalog", "revision": revision, "egresses": egresses}
    message.update(extra)
    return json.dumps(message, separators=(",", ":"))


CATALOG_EVENTS = [
    ("first", catalog_text(4, [
        {"clientId": 2, "clientName": "office-gateway", "online": True, "scope": "PUBLIC", "protocols": ["tcp"],
         "domainTargetCapable": True, "ipv6TargetCapable": False},
        {"clientId": 3, "clientName": "home-gateway", "online": True, "scope": "PUBLIC", "protocols": ["tcp"],
         "domainTargetCapable": False, "ipv6TargetCapable": False}])),
    ("same-revision-ignored", catalog_text(4, [{"clientId": 3, "domainTargetCapable": True}])),
    ("older-revision-ignored", catalog_text(3, [{"clientId": 3, "domainTargetCapable": True}])),
    ("newer-replaces-everything", catalog_text(5, [{"clientId": 3, "domainTargetCapable": True}])),
    ("not-a-catalogue", json.dumps({"type": "egress-config", "revision": 9, "enabled": False},
                                   separators=(",", ":"))),
    ("only-json-true-counts", catalog_text(6, [{"clientId": 2, "domainTargetCapable": "true"},
                                                {"clientId": 3, "domainTargetCapable": 1}],
                                           createdAtMillis=1757000000000)),
    ("absent-list-is-empty", json.dumps({"type": "egress-catalog", "revision": 7}, separators=(",", ":"))),
    ("revision-must-be-a-number", catalog_text("8", [{"clientId": 2, "domainTargetCapable": True}])),
    ("list-must-be-a-list", catalog_text(8, {"clientId": 2, "domainTargetCapable": True})),
    ("new-session", None),
    ("floor-reset-by-the-new-session", catalog_text(1, [{"clientId": 2, "domainTargetCapable": True}])),
    ("entries-without-a-usable-id-skipped", catalog_text(2, [
        {"clientId": 0, "domainTargetCapable": True}, {"clientId": -3, "domainTargetCapable": True},
        {"clientId": "2", "domainTargetCapable": True}, {"clientId": True, "domainTargetCapable": True},
        "gateway", {"clientId": 4, "domainTargetCapable": True}])),
    ("not-json", "{\"type\":\"egress-catalog\","),
]

STEERING_RULES = [
    {"match": "example.com", "action": "egress", "egressClientId": 2},
    {"match": "*.example.com", "action": "egress", "egressClientId": 3},
    {"match": "*.ads.example.com", "action": "block"},
    {"match": "direct.example.com", "action": "direct"},
    {"match": "203.0.113.0/24", "action": "egress", "egressClientId": 2},
]


def tcp(source_port, destination, flags, port=443):
    return {"packet": {"protocol": "tcp", "sourcePort": source_port, "destination": destination,
                       "destinationPort": port, "flags": flags}}


def udp(source_port, destination, port=443):
    return {"packet": {"protocol": "udp", "sourcePort": source_port, "destination": destination,
                       "destinationPort": port}}


STEERING_EVENTS = [
    {"online": {"2": True, "3": True}, "catalog": {"2": True, "3": False}},
    {"map": "example.com"},
    {"map": "www.example.com"},
    {"map": "x.ads.example.com"},
    tcp(40000, "198.18.0.2", "S"),
    tcp(40000, "198.18.0.2", "S"),
    tcp(40000, "198.18.0.2", "A"),
    udp(50000, "198.18.0.2"),
    udp(50000, "198.18.0.2"),
    {"reply": {"protocol": "udp", "sourcePort": 50000, "destination": "198.18.0.2", "destinationPort": 443}},
    udp(50000, "198.18.0.2"),
    tcp(40001, "198.18.0.3", "S"),
    tcp(40002, "198.18.0.4", "S"),
    tcp(40003, "198.18.0.5", "S"),
    {"packet": {"protocol": "icmp", "destination": "198.18.0.2"}},
    tcp(40004, "203.0.113.10", "S"),
    tcp(40005, "192.0.2.1", "S"),
    {"catalog": {"2": True, "3": True}},
    tcp(40001, "198.18.0.3", "S"),
    {"catalog": {"2": False, "3": True}},
    tcp(40000, "198.18.0.2", "A"),
    tcp(40004, "203.0.113.10", "A"),
    {"catalog": {"2": True, "3": True}},
    tcp(40006, "198.18.0.2", "S"),
    {"rules": [{"match": "example.com", "action": "block"}] + STEERING_RULES[1:]},
    tcp(40006, "198.18.0.2", "A"),
    {"online": {"3": False}},
    tcp(40001, "198.18.0.3", "A"),
    {"rules": [{"match": "example.com", "action": "block"}] + STEERING_RULES[2:]},
    tcp(40007, "198.18.0.3", "S"),
]

EGRESS_BIND_EVENTS = [
    {"open": "early", "consumer": 1, "address": "198.18.0.5"},
    {"open": "other-consumer", "consumer": 7, "address": "198.18.0.5"},
    {"nameBind": "example.com", "consumer": 1, "address": "198.18.0.5"},
    {"open": "bound", "consumer": 1, "address": "198.18.0.5"},
    {"nameBind": "Example.COM.", "consumer": 1, "address": "198.18.0.5"},
    {"nameBind": "www.example.com", "consumer": 1, "address": "198.18.0.5"},
]

EGRESS_CHOICES = [
    ("first-allowed-a", ["203.0.113.10", "203.0.113.11"], [], False,
     {"203.0.113.10": "EGRESS_ALLOWED", "203.0.113.11": "EGRESS_ALLOWED"}),
    ("skips-a-denied-address", ["127.0.0.1", "203.0.113.11"], [], False,
     {"127.0.0.1": "EGRESS_FORBIDDEN_DESTINATION", "203.0.113.11": "EGRESS_ALLOWED"}),
    ("rebinding-to-loopback-refused", ["127.0.0.1"], [], False, {"127.0.0.1": "EGRESS_FORBIDDEN_DESTINATION"}),
    ("all-denied-reports-the-first", ["10.0.0.5", "198.51.100.9"], [], False,
     {"10.0.0.5": "EGRESS_SCOPE_DENIED", "198.51.100.9": "EGRESS_DEST_DENIED"}),
    ("a-preferred-over-aaaa", ["203.0.113.10"], ["2001:db8::10"], True,
     {"203.0.113.10": "EGRESS_ALLOWED", "2001:db8::10": "EGRESS_ALLOWED"}),
    ("aaaa-when-no-a-and-capable", [], ["2001:db8::10"], True, {"2001:db8::10": "EGRESS_ALLOWED"}),
    ("aaaa-ignored-when-not-capable", [], ["2001:db8::10"], False, {"2001:db8::10": "EGRESS_ALLOWED"}),
    ("nothing-resolved", [], [], True, {}),
]


def build():
    rules = [dict(rule) for rule in RULES]
    validation = []
    for name, rule, takeover, code in VALIDATION:
        produced = validate_rule(rule, takeover)
        assert produced == code, (name, produced, code)
        validation.append({"name": name, "rule": rule, "takeover": takeover, "code": code})
    pool_config = []
    for name, cidr, code in POOL_CONFIG:
        produced = pool_problem(cidr)
        assert produced == code, (name, produced, code)
        pool_config.append({"name": name, "cidr": cidr, "code": code})
    capability = []
    for name, rule, capable, code in EGRESS_CAPABILITY:
        produced = rule_in_force(rule, True, capable)
        assert produced == code, (name, produced, code)
        capability.append({"name": name, "rule": rule, "egressDomainTargetCapable": capable, "code": code})
    selection = []
    for name, qname, index in SELECTION:
        produced = select_domain_rule(rules, qname)
        assert produced == index, (name, produced, index)
        selection.append({"name": name, "query": qname, "ruleIndex": index})
    answers = []
    for name, qname, qtype in ANSWERS:
        produced = dns_answer(rules, qname, qtype)
        answers.append({"name": name, "query": qname, "type": qtype, **produced})
    # Hand-checked expectations for the answers, so the reference itself is pinned.
    expected_answers = {"egress-a": "fake", "egress-aaaa-nodata": "nodata", "egress-https-nodata": "nodata",
                        "egress-svcb-nodata": "nodata", "egress-mx-forwarded": "forward", "block-a": "fake",
                        "direct-forwarded": "forward", "unmatched-forwarded": "forward"}
    for case in answers:
        assert case["answer"] == expected_answers[case["name"]], case
    pool = []
    for case in POOL_CASES:
        pool.append({**case, "results": run_pool(case["cidr"], case["events"])})
    # Hand-checked expectations for the pool, so the reference itself is pinned.
    first = [result.get("address") or result.get("name") or result.get("blocked") for result in pool[0]["results"]]
    assert first == ["198.18.0.2", "198.18.0.3", "198.18.0.2", "b.example.com", "fake-ip-unmapped"], first
    second = pool[1]["results"]
    assert [r.get("address") for r in second[:5]] == [f"198.18.0.{i}" for i in range(2, 7)], second
    assert second[5] == {"exhausted": True, "evicted": []}, second
    # n2 was used at 3 h and survives; the other four have been idle for 6 h and go, into quarantine,
    # so the query that evicted them still finds nothing free. Their addresses block until reused,
    # and become free again only when the 30 minutes are over.
    third = pool[2]["results"]
    assert third[6] == {"exhausted": True, "evicted": ["n1.example", "n3.example", "n4.example", "n5.example"]}, third
    assert third[7] == {"blocked": "fake-ip-unmapped"}, third
    assert third[8] == {"exhausted": True, "evicted": []}, third
    assert third[9] == {"address": "198.18.0.2", "evicted": []}, third
    fourth = pool[3]["results"]
    assert fourth[1] == {"exhausted": True, "evicted": ["only.example"]}, fourth
    assert fourth[2] == {"address": "198.18.0.2", "evicted": []}, fourth
    assert fourth[3] == {"name": "next.example"}, fourth
    name_bind = [
        {"name": "plain", "address": "198.18.0.5", "domain": "example.com",
         "json": encode_name_bind("198.18.0.5", "example.com")},
        {"name": "normalised", "address": "198.18.0.6", "domain": "WWW.Example.com.",
         "json": encode_name_bind("198.18.0.6", "WWW.Example.com.")},
    ]
    assert name_bind[1]["json"] == '{"type":"name-bind","address":"198.18.0.6","name":"www.example.com"}'
    bind_at_egress = [
        {"name": "capable-egress-binds", "domainTargetCapable": True,
         "json": encode_name_bind("198.18.0.5", "example.com"), "code": name_bind_at_egress(True)},
        {"name": "incapable-egress-refuses", "domainTargetCapable": False,
         "json": encode_name_bind("198.18.0.5", "example.com"), "code": name_bind_at_egress(False)},
    ]
    phase = []
    for name, consumer_enabled, takeover, cidr in PHASE_TWO:
        phase.append({"name": name, "consumerEnabled": consumer_enabled, "takeover": takeover, "cidr": cidr,
                      **phase_two(consumer_enabled, takeover, cidr)})
    assert [case["active"] for case in phase] == [False, True, False, False, False], phase
    rule_status_cases = []
    for name, rule, takeover, online, capable in RULE_STATUS:
        rule_status_cases.append({"name": name, "rule": rule, "takeover": takeover, "egressOnline": online,
                                  "egressDomainTargetCapable": capable,
                                  "code": rule_status(rule, takeover, {2: online}, {2: capable})})
    assert [case["code"] for case in rule_status_cases] == [
        None, "EGRESS_RULE_EGRESS_NO_DOMAIN", "EGRESS_RULE_EGRESS_NO_DOMAIN", None, None, None,
        "EGRESS_RULE_DOMAIN_UNSUPPORTED", "EGRESS_RULE_DISABLED"], rule_status_cases
    reader = CatalogReader()
    catalog = []
    for name, text in CATALOG_EVENTS:
        if text is None:
            reader.new_session()
            catalog.append({"name": name, "newSession": True, "domainTargetCapable": reader.capable_ids()})
            continue
        accepted = reader.read(text)
        catalog.append({"name": name, "json": text, "accepted": accepted,
                        "domainTargetCapable": reader.capable_ids()})
    # Hand-checked, so the reference itself is pinned.
    assert [(case.get("accepted"), case["domainTargetCapable"]) for case in catalog] == [
        (True, [2]), (False, [2]), (False, [2]), (True, [3]), (False, [3]), (True, []), (True, []),
        (False, []), (False, []), (None, []), (True, [2]), (True, [4]), (False, [4])], catalog
    events = [{"at": index, **event} for index, event in enumerate(STEERING_EVENTS)]
    steering_case = {"name": "consumer-steering", "cidr": "198.18.0.0/29", "rules": STEERING_RULES,
                     "events": events}
    steering_case["results"] = run_steering(steering_case)
    outcomes = [result.get("outcome") or result.get("address") or result for result in steering_case["results"]]
    fake2 = {"address": "198.18.0.2", "name": "example.com"}
    fake3 = {"address": "198.18.0.3", "name": "www.example.com"}
    assert steering_case["results"] == [
        {"purge": {}},
        {"address": "198.18.0.2", "evicted": []},
        {"address": "198.18.0.3", "evicted": []},
        {"address": "198.18.0.4", "evicted": []},
        {"outcome": "forwarded", "egressClientId": 2, "nameBind": fake2},
        {"outcome": "forwarded", "egressClientId": 2, "nameBind": fake2},
        {"outcome": "forwarded", "egressClientId": 2, "nameBind": None},
        {"outcome": "forwarded", "egressClientId": 2, "nameBind": fake2},
        {"outcome": "forwarded", "egressClientId": 2, "nameBind": fake2},
        {"accepted": True},
        {"outcome": "forwarded", "egressClientId": 2, "nameBind": None},
        {"outcome": "blocked", "reason": "egress-no-domain", "answered": True},
        {"outcome": "blocked", "reason": "rule", "answered": False},
        {"outcome": "blocked", "reason": "fake-ip-unmapped", "answered": True},
        {"outcome": "blocked", "reason": "unsupported-protocol", "answered": False},
        {"outcome": "forwarded", "egressClientId": 2, "nameBind": None},
        {"outcome": "not-mine"},
        {"purge": {}},
        {"outcome": "forwarded", "egressClientId": 3, "nameBind": fake3},
        {"purge": {"2": ["198.18.0.2/32"]}},
        {"outcome": "blocked", "reason": "egress-no-domain", "answered": True},
        {"outcome": "forwarded", "egressClientId": 2, "nameBind": None},
        {"purge": {}},
        {"outcome": "forwarded", "egressClientId": 2, "nameBind": fake2},
        {"purge": {"2": ["198.18.0.2/32"]}},
        {"outcome": "blocked", "reason": "rule", "answered": False},
        {"purge": {"3": ["198.18.0.3/32"]}},
        {"outcome": "blocked", "reason": "egress-unavailable", "answered": True},
        {"purge": {}},
        {"outcome": "blocked", "reason": "fake-ip-stale", "answered": True},
    ], outcomes
    bind_events = [dict(event) for event in EGRESS_BIND_EVENTS]
    bind_results = run_egress_binds(bind_events)
    assert bind_results == [
        {"name": None}, {"name": None}, {"closed": ["early"], "reset": []}, {"name": "example.com"},
        {"closed": [], "reset": []}, {"closed": ["bound"], "reset": ["bound"]}], bind_results
    choices = []
    for name, a_records, aaaa_records, capable, decisions in EGRESS_CHOICES:
        choices.append({"name": name, "a": a_records, "aaaa": aaaa_records, "ipv6TargetCapable": capable,
                        "decisions": decisions, **choose_address(a_records, aaaa_records, capable, decisions)})
    return {
        "description": "Phase two of peer egress: domain rules, the DNS responder, the fake-IP pool, "
                       "name-bind and the egress's choice of address. See protocol/spec/peer-egress-dns.md.",
        "meshCidr": MESH_CIDR,
        "fakeIpCidr": DEFAULT_POOL,
        "minLifetimeSeconds": MIN_LIFETIME,
        "quarantineSeconds": QUARANTINE,
        "rules": rules,
        "validation": validation,
        "poolConfig": pool_config,
        "egressCapability": capability,
        "selection": selection,
        "answers": answers,
        "pool": pool,
        "nameBind": name_bind,
        "nameBindAtEgress": bind_at_egress,
        "egressChoice": choices,
        "phaseTwo": phase,
        "ruleStatus": rule_status_cases,
        "catalog": catalog,
        "steering": [steering_case],
        "nameBindClosesFlows": {"events": bind_events, "results": bind_results},
    }


def main():
    document = build()
    path = VECTORS / "peer-egress-dns-v1.json"
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {path}: validation={len(document['validation'])} selection={len(document['selection'])} "
          f"answers={len(document['answers'])} pool={len(document['pool'])} egressChoice={len(document['egressChoice'])} "
          f"phaseTwo={len(document['phaseTwo'])} ruleStatus={len(document['ruleStatus'])} "
          f"catalog={len(document['catalog'])} steering={len(document['steering'][0]['events'])}")


if __name__ == "__main__":
    main()
