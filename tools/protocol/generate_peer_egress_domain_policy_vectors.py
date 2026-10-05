"""Generate peer-egress-domain-policy-v1.json: the domain rules of an egress policy.

Destination rules grant addresses. A name a consumer bound with name-bind resolves at the egress to
addresses an operator rarely knows ahead of time -- a CDN moves them -- so a policy meant to allow
one site had to allow 0.0.0.0/0. Domain rules grant names: a flow that carries a name is also
admitted by a domain rule that matches it, with that rule's protocols and ports. The resolved
address still goes through the forced-deny list and the scope first, so a name that resolves to
loopback, a private network or the mesh is refused exactly as before (DNS rebinding). A flow without
a name is never admitted by a domain rule. See protocol/spec/peer-egress.md, 出口授权模型.

Two halves: what a server stores and refuses when a policy is saved (management), and what an
egress decides for a pushed egress-config (authorize). Every expectation is produced by the
reference here and pinned against hand-written values.
"""
import ipaddress
import json
from pathlib import Path

from generate_peer_egress_dns_vectors import looks_like_domain, normalize_name, valid_domain_match

VECTORS = Path("protocol/test-vectors")
MAX_RULES = 64
MAX_PORT_RANGES = 32
MAX_RULES_JSON_BYTES = 4096

FORCED_DENY = ["0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
               "255.255.255.255/32", "100.96.0.0/11", "100.100.100.200/32"]
LAN_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"]


class Refused(Exception):
    pass


# --------------------------------------------------------------------------------------------------
# Management: what a server stores
# --------------------------------------------------------------------------------------------------

def stored_match(value):
    """The match as stored: trimmed, trailing dot removed, lower case. Only a name or *.name with
    at least two labels, punycode for IDN -- the consumer's domain rule syntax."""
    if not isinstance(value, str):
        raise Refused("match")
    text = value.strip()
    if not text or not looks_like_domain(text) or not valid_domain_match(text):
        raise Refused("match")
    return normalize_name(text)


def normalize_domain_rules(rules):
    """Protocols and port ranges follow the destination rules (peer-egress-management-v1.json)."""
    if len(rules) > MAX_RULES:
        raise Refused("too many rules")
    stored = []
    for rule in rules:
        match = stored_match(rule.get("match"))
        protocols = []
        for protocol in rule.get("protocols") or []:
            value = str(protocol).strip().lower()
            if value not in ("tcp", "udp"):
                raise Refused("protocol")
            if value not in protocols:
                protocols.append(value)
        ranges = []
        for pair in rule.get("portRanges") or []:
            if (not isinstance(pair, list) or len(pair) != 2
                    or not all(isinstance(port, int) and not isinstance(port, bool) for port in pair)):
                raise Refused("port range shape")
            low, high = pair
            if low < 0 or high > 65535 or low > high:
                raise Refused("port range bounds")
            ranges.append([low, high])
        if len(ranges) > MAX_PORT_RANGES:
            raise Refused("too many port ranges")
        stored.append({"match": match, "protocols": protocols, "portRanges": ranges})
    if len(json.dumps(stored, separators=(",", ":"))) > MAX_RULES_JSON_BYTES:
        raise Refused("too large")
    return stored


def domain(match="example.com", protocols=("tcp",), ranges=((443, 443),)):
    return {"match": match, "protocols": list(protocols), "portRanges": [list(pair) for pair in ranges]}


ACCEPT = [
    ("exact", [domain()]),
    ("suffix", [domain("*.cdn.example", ("tcp", "udp"))]),
    ("spelling-normalised", [{"match": " *.CDN.Example. ", "protocols": [" UDP ", "tcp", "udp"], "portRanges": [[443, 443]]}]),
    ("punycode", [domain("xn--fiqs8s.example")]),
    ("deny-all-kept", [domain(protocols=(), ranges=())]),
    ("absent-lists", [{"match": "example.org"}]),
    ("no-rules", []),
    ("most-rules", [domain(f"h{index}.example", (), ()) for index in range(MAX_RULES)]),
]

REJECT = [
    ("bare-wildcard", [domain("*")]),
    ("wildcard-of-a-top-level-label", [domain("*.com")]),
    ("single-label", [domain("localhost")]),
    ("wildcard-inside", [domain("a.*.example.com")]),
    ("unicode", [domain("中国.example")]),
    ("underscore", [domain("_srv.example.com")]),
    ("label-too-long", [domain(("a" * 64) + ".example")]),
    ("address-is-a-destination-rule", [domain("203.0.113.5")]),
    ("cidr-is-a-destination-rule", [domain("203.0.113.0/24")]),
    ("with-port", [domain("example.com:443")]),
    ("empty-match", [domain("")]),
    ("missing-match", [{"protocols": ["tcp"], "portRanges": [[443, 443]]}]),
    ("unknown-protocol", [domain(protocols=("icmp",))]),
    ("reversed-range", [domain(ranges=((443, 80),))]),
    ("too-many-rules", [domain(f"h{index}.example", (), ()) for index in range(MAX_RULES + 1)]),
    ("too-many-port-ranges", [domain(ranges=tuple((port, port) for port in range(1000, 1000 + MAX_PORT_RANGES + 1)))]),
    ("too-large", [domain(f"host-{index:02d}.example", ("tcp", "udp"), tuple((port, port) for port in range(8000, 8008)))
                   for index in range(40)]),
]


# --------------------------------------------------------------------------------------------------
# Egress: decoding the pushed policy and deciding a flow
# --------------------------------------------------------------------------------------------------

def readable_lists(entry):
    """protocols must be an array of strings and portRanges an array of [integer, integer] pairs;
    absent means empty. Anything else makes the entry unreadable."""
    protocols = entry.get("protocols", [])
    ranges = entry.get("portRanges", [])
    if protocols is None:
        protocols = []
    if ranges is None:
        ranges = []
    if not isinstance(protocols, list) or not all(isinstance(value, str) for value in protocols):
        return None
    if not isinstance(ranges, list) or not all(
            isinstance(pair, list) and len(pair) == 2
            and all(isinstance(port, int) and not isinstance(port, bool) for port in pair) for pair in ranges):
        return None
    return protocols, ranges


def decode_domain_rules(config):
    """What an egress keeps from egress-config: an absent or non-array field is no domain rules; an
    entry that is not an object, whose match is not a valid name, or whose protocols or portRanges
    are not the shapes destinationRules use, is skipped and the rest kept. A skipped entry grants
    nothing, which is what a rule the egress cannot read must do."""
    value = config.get("domainRules")
    if not isinstance(value, list):
        return []
    kept = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        try:
            match = stored_match(entry.get("match"))
        except Refused:
            continue
        lists = readable_lists(entry)
        if lists is None:
            continue
        kept.append({"match": match, "protocols": lists[0], "portRanges": lists[1]})
    return kept


def covers(match, name):
    if match.startswith("*."):
        return name.endswith(match[1:])
    return name == match


def in_any(address, cidrs):
    value = ipaddress.IPv4Address(address)
    return any(value in ipaddress.IPv4Network(cidr) for cidr in cidrs)


def allows_port(rule, port):
    return any(isinstance(pair, list) and len(pair) == 2 and pair[0] <= port <= pair[1]
               for pair in rule["portRanges"])


def decide(config, request):
    """The fixed order of peer-egress-authz-v1.json. The destination, protocol and port steps look
    at the destination rules that contain the address together with, for a flow that carries a name,
    the domain rules that cover it. The steps before stay on the address."""
    if not config.get("enabled"):
        return "EGRESS_DISABLED"
    if request["consumerClientId"] not in config.get("allowedConsumerClientIds", []):
        return "EGRESS_CONSUMER_DENIED"
    address = request["destinationIp"]
    if in_any(address, FORCED_DENY):
        return "EGRESS_FORBIDDEN_DESTINATION"
    if ("LAN" if in_any(address, LAN_RANGES) else "PUBLIC") != config.get("scope"):
        return "EGRESS_SCOPE_DENIED"
    matched = [rule for rule in config.get("destinationRules", []) if in_any(address, [rule["cidr"]])]
    if request.get("name") is not None:
        name = normalize_name(request["name"])
        matched += [rule for rule in decode_domain_rules(config) if covers(rule["match"], name)]
    if not matched:
        return "EGRESS_DEST_DENIED"
    matched = [rule for rule in matched if request["protocol"] in rule["protocols"]]
    if not matched:
        return "EGRESS_PROTOCOL_DENIED"
    if not any(allows_port(rule, request["destinationPort"]) for rule in matched):
        return "EGRESS_PORT_DENIED"
    return "EGRESS_ALLOWED"


CONFIG = {
    "type": "egress-config",
    "enabled": True,
    "revision": 1,
    "scope": "PUBLIC",
    "allowedConsumerClientIds": [1],
    "destinationRules": [{"cidr": "203.0.113.0/24", "protocols": ["tcp"], "portRanges": [[443, 443]]}],
    "domainRules": [
        {"match": "example.com", "protocols": ["tcp"], "portRanges": [[443, 443]]},
        {"match": "*.cdn.example", "protocols": ["tcp", "udp"], "portRanges": [[443, 443]]},
        {"match": "api.example.org", "protocols": ["udp"], "portRanges": [[53, 53]]},
    ],
    "limits": {"maxConcurrentFlows": 256, "maxFlowsPerConsumer": 64, "idleTimeoutSeconds": 60},
}


def flow(address, name=None, port=443, protocol="tcp", consumer=1):
    request = {"consumerClientId": consumer, "destinationIp": address, "destinationPort": port, "protocol": protocol}
    if name is not None:
        request["name"] = name
    return request


# (case, config override, request, expected code), checked against decide() before writing.
AUTHORIZE = [
    ("name-granted-by-exact-rule", None, flow("192.0.2.10", "example.com"), "EGRESS_ALLOWED"),
    ("name-compared-normalised", None, flow("192.0.2.10", "Example.COM."), "EGRESS_ALLOWED"),
    ("exact-rule-does-not-cover-subdomain", None, flow("192.0.2.10", "www.example.com"), "EGRESS_DEST_DENIED"),
    ("suffix-rule-covers-deep-subdomain", None, flow("192.0.2.10", "a.b.cdn.example"), "EGRESS_ALLOWED"),
    ("suffix-rule-does-not-cover-apex", None, flow("192.0.2.10", "cdn.example"), "EGRESS_DEST_DENIED"),
    ("suffix-rule-needs-a-label-boundary", None, flow("192.0.2.10", "xcdn.example"), "EGRESS_DEST_DENIED"),
    ("suffix-rule-grants-udp", None, flow("192.0.2.10", "v.cdn.example", protocol="udp"), "EGRESS_ALLOWED"),
    ("name-rule-protocol-denied", None, flow("192.0.2.10", "example.com", protocol="udp"), "EGRESS_PROTOCOL_DENIED"),
    ("name-rule-port-denied", None, flow("192.0.2.10", "example.com", port=80), "EGRESS_PORT_DENIED"),
    ("flow-without-name-not-granted-by-domain", None, flow("192.0.2.10"), "EGRESS_DEST_DENIED"),
    ("rebinding-to-loopback-refused", None, flow("127.0.0.1", "example.com"), "EGRESS_FORBIDDEN_DESTINATION"),
    ("rebinding-to-mesh-refused", None, flow("100.96.0.9", "example.com"), "EGRESS_FORBIDDEN_DESTINATION"),
    ("rebinding-to-metadata-refused", None, flow("100.100.100.200", "example.com"), "EGRESS_FORBIDDEN_DESTINATION"),
    ("rebinding-to-private-refused-by-scope", None, flow("10.0.0.5", "example.com"), "EGRESS_SCOPE_DENIED"),
    ("unlisted-consumer-refused-first", None, flow("192.0.2.10", "example.com", consumer=9), "EGRESS_CONSUMER_DENIED"),
    ("destination-rule-still-grants-any-name", None, flow("203.0.113.9", "other.example"), "EGRESS_ALLOWED"),
    ("rules-combine-for-protocol", None, flow("203.0.113.9", "api.example.org", port=53, protocol="udp"), "EGRESS_ALLOWED"),
    ("rules-combine-for-port", None, flow("203.0.113.9", "api.example.org", port=80), "EGRESS_PORT_DENIED"),
    ("disabled-policy-grants-nothing", {"enabled": False}, flow("192.0.2.10", "example.com"), "EGRESS_DISABLED"),
    ("lan-scope-name-to-private", {"scope": "LAN"}, flow("192.168.1.20", "example.com"), "EGRESS_ALLOWED"),
    ("lan-scope-name-to-public-refused", {"scope": "LAN"}, flow("192.0.2.10", "example.com"), "EGRESS_SCOPE_DENIED"),
    ("absent-domain-rules", {"domainRules": None}, flow("192.0.2.10", "example.com"), "EGRESS_DEST_DENIED"),
    ("domain-rules-not-an-array", {"domainRules": {"match": "example.com"}}, flow("192.0.2.10", "example.com"),
     "EGRESS_DEST_DENIED"),
    ("unreadable-entries-skipped", {"domainRules": [
        "example.com", {"match": "*", "protocols": ["tcp"], "portRanges": [[443, 443]]},
        {"match": 7, "protocols": ["tcp"], "portRanges": [[443, 443]]},
        {"match": "EXAMPLE.com.", "protocols": ["tcp"], "portRanges": [[443, 443]]}]},
     flow("192.0.2.10", "example.com"), "EGRESS_ALLOWED"),
    ("wildcard-entry-grants-nothing", {"domainRules": [{"match": "*", "protocols": ["tcp"], "portRanges": [[443, 443]]}]},
     flow("192.0.2.10", "example.com"), "EGRESS_DEST_DENIED"),
    # A protocols string is not a list of protocols: read as one, "tcp" in "tcp" would grant.
    ("protocols-not-an-array-skipped", {"domainRules": [{"match": "example.com", "protocols": "tcp",
                                                          "portRanges": [[443, 443]]}]},
     flow("192.0.2.10", "example.com"), "EGRESS_DEST_DENIED"),
    ("port-range-not-integers-skipped", {"domainRules": [{"match": "example.com", "protocols": ["tcp"],
                                                           "portRanges": [[443.0, 443.0]]}]},
     flow("192.0.2.10", "example.com"), "EGRESS_DEST_DENIED"),
    # Absent lists are empty ones: the rule covers the name and allows no protocol.
    ("absent-lists-allow-no-protocol", {"domainRules": [{"match": "example.com"}]},
     flow("192.0.2.10", "example.com"), "EGRESS_PROTOCOL_DENIED"),
]


def build():
    accept = [{"name": name, "domainRules": rules, "stored": normalize_domain_rules(rules)} for name, rules in ACCEPT]
    reject = []
    for name, rules in REJECT:
        try:
            normalize_domain_rules(rules)
        except Refused:
            reject.append({"name": name, "domainRules": rules})
            continue
        raise AssertionError(f"{name} was accepted")
    stored = {case["name"]: case["stored"] for case in accept}
    assert stored["spelling-normalised"] == [{"match": "*.cdn.example", "protocols": ["udp", "tcp"], "portRanges": [[443, 443]]}]
    assert stored["absent-lists"] == [{"match": "example.org", "protocols": [], "portRanges": []}]

    authorize = []
    for name, override, request, expected in AUTHORIZE:
        config = dict(CONFIG)
        for key, value in (override or {}).items():
            if value is None:
                config.pop(key, None)
            else:
                config[key] = value
        produced = decide(config, request)
        assert produced == expected, (name, produced, expected)
        case = {"name": name, "request": request, "code": expected}
        if override:
            case["config"] = config
        authorize.append(case)
    return {
        "description": "Domain rules of an egress policy: what a server stores and refuses with 400 when the policy "
                       "is saved, and what an egress decides for a flow that carries a name. A case without its own "
                       "config uses the top-level config. See protocol/spec/peer-egress.md, 出口授权模型.",
        "limits": {"rules": MAX_RULES, "portRangesPerRule": MAX_PORT_RANGES, "storedJsonBytes": MAX_RULES_JSON_BYTES},
        "management": {"accept": accept, "reject": reject},
        "config": CONFIG,
        "authorize": authorize,
    }


def main():
    document = build()
    path = VECTORS / "peer-egress-domain-policy-v1.json"
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {path}: accept={len(document['management']['accept'])} reject={len(document['management']['reject'])} "
          f"authorize={len(document['authorize'])}")


if __name__ == "__main__":
    main()
