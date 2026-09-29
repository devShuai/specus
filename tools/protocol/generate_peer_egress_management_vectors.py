"""Generate peer-egress-management-v1.json: what a server stores for the destination rules of an
egress policy saved through the management API, and what it refuses.

An egress reads a destination rule strictly (protocol/spec/peer-egress.md): a CIDR it cannot parse,
a protocol other than tcp or udp, or a malformed port range never matches. Until this vector the
servers stored such rules as given, so a typo became a rule that silently did nothing. The reference
here is what all four servers now do: normalise what is only spelling, refuse what is wrong.
"""
import ipaddress
import json
import re
from pathlib import Path

VECTORS = Path("protocol/test-vectors")
MAX_RULES = 64
MAX_PORT_RANGES = 32
MAX_RULES_JSON_BYTES = 4096
OCTET = re.compile(r"^(0|[1-9][0-9]{0,2})$")


class Refused(Exception):
    pass


def valid_cidr(text):
    """The egress's parser: dotted decimal without leading zeros, an optional /0-32, host bits zero.
    A bare address is a /32."""
    address, _, prefix = text.partition("/")
    parts = address.split(".")
    if len(parts) != 4 or not all(OCTET.match(part) and int(part) <= 255 for part in parts):
        return False
    if "/" in text:
        if not re.match(r"^(0|[1-9][0-9]?)$", prefix) or int(prefix) > 32:
            return False
    else:
        prefix = "32"
    try:
        ipaddress.IPv4Network(f"{address}/{prefix}", strict=True)
    except ValueError:
        return False
    return True


def normalize_rules(rules):
    """The rules as stored, or Refused. The CIDR is kept as written after trimming; protocols are
    trimmed, lowercased and de-duplicated in order; an absent list is an empty one."""
    if len(rules) > MAX_RULES:
        raise Refused("too many rules")
    stored = []
    for rule in rules:
        cidr = (rule.get("cidr") or "").strip()
        if not valid_cidr(cidr):
            raise Refused("cidr")
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
        stored.append({"cidr": cidr, "protocols": protocols, "portRanges": ranges})
    if len(json.dumps(stored, separators=(",", ":"))) > MAX_RULES_JSON_BYTES:
        raise Refused("too large")
    return stored


def rule(cidr="203.0.113.0/24", protocols=("tcp",), ranges=((443, 443),)):
    return {"cidr": cidr, "protocols": list(protocols), "portRanges": [list(pair) for pair in ranges]}


ACCEPT = [
    ("cidr", [rule()]),
    ("bare-address", [rule("203.0.113.7", ("udp",), ((53, 53),))]),
    ("whole-internet", [rule("0.0.0.0/0", ("tcp", "udp"), ((1, 65535),))]),
    ("spelling-normalised", [{"cidr": " 10.0.0.0/8 ", "protocols": [" TCP ", "udp", "tcp"], "portRanges": [[80, 80], [8000, 8100]]}]),
    ("deny-all-kept", [rule(protocols=(), ranges=())]),
    ("absent-lists", [{"cidr": "198.51.100.0/24"}]),
    ("no-rules", []),
    ("port-zero-allowed", [rule(ranges=((0, 0),))]),
    # Short rules, so the count is what is tested and not the stored size.
    ("most-rules", [rule(f"10.{index}.0.0/16", (), ()) for index in range(MAX_RULES)]),
    ("most-port-ranges", [rule(ranges=tuple((port, port) for port in range(1000, 1000 + MAX_PORT_RANGES)))]),
]

REJECT = [
    ("host-bits-set", [rule("203.0.113.1/24")]),
    ("leading-zero", [rule("203.0.113.07")]),
    ("prefix-too-long", [rule("10.0.0.0/33")]),
    ("prefix-leading-zero", [rule("10.0.0.0/08")]),
    ("ipv6", [rule("2001:db8::/32")]),
    ("domain", [rule("example.com")]),
    ("empty-cidr", [rule("")]),
    ("missing-cidr", [{"protocols": ["tcp"], "portRanges": [[443, 443]]}]),
    ("unknown-protocol", [rule(protocols=("icmp",))]),
    ("reversed-range", [rule(ranges=((443, 80),))]),
    ("port-above-range", [rule(ranges=((1, 65536),))]),
    ("negative-port", [rule(ranges=((-1, 80),))]),
    ("single-port-not-a-pair", [{"cidr": "203.0.113.0/24", "protocols": ["tcp"], "portRanges": [[443]]}]),
    ("too-many-rules", [rule(f"10.{index}.0.0/16", (), ()) for index in range(MAX_RULES + 1)]),
    ("too-many-port-ranges", [rule(ranges=tuple((port, port) for port in range(1000, 1000 + MAX_PORT_RANGES + 1)))]),
    ("too-large", [rule(f"10.{index}.0.0/16", ("tcp", "udp"), tuple((port, port + 1) for port in range(10000, 10020, 2)))
                   for index in range(40)]),
]


def build():
    accept = []
    for name, rules in ACCEPT:
        accept.append({"name": name, "destinationRules": rules, "stored": normalize_rules(rules)})
    reject = []
    for name, rules in REJECT:
        try:
            normalize_rules(rules)
        except Refused:
            reject.append({"name": name, "destinationRules": rules})
            continue
        raise AssertionError(f"{name} was accepted")
    # Hand-checked, so the reference itself is pinned.
    by_name = {case["name"]: case["stored"] for case in accept}
    assert by_name["spelling-normalised"] == [{"cidr": "10.0.0.0/8", "protocols": ["tcp", "udp"], "portRanges": [[80, 80], [8000, 8100]]}]
    assert by_name["absent-lists"] == [{"cidr": "198.51.100.0/24", "protocols": [], "portRanges": []}]
    assert by_name["bare-address"][0]["cidr"] == "203.0.113.7"
    return {
        "description": "Destination rules of an egress policy saved through the management API: what the server "
                       "stores and what it refuses with 400. See protocol/spec/peer-egress.md.",
        "limits": {"rules": MAX_RULES, "portRangesPerRule": MAX_PORT_RANGES, "storedJsonBytes": MAX_RULES_JSON_BYTES},
        "accept": accept,
        "reject": reject,
    }


def main():
    document = build()
    path = VECTORS / "peer-egress-management-v1.json"
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {path}: accept={len(document['accept'])} reject={len(document['reject'])}")


if __name__ == "__main__":
    main()
