"""Independent check of the peer-egress vectors against protocol/spec/peer-egress.md.

Reads the shipped files fresh (no shared code with the generator) and asserts:
  * every frameHex decodes to the declared header fields
  * accept-case IPv4 packets have verifying header and transport checksums
  * control bodies re-encode to exactly the declared canonical bytes
  * declared innerSourceIp / innerDestinationIp match the actual packet
  * every error code used in a vector is documented in the spec table
  * every error code in the spec table is exercised by at least one vector
"""
import json
import re
import struct
import ipaddress
import sys
from pathlib import Path

VECTORS = Path("protocol/test-vectors")
SPEC = Path("protocol/spec/peer-egress.md")
failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def ones_complement_sum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return total


def verifies(data):
    return ones_complement_sum(data) == 0xFFFF


frame = json.loads((VECTORS / "peer-egress-frame-v1.json").read_text(encoding="utf-8"))
rules = json.loads((VECTORS / "peer-egress-rules-v1.json").read_text(encoding="utf-8"))
authz = json.loads((VECTORS / "peer-egress-authz-v1.json").read_text(encoding="utf-8"))
control = json.loads((VECTORS / "peer-egress-control-v1.json").read_text(encoding="utf-8"))

# ---- frame vector -------------------------------------------------------
for case in frame["accept"]:
    raw = bytes.fromhex(case["frameHex"])
    name = case["name"]
    check(len(raw) == case["frameLength"], f"{name}: frameLength mismatch")
    check(raw[:5] == b"SPEG1", f"{name}: magic is not SPEG1")
    check(raw[5] == case["type"], f"{name}: type byte mismatch")
    check(raw[6] == case["flags"], f"{name}: flags byte mismatch")
    check(raw[7] == 0, f"{name}: reserved byte must be zero")
    body = raw[8:]

    if case["type"] == 1:
        check(body.hex() == case["innerPacketHex"], f"{name}: innerPacketHex mismatch")
        check(body[0] >> 4 == 4, f"{name}: not an IPv4 packet")
        ihl = (body[0] & 0x0F) * 4
        total_len = struct.unpack("!H", body[2:4])[0]
        check(total_len == len(body), f"{name}: IPv4 totalLength {total_len} != body {len(body)}")
        check(verifies(body[:ihl]), f"{name}: IPv4 header checksum does not verify")
        src = str(ipaddress.IPv4Address(body[12:16]))
        dst = str(ipaddress.IPv4Address(body[16:20]))
        check(src == case["innerSourceIp"], f"{name}: declared source {case['innerSourceIp']} != actual {src}")
        check(dst == case["innerDestinationIp"], f"{name}: declared destination {case['innerDestinationIp']} != actual {dst}")

        proto = body[9]
        segment = body[ihl:]
        pseudo = body[12:20] + struct.pack("!BBH", 0, proto, len(segment))
        check(verifies(pseudo + segment), f"{name}: transport checksum does not verify")
        expected_proto = {"tcp": 6, "udp": 17}[case["innerProtocol"]]
        check(proto == expected_proto, f"{name}: protocol byte {proto} != declared {case['innerProtocol']}")
        sport, dport = struct.unpack("!HH", segment[:4])
        check(sport == case["innerSourcePort"], f"{name}: source port mismatch")
        check(dport == case["innerDestinationPort"], f"{name}: destination port mismatch")

    elif case["type"] == 2:
        canonical = json.dumps(case["controlJson"], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        check(canonical == body, f"{name}: control body is not the canonical encoding of controlJson")
        check(canonical.hex() == case["controlCanonicalUtf8Hex"], f"{name}: controlCanonicalUtf8Hex mismatch")
        check(b" " not in body, f"{name}: canonical control JSON must not contain whitespace")

for case in frame["reject"]:
    try:
        bytes.fromhex(case["frameHex"])
    except ValueError:
        failures.append(f"{case['name']}: frameHex is not valid hex")

# ---- rules vector -------------------------------------------------------
# The rule list carries refused rules on purpose, and a refused rule steers nothing. The skip set
# is read from the file rather than re-derived here, so this stays an independent check of the
# cases rather than a second copy of the generator's validator.
REFUSED_INDEXES = {entry["index"] for entry in rules["refusedRules"]}
check(bool(REFUSED_INDEXES), "rules: refusedRules must not be empty")
for entry in rules["refusedRules"]:
    check(0 <= entry["index"] < len(rules["rules"]),
          f"rules: refusedRules names rule {entry['index']}, which does not exist")


def match(destination, rule_list, skip=REFUSED_INDEXES):
    addr = ipaddress.IPv4Address(destination)
    best = None
    for rule in rule_list:
        if rule["index"] in skip:
            continue
        net = ipaddress.IPv4Network(rule["match"])
        if addr in net and (best is None or net.prefixlen > ipaddress.IPv4Network(best["match"]).prefixlen):
            best = rule
    return best


# A refused rule that no case would have picked proves nothing, and the two cases that do pick one
# could be weakened later without anything noticing. So the skip has to be load-bearing here.
check(any(
    (unfiltered := match(case["destination"], rules["rules"], skip=set())) is not None
    and unfiltered["index"] in REFUSED_INDEXES
    for case in rules["cases"]
), "rules: no case would have matched a refused rule, so the skip is untested")

for case in rules["cases"]:
    best = match(case["destination"], rules["rules"])
    expect = case["expect"]
    if best is None:
        check(expect["action"] == "direct" and expect["matchedRuleIndex"] is None,
              f"rules/{case['name']}: unmatched destination must fall through to direct")
    else:
        check(best["index"] == expect["matchedRuleIndex"],
              f"rules/{case['name']}: expected rule {expect['matchedRuleIndex']}, matcher picked {best['index']}")
        check(best["action"] == expect["action"], f"rules/{case['name']}: action mismatch")

for rule in rules["rules"]:
    net = ipaddress.IPv4Network(rule["match"])
    check(str(net) == rule["match"], f"rules: {rule['match']} is not in canonical form")
    check(not net.overlaps(ipaddress.IPv4Network(rules["meshCidr"])),
          f"rules: {rule['match']} overlaps the mesh CIDR")

# ---- control vector -----------------------------------------------------
# Checked without re-implementing the decoder: what matters is that the cases still exercise the
# two things a JSON library would otherwise decide on the protocol's behalf.
egress_config = control["egressConfig"]
check(bool(egress_config["accept"]) and bool(egress_config["reject"]),
      "control: egressConfig needs both accept and reject cases")

normalised = False
absent_scope = False
for case in egress_config["accept"]:
    name = case["name"]
    message = json.loads(case["message"])
    check(message.get("type") == "egress-config",
          f"control/{name}: an accept case must carry type egress-config")
    decoded_scope = case["expect"]["policy"]["scope"]
    check(decoded_scope in ("", "PUBLIC", "LAN"),
          f"control/{name}: decoded scope {decoded_scope!r} is not one the judgment layer compares against")
    check(decoded_scope == decoded_scope.strip().upper(),
          f"control/{name}: decoded scope is not normalised")
    raw_scope = message.get("scope")
    if raw_scope is None:
        absent_scope = True
        check(decoded_scope == "",
              f"control/{name}: an absent scope must decode to empty, never to the permissive value")
    elif raw_scope != decoded_scope:
        normalised = True
    check(case["expect"]["revision"] == message.get("revision", 0),
          f"control/{name}: revision must be carried through unchanged")

# Without these the two behaviours could be dropped from the decoders and every case would still
# pass, because no case would depend on them.
check(normalised, "control: no accept case has a scope that needs normalising")
check(absent_scope, "control: no accept case omits scope, so the deny default is untested")

for case in egress_config["reject"]:
    name = case["name"]
    try:
        message = json.loads(case["message"])
    except ValueError:
        continue
    check(not isinstance(message, dict) or message.get("type") != "egress-config",
          f"control/{name}: a reject case must not be a well-formed egress-config")

# ---- error code coverage ------------------------------------------------
spec_text = SPEC.read_text(encoding="utf-8")
table_codes = set(re.findall(r"^\| `(EGRESS_[A-Z0-9_]+)` \|", spec_text, re.MULTILINE))

used = set()
for case in frame["reject"]:
    used.add(case["code"])
for case in rules["configValidation"]:
    used.add(case["code"])
for entry in rules["refusedRules"]:
    used.add(entry["code"])
for case in authz["cases"] + authz["policyVariantCases"]:
    used.add(case["expect"]["code"])

undocumented = used - table_codes
uncovered = table_codes - used
check(not undocumented, f"codes used in vectors but missing from the spec table: {sorted(undocumented)}")
check(not uncovered, f"codes in the spec table with no vector case: {sorted(uncovered)}")

# ---- authz order sanity -------------------------------------------------
order = authz["evaluationOrder"]
check(order[:5] == ["hop", "enabled", "peerAcl", "consumer", "forcedDeny"],
      "authz: forcedDeny must be evaluated before scope and destination rules")
check(order.index("forcedDeny") < order.index("destination"),
      "authz: a broad destination rule must never be able to pre-empt the forced-deny list")

print(f"frame accept={len(frame['accept'])} reject={len(frame['reject'])}")
print(f"rules cases={len(rules['cases'])} configValidation={len(rules['configValidation'])}"
      f" refusedRules={len(rules['refusedRules'])}")
print(f"authz cases={len(authz['cases'])} variants={len(authz['policyVariantCases'])}")
print(f"control egressConfig accept={len(egress_config['accept'])} reject={len(egress_config['reject'])}")
print(f"error codes: {len(table_codes)} documented, {len(used)} exercised")

if failures:
    print(f"\nFAILED ({len(failures)}):")
    for f in failures:
        print("  -", f)
    sys.exit(1)
print("\nall checks passed")
