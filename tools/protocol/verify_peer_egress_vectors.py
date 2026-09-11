"""Independent check of the peer-egress vectors against protocol/spec/peer-egress.md.

Reads the shipped files fresh (no shared code with the generator) and asserts:
  * every frameHex decodes to the declared header fields
  * accept-case IPv4 packets have verifying header and transport checksums
  * control bodies re-encode to exactly the declared canonical bytes
  * declared innerSourceIp / innerDestinationIp match the actual packet
  * every error code used in a vector is documented in the spec table
  * every error code in the spec table is exercised by at least one vector
  * the Windows route fixtures still carry their sampled cases, and each parser behaviour
    they pin is needed by at least one of them
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
windows = json.loads((VECTORS / "peer-egress-windows-routes-v1.json").read_text(encoding="utf-8"))

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

# ---- windows route vector ----------------------------------------------
# The point of this file is that its fixtures came off a real Windows machine. A version of it
# rewritten into plausible-looking strings would still pass every implementation's tests, so the
# sampled count is asserted here rather than left to whoever edits it next.
sampled = [case for section in ("routeFind", "routeShow", "commandErrors")
           for case in windows[section] if case.get("sampled")]
check(len(sampled) >= 10, f"windows: only {len(sampled)} sampled cases left, want at least 10")

on_link = windows["onLinkNextHop"]
check(on_link == "0.0.0.0", f"windows: unexpected on-link next hop {on_link!r}")

# Each of the three readings has to be load-bearing in at least one case, or an implementation
# could drop it and still pass every case in the file.
check(any(case["expect"].get("parsed") and case["expect"]["gateway"] == "" and on_link in case["output"]
          for case in windows["routeFind"]),
      "windows: no find case needs the on-link next hop rewritten to an empty gateway")
check(any(case["expect"].get("parsed") and isinstance(json.loads(case["output"])[0].get("DestinationPrefix"), type(None))
          for case in windows["routeFind"] if case["output"].lstrip().startswith("[{")),
      "windows: no find case has the route behind a leading object, so picking it out is untested")
check(any("(+" in case["expect"]["description"] for case in windows["routeShow"]),
      "windows: no show case carries more than one route, so the count is untested")
check({case["expect"]["failure"] for case in windows["commandErrors"]} >= {"permission-denied", "failed", ""},
      "windows: the error cases do not cover all three classifications")
# An error id that is still not a failure. Without one, treating every non-empty errorId as a
# failure would pass the whole file -- and that reading turns every post-reboot cleanup into noise.
check(any(case["expect"]["failure"] == "" and "errorId" in case["output"]
          for case in windows["commandErrors"]),
      "windows: no error case carries an id that is not a failure")

# An empty gateway means on-link everywhere in this feature. A vector that expected the literal
# 0.0.0.0 back would be asking implementations to install a route pointing at nothing.
for case in windows["routeFind"]:
    check(case["expect"].get("gateway") != on_link,
          f"windows: find case {case['name']} expects the on-link sentinel as a gateway")

# Recompute each show description from the output rather than trusting the generator: the string is
# what an operator reads before deciding whether to clear a prefix, and a wrong prefix in it sends
# them after the wrong route.
for case in windows["routeShow"]:
    routes = []
    try:
        decoded = json.loads(case["output"])
        if isinstance(decoded, list):
            routes = [entry for entry in decoded
                      if isinstance(entry, dict) and isinstance(entry.get("DestinationPrefix"), str)
                      and entry["DestinationPrefix"].strip()]
    except ValueError:
        routes = []
    check(case["expect"]["present"] == bool(routes),
          f"windows: show case {case['name']} disagrees with its own output about a route existing")
    if not routes:
        check(case["expect"]["description"] == "",
              f"windows: show case {case['name']} describes a route it says is absent")
        continue
    check(case["expect"]["description"].startswith(routes[0]["DestinationPrefix"].strip() + " "),
          f"windows: show case {case['name']} describes a prefix other than the one in its output")
    check(("(+{} more)".format(len(routes) - 1) in case["expect"]["description"]) == (len(routes) > 1),
          f"windows: show case {case['name']} miscounts the routes on the prefix")


# ---- windows scripts ----------------------------------------------------
scripts = windows["scripts"]
check(scripts["showAllRoutes"].endswith(
          "Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)"),
      "windows: the whole-table query selects fields beyond the four that are ASCII")
check(windows["outputEncoding"]["consoleCodePage"] != 0,
      "windows: the sampled console code page is gone, and with it the reason for the rule below")

# No script may select a name. The child process writes stdout in the console code page -- 936 on
# the sampling machine -- and in GBK the low byte of a character can be 0x5C, so a Chinese adapter
# name echoed into the JSON can emit a bare backslash and break the document.
for case in scripts["interfaceIndex"]:
    check(case["expect"].endswith("Select-Object InterfaceIndex)"),
          f"windows: interface script {case['name']} selects more than the index")
for group in ("showRoutes", "findRoutes"):
    for case in scripts[group]:
        check("Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)" in case["expect"],
              f"windows: query script {case['name']} selects fields beyond the ASCII four")

# The adapter name is the one argument that cannot be whitelisted, so it is the one place the quote
# escape has to fire. A case list without it would let an implementation drop the escaping.
check(any("''" in case["expect"] for case in scripts["interfaceIndex"]),
      "windows: no interface name in the vector needs its quote escaped")

# Every install and remove has to name the store explicitly. ActiveStore is what keeps these routes
# from outliving a reboot, and a script that left the default in place would install persistent ones.
for group in ("installRoute", "removeRoute"):
    for case in scripts[group]:
        check("-PolicyStore ActiveStore" in case["expect"],
              f"windows: {group} case {case['name']} does not pin the policy store")
for case in scripts["removeRoute"]:
    check("-Confirm:$false" in case["expect"],
          f"windows: remove case {case['name']} would wait for a confirmation nobody can give")

# Nothing that a validator would refuse may appear as an accepted script argument.
for case in scripts["rejectedArguments"]:
    for group in ("showRoutes", "findRoutes"):
        for accepted in scripts[group]:
            values = accepted.get("prefixes") or accepted.get("addresses") or []
            check(case["value"] not in values,
                  f"windows: {case['name']} is both refused and used in {accepted['name']}")

print(f"frame accept={len(frame['accept'])} reject={len(frame['reject'])}")
print(f"rules cases={len(rules['cases'])} configValidation={len(rules['configValidation'])}"
      f" refusedRules={len(rules['refusedRules'])}")
print(f"authz cases={len(authz['cases'])} variants={len(authz['policyVariantCases'])}")
print(f"control egressConfig accept={len(egress_config['accept'])} reject={len(egress_config['reject'])}")
print(f"error codes: {len(table_codes)} documented, {len(used)} exercised")
print(f"windows routes find={len(windows['routeFind'])} show={len(windows['routeShow'])}"
      f" errors={len(windows['commandErrors'])} sampled={len(sampled)}")
print(f"windows scripts show={len(scripts['showRoutes'])} find={len(scripts['findRoutes'])}"
      f" install={len(scripts['installRoute'])} remove={len(scripts['removeRoute'])}"
      f" interface={len(scripts['interfaceIndex'])}"
      f" refused={len(scripts['rejectedArguments'])}")

if failures:
    print(f"\nFAILED ({len(failures)}):")
    for f in failures:
        print("  -", f)
    sys.exit(1)
print("\nall checks passed")
