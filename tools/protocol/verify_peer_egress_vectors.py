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
macos = json.loads((VECTORS / "peer-egress-macos-routes-v1.json").read_text(encoding="utf-8"))

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

# ---- macos route vector -------------------------------------------------
#
# The rules below are the ones that stop this section decaying into something that passes without
# pinning anything. Each of them corresponds to a capture that changed the design.

macos_sampled = [case for case in macos["routeGet"] + macos["commandResults"]
                 if case.get("sampled")]
check(len(macos_sampled) >= 20,
      f"macos: only {len(macos_sampled)} sampled cases left, want at least 20")
check(all(case.get("sampled") for case in macos["commandResults"]),
      "macos: a command result stopped being sampled output, so it is now somebody's guess")

# `route` exits 0 when it fails. Without a case like this, an implementation could read the exit
# status and pass the whole file.
check(any(case["exit"] == 0 and case["expect"]["failure"] for case in macos["commandResults"]),
      "macos: no failure exits 0, so nothing stops an implementation trusting the exit status")
check(any(case["exit"] == 0 and not case["expect"]["failure"]
          for case in macos["commandResults"]),
      "macos: no success exits 0 either, so the exit status carries information after all")
# And the permission failure has to be the one with nothing on stdout, which is what forces stderr
# to be read at all.
denied = [case for case in macos["commandResults"]
          if case["expect"]["failure"] == "permission-denied"]
check(denied, "macos: no permission failure left")
check(any(not case["stdout"].strip() and case["stderr"].strip() for case in denied),
      "macos: the permission failure now says something on stdout, so reading stderr is untested")
check({case["expect"]["failure"] for case in macos["commandResults"]}
      >= {"permission-denied", "failed", ""},
      "macos: the command results do not cover all three classifications")
check(any(case["expect"]["failure"] == "" and "not in table" in case["stdout"]
          for case in macos["commandResults"]),
      "macos: nothing pins a removal of something already gone counting as success")

# The malformed prefix that `route` accepts, and what it actually installed.
malformed = macos["malformedPrefix"]
check(malformed.get("sampled"), "macos: the malformed-prefix evidence is no longer sampled")
check(malformed["exit"] == 0,
      "macos: the malformed add now fails, so the argument check is not the only defence")
check(malformed["installedPrefix"] not in malformed["stdout"],
      "macos: the output names the prefix it installed after all, so the evidence is stale")
check(malformed["installedPrefix"] in malformed["tableAfter"].replace("128.0/1", "128.0.0.0/1")
      or "128.0/1" in malformed["tableAfter"],
      "macos: the table no longer shows what the malformed add installed")
refused_values = {case["value"] for case in macos["commands"]["rejectedArguments"]}
check("203.0.113.0/33" in refused_values,
      "macos: the argument that installs half the internet is no longer refused")
check(any(value.startswith("010.") for value in refused_values),
      "macos: a leading zero is no longer refused, and inet_aton reads it as octal")

# The kernel-generated filter has to change an answer rather than only a count.
presence = {(case["prefix"], case["table"]): case["expect"] for case in
            macos["conflictFromTable"]["cases"]}
broadcast = presence.get(("192.168.64.255/32", "netstat-rn-inet-after"))
check(broadcast is not None and not broadcast["present"],
      "macos: nothing pins kernel-generated entries being left out of the conflict answer")
check(any(case["expect"]["present"] and "(+" in case["expect"]["existing"]
          for case in macos["conflictFromTable"]["cases"]),
      "macos: no conflict case reports a route count")
exact = presence.get(("0.0.0.0/1", "netstat-rn-inet-after"))
check(exact is not None and not exact["present"],
      "macos: nothing pins the prefix comparison being exact rather than longest-prefix")

# The IPv6 section has default routes of its own. The gate is what keeps them out.
both = presence.get(("0.0.0.0/0", "netstat-rn-after"))
check(both is not None and both["present"] and "(+" not in both["existing"],
      "macos: nothing pins the IPv6 section being left out of the table")
check("Internet6:" in macos["bothFamilies"]["stdout"],
      "macos: the two-family fixture no longer carries an IPv6 section to leave out")
check(macos["bothFamilies"]["expect"]["prefixes"] == macos["table"]["expect"]["prefixes"],
      "macos: the two-family table is expected to read differently than the IPv4-only one")

# Normalisation has to be exercised on both the abbreviated and the masked side.
normalise = {case["input"]: case["expect"] for case in macos["normalisePrefix"]["cases"]}
check(normalise.get("default") == "0.0.0.0/0", "macos: the default route no longer normalises")
check(normalise.get("203.0.113") == "203.0.113.0/24",
      "macos: nothing pins the implied prefix length")
check(normalise.get("100.64/10") == "100.64.0.0/10",
      "macos: nothing pins a destination with both an abbreviation and a length")
check(normalise.get("10.1.2.3/8") == "10.0.0.0/8",
      "macos: nothing pins the address being masked by its length")
check(any(value == "" and key.strip() and ":" in key for key in normalise
          for value in [normalise[key]]),
      "macos: no IPv6 destination is rejected, so the family check is untested")

# The commands themselves, not just their output.
commands = macos["commands"]
check(commands["showTable"] == ["netstat", "-rn", "-f", "inet"],
      "macos: the table query changed shape")
for entry in commands["installInterface"]:
    check(entry["argv"][:4] == ["route", "-n", "add", "-net"],
          f"macos: install {entry['prefix']} no longer adds a net")
    check("-interface" in entry["argv"],
          f"macos: install {entry['prefix']} no longer names an interface")
for entry in commands["remove"]:
    check(entry["argv"] == ["route", "-n", "delete", "-net", entry["prefix"]],
          f"macos: remove {entry['prefix']} changed shape")
    check("-ifscope" not in entry["argv"],
          f"macos: remove {entry['prefix']} scopes the withdrawal, which would leave ours behind")
for group in ("findRoute", "installInterface", "installGateway", "remove"):
    for entry in commands[group]:
        check("-n" in entry["argv"],
              f"macos: {group} lost -n, so a name lookup can hold the process")

# Nothing a validator refuses may appear as an accepted argument.
#
# Compared against the values an entry declares rather than against its whole argv, because some of
# the refused values are option names: `-net` is refused as a prefix precisely because `route` would
# read it as the option it also is.
for case in commands["rejectedArguments"]:
    for group in ("findRoute", "installInterface", "installGateway", "remove"):
        for accepted in commands[group]:
            values = {accepted.get(field)
                      for field in ("prefix", "interface", "gateway", "address")}
            check(case["value"] not in values,
                  f"macos: {case['value']!r} is both refused and used in {group}")

# And the two measurements that justify design decisions rather than describing behaviour.
check(macos["timings"]["cache"] is False,
      "macos: the vector now expects a cached table, which the measurement does not support")
check(macos["timings"]["netstatMedianMs"] < 100,
      "macos: the table read is no longer cheap, so not caching needs rethinking")
check(macos["localisation"]["identical"] is True and macos["localisation"].get("sampled"),
      "macos: the evidence that the output is not localised is gone")
check(macos["tunNeedsAddress"]["withoutAddress"]["stderr"].strip()
      and not macos["tunNeedsAddress"]["withAddress"]["stderr"].strip(),
      "macos: the evidence that a TUN needs an address before a route can point at it is gone")

# ---- socket binding vector ----------------------------------------------
#
# Recomputed from the raw inputs rather than trusted, and each behaviour that decides an answer has
# to still be the thing deciding at least one case.

def binding_select(routes, tunnel, destination):
    address = ipaddress.IPv4Address(destination)
    best, best_key = None, None
    for candidate in routes:
        if not candidate["usable"] or (tunnel and candidate["interface"] == tunnel):
            continue
        network = ipaddress.IPv4Network(candidate["prefix"])
        if address in network:
            key = (network.prefixlen, -candidate["metric"])
            if best_key is None or key > best_key:
                best, best_key = candidate["interface"], key
    return best


def binding_without(routes, tunnel, destination, change):
    return binding_select([change(dict(r)) for r in routes], tunnel, destination)


binding = json.loads((VECTORS / "peer-egress-socket-binding-v1.json").read_text(encoding="utf-8"))
select_cases = binding["select"]["cases"]
for case in select_cases:
    check(binding_select(case["routes"], case["tunnel"], case["destination"])
          == case["expect"]["interface"], f"binding select {case['name']}: expectation is wrong")

check(any(case["expect"]["interface"] is not None
          and binding_select(case["routes"], "", case["destination"]) != case["expect"]["interface"]
          for case in select_cases),
      "binding: no case where leaving the tunnel out changes the answer")
check(any(case["expect"]["interface"] is None for case in select_cases),
      "binding: no case refuses the dial, so failing closed is untested")
check(any(binding_without(case["routes"], case["tunnel"], case["destination"],
                          lambda r: {**r, "usable": True}) != case["expect"]["interface"]
          for case in select_cases),
      "binding: no case where an unusable route would otherwise win")
check(any(binding_without(case["routes"], case["tunnel"], case["destination"],
                          lambda r: {**r, "metric": 0}) != case["expect"]["interface"]
          for case in select_cases),
      "binding: no case where the metric decides")
check(any(case["tunnel"] and any(r["interface"].startswith(case["tunnel"])
                                 and r["interface"] != case["tunnel"] for r in case["routes"])
          for case in select_cases),
      "binding: nothing pins the tunnel comparison being exact")


def binding_table(hex_text, size, family_offset, family_width):
    raw = bytes.fromhex(hex_text)
    if len(raw) < 8:
        return None
    count = struct.unpack_from("<I", raw, 0)[0]
    if len(raw) < 8 + count * size:
        return None
    return [raw[8 + i * size: 8 + (i + 1) * size] for i in range(count)]


layout = binding["windows"]["layout"]
forward_layout = layout["forwardRow"]
interface_layout = layout["interfaceRow"]
check(layout["tableHeader"] == 8 and forward_layout["size"] == 104 and interface_layout["size"] == 168,
      "binding: the Windows row sizes changed, and they were measured, not chosen")
for table in binding["windows"]["forwardTables"]:
    rows = binding_table(table["hex"], forward_layout["size"], forward_layout["prefixFamily"], 2)
    check((rows is not None) == table["expect"]["parsed"],
          f"binding forward table {table['name']}: parsed flag is wrong")
    read = []
    for row in rows or []:
        if struct.unpack_from("<H", row, forward_layout["prefixFamily"])[0] != 2:
            continue
        length = row[forward_layout["prefixLength"]]
        if length > 32:
            continue
        network = ipaddress.IPv4Network(
            (bytes(row[forward_layout["prefixAddress"]:forward_layout["prefixAddress"] + 4]), length),
            strict=False)
        next_hop = ""
        if struct.unpack_from("<H", row, forward_layout["nextHopFamily"])[0] == 2:
            next_hop = str(ipaddress.IPv4Address(
                bytes(row[forward_layout["nextHopAddress"]:forward_layout["nextHopAddress"] + 4])))
        read.append({"interfaceIndex": struct.unpack_from("<I", row, forward_layout["interfaceIndex"])[0],
                     "prefix": str(network),
                     "nextHop": next_hop,
                     "metric": struct.unpack_from("<I", row, forward_layout["metric"])[0]})
    check(read == table["expect"]["rows"], f"binding forward table {table['name']}: rows are wrong")
for table in binding["windows"]["interfaceTables"]:
    rows = binding_table(table["hex"], interface_layout["size"], interface_layout["family"], 2)
    check((rows is not None) == table["expect"]["parsed"],
          f"binding interface table {table['name']}: parsed flag is wrong")
    read = []
    for row in rows or []:
        if struct.unpack_from("<H", row, interface_layout["family"])[0] != 2:
            continue
        read.append({"interfaceIndex": struct.unpack_from("<I", row, interface_layout["interfaceIndex"])[0],
                     "metric": struct.unpack_from("<I", row, interface_layout["metric"])[0],
                     "connected": row[interface_layout["connected"]] != 0,
                     "disableDefaultRoutes": row[interface_layout["disableDefaultRoutes"]] != 0})
    check(read == table["expect"]["rows"], f"binding interface table {table['name']}: rows are wrong")
check(any(not table["expect"]["parsed"] for table in binding["windows"]["forwardTables"]),
      "binding: no truncated forward table, so reading past the buffer is untested")

windows_routes = binding["windows"]["routes"]["expect"]
for case in binding["windows"]["cases"]:
    check(binding_select(windows_routes, case["tunnel"], case["destination"])
          == case["expect"]["interface"], f"binding windows {case['name']}: expectation is wrong")
default_ruled_out = ({r["interface"] for r in windows_routes
                      if r["prefix"] == "0.0.0.0/0" and not r["usable"]}
                     & {r["interface"] for r in windows_routes
                        if r["prefix"] != "0.0.0.0/0" and r["usable"]})
check(default_ruled_out and any(case["expect"]["interface"] in default_ruled_out
                                for case in binding["windows"]["cases"]),
      "binding: nothing pins DisableDefaultRoutes ruling out a default route while leaving the "
      "interface's other routes usable")

macos_binding_routes = {entry["table"]: entry["expect"] for entry in binding["macos"]["routes"]}
for entry in binding["macos"]["routes"]:
    check(binding["macos"]["tables"][entry["table"]] == macos[entry["table"]]["stdout"],
          f"binding macos table {entry['table']}: no longer the sampled capture")
for case in binding["macos"]["cases"]:
    check(binding_select(macos_binding_routes[case["table"]], case["tunnel"], case["destination"])
          == case["expect"]["interface"], f"binding macos {case['name']}: expectation is wrong")
check(any(not r["usable"] for routes in macos_binding_routes.values() for r in routes),
      "binding: no scoped route in the macOS tables")

# Linux: re-read the sampled main tables here, without the generator's parser.
def binding_linux_routes(text):
    rows, last, deviceless = [], None, []
    for line in text.split("\n"):
        if not line.strip():
            continue
        words = line.split()
        if line[0] in " \t":
            if words[0] == "nexthop" and last is not None and last["interface"] == "":
                pairs = dict(zip(words[1::2], words[2::2]))
                if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", pairs.get("via", "")):
                    last["gateway"] = pairs["via"]
                last["interface"] = pairs.get("dev", "")
            continue
        last = None
        nowhere = words[0] in ("blackhole", "unreachable", "prohibit", "throw")
        if words[0] in ("local", "broadcast", "anycast", "multicast", "nat"):
            continue
        if nowhere:
            words = words[1:]
        destination = "0.0.0.0/0" if words[0] == "default" else words[0]
        if "/" not in destination:
            destination += "/32"
        entry = {"prefix": str(ipaddress.IPv4Network(destination, strict=False)), "interface": "",
                 "gateway": "", "metric": 0, "usable": "dead" not in words}
        for index in range(1, len(words) - 1):
            if words[index] == "via" and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", words[index + 1]):
                entry["gateway"] = words[index + 1]
            if words[index] == "dev":
                entry["interface"] = words[index + 1]
            if words[index] == "metric":
                entry["metric"] = int(words[index + 1])
        if nowhere:
            entry["interface"], entry["gateway"] = "", ""
        elif entry["interface"] == "":
            last = entry
            deviceless.append(entry)
        rows.append(entry)
    for entry in deviceless:
        if entry["interface"] == "":
            entry["usable"] = False
    return rows


linux_binding = binding["linux"]
for entry in linux_binding["routes"]:
    check(linux_binding["tables"][entry["table"]] == linux_binding["captures"][entry["table"]]["stdout"],
          f"binding linux table {entry['table']}: no longer the sampled capture")
    check(binding_linux_routes(linux_binding["tables"][entry["table"]]) == entry["expect"],
          f"binding linux table {entry['table']}: rows are wrong")
covered = [capture for name, capture in linux_binding["captures"].items() if name.startswith("get-covered")]
check(covered and all(capture["exit"] == 0 and " dev specus0 " in capture["stdout"] for capture in covered),
      "binding: the evidence that `ip route get` answers with the tunnel is gone")
check("\tnexthop " in linux_binding["tables"]["show-rich"],
      "binding: the sampled Linux table no longer has a multipath route")

hop_tables = {"linux": {e["table"]: e["expect"] for e in linux_binding["routes"]},
              "macos": macos_binding_routes,
              "windows": {"typical": windows_routes}}


def binding_hop(routes, tunnel, destination, owned):
    kept = [r for r in routes if r["prefix"] not in set(owned)]
    address = ipaddress.IPv4Address(destination)
    best, best_key = None, None
    for candidate in kept:
        if not candidate["usable"] or (tunnel and candidate["interface"] == tunnel):
            continue
        network = ipaddress.IPv4Network(candidate["prefix"])
        if address in network:
            key = (network.prefixlen, -candidate["metric"])
            if best_key is None or key > best_key:
                best, best_key = candidate, key
    if best is None or best["interface"] == "":
        return None
    return {"interface": best["interface"], "gateway": best["gateway"]}


hop_cases = binding["hops"]["cases"]
for case in hop_cases:
    routes = case["routes"] if case["platform"] == "inline" else hop_tables[case["platform"]][case["table"]]
    case["_routes"] = routes
    check(binding_hop(routes, case["tunnel"], case["destination"], case["owned"]) == case["expect"]["hop"],
          f"binding hop {case['name']}: expectation is wrong")
check(any(case["owned"] and binding_hop(case["_routes"], case["tunnel"], case["destination"], [])
          != case["expect"]["hop"] for case in hop_cases),
      "binding: no hop case where leaving an owned bypass out changes the answer")
check(any(case["expect"]["hop"] is None and any(
          r["interface"] == "" and r["usable"] for r in case["_routes"]) for case in hop_cases),
      "binding: no hop case where a route leading nowhere decides")
check(any(case["expect"]["hop"] is not None and case["expect"]["hop"]["gateway"] == ""
          for case in hop_cases),
      "binding: no hop case with an on-link answer")
for platform in ("linux", "macos", "windows"):
    check(any(case["platform"] == platform and case["tunnel"] and case["expect"]["hop"] is not None
              and binding_hop(case["_routes"], "", case["destination"], case["owned"]) != case["expect"]["hop"]
              for case in hop_cases),
          f"binding: no {platform} hop case where leaving the tunnel out changes the answer")

# Drift: the consumer's own routes after a network change, restated independently of the
# generator's function. What matters is the policy -- a tunnel route on another interface is a
# conflict rather than something to take back, a bypass follows the hop the table would choose
# now with the owned prefixes left out -- so each of those has to be exercised by some case.
def binding_drift(owned, routes, tunnel):
    prefixes = [o["cidr"] for o in owned]
    found = []
    for entry in owned:
        rows = [r for r in routes if r["prefix"] == entry["cidr"]]
        if entry["kind"] == "tun":
            if not any(r["interface"] == tunnel for r in rows):
                found.append((entry["cidr"], "moved" if rows else "missing", "conflict" if rows else "reinstall"))
            continue
        hop = binding_hop(routes, tunnel, entry["cidr"][:-3], prefixes)
        present = [r for r in rows if r["interface"] != tunnel]
        if not present:
            found.append((entry["cidr"], "missing", "reinstall"))
        elif hop is not None and (present[0]["interface"], present[0]["gateway"]) != (hop["interface"], hop["gateway"]):
            found.append((entry["cidr"], "moved", "reinstall"))
    return found


drift_cases = binding["drift"]["cases"]
drift_seen = set()
for case in drift_cases:
    routes = case["routes"] if case["platform"] == "inline" else hop_tables[case["platform"]][case["table"]]
    case["_routes"] = routes
    for entry in case["owned"]:
        check(entry["kind"] in ("tun", "bypass"), f"binding drift {case['name']}: unknown kind")
        check(entry["kind"] != "bypass" or entry["cidr"].endswith("/32"),
              f"binding drift {case['name']}: a bypass wider than /32")
    produced = [(d["cidr"], d["reason"], d["action"]) for d in case["expect"]]
    check(binding_drift(case["owned"], routes, case["tunnel"]) == produced,
          f"binding drift {case['name']}: expectation is wrong")
    for entry in case["expect"]:
        check(entry["cidr"] in {o["cidr"] for o in case["owned"]},
              f"binding drift {case['name']}: reports a route it does not own")
        drift_seen.add((entry["reason"], entry["action"]))
    if not case["expect"]:
        drift_seen.add(("none", "none"))
for needed in (("missing", "reinstall"), ("moved", "reinstall"), ("moved", "conflict"), ("none", "none")):
    check(needed in drift_seen, f"binding: no drift case ends in {needed}")
check(any(entry["kind"] == "bypass"
          and binding_hop(case["_routes"], case["tunnel"], entry["cidr"][:-3], [])
          != binding_hop(case["_routes"], case["tunnel"], entry["cidr"][:-3],
                         [o["cidr"] for o in case["owned"]])
          for case in drift_cases for entry in case["owned"]),
      "binding: no drift case where leaving the owned bypass out changes the hop it is compared with")
check(any(case["platform"] != "inline" and case["owned"] and not case["expect"] for case in drift_cases),
      "binding: no drift case where a sampled table carries everything owned")
check(any(case["platform"] != "inline" and case["expect"] for case in drift_cases),
      "binding: no drift case where a sampled table has lost an owned route")

options = binding["socketOptions"]
check(options["windows"]["name"] == 31 and options["windows"]["byteOrder"] == "network",
      "binding: IP_UNICAST_IF changed shape")
check(options["macos"]["name"] == 25 and options["macos"]["byteOrder"] == "host",
      "binding: IP_BOUND_IF changed shape")
for case in options["windows"]["cases"]:
    check(bytes.fromhex(case["hex"]) == struct.pack(">I", case["index"]),
          f"binding: IP_UNICAST_IF {case['index']} is not in network order")
for case in options["macos"]["cases"]:
    check(bytes.fromhex(case["hex"]) == struct.pack("<I", case["index"]),
          f"binding: IP_BOUND_IF {case['index']} is not in host order")
check(any(struct.pack(">I", c["index"]) != struct.pack("<I", c["index"])
          for c in options["windows"]["cases"]),
      "binding: every Windows option case reads the same in both byte orders")

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
print(f"macos routes get={len(macos['routeGet'])} normalise={len(macos['normalisePrefix']['cases'])}"
      f" conflict={len(macos['conflictFromTable']['cases'])}"
      f" results={len(macos['commandResults'])}"
      f" refused={len(macos['commands']['rejectedArguments'])}"
      f" sampled={len(macos_sampled)}")
# ---- failure vector -----------------------------------------------------
# What the consumer writes back into the TUN. Checked from the packet bytes up: every expected
# packet has to be a well-formed IPv4 packet with verifying checksums, the reset has to sit where
# RFC 793 and RFC 5961 say a stack accepts it, and the ICMP has to quote the datagram it answers.
failure = json.loads((VECTORS / "peer-egress-failure-v1.json").read_text(encoding="utf-8"))


def failure_tcp(packet):
    ihl = (packet[0] & 0x0F) * 4
    check(packet[0] == 0x45 and packet[9] == 6 and verifies(packet[:20]), "failure: not a checksummed IPv4/TCP packet")
    segment = packet[ihl:struct.unpack("!H", packet[2:4])[0]]
    pseudo = packet[12:20] + struct.pack("!BBH", 0, 6, len(segment))
    check(verifies(pseudo + segment), "failure: TCP checksum does not verify")
    sport, dport, seq, ack, offset, flags, window = struct.unpack("!HHIIBBH", segment[:16])
    return {"src": packet[12:16], "dst": packet[16:20], "sport": sport, "dport": dport, "seq": seq,
            "ack": ack, "flags": flags, "window": window, "payload": segment[(offset >> 4) * 4:]}


for case in failure["resetOnPurge"]["cases"]:
    reset = failure_tcp(bytes.fromhex(case["expect"]["packetHex"]))
    check(reset["src"] == ipaddress.IPv4Address(case["remoteIp"]).packed
          and reset["dst"] == ipaddress.IPv4Address(case["consumerIp"]).packed,
          f"failure purge {case['name']}: the reset does not travel from the remote to the application")
    check(reset["sport"] == case["remotePort"] and reset["dport"] == case["consumerPort"],
          f"failure purge {case['name']}: ports are not mirrored")
    check(reset["flags"] == 0x14, f"failure purge {case['name']}: flags are not RST|ACK")
    check(reset["seq"] == case["appAck"], f"failure purge {case['name']}: sequence is not the application's receive-next")
    check(reset["ack"] == case["appSeqNext"], f"failure purge {case['name']}: ack is not what the application sent")
    check(reset["window"] == 0 and not reset["payload"], f"failure purge {case['name']}: a reset carries a window or data")
check(any(case["appAck"] > 0x7FFFFFFF for case in failure["resetOnPurge"]["cases"]),
      "failure: no purge case with a sequence number above the signed range")

for case in failure["resetOnPacket"]["cases"]:
    incoming = failure_tcp(bytes.fromhex(case["packetHex"]))
    reset = failure_tcp(bytes.fromhex(case["expect"]["packetHex"]))
    check(reset["src"] == incoming["dst"] and reset["dst"] == incoming["src"]
          and reset["sport"] == incoming["dport"] and reset["dport"] == incoming["sport"],
          f"failure packet {case['name']}: the reset is not addressed back to the sender")
    if incoming["flags"] & 0x10:
        check(reset["flags"] == 0x04 and reset["seq"] == incoming["ack"],
              f"failure packet {case['name']}: a segment with ACK must be reset at its acknowledgement")
    else:
        length = len(incoming["payload"]) + bool(incoming["flags"] & 0x02) + bool(incoming["flags"] & 0x01)
        check(reset["flags"] == 0x14 and reset["ack"] == (incoming["seq"] + length) & 0xFFFFFFFF,
              f"failure packet {case['name']}: a segment without ACK must be answered with RST|ACK covering it")
check(any(not (failure_tcp(bytes.fromhex(c["packetHex"]))["flags"] & 0x10) for c in failure["resetOnPacket"]["cases"]),
      "failure: no packet case for a SYN without ACK")
check(any(failure_tcp(bytes.fromhex(c["packetHex"]))["flags"] & 0x10 for c in failure["resetOnPacket"]["cases"]),
      "failure: no packet case for a segment carrying ACK")
check(any(failure_tcp(bytes.fromhex(c["packetHex"]))["payload"] and not (failure_tcp(bytes.fromhex(c["packetHex"]))["flags"] & 0x10)
          for c in failure["resetOnPacket"]["cases"]),
      "failure: no packet case where data on a SYN has to be covered by the ack")

for case in failure["unreachableOnDatagram"]["cases"]:
    datagram = bytes.fromhex(case["packetHex"])
    icmp = bytes.fromhex(case["expect"]["packetHex"])
    check(icmp[0] == 0x45 and icmp[9] == 1 and verifies(icmp[:20]), f"failure datagram {case['name']}: not a checksummed IPv4/ICMP packet")
    check(icmp[12:16] == datagram[16:20] and icmp[16:20] == datagram[12:16],
          f"failure datagram {case['name']}: the ICMP is not addressed back to the sender")
    body = icmp[20:struct.unpack("!H", icmp[2:4])[0]]
    check(verifies(body), f"failure datagram {case['name']}: ICMP checksum does not verify")
    check(body[0] == 3 and body[1] == 1, f"failure datagram {case['name']}: not host unreachable")
    ihl = (datagram[0] & 0x0F) * 4
    quoted = datagram[:min(struct.unpack("!H", datagram[2:4])[0], ihl + 8)]
    check(body[8:] == quoted, f"failure datagram {case['name']}: the quoted datagram is not its header plus eight bytes")
check(any(len(bytes.fromhex(c["packetHex"])) > 20 + 16 for c in failure["unreachableOnDatagram"]["cases"]),
      "failure: no datagram case with payload beyond the quoted eight bytes")

# ---- routes vector ------------------------------------------------------
# The planner's contract with the bypass list, stated a second time here so the generator's own
# planner cannot quietly change it: a bypass address gets a route only when a rule's route would
# otherwise capture it, and never through a rule that installs nothing.
routes_vector = json.loads((VECTORS / "peer-egress-routes-v1.json").read_text(encoding="utf-8"))
routes_refused = set()
covered_bypass_seen = uncovered_bypass_seen = 0
for case in routes_vector["planCases"]:
    name = case["name"]
    planned = case["expect"]["routes"]
    refused = {entry["index"] for entry in case["expect"]["refused"]}
    routes_refused |= {entry["code"] for entry in case["expect"]["refused"]}
    installing = []
    for index, rule in enumerate(case["rules"]):
        if index in refused or rule.get("action") not in ("egress", "block"):
            continue
        installing.append(ipaddress.IPv4Network(rule["match"].strip()))
    check(len({r["cidr"] for r in planned}) == len(planned), f"routes: {name} plans a prefix twice")
    kinds = [r["kind"] for r in planned]
    check(kinds == sorted(kinds, key=lambda k: 0 if k == "bypass" else 1),
          f"routes: {name} orders a tunnel route before a bypass")
    for route in planned:
        network = ipaddress.IPv4Network(route["cidr"])
        if route["kind"] == "bypass":
            check(network.prefixlen == 32, f"routes: {name} plans a bypass wider than /32")
            check(any(network.network_address in captured for captured in installing),
                  f"routes: {name} plans a bypass {route['cidr']} no installing rule covers")
            check(route["origin"] == "bypass", f"routes: {name} bypass origin is not 'bypass'")
        else:
            check(network in installing,
                  f"routes: {name} plans {route['cidr']} which no installing rule asked for")
            check(route["origin"].startswith("rule:"),
                  f"routes: {name} tunnel route origin does not name its rule")
    planned_bypass = {r["cidr"] for r in planned if r["kind"] == "bypass"}
    for endpoint in case["bypass"]:
        try:
            address = ipaddress.IPv4Address(endpoint.strip())
        except ValueError:
            continue
        covered = any(address in captured for captured in installing)
        if covered:
            covered_bypass_seen += 1
            check(str(address) + "/32" in planned_bypass,
                  f"routes: {name} left out a bypass for {address}, which a rule covers")
        else:
            uncovered_bypass_seen += 1
            check(str(address) + "/32" not in {r["cidr"] for r in planned},
                  f"routes: {name} planned a route for {address}, which nothing covers")
check(covered_bypass_seen > 0, "routes: no plan case has a bypass a rule covers")
check(uncovered_bypass_seen > 0, "routes: no plan case has a bypass nothing covers")
check(any(rule.get("action") == "direct" and case["bypass"]
          for case in routes_vector["planCases"] for rule in case["rules"]),
      "routes: no plan case puts a bypass under a direct rule")
check(routes_refused, "routes: no plan case refuses a rule")


def routes_reconcile(previous, desired, troubled, elapsed_ms, retry_after_ms):
    if previous is None:
        return True
    key = lambda r: (r["cidr"], r["kind"], r["origin"])  # noqa: E731
    if sorted(map(key, previous)) != sorted(map(key, desired)):
        return True
    return bool(troubled) and elapsed_ms >= retry_after_ms


reconcile = routes_vector["reconcile"]
check(reconcile["retryAfterMs"] >= 30_000, "routes: reconcile retries faster than every 30 s")
outcomes = set()
for case in reconcile["cases"]:
    produced = routes_reconcile(case["previous"], case["desired"], case["troubled"],
                                case["elapsedMs"], reconcile["retryAfterMs"])
    check(produced == case["expect"]["apply"],
          f"routes: reconcile case {case['name']} expects {case['expect']['apply']}")
    outcomes.add((case["previous"] is None, case["troubled"],
                  case["elapsedMs"] >= reconcile["retryAfterMs"], case["expect"]["apply"]))
# The decisions that have to be exercised: never applied, an unchanged troubled plan on either side
# of the interval, and a changed plan inside it.
check((True, False, False, True) in outcomes, "routes: no reconcile case for a first apply")
check((False, True, False, False) in outcomes, "routes: no reconcile case waits out the interval")
check((False, True, True, True) in outcomes, "routes: no reconcile case retries after the interval")
check(any(not case["troubled"] and case["previous"] is not None and case["expect"]["apply"]
          for case in reconcile["cases"]),
      "routes: no reconcile case applies a changed plan without trouble")
check(any(case["troubled"] and case["elapsedMs"] < reconcile["retryAfterMs"] and case["expect"]["apply"]
          for case in reconcile["cases"]),
      "routes: no reconcile case applies a changed plan inside the interval")

print(f"socket binding select={len(select_cases)} windows={len(binding['windows']['cases'])}"
      f" macos={len(binding['macos']['cases'])} hops={len(hop_cases)} drift={len(drift_cases)}")
print(f"routes plan={len(routes_vector['planCases'])} diff={len(routes_vector['diffCases'])}"
      f" reconcile={len(reconcile['cases'])}")
print(f"failure purge={len(failure['resetOnPurge']['cases'])} packet={len(failure['resetOnPacket']['cases'])}"
      f" datagram={len(failure['unreachableOnDatagram']['cases'])}")

if failures:
    print(f"\nFAILED ({len(failures)}):")
    for f in failures:
        print("  -", f)
    sys.exit(1)
print("\nall checks passed")
