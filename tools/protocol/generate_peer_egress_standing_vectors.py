"""Generate peer-egress-standing-v1.json: what a consumer makes of an egress its rules name.

A rule names an egress by client id. Whether that egress can take a flow used to be read from the
mesh roster alone, so an egress running a client without peer egress support, being online, was
sent flows it silently dropped. The consumer now also reads egress-catalog: whether the egress is
offered to it at all, and the egressVersion its online session announced. Every expectation is
produced by the reference here and checked against a hand-written table before writing. See
protocol/spec/peer-egress.md, "能力不支持".
"""
import json
from pathlib import Path

VECTORS = Path("protocol/test-vectors")


def standing(catalog_received, listed, egress_version):
    """What the catalogue says about one egress.

    unknown: no catalogue accepted in this control session (an older server sends none);
    not-offered: a catalogue was accepted and does not list the egress;
    unsupported: listed, and its online session announced no peer egress (egressVersion 0);
    offered: listed, with egressVersion 1 or more, or without the field (an older server)."""
    if not catalog_received:
        return "unknown"
    if not listed:
        return "not-offered"
    if egress_version is not None and egress_version < 1:
        return "unsupported"
    return "offered"


def decision(online, catalog_received, listed, egress_version):
    """Whether a flow to the egress goes out, and if not, the blocked reason. Offline comes first:
    the catalogue cannot speak for a device that is not there."""
    if not online:
        return {"standing": standing(catalog_received, listed, egress_version), "blocked": "egress-unavailable"}
    state = standing(catalog_received, listed, egress_version)
    if state == "not-offered":
        return {"standing": state, "blocked": "egress-not-offered"}
    if state == "unsupported":
        return {"standing": state, "blocked": "egress-unsupported"}
    return {"standing": state, "blocked": None}


CASES = [
    ("offered-and-capable", True, True, True, 1),
    ("listed-by-an-older-server", True, True, True, None),
    ("listed-but-announced-no-egress", True, True, True, 0),
    ("not-in-the-catalogue", True, True, False, None),
    ("no-catalogue-yet-or-older-server", True, False, False, None),
    ("offline-wins-over-everything", False, True, True, 1),
    ("offline-and-not-offered", False, True, False, None),
]

EXPECTED = [
    ("offered", None),
    ("offered", None),
    ("unsupported", "egress-unsupported"),
    ("not-offered", "egress-not-offered"),
    ("unknown", None),
    ("offered", "egress-unavailable"),
    ("not-offered", "egress-unavailable"),
]


def build():
    cases = []
    for name, online, received, listed, version in CASES:
        entry = {"name": name, "online": online, "catalogReceived": received, "listed": listed}
        if version is not None:
            entry["egressVersion"] = version
        cases.append({**entry, **decision(online, received, listed, version)})
    assert [(c["standing"], c["blocked"]) for c in cases] == EXPECTED, cases
    return {
        "description": "What a consumer makes of an egress its rules name, from the roster and egress-catalog: "
                       "the catalogue standing and whether a flow goes out. See protocol/spec/peer-egress.md.",
        "catalogWaitSeconds": 30,
        "cases": cases,
    }


def main():
    document = build()
    path = VECTORS / "peer-egress-standing-v1.json"
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {path}: cases={len(document['cases'])}")


if __name__ == "__main__":
    main()
