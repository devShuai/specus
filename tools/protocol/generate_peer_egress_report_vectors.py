"""Generate peer-egress-report-v1.json: when an egress sends egress-report and what it says.

The servers keep the latest report of each egress and show it on the admin activity page, replacing
the previous one, and ignore a report whose revision is below the stored one. So a report carries
running totals -- the same numbers as the egress section of the local status -- rather than counts
for an interval, and its revision is the wall clock in milliseconds, kept strictly increasing, so
that the first report after the egress restarts is not taken for an old one. See
protocol/spec/peer-egress.md, egress-report.

Every expectation is produced by the reference here and pinned against a hand-written table.
"""
import json
from pathlib import Path

VECTORS = Path("protocol/test-vectors")
INTERVAL_SECONDS = 60


class Reporter:
    """One per egress process. A tick runs every INTERVAL_SECONDS."""

    def __init__(self):
        self.revision = 0
        self.last_sent = None  # the counters last sent in this control session while active

    def new_session(self):
        # The server may have restarted or lost the row: report again at the next tick.
        self.last_sent = None

    def tick(self, wall_ms, active, egress):
        if not active:
            self.last_sent = None
            return None
        counters = (egress["flows"], egress["totalFlows"], tuple(sorted(egress["refused"].items())),
                    egress["bytesIn"], egress["bytesOut"])
        if counters == self.last_sent:
            return None
        self.revision = max(self.revision + 1, wall_ms)
        self.last_sent = counters
        return {
            "type": "egress-report",
            "revision": self.revision,
            "activeFlows": egress["flows"],
            "totalFlows": egress["totalFlows"],
            "rejectedFlows": {code: count for code, count in sorted(egress["refused"].items()) if count > 0},
            "bytesIn": egress["bytesIn"],
            "bytesOut": egress["bytesOut"],
        }


def egress(flows=0, total=0, refused=None, bytes_in=0, bytes_out=0):
    return {"flows": flows, "totalFlows": total, "refused": refused or {}, "bytesIn": bytes_in, "bytesOut": bytes_out}


T0 = 1_791_000_000_000  # a wall clock in 2026, in milliseconds

EVENTS = [
    # The egress is switched on; the first tick reports even though nothing happened yet, so the
    # page shows the egress as reporting.
    ("tick", T0, True, egress()),
    # Nothing changed: no report.
    ("tick", T0 + 60_000, True, egress()),
    ("tick", T0 + 120_000, True, egress(2, 5, {"EGRESS_DEST_DENIED": 1}, 900, 1200)),
    ("tick", T0 + 180_000, True, egress(2, 5, {"EGRESS_DEST_DENIED": 1}, 900, 1200)),
    # Only bytes moved: that is a change.
    ("tick", T0 + 240_000, True, egress(2, 5, {"EGRESS_DEST_DENIED": 1}, 4096, 1200)),
    # A new control session reports again at the next tick, unchanged or not.
    ("session",),
    ("tick", T0 + 300_000, True, egress(2, 5, {"EGRESS_DEST_DENIED": 1}, 4096, 1200)),
    # The wall clock stepped back: the revision still increases.
    ("tick", T0 + 200_000, True, egress(1, 6, {"EGRESS_DEST_DENIED": 1, "EGRESS_PORT_DENIED": 2}, 5000, 1300)),
    # Switched off: nothing is sent, and the first tick after it is switched on again reports.
    ("tick", T0 + 360_000, False, egress(0, 6, {"EGRESS_DEST_DENIED": 1, "EGRESS_PORT_DENIED": 2}, 5000, 1300)),
    ("tick", T0 + 420_000, True, egress(0, 6, {"EGRESS_DEST_DENIED": 1, "EGRESS_PORT_DENIED": 2}, 5000, 1300)),
    # A zero count is not listed.
    ("tick", T0 + 480_000, True, egress(0, 6, {"EGRESS_DEST_DENIED": 1, "EGRESS_PORT_DENIED": 2, "EGRESS_SCOPE_DENIED": 0},
                                         5000, 1301)),
]

EXPECTED_REVISIONS = [T0, None, T0 + 120_000, None, T0 + 240_000, "session", T0 + 300_000, T0 + 300_001, None,
                      T0 + 420_000, T0 + 480_000]


def build():
    reporter = Reporter()
    events = []
    for event in EVENTS:
        if event[0] == "session":
            reporter.new_session()
            events.append({"newSession": True})
            continue
        _, wall_ms, active, status = event
        report = reporter.tick(wall_ms, active, status)
        events.append({"wallMs": wall_ms, "active": active, "egress": status, "report": report})
    produced = ["session" if "newSession" in e else (e["report"] or {}).get("revision") for e in events]
    assert produced == EXPECTED_REVISIONS, produced
    assert events[-1]["report"]["rejectedFlows"] == {"EGRESS_DEST_DENIED": 1, "EGRESS_PORT_DENIED": 2}
    return {
        "description": "When an egress sends egress-report and its body. A tick runs every intervalSeconds; `egress` is "
                       "the egress section of the local status at that tick, `report` the message sent or null. See "
                       "protocol/spec/peer-egress.md, egress-report.",
        "intervalSeconds": INTERVAL_SECONDS,
        "events": events,
    }


def main():
    document = build()
    path = VECTORS / "peer-egress-report-v1.json"
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {path}: events={len(document['events'])}")


if __name__ == "__main__":
    main()
