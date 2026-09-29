"""Generate peer-egress-consumer-flows-v1.json: when a consumer forgets a flow it steered to an egress.

The consumer keeps one entry per four-tuple it sent through an egress: the return path is checked
against it, a revocation resets from what it remembers, and the status counts it. Until this vector
nothing removed an entry except a revocation or a flow-reject, so every flow ever made stayed in
memory and the status's "active flows" only ever grew. The reference below is what the three clients
now do; see protocol/spec/peer-egress.md.
"""
import json
from pathlib import Path

VECTORS = Path("protocol/test-vectors")

UDP_IDLE = 180
TCP_IDLE = 7200
TCP_CLOSED_LINGER = 120


class Table:
    def __init__(self, capacity):
        self.capacity = capacity
        self.flows = {}  # key -> flow; insertion order breaks ties in eviction
        self.order = 0

    @staticmethod
    def deadline(flow):
        if flow["protocol"] == "udp":
            return flow["last"] + UDP_IDLE
        if flow["closedAt"] is not None:
            return flow["closedAt"] + TCP_CLOSED_LINGER
        return flow["last"] + TCP_IDLE

    def live(self, now):
        return {key: flow for key, flow in self.flows.items() if now < self.deadline(flow)}

    def sweep(self, now):
        self.flows = self.live(now)

    def _note(self, flow, flags, direction, now):
        flow["last"] = now
        if flow["protocol"] != "tcp":
            return
        if "R" in flags:
            flow["closedAt"] = flow["closedAt"] if flow["closedAt"] is not None else now
        if "F" in flags:
            flow["fin" + direction] = True
        if flow["finOut"] and flow["finIn"] and flow["closedAt"] is None:
            flow["closedAt"] = now

    def outbound(self, key, protocol, flags, now):
        self.sweep(now)
        flow = self.flows.get(key)
        # A SYN on a four-tuple whose flow has closed is a new connection reusing the port.
        if flow is not None and protocol == "tcp" and "S" in flags and "A" not in flags and flow["closedAt"] is not None:
            del self.flows[key]
            flow = None
        if flow is None:
            if len(self.flows) >= self.capacity:
                oldest = min(self.flows.items(), key=lambda item: (item[1]["last"], item[1]["order"]))[0]
                del self.flows[oldest]
            self.order += 1
            flow = {"protocol": protocol, "last": now, "finOut": False, "finIn": False, "closedAt": None,
                    "order": self.order}
            self.flows[key] = flow
        self._note(flow, flags, "Out", now)
        return "forwarded"

    def inbound(self, key, flags, now):
        self.sweep(now)
        flow = self.flows.get(key)
        if flow is None:
            return "return-no-flow"
        self._note(flow, flags, "In", now)
        return "delivered"


CASES = [
    {
        "name": "udp-forgotten-after-idle",
        "capacity": 16,
        "events": [
            {"at": 0, "out": 5000, "protocol": "udp"},
            {"at": 100, "in": 5000},
            {"at": 279, "known": 5000},
            {"at": 280, "known": 5000},
            {"at": 281, "in": 5000},
            {"at": 282, "count": True},
        ],
    },
    {
        "name": "tcp-closed-by-fin-both-ways",
        "capacity": 16,
        "events": [
            {"at": 0, "out": 6000, "protocol": "tcp", "flags": "S"},
            {"at": 1, "in": 6000, "flags": "SA"},
            {"at": 2, "out": 6000, "protocol": "tcp", "flags": "A"},
            {"at": 10, "in": 6000, "flags": "FA"},
            {"at": 11, "out": 6000, "protocol": "tcp", "flags": "FA"},
            {"at": 12, "in": 6000, "flags": "A"},
            {"at": 130, "known": 6000},
            {"at": 131, "known": 6000},
        ],
    },
    {
        "name": "tcp-closed-by-reset",
        "capacity": 16,
        "events": [
            {"at": 0, "out": 6100, "protocol": "tcp", "flags": "S"},
            {"at": 1, "in": 6100, "flags": "R"},
            {"at": 60, "in": 6100, "flags": "A"},
            {"at": 120, "known": 6100},
            {"at": 121, "known": 6100},
        ],
    },
    {
        "name": "tcp-half-closed-stays",
        "capacity": 16,
        "events": [
            {"at": 0, "out": 6200, "protocol": "tcp", "flags": "S"},
            {"at": 5, "out": 6200, "protocol": "tcp", "flags": "FA"},
            {"at": 1000, "known": 6200},
            {"at": 7204, "known": 6200},
            {"at": 7205, "known": 6200},
        ],
    },
    {
        "name": "tcp-idle-established-forgotten-after-two-hours",
        "capacity": 16,
        "events": [
            {"at": 0, "out": 6300, "protocol": "tcp", "flags": "S"},
            {"at": 3600, "in": 6300, "flags": "A"},
            {"at": 10799, "known": 6300},
            {"at": 10800, "known": 6300},
        ],
    },
    {
        "name": "port-reuse-after-close-starts-a-new-flow",
        "capacity": 16,
        "events": [
            {"at": 0, "out": 6400, "protocol": "tcp", "flags": "S"},
            {"at": 1, "in": 6400, "flags": "R"},
            {"at": 30, "out": 6400, "protocol": "tcp", "flags": "S"},
            {"at": 200, "known": 6400},
        ],
    },
    {
        "name": "capacity-evicts-the-least-recently-seen",
        "capacity": 3,
        "events": [
            {"at": 0, "out": 7001, "protocol": "udp"},
            {"at": 1, "out": 7002, "protocol": "udp"},
            {"at": 2, "out": 7003, "protocol": "udp"},
            {"at": 3, "in": 7001},
            {"at": 4, "out": 7004, "protocol": "udp"},
            {"at": 5, "known": 7002},
            {"at": 5, "known": 7001},
            {"at": 5, "count": True},
        ],
    },
    {
        "name": "unknown-return-is-dropped",
        "capacity": 16,
        "events": [
            {"at": 0, "in": 8000, "flags": "A"},
            {"at": 0, "count": True},
        ],
    },
]


def run(case):
    table = Table(case["capacity"])
    results = []
    for event in case["events"]:
        now = event["at"]
        if "out" in event:
            results.append(table.outbound(event["out"], event["protocol"], event.get("flags", ""), now))
        elif "in" in event:
            results.append(table.inbound(event["in"], event.get("flags", ""), now))
        elif "known" in event:
            results.append(event["known"] in table.live(now))
        else:
            results.append(len(table.live(now)))
    return results


def build():
    cases = []
    for case in CASES:
        cases.append({**case, "results": run(case)})
    # Hand-checked, so the reference itself is pinned.
    by_name = {case["name"]: case["results"] for case in cases}
    assert by_name["udp-forgotten-after-idle"] == ["forwarded", "delivered", True, False, "return-no-flow", 0]
    assert by_name["tcp-closed-by-fin-both-ways"][-2:] == [True, False]
    assert by_name["tcp-closed-by-reset"] == ["forwarded", "delivered", "delivered", True, False]
    assert by_name["tcp-half-closed-stays"][-3:] == [True, True, False]
    assert by_name["tcp-idle-established-forgotten-after-two-hours"][-2:] == [True, False]
    assert by_name["port-reuse-after-close-starts-a-new-flow"][-1] is True
    assert by_name["capacity-evicts-the-least-recently-seen"][-3:] == [False, True, 3]
    assert by_name["unknown-return-is-dropped"] == ["return-no-flow", 0]
    return {
        "description": "When a consumer forgets a flow it steered to an egress. Events are packets out of the "
                       "TUN ('out', with protocol and TCP flags) and back from the egress ('in'), a question whether "
                       "a flow is still known ('known') or how many are ('count'). See protocol/spec/peer-egress.md.",
        "udpIdleSeconds": UDP_IDLE,
        "tcpIdleSeconds": TCP_IDLE,
        "tcpClosedLingerSeconds": TCP_CLOSED_LINGER,
        "consumer": "100.96.0.2",
        "remote": "203.0.113.10:443",
        "cases": cases,
    }


def main():
    document = build()
    path = VECTORS / "peer-egress-consumer-flows-v1.json"
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {path}: cases={len(document['cases'])}")


if __name__ == "__main__":
    main()
