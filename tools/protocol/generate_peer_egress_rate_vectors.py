"""Generate peer-egress-rate-v1.json: how fast an egress lets one consumer open new flows.

An egress must not become an open proxy, and the concurrency limits alone let a consumer churn
through short flows -- a port scan, say -- as fast as the network allows. Each consumer therefore
draws new flows from a token bucket at the egress. A flow takes a token only when everything else
already admitted it, so refused attempts cost nothing and a retransmitted SYN of a flow that exists
is not a new flow. Every expectation is produced here and checked against a hand-written table.
See protocol/spec/peer-egress.md, 资源上限.
"""
import json
from pathlib import Path

VECTORS = Path("protocol/test-vectors")
CAPACITY = 128
REFILL_PER_SECOND = 64


class Buckets:
    """Tokens are counted in thousandths, in integers, so every runtime lands on the same side of a
    boundary: a millisecond refills REFILL_PER_SECOND thousandths."""

    def __init__(self):
        self.buckets = {}  # consumer -> (milli-tokens, last time in ms)

    def admit(self, consumer, now_ms):
        milli, last = self.buckets.get(consumer, (CAPACITY * 1000, now_ms))
        milli = min(CAPACITY * 1000, milli + max(0, now_ms - last) * REFILL_PER_SECOND)
        if milli < 1000:
            self.buckets[consumer] = (milli, now_ms)
            return False
        self.buckets[consumer] = (milli - 1000, now_ms)
        return True


EVENTS = [
    # A burst of 130 new flows from consumer 1 at once: the bucket holds 128.
    {"atMs": 0, "consumer": 1, "flows": 130},
    # Another consumer has a bucket of its own.
    {"atMs": 0, "consumer": 2, "flows": 3},
    # Half a second later 32 tokens have come back.
    {"atMs": 500, "consumer": 1, "flows": 40},
    # A token takes 15.625 ms to come back: 15 ms is not enough, 16 ms is.
    {"atMs": 515, "consumer": 1, "flows": 1},
    {"atMs": 516, "consumer": 1, "flows": 1},
    # Ten seconds of quiet fill the bucket again, but never past its size.
    {"atMs": 10516, "consumer": 1, "flows": 129},
]

EXPECTED = [(128, 2), (3, 0), (32, 8), (0, 1), (1, 0), (128, 1)]


def build():
    buckets = Buckets()
    events = []
    for event in EVENTS:
        admitted = sum(1 for _ in range(event["flows"]) if buckets.admit(event["consumer"], event["atMs"]))
        events.append({**event, "admitted": admitted, "refused": event["flows"] - admitted})
    assert [(e["admitted"], e["refused"]) for e in events] == EXPECTED, events
    return {
        "description": "New flows an egress admits per consumer: a token bucket per consumer, taken only by a flow "
                       "everything else admitted. A refusal is EGRESS_LIMIT_EXCEEDED. See protocol/spec/peer-egress.md.",
        "capacity": CAPACITY,
        "refillPerSecond": REFILL_PER_SECOND,
        "refusalCode": "EGRESS_LIMIT_EXCEEDED",
        "events": events,
    }


def main():
    document = build()
    path = VECTORS / "peer-egress-rate-v1.json"
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {path}: events={len(document['events'])}")


if __name__ == "__main__":
    main()
