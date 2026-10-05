package client

import "time"

// How fast a consumer may open new flows through this egress (protocol/spec/peer-egress.md, 资源上限).
//
// The concurrency caps bound the flows that exist at once, not how fast a consumer churns through
// short ones: a scan that opens and closes a flow per port never holds more than a few. Each
// consumer therefore draws new flows from a token bucket of its own. Tokens are counted in integer
// thousandths against an integer millisecond clock, so every runtime lands on the same side of a
// boundary. Pinned by protocol/test-vectors/peer-egress-rate-v1.json.

const (
	egressFlowRateCapacity        = 128
	egressFlowRateRefillPerSecond = 64

	egressFlowRateMilliPerToken = 1000
	egressFlowRateFullMilli     = egressFlowRateCapacity * egressFlowRateMilliPerToken
	// A millisecond refills refillPerSecond thousandths, so an empty bucket is full again after
	// this long, and a bucket untouched for this long is full whatever it last held.
	egressFlowRateFullAfterMs = (egressFlowRateFullMilli + egressFlowRateRefillPerSecond - 1) /
		egressFlowRateRefillPerSecond
)

type egressFlowRateBucket struct {
	milli  int64
	lastMs int64
}

func (b *egressFlowRateBucket) refill(nowMs int64) {
	if elapsed := nowMs - b.lastMs; elapsed >= egressFlowRateFullAfterMs {
		b.milli = egressFlowRateFullMilli
	} else if elapsed > 0 {
		b.milli = min(egressFlowRateFullMilli, b.milli+elapsed*egressFlowRateRefillPerSecond)
	}
	b.lastMs = nowMs
}

// egressFlowRate holds one bucket per consumer. Not safe for concurrent use; the runtime's lock
// covers it like the flow table.
type egressFlowRate struct {
	// clock reads milliseconds on a monotonic clock: a wall clock stepped forward would refill every
	// bucket at once. Read under the runtime's lock, so the times buckets see never run backwards.
	clock     func() int64
	buckets   map[int64]egressFlowRateBucket
	sweptAtMs int64
}

func newEgressFlowRate() *egressFlowRate {
	return &egressFlowRate{clock: newEgressMonotonicMs(), buckets: make(map[int64]egressFlowRateBucket)}
}

func newEgressMonotonicMs() func() int64 {
	start := time.Now()
	return func() int64 { return int64(time.Since(start) / time.Millisecond) }
}

// take spends one token for a new flow from consumer and reports whether there was one. The caller
// asks only for a flow every other check admitted and that does not exist yet, so a refused attempt
// or a retransmission costs nothing.
func (r *egressFlowRate) take(consumer int64) bool {
	return r.admit(consumer, r.clock())
}

func (r *egressFlowRate) admit(consumer int64, nowMs int64) bool {
	r.forgetFull(nowMs)
	bucket, known := r.buckets[consumer]
	if !known {
		bucket = egressFlowRateBucket{milli: egressFlowRateFullMilli, lastMs: nowMs}
	}
	bucket.refill(nowMs)
	admitted := bucket.milli >= egressFlowRateMilliPerToken
	if admitted {
		bucket.milli -= egressFlowRateMilliPerToken
	}
	r.buckets[consumer] = bucket
	return admitted
}

// forgetFull drops the buckets that have refilled. A forgotten bucket comes back full, exactly as a
// kept one would have, so this bounds the map by the consumers active in the last few seconds rather
// than by every consumer that ever opened a flow. Swept at most once per refill period, so the cost
// stays off the per-flow path.
func (r *egressFlowRate) forgetFull(nowMs int64) {
	if nowMs-r.sweptAtMs < egressFlowRateFullAfterMs {
		return
	}
	r.sweptAtMs = nowMs
	for consumer, bucket := range r.buckets {
		bucket.refill(nowMs)
		if bucket.milli == egressFlowRateFullMilli {
			delete(r.buckets, consumer)
		}
	}
}
