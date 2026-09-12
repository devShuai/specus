package client

import "time"

// Refusal accounting for the egress side.
//
// Two jobs that must not be conflated. The egress-report carries a count per error code and nothing
// else: no destination, no domain, no payload. A report that named destinations would hand the
// server a browsing history it has no reason to hold, so the aggregate is the only thing that
// leaves this node.
//
// Local diagnostic logging may name the destination, because it stays on the operator's own
// machine. It is rate limited by subject and reason, so a consumer retrying a refused flow in a
// loop cannot bury the one refusal an operator needs to see.

const (
	// egressRejectionWindow and egressRejectionsPerWindow bound diagnostic lines for one subject
	// and reason. Twenty a minute is enough to show a pattern; the count in the suppression note
	// carries the volume.
	egressRejectionWindow     = time.Minute
	egressRejectionsPerWindow = 20

	// egressRejectionMaxSubjects is the process-wide hard cap the spec requires on the audit
	// cache. Without it a peer that varies its identity turns a rate limiter into a memory leak,
	// which is a worse outcome than the flooding the limiter exists to prevent.
	egressRejectionMaxSubjects = 4096
)

type egressRejectionKey struct {
	consumer int64
	code     string
}

type egressRejectionBucket struct {
	startedAt time.Time
	logged    int
	// suppressed counts refusals dropped since the last line that was emitted, so that line can
	// say how much it stands for instead of leaving the gap unexplained.
	suppressed int64
}

type egressRejectionLog struct {
	counts map[string]int64
	// cumulative is the same tally for the status surface, and nothing resets it.
	//
	// Separate from counts on purpose. counts belongs to the periodic report and is drained so
	// that consecutive reports describe consecutive intervals; a status reading that same map
	// would answer "since whenever the last report went out", which is not a question anybody
	// asked and changes meaning the day the report is wired up. Two counters cost a map.
	cumulative map[string]int64
	recent  map[egressRejectionKey]*egressRejectionBucket
	total   int64
	limited bool
}

func newEgressRejectionLog() *egressRejectionLog {
	return &egressRejectionLog{
		counts:     make(map[string]int64),
		cumulative: make(map[string]int64),
		recent:     make(map[egressRejectionKey]*egressRejectionBucket),
	}
}

// record registers one refusal. It returns whether a diagnostic line should be written and how many
// refusals that line stands for beyond itself.
//
// The aggregate is incremented unconditionally: rate limiting governs what an operator reads, never
// what the report counts. A report that undercounted because logging was busy would be worse than
// no report, since it would look like the refusals stopped.
func (l *egressRejectionLog) record(consumer int64, code string, now time.Time) (bool, int64) {
	l.counts[code]++
	l.cumulative[code]++
	l.total++

	key := egressRejectionKey{consumer: consumer, code: code}
	window, known := l.recent[key]
	if !known {
		if len(l.recent) >= egressRejectionMaxSubjects {
			l.sweep(now)
		}
		if len(l.recent) >= egressRejectionMaxSubjects {
			// At the cap with every window still live. The refusal stays in the aggregate,
			// so nothing is lost from the report; only the diagnostic line is dropped.
			l.limited = true
			return false, 0
		}
		window = &egressRejectionBucket{startedAt: now}
		l.recent[key] = window
	}

	if now.Sub(window.startedAt) >= egressRejectionWindow {
		window.startedAt = now
		window.logged = 0
	}
	if window.logged >= egressRejectionsPerWindow {
		window.suppressed++
		return false, 0
	}
	window.logged++
	suppressed := window.suppressed
	window.suppressed = 0
	return true, suppressed
}

// sweep drops windows that have already elapsed. Called only when the cap is reached, because until
// then an expired window costs one map entry and reusing it costs nothing.
func (l *egressRejectionLog) sweep(now time.Time) {
	for key, window := range l.recent {
		if now.Sub(window.startedAt) >= egressRejectionWindow {
			delete(l.recent, key)
		}
	}
}

// cumulativeCounts returns the per-code totals since this runtime started, for the status surface.
//
// A copy, because the caller is a diagnostic reader and this log goes on counting.
func (l *egressRejectionLog) cumulativeCounts() map[string]int64 {
	counts := make(map[string]int64, len(l.cumulative))
	for code, count := range l.cumulative {
		counts[code] = count
	}
	return counts
}

// drainCounts returns the per-code totals for one egress-report and resets them, so consecutive
// reports describe consecutive intervals rather than a running sum the server has to difference.
// The cumulative tally above is deliberately not reset here.
func (l *egressRejectionLog) drainCounts() map[string]int64 {
	if len(l.counts) == 0 {
		return nil
	}
	drained := l.counts
	l.counts = make(map[string]int64)
	l.total = 0
	l.limited = false
	return drained
}
