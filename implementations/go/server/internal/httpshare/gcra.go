package httpshare

import "sync"

// DefaultMaxLimiterKeys bounds the memory of one limiter.
const DefaultMaxLimiterKeys = 10_000

// Limiter is a generic cell rate algorithm limiter: one theoretical arrival time (TAT) per key in
// integer milliseconds. A request at now conforms when now >= TAT - tolerance, which moves TAT to
// max(TAT, now) + interval; tolerance = (burst - 1) * interval. A refusal consumes nothing.
type Limiter struct {
	mu        sync.Mutex
	interval  int64
	tolerance int64
	maxKeys   int
	tat       map[string]int64
}

// NewLimiter builds a limiter admitting burst requests at once and then one per interval.
func NewLimiter(intervalMs int64, burst int) *Limiter {
	return &Limiter{interval: intervalMs, tolerance: int64(burst-1) * intervalMs,
		maxKeys: DefaultMaxLimiterKeys, tat: make(map[string]int64)}
}

// Take admits one request for key at nowMs, or returns the milliseconds to wait.
func (l *Limiter) Take(key string, nowMs int64) (bool, int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	tat, known := l.tat[key]
	if !known {
		if len(l.tat) >= l.maxKeys {
			l.evict(nowMs)
			if len(l.tat) >= l.maxKeys {
				// Every entry is still limiting someone: refuse the new key instead of forgetting
				// an active one.
				return false, l.interval
			}
		}
		tat = nowMs
	}
	if wait := tat - l.tolerance - nowMs; wait > 0 {
		return false, wait
	}
	l.tat[key] = max(tat, nowMs) + l.interval
	return true, 0
}

// evict drops entries whose TAT is not later than now: they limit nothing any more.
func (l *Limiter) evict(nowMs int64) {
	for key, tat := range l.tat {
		if tat <= nowMs {
			delete(l.tat, key)
		}
	}
}

// RetryAfterSeconds turns a wait into the Retry-After value: rounded up, at least one second.
func RetryAfterSeconds(waitMs int64) int64 {
	return max(1, (waitMs+999)/1000)
}
