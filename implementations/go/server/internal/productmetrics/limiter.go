package productmetrics

import "sync"

// Limits are the per-minute event budgets of section 8.
type Limits struct {
	PerUserEventsPerMinute   int
	PerTenantEventsPerMinute int
}

// DefaultLimits are the contract's defaults.
func DefaultLimits() Limits {
	return Limits{PerUserEventsPerMinute: DefaultPerUserEventsPerMinute,
		PerTenantEventsPerMinute: DefaultPerTenantEventsPerMinute}
}

// limiter counts events in fixed UTC-minute windows per tenant+username and per tenant. It is per
// process, like the other limiters; with several instances the effective budget is a multiple,
// which only ever affects the tenant's own statistics.
type limiter struct {
	mu      sync.Mutex
	limits  Limits
	minute  int64
	users   map[string]int
	tenants map[string]int
}

func newLimiter(limits Limits) *limiter {
	return &limiter{limits: limits, minute: -1, users: map[string]int{}, tenants: map[string]int{}}
}

// admit charges count events to both keys when neither would exceed its budget, and charges
// nothing otherwise: a refused batch consumes no quota.
func (l *limiter) admit(tenantID, username string, count int, nowMs int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	minute := floorDiv(nowMs, 60_000)
	if minute != l.minute {
		l.minute = minute
		l.users = map[string]int{}
		l.tenants = map[string]int{}
	}
	userKey := tenantID + "\n" + username
	if l.users[userKey]+count > l.limits.PerUserEventsPerMinute ||
		l.tenants[tenantID]+count > l.limits.PerTenantEventsPerMinute {
		return false
	}
	l.users[userKey] += count
	l.tenants[tenantID] += count
	return true
}

func (l *limiter) reset(limits Limits) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.limits = limits
	l.minute = -1
	l.users = map[string]int{}
	l.tenants = map[string]int{}
}

func floorDiv(value, divisor int64) int64 {
	quotient := value / divisor
	if value%divisor != 0 && (value < 0) != (divisor < 0) {
		quotient--
	}
	return quotient
}
