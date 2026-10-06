package connectivity

import (
	"strconv"
	"sync"
)

const (
	maxConcurrentPerServer = 32
	routeIntervalMs        = 10_000
	routeBurst             = 1
	userIntervalMs         = 30_000
	userBurst              = 10
	// maxRateKeys bounds each limiter's table. Entries whose TAT is not after now are dead and can
	// go at any time; a live entry is never evicted, since that would hand it a fresh allowance.
	maxRateKeys = 10_000
	// refusalLogIntervalMs: a rate-limited caller is logged at most once a minute.
	refusalLogIntervalMs = 60_000
)

type refusalReason struct {
	status            int
	code              string
	retryAfterSeconds int
	limitedBy         string
}

// gcra is the generic cell rate algorithm with one theoretical arrival time (TAT) per key, in
// integer milliseconds. A request at now conforms when now >= TAT - tolerance; conforming moves
// TAT to max(TAT, now) + interval; tolerance = (burst - 1) * interval.
type gcra struct {
	interval  int64
	tolerance int64
	tat       map[string]int64
}

func newGCRA(intervalMs int64, burst int64) *gcra {
	return &gcra{interval: intervalMs, tolerance: (burst - 1) * intervalMs, tat: make(map[string]int64)}
}

func (g *gcra) waitMs(key string, now int64) int64 {
	tat, ok := g.tat[key]
	if !ok {
		tat = now
	}
	if wait := tat - g.tolerance - now; wait > 0 {
		return wait
	}
	return 0
}

// hasRoom reports whether key can be stored, purging dead entries when the table is full.
func (g *gcra) hasRoom(key string, now int64) bool {
	if _, ok := g.tat[key]; ok || len(g.tat) < maxRateKeys {
		return true
	}
	for existing, tat := range g.tat {
		if tat <= now {
			delete(g.tat, existing)
		}
	}
	return len(g.tat) < maxRateKeys
}

func (g *gcra) take(key string, now int64) {
	tat, ok := g.tat[key]
	if !ok || tat < now {
		tat = now
	}
	g.tat[key] = tat + g.interval
}

// admission holds the process-wide concurrency slots, both rate limiters and the throttle of
// rate-limit log lines. Refused requests consume nothing.
type admission struct {
	mu          sync.Mutex
	running     map[int64]bool
	total       int
	perRoute    *gcra
	perUser     *gcra
	lastRefusal map[string]int64
}

func newAdmission() *admission {
	return &admission{
		running: make(map[int64]bool), perRoute: newGCRA(routeIntervalMs, routeBurst),
		perUser: newGCRA(userIntervalMs, userBurst), lastRefusal: make(map[string]int64),
	}
}

func routeKey(tenant string, routeID int64) string {
	return strconv.Itoa(len(tenant)) + ":" + tenant + "/" + strconv.FormatInt(routeID, 10)
}

func userKey(tenant, username string) string {
	return strconv.Itoa(len(tenant)) + ":" + tenant + "/" + username
}

// admit applies steps 5 to 7 of section 3.2. On success the caller must call release once the check
// finished.
func (a *admission) admit(tenant, username string, routeID int64, now int64) (func(), *refusalReason) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.running[routeID] {
		return nil, &refusalReason{status: 429, code: "CHECK_IN_PROGRESS", retryAfterSeconds: 1}
	}
	if a.total >= maxConcurrentPerServer {
		return nil, &refusalReason{status: 503, code: "CHECK_BUSY", retryAfterSeconds: 1}
	}
	if refused := a.rateLocked(tenant, username, routeID, now); refused != nil {
		return nil, refused
	}
	a.running[routeID] = true
	a.total++
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			delete(a.running, routeID)
			a.total--
			a.mu.Unlock()
		})
	}, nil
}

// rate admits on both keys or on neither. Retry-After is the longer wait in whole seconds, at least 1.
func (a *admission) rate(tenant, username string, routeID int64, now int64) *refusalReason {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rateLocked(tenant, username, routeID, now)
}

func (a *admission) rateLocked(tenant, username string, routeID int64, now int64) *refusalReason {
	route, user := routeKey(tenant, routeID), userKey(tenant, username)
	routeWait, userWait := a.perRoute.waitMs(route, now), a.perUser.waitMs(user, now)
	if wait := max(routeWait, userWait); wait > 0 {
		limitedBy := "user"
		if routeWait >= userWait {
			limitedBy = "route"
		}
		return &refusalReason{status: 429, code: "CHECK_RATE_LIMITED",
			retryAfterSeconds: int(max(1, (wait+999)/1000)), limitedBy: limitedBy}
	}
	if !a.perRoute.hasRoom(route, now) || !a.perUser.hasRoom(user, now) {
		return &refusalReason{status: 503, code: "CHECK_BUSY", retryAfterSeconds: 1}
	}
	a.perRoute.take(route, now)
	a.perUser.take(user, now)
	return nil
}

// shouldLogRefusal throttles rate-limit log lines to one a minute per caller.
func (a *admission) shouldLogRefusal(tenant, username string, now int64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := userKey(tenant, username)
	if last, ok := a.lastRefusal[key]; ok && now-last < refusalLogIntervalMs {
		return false
	}
	if _, ok := a.lastRefusal[key]; !ok && len(a.lastRefusal) >= maxRateKeys {
		for existing, last := range a.lastRefusal {
			if now-last >= refusalLogIntervalMs {
				delete(a.lastRefusal, existing)
			}
		}
		if len(a.lastRefusal) >= maxRateKeys {
			return false
		}
	}
	a.lastRefusal[key] = now
	return true
}
