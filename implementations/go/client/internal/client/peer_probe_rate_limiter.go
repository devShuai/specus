package client

import (
	"net"
	"sync"
	"time"
)

// Aligned with the Java and .NET clients.
const (
	probeRateWindow             = time.Second
	probeSourceTTL              = time.Minute
	probeGlobalPacketsPerWindow = 2000
	probeSourcePacketsPerWindow = 100
	probeMaxTrackedSources      = 4096
)

// peerUDPProbeRateLimiter caps how many probe datagrams the client will parse and answer.
//
// Probes arrive unauthenticated on the mesh socket, and answering one costs a JSON decode plus a
// reply datagram. Without a cap any host that knows the port can make the client spend its CPU and
// its uplink on traffic no peer asked for. Two fixed windows: a global one that bounds the total
// cost, and a per-source one so a single flooder cannot consume the global budget.
type peerUDPProbeRateLimiter struct {
	mu                sync.Mutex
	sources           map[string]*probeSourceWindow
	globalWindowStart time.Time
	globalPackets     int
}

type probeSourceWindow struct {
	windowStart time.Time
	packets     int
	lastSeen    time.Time
}

func newPeerUDPProbeRateLimiter() *peerUDPProbeRateLimiter {
	return &peerUDPProbeRateLimiter{sources: make(map[string]*probeSourceWindow)}
}

// tryAcquire reports whether this probe may be handled. A nil limiter allows everything so callers
// constructed without one (tests, early startup) keep working.
func (limiter *peerUDPProbeRateLimiter) tryAcquire(source net.IP, now time.Time) bool {
	if limiter == nil {
		return true
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	if limiter.globalWindowStart.IsZero() || now.Sub(limiter.globalWindowStart) >= probeRateWindow {
		limiter.globalWindowStart = now
		limiter.globalPackets = 0
	}
	limiter.globalPackets++
	if limiter.globalPackets > probeGlobalPacketsPerWindow || source == nil {
		return false
	}

	key := normalizeProbeSource(source)
	window, ok := limiter.sources[key]
	if !ok {
		limiter.evictLocked(now)
		window = &probeSourceWindow{windowStart: now, lastSeen: now}
		limiter.sources[key] = window
	}
	if now.Sub(window.windowStart) >= probeRateWindow {
		window.windowStart = now
		window.packets = 0
	}
	window.lastSeen = now
	window.packets++
	return window.packets <= probeSourcePacketsPerWindow
}

// cleanup drops sources that have gone quiet, so a long-lived client does not accumulate one entry
// per address that ever probed it.
func (limiter *peerUDPProbeRateLimiter) cleanup(now time.Time) {
	if limiter == nil {
		return
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.cleanupLocked(now)
}

func (limiter *peerUDPProbeRateLimiter) cleanupLocked(now time.Time) {
	for key, window := range limiter.sources {
		if now.Sub(window.lastSeen) > probeSourceTTL {
			delete(limiter.sources, key)
		}
	}
}

// evictLocked keeps the table bounded. Expiring stale entries first usually suffices; a flood of
// distinct addresses within one TTL is what forces the oldest-first eviction below.
func (limiter *peerUDPProbeRateLimiter) evictLocked(now time.Time) {
	limiter.cleanupLocked(now)
	for len(limiter.sources) >= probeMaxTrackedSources {
		oldestKey := ""
		var oldestSeen time.Time
		for key, window := range limiter.sources {
			if oldestKey == "" || window.lastSeen.Before(oldestSeen) {
				oldestKey = key
				oldestSeen = window.lastSeen
			}
		}
		if oldestKey == "" {
			return
		}
		delete(limiter.sources, oldestKey)
	}
}

func (limiter *peerUDPProbeRateLimiter) sourceCount() int {
	if limiter == nil {
		return 0
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	return len(limiter.sources)
}

// normalizeProbeSource folds IPv4-mapped IPv6 onto the IPv4 form so one host cannot get two budgets.
func normalizeProbeSource(source net.IP) string {
	if v4 := source.To4(); v4 != nil {
		return v4.String()
	}
	return source.String()
}
