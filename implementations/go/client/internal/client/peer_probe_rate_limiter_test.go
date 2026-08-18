package client

import (
	"net"
	"testing"
	"time"
)

func TestProbeRateLimiterBoundsASingleSource(t *testing.T) {
	limiter := newPeerUDPProbeRateLimiter()
	now := time.Now()
	source := net.IPv4(203, 0, 113, 40)

	allowed := 0
	for i := 0; i < probeSourcePacketsPerWindow*3; i++ {
		if limiter.tryAcquire(source, now) {
			allowed++
		}
	}
	if allowed != probeSourcePacketsPerWindow {
		t.Fatalf("allowed %d probes in one window, want %d", allowed, probeSourcePacketsPerWindow)
	}

	// The next window starts a fresh budget.
	if !limiter.tryAcquire(source, now.Add(probeRateWindow)) {
		t.Fatal("a new window must admit the source again")
	}
}

// One flooder must not eat the budget of every other peer.
func TestProbeRateLimiterKeepsSourcesIndependent(t *testing.T) {
	limiter := newPeerUDPProbeRateLimiter()
	now := time.Now()
	flooder := net.IPv4(203, 0, 113, 41)
	peer := net.IPv4(203, 0, 113, 42)

	for i := 0; i < probeSourcePacketsPerWindow*2; i++ {
		limiter.tryAcquire(flooder, now)
	}
	if limiter.tryAcquire(flooder, now) {
		t.Fatal("the flooder should be over its per-source budget")
	}
	if !limiter.tryAcquire(peer, now) {
		t.Fatal("an unrelated peer must still be admitted")
	}
}

func TestProbeRateLimiterBoundsTheGlobalWindow(t *testing.T) {
	limiter := newPeerUDPProbeRateLimiter()
	now := time.Now()

	allowed := 0
	// Distinct sources, each well inside its own budget: only the global window can stop this.
	for i := 0; i < probeGlobalPacketsPerWindow+500; i++ {
		source := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i))
		if limiter.tryAcquire(source, now) {
			allowed++
		}
	}
	if allowed > probeGlobalPacketsPerWindow {
		t.Fatalf("allowed %d probes, global cap is %d", allowed, probeGlobalPacketsPerWindow)
	}
	if allowed == 0 {
		t.Fatal("the limiter rejected everything")
	}
}

// A flood of distinct addresses must not grow the table without bound.
func TestProbeRateLimiterBoundsTheSourceTable(t *testing.T) {
	limiter := newPeerUDPProbeRateLimiter()
	now := time.Now()

	for i := 0; i < probeMaxTrackedSources*2; i++ {
		// Spread across windows so the global cap does not stop the walk early.
		at := now.Add(time.Duration(i) * probeRateWindow)
		limiter.tryAcquire(net.IPv4(172, byte(i>>16), byte(i>>8), byte(i)), at)
	}
	if count := limiter.sourceCount(); count > probeMaxTrackedSources {
		t.Fatalf("tracked %d sources, cap is %d", count, probeMaxTrackedSources)
	}
}

func TestProbeRateLimiterExpiresIdleSources(t *testing.T) {
	limiter := newPeerUDPProbeRateLimiter()
	now := time.Now()
	limiter.tryAcquire(net.IPv4(198, 51, 100, 7), now)
	if limiter.sourceCount() != 1 {
		t.Fatalf("sourceCount = %d, want 1", limiter.sourceCount())
	}

	limiter.cleanup(now.Add(probeSourceTTL / 2))
	if limiter.sourceCount() != 1 {
		t.Fatal("a source seen recently must be kept")
	}
	limiter.cleanup(now.Add(probeSourceTTL + time.Second))
	if limiter.sourceCount() != 0 {
		t.Fatalf("sourceCount = %d, want the idle source expired", limiter.sourceCount())
	}
}

func TestProbeRateLimiterNormalizesAndTolerates(t *testing.T) {
	limiter := newPeerUDPProbeRateLimiter()
	now := time.Now()

	// The same host as IPv4 and as IPv4-mapped IPv6 shares one budget.
	v4 := net.IPv4(192, 0, 2, 33)
	mapped := net.IP(append([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}, 192, 0, 2, 33))
	limiter.tryAcquire(v4, now)
	limiter.tryAcquire(mapped, now)
	if count := limiter.sourceCount(); count != 1 {
		t.Fatalf("sourceCount = %d, want the mapped address folded onto the IPv4 one", count)
	}

	// A missing source is refused rather than tracked, and a nil limiter allows everything.
	if limiter.tryAcquire(nil, now) {
		t.Fatal("a probe with no source address must not be admitted")
	}
	var absent *peerUDPProbeRateLimiter
	if !absent.tryAcquire(v4, now) {
		t.Fatal("a nil limiter must allow probes")
	}
	absent.cleanup(now)
	if absent.sourceCount() != 0 {
		t.Fatal("a nil limiter tracks nothing")
	}
}
