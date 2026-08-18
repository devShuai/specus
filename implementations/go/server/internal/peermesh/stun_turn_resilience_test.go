package peermesh

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestDatagramRateLimiterBoundsPerSourceAndGlobally(t *testing.T) {
	limiter := newDatagramRateLimiter()
	base := time.Now()
	limiter.now = func() time.Time { return base }
	source := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 5000}

	for attempt := 0; attempt < maxDatagramsPerSourcePerWindow; attempt++ {
		if !limiter.allow(source) {
			t.Fatalf("attempt %d should be allowed inside the per-source budget", attempt)
		}
	}
	if limiter.allow(source) {
		t.Fatal("a source must not exceed its per-window budget")
	}
	// A different source still has its own budget inside the same window.
	other := &net.UDPAddr{IP: net.ParseIP("203.0.113.11"), Port: 5000}
	if !limiter.allow(other) {
		t.Fatal("a different source must not inherit another source's exhausted budget")
	}

	// The window rolls over on time, restoring the budget.
	limiter.now = func() time.Time { return base.Add(datagramRateWindow) }
	if !limiter.allow(source) {
		t.Fatal("the per-source budget must reset when the window rolls over")
	}
}

func TestDatagramRateLimiterDeniesNewSourcesWhenTableIsFull(t *testing.T) {
	limiter := newDatagramRateLimiter()
	base := time.Now()
	limiter.now = func() time.Time { return base }
	// Open the window first: the first allow() of a fresh limiter starts a window and rebuilds the
	// source table, which would discard the entries seeded below.
	limiter.windowStart = base
	// Fill the table so an unseen source cannot grow it further.
	for index := 0; index < maxTrackedDatagramSources; index++ {
		limiter.sources[net.IPv4(10, byte(index>>16), byte(index>>8), byte(index)).String()] =
			datagramWindow{started: base, count: 1}
	}
	if limiter.allow(&net.UDPAddr{IP: net.ParseIP("203.0.113.99"), Port: 1}) {
		t.Fatal("a new source must be denied once the tracking table is full")
	}
	// A source already in the table keeps working.
	known := net.IPv4(10, 0, 0, 0).String()
	limiter.sources[known] = datagramWindow{started: base, count: 1}
	if !limiter.allow(&net.UDPAddr{IP: net.ParseIP(known), Port: 1}) {
		t.Fatal("an already tracked source must keep its budget when the table is full")
	}
}

func TestDatagramRateLimiterAllowsNilAddressWithoutPanic(t *testing.T) {
	limiter := newDatagramRateLimiter()
	if !limiter.allow(nil) {
		t.Fatal("a datagram with no resolvable source must still be admitted once")
	}
	var absent *datagramRateLimiter
	if !absent.allow(nil) {
		t.Fatal("an unconfigured limiter must admit everything")
	}
}

func TestTransientReceiveErrorClassification(t *testing.T) {
	// ICMP unreachable and friends describe one datagram, not a dead socket.
	for _, errno := range []syscall.Errno{
		syscall.ECONNRESET,
		syscall.ECONNREFUSED,
		syscall.EHOSTUNREACH,
		syscall.ENETUNREACH,
		syscall.EMSGSIZE,
	} {
		err := &net.OpError{Op: "read", Err: os.NewSyscallError("recvfrom", errno)}
		if !transientReceiveError(err) {
			t.Fatalf("errno %v should be treated as transient", errno)
		}
	}
	// A closed socket must end the loop.
	if transientReceiveError(net.ErrClosed) {
		t.Fatal("a closed socket must not be treated as transient")
	}
	if transientReceiveError(errors.New("boom")) {
		t.Fatal("an unknown error must not be treated as transient")
	}
	if transientReceiveError(nil) {
		t.Fatal("nil must not be treated as transient")
	}
}
