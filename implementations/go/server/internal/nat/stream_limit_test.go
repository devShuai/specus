package nat

import (
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/directhttp"
)

// HTTP and WebSocket NAT streams enter through /http/** and never pass the external-connection cap
// that guards raw TCP, so without their own ceiling a single client could hold unbounded streams.
func TestNatStreamLimitCountsEveryStreamKindAgainstThePerClientBudget(t *testing.T) {
	session := &clientSession{
		externals:   make(map[uint32]*externalConn),
		httpStreams: make(map[uint32]*HTTPStream),
		wsStreams:   make(map[uint32]*directhttp.WebSocketSpecus),
		portCounts:  make(map[int]int),
		limits:      Limits{PerClient: 3},
	}

	if session.natStreamLimitReachedLocked() {
		t.Fatal("an idle session must be under its budget")
	}

	// Raw TCP, HTTP and WebSocket streams all consume the same budget.
	session.activeExternal = 1
	session.httpStreams[1] = &HTTPStream{}
	if session.natStreamLimitReachedLocked() {
		t.Fatal("two streams must still be under a budget of three")
	}
	session.wsStreams[2] = &directhttp.WebSocketSpecus{}
	if !session.natStreamLimitReachedLocked() {
		t.Fatal("the third stream must reach the per-client budget")
	}

	// Releasing any kind of stream frees the slot again.
	delete(session.httpStreams, 1)
	if session.natStreamLimitReachedLocked() {
		t.Fatal("closing a stream must free its slot")
	}
}

func TestNatStreamLimitIsDisabledWhenPerClientBudgetIsUnset(t *testing.T) {
	session := &clientSession{
		externals:   make(map[uint32]*externalConn),
		httpStreams: make(map[uint32]*HTTPStream),
		wsStreams:   make(map[uint32]*directhttp.WebSocketSpecus),
		portCounts:  make(map[int]int),
		limits:      Limits{PerClient: 0},
	}
	for id := uint32(0); id < 1000; id++ {
		session.httpStreams[id] = &HTTPStream{}
	}
	if session.natStreamLimitReachedLocked() {
		t.Fatal("a zero budget means unlimited, matching the other NAT limits")
	}
}
