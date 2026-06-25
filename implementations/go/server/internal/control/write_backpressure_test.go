package control

import "testing"

func TestWriteBackpressureGateUsesHighLowWaterMarks(t *testing.T) {
	gate := NewWriteBackpressureGate(10, 20)
	var changes []bool
	unsubscribe := gate.AddListener(func(backpressured bool) {
		changes = append(changes, backpressured)
	})
	defer unsubscribe()

	if tracked := gate.AddPending(19); tracked != 19 {
		t.Fatalf("tracked bytes = %d, want 19", tracked)
	}
	if gate.IsBackpressured() {
		t.Fatal("gate should stay writable below high water mark")
	}

	gate.AddPending(1)
	if !gate.IsBackpressured() {
		t.Fatal("gate should become backpressured at high water mark")
	}
	if got, want := len(changes), 1; got != want || !changes[0] {
		t.Fatalf("changes = %#v, want [true]", changes)
	}

	gate.ReleasePending(9)
	if !gate.IsBackpressured() {
		t.Fatal("gate should remain backpressured above low water mark")
	}

	gate.ReleasePending(1)
	if gate.IsBackpressured() {
		t.Fatal("gate should become writable at low water mark")
	}
	if got, want := len(changes), 2; got != want || changes[1] {
		t.Fatalf("changes = %#v, want [true false]", changes)
	}
}

func TestWriteBackpressureGateNormalizesInvalidWaterMarks(t *testing.T) {
	gate := NewWriteBackpressureGate(-10, -5)
	gate.AddPending(1)
	if !gate.IsBackpressured() {
		t.Fatal("high water mark should normalize above low water mark")
	}
	gate.ReleasePending(1)
	if gate.IsBackpressured() {
		t.Fatal("release should restore writable state")
	}
}
