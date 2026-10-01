package main

import (
	"errors"
	"strings"
	"testing"
)

// A failed write must not end publication: the next tick writes again, and the failure and the
// recovery are each said once rather than once a second.
func TestStatePublisherKeepsWritingAfterAFailure(t *testing.T) {
	denied := errors.New("access denied")
	results := []error{nil, denied, denied, nil, nil}
	calls := 0
	var report strings.Builder
	publisher := statePublisher{
		write:  func() error { err := results[calls]; calls++; return err },
		report: &report,
	}
	for range results {
		publisher.tick()
	}
	if calls != len(results) {
		t.Fatalf("wrote %d times, want %d: a failure stopped publication", calls, len(results))
	}
	want := []string{
		"State publication failed (access denied); retrying every second, so status may be stale meanwhile.",
		"State publication recovered.",
	}
	if got := strings.Split(strings.TrimSpace(report.String()), "\n"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("report = %q, want %q", got, want)
	}
}
