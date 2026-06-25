package server

import (
	"testing"
	"time"
)

func TestConnectionArchiveCutoffUsesUtcDayBoundary(t *testing.T) {
	now := time.Date(2026, 6, 25, 15, 30, 12, 0, time.FixedZone("CST", 8*60*60))

	cutoff, ok := connectionArchiveCutoff(now, 60)
	if !ok {
		t.Fatal("cutoff disabled, want enabled")
	}

	want := time.Date(2026, 4, 26, 0, 0, 0, 0, time.UTC)
	if !cutoff.Equal(want) {
		t.Fatalf("cutoff = %s, want %s", cutoff.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

func TestConnectionArchiveCutoffDisabledWhenRetentionNonPositive(t *testing.T) {
	if cutoff, ok := connectionArchiveCutoff(time.Now(), 0); ok || !cutoff.IsZero() {
		t.Fatalf("cutoff = %s, enabled = %v; want disabled zero time", cutoff, ok)
	}
}
