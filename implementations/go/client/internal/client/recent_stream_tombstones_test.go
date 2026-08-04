package client

import "testing"

func TestRecentStreamTombstonesAreBoundedAndRefreshExistingIDs(t *testing.T) {
	tombstones := newRecentStreamTombstones(2)
	tombstones.add(1)
	tombstones.add(2)
	tombstones.add(1)
	tombstones.add(3)

	if !tombstones.contains(1) || !tombstones.contains(3) || tombstones.contains(2) {
		t.Fatal("tombstones did not retain the two most recently closed stream IDs")
	}
	if tombstones.len() != 2 {
		t.Fatalf("tombstone size = %d, want 2", tombstones.len())
	}
	tombstones.clear()
	if tombstones.len() != 0 {
		t.Fatalf("tombstone size after clear = %d, want 0", tombstones.len())
	}
}
