package nat

import "testing"

func TestRemotePortManagerTracksTenantCounters(t *testing.T) {
	manager := NewRemotePortManager(1)

	if !manager.TryAcquire("tenant-a") {
		t.Fatal("first connection should be accepted")
	}
	if manager.ActiveExternalConnections() != 1 || manager.ActiveExternalConnectionsByTenant("tenant-a") != 1 {
		t.Fatalf("unexpected active counters: global=%d tenant=%d",
			manager.ActiveExternalConnections(), manager.ActiveExternalConnectionsByTenant("tenant-a"))
	}
	if manager.TryAcquire("tenant-b") {
		t.Fatal("connection above the global limit should be rejected")
	}
	if manager.RejectedExternalConnections() != 1 || manager.RejectedExternalConnectionsByTenant("tenant-b") != 1 {
		t.Fatalf("unexpected rejected counters: global=%d tenant=%d",
			manager.RejectedExternalConnections(), manager.RejectedExternalConnectionsByTenant("tenant-b"))
	}

	manager.ReleaseExternal("tenant-a")
	if manager.ActiveExternalConnections() != 0 || manager.ActiveExternalConnectionsByTenant("tenant-a") != 0 {
		t.Fatalf("unexpected released counters: global=%d tenant=%d",
			manager.ActiveExternalConnections(), manager.ActiveExternalConnectionsByTenant("tenant-a"))
	}
}
