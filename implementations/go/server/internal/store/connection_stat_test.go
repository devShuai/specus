package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestArchiveOldConnectionsKeepsTenantScopedStats(t *testing.T) {
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "connection-stat.db"))
	if err != nil {
		t.Fatalf("open temp db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	connectedAt := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	clientA := int64(101)
	clientB := int64(202)
	if _, err := db.InsertConnectionRecord(ctx, ConnectionRecord{
		TenantID:    "tenant-a",
		ClientID:    &clientA,
		ClientName:  "shared-client",
		ConnectedAt: connectedAt,
		Success:     true,
	}); err != nil {
		t.Fatalf("insert tenant-a connection: %v", err)
	}
	if _, err := db.InsertConnectionRecord(ctx, ConnectionRecord{
		TenantID:    "tenant-b",
		ClientID:    &clientB,
		ClientName:  "shared-client",
		ConnectedAt: connectedAt.Add(time.Hour),
		Success:     false,
	}); err != nil {
		t.Fatalf("insert tenant-b connection: %v", err)
	}

	archived, err := db.ArchiveOldConnections(ctx, time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("archive connections: %v", err)
	}
	if archived != 2 {
		t.Fatalf("archived = %d, want 2", archived)
	}

	tenantA, err := db.ListConnectionStatsScoped(ctx, "tenant-a", "", nil, 10)
	if err != nil {
		t.Fatalf("list tenant-a stats: %v", err)
	}
	if len(tenantA) != 1 || tenantA[0].TenantID != "tenant-a" || tenantA[0].ClientID == nil ||
		*tenantA[0].ClientID != clientA || tenantA[0].TotalCount != 1 || tenantA[0].SuccessCount != 1 ||
		tenantA[0].FailureCount != 0 {
		t.Fatalf("tenant-a stats mismatch: %+v", tenantA)
	}

	tenantB, err := db.ListConnectionStatsScoped(ctx, "tenant-b", "", []int64{clientB}, 10)
	if err != nil {
		t.Fatalf("list tenant-b stats: %v", err)
	}
	if len(tenantB) != 1 || tenantB[0].TenantID != "tenant-b" || tenantB[0].ClientID == nil ||
		*tenantB[0].ClientID != clientB || tenantB[0].TotalCount != 1 || tenantB[0].SuccessCount != 0 ||
		tenantB[0].FailureCount != 1 {
		t.Fatalf("tenant-b stats mismatch: %+v", tenantB)
	}

	hidden, err := db.ListConnectionStatsScoped(ctx, "tenant-b", "", []int64{clientA}, 10)
	if err != nil {
		t.Fatalf("list hidden tenant-b stats: %v", err)
	}
	if len(hidden) != 0 {
		t.Fatalf("hidden stats len = %d, want 0: %+v", len(hidden), hidden)
	}
}
