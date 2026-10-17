package peermesh

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestRuntimePeerObservationUsesCurrentParent(t *testing.T) {
	for _, operation := range []string{"ensure-existing", "report-existing", "ensure-create", "report-create"} {
		t.Run(operation, func(t *testing.T) {
			db := openPeerMeshTestDB(t)
			service := newPeerMeshTestService(db)
			ctx := context.Background()
			before := insertPeerClient(t, db, 71001, "tenant-a", "old-owner", "old-name")
			if operation == "ensure-existing" || operation == "report-existing" {
				insertPeerDevice(t, db, before, "100.96.0.40", "current-key")
			}
			current := before
			current.OwnerUsername, current.ClientName = "new-owner", "new-name"
			if err := db.UpdateClientAndRenameReferences(ctx, current, before.ClientName); err != nil {
				t.Fatal(err)
			}
			if operation == "ensure-existing" || operation == "ensure-create" {
				if _, err := service.EnsureDevice(ctx, before, "fresh-key"); err != nil {
					t.Fatal(err)
				}
			} else {
				natType := "PORT_RESTRICTED"
				if _, err := service.ReportDevice(ctx, before, ControlMessage{NatType: &natType}); err != nil {
					t.Fatal(err)
				}
			}
			device, err := db.FindPeerMeshDeviceByClientID(ctx, current.TenantID, current.ID)
			if err != nil || device == nil {
				t.Fatalf("device absent: %v", err)
			}
			if device.OwnerUsername != current.OwnerUsername || device.ClientName != current.ClientName {
				t.Fatalf("stale runtime snapshot restored peer owner/name: %q/%q", device.OwnerUsername, device.ClientName)
			}
		})
	}
}

func TestRuntimePeerObservationDoesNotRecreateDeletedParent(t *testing.T) {
	for _, operation := range []string{"ensure", "report"} {
		t.Run(operation, func(t *testing.T) {
			db := openPeerMeshTestDB(t)
			service := newPeerMeshTestService(db)
			ctx := context.Background()
			before := insertPeerClient(t, db, 71002, "tenant-a", "owner", "gone-client")
			if err := db.DeleteClient(ctx, before.ID); err != nil {
				t.Fatal(err)
			}
			var err error
			if operation == "ensure" {
				_, err = service.EnsureDevice(ctx, before, "key")
			} else {
				_, err = service.ReportDevice(ctx, before, ControlMessage{})
			}
			if !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("deleted parent must be rejected, got %v", err)
			}
			device, err := db.FindPeerMeshDeviceByClientID(ctx, before.TenantID, before.ID)
			if err != nil || device != nil {
				t.Fatalf("runtime report recreated orphan peer: %+v / %v", device, err)
			}
		})
	}
}

func TestPeerEnabledEditChecksCurrentParentOwner(t *testing.T) {
	db := openPeerMeshTestDB(t)
	service := newPeerMeshTestService(db)
	ctx := context.Background()
	before := insertPeerClient(t, db, 71003, "tenant-a", "old-owner", "owned-client")
	insertPeerDevice(t, db, before, "100.96.0.40", "key")
	current := before
	current.OwnerUsername = "new-owner"
	if err := db.UpdateClient(ctx, current); err != nil {
		t.Fatal(err)
	}
	enabled := false
	user, err := db.InsertManagementUser(ctx, store.ManagementUser{Username: "old-owner", TenantID: before.TenantID,
		Role: store.ManagementRoleUser, Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpdateDevice(ctx, AccessContext{TenantID: before.TenantID, Username: "old-owner", AccountKey: user.AccountKey},
		before.ID, DeviceMutation{Enabled: &enabled}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old owner authorized through stale peer row: %v", err)
	}
	device, err := db.FindPeerMeshDeviceByClientID(ctx, before.TenantID, before.ID)
	if err != nil || device == nil || !device.Enabled {
		t.Fatalf("rejected edit changed device: %+v / %v", device, err)
	}
}

func TestStalePeerSessionWriteCannotReopenClosedGrant(t *testing.T) {
	db := openPeerMeshTestDB(t)
	ctx := context.Background()
	source := insertPeerClient(t, db, 71004, "tenant-a", "owner", "source")
	target := insertPeerClient(t, db, 71005, "tenant-a", "owner", "target")
	insertPeerSession(t, db, 72004, source, target, StatusActive, time.Now().Add(time.Hour))
	stale, err := db.GetPeerMeshSession(ctx, 72004)
	if err != nil {
		t.Fatal(err)
	}
	closed := *stale
	now := time.Now().UTC()
	closed.Status, closed.ClosedAt, closed.UpdatedAt = StatusClosed, &now, now
	if err := db.UpdatePeerMeshSession(ctx, closed); err != nil {
		t.Fatal(err)
	}
	// A path/traffic/relay activation loaded this old row before another transaction closed it.
	// Its error is intentionally not the assertion: durable state must remain closed regardless.
	_ = db.UpdatePeerMeshSession(ctx, *stale)
	current, err := db.GetPeerMeshSession(ctx, stale.ID)
	if err != nil || current.Status != StatusClosed || current.ClosedAt == nil ||
		current.ClosedAt.Sub(now) > time.Microsecond || now.Sub(*current.ClosedAt) > time.Microsecond {
		t.Fatalf("stale update resurrected/rewrote closed grant: %+v / %v", current, err)
	}
}

func TestClosedPeerReportInvalidatesLocalRelayCache(t *testing.T) {
	for _, scenario := range []string{"path-close", "closed-traffic", "closed-path"} {
		t.Run(scenario, func(t *testing.T) {
			db := openPeerMeshTestDB(t)
			service := newPeerMeshTestService(db)
			ctx := context.Background()
			source := insertPeerClient(t, db, 71006, "tenant-a", "owner", "source")
			target := insertPeerClient(t, db, 71007, "tenant-a", "owner", "target")
			const id = int64(72006)
			insertPeerSession(t, db, id, source, target, StatusActive, time.Now().Add(time.Hour))
			item, err := db.GetPeerMeshSession(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			service.cacheRelayAuthorization(*item, now)
			service.cacheSessionToken(id, "held-token")
			header := DataFrameHeader{SessionID: id}
			if !service.authorizeRelayFrameCached(header, source.ID, target.ID, 1, now, false) {
				t.Fatal("fixture has no relay grant")
			}
			if scenario != "path-close" {
				item.Status, item.ClosedAt = StatusClosed, &now
				if err := db.UpdatePeerMeshSession(ctx, *item); err != nil {
					t.Fatal(err)
				}
			}
			report := ControlMessage{SessionID: int64Ptr(id), Status: StatusClosed, DirectBytes: 3}
			var view SessionView
			if scenario == "closed-traffic" {
				view, err = service.ReportTraffic(ctx, source, report)
			} else {
				view, err = service.ReportPath(ctx, source, report)
			}
			if err != nil || view.Status != StatusClosed {
				t.Fatalf("closed report: %+v / %v", view, err)
			}
			if service.authorizeRelayFrameCached(header, source.ID, target.ID, 1, time.Now(), false) {
				t.Fatal("closed report retained relay authorization")
			}
			if _, ok := service.getCachedSessionToken(id); ok {
				t.Fatal("closed report retained plaintext grant")
			}
			current, err := db.GetPeerMeshSession(ctx, id)
			if err != nil || current.Status != StatusClosed || current.ClosedAt == nil {
				t.Fatalf("closed state not durable: %+v / %v", current, err)
			}
		})
	}
}
