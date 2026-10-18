package peermesh

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

type closeCommitFixture struct {
	db      *store.DB
	raw     *sql.DB
	service *Service
	source  store.ClientAccount
	ids     []int64
}

func newCloseCommitFixture(t *testing.T, count int) closeCommitFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "close-commit.db")
	db, err := store.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	service := newPeerMeshTestService(db)
	source := insertPeerClient(t, db, 1001, "tenant-a", "alice", "close-source")
	insertPeerDevice(t, db, source, "100.96.0.10", "source-key")
	f := closeCommitFixture{db: db, raw: raw, service: service, source: source}
	for i := 0; i < count; i++ {
		target := insertPeerClient(t, db, 1002+int64(i), "tenant-a", "alice", fmt.Sprintf("close-target-%d", i))
		insertPeerDevice(t, db, target, fmt.Sprintf("100.96.0.%d", 11+i), "target-key")
		grant, err := service.CreateSession(context.Background(), source, target, PathDirect)
		if err != nil {
			t.Fatal(err)
		}
		id := grant.session.ID
		if _, err := service.ReportPath(context.Background(), source, ControlMessage{SessionID: &id, Status: StatusActive}); err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(`UPDATE peer_mesh_session SET direct_bytes=11,relay_bytes=22 WHERE id=?`, id); err != nil {
			t.Fatal(err)
		}
		service.cacheRelayAuthorization(*getPeerSession(t, db, id), time.Now())
		service.addPendingRelayBytes(id, 19)
		f.ids = append(f.ids, id)
	}
	return f
}

func assertCloseNotCommitted(t *testing.T, f closeCommitFixture) {
	t.Helper()
	for _, id := range f.ids {
		row := getPeerSession(t, f.db, id)
		if row.Status != StatusActive || row.ClosedAt != nil || row.DirectBytes != 11 || row.RelayBytes != 22 {
			t.Errorf("failed close changed SQL: %+v", row)
		}
		if token, ok := f.service.getCachedSessionToken(id); !ok || token == "" {
			t.Errorf("failed close evicted token: %d", id)
		}
		f.service.relayMu.Lock()
		pending := f.service.pendingRelayBytes[id]
		f.service.relayMu.Unlock()
		if pending != 19 {
			t.Errorf("failed close lost pending bytes: id=%d got=%d", id, pending)
		}
	}
}

func TestPeerCloseFailurePreservesSQLTokensAndPendingTraffic(t *testing.T) {
	for _, mode := range []string{"client", "managed", "path", "traffic-expired", "cleanup-expired", "probe-expired", "relay-expired", "flush-expired"} {
		t.Run(mode, func(t *testing.T) {
			f := newCloseCommitFixture(t, 1)
			id := f.ids[0]
			if mode != "client" && mode != "managed" && mode != "path" {
				if _, err := f.raw.Exec(`UPDATE peer_mesh_session SET expires_at=? WHERE id=?`, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano), id); err != nil {
					t.Fatal(err)
				}
				f.service.cacheRelayAuthorization(*getPeerSession(t, f.db, id), time.Now())
			}
			if _, err := f.raw.Exec(`CREATE TRIGGER reject_close BEFORE UPDATE ON peer_mesh_session WHEN NEW.status='CLOSED' BEGIN SELECT RAISE(ABORT,'injected close failure'); END`); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			var err error
			switch mode {
			case "client":
				_, err = f.service.CloseSessionFromClient(ctx, f.source, ControlMessage{SessionID: &id})
			case "managed":
				_, err = f.service.ForceClose(ctx, AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true, BuiltIn: true}, id)
			case "path":
				_, err = f.service.ReportPath(ctx, f.source, ControlMessage{SessionID: &id, Status: StatusClosed})
			case "traffic-expired":
				_, err = f.service.ReportTraffic(ctx, f.source, ControlMessage{SessionID: &id, RelayBytes: 10})
			case "cleanup-expired":
				_, err = f.service.expireStaleSessions(ctx, 100)
			case "flush-expired":
				err = f.service.FlushRelayTraffic(ctx)
			case "probe-expired":
				token, _ := f.service.getCachedSessionToken(id)
				if f.service.AuthorizeRelayProbe(ctx, relayProbe{Type: peerProbeTypeCheck, SessionID: id, FromClientID: f.source.ID, ToClientID: 1002, Token: token}) {
					t.Error("expired probe admitted")
				}
			case "relay-expired":
				if f.service.AuthorizeRelayFrame(ctx, DataFrameHeader{SessionID: id}, f.source.ID, 1002, 10) {
					t.Error("expired frame admitted")
				}
			}
			if mode != "probe-expired" && mode != "relay-expired" && err == nil {
				t.Fatal("injected SQL close failure was hidden")
			}
			assertCloseNotCommitted(t, f)
		})
	}
}

func TestPeerCloseBatchRollsBackEverySession(t *testing.T) {
	for _, mode := range []string{"all", "device", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			f := newCloseCommitFixture(t, 2)
			if mode == "expiry" {
				if _, err := f.raw.Exec(`UPDATE peer_mesh_session SET expires_at=?`, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.raw.Exec(`CREATE TRIGGER reject_second_close BEFORE UPDATE ON peer_mesh_session WHEN NEW.status='CLOSED' AND (SELECT COUNT(*) FROM peer_mesh_session WHERE status='CLOSED')>=1 BEGIN SELECT RAISE(ABORT,'injected second close failure'); END`); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			access := AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true, BuiltIn: true}
			var err error
			switch mode {
			case "all":
				_, err = f.service.CloseOpenSessions(ctx, access)
			case "device":
				_, err = f.service.CloseOpenSessionsForDevice(ctx, access, f.source.ID)
			case "expiry":
				_, err = f.service.expireStaleSessions(ctx, 100)
			}
			if err == nil {
				t.Fatal("second close failure hidden")
			}
			assertCloseNotCommitted(t, f)
		})
	}
}

func TestPeerCloseDoesNotOverwriteTrafficAtWriteBoundary(t *testing.T) {
	f := newCloseCommitFixture(t, 1)
	if _, err := f.raw.Exec(`CREATE TRIGGER fresh_traffic BEFORE UPDATE ON peer_mesh_session WHEN NEW.status='CLOSED' BEGIN UPDATE peer_mesh_session SET direct_bytes=direct_bytes+100,relay_bytes=relay_bytes+200,rtt_millis=7 WHERE id=OLD.id; END`); err != nil {
		t.Fatal(err)
	}
	id := f.ids[0]
	view, err := f.service.CloseSessionFromClient(context.Background(), f.source, ControlMessage{SessionID: &id})
	if err != nil {
		t.Fatal(err)
	}
	row := getPeerSession(t, f.db, id)
	if row.DirectBytes != 111 || row.RelayBytes != 222 || row.RTTMillis == nil || *row.RTTMillis != 7 {
		t.Fatalf("close overwrote fresh traffic metadata: %+v", row)
	}
	if view.DirectBytes != 111 || view.RelayBytes != 222 {
		t.Fatalf("close returned stale snapshot: %+v", view)
	}
}

func TestPeerRelayFlushFailureRestoresEveryUnprocessedCounter(t *testing.T) {
	f := newCloseCommitFixture(t, 2)
	if _, err := f.raw.Exec(`CREATE TRIGGER reject_flush BEFORE UPDATE ON peer_mesh_session BEGIN SELECT RAISE(ABORT,'injected flush failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := f.service.FlushRelayTraffic(context.Background()); err == nil {
		t.Fatal("flush SQL failure hidden")
	}
	assertCloseNotCommitted(t, f)
}

func TestPeerCloseIgnoredSQLWriteIsNotReportedAsSuccess(t *testing.T) {
	f := newCloseCommitFixture(t, 1)
	if _, err := f.raw.Exec(`CREATE TRIGGER ignore_close BEFORE UPDATE ON peer_mesh_session WHEN NEW.status='CLOSED' BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.ForceClose(context.Background(), AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true, BuiltIn: true}, f.ids[0]); err == nil {
		t.Fatal("unapplied close reported success")
	}
	assertCloseNotCommitted(t, f)
}
