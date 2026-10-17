package ownership

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

type reconcileFunc func(context.Context, string, []int64) error

func (f reconcileFunc) ReconcileOwnership(ctx context.Context, tenant string, ids []int64) error {
	return f(ctx, tenant, ids)
}

func journalFixture(t *testing.T) (*store.DB, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ownership.db")
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
	return db, raw
}
func insertEvent(t *testing.T, raw *sql.DB, id int64, detail string) {
	t.Helper()
	if _, err := raw.Exec(`INSERT INTO client_owner_transfer_audit(id,tenant_id,occurred_at,actor,scope,path_id,target_username,detail_json) VALUES(?,'default','2026-10-16','admin','single',1001,'bob',?)`, id, detail); err != nil {
		t.Fatal(err)
	}
}
func newNotifications(t *testing.T, db *store.DB, fn reconcileFunc, logger *slog.Logger) *Notifications {
	t.Helper()
	n, err := New(db, fn, logger)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestOwnerNotificationsFailureReceiptAndRestart(t *testing.T) {
	db, raw := journalFixture(t)
	ctx := context.Background()
	insertEvent(t, raw, 200, `{"affectedClientIds":[3,1,3],"legacy":"not-to-be-logged"}`)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	calls := 0
	fail := true
	n := newNotifications(t, db, func(ctx context.Context, tenant string, ids []int64) error {
		calls++
		if tenant != "default" || !reflect.DeepEqual(ids, []int64{1, 3}) {
			t.Fatalf("untrusted event scope: %s %+v", tenant, ids)
		}
		// A database call inside reconciliation must work with the real SQLite pool of one:
		// the journal reader must have released its connection, not just its transaction.
		query, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if _, err := db.ListClients(query); err != nil {
			return err
		}
		if fail {
			return errors.New("dsn-secret")
		}
		return nil
	}, logger)
	if err := n.Drain(ctx); err == nil {
		t.Fatal("delivery error hidden")
	}
	if event, err := db.FindPendingOwnerTransferEvent(ctx, n.node, 200); err != nil || event == nil {
		t.Fatal("delivery failure consumed event")
	}
	fail = false
	if _, err := raw.Exec(`CREATE TRIGGER reject_owner_receipt BEFORE INSERT ON client_owner_transfer_receipt BEGIN SELECT RAISE(ABORT,'receipt fault'); END`); err != nil {
		t.Fatal(err)
	}
	if err := n.Drain(ctx); err == nil {
		t.Fatal("receipt fault hidden")
	}
	if _, err := raw.Exec(`DROP TRIGGER reject_owner_receipt`); err != nil {
		t.Fatal(err)
	}
	if err := n.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("failed effect/receipt not replayed: %d", calls)
	}
	if err := n.Drain(ctx); err != nil || calls != 3 {
		t.Fatal("successful receipt repeated on same process")
	}
	otherCalls := 0
	other := newNotifications(t, db, func(context.Context, string, []int64) error { otherCalls++; return nil }, logger)
	if other.node == n.node {
		t.Fatal("process identity reused")
	}
	if err := other.Drain(ctx); err != nil || otherCalls != 1 {
		t.Fatalf("new process did not replay committed history: %v %d", err, otherCalls)
	}
	insertEvent(t, raw, 100, `{"affectedClientIds":[]}`)
	if err := other.Drain(ctx); err != nil || otherCalls != 2 {
		t.Fatal("late lower ID missed by cursor")
	}
	if strings.Contains(logs.String(), "dsn-secret") || strings.Contains(logs.String(), "not-to-be-logged") {
		t.Fatalf("notification logs disclosed payload: %s", logs.String())
	}
}

func TestOwnerNotificationsPoisonPageDoesNotStarveLaterCommits(t *testing.T) {
	db, raw := journalFixture(t)
	for id := int64(1); id <= 32; id++ {
		insertEvent(t, raw, id, `{"affectedClientIds":["1"]}`)
	}
	insertEvent(t, raw, 33, `{"affectedClientIds":[7]}`)
	called := 0
	n := newNotifications(t, db, func(_ context.Context, _ string, ids []int64) error { called++; return nil }, nil)
	if err := n.Drain(context.Background()); err == nil || called != 0 {
		t.Fatal("malformed IDs accepted")
	}
	if err := n.Drain(context.Background()); err != nil || called != 1 {
		t.Fatalf("poison page starved next event: %v calls=%d", err, called)
	}
	if event, err := db.FindPendingOwnerTransferEvent(context.Background(), n.node, 1); err != nil || event == nil {
		t.Fatal("poison event silently acknowledged")
	}
}

func TestOwnerNotificationsValidateCompleteClientList(t *testing.T) {
	for _, raw := range []string{`{}`, `null`, `[]`, `{"affectedClientIds":null}`, `{"affectedClientIds":[1.0]}`, `{"affectedClientIds":[1e2]}`, `{"affectedClientIds":["1"]}`, `{"affectedClientIds":[0]}`, `{"affectedClientIds":[-1]}`, `{"affectedClientIds":[9007199254740992]}`, `{"affectedClientIds":[true]}`} {
		t.Run(raw, func(t *testing.T) {
			if ids, err := affectedClients(store.OwnerTransferEvent{DetailJSON: raw}); err == nil {
				t.Fatalf("accepted malformed whole list: %+v", ids)
			}
		})
	}
}

func TestOwnerNotificationsSingleFlightAndCancellation(t *testing.T) {
	db, raw := journalFixture(t)
	insertEvent(t, raw, 1, `{"affectedClientIds":[1]}`)
	entered := make(chan struct{})
	var calls atomic.Int64
	n := newNotifications(t, db, func(ctx context.Context, _ string, _ []int64) error {
		calls.Add(1)
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- n.Drain(ctx) }()
	<-entered
	if err := n.Drain(context.Background()); err != nil || calls.Load() != 1 {
		t.Fatalf("overlapping drains: %v %d", err, calls.Load())
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled reconciliation did not finish")
	}
	if event, err := db.FindPendingOwnerTransferEvent(context.Background(), n.node, 1); err != nil || event == nil {
		t.Fatal("cancelled effect acknowledged")
	}
}

func TestOwnerNotificationsWorkerConsumesCommittedAuditAndStops(t *testing.T) {
	db, raw := journalFixture(t)
	insertEvent(t, raw, 1, `{"affectedClientIds":[1]}`)
	delivered := make(chan struct{}, 1)
	n := newNotifications(t, db, func(context.Context, string, []int64) error {
		select {
		case delivered <- struct{}{}:
		default:
		}
		return nil
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { n.Run(ctx); close(done) }()
	select {
	case <-delivered:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not replay existing audit")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker outlived cancellation")
	}
	for range 100 {
		n.Committed()
	} // coalesced hint cannot block a completed request
}
