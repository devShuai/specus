package store

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func ownerJournalProviderContract(t *testing.T, db *DB, ctx context.Context) {
	t.Helper()
	node, other := strings.Repeat("a", 32), strings.Repeat("b", 32)
	insert := func(id int64) OwnerTransferEvent {
		event := OwnerTransferEvent{id, "journal-tenant", `{"affectedClientIds":[821001]}`}
		_, err := db.sql.ExecContext(ctx, db.rebind(`INSERT INTO client_owner_transfer_audit(id,tenant_id,occurred_at,actor,scope,path_id,target_username,detail_json) VALUES(?,?,'2026-10-16T00:00:00Z','journal-actor','single',821001,'journal-target',?)`), id, event.TenantID, event.DetailJSON)
		if err != nil {
			t.Fatal(err)
		}
		return event
	}
	high := insert(891010)
	if err := db.AcknowledgeOwnerTransferEvent(ctx, node, high); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := db.sql.QueryRowContext(ctx, db.rebind(`SELECT processed_at FROM client_owner_transfer_receipt WHERE node_id=? AND event_id=?`), node, high.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := db.AcknowledgeOwnerTransferEvent(ctx, node, high); err != nil {
		t.Fatal(err)
	}
	var after string
	if err := db.sql.QueryRowContext(ctx, db.rebind(`SELECT processed_at FROM client_owner_transfer_receipt WHERE node_id=? AND event_id=?`), node, high.ID).Scan(&after); err != nil || before != after {
		t.Fatalf("idempotent receipt changed: %q %q %v", before, after, err)
	}
	if event, err := db.FindPendingOwnerTransferEvent(ctx, node, high.ID); err != nil || event != nil {
		t.Fatalf("acknowledged still pending: %+v %v", event, err)
	}
	if event, err := db.FindPendingOwnerTransferEvent(ctx, other, high.ID); err != nil || event == nil {
		t.Fatalf("another process lost event: %+v %v", event, err)
	}
	low := insert(891009)
	if events, err := db.PendingOwnerTransferEvents(ctx, node, high.ID); err != nil || len(events) != 0 {
		t.Fatalf("after query mismatch: %+v %v", events, err)
	}
	if events, err := db.PendingOwnerTransferEvents(ctx, node, 0); err != nil || len(events) != 1 || events[0].ID != low.ID {
		t.Fatalf("late lower ID lost: %+v %v", events, err)
	}
	wrong := low
	wrong.TenantID = "JOURNAL-TENANT"
	if err := db.AcknowledgeOwnerTransferEvent(ctx, node, wrong); err == nil {
		t.Fatal("case-distinct tenant acknowledged")
	}
	wrong = low
	wrong.DetailJSON = `{"affectedClientIds":[]}`
	if err := db.AcknowledgeOwnerTransferEvent(ctx, node, wrong); err == nil {
		t.Fatal("changed event acknowledged")
	}
	if event, err := db.FindPendingOwnerTransferEvent(ctx, node, low.ID); err != nil || event == nil {
		t.Fatalf("failed ack consumed event: %+v %v", event, err)
	}
	if _, err := db.PendingOwnerTransferEvents(ctx, "remote-node", 0); err == nil {
		t.Fatal("invalid process identity accepted")
	}
	if db.dialect != DialectSQLite {
		faultNode := strings.Repeat("f", 32)
		if _, err := db.sql.ExecContext(ctx, `ALTER TABLE client_owner_transfer_receipt ADD CONSTRAINT ck_owner_journal_ack_failure CHECK (node_id<>'`+faultNode+`')`); err != nil {
			t.Fatal(err)
		}
		if err := db.AcknowledgeOwnerTransferEvent(ctx, faultNode, low); err == nil {
			t.Fatal("native receipt failure hidden")
		}
		if event, err := db.FindPendingOwnerTransferEvent(ctx, faultNode, low.ID); err != nil || event == nil {
			t.Fatalf("native failed receipt lost retry: %+v %v", event, err)
		}
		drop := `ALTER TABLE client_owner_transfer_receipt DROP CONSTRAINT ck_owner_journal_ack_failure`
		if db.dialect == DialectMySQL {
			drop = `ALTER TABLE client_owner_transfer_receipt DROP CHECK ck_owner_journal_ack_failure`
		}
		if _, err := db.sql.ExecContext(ctx, drop); err != nil {
			t.Fatal(err)
		}
		if err := db.AcknowledgeOwnerTransferEvent(ctx, faultNode, low); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("native ownership journal contract PASS dialect=%s independent-process/late-low-id/current-event/idempotence/failed-receipt-retry", db.dialect)
}

func TestOwnerJournalReceiptsAndLateCommit(t *testing.T) {
	ownerJournalProviderContract(t, provisionTestDB(t), context.Background())
}

func TestOwnerJournalComesFromCommittedTransferOnly(t *testing.T) {
	db := provisionTestDB(t)
	ctx := context.Background()
	actor := ownerWriteFixture(t, db, 1)
	out, err := db.TransferClientOwnership(ctx, ownerWriteRequest(t, db, actor, OwnerScopeSingle, 1001, "Bob", 899001))
	if err != nil || out.AuditID == nil {
		t.Fatalf("real transfer failed: %+v %v", out, err)
	}
	node := strings.Repeat("c", 32)
	events, err := db.PendingOwnerTransferEvents(ctx, node, 0)
	if err != nil || len(events) != 1 || events[0].ID != *out.AuditID || strings.Contains(events[0].DetailJSON, "secret-marker") {
		t.Fatalf("committed audit mismatch: %+v %v", events, err)
	}
	if _, err := db.sql.Exec(`CREATE TRIGGER ignore_owner_receipt BEFORE INSERT ON client_owner_transfer_receipt BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.AcknowledgeOwnerTransferEvent(ctx, node, events[0]); err == nil {
		t.Fatal("ignored receipt reported success")
	}
	if event, err := db.FindPendingOwnerTransferEvent(ctx, node, *out.AuditID); err != nil || event == nil {
		t.Fatal("ignored receipt lost event")
	}
}

func TestOwnerJournalExternalProvider(t *testing.T) {
	parent, ctx := openOwnedStartupProviderDB(t)
	// Keep the original provider suites' audit/cardinality fixtures untouched. Use a fresh
	// child database on the same explicitly owned server, never delete somebody else's rows.
	name := "specus_startup_237_owner_journal_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if _, err := parent.sql.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	dsn := os.Getenv("SPECUS_TEST_STARTUP_DSN")
	if parent.dialect == DialectMySQL {
		cfg, err := mysql.ParseDSN(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.DBName = name
		dsn = cfg.FormatDSN()
	} else {
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Database = name
		dsn = stdlib.RegisterConnConfig(cfg)
		t.Cleanup(func() { stdlib.UnregisterConnConfig(dsn) })
	}
	db, err := Open(os.Getenv("SPECUS_TEST_STARTUP_PROVIDER"), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ownerJournalProviderContract(t, db, ctx)
}
