package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

// The route lock of InsertHTTPShare only exists on MySQL and PostgreSQL, which the tests do not
// run. These tests drive the real store method over a database/sql connector that runs nothing:
// it records every statement in order and answers the few rows the creation reads.

type statementRecorder struct {
	mu         sync.Mutex
	statements []string
	routeGone  bool
}

func (r *statementRecorder) record(query string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.statements = append(r.statements, query)
}

func (r *statementRecorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.statements...)
}

func (r *statementRecorder) Connect(context.Context) (driver.Conn, error) {
	return &recordingConn{recorder: r}, nil
}

func (r *statementRecorder) Driver() driver.Driver { return recordingDriver{recorder: r} }

type recordingDriver struct{ recorder *statementRecorder }

func (d recordingDriver) Open(string) (driver.Conn, error) {
	return &recordingConn{recorder: d.recorder}, nil
}

type recordingConn struct{ recorder *statementRecorder }

func (c *recordingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("recording connection: prepared statements are not supported")
}

func (c *recordingConn) Close() error { return nil }

func (c *recordingConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *recordingConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	c.recorder.record("BEGIN")
	return recordingTx{recorder: c.recorder}, nil
}

func (c *recordingConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.recorder.record(query)
	return driver.RowsAffected(1), nil
}

func (c *recordingConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.recorder.record(query)
	switch {
	case strings.Contains(query, "FROM http_route_mapping"):
		if c.recorder.routeGone {
			return &recordedRows{columns: []string{"id"}}, nil
		}
		return &recordedRows{columns: []string{"id"}, values: [][]driver.Value{{int64(42)}}}, nil
	case strings.Contains(query, "COUNT(*)"):
		return &recordedRows{columns: []string{"count"}, values: [][]driver.Value{{int64(0)}}}, nil
	default:
		// The lookup of the drawn share id: no such share yet.
		return &recordedRows{columns: strings.Split(httpShareColumns, ",")}, nil
	}
}

type recordingTx struct{ recorder *statementRecorder }

func (tx recordingTx) Commit() error {
	tx.recorder.record("COMMIT")
	return nil
}

func (tx recordingTx) Rollback() error {
	tx.recorder.record("ROLLBACK")
	return nil
}

type recordedRows struct {
	columns []string
	values  [][]driver.Value
}

func (r *recordedRows) Columns() []string { return r.columns }

func (r *recordedRows) Close() error { return nil }

func (r *recordedRows) Next(dest []driver.Value) error {
	if len(r.values) == 0 {
		return io.EOF
	}
	copy(dest, r.values[0])
	r.values = r.values[1:]
	return nil
}

func insertRecordedShare(t *testing.T, dialect Dialect, routeGone bool) []string {
	t.Helper()
	recorder := &statementRecorder{routeGone: routeGone}
	handle := sql.OpenDB(recorder)
	t.Cleanup(func() { _ = handle.Close() })
	db := &DB{sql: handle, dialect: dialect}
	actor := "alice"
	shareID := "WlpaWlpaWlpaWlpa"
	share := HTTPShare{ShareID: shareID, TenantID: "t1", RouteID: 42, TokenSHA256: strings.Repeat("a", 64),
		Access: "read", PathPrefix: "/", CreatedBy: actor, CreatedAt: 1000, ExpiresAt: 4600}
	audit := HTTPAccessAuditEntry{TenantID: "t1", At: 1000, Actor: &actor, Action: "share.created", RouteID: 42,
		ShareID: &shareID, Detail: "{}"}
	if err := db.InsertHTTPShare(context.Background(), share, 20, 1000, audit); err != nil {
		t.Fatalf("InsertHTTPShare: %v", err)
	}
	return recorder.recorded()
}

func TestInsertHTTPShareLocksTheRouteBeforeCountingOnMySQLAndPostgreSQL(t *testing.T) {
	for _, tc := range []struct {
		dialect Dialect
		lock    string
	}{
		{DialectMySQL, `SELECT id FROM http_route_mapping WHERE id = ? FOR UPDATE`},
		{DialectPostgres, `SELECT id FROM http_route_mapping WHERE id = $1 FOR UPDATE`},
	} {
		t.Run(string(tc.dialect), func(t *testing.T) {
			statements := insertRecordedShare(t, tc.dialect, false)
			if len(statements) < 3 || statements[0] != "BEGIN" || statements[1] != tc.lock {
				t.Fatalf("the transaction must start by locking the route, got %q", statements)
			}
			if !strings.Contains(statements[2], "SELECT COUNT(*) FROM http_share") {
				t.Fatalf("the active shares must be counted right after the lock, got %q", statements[2])
			}
			if statements[len(statements)-1] != "COMMIT" {
				t.Fatalf("the creation must commit, got %q", statements)
			}
		})
	}
}

func TestInsertHTTPShareGoesOnWhenTheLockedRouteIsGone(t *testing.T) {
	statements := insertRecordedShare(t, DialectMySQL, true)
	if statements[len(statements)-1] != "COMMIT" {
		t.Fatalf("a route row missing under the lock must not fail the creation, got %q", statements)
	}
}

func TestInsertHTTPShareDoesNotLockOnSQLite(t *testing.T) {
	statements := insertRecordedShare(t, DialectSQLite, false)
	for _, statement := range statements {
		if strings.Contains(statement, "FOR UPDATE") {
			t.Fatalf("SQLite does not support FOR UPDATE, got %q", statement)
		}
	}
	if len(statements) < 2 || !strings.Contains(statements[1], "SELECT COUNT(*) FROM http_share") {
		t.Fatalf("SQLite counts first, got %q", statements)
	}
}
