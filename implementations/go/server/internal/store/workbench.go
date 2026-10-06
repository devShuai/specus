package store

import (
	"context"
	"database/sql"
)

// ---- management_workbench_item ----------------------------------------------------------
//
// The service workbench keeps two short lists per management identity (tenant_id + username):
// favourite services and recently opened services. A row holds only the reference (kind and
// object id) and one time in epoch milliseconds; never a name, an address or anything about the
// visit. The bounds, ordering and retention live in the management package; this file only
// reads and writes rows. See protocol/spec/service-workbench.md.

const (
	WorkbenchListFavorite = "favorite"
	WorkbenchListRecent   = "recent"

	WorkbenchKindHTTPRoute   = "http-route"
	WorkbenchKindTCPMapping  = "tcp-mapping"
	WorkbenchKindPeerService = "peer-service"
)

// WorkbenchItem is one stored reference.
type WorkbenchItem struct {
	TenantID string
	Username string
	List     string
	Kind     string
	ObjectID int64
	AtMs     int64
}

// ListWorkbenchItems returns every row of one identity, both lists, in no particular order.
func (db *DB) ListWorkbenchItems(ctx context.Context, tenantID, username string) ([]WorkbenchItem, error) {
	return listWorkbenchItems(ctx, db, db.sql, tenantID, username)
}

// ListAllWorkbenchItems returns every stored row, for tests and diagnostics.
func (db *DB) ListAllWorkbenchItems(ctx context.Context) ([]WorkbenchItem, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT tenant_id, username, list, kind, object_id, at_ms
		FROM management_workbench_item`)
	if err != nil {
		return nil, err
	}
	return scanWorkbenchItems(rows)
}

// InsertWorkbenchItem writes a row as given. The API never calls it; tests use it to place rows
// a race between instances could have left behind.
func (db *DB) InsertWorkbenchItem(ctx context.Context, item WorkbenchItem) error {
	return (&WorkbenchTx{db: db, exec: db.sql}).Insert(ctx, item)
}

// WorkbenchTx runs workbench writes inside one database transaction.
type WorkbenchTx struct {
	db   *DB
	exec sqlExecutor
}

type sqlExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// InWorkbenchTx runs fn in a transaction and commits it when fn returns nil.
func (db *DB) InWorkbenchTx(ctx context.Context, fn func(*WorkbenchTx) error) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(&WorkbenchTx{db: db, exec: tx}); err != nil {
		return err
	}
	return tx.Commit()
}

// Items returns every row of one identity inside the transaction.
func (t *WorkbenchTx) Items(ctx context.Context, tenantID, username string) ([]WorkbenchItem, error) {
	return listWorkbenchItems(ctx, t.db, t.exec, tenantID, username)
}

// Insert adds a row; the caller has checked that the reference is not stored yet.
func (t *WorkbenchTx) Insert(ctx context.Context, item WorkbenchItem) error {
	_, err := t.exec.ExecContext(ctx, t.db.rebind(`INSERT INTO management_workbench_item
		(tenant_id, username, list, kind, object_id, at_ms) VALUES (?, ?, ?, ?, ?, ?)`),
		item.TenantID, item.Username, item.List, item.Kind, item.ObjectID, item.AtMs)
	return err
}

// Touch writes the row or, when the reference is already stored, moves its time to the later of
// the two. An instance whose clock is behind therefore never moves an entry back, and two
// concurrent writes of one reference meet on the primary key instead of adding a second row.
func (t *WorkbenchTx) Touch(ctx context.Context, item WorkbenchItem) error {
	var query string
	switch t.db.dialect {
	case DialectMySQL:
		query = `INSERT INTO management_workbench_item (tenant_id, username, list, kind, object_id, at_ms)
			VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE at_ms = GREATEST(at_ms, VALUES(at_ms))`
	case DialectPostgres:
		query = `INSERT INTO management_workbench_item (tenant_id, username, list, kind, object_id, at_ms)
			VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (tenant_id, username, list, kind, object_id)
			DO UPDATE SET at_ms = GREATEST(management_workbench_item.at_ms, EXCLUDED.at_ms)`
	default:
		query = `INSERT INTO management_workbench_item (tenant_id, username, list, kind, object_id, at_ms)
			VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (tenant_id, username, list, kind, object_id)
			DO UPDATE SET at_ms = MAX(at_ms, excluded.at_ms)`
	}
	_, err := t.exec.ExecContext(ctx, t.db.rebind(query),
		item.TenantID, item.Username, item.List, item.Kind, item.ObjectID, item.AtMs)
	return err
}

// Delete removes one reference of one identity's list; absent rows are not an error.
func (t *WorkbenchTx) Delete(ctx context.Context, tenantID, username, list, kind string, objectID int64) error {
	_, err := t.exec.ExecContext(ctx, t.db.rebind(`DELETE FROM management_workbench_item
		WHERE tenant_id = ? AND username = ? AND list = ? AND kind = ? AND object_id = ?`),
		tenantID, username, list, kind, objectID)
	return err
}

// Clear removes one list of one identity.
func (t *WorkbenchTx) Clear(ctx context.Context, tenantID, username, list string) error {
	_, err := t.exec.ExecContext(ctx, t.db.rebind(`DELETE FROM management_workbench_item
		WHERE tenant_id = ? AND username = ? AND list = ?`), tenantID, username, list)
	return err
}

// SweepWorkbenchRecents deletes every identity's recent entries stored at or before cutoffMs.
// It is idempotent, so any number of instances may run it at the same time.
func (db *DB) SweepWorkbenchRecents(ctx context.Context, cutoffMs int64) (int64, error) {
	result, err := db.sql.ExecContext(ctx, db.rebind(`DELETE FROM management_workbench_item
		WHERE list = ? AND at_ms <= ?`), WorkbenchListRecent, cutoffMs)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// deleteWorkbenchReferences removes every identity's references to one object, so an id handed
// out again later does not inherit them.
func deleteWorkbenchReferences(ctx context.Context, db *DB, exec sqlExecutor, kind string, objectID int64) error {
	_, err := exec.ExecContext(ctx, db.rebind(`DELETE FROM management_workbench_item
		WHERE kind = ? AND object_id = ?`), kind, objectID)
	return err
}

// deleteClientWorkbenchReferences removes every reference to a service the client carries.
func deleteClientWorkbenchReferences(ctx context.Context, db *DB, exec sqlExecutor, clientID int64) error {
	for _, source := range []struct{ kind, table string }{
		{WorkbenchKindHTTPRoute, "http_route_mapping"},
		{WorkbenchKindTCPMapping, "specus_mapping"},
		{WorkbenchKindPeerService, "peer_mesh_shared_service"},
	} {
		if _, err := exec.ExecContext(ctx, db.rebind(`DELETE FROM management_workbench_item
			WHERE kind = ? AND object_id IN (SELECT id FROM `+source.table+` WHERE client_id = ?)`),
			source.kind, clientID); err != nil {
			return err
		}
	}
	return nil
}

func listWorkbenchItems(ctx context.Context, db *DB, exec sqlExecutor, tenantID, username string) ([]WorkbenchItem, error) {
	rows, err := exec.QueryContext(ctx, db.rebind(`SELECT tenant_id, username, list, kind, object_id, at_ms
		FROM management_workbench_item WHERE tenant_id = ? AND username = ?`), tenantID, username)
	if err != nil {
		return nil, err
	}
	return scanWorkbenchItems(rows)
}

func scanWorkbenchItems(rows *sql.Rows) ([]WorkbenchItem, error) {
	defer rows.Close()
	items := make([]WorkbenchItem, 0)
	for rows.Next() {
		var item WorkbenchItem
		if err := rows.Scan(&item.TenantID, &item.Username, &item.List, &item.Kind, &item.ObjectID,
			&item.AtMs); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
