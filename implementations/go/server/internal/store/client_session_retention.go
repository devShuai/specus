package store

import (
	"context"
	"time"
)

// PurgeDisconnectedClientSessions deletes session history that has aged out.
//
// Every reconnect retires the previous session row rather than reusing it, so a fleet that flaps
// writes rows forever. The live table is on the authentication path — it is read on every login and
// every capability check — so unbounded growth is a latency problem, not just a disk one. Sessions
// that are still usable are never touched: only rows already past `expires_at` and last seen before
// the cutoff are removed, which keeps a bounded window of history for support and auditing.
func (db *DB) PurgeDisconnectedClientSessions(ctx context.Context, cutoff,
	now time.Time) (int64, error) {
	query := db.rebind(`DELETE FROM specus_client_session
		WHERE status <> ?
		  AND expires_at < ?
		  AND COALESCE(disconnected_at, http_login_at) < ?`)
	result, err := db.sql.ExecContext(ctx, query, statusNettyOnline, formatTime(now), formatTime(cutoff))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// statusNettyOnline is duplicated from the auth package to keep the store free of that dependency.
const statusNettyOnline = "NETTY_ONLINE"
