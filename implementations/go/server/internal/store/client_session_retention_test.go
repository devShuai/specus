package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func retentionTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "retention.db"))
	if err != nil {
		t.Fatalf("open temp db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func seedSession(t *testing.T, db *DB, id int64, status string, loginAt,
	disconnectedAt, expiresAt time.Time) {
	t.Helper()
	session := ClientSession{
		ID: id, TenantID: "default", CredentialID: 1, IdentityID: id, ClientID: 1,
		ClientName: "machine", TokenHash: fmt.Sprintf("hash-%d", id), Status: status,
		MachineFingerprint: "machine", OSUser: "alice", HTTPLoginAt: loginAt, ExpiresAt: expiresAt,
	}
	if !disconnectedAt.IsZero() {
		session.DisconnectedAt = &disconnectedAt
	}
	if err := db.InsertClientSession(context.Background(), session); err != nil {
		t.Fatalf("insert session %d: %v", id, err)
	}
}

// Every reconnect retires a session row, so history has to have a cutoff. What it must never remove
// is a session that could still authenticate, or one inside the retention window.
func TestPurgeDisconnectedClientSessionsRemovesOnlyAgedOutHistory(t *testing.T) {
	db := retentionTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	cutoff := now.AddDate(0, 0, -30)

	old := now.AddDate(0, 0, -60)
	recent := now.AddDate(0, 0, -2)

	seedSession(t, db, 1, "DISCONNECTED", old, old, old.Add(time.Hour))               // aged out
	seedSession(t, db, 2, "DISCONNECTED", recent, recent, recent.Add(time.Hour))      // inside the window
	seedSession(t, db, 3, "NETTY_ONLINE", old, time.Time{}, now.Add(time.Hour))       // still connected
	seedSession(t, db, 4, "HTTP_AUTHENTICATED", old, time.Time{}, now.Add(time.Hour)) // still valid

	purged, err := db.PurgeDisconnectedClientSessions(ctx, cutoff, now)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if purged != 1 {
		t.Fatalf("purged %d sessions, want 1", purged)
	}

	for id, wantPresent := range map[int64]bool{1: false, 2: true, 3: true, 4: true} {
		session, err := db.GetClientSession(ctx, id)
		switch {
		case wantPresent && (err != nil || session == nil):
			t.Fatalf("session %d should have been kept: %v", id, err)
		case !wantPresent && !errors.Is(err, ErrNotFound):
			t.Fatalf("session %d should have been purged, got %+v (err %v)", id, session, err)
		}
	}
}

// An expired session that never recorded a disconnect still has to age out; falling back to the
// login time is what stops those rows living forever.
func TestPurgeDisconnectedClientSessionsFallsBackToTheLoginTime(t *testing.T) {
	db := retentionTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	cutoff := now.AddDate(0, 0, -30)
	old := now.AddDate(0, 0, -90)

	seedSession(t, db, 10, "HTTP_AUTHENTICATED", old, time.Time{}, old.Add(time.Hour))

	purged, err := db.PurgeDisconnectedClientSessions(ctx, cutoff, now)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if purged != 1 {
		t.Fatalf("purged %d sessions, want the expired row removed", purged)
	}
}

func TestPurgeDisconnectedClientSessionsIsANoOpWhenNothingHasAgedOut(t *testing.T) {
	db := retentionTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	seedSession(t, db, 20, "DISCONNECTED", now.Add(-time.Hour), now.Add(-time.Minute), now.Add(-time.Minute))

	purged, err := db.PurgeDisconnectedClientSessions(ctx, now.AddDate(0, 0, -30), now)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if purged != 0 {
		t.Fatalf("purged %d sessions, want 0", purged)
	}
}
