package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientPeerDeletionSharedVector(t *testing.T) {
	var vector struct {
		Version  int
		ClientID int64
		Actor    string
		Setup    []string
		Checks   []struct {
			Name, Query       string
			Deleted, Retained int
		}
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "protocol", "test-vectors", "client-peer-deletion-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Version != 1 || len(vector.Setup) != 7 || len(vector.Checks) != 23 || vector.ClientID != 1001 {
		t.Fatal("incomplete deletion vector")
	}
	sqlFor := func(sql string) string { return strings.ReplaceAll(sql, "client_account", "specus_client_account") }
	for _, audited := range []bool{false, true} {
		for _, rollback := range []bool{false, true} {
			name := "plain"
			if audited {
				name = "audited"
			}
			if rollback {
				name += "-rollback"
			} else {
				name += "-commit"
			}
			t.Run(name, func(t *testing.T) {
				db, err := Open("sqlite", filepath.Join(t.TempDir(), "vector.db"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { db.Close() })
				for _, sql := range vector.Setup {
					if _, err := db.sql.Exec(sqlFor(sql)); err != nil {
						t.Fatal(err)
					}
				}
				if rollback {
					if _, err := db.sql.Exec("CREATE TRIGGER fail_vector_delete BEFORE DELETE ON specus_client_account WHEN OLD.id=1001 BEGIN SELECT RAISE(ABORT,'injected failure'); END"); err != nil {
						t.Fatal(err)
					}
				}
				if audited {
					_, closed, deleteErr := db.DeleteClientAuditedWithPeerSessions(context.Background(), vector.ClientID, vector.Actor, time.Now().Unix(), func(HTTPRouteMapping) string { return "private" })
					err = deleteErr
					if rollback && closed != nil {
						t.Fatal("uncommitted close identities escaped")
					}
					if !rollback && (len(closed) != 1 || closed[0].ID != 40) {
						t.Fatal("committed close identity missing")
					}
				} else {
					err = db.DeleteClient(context.Background(), vector.ClientID)
				}
				if (err == nil) == rollback {
					t.Fatalf("delete outcome mismatch: %v", err)
				}
				for _, check := range vector.Checks {
					want := check.Deleted
					if rollback {
						want = check.Retained
					}
					var got int
					if err := db.sql.QueryRow(sqlFor(check.Query)).Scan(&got); err != nil {
						t.Fatal(err)
					}
					if got != want {
						t.Errorf("%s: got %d want %d", check.Name, got, want)
					}
				}
			})
		}
	}
}
