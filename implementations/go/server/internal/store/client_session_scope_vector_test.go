package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOnlineSessionScopeDoesNotUseDatabaseCollation(t *testing.T) {
	var vector struct {
		SchemaVersion int
		ConsumerIPv6  bool `json:"consumerIpv6DataPlaneEnabled"`
		TenantID      string
		ClientID      int64
		Status        string
		Cases         []struct {
			Name     string
			Sessions []struct {
				ID          int64
				TenantID    string
				ClientID    int64
				Status      string
				HTTPLoginAt string
				ConnectedAt *string
				Version     int
				Domain      bool `json:"domainTargetCapable"`
				IPv6        bool `json:"ipv6TargetCapable"`
			}
			Expected struct {
				SessionID *int64
				Version   int
				Domain    bool `json:"domainTargetCapable"`
				IPv6      bool `json:"ipv6TargetCapable"`
			}
		}
	}
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		data, readErr := os.ReadFile(filepath.Join(directory, "protocol", "test-vectors", "peer-egress-session-scope-v1.json"))
		if readErr == nil {
			if err := json.Unmarshal(data, &vector); err != nil {
				t.Fatal(err)
			}
			break
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("session scope vector not found")
		}
		directory = parent
	}
	if vector.SchemaVersion != 1 || vector.ConsumerIPv6 || len(vector.Cases) != 8 {
		t.Fatal("unexpected session scope contract")
	}
	providers := []struct {
		name, provider, connection string
		noCase                     bool
	}{
		{"sqlite-binary", "sqlite", filepath.Join(t.TempDir(), "binary.db"), false},
		{"sqlite-nocase", "sqlite", filepath.Join(t.TempDir(), "nocase.db"), true},
	}
	// The mandatory owned native gate supplies a fresh, dedicated database. Normal
	// offline runs still execute both SQLite collation variants, with no skipped test.
	if connection := os.Getenv("SPECUS_TEST_SESSION_SCOPE_MYSQL_DSN"); connection != "" {
		providers = append(providers, struct {
			name, provider, connection string
			noCase                     bool
		}{"mysql-native", "mysql", connection, false})
	}
	for _, provider := range providers {
		t.Run(provider.name, func(t *testing.T) {
			db, err := Open(provider.provider, provider.connection)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			ctx := context.Background()
			var existing int
			if err := db.sql.QueryRow("SELECT COUNT(*) FROM specus_client_session").Scan(&existing); err != nil || existing != 0 {
				t.Fatal("scope fixture requires an empty owned database", err)
			}
			if provider.noCase {
				var ddl string
				if err := db.sql.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='specus_client_session'").Scan(&ddl); err != nil {
					t.Fatal(err)
				}
				for _, column := range []string{"tenant_id", "status"} {
					before := column + " TEXT NOT NULL"
					if !strings.Contains(ddl, before) {
						t.Fatal("scope fixture column missing", column)
					}
					ddl = strings.Replace(ddl, before, column+" TEXT COLLATE NOCASE NOT NULL", 1)
				}
				// Only the empty test-owned session table is recreated. No production
				// schema or collation changes are part of the fix.
				if _, err := db.sql.Exec("DROP TABLE specus_client_session"); err != nil {
					t.Fatal(err)
				}
				if _, err := db.sql.Exec(ddl); err != nil {
					t.Fatal(err)
				}
			}
			for _, example := range vector.Cases {
				t.Run(example.Name, func(t *testing.T) {
					if _, err := db.sql.ExecContext(ctx, "DELETE FROM specus_client_session"); err != nil {
						t.Fatal(err)
					}
					for _, declaration := range example.Sessions {
						at := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
						if err := db.InsertClientSession(ctx, ClientSession{ID: declaration.ID, TenantID: declaration.TenantID, ClientID: declaration.ClientID,
							ClientName: "scope-egress", TokenHash: fmt.Sprintf("scope-session-%d", declaration.ID), Status: declaration.Status,
							MachineFingerprint: "fixture-machine", OSUser: "fixture-user", HTTPLoginAt: at, NettyConnectedAt: &at, ExpiresAt: at.Add(time.Hour),
							ClientEgressVersion: declaration.Version, ClientEgressDomainTargets: declaration.Domain, ClientEgressIPv6Targets: declaration.IPv6}); err != nil {
							t.Fatal(err)
						}
						var connected any
						if declaration.ConnectedAt != nil {
							connected = *declaration.ConnectedAt
						}
						// Preserve tenant/status bytes too: the login writer intentionally
						// normalizes tenant input, unlike already-persisted foreign data.
						if _, err := db.sql.ExecContext(ctx, db.rebind("UPDATE specus_client_session SET tenant_id=?, status=?, netty_connected_at=?, http_login_at=? WHERE id=?"),
							declaration.TenantID, declaration.Status, connected, declaration.HTTPLoginAt, declaration.ID); err != nil {
							t.Fatal(err)
						}
					}
					got, err := db.GetOnlineClientSession(ctx, vector.TenantID, vector.ClientID, vector.Status)
					if err != nil {
						t.Fatal(err)
					}
					if example.Expected.SessionID == nil {
						if got != nil {
							t.Fatalf("out-of-scope or unorderable rows selected session %d", got.ID)
						}
						return
					}
					if got == nil || got.ID != *example.Expected.SessionID {
						t.Fatalf("wrong selected session: got %+v, want %d", got, *example.Expected.SessionID)
					}
					if got.ClientEgressVersion != example.Expected.Version || got.ClientEgressDomainTargets != example.Expected.Domain || got.ClientEgressIPv6Targets != example.Expected.IPv6 {
						t.Fatal("foreign scope supplied announcement")
					}
				})
			}
		})
	}
}
