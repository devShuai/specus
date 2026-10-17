package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOnlineEgressSessionOrderingVector(t *testing.T) {
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
		data, readErr := os.ReadFile(filepath.Join(directory, "protocol", "test-vectors", "peer-egress-session-order-v1.json"))
		if readErr == nil {
			if err := json.Unmarshal(data, &vector); err != nil {
				t.Fatal(err)
			}
			break
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("session ordering vector not found")
		}
		directory = parent
	}
	if vector.SchemaVersion != 1 || vector.ConsumerIPv6 || len(vector.Cases) != 26 {
		t.Fatal("unexpected session ordering contract")
	}
	provider, connection := "sqlite", filepath.Join(t.TempDir(), "session-order.db")
	if native := os.Getenv("SPECUS_TEST_SESSION_ORDER_MYSQL_DSN"); native != "" {
		provider, connection = "mysql", native
		t.Log("native MySQL database for all 26 persisted ordering vectors")
	}
	db, err := Open(provider, connection)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	for _, example := range vector.Cases {
		t.Run(example.Name, func(t *testing.T) {
			if _, err := db.sql.ExecContext(ctx, "DELETE FROM specus_client_session"); err != nil {
				t.Fatal(err)
			}
			for _, declaration := range example.Sessions {
				at := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
				if err := db.InsertClientSession(ctx, ClientSession{
					ID: declaration.ID, TenantID: declaration.TenantID, ClientID: declaration.ClientID,
					ClientName: "session-order-egress", TokenHash: fmt.Sprintf("session-order-%d", declaration.ID),
					Status: declaration.Status, MachineFingerprint: "fixture-machine", OSUser: "fixture-user",
					HTTPLoginAt: at, NettyConnectedAt: &at, ExpiresAt: at.Add(time.Hour),
					ClientEgressVersion: declaration.Version, ClientEgressDomainTargets: declaration.Domain,
					ClientEgressIPv6Targets: declaration.IPv6,
				}); err != nil {
					t.Fatal(err)
				}
				// Bypass the CURRENT writer's canonical formatting. These are the exact persisted
				// strings a different implementation/older deployment wrote, including corrupt data.
				var connected any
				if declaration.ConnectedAt != nil {
					connected = *declaration.ConnectedAt
				}
				if _, err := db.sql.ExecContext(ctx, "UPDATE specus_client_session SET netty_connected_at = ?, http_login_at = ? WHERE id = ?",
					connected, declaration.HTTPLoginAt, declaration.ID); err != nil {
					t.Fatal(err)
				}
			}
			got, err := db.GetOnlineClientSession(ctx, vector.TenantID, vector.ClientID, vector.Status)
			if err != nil {
				t.Fatal(err)
			}
			if example.Expected.SessionID == nil {
				if got != nil {
					t.Fatalf("unorderable/absent sessions must be unknown, selected %d", got.ID)
				}
				return
			}
			if got == nil || got.ID != *example.Expected.SessionID {
				t.Fatalf("wrong selected session: got %+v, want %d", got, *example.Expected.SessionID)
			}
			version, domain, ipv6 := 0, false, false
			if got.ClientEgressVersion >= 1 {
				version, domain, ipv6 = got.ClientEgressVersion, got.ClientEgressDomainTargets, got.ClientEgressIPv6Targets
			}
			if version != example.Expected.Version || domain != example.Expected.Domain || ipv6 != example.Expected.IPv6 {
				t.Fatalf("mixed or incorrect announcement: version=%d domain=%v ipv6=%v", version, domain, ipv6)
			}
		})
	}
}
