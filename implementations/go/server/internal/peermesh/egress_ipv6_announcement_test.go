package peermesh

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestCatalogCarriesCurrentEgressIPv6TargetAnnouncement(t *testing.T) {
	cases := []struct {
		name        string
		status      string
		version     int
		declared    bool
		olderTrue   bool
		foreignTrue bool
		want        bool
	}{
		{"online announced", "NETTY_ONLINE", 1, true, false, false, true},
		{"online false", "NETTY_ONLINE", 1, false, false, false, false},
		{"disconnected declaration", "DISCONNECTED", 1, true, false, false, false},
		{"HTTP authentication is not online", "HTTP_AUTHENTICATED", 1, true, false, false, false},
		{"zero version declaration", "NETTY_ONLINE", 0, true, false, false, false},
		{"newer false does not borrow older true", "NETTY_ONLINE", 1, false, true, false, false},
		{"newer old client clears capability", "NETTY_ONLINE", 0, false, true, false, false},
		{"another tenant cannot lend capability", "NETTY_ONLINE", 1, false, false, true, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			service, db := newEgressTestService(t)
			consumer := insertPeerClient(t, db, 1001, "tenant-a", "alice", "ipv6-consumer")
			egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "ipv6-egress")
			insertPeerDevice(t, db, consumer, "100.96.0.10", "consumer-key")
			insertPeerDevice(t, db, egress, "100.96.0.11", "egress-key")
			upsertTestPolicy(t, service, egress.ID, []int64{consumer.ID}, true)
			now := time.Now().UTC()
			insert := func(id int64, tenant, status string, version int, declared bool, connected time.Time) {
				t.Helper()
				session := store.ClientSession{
					ID: id, TenantID: tenant, ClientID: egress.ID, ClientName: egress.ClientName,
					TokenHash: fmt.Sprintf("ipv6-announcement-%d", id), Status: status,
					MachineFingerprint: "fixture-machine", OSUser: "fixture-user",
					ClientEgressVersion: version, HTTPLoginAt: connected,
					NettyConnectedAt: &connected, ExpiresAt: now.Add(time.Hour),
				}
				// Legacy models ignore this unknown field, reproducing the lost
				// declaration without requiring the production change to compile.
				declaration := fmt.Sprintf(`{"ClientEgressIPv6Targets":%t}`, declared)
				if err := json.Unmarshal([]byte(declaration), &session); err != nil {
					t.Fatal(err)
				}
				if err := db.InsertClientSession(ctx, session); err != nil {
					t.Fatal(err)
				}
			}
			if test.olderTrue {
				insert(91, "tenant-a", "NETTY_ONLINE", 1, true, now.Add(-time.Minute))
			}
			insert(92, "tenant-a", test.status, test.version, test.declared, now)
			if test.foreignTrue {
				insert(93, "tenant-b", "NETTY_ONLINE", 1, true, now.Add(time.Second))
			}
			catalog, err := service.BuildEgressCatalog(ctx, consumer, capableClient())
			if err != nil {
				t.Fatal(err)
			}
			if len(catalog.Egresses) != 1 || catalog.Egresses[0].ClientID != egress.ID {
				t.Fatalf("unexpected catalog: %+v", catalog)
			}
			if got := catalog.Egresses[0].IPv6TargetCapable; got != test.want {
				t.Fatalf("catalog ipv6TargetCapable = %v, want %v", got, test.want)
			}
		})
	}
}
