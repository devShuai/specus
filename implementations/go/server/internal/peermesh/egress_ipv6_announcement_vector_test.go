package peermesh

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

type ipv6AnnouncementVector struct {
	ConsumerIPv6 bool `json:"consumerIpv6DataPlaneEnabled"`
	Login        []struct {
		Name              string
		Capabilities      *EgressCapabilities
		NormalizedVersion int
		Stored            bool
	}
	Catalog []struct {
		Name     string
		Expected bool
		Sessions []struct {
			ID          int64
			TenantID    string
			Status      string
			ConnectedAt time.Time
			Version     int
			IPv6        bool `json:"ipv6TargetCapable"`
		}
	}
}

func loadIPv6AnnouncementVector(t *testing.T) ipv6AnnouncementVector {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		data, readErr := os.ReadFile(filepath.Join(directory, "protocol", "test-vectors", "peer-egress-ipv6-target-announcement-v1.json"))
		if readErr == nil {
			var vector ipv6AnnouncementVector
			if err := json.Unmarshal(data, &vector); err != nil {
				t.Fatal(err)
			}
			if vector.ConsumerIPv6 || len(vector.Login) != 7 || len(vector.Catalog) != 9 {
				t.Fatal("unexpected shared contract scope")
			}
			return vector
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("shared announcement vector not found")
		}
		directory = parent
	}
}

func TestEgressIPv6AnnouncementNormalizationVector(t *testing.T) {
	for _, example := range loadIPv6AnnouncementVector(t).Login {
		t.Run(example.Name, func(t *testing.T) {
			version, declared := 0, false
			if example.Capabilities != nil {
				version, declared = example.Capabilities.Version, example.Capabilities.IPv6TargetCapable
			}
			if NormalizeEgressVersion(version) != example.NormalizedVersion || EgressIPv6Targets(version, declared) != example.Stored {
				t.Fatal("announcement normalization differs from shared contract")
			}
		})
	}
}

func TestEgressIPv6AnnouncementCatalogVector(t *testing.T) {
	for _, example := range loadIPv6AnnouncementVector(t).Catalog {
		t.Run(example.Name, func(t *testing.T) {
			ctx := context.Background()
			service, db := newEgressTestService(t)
			consumer := insertPeerClient(t, db, 1001, "tenant-a", "alice", "ipv6-vector-consumer")
			egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "ipv6-vector-egress")
			insertPeerDevice(t, db, consumer, "100.96.0.10", "consumer-key")
			insertPeerDevice(t, db, egress, "100.96.0.11", "egress-key")
			upsertTestPolicy(t, service, egress.ID, []int64{consumer.ID}, true)
			for _, declaration := range example.Sessions {
				at := declaration.ConnectedAt
				if err := db.InsertClientSession(ctx, store.ClientSession{
					ID: declaration.ID, TenantID: declaration.TenantID, ClientID: egress.ID, ClientName: egress.ClientName,
					TokenHash: fmt.Sprintf("ipv6-vector-%d", declaration.ID), Status: declaration.Status,
					MachineFingerprint: "fixture-machine", OSUser: "fixture-user",
					ClientEgressVersion: declaration.Version, ClientEgressIPv6Targets: declaration.IPv6,
					HTTPLoginAt: at, NettyConnectedAt: &at, ExpiresAt: time.Now().UTC().Add(time.Hour),
				}); err != nil {
					t.Fatal(err)
				}
			}
			catalog, err := service.BuildEgressCatalog(ctx, consumer, capableClient())
			if err != nil {
				t.Fatal(err)
			}
			if len(catalog.Egresses) != 1 || catalog.Egresses[0].IPv6TargetCapable != example.Expected {
				t.Fatalf("catalog differs: %+v", catalog)
			}
		})
	}
}
