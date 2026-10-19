package peermesh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

type ipv6PacketAnnouncementVector struct {
	SessionColumn string
	LegacyDefault bool
	Login         []struct {
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
			Targets     bool `json:"ipv6TargetCapable"`
			Packets     bool `json:"ipv6PacketCapable"`
		}
	}
}

func loadIPv6PacketAnnouncementVector(t *testing.T) ipv6PacketAnnouncementVector {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		data, readErr := os.ReadFile(filepath.Join(directory, "protocol", "test-vectors", "peer-egress-ipv6-packet-announcement-v1.json"))
		if readErr == nil {
			var vector ipv6PacketAnnouncementVector
			if err := json.Unmarshal(data, &vector); err != nil {
				t.Fatal(err)
			}
			if vector.SessionColumn != "client_egress_ipv6_packets" || vector.LegacyDefault ||
				len(vector.Login) != 8 || len(vector.Catalog) != 10 {
				t.Fatal("unexpected shared contract scope")
			}
			return vector
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("shared packet announcement vector not found")
		}
		directory = parent
	}
}

func TestEgressIPv6PacketAnnouncementNormalizationVector(t *testing.T) {
	for _, example := range loadIPv6PacketAnnouncementVector(t).Login {
		t.Run(example.Name, func(t *testing.T) {
			version, declared := 0, false
			if example.Capabilities != nil {
				version, declared = example.Capabilities.Version, example.Capabilities.IPv6PacketCapable
			}
			if NormalizeEgressVersion(version) != example.NormalizedVersion || EgressIPv6Packets(version, declared) != example.Stored {
				t.Fatal("packet announcement normalization differs from shared contract")
			}
		})
	}
}

func TestEgressIPv6PacketAnnouncementCatalogVector(t *testing.T) {
	for _, example := range loadIPv6PacketAnnouncementVector(t).Catalog {
		t.Run(example.Name, func(t *testing.T) {
			ctx := context.Background()
			service, db := newEgressTestService(t)
			consumer := insertPeerClient(t, db, 1001, "tenant-a", "alice", "ipv6-packet-vector-consumer")
			egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "ipv6-packet-vector-egress")
			insertPeerDevice(t, db, consumer, "100.96.0.10", "consumer-key")
			insertPeerDevice(t, db, egress, "100.96.0.11", "egress-key")
			upsertTestPolicy(t, service, egress.ID, []int64{consumer.ID}, true)
			for _, declaration := range example.Sessions {
				at := declaration.ConnectedAt
				if err := db.InsertClientSession(ctx, store.ClientSession{
					ID: declaration.ID, TenantID: declaration.TenantID, ClientID: egress.ID, ClientName: egress.ClientName,
					TokenHash: fmt.Sprintf("ipv6-packet-vector-%d", declaration.ID), Status: declaration.Status,
					MachineFingerprint: "fixture-machine", OSUser: "fixture-user",
					ClientEgressVersion:     declaration.Version,
					ClientEgressIPv6Targets: declaration.Targets, ClientEgressIPv6Packets: declaration.Packets,
					HTTPLoginAt: at, NettyConnectedAt: &at, ExpiresAt: time.Now().UTC().Add(time.Hour),
				}); err != nil {
					t.Fatal(err)
				}
			}
			catalog, err := service.BuildEgressCatalog(ctx, consumer, capableClient())
			if err != nil {
				t.Fatal(err)
			}
			if len(catalog.Egresses) != 1 || catalog.Egresses[0].IPv6PacketCapable != example.Expected {
				t.Fatalf("catalog differs: %+v", catalog)
			}
		})
	}
}

// The two IPv6 declarations travel side by side and neither stands in for the other. On the wire
// ipv6PacketCapable follows ipv6TargetCapable, the order the spec gives for an egress-catalog entry.
func TestCatalogCarriesIPv6PacketCapabilityIndependentlyOfIPv6Targets(t *testing.T) {
	cases := []struct {
		name             string
		targets, packets bool
	}{
		{"neither", false, false},
		{"targets only", true, false},
		{"packets only", false, true},
		{"both", true, true},
	}
	for index, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			service, db := newEgressTestService(t)
			consumer := insertPeerClient(t, db, 1001, "tenant-a", "alice", "ipv6-packet-consumer")
			egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "ipv6-packet-egress")
			insertPeerDevice(t, db, consumer, "100.96.0.10", "consumer-key")
			insertPeerDevice(t, db, egress, "100.96.0.11", "egress-key")
			upsertTestPolicy(t, service, egress.ID, []int64{consumer.ID}, true)
			now := time.Now().UTC()
			if err := db.InsertClientSession(ctx, store.ClientSession{
				ID: int64(91 + index), TenantID: "tenant-a", ClientID: egress.ID, ClientName: egress.ClientName,
				TokenHash: fmt.Sprintf("ipv6-packet-%d", index), Status: "NETTY_ONLINE",
				MachineFingerprint: "fixture-machine", OSUser: "fixture-user",
				ClientEgressVersion:     EgressProtocolVersion,
				ClientEgressIPv6Targets: test.targets, ClientEgressIPv6Packets: test.packets,
				HTTPLoginAt: now, NettyConnectedAt: &now, ExpiresAt: now.Add(time.Hour),
			}); err != nil {
				t.Fatal(err)
			}
			catalog, err := service.BuildEgressCatalog(ctx, consumer, capableClient())
			if err != nil {
				t.Fatal(err)
			}
			if len(catalog.Egresses) != 1 {
				t.Fatalf("unexpected catalog: %+v", catalog)
			}
			entry := catalog.Egresses[0]
			if entry.IPv6TargetCapable != test.targets || entry.IPv6PacketCapable != test.packets {
				t.Fatalf("ipv6TargetCapable = %v, ipv6PacketCapable = %v, want %v, %v",
					entry.IPv6TargetCapable, entry.IPv6PacketCapable, test.targets, test.packets)
			}
			encoded, err := json.Marshal(entry)
			if err != nil {
				t.Fatal(err)
			}
			pair := fmt.Sprintf(`"ipv6TargetCapable":%t,"ipv6PacketCapable":%t,`, test.targets, test.packets)
			if !bytes.Contains(encoded, []byte(pair)) {
				t.Fatalf("encoded entry = %s, want %s", encoded, pair)
			}
		})
	}
}
