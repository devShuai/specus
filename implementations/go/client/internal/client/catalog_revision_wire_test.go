package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCatalogRevisionWirePublisherReconnect(t *testing.T) {
	directory := os.Getenv("SPECUS_TEST_CATALOG_REVISION_WIRE_DIR")
	producers := []string{"canonical"}
	if directory != "" {
		producers = []string{"java", "go", "dotnet", "c"}
	}
	for _, producer := range producers {
		t.Run(producer, func(t *testing.T) {
			var wire []string
			if directory != "" {
				body, err := os.ReadFile(filepath.Join(directory, producer+".jsonl"))
				if err != nil {
					t.Fatal(err) // Missing actual producers must not fall back to canonical data.
				}
				wire = strings.Split(strings.TrimSpace(string(body)), "\n")
			} else {
				session := int64(7381)
				for revision := int64(1); revision <= 5; revision++ {
					message := peerControlMessage{Type: peerControlTypeServiceCatalog,
						PublisherClientID: 7301, PublisherSessionID: &session, Revision: &revision,
						ExpiresAt: time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano)}
					if revision != 3 && revision != 4 {
						message.Services = []peerAdvertisedService{{ServiceID: "svc-revision", Name: "revision-service",
							Transport: "tcp", Application: "http", PublishedPort: 18080, Path: "/"}}
					}
					body, err := json.Marshal(message)
					if err != nil {
						t.Fatal(err)
					}
					wire = append(wire, string(body))
				}
			}
			if len(wire) != 5 {
				t.Fatalf("want 5 original frames, got %d", len(wire))
			}
			runtime := newPeerServiceRuntime(nil, func(any) error { return nil })
			defer runtime.close()
			runtime.applyConfig(testPeerMeshConfig(true, 1, false))
			messages := make([]peerControlMessage, len(wire))
			counts := []int{1, 1, 0, 0, 1}
			for i, raw := range wire {
				if err := json.Unmarshal([]byte(raw), &messages[i]); err != nil {
					t.Fatal(err)
				}
				message := messages[i]
				if message.Type != peerControlTypeServiceCatalog || message.PublisherClientID <= 0 ||
					message.PublisherSessionID == nil || *message.PublisherSessionID <= 0 ||
					message.PublisherClientID != messages[0].PublisherClientID ||
					*message.PublisherSessionID != *messages[0].PublisherSessionID ||
					message.Revision == nil || *message.Revision != int64(i+1) || len(message.Services) != counts[i] {
					t.Fatalf("unexpected producer frame %d: %s", i, raw)
				}
				if counts[i] != 0 {
					expires, err := time.Parse(time.RFC3339Nano, message.ExpiresAt)
					if err != nil || !expires.After(time.Now()) {
						t.Fatal("captured catalog expired: regenerate producers, do not rewrite wire timestamps")
					}
				}
				runtime.setRoster(map[int64]peerServiceRosterHint{message.PublisherClientID: {virtualIP: "100.96.0.2", online: true}})
				runtime.applyCatalog(message)
				if got := len(runtime.remoteServices()); got != counts[i] {
					t.Fatalf("stage %d: want %d services, got %d", i, counts[i], got)
				}
			}
			runtime.applyCatalog(messages[1])
			runtime.applyCatalog(messages[3])
			if len(runtime.remoteServices()) != 1 {
				t.Fatal("late data/withdrawal rolled back reconnected publisher")
			}
			t.Logf("[catalog-revision-wire] %s -> go PASS (5 stages + 2 stale replays)", producer)
		})
	}
}
