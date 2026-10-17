package management

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestDisconnectReasonsSharedVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "protocol", "test-vectors", "disconnect-reasons-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Version int
		Reasons []struct{ Code, Text string }
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Version != 1 || len(vector.Reasons) != 17 {
		t.Fatal("incomplete disconnect-reason vector")
	}
	seen := map[string]bool{}
	for _, reason := range vector.Reasons {
		if seen[reason.Code] {
			t.Fatalf("duplicate reason %s", reason.Code)
		}
		seen[reason.Code] = true
		t.Run(reason.Code, func(t *testing.T) {
			// Exercise the actual management JSON read model, not a copy of its label table.
			item := connectionItem(store.ConnectionRecord{DisconnectReason: &reason.Code})
			encoded, err := json.Marshal(item)
			if err != nil {
				t.Fatal(err)
			}
			var wire struct{ DisconnectReason, DisconnectReasonText string }
			if err := json.Unmarshal(encoded, &wire); err != nil {
				t.Fatal(err)
			}
			if wire.DisconnectReason != reason.Code || wire.DisconnectReasonText != reason.Text {
				t.Fatalf("got %s", encoded)
			}
		})
	}
	if item := connectionItem(store.ConnectionRecord{}); item.DisconnectReason != nil || item.DisconnectReasonText != nil {
		t.Fatal("an open/unmarked connection acquired a disconnect reason")
	}
	// Preserve Go's forward-compatible raw-code behavior for genuinely unknown future reasons.
	future := "FUTURE_REASON"
	if item := connectionItem(store.ConnectionRecord{DisconnectReason: &future}); item.DisconnectReason == nil || *item.DisconnectReason != future || item.DisconnectReasonText == nil || *item.DisconnectReasonText != "未知" {
		t.Fatal("unknown reason fallback changed")
	}
}
