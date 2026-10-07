package productmetrics

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// Section 14: a storage failure is logged with the tenant, the operation and the error class only.
// The error text, which a driver may fill with column values, and the username never reach the log.
func TestStorageFailureLogsOnlyTheErrorClass(t *testing.T) {
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "product-metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	service := New(db, slog.New(slog.NewTextHandler(&logs, nil)))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if response := service.Settings(ctx, Actor{TenantID: "t1", Username: "alice"}); response.Status != http.StatusServiceUnavailable {
		t.Fatalf("settings on a closed store answered %d", response.Status)
	}
	if effect := service.Milestone(ctx, "t1", "alice", StepSignedIn); effect != "ignored" {
		t.Fatalf("milestone on a closed store: %q", effect)
	}
	if effect := service.UserDeleted(ctx, "t1", "alice"); effect != "ignored" {
		t.Fatalf("user deletion on a closed store: %q", effect)
	}
	text := logs.String()
	for _, want := range []string{"operation=settings", "tenant=t1", "step=signed_in", "error=*"} {
		if !strings.Contains(text, want) {
			t.Fatalf("log lacks %q:\n%s", want, text)
		}
	}
	for _, leak := range []string{"closed", "alice"} {
		if strings.Contains(text, leak) {
			t.Fatalf("log contains %q:\n%s", leak, text)
		}
	}
}
