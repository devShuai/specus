package productmetrics

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// Section 9: steps 1 and 4 decide on the switch when they delete, not on the switches the sweep
// read first. A tenant that is off and purged in that snapshot but switched back on before the
// deletes keeps the progress and counts it collected since.
func TestSweepKeepsWhatATenantSwitchedBackOnCollects(t *testing.T) {
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "product-metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	service := New(db, nil)
	service.SetClock(func() time.Time { return time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC) })
	admin := Actor{TenantID: "t1", Username: "admin", Admin: true}
	on := []byte(`{"enabled":true,"disclosureVersion":1}`)
	for _, step := range []func() Response{
		func() Response { return service.PutSettings(ctx, admin, on) },
		func() Response { return service.PutSettings(ctx, admin, []byte(`{"enabled":false}`)) },
		func() Response { return service.Purge(ctx, admin) },
	} {
		if response := step(); response.Status != http.StatusOK {
			t.Fatalf("setup answered %d", response.Status)
		}
	}
	switches, err := db.ProductMetrics().Switches(ctx)
	if err != nil || len(switches) != 1 || switches[0].Enabled || switches[0].PurgedAtMs == nil {
		t.Fatalf("snapshot: %+v %v", switches, err)
	}

	// Between the snapshot and the deletes: switched back on, then a transfer, a started account
	// and a completed one.
	if response := service.PutSettings(ctx, admin, on); response.Status != http.StatusOK {
		t.Fatalf("switching on answered %d", response.Status)
	}
	event := `{"mode":"device","path":"direct","sizeBucket":"lt1m","attempt":"first","outcome":"success"}`
	ingest := service.Ingest(ctx, admin, []byte(`{"schemaVersion":1,"events":[`+event+`]}`))
	if ingest.Status != http.StatusOK {
		t.Fatalf("ingest answered %d", ingest.Status)
	}
	for _, step := range []struct{ username, step, effect string }{
		{"bob", StepAccountCreated, "started"},
		{"carol", StepAccountCreated, "started"},
		{"carol", StepServicePublished, "completed"},
	} {
		if effect := service.Milestone(ctx, "t1", step.username, step.step); effect != step.effect {
			t.Fatalf("%s %s: %q", step.username, step.step, effect)
		}
	}

	if err := service.sweep(ctx, switches); err != nil {
		t.Fatal(err)
	}
	metrics := db.ProductMetrics()
	progress, err := metrics.ProgressRows(ctx, "t1")
	if err != nil || len(progress) != 1 || progress[0].Username != "bob" {
		t.Fatalf("progress after the sweep: %+v %v", progress, err)
	}
	cohorts, err := metrics.OnboardingCounts(ctx, "t1", "", "")
	if err != nil || len(cohorts) != 1 || cohorts[0].Users != 1 {
		t.Fatalf("onboarding counts after the sweep: %+v %v", cohorts, err)
	}
	transfers, err := metrics.TransferCounts(ctx, "t1", "", "")
	if err != nil || len(transfers) != 1 || transfers[0].Count != 1 {
		t.Fatalf("transfer counts after the sweep: %+v %v", transfers, err)
	}

	// When the deployment does not allow metrics no tenant collects: step 1 drops the row although
	// the tenant's switch is on.
	service.SetAllowed(false)
	if err := service.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if progress, err := metrics.ProgressRows(ctx, "t1"); err != nil || len(progress) != 0 {
		t.Fatalf("progress after a sweep the deployment disallows: %+v %v", progress, err)
	}
}

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
