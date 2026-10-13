package management

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/nat"
	"github.com/devShuai/specus/implementations/go/server/internal/productmetrics"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// Replays protocol/test-vectors/product-metrics-v1.json through the real routing, the shared
// Bearer authentication, the product metrics handlers and a fresh SQLite database per scenario.
// Milestone, user-deletion and sweep ops call the server-internal hooks directly, as the vector
// prescribes; every other op is an HTTP request.

type pmVectorActor struct {
	TenantID string `json:"tenantId"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

type pmVectorSwitch struct {
	TenantID  string  `json:"tenantId"`
	Enabled   bool    `json:"enabled"`
	UpdatedBy *string `json:"updatedBy"`
	UpdatedAt *string `json:"updatedAt"`
	PurgedAt  *string `json:"purgedAt"`
}

type pmVectorProgress struct {
	TenantID            string  `json:"tenantId"`
	Username            string  `json:"username"`
	StartedAt           string  `json:"startedAt"`
	SignedInAt          *string `json:"signedInAt"`
	CredentialCreatedAt *string `json:"credentialCreatedAt"`
	ClientOnlineAt      *string `json:"clientOnlineAt"`
}

type pmVectorOnboarding struct {
	TenantID       string `json:"tenantId"`
	CohortDay      string `json:"cohortDay"`
	ReachedStep    string `json:"reachedStep"`
	DurationBucket string `json:"durationBucket"`
	Users          int64  `json:"users"`
}

type pmVectorTransfer struct {
	TenantID   string `json:"tenantId"`
	Day        string `json:"day"`
	Mode       string `json:"mode"`
	Path       string `json:"path"`
	SizeBucket string `json:"sizeBucket"`
	Attempt    string `json:"attempt"`
	Outcome    string `json:"outcome"`
	Count      int64  `json:"count"`
}

type pmVectorState struct {
	Switches        []pmVectorSwitch     `json:"switches"`
	Progress        []pmVectorProgress   `json:"progress"`
	OnboardingDaily []pmVectorOnboarding `json:"onboardingDaily"`
	TransferDaily   []pmVectorTransfer   `json:"transferDaily"`
}

type pmVectorExpect struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
	Effect string          `json:"effect"`
	State  *pmVectorState  `json:"state"`
}

type pmVectorOp struct {
	Op       string            `json:"op"`
	At       string            `json:"at"`
	Actor    *pmVectorActor    `json:"actor"`
	Body     json.RawMessage   `json:"body"`
	BodyText string            `json:"bodyText"`
	Query    map[string]string `json:"query"`
	TenantID string            `json:"tenantId"`
	Username string            `json:"username"`
	Step     string            `json:"step"`
	Expect   pmVectorExpect    `json:"expect"`
}

type pmVectorLimits struct {
	PerUser   int `json:"perUserEventsPerMinute"`
	PerTenant int `json:"perTenantEventsPerMinute"`
}

type pmVectorScenario struct {
	Name         string         `json:"name"`
	Limits       pmVectorLimits `json:"limits"`
	InitialState pmVectorState  `json:"initialState"`
	Ops          []pmVectorOp   `json:"ops"`
}

type pmVectorFile struct {
	SizeBuckets []struct {
		SizeBytes int64   `json:"sizeBytes"`
		Bucket    *string `json:"bucket"`
	} `json:"sizeBuckets"`
	DurationBuckets []struct {
		Seconds int64   `json:"seconds"`
		Bucket  *string `json:"bucket"`
	} `json:"durationBuckets"`
	Rates []struct {
		Numerator   int64  `json:"numerator"`
		Denominator int64  `json:"denominator"`
		RateBp      *int64 `json:"rateBp"`
	} `json:"rates"`
	IngestValidation struct {
		Context struct {
			Actor pmVectorActor `json:"actor"`
			At    string        `json:"at"`
		} `json:"context"`
		Cases []struct {
			Name      string         `json:"name"`
			BodyText  string         `json:"bodyText"`
			BodyBytes int            `json:"bodyBytes"`
			Expect    pmVectorExpect `json:"expect"`
		} `json:"cases"`
	} `json:"ingestValidation"`
	Scenarios []pmVectorScenario `json:"scenarios"`
}

func readProductMetricsVector(t *testing.T) pmVectorFile {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for depth := 0; depth < 8; depth++ {
		data, err := os.ReadFile(filepath.Join(dir, "protocol", "test-vectors", "product-metrics-v1.json"))
		if err == nil {
			var vector pmVectorFile
			if err := json.Unmarshal(data, &vector); err != nil {
				t.Fatalf("decode vector: %v", err)
			}
			return vector
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("cannot locate protocol/test-vectors/product-metrics-v1.json")
	return pmVectorFile{}
}

func TestProductMetricsVectorBucketsAndRates(t *testing.T) {
	vector := readProductMetricsVector(t)
	for _, item := range vector.SizeBuckets {
		name, ok := productmetrics.SizeBucket(item.SizeBytes)
		if (item.Bucket == nil) == ok || (ok && name != *item.Bucket) {
			t.Fatalf("size %d: got %q %v want %v", item.SizeBytes, name, ok, item.Bucket)
		}
	}
	for _, item := range vector.DurationBuckets {
		name, ok := productmetrics.DurationBucket(item.Seconds)
		if (item.Bucket == nil) == ok || (ok && name != *item.Bucket) {
			t.Fatalf("duration %d: got %q %v want %v", item.Seconds, name, ok, item.Bucket)
		}
	}
	for _, item := range vector.Rates {
		got := productmetrics.RateBp(item.Numerator, item.Denominator)
		if !reflect.DeepEqual(got, item.RateBp) {
			t.Fatalf("rate %d/%d: got %v want %v", item.Numerator, item.Denominator, got, item.RateBp)
		}
	}
	if len(vector.SizeBuckets) == 0 || len(vector.DurationBuckets) == 0 || len(vector.Rates) == 0 {
		t.Fatal("vector has no bucket or rate cases")
	}
}

func TestProductMetricsVectorIngestValidation(t *testing.T) {
	vector := readProductMetricsVector(t)
	cases := vector.IngestValidation.Cases
	if len(cases) == 0 {
		t.Fatal("vector has no validation cases")
	}
	h := newProductMetricsHarness(t)
	actor := vector.IngestValidation.Context.Actor
	h.addActor(actor)
	at := h.instant(vector.IngestValidation.Context.At)
	h.clockMs.Store(at)
	enabledBy := "root"
	if err := h.db.ProductMetrics().SaveSwitch(h.ctx, store.ProductMetricsSwitch{TenantID: actor.TenantID,
		Enabled: true, UpdatedBy: &enabledBy, UpdatedAtMs: &at}); err != nil {
		t.Fatal(err)
	}
	for _, item := range cases {
		if len(item.BodyText) != item.BodyBytes {
			t.Fatalf("%s: body has %d bytes, vector says %d", item.Name, len(item.BodyText), item.BodyBytes)
		}
		h.api.productMetrics.SetLimits(productmetrics.DefaultLimits())
		before := h.transferTotal()
		status, body := h.call(http.MethodPost, "/api/admin/product-metrics/transfer-outcomes", &actor,
			[]byte(item.BodyText))
		h.compare(item.Name, item.Expect, status, body)
		accepted := int64(0)
		if item.Expect.Status == http.StatusOK {
			var answer struct {
				Accepted int64 `json:"accepted"`
			}
			_ = json.Unmarshal(item.Expect.Body, &answer)
			accepted = answer.Accepted
		}
		if after := h.transferTotal(); after != before+accepted {
			t.Fatalf("%s: counted %d events, want %d", item.Name, after-before, accepted)
		}
	}
	t.Logf("replayed %d validation cases", len(cases))
}

func TestProductMetricsVectorScenarios(t *testing.T) {
	vector := readProductMetricsVector(t)
	if len(vector.Scenarios) == 0 {
		t.Fatal("vector has no scenarios")
	}
	var replayed atomic.Int64
	wantOps := 0
	t.Run("scenarios", func(t *testing.T) {
		for _, scenario := range vector.Scenarios {
			wantOps += len(scenario.Ops)
			scenario := scenario
			t.Run(scenario.Name, func(t *testing.T) {
				t.Parallel() // every scenario has its own database, server and limiter
				replayed.Add(int64(replayProductMetricsScenario(t, scenario)))
			})
		}
	})
	if int(replayed.Load()) != wantOps {
		t.Fatalf("replayed %d of %d ops", replayed.Load(), wantOps)
	}
	t.Logf("replayed %d scenarios, %d ops", len(vector.Scenarios), replayed.Load())
}

func replayProductMetricsScenario(t *testing.T, scenario pmVectorScenario) int {
	h := newProductMetricsHarness(t)
	h.api.productMetrics.SetLimits(productmetrics.Limits{PerUserEventsPerMinute: scenario.Limits.PerUser,
		PerTenantEventsPerMinute: scenario.Limits.PerTenant})
	h.load(scenario.InitialState)
	for _, op := range scenario.Ops {
		if op.Actor != nil {
			h.addActor(*op.Actor)
		}
	}
	for index, op := range scenario.Ops {
		label := fmt.Sprintf("%s op %d (%s at %s)", scenario.Name, index, op.Op, op.At)
		h.clockMs.Store(h.instant(op.At))
		switch op.Op {
		case "milestone":
			effect := h.api.productMetrics.Milestone(h.ctx, op.TenantID, op.Username, op.Step)
			if effect != op.Expect.Effect {
				t.Fatalf("%s: effect %q, want %q", label, effect, op.Expect.Effect)
			}
		case "userDeleted":
			effect := h.api.productMetrics.UserDeleted(h.ctx, op.TenantID, op.Username)
			if effect != op.Expect.Effect {
				t.Fatalf("%s: effect %q, want %q", label, effect, op.Expect.Effect)
			}
		case "sweep":
			if err := h.api.productMetrics.Sweep(h.ctx); err != nil {
				t.Fatalf("%s: %v", label, err)
			}
		case "checkpoint":
			h.compareState(label, *op.Expect.State)
		case "getSettings":
			status, body := h.call(http.MethodGet, "/api/admin/product-metrics/settings", op.Actor, nil)
			h.compare(label, op.Expect, status, body)
		case "putSettings":
			status, body := h.call(http.MethodPut, "/api/admin/product-metrics/settings", op.Actor, op.Body)
			h.compare(label, op.Expect, status, body)
		case "purge":
			status, body := h.call(http.MethodDelete, "/api/admin/product-metrics/data", op.Actor, nil)
			h.compare(label, op.Expect, status, body)
		case "ingest":
			status, body := h.call(http.MethodPost, "/api/admin/product-metrics/transfer-outcomes", op.Actor,
				[]byte(op.BodyText))
			h.compare(label, op.Expect, status, body)
		case "summary":
			query := url.Values{}
			for key, value := range op.Query {
				query.Set(key, value)
			}
			path := "/api/admin/product-metrics/summary"
			if len(query) > 0 {
				path += "?" + query.Encode()
			}
			status, body := h.call(http.MethodGet, path, op.Actor, nil)
			h.compare(label, op.Expect, status, body)
		default:
			t.Fatalf("%s: unknown op", label)
		}
	}
	return len(scenario.Ops)
}

// ---- harness ------------------------------------------------------------------------------

type productMetricsHarness struct {
	t       *testing.T
	ctx     context.Context
	db      *store.DB
	api     *API
	server  *httptest.Server
	tokens  *security.LocalTokenService
	clockMs atomic.Int64
	actors  map[string]pmVectorActor
}

func newProductMetricsHarness(t *testing.T) *productMetricsHarness {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "product-metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sessions := session.NewRegistry()
	secret := "product-metrics-test-secret"
	tokens := security.NewLocalTokenService(config.AuthConfig{JwtSecret: secret})
	api := NewAPI(db, sessions, tokens, nil, nat.NewControlService(db, sessions, 0, ""), nil,
		config.OidcConfig{}, config.AuthConfig{JwtSecret: secret},
		config.ClientAuthConfig{}, config.TrafficConfig{}, nil, nil, nil, nil, nil, nil, nil)
	h := &productMetricsHarness{t: t, ctx: context.Background(), db: db, api: api, tokens: tokens,
		actors: map[string]pmVectorActor{}}
	api.productMetrics.SetClock(func() time.Time { return time.UnixMilli(h.clockMs.Load()) })
	mux := http.NewServeMux()
	api.Register(mux)
	h.server = httptest.NewServer(mux)
	t.Cleanup(h.server.Close)
	return h
}

func (h *productMetricsHarness) instant(text string) int64 {
	h.t.Helper()
	at, err := time.Parse(time.RFC3339, text)
	if err != nil {
		h.t.Fatalf("instant %q: %v", text, err)
	}
	return at.UnixMilli()
}

func (h *productMetricsHarness) instantPointer(text *string) *int64 {
	if text == nil {
		return nil
	}
	at := h.instant(*text)
	return &at
}

// addActor creates the vector's actor as a real account of its tenant with its role; usernames
// are unique across the vector's tenants, as they are on this server.
func (h *productMetricsHarness) addActor(actor pmVectorActor) {
	h.t.Helper()
	if known, ok := h.actors[actor.Username]; ok {
		if known != actor {
			h.t.Fatalf("actor %s appears with two identities", actor.Username)
		}
		return
	}
	now := time.Now()
	if _, err := h.db.InsertManagementUser(h.ctx, store.ManagementUser{Username: actor.Username,
		TenantID: actor.TenantID, PasswordHash: "unused", Role: actor.Role, Enabled: true, CreatedAt: now,
		UpdatedAt: now}); err != nil {
		h.t.Fatalf("insert user %s: %v", actor.Username, err)
	}
	h.actors[actor.Username] = actor
}

func (h *productMetricsHarness) call(method, path string, actor *pmVectorActor, body []byte) (int, []byte) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequest(method, h.server.URL+path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if actor != nil {
		// The role claim is ignored: authentication re-reads the account's role from the database.
		request.Header.Set("Authorization", "Bearer "+h.tokens.IssueForUser(actor.Username, actor.TenantID,
			store.ManagementRoleUser))
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	if response.Header.Get("Cache-Control") != "private, no-store" {
		h.t.Fatalf("%s %s: Cache-Control %q", method, path, response.Header.Get("Cache-Control"))
	}
	return response.StatusCode, payload
}

func (h *productMetricsHarness) compare(label string, expect pmVectorExpect, status int, body []byte) {
	h.t.Helper()
	if status != expect.Status {
		h.t.Fatalf("%s: status %d, want %d (%s)", label, status, expect.Status, body)
	}
	if len(expect.Body) == 0 {
		return
	}
	var got, want any
	if err := json.Unmarshal(body, &got); err != nil {
		h.t.Fatalf("%s: response is not JSON: %s", label, body)
	}
	if err := json.Unmarshal(expect.Body, &want); err != nil {
		h.t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		h.t.Fatalf("%s: body\n got %s\nwant %s", label, body, expect.Body)
	}
}

func (h *productMetricsHarness) load(state pmVectorState) {
	h.t.Helper()
	metrics := h.db.ProductMetrics()
	for _, row := range state.Switches {
		if err := metrics.SaveSwitch(h.ctx, store.ProductMetricsSwitch{TenantID: row.TenantID, Enabled: row.Enabled,
			UpdatedBy: row.UpdatedBy, UpdatedAtMs: h.instantPointer(row.UpdatedAt),
			PurgedAtMs: h.instantPointer(row.PurgedAt)}); err != nil {
			h.t.Fatal(err)
		}
	}
	for _, row := range state.Progress {
		if _, err := metrics.InsertProgressIfAbsent(h.ctx, store.ProductMetricsProgress{TenantID: row.TenantID,
			Username: row.Username, StartedAtMs: h.instant(row.StartedAt),
			SignedInAtMs: h.instantPointer(row.SignedInAt), CredentialCreatedAtMs: h.instantPointer(row.CredentialCreatedAt),
			ClientOnlineAtMs: h.instantPointer(row.ClientOnlineAt)}); err != nil {
			h.t.Fatal(err)
		}
	}
	for _, row := range state.OnboardingDaily {
		if err := metrics.AddOnboardingCount(h.ctx, store.ProductMetricsOnboardingCount(row)); err != nil {
			h.t.Fatal(err)
		}
	}
	for _, row := range state.TransferDaily {
		if err := metrics.AddTransferCount(h.ctx, store.ProductMetricsTransferCount(row)); err != nil {
			h.t.Fatal(err)
		}
	}
}

func (h *productMetricsHarness) transferTotal() int64 {
	h.t.Helper()
	rows, err := h.db.ProductMetrics().TransferCounts(h.ctx, "", "", "")
	if err != nil {
		h.t.Fatal(err)
	}
	var total int64
	for _, row := range rows {
		total += row.Count
	}
	return total
}

// compareState compares the four tables with a checkpoint; times compare as instants.
func (h *productMetricsHarness) compareState(label string, want pmVectorState) {
	h.t.Helper()
	metrics := h.db.ProductMetrics()
	switches, err := metrics.Switches(h.ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	gotSwitches := make([]string, 0)
	for _, row := range switches {
		gotSwitches = append(gotSwitches, fmt.Sprintf("%s|%v|%s|%s|%s", row.TenantID, row.Enabled,
			textOrNull(row.UpdatedBy), millisOrNull(row.UpdatedAtMs), millisOrNull(row.PurgedAtMs)))
	}
	wantSwitches := make([]string, 0)
	for _, row := range want.Switches {
		wantSwitches = append(wantSwitches, fmt.Sprintf("%s|%v|%s|%s|%s", row.TenantID, row.Enabled,
			textOrNull(row.UpdatedBy), millisOrNull(h.instantPointer(row.UpdatedAt)),
			millisOrNull(h.instantPointer(row.PurgedAt))))
	}
	progress, err := metrics.ProgressRows(h.ctx, "")
	if err != nil {
		h.t.Fatal(err)
	}
	gotProgress := make([]string, 0)
	for _, row := range progress {
		gotProgress = append(gotProgress, fmt.Sprintf("%s|%s|%d|%s|%s|%s", row.TenantID, row.Username,
			row.StartedAtMs, millisOrNull(row.SignedInAtMs), millisOrNull(row.CredentialCreatedAtMs),
			millisOrNull(row.ClientOnlineAtMs)))
	}
	wantProgress := make([]string, 0)
	for _, row := range want.Progress {
		wantProgress = append(wantProgress, fmt.Sprintf("%s|%s|%d|%s|%s|%s", row.TenantID, row.Username,
			h.instant(row.StartedAt), millisOrNull(h.instantPointer(row.SignedInAt)),
			millisOrNull(h.instantPointer(row.CredentialCreatedAt)), millisOrNull(h.instantPointer(row.ClientOnlineAt))))
	}
	onboarding, err := metrics.OnboardingCounts(h.ctx, "", "", "")
	if err != nil {
		h.t.Fatal(err)
	}
	gotOnboarding := make([]string, 0)
	for _, row := range onboarding {
		gotOnboarding = append(gotOnboarding, fmt.Sprintf("%+v", pmVectorOnboarding(row)))
	}
	wantOnboarding := make([]string, 0)
	for _, row := range want.OnboardingDaily {
		wantOnboarding = append(wantOnboarding, fmt.Sprintf("%+v", row))
	}
	transfers, err := metrics.TransferCounts(h.ctx, "", "", "")
	if err != nil {
		h.t.Fatal(err)
	}
	gotTransfers := make([]string, 0)
	for _, row := range transfers {
		gotTransfers = append(gotTransfers, fmt.Sprintf("%+v", pmVectorTransfer(row)))
	}
	wantTransfers := make([]string, 0)
	for _, row := range want.TransferDaily {
		wantTransfers = append(wantTransfers, fmt.Sprintf("%+v", row))
	}
	for _, pair := range []struct {
		table     string
		got, want []string
	}{
		{"product_metrics_switch", gotSwitches, wantSwitches},
		{"product_metrics_onboarding_progress", gotProgress, wantProgress},
		{"product_metrics_onboarding_daily", gotOnboarding, wantOnboarding},
		{"product_metrics_transfer_daily", gotTransfers, wantTransfers},
	} {
		sort.Strings(pair.got)
		sort.Strings(pair.want)
		if !reflect.DeepEqual(pair.got, pair.want) {
			h.t.Fatalf("%s: %s\n got %s\nwant %s", label, pair.table, strings.Join(pair.got, "\n     "),
				strings.Join(pair.want, "\n     "))
		}
	}
}

func textOrNull(value *string) string {
	if value == nil {
		return "null"
	}
	return *value
}

func millisOrNull(value *int64) string {
	if value == nil {
		return "null"
	}
	return fmt.Sprint(*value)
}
