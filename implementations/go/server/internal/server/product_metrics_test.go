package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func productMetricsProgress(t *testing.T, app *App, username string) *store.ProductMetricsProgress {
	t.Helper()
	row, err := app.DB().ProductMetrics().Progress(context.Background(), "default", username)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func decodeProductMetrics(t *testing.T, response *http.Response) map[string]any {
	t.Helper()
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode %q: %v", raw, err)
	}
	return body
}

func expectStatus(t *testing.T, response *http.Response, status int, label string) {
	t.Helper()
	if response.StatusCode != status {
		raw, _ := io.ReadAll(response.Body)
		t.Fatalf("%s: status %d, want %d: %s", label, response.StatusCode, status, raw)
	}
}

// The real write paths fire the onboarding milestones: an admin creating the account, the
// account's password sign-in, its first credential, its client's control login and the first HTTP
// route on that client. Deleting another account drops its progress row; switching off drops the
// rest. Transfer outcomes from a signed-in member are counted and the summary reads them back.
func TestProductMetricsWritePathsRecordMilestones(t *testing.T) {
	app, port := startTestApp(t)
	_, ts := newHTTPTestServer(t, app)
	admin := adminToken(t, ts)

	disabled := authRequest(t, ts, http.MethodPost, "/api/admin/users", admin,
		`{"username":"metrics-early","password":"metrics-password","role":"USER"}`)
	expectStatus(t, disabled, http.StatusCreated, "user before opt-in")
	disabled.Body.Close()
	if row := productMetricsProgress(t, app, "metrics-early"); row != nil {
		t.Fatalf("an account created before opt-in has progress: %+v", row)
	}

	enable := authRequest(t, ts, http.MethodPut, "/api/admin/product-metrics/settings", admin,
		`{"enabled":true,"disclosureVersion":1}`)
	expectStatus(t, enable, http.StatusOK, "enable")
	if body := decodeProductMetrics(t, enable); body["enabled"] != true || body["updatedBy"] != "admin" {
		t.Fatalf("enable answer %v", body)
	}

	created := authRequest(t, ts, http.MethodPost, "/api/admin/users", admin,
		`{"username":"metrics-alice","password":"metrics-password","role":"USER"}`)
	expectStatus(t, created, http.StatusCreated, "create user")
	created.Body.Close()
	row := productMetricsProgress(t, app, "metrics-alice")
	if row == nil || row.SignedInAtMs != nil {
		t.Fatalf("account_created: %+v", row)
	}

	alice := loginToken(t, ts, "metrics-alice", "metrics-password")
	if row = productMetricsProgress(t, app, "metrics-alice"); row == nil || row.SignedInAtMs == nil {
		t.Fatalf("signed_in: %+v", row)
	}

	credential := authRequest(t, ts, http.MethodPost, "/api/admin/client-credentials", alice, `{}`)
	expectStatus(t, credential, http.StatusCreated, "create credential")
	credential.Body.Close()
	if row = productMetricsProgress(t, app, "metrics-alice"); row == nil || row.CredentialCreatedAtMs == nil {
		t.Fatalf("credential_created: %+v", row)
	}

	now := time.Now()
	client := store.ClientAccount{ID: 7_700_001, TenantID: "default", OwnerUsername: "metrics-alice",
		ClientName: "metrics-client", PasswordHash: "unused", Enabled: true, ConnectionRateLimitPerMinute: 60,
		CreatedAt: now, UpdatedAt: now}
	if err := app.DB().InsertClient(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	_, reader := dialAndLogin(t, app, port, client.ClientName)
	if response, ok := readPacket(t, reader).(protocol.LoginResponse); !ok || !response.Success {
		t.Fatalf("client login: %+v", response)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		row = productMetricsProgress(t, app, "metrics-alice")
		if row != nil && row.ClientOnlineAtMs != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("client_online was not recorded: %+v", row)
		}
		time.Sleep(20 * time.Millisecond)
	}

	route := authRequest(t, ts, http.MethodPost, "/api/admin/clients/7700001/http-routes", alice,
		`{"route":"metrics","targetBaseUrl":"http://127.0.0.1:18080","enabled":true}`)
	expectStatus(t, route, http.StatusCreated, "create route")
	route.Body.Close()
	if row = productMetricsProgress(t, app, "metrics-alice"); row != nil {
		t.Fatalf("service_published left the progress row: %+v", row)
	}
	cohorts, err := app.DB().ProductMetrics().OnboardingCounts(context.Background(), "default", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cohorts) != 1 || cohorts[0].ReachedStep != "service_published" || cohorts[0].DurationBucket != "lt10m" ||
		cohorts[0].Users != 1 {
		t.Fatalf("cohort counters %+v", cohorts)
	}

	bob := authRequest(t, ts, http.MethodPost, "/api/admin/users", admin,
		`{"username":"metrics-bob","password":"metrics-password","role":"USER"}`)
	expectStatus(t, bob, http.StatusCreated, "create bob")
	bob.Body.Close()
	if productMetricsProgress(t, app, "metrics-bob") == nil {
		t.Fatal("bob has no progress row")
	}
	deleted := authRequest(t, ts, http.MethodDelete, "/api/admin/users/metrics-bob", admin, "")
	expectStatus(t, deleted, http.StatusNoContent, "delete bob")
	deleted.Body.Close()
	if row := productMetricsProgress(t, app, "metrics-bob"); row != nil {
		t.Fatalf("a deleted account keeps progress: %+v", row)
	}

	event := `{"mode":"device","path":"turn","sizeBucket":"1m-16m","attempt":"retry_after_failure","outcome":"success"}`
	ingest := authRequest(t, ts, http.MethodPost, "/api/admin/product-metrics/transfer-outcomes", alice,
		`{"schemaVersion":1,"events":[`+event+`]}`)
	expectStatus(t, ingest, http.StatusOK, "ingest")
	if body := decodeProductMetrics(t, ingest); body["collecting"] != true || body["accepted"] != float64(1) {
		t.Fatalf("ingest answer %v", body)
	}
	member := authRequest(t, ts, http.MethodGet, "/api/admin/product-metrics/settings", alice, "")
	expectStatus(t, member, http.StatusOK, "member settings")
	if body := decodeProductMetrics(t, member); body["enabled"] != true {
		t.Fatalf("member settings %v", body)
	} else if _, leaked := body["updatedBy"]; leaked {
		t.Fatalf("a member sees updatedBy: %v", body)
	}
	forbidden := authRequest(t, ts, http.MethodGet, "/api/admin/product-metrics/summary", alice, "")
	expectStatus(t, forbidden, http.StatusForbidden, "member summary")
	forbidden.Body.Close()

	summary := authRequest(t, ts, http.MethodGet, "/api/admin/product-metrics/summary", admin, "")
	expectStatus(t, summary, http.StatusOK, "summary")
	body := decodeProductMetrics(t, summary)
	onboarding := body["onboarding"].(map[string]any)
	transfers := body["transfers"].(map[string]any)
	if onboarding["completed"] != float64(1) || onboarding["medianDurationBucket"] != "lt10m" {
		t.Fatalf("summary onboarding %v", onboarding)
	}
	attempts := transfers["byAttempt"].([]any)
	if retry := attempts[1].(map[string]any); retry["attempt"] != "retry_after_failure" ||
		retry["successRateBp"] != float64(10000) {
		t.Fatalf("summary attempts %v", attempts)
	}

	carol := authRequest(t, ts, http.MethodPost, "/api/admin/users", admin,
		`{"username":"metrics-carol","password":"metrics-password","role":"USER"}`)
	expectStatus(t, carol, http.StatusCreated, "create carol")
	carol.Body.Close()
	off := authRequest(t, ts, http.MethodPut, "/api/admin/product-metrics/settings", admin, `{"enabled":false}`)
	expectStatus(t, off, http.StatusOK, "disable")
	off.Body.Close()
	if row := productMetricsProgress(t, app, "metrics-carol"); row != nil {
		t.Fatalf("switching off keeps progress: %+v", row)
	}
	stopped := authRequest(t, ts, http.MethodPost, "/api/admin/product-metrics/transfer-outcomes", alice,
		`{"schemaVersion":1,"events":[`+event+`]}`)
	expectStatus(t, stopped, http.StatusOK, "ingest after disable")
	if body := decodeProductMetrics(t, stopped); body["collecting"] != false || body["accepted"] != float64(0) {
		t.Fatalf("ingest after disable %v", body)
	}
}

// productMetrics.allowed=false keeps every tenant off: enabling answers 409 and nothing counts.
func TestProductMetricsDeploymentSwitch(t *testing.T) {
	cfg := config.Default()
	cfg.ProductMetrics.Allowed = false
	_, ts := newAPIServerWithConfig(t, cfg)
	admin := adminToken(t, ts)
	enable := authRequest(t, ts, http.MethodPut, "/api/admin/product-metrics/settings", admin,
		`{"enabled":true,"disclosureVersion":1}`)
	expectStatus(t, enable, http.StatusConflict, "enable while not allowed")
	if body := decodeProductMetrics(t, enable); body["code"] != "PRODUCT_METRICS_NOT_ALLOWED" {
		t.Fatalf("enable answer %v", body)
	}
	settings := authRequest(t, ts, http.MethodGet, "/api/admin/product-metrics/settings", admin, "")
	expectStatus(t, settings, http.StatusOK, "settings")
	if body := decodeProductMetrics(t, settings); body["enabled"] != false {
		t.Fatalf("settings %v", body)
	}
	ingest := authRequest(t, ts, http.MethodPost, "/api/admin/product-metrics/transfer-outcomes", admin,
		`{"schemaVersion":1,"events":[{"mode":"link","path":"cloud","sizeBucket":"gt512m","attempt":"first","outcome":"failure"}]}`)
	expectStatus(t, ingest, http.StatusOK, "ingest")
	if body := decodeProductMetrics(t, ingest); body["collecting"] != false {
		t.Fatalf("ingest %v", body)
	}
	oversize := authRequest(t, ts, http.MethodPost, "/api/admin/product-metrics/transfer-outcomes", admin,
		strings.Repeat(" ", 4097))
	expectStatus(t, oversize, http.StatusRequestEntityTooLarge, "oversize")
	oversize.Body.Close()
}
