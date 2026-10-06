package management

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/nat"
	"github.com/devShuai/specus/implementations/go/server/internal/peermesh"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// Replays protocol/test-vectors/service-workbench-v1.json through the real routing, the shared
// authentication layer and the workbench handlers, against a fresh SQLite database per scenario.

type workbenchVectorFile struct {
	BaseTime  string                    `json:"baseTime"`
	Scenarios []workbenchVectorScenario `json:"scenarios"`
}

type workbenchVectorIdentity struct {
	TenantID string `json:"tenantId"`
	Username string `json:"username"`
	Admin    bool   `json:"admin"`
}

type workbenchVectorObject struct {
	Kind          string `json:"kind"`
	ID            int64  `json:"id"`
	TenantID      string `json:"tenantId"`
	OwnerUsername string `json:"ownerUsername"`
}

type workbenchVectorRow struct {
	TenantID string `json:"tenantId"`
	Username string `json:"username"`
	List     string `json:"list"`
	Kind     string `json:"kind"`
	ID       int64  `json:"id"`
	AtMs     int64  `json:"atMs"`
}

type workbenchVectorExpect struct {
	HTTPStatus        int             `json:"httpStatus"`
	RetryAfterSeconds *int            `json:"retryAfterSeconds"`
	Body              json.RawMessage `json:"body"`
	SessionRejected   bool            `json:"sessionRejected"`
}

type workbenchVectorStep struct {
	AtMs          int64                    `json:"atMs"`
	Event         string                   `json:"event"`
	Method        string                   `json:"method"`
	Path          string                   `json:"path"`
	As            *workbenchVectorIdentity `json:"as"`
	Expect        *workbenchVectorExpect   `json:"expect"`
	Kind          string                   `json:"kind"`
	ID            int64                    `json:"id"`
	TenantID      string                   `json:"tenantId"`
	Username      string                   `json:"username"`
	OwnerUsername string                   `json:"ownerUsername"`
	Admin         bool                     `json:"admin"`
}

type workbenchVectorScenario struct {
	Name      string                    `json:"name"`
	Users     []workbenchVectorIdentity `json:"users"`
	Objects   []workbenchVectorObject   `json:"objects"`
	Rows      []workbenchVectorRow      `json:"rows"`
	Steps     []workbenchVectorStep     `json:"steps"`
	RowsAfter []workbenchVectorRow      `json:"rowsAfter"`
}

func TestWorkbenchVectorScenarios(t *testing.T) {
	var vector workbenchVectorFile
	readWorkbenchVector(t, &vector)
	base, err := time.Parse(time.RFC3339, vector.BaseTime)
	if err != nil {
		t.Fatalf("baseTime: %v", err)
	}
	if len(vector.Scenarios) == 0 {
		t.Fatal("vector has no scenarios")
	}
	wantSteps := 0
	var replayed, completed atomic.Int64
	t.Run("scenarios", func(t *testing.T) {
		for _, scenario := range vector.Scenarios {
			wantSteps += len(scenario.Steps)
			scenario := scenario
			t.Run(scenario.Name, func(t *testing.T) {
				t.Parallel() // each scenario has its own database, server and limiter
				replayed.Add(int64(replayWorkbenchScenario(t, base, scenario)))
				completed.Add(1)
			})
		}
	})
	if int(completed.Load()) != len(vector.Scenarios) || int(replayed.Load()) != wantSteps {
		t.Fatalf("replayed %d of %d scenarios, %d of %d steps", completed.Load(), len(vector.Scenarios),
			replayed.Load(), wantSteps)
	}
	t.Logf("replayed %d scenarios, %d steps", completed.Load(), replayed.Load())
}

func replayWorkbenchScenario(t *testing.T, base time.Time, scenario workbenchVectorScenario) int {
	h := newWorkbenchHarness(t, base)
	tenants := map[string]bool{}
	for _, user := range scenario.Users {
		tenants[user.TenantID] = true
	}
	for _, object := range scenario.Objects {
		tenants[object.TenantID] = true
	}
	for _, step := range scenario.Steps {
		if step.TenantID != "" {
			tenants[step.TenantID] = true
		}
	}
	for tenant := range tenants {
		h.addFixtureAdmin(tenant)
	}
	for _, user := range scenario.Users {
		h.addUser(user)
	}
	for _, object := range scenario.Objects {
		h.addObject(object)
	}
	for _, row := range scenario.Rows {
		if err := h.db.InsertWorkbenchItem(h.ctx, h.storedRow(row)); err != nil {
			t.Fatalf("insert row %+v: %v", row, err)
		}
	}
	replayed := 0
	for index, step := range scenario.Steps {
		h.setClock(step.AtMs)
		label := fmt.Sprintf("step %d (%s %s%s)", index, step.Method, step.Path, step.Event)
		if step.Event != "" {
			h.applyEvent(label, step)
		} else {
			h.checkCall(label, step)
		}
		replayed++
	}
	got := h.vectorRows()
	want := append([]workbenchVectorRow{}, scenario.RowsAfter...)
	sortWorkbenchVectorRows(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rows after scenario:\n got %+v\nwant %+v", got, want)
	}
	return replayed
}

// ---- harness ----------------------------------------------------------------------------

type workbenchHarness struct {
	t            *testing.T
	ctx          context.Context
	db           *store.DB
	dbPath       string
	api          *API
	server       *httptest.Server
	tokens       *security.LocalTokenService
	base         time.Time
	clockMs      atomic.Int64
	nextClientID int64
	nextPort     int
	objectClient map[string]int64
	identities   map[string]workbenchVectorIdentity
	fixtures     map[string]string
}

func newWorkbenchHarness(t *testing.T, base time.Time) *workbenchHarness {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "workbench.db")
	db, err := store.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sessions := session.NewRegistry()
	secret := "workbench-test-secret"
	tokens := security.NewLocalTokenService(config.AuthConfig{JwtSecret: secret})
	mesh := peermesh.New(config.PeerMeshConfig{Enabled: true, CIDR: "100.96.0.0/11", PublicAddress: "203.0.113.10",
		StunTurnPort: 3478, SessionTTLSeconds: 3600}, db, sessions, nil)
	api := NewAPI(db, sessions, tokens, nil, nat.NewControlService(db, sessions, 0, ""), nil,
		config.OidcConfig{}, config.AuthConfig{JwtSecret: secret},
		config.ClientAuthConfig{}, config.TrafficConfig{}, nil, nil, mesh, nil, nil, nil, nil)
	h := &workbenchHarness{t: t, ctx: context.Background(), db: db, dbPath: dbPath, api: api, tokens: tokens,
		base: base, nextClientID: 9000, nextPort: 41000, objectClient: map[string]int64{},
		identities: map[string]workbenchVectorIdentity{}, fixtures: map[string]string{}}
	api.workbench.now = func() time.Time { return h.base.Add(time.Duration(h.clockMs.Load()) * time.Millisecond) }
	mux := http.NewServeMux()
	api.Register(mux)
	h.server = httptest.NewServer(mux)
	t.Cleanup(h.server.Close)
	return h
}

func (h *workbenchHarness) setClock(atMs int64) { h.clockMs.Store(atMs) }

// realUsername maps a vector identity to an account name. Usernames are globally unique on this
// server, so the vector's "alice" of tenant t2 cannot share the name of t1's alice; every tenant
// but t1 gets a suffix, and rows are mapped back before they are compared.
func (h *workbenchHarness) realUsername(tenantID, username string) string {
	real := username
	if tenantID != "t1" {
		real = username + "-" + tenantID
	}
	h.identities[real] = workbenchVectorIdentity{TenantID: tenantID, Username: username}
	return real
}

func (h *workbenchHarness) insertUser(username, tenantID string, admin bool) {
	h.t.Helper()
	role := store.ManagementRoleUser
	if admin {
		role = store.ManagementRoleAdmin
	}
	now := time.Now()
	if err := h.db.InsertManagementUser(h.ctx, store.ManagementUser{Username: username, TenantID: tenantID,
		PasswordHash: "test-password-hash", Role: role, Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		h.t.Fatalf("insert user %s: %v", username, err)
	}
}

func (h *workbenchHarness) addFixtureAdmin(tenantID string) {
	name := "wbfixture-" + tenantID
	h.insertUser(name, tenantID, true)
	h.fixtures[tenantID] = name
}

func (h *workbenchHarness) addUser(user workbenchVectorIdentity) {
	h.insertUser(h.realUsername(user.TenantID, user.Username), user.TenantID, user.Admin)
}

func (h *workbenchHarness) token(tenantID, username string) string {
	return h.tokens.IssueForUser(h.realUsername(tenantID, username), tenantID, store.ManagementRoleUser)
}

func (h *workbenchHarness) fixtureToken(tenantID string) string {
	name, ok := h.fixtures[tenantID]
	if !ok {
		h.t.Fatalf("no fixture administrator for tenant %s", tenantID)
	}
	return h.tokens.IssueForUser(name, tenantID, store.ManagementRoleAdmin)
}

// addObject creates the service on a client of its own, so changing one object's owner touches
// no other object.
func (h *workbenchHarness) addObject(object workbenchVectorObject) {
	h.addService(object, h.addClient(object.TenantID, object.OwnerUsername))
}

func (h *workbenchHarness) addClient(tenantID, owner string) store.ClientAccount {
	h.t.Helper()
	h.nextClientID++
	now := time.Now()
	client := store.ClientAccount{ID: h.nextClientID, TenantID: tenantID,
		OwnerUsername: h.realUsername(tenantID, owner),
		ClientName:    fmt.Sprintf("wb-client-%d", h.nextClientID), PasswordHash: "unused", Enabled: true,
		ConnectionRateLimitPerMinute: 60, CreatedAt: now, UpdatedAt: now}
	if err := h.db.InsertClient(h.ctx, client); err != nil {
		h.t.Fatalf("insert client: %v", err)
	}
	return client
}

func (h *workbenchHarness) addService(object workbenchVectorObject, client store.ClientAccount) {
	h.t.Helper()
	now := time.Now()
	var err error
	switch object.Kind {
	case store.WorkbenchKindHTTPRoute:
		err = h.db.InsertHTTPRoute(h.ctx, store.HTTPRouteMapping{ID: object.ID, TenantID: object.TenantID,
			ClientID: client.ID, ClientName: client.ClientName, Route: "wb" + strconv.FormatInt(object.ID, 10),
			TargetBaseURL: "http://127.0.0.1:8080", Enabled: true, CreatedAt: now, UpdatedAt: now})
	case store.WorkbenchKindTCPMapping:
		h.nextPort++
		err = h.db.InsertSpecus(h.ctx, store.SpecusMapping{ID: object.ID, TenantID: object.TenantID,
			ClientID: client.ID, ClientName: client.ClientName, ListenPort: h.nextPort, TargetAddress: "127.0.0.1",
			TargetPort: 22, Enabled: true, CreatedAt: now, UpdatedAt: now})
	case store.WorkbenchKindPeerService:
		err = h.db.InsertPeerMeshSharedService(h.ctx, store.PeerMeshSharedService{ID: object.ID,
			TenantID: object.TenantID, ClientID: client.ID, ClientName: client.ClientName,
			ServiceID: "wb-" + strconv.FormatInt(object.ID, 10), Name: "service", Transport: "tcp",
			TargetHost: "127.0.0.1", TargetPort: 22, PublishedPort: 22, Enabled: true, Visibility: "OWNER",
			CreatedAt: now, UpdatedAt: now})
	default:
		h.t.Fatalf("unknown kind %s", object.Kind)
	}
	if err != nil {
		h.t.Fatalf("insert %s %d: %v", object.Kind, object.ID, err)
	}
	h.objectClient[object.Kind+"/"+strconv.FormatInt(object.ID, 10)] = client.ID
}

func (h *workbenchHarness) storedRow(row workbenchVectorRow) store.WorkbenchItem {
	return store.WorkbenchItem{TenantID: row.TenantID, Username: h.realUsername(row.TenantID, row.Username),
		List: row.List, Kind: row.Kind, ObjectID: row.ID, AtMs: h.base.UnixMilli() + row.AtMs}
}

func (h *workbenchHarness) vectorRows() []workbenchVectorRow {
	h.t.Helper()
	items, err := h.db.ListAllWorkbenchItems(h.ctx)
	if err != nil {
		h.t.Fatalf("read rows: %v", err)
	}
	rows := make([]workbenchVectorRow, 0, len(items))
	for _, item := range items {
		identity, ok := h.identities[item.Username]
		if !ok || identity.TenantID != item.TenantID {
			h.t.Fatalf("row of an unknown identity: %+v", item)
		}
		rows = append(rows, workbenchVectorRow{TenantID: item.TenantID, Username: identity.Username, List: item.List,
			Kind: item.Kind, ID: item.ObjectID, AtMs: item.AtMs - h.base.UnixMilli()})
	}
	sortWorkbenchVectorRows(rows)
	return rows
}

func sortWorkbenchVectorRows(rows []workbenchVectorRow) {
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.TenantID != b.TenantID {
			return a.TenantID < b.TenantID
		}
		if a.Username != b.Username {
			return a.Username < b.Username
		}
		if a.List != b.List {
			return a.List < b.List
		}
		if a.Kind != b.Kind {
			return workbenchKindOrder(a.Kind) < workbenchKindOrder(b.Kind)
		}
		return a.ID < b.ID
	})
}

func (h *workbenchHarness) do(method, path, token string, body any) (*http.Response, []byte) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		reader = bytes.NewReader(payload)
	}
	request, err := http.NewRequest(method, h.server.URL+path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
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
	return response, payload
}

func (h *workbenchHarness) expect2xx(label, method, path, token string, body any) {
	h.t.Helper()
	response, payload := h.do(method, path, token, body)
	if response.StatusCode/100 != 2 {
		h.t.Fatalf("%s: %s %s answered %d %s", label, method, path, response.StatusCode, payload)
	}
}

// setStoreDown makes the workbench table unreadable and unwritable by renaming it through a second
// connection, and restores it again: the server sees a real storage failure, not a test switch.
func (h *workbenchHarness) setStoreDown(down bool) {
	h.t.Helper()
	conn, err := sql.Open("sqlite", h.dbPath)
	if err != nil {
		h.t.Fatal(err)
	}
	defer conn.Close()
	statement := `ALTER TABLE management_workbench_item RENAME TO management_workbench_item_offline`
	if !down {
		statement = `ALTER TABLE management_workbench_item_offline RENAME TO management_workbench_item`
	}
	if _, err := conn.ExecContext(h.ctx, statement); err != nil {
		h.t.Fatalf("store fault: %v", err)
	}
}

func (h *workbenchHarness) applyEvent(label string, step workbenchVectorStep) {
	h.t.Helper()
	switch step.Event {
	case "delete-object":
		clientID := h.objectClient[step.Kind+"/"+strconv.FormatInt(step.ID, 10)]
		account, err := h.db.GetClient(h.ctx, clientID)
		if err != nil {
			h.t.Fatalf("%s: client of the object: %v", label, err)
		}
		path := map[string]string{
			store.WorkbenchKindHTTPRoute:   "/api/admin/http-routes/",
			store.WorkbenchKindTCPMapping:  "/api/admin/specus-mappings/",
			store.WorkbenchKindPeerService: "/api/admin/peer-mesh/services/",
		}[step.Kind] + strconv.FormatInt(step.ID, 10)
		h.expect2xx(label, http.MethodDelete, path, h.fixtureToken(account.TenantID), nil)
	case "create-object":
		h.addObject(workbenchVectorObject{Kind: step.Kind, ID: step.ID, TenantID: step.TenantID,
			OwnerUsername: step.OwnerUsername})
	case "change-owner":
		clientID := h.objectClient[step.Kind+"/"+strconv.FormatInt(step.ID, 10)]
		account, err := h.db.GetClient(h.ctx, clientID)
		if err != nil {
			h.t.Fatalf("%s: %v", label, err)
		}
		account.OwnerUsername = h.realUsername(account.TenantID, step.OwnerUsername)
		if err := h.db.UpdateClient(h.ctx, *account); err != nil {
			h.t.Fatalf("%s: %v", label, err)
		}
	case "set-admin":
		role := store.ManagementRoleUser
		if step.Admin {
			role = store.ManagementRoleAdmin
		}
		h.expect2xx(label, http.MethodPut, "/api/admin/users/"+h.realUsername(step.TenantID, step.Username),
			h.fixtureToken(step.TenantID), map[string]any{"role": role})
	case "create-user":
		role := store.ManagementRoleUser
		if step.Admin {
			role = store.ManagementRoleAdmin
		}
		h.expect2xx(label, http.MethodPost, "/api/admin/users", h.fixtureToken(step.TenantID),
			map[string]any{"username": h.realUsername(step.TenantID, step.Username),
				"password": "workbench-test-password", "role": role})
	case "delete-user":
		h.expect2xx(label, http.MethodDelete, "/api/admin/users/"+h.realUsername(step.TenantID, step.Username),
			h.fixtureToken(step.TenantID), nil)
	case "store-down":
		h.setStoreDown(true)
	case "store-up":
		h.setStoreDown(false)
	case "sweep":
		if _, err := h.api.SweepWorkbench(h.ctx); err != nil {
			h.t.Fatalf("%s: %v", label, err)
		}
	default:
		h.t.Fatalf("%s: unknown event", label)
	}
}

var workbenchStampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)

func (h *workbenchHarness) checkCall(label string, step workbenchVectorStep) {
	h.t.Helper()
	if step.Expect == nil {
		h.t.Fatalf("%s: no expectation", label)
	}
	token := ""
	if step.As != nil {
		token = h.token(step.As.TenantID, step.As.Username)
	}
	var before []workbenchVectorRow
	if step.Expect.SessionRejected {
		before = h.vectorRows()
	}
	response, payload := h.do(step.Method, step.Path, token, nil)
	if got := response.Header.Get("Cache-Control"); got != "private, no-store" {
		h.t.Errorf("%s: Cache-Control = %q", label, got)
	}
	expect := step.Expect
	if expect.SessionRejected {
		if response.StatusCode/100 == 2 {
			h.t.Fatalf("%s: a deleted account's token was accepted: %d %s", label, response.StatusCode, payload)
		}
		if after := h.vectorRows(); !reflect.DeepEqual(after, before) {
			h.t.Fatalf("%s: a refused session wrote rows: %+v", label, after)
		}
		return
	}
	if response.StatusCode != expect.HTTPStatus {
		h.t.Fatalf("%s: status = %d, want %d; body=%s", label, response.StatusCode, expect.HTTPStatus, payload)
	}
	if expect.RetryAfterSeconds != nil {
		if got := response.Header.Get("Retry-After"); got != strconv.Itoa(*expect.RetryAfterSeconds) {
			h.t.Fatalf("%s: Retry-After = %q, want %d", label, got, *expect.RetryAfterSeconds)
		}
	}
	if len(expect.Body) == 0 {
		return
	}
	if expect.HTTPStatus != http.StatusOK {
		var want, got struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(expect.Body, &want); err != nil {
			h.t.Fatal(err)
		}
		if err := json.Unmarshal(payload, &got); err != nil || got.Code != want.Code {
			h.t.Fatalf("%s: code = %q, want %q; body=%s", label, got.Code, want.Code, payload)
		}
		return
	}
	want, got := decodeWorkbenchJSON(h.t, expect.Body, false), decodeWorkbenchJSON(h.t, payload, true)
	if !reflect.DeepEqual(got, want) {
		h.t.Fatalf("%s: body\n got %s\nwant %s", label, payload, expect.Body)
	}
}

// decodeWorkbenchJSON decodes a document with exact numbers and turns addedAt/visitedAt into
// instants, so times compare as instants; for the server's answer it also checks the format.
func decodeWorkbenchJSON(t *testing.T, data []byte, checkFormat bool) any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
	var walk func(any) any
	walk = func(node any) any {
		switch typed := node.(type) {
		case map[string]any:
			for key, child := range typed {
				if text, ok := child.(string); ok && (key == "addedAt" || key == "visitedAt") {
					if checkFormat && !workbenchStampPattern.MatchString(text) {
						t.Fatalf("time %q is not RFC 3339 UTC with three fractional digits", text)
					}
					parsed, err := time.Parse(time.RFC3339Nano, text)
					if err != nil {
						t.Fatalf("time %q: %v", text, err)
					}
					typed[key] = parsed.UnixMilli()
					continue
				}
				typed[key] = walk(child)
			}
		case []any:
			for i, child := range typed {
				typed[i] = walk(child)
			}
		}
		return node
	}
	return walk(value)
}

func readWorkbenchVector(t *testing.T, target any) {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for depth := 0; depth < 8; depth++ {
		if data, err := os.ReadFile(filepath.Join(dir, "protocol", "test-vectors", "service-workbench-v1.json")); err == nil {
			if err := json.Unmarshal(data, target); err != nil {
				t.Fatalf("decode vector: %v", err)
			}
			return
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("cannot locate protocol/test-vectors/service-workbench-v1.json")
}
