package management

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

type ownerVectorCase struct {
	Name           string          `json:"name"`
	Snapshot       string          `json:"snapshot"`
	Scope          string          `json:"scope"`
	ID             int64           `json:"id"`
	Admin          *bool           `json:"admin"`
	Request        json.RawMessage `json:"request"`
	PreparedTarget *string         `json:"preparedTarget"`
	Error          *struct {
		Status int
		Code   string
	} `json:"error"`
	Preview struct {
		ClientID          *int64  `json:"clientId"`
		CredentialID      *int64  `json:"credentialId"`
		AffectedClientIDs []int64 `json:"affectedClientIds"`
		CanTransfer       bool    `json:"canTransfer"`
		ConflictCode      *string `json:"conflictCode"`
		HasRevision       bool    `json:"hasRevision"`
	} `json:"preview"`
}
type ownerVectorFile struct {
	Version   int                                   `json:"version"`
	TenantID  string                                `json:"tenantId"`
	Base      map[string]json.RawMessage            `json:"base"`
	Snapshots map[string]map[string]json.RawMessage `json:"snapshots"`
	Cases     []ownerVectorCase                     `json:"cases"`
}

func readOwnerVector(t *testing.T) ownerVectorFile {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		path := filepath.Join(dir, "protocol", "test-vectors", "client-owner-transfer-plan-v1.json")
		data, err := os.ReadFile(path)
		if err == nil {
			var result ownerVectorFile
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
			if result.Version != 1 || len(result.Cases) != 29 {
				t.Fatal("unexpected shared vector version/count")
			}
			return result
		}
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("missing shared ownership vectors")
		}
		dir = parent
	}
}
func ownerSnapshot(t *testing.T, v ownerVectorFile, name string) store.OwnerTransferSnapshot {
	t.Helper()
	fields := make(map[string]json.RawMessage)
	for key, value := range v.Base {
		fields[key] = value
	}
	overrides, ok := v.Snapshots[name]
	if !ok {
		t.Fatalf("missing snapshot %s", name)
	}
	for key, value := range overrides {
		fields[key] = value
	}
	var result store.OwnerTransferSnapshot
	ownerRoundTrip(t, fields, &result)
	return result
}
func ownerRoundTrip(t *testing.T, input, output any) {
	t.Helper()
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, output); err != nil {
		t.Fatal(err)
	}
}
func ownerJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
func assertOwnerProblem(t *testing.T, err error, status int, code string) {
	t.Helper()
	problem, ok := err.(*ownerTransferError)
	if !ok || problem.Status != status || problem.Code != code || problem.Error() != code {
		t.Fatalf("error=%v, want %d/%s", err, status, code)
	}
}
func assertOwnerPreview(t *testing.T, result ownerTransferPreview, c ownerVectorCase, data store.OwnerTransferSnapshot) {
	t.Helper()
	if result.Scope != c.Scope || !reflect.DeepEqual(result.ClientID, c.Preview.ClientID) || !reflect.DeepEqual(result.CredentialID, c.Preview.CredentialID) || result.CanTransfer != c.Preview.CanTransfer || !reflect.DeepEqual(result.ConflictCode, c.Preview.ConflictCode) || (result.Revision != nil) != c.Preview.HasRevision || !result.AccessRetained {
		t.Fatalf("unexpected preview %s", ownerJSON(t, result))
	}
	ids := make([]int64, 0)
	for _, row := range result.AffectedClients {
		ids = append(ids, row.ID)
		found := false
		for _, original := range data.Clients {
			if original.ID == row.ID {
				found = reflect.DeepEqual(row, ownerAffectedClient{original.ID, original.ClientName, original.OwnerUsername, original.Enabled})
			}
		}
		if !found {
			t.Fatalf("affected row differs from actual source: %+v", row)
		}
	}
	if !reflect.DeepEqual(ids, c.Preview.AffectedClientIDs) || len(ids) != result.AffectedClientCount {
		t.Fatalf("ids=%v count=%d, want %v", ids, result.AffectedClientCount, c.Preview.AffectedClientIDs)
	}
	if result.CredentialID == nil {
		if result.CredentialEnabled != nil || result.CredentialOwnerUsername != nil {
			t.Fatal("legacy preview has credential fields")
		}
	} else {
		for _, row := range data.Credentials {
			if row.ID == *result.CredentialID && (!reflect.DeepEqual(row.OwnerUsername, result.CredentialOwnerUsername) || result.CredentialEnabled == nil || *result.CredentialEnabled != row.Enabled) {
				t.Fatal("credential owner/enabled changed")
			}
		}
	}
}

func TestOwnerTransferSharedPlanVectors(t *testing.T) {
	v := readOwnerVector(t)
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			data := ownerSnapshot(t, v, c.Snapshot)
			before := ownerJSON(t, data)
			p := managementPrincipal{TenantID: v.TenantID, Username: "admin", Admin: c.Admin == nil || *c.Admin}
			var preview ownerTransferPreview
			var target string
			var err error
			if c.Request != nil {
				var request any
				if err := json.Unmarshal(c.Request, &request); err != nil {
					t.Fatal(err)
				}
				if object, ok := request.(map[string]any); ok && object["expectedRevision"] == "$current" {
					current, err := previewOwnerTransfer(p, c.Scope, c.ID, data)
					if err != nil || current.Revision == nil {
						t.Fatalf("current revision: %v", err)
					}
					object["expectedRevision"] = *current.Revision
				}
				preview, target, err = prepareOwnerTransfer(p, c.Scope, c.ID, request, data)
			} else {
				preview, err = previewOwnerTransfer(p, c.Scope, c.ID, data)
			}
			if c.Error != nil {
				assertOwnerProblem(t, err, c.Error.Status, c.Error.Code)
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if c.PreparedTarget != nil {
					if target != *c.PreparedTarget || !preview.AccessRetained {
						t.Fatalf("target=%s", target)
					}
				} else {
					assertOwnerPreview(t, preview, c, data)
				}
			}
			if ownerJSON(t, data) != before {
				t.Fatal("pure planner mutated input")
			}
		})
	}
}

func TestOwnerTransferRevisionBindings(t *testing.T) {
	v := readOwnerVector(t)
	p := managementPrincipal{TenantID: v.TenantID, Username: "admin", Admin: true}
	base := ownerSnapshot(t, v, "shared")
	old, err := previewOwnerTransfer(p, ownerScopeGroup, 501, base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*store.OwnerTransferSnapshot){
		"client owner":       func(s *store.OwnerTransferSnapshot) { s.Clients[0].OwnerUsername = ownerText("bob") },
		"client enabled":     func(s *store.OwnerTransferSnapshot) { s.Clients[0].Enabled = false },
		"client name":        func(s *store.OwnerTransferSnapshot) { s.Clients[0].ClientName = ownerText("renamed") },
		"credential owner":   func(s *store.OwnerTransferSnapshot) { s.Credentials[0].OwnerUsername = ownerText("bob") },
		"credential enabled": func(s *store.OwnerTransferSnapshot) { s.Credentials[0].Enabled = true },
		"peer owner":         func(s *store.OwnerTransferSnapshot) { s.Peers[0].OwnerUsername = ownerText("bob") },
		"peer enabled":       func(s *store.OwnerTransferSnapshot) { s.Peers[0].Enabled = false },
		"peer name":          func(s *store.OwnerTransferSnapshot) { s.Peers[0].ClientName = ownerText("renamed") },
		"complete deletion":  func(s *store.OwnerTransferSnapshot) { s.Clients = s.Clients[:1]; s.Identities = s.Identities[:1] },
		"new client": func(s *store.OwnerTransferSnapshot) {
			row := s.Clients[1]
			row.ID = 1003
			s.Clients = append(s.Clients, row)
			edge := s.Identities[1]
			edge.ID = 703
			edge.ClientID = 1003
			s.Identities = append(s.Identities, edge)
		},
		"identity id":  func(s *store.OwnerTransferSnapshot) { s.Identities[0].ID = 799 },
		"peer removed": func(s *store.OwnerTransferSnapshot) { s.Peers = nil },
		"peer id":      func(s *store.OwnerTransferSnapshot) { s.Peers[0].ID = 899 },
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			var current store.OwnerTransferSnapshot
			ownerRoundTrip(t, base, &current)
			change(&current)
			result, err := previewOwnerTransfer(p, ownerScopeGroup, 501, current)
			if err != nil || result.Revision == nil || *result.Revision == *old.Revision {
				t.Fatalf("change did not invalidate revision: %v", err)
			}
			_, _, err = prepareOwnerTransfer(p, ownerScopeGroup, 501, map[string]any{"scope": ownerScopeGroup, "targetUsername": "bob", "expectedRevision": *old.Revision}, current)
			assertOwnerProblem(t, err, 409, "TRANSFER_PREVIEW_CHANGED")
		})
	}
	// Order, acting administrator and unrelated foreign Peer rows do not alter the revision.
	data := ownerSnapshot(t, v, "foreign-peer")
	slices.Reverse(data.Clients)
	slices.Reverse(data.Credentials)
	slices.Reverse(data.Identities)
	slices.Reverse(data.Peers)
	p.Username = "other-admin"
	result, err := previewOwnerTransfer(p, ownerScopeGroup, 501, data)
	if err != nil || !reflect.DeepEqual(old, result) {
		t.Fatalf("order/actor/foreign Peer changed revision: %v", err)
	}
	for i := range data.Clients {
		data.Clients[i].TenantID = "other"
	}
	for i := range data.Credentials {
		data.Credentials[i].TenantID = "other"
	}
	for i := range data.Identities {
		data.Identities[i].TenantID = "other"
	}
	data.Peers = nil
	p.TenantID = "other"
	result, err = previewOwnerTransfer(p, ownerScopeGroup, 501, data)
	if err != nil || *result.Revision == *old.Revision {
		t.Fatal("revision not tenant bound")
	}
	p.TenantID = v.TenantID
	unique := ownerSnapshot(t, v, "unique")
	single, _ := previewOwnerTransfer(p, ownerScopeSingle, 1001, unique)
	group, _ := previewOwnerTransfer(p, ownerScopeGroup, 501, unique)
	if single.Revision == nil || group.Revision == nil || *single.Revision == *group.Revision {
		t.Fatal("revision not scope/path bound")
	}
	legacy := ownerSnapshot(t, v, "legacy")
	first, _ := previewOwnerTransfer(p, ownerScopeSingle, 1001, legacy)
	second, _ := previewOwnerTransfer(p, ownerScopeSingle, 1002, legacy)
	if *first.Revision == *second.Revision {
		t.Fatal("revision not path bound")
	}
	_, _, err = prepareOwnerTransfer(p, ownerScopeGroup, 501, map[string]any{"scope": ownerScopeGroup, "targetUsername": "bob", "expectedRevision": " " + *old.Revision}, base)
	assertOwnerProblem(t, err, 409, "TRANSFER_PREVIEW_CHANGED")
	base.Clients[0].ClientName = ownerText("one\ntwo")
	base.Clients[0].OwnerUsername = ownerText("three")
	one, _ := previewOwnerTransfer(p, ownerScopeGroup, 501, base)
	base.Clients[0].ClientName = ownerText("one")
	base.Clients[0].OwnerUsername = ownerText("two\nthree")
	two, _ := previewOwnerTransfer(p, ownerScopeGroup, 501, base)
	if *one.Revision == *two.Revision {
		t.Fatal("ambiguous revision text encoding")
	}
	base.Clients[0].OwnerUsername = nil
	nullOwner, _ := previewOwnerTransfer(p, ownerScopeGroup, 501, base)
	base.Clients[0].OwnerUsername = ownerText("")
	emptyOwner, _ := previewOwnerTransfer(p, ownerScopeGroup, 501, base)
	if *nullOwner.Revision == *emptyOwner.Revision {
		t.Fatal("null and empty owner collapsed")
	}
}
func ownerText(value string) *string { return &value }

// Use actual routing, authentication and SQLite. SQL is used only for deterministic fixtures.
func TestOwnerTransferPreviewHTTPVectors(t *testing.T) {
	v := readOwnerVector(t)
	for _, c := range v.Cases {
		if c.Request != nil || c.Snapshot == "duplicate-peer" {
			continue
		} // Duplicate Peer is rejected by the actual DB constraint; pure vector covers corrupted snapshots.
		t.Run(c.Name, func(t *testing.T) {
			h := newWorkbenchHTTPHarness(t)
			snapshot := ownerSnapshot(t, v, c.Snapshot)
			seedOwnerSnapshot(t, h, &snapshot, v.TenantID)
			connection, err := sql.Open("sqlite", h.dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			connection.SetMaxOpenConns(1)
			var before, after int
			if err := connection.QueryRow("PRAGMA data_version").Scan(&before); err != nil {
				t.Fatal(err)
			}
			path := "/api/admin/client-credentials/" + strconv.FormatInt(c.ID, 10) + "/owner-transfer"
			if c.Scope == ownerScopeSingle {
				path = "/api/admin/clients/" + strconv.FormatInt(c.ID, 10) + "/owner-transfer"
			}
			response, payload := h.do(http.MethodGet, path, h.fixtureToken("t1"), nil)
			want := 200
			if c.Error != nil {
				want = c.Error.Status
			}
			if response.StatusCode != want || response.Header.Get("Cache-Control") != "private, no-store" {
				t.Fatalf("status=%d cache=%q body=%s", response.StatusCode, response.Header.Get("Cache-Control"), payload)
			}
			if c.Error != nil {
				var problem map[string]string
				if err := json.Unmarshal(payload, &problem); err != nil || problem["code"] != c.Error.Code || problem["error"] == "" {
					t.Fatalf("error body=%s", payload)
				}
			} else {
				var preview ownerTransferPreview
				if err := json.Unmarshal(payload, &preview); err != nil {
					t.Fatal(err)
				}
				assertOwnerPreview(t, preview, c, snapshot)
			}
			for _, secret := range []string{"secret-marker", "password", "fingerprint", "privateKey", "secret-other"} {
				if strings.Contains(string(payload), secret) {
					t.Fatalf("preview leaked %s: %s", secret, payload)
				}
			}
			if err := connection.QueryRow("PRAGMA data_version").Scan(&after); err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Fatal("preview committed database changes")
			}
		})
	}
}

func seedOwnerSnapshot(t *testing.T, h *workbenchHarness, data *store.OwnerTransferSnapshot, tenant string) {
	t.Helper()
	now := time.Now()
	text := func(value *string) string {
		if value == nil {
			return ""
		}
		return *value
	}
	for i := range data.Clients {
		row := &data.Clients[i]
		if row.TenantID == tenant {
			row.TenantID = "t1"
		}
		if err := h.db.InsertClient(h.ctx, store.ClientAccount{ID: row.ID, TenantID: row.TenantID, ClientName: text(row.ClientName), OwnerUsername: text(row.OwnerUsername), Enabled: row.Enabled, PasswordHash: "secret-marker-password", CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range data.Credentials {
		row := &data.Credentials[i]
		if row.TenantID == tenant {
			row.TenantID = "t1"
		}
		if err := h.db.InsertCredential(h.ctx, store.ClientCredential{ID: row.ID, TenantID: row.TenantID, OwnerUsername: text(row.OwnerUsername), Enabled: row.Enabled, APIKey: fmt.Sprint("secret-marker-key-", row.ID), SecretHash: "secret-marker-hash", MaxOnlineInstances: 5, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range data.Identities {
		row := &data.Identities[i]
		if row.TenantID == tenant {
			row.TenantID = "t1"
		}
		if err := h.db.InsertIdentity(h.ctx, store.ClientIdentity{ID: row.ID, TenantID: row.TenantID, CredentialID: row.CredentialID, ClientID: row.ClientID, ClientName: fmt.Sprint("identity-", row.ID), MachineFingerprint: fmt.Sprint("secret-marker-fingerprint-", row.ID), OSUser: "test", FirstSeenAt: now, LastSeenAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range data.Peers {
		row := &data.Peers[i]
		if row.TenantID == tenant {
			row.TenantID = "t1"
		}
		if err := h.db.InsertPeerMeshDevice(h.ctx, store.PeerMeshDevice{ID: row.ID, TenantID: row.TenantID, ClientID: row.ClientID, ClientName: text(row.ClientName), OwnerUsername: text(row.OwnerUsername), Enabled: row.Enabled, VirtualIP: fmt.Sprint("100.96.", row.ID/255, ".", row.ID%255), CIDR: "100.96.0.0/11", PublicKey: ownerText("secret-marker-public-key"), CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOwnerTransferPreviewHTTPAuthorizationAndPath(t *testing.T) {
	h := newWorkbenchHTTPHarness(t)
	for _, prefix := range []string{"/api/admin/clients/", "/api/admin/client-credentials/"} {
		for _, c := range []struct {
			token, id string
			status    int
			code      string
		}{
			{"", "invalid", 401, ""}, {"bad-token", "invalid", 401, ""},
			{h.token("t1", "alice"), "invalid", 403, "FORBIDDEN"},
			{h.fixtureToken("t1"), "0", 400, "INVALID_TRANSFER_REQUEST"},
			{h.fixtureToken("t1"), "+1", 400, "INVALID_TRANSFER_REQUEST"},
			{h.fixtureToken("t1"), "1.0", 400, "INVALID_TRANSFER_REQUEST"},
			{h.fixtureToken("t1"), "9007199254740992", 400, "INVALID_TRANSFER_REQUEST"},
			{h.fixtureToken("t1"), "99999999999999999999", 400, "INVALID_TRANSFER_REQUEST"},
			{h.fixtureToken("t1"), "42", 404, "RESOURCE_NOT_FOUND"},
		} {
			response, payload := h.do(http.MethodGet, prefix+c.id+"/owner-transfer", c.token, nil)
			if response.StatusCode != c.status || response.Header.Get("Cache-Control") != "private, no-store" {
				t.Fatalf("status=%d cache=%q body=%s", response.StatusCode, response.Header.Get("Cache-Control"), payload)
			}
			if c.code != "" {
				var problem map[string]string
				ownerRoundTrip(t, json.RawMessage(payload), &problem)
				if problem["code"] != c.code {
					t.Fatalf("body=%s", payload)
				}
			}
		}
		response, _ := h.do(http.MethodPost, prefix+"42/owner-transfer", h.fixtureToken("t1"), map[string]string{"scope": ownerScopeGroup})
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("write endpoint must reject missing resource before missing fields: %d", response.StatusCode)
		}
	}
}

func TestOwnerTransferPreviewHTTPLargeGroupAndLiveness(t *testing.T) {
	h := newWorkbenchHTTPHarness(t)
	data := store.OwnerTransferSnapshot{Credentials: []store.OwnerTransferCredential{{ID: 501, TenantID: "t1", OwnerUsername: ownerText("alice"), Enabled: false}}}
	for n := 0; n < 1050; n++ {
		id := int64(1001 + n)
		data.Clients = append(data.Clients, store.OwnerTransferClient{ID: id, TenantID: "t1", ClientName: ownerText(fmt.Sprint("device-", n)), OwnerUsername: ownerText("alice"), Enabled: n%2 == 0})
		data.Identities = append(data.Identities, store.OwnerTransferIdentity{ID: int64(10001 + n), TenantID: "t1", CredentialID: 501, ClientID: id})
	}
	seedLargeOwnerSnapshotFixture(t, h, data)
	load := func() ownerTransferPreview {
		t.Helper()
		response, payload := h.do(http.MethodGet, "/api/admin/client-credentials/501/owner-transfer", h.fixtureToken("t1"), nil)
		if response.StatusCode != 200 {
			t.Fatalf("status=%d body=%s", response.StatusCode, payload)
		}
		var result ownerTransferPreview
		if err := json.Unmarshal(payload, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	first := load()
	if first.AffectedClientCount != 1050 || len(first.AffectedClients) != 1050 || first.AffectedClients[1049].ID != 2050 {
		t.Fatal("large group truncated or not ordered")
	}
	connection, err := sql.Open("sqlite", h.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Exec("UPDATE specus_client_identity SET last_seen_at = '2026-10-14T12:00:00Z'"); err != nil {
		t.Fatal(err)
	}
	second := load()
	if !reflect.DeepEqual(first, second) {
		t.Fatal("identity liveness invalidated preview")
	}
	if _, err := connection.Exec("UPDATE specus_client_account SET client_name='renamed' WHERE id=1001"); err != nil {
		t.Fatal(err)
	}
	third := load()
	if *first.Revision == *third.Revision {
		t.Fatal("name change did not invalidate revision")
	}
}

// Two actual HTTP API instances use independent database connections. This proves preview
// revisions are stateless; it does not stand in for the future cross-instance transfer writer.
func TestOwnerTransferPreviewAcrossAPIInstances(t *testing.T) {
	h := newWorkbenchHTTPHarness(t)
	v := readOwnerVector(t)
	data := ownerSnapshot(t, v, "shared")
	seedOwnerSnapshot(t, h, &data, v.TenantID)
	firstResponse, firstPayload := h.do(http.MethodGet, "/api/admin/client-credentials/501/owner-transfer", h.fixtureToken("t1"), nil)
	if firstResponse.StatusCode != http.StatusOK {
		t.Fatalf("first body=%s", firstPayload)
	}
	secondDB, err := store.Open("sqlite", h.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := secondDB.Close(); err != nil {
			t.Error(err)
		}
	})
	secondAPI := *h.api
	secondAPI.db = secondDB
	mux := http.NewServeMux()
	secondAPI.Register(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	request, err := http.NewRequest(http.MethodGet, server.URL+"/api/admin/client-credentials/501/owner-transfer", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+h.fixtureToken("t1"))
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var first, second ownerTransferPreview
	if err := json.Unmarshal(firstPayload, &first); err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(response.Body).Decode(&second); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "private, no-store" || !reflect.DeepEqual(first, second) {
		t.Fatalf("second instance status=%d preview=%+v", response.StatusCode, second)
	}
}
