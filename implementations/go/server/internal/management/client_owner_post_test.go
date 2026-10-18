package management

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/ownership"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// Real TCP HTTP routing, bearer authentication and transactional SQLite writes.
// The journal is deliberately drained only after HTTP completes: success is not
// dependent on a request-scoped network callback or an in-memory notification.
func TestOwnerTransferPOSTCommitsAndReplaysOnIndependentNodes(t *testing.T) {
	for _, c := range []struct {
		name, snapshot, scope string
		id                    int64
		ids                   []int64
	}{
		{"legacy", "legacy", ownerScopeSingle, 1001, []int64{1001}},
		{"unique", "unique", ownerScopeSingle, 1001, []int64{1001}},
		{"shared-group", "shared", ownerScopeGroup, 501, []int64{1001, 1002}},
		{"zero-device", "empty", ownerScopeGroup, 501, []int64{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newWorkbenchHTTPHarness(t)
			v := readOwnerVector(t)
			data := ownerSnapshot(t, v, c.snapshot)
			seedOwnerSnapshot(t, h, &data, v.TenantID)
			n, err := ownership.New(h.db, h.api.peerMesh, nil)
			if err != nil {
				t.Fatal(err)
			}
			h.api.SetOwnerNotifications(n)
			path := fmt.Sprintf("/api/admin/clients/%d/owner-transfer", c.id)
			if c.scope == ownerScopeGroup {
				path = fmt.Sprintf("/api/admin/client-credentials/%d/owner-transfer", c.id)
			}
			response, payload := h.do(http.MethodGet, path, h.fixtureToken("t1"), nil)
			var preview ownerTransferPreview
			if response.StatusCode != 200 || json.Unmarshal(payload, &preview) != nil || preview.Revision == nil {
				t.Fatalf("preview: %d %s", response.StatusCode, payload)
			}
			response, payload = h.do(http.MethodPost, path, h.fixtureToken("t1"), map[string]any{"scope": c.scope, "targetUsername": "BoB", "expectedRevision": *preview.Revision})
			var result store.OwnerTransferResult
			if response.StatusCode != 200 || json.Unmarshal(payload, &result) != nil || !result.Changed || !result.AccessRetained || result.TargetUsername != "bob" || !reflect.DeepEqual(result.AffectedClientIDs, c.ids) || response.Header.Get("Cache-Control") != "private, no-store" {
				t.Fatalf("POST: %d %s", response.StatusCode, payload)
			}
			for _, id := range c.ids {
				row, err := h.db.GetClient(h.ctx, id)
				if err != nil || row.OwnerUsername != "bob" || row.PasswordHash != "secret-marker-password" {
					t.Fatalf("transferred client: %+v %v", row, err)
				}
			}
			connection, err := sql.Open("sqlite", h.dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			var audits, receipts int
			if err := connection.QueryRow("SELECT COUNT(*) FROM client_owner_transfer_audit").Scan(&audits); err != nil || audits != 1 {
				t.Fatalf("durable audit=%d %v", audits, err)
			}
			if err := connection.QueryRow("SELECT COUNT(*) FROM client_owner_transfer_receipt").Scan(&receipts); err != nil || receipts != 0 {
				t.Fatalf("premature receipts=%d %v", receipts, err)
			}
			// A second process incarnation must independently observe the same committed audit.
			n2, err := ownership.New(h.db, h.api.peerMesh, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := n.Drain(h.ctx); err != nil {
				t.Fatal(err)
			}
			if err := n2.Drain(h.ctx); err != nil {
				t.Fatal(err)
			}
			if err := connection.QueryRow("SELECT COUNT(*) FROM client_owner_transfer_receipt").Scan(&receipts); err != nil || receipts != 2 {
				t.Fatalf("independent receipts=%d %v", receipts, err)
			}
			// Re-read and explicitly confirm a no-op, rather than retrying the old revision.
			response, payload = h.do(http.MethodGet, path, h.fixtureToken("t1"), nil)
			if response.StatusCode != 200 || json.Unmarshal(payload, &preview) != nil || preview.Revision == nil {
				t.Fatal("fresh preview missing")
			}
			response, payload = h.do(http.MethodPost, path, h.fixtureToken("t1"), map[string]any{"scope": c.scope, "targetUsername": "bob", "expectedRevision": *preview.Revision})
			if response.StatusCode != 200 || json.Unmarshal(payload, &result) != nil || result.Changed {
				t.Fatalf("no-op: %d %s", response.StatusCode, payload)
			}
			if err := connection.QueryRow("SELECT COUNT(*) FROM client_owner_transfer_audit").Scan(&audits); err != nil || audits != 1 {
				t.Fatalf("duplicate audit=%d %v", audits, err)
			}
		})
	}
}

func TestOwnerTransferPOSTSharedRequestVectors(t *testing.T) {
	v := readOwnerVector(t)
	for _, c := range v.Cases {
		if c.Request == nil {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			h := newWorkbenchHTTPHarness(t)
			data := ownerSnapshot(t, v, c.Snapshot)
			seedOwnerSnapshot(t, h, &data, v.TenantID)
			path := fmt.Sprintf("/api/admin/clients/%d/owner-transfer", c.ID)
			if c.Scope == ownerScopeGroup {
				path = fmt.Sprintf("/api/admin/client-credentials/%d/owner-transfer", c.ID)
			}
			before, err := h.db.LoadOwnerTransferSnapshot(h.ctx, "t1", c.Scope, c.ID)
			if err != nil {
				t.Fatal(err)
			}
			var body any
			if err := json.Unmarshal(c.Request, &body); err != nil {
				t.Fatal(err)
			}
			if object, ok := body.(map[string]any); ok && object["expectedRevision"] == "$current" {
				response, payload := h.do(http.MethodGet, path, h.fixtureToken("t1"), nil)
				var preview ownerTransferPreview
				if response.StatusCode != 200 || json.Unmarshal(payload, &preview) != nil || preview.Revision == nil {
					t.Fatalf("preview: %d %s", response.StatusCode, payload)
				}
				object["expectedRevision"] = *preview.Revision
			}
			token := h.fixtureToken("t1")
			if c.Admin != nil && !*c.Admin {
				token = h.token("t1", "alice")
			}
			response, payload := h.do(http.MethodPost, path, token, body)
			if response.Header.Get("Cache-Control") != "private, no-store" {
				t.Fatal("missing no-store")
			}
			if c.Error == nil {
				if response.StatusCode != 200 {
					t.Fatalf("valid POST: %d %s", response.StatusCode, payload)
				}
			} else {
				var problem map[string]string
				if response.StatusCode != c.Error.Status || json.Unmarshal(payload, &problem) != nil || problem["code"] != c.Error.Code || problem["error"] == "" {
					t.Fatalf("error precedence: %d %s", response.StatusCode, payload)
				}
				after, err := h.db.LoadOwnerTransferSnapshot(h.ctx, "t1", c.Scope, c.ID)
				if err != nil || ownerJSON(t, before) != ownerJSON(t, after) {
					t.Fatal("rejected POST changed resource state", err)
				}
			}
			for _, secret := range []string{"secret-marker", "password", "fingerprint", "secret-other"} {
				if strings.Contains(string(payload), secret) {
					t.Fatalf("POST response leaked %s", secret)
				}
			}
		})
	}
}

func TestOwnerTransferPOSTAuthenticatesBeforeDecodingAndRejectsTrailingJSON(t *testing.T) {
	h := newWorkbenchHTTPHarness(t)
	v := readOwnerVector(t)
	data := ownerSnapshot(t, v, "unique")
	seedOwnerSnapshot(t, h, &data, v.TenantID)
	for _, prefix := range []string{"/api/admin/clients/", "/api/admin/client-credentials/"} {
		for _, c := range []struct {
			token, id, body string
			status          int
			code            string
		}{
			{"", "bad", "{", 401, ""},
			{"invalid", "bad", "{", 401, ""},
			{h.token("t1", "alice"), "bad", "{", 403, "FORBIDDEN"},
			{h.fixtureToken("t1"), "bad", "{}", 400, "INVALID_TRANSFER_REQUEST"},
			{h.fixtureToken("t1"), "9007199254740992", "{}", 400, "INVALID_TRANSFER_REQUEST"},
			{h.fixtureToken("t1"), "999", "{", 400, "INVALID_TRANSFER_REQUEST"},
			{h.fixtureToken("t1"), "999", "{} {}", 400, "INVALID_TRANSFER_REQUEST"},
			{h.fixtureToken("t1"), "999", "{}garbage", 400, "INVALID_TRANSFER_REQUEST"},
			{h.fixtureToken("t1"), "999", "null", 400, "INVALID_TRANSFER_REQUEST"},
			{h.fixtureToken("t1"), "999", "{}", 404, "RESOURCE_NOT_FOUND"},
			{h.fixtureToken("t1"), "999", `{"scope":"` + strings.Repeat("x", 65536) + `"}`, 400, "INVALID_TRANSFER_REQUEST"},
		} {
			request, err := http.NewRequest(http.MethodPost, h.server.URL+prefix+c.id+"/owner-transfer", strings.NewReader(c.body))
			if err != nil {
				t.Fatal(err)
			}
			if c.token != "" {
				request.Header.Set("Authorization", "Bearer "+c.token)
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != c.status || response.Header.Get("Cache-Control") != "private, no-store" {
				t.Fatalf("POST %s: %d %s %v", c.id, response.StatusCode, payload, err)
			}
			if c.code != "" {
				var problem map[string]string
				if json.Unmarshal(payload, &problem) != nil || problem["code"] != c.code {
					t.Fatalf("error body=%s", payload)
				}
			}
		}
	}
}

func TestOwnerTransferPOSTRollbackAndStalePreview(t *testing.T) {
	h := newWorkbenchHTTPHarness(t)
	v := readOwnerVector(t)
	data := ownerSnapshot(t, v, "unique")
	seedOwnerSnapshot(t, h, &data, v.TenantID)
	path := "/api/admin/clients/1001/owner-transfer"
	response, payload := h.do(http.MethodGet, path, h.fixtureToken("t1"), nil)
	var preview ownerTransferPreview
	if response.StatusCode != 200 || json.Unmarshal(payload, &preview) != nil || preview.Revision == nil {
		t.Fatal("missing preview")
	}
	body := map[string]any{"scope": ownerScopeSingle, "targetUsername": "bob", "expectedRevision": *preview.Revision}
	connection, err := sql.Open("sqlite", h.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Exec(`CREATE TRIGGER reject_post_audit BEFORE INSERT ON client_owner_transfer_audit BEGIN SELECT RAISE(ABORT,'injected POST audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	response, payload = h.do(http.MethodPost, path, h.fixtureToken("t1"), body)
	if response.StatusCode != 500 {
		t.Fatalf("audit fault: %d %s", response.StatusCode, payload)
	}
	row, err := h.db.GetClient(h.ctx, 1001)
	if err != nil || row.OwnerUsername != "alice" {
		t.Fatal("audit failure committed owner", err)
	}
	if _, err := connection.Exec("DROP TRIGGER reject_post_audit"); err != nil {
		t.Fatal(err)
	}
	row.ClientName = "renamed-after-preview"
	if err := h.db.UpdateClient(h.ctx, *row); err != nil {
		t.Fatal(err)
	}
	response, payload = h.do(http.MethodPost, path, h.fixtureToken("t1"), body)
	var problem map[string]string
	if response.StatusCode != 409 || json.Unmarshal(payload, &problem) != nil || problem["code"] != "TRANSFER_PREVIEW_CHANGED" {
		t.Fatalf("stale preview: %d %s", response.StatusCode, payload)
	}
	var count int
	if err := connection.QueryRow("SELECT COUNT(*) FROM client_owner_transfer_audit").Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected audit count=%d %v", count, err)
	}
}
