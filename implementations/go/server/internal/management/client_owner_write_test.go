package management

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// Exercise the service with a previously resolved bearer identity and database write,
// then check current REST visibility through the real router (including a stale actor).
func TestOwnerWriteServiceUsesCurrentIdentityAndRESTOwnership(t *testing.T) {
	h := newWorkbenchHTTPHarness(t)
	now := time.Now()
	if err := h.db.InsertClient(h.ctx, store.ClientAccount{ID: 1001, TenantID: "t1", OwnerUsername: "alice", ClientName: "service-device", PasswordHash: "fixture-hash", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	p, ok := h.api.authenticate(h.ctx, h.fixtureToken("t1"))
	if !ok || p.AccountKey == "" || !p.Admin {
		t.Fatal("real bearer did not resolve to current admin account")
	}
	response, payload := h.do(http.MethodGet, "/api/admin/clients/1001/owner-transfer", h.fixtureToken("t1"), nil)
	var preview ownerTransferPreview
	if response.StatusCode != 200 || json.Unmarshal(payload, &preview) != nil || preview.Revision == nil {
		t.Fatalf("preview: %d %s", response.StatusCode, payload)
	}
	out, err := h.api.commitOwnerTransfer(h.ctx, p, ownerScopeSingle, "1001", map[string]any{"scope": ownerScopeSingle, "targetUsername": "BoB", "expectedRevision": *preview.Revision})
	if err != nil || !out.Response.Changed || out.Response.TargetUsername != "bob" || out.AuditID == nil {
		t.Fatalf("service write: %+v / %v", out, err)
	}
	for _, check := range []struct {
		user   string
		status int
	}{{"alice", 403}, {"bob", 200}, {"root", 200}} {
		response, payload := h.do(http.MethodGet, "/api/admin/clients/1001", h.token("t1", check.user), nil)
		if response.StatusCode != check.status {
			t.Fatalf("current REST as %s: %d %s", check.user, response.StatusCode, payload)
		}
	}
	user, err := h.db.FindManagementUserByAccountKey(h.ctx, p.AccountKey)
	if err != nil || user == nil {
		t.Fatal(err)
	}
	user.Enabled = false
	if err := h.db.UpdateManagementUser(h.ctx, *user); err != nil {
		t.Fatal(err)
	}
	_, err = h.api.commitOwnerTransfer(h.ctx, p, ownerScopeSingle, "1001", map[string]any{"scope": ownerScopeSingle, "targetUsername": "alice", "expectedRevision": *preview.Revision})
	if !errors.Is(err, store.ErrManagementActorChanged) {
		t.Fatalf("stale resolved actor wrote: %v", err)
	}
}
