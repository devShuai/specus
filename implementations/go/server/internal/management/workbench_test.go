package management

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func newWorkbenchHTTPHarness(t *testing.T) *workbenchHarness {
	t.Helper()
	h := newWorkbenchHarness(t, time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC))
	h.addFixtureAdmin("t1")
	for _, user := range []workbenchVectorIdentity{
		{TenantID: "t1", Username: "alice"},
		{TenantID: "t1", Username: "bob"},
		{TenantID: "t1", Username: "root", Admin: true},
	} {
		h.addUser(user)
	}
	return h
}

// call performs one workbench request and checks status and Cache-Control.
func (h *workbenchHarness) call(method, path, username string, body any, wantStatus int) []byte {
	h.t.Helper()
	token := ""
	if username != "" {
		token = h.token("t1", username)
	}
	response, payload := h.do(method, "/api/admin/workbench"+path, token, body)
	if response.StatusCode != wantStatus {
		h.t.Fatalf("%s %s as %q: status %d, want %d; body=%s", method, path, username, response.StatusCode,
			wantStatus, payload)
	}
	if got := response.Header.Get("Cache-Control"); got != "private, no-store" {
		h.t.Fatalf("%s %s: Cache-Control = %q", method, path, got)
	}
	return payload
}

func (h *workbenchHarness) refs(username string) (favorites, recents []string) {
	h.t.Helper()
	var document workbenchDocument
	if err := json.Unmarshal(h.call(http.MethodGet, "", username, nil, http.StatusOK), &document); err != nil {
		h.t.Fatal(err)
	}
	favorites, recents = []string{}, []string{}
	for _, entry := range document.Favorites {
		favorites = append(favorites, entry.Kind+"/"+strconv.FormatInt(entry.ID, 10))
	}
	for _, entry := range document.Recents {
		recents = append(recents, entry.Kind+"/"+strconv.FormatInt(entry.ID, 10))
	}
	return favorites, recents
}

func (h *workbenchHarness) expectRefs(username string, favorites, recents []string) {
	h.t.Helper()
	gotFavorites, gotRecents := h.refs(username)
	if !reflect.DeepEqual(gotFavorites, favorites) || !reflect.DeepEqual(gotRecents, recents) {
		h.t.Fatalf("%s: favourites %v recents %v, want %v %v", username, gotFavorites, gotRecents, favorites, recents)
	}
}

func TestWorkbenchRequiresASession(t *testing.T) {
	h := newWorkbenchHTTPHarness(t)
	for _, request := range []struct{ method, path string }{
		{http.MethodGet, ""},
		{http.MethodPut, "/favorites/http-route/1"},
		{http.MethodPost, "/recents/http-route/1"},
		{http.MethodDelete, "/favorites"},
		{http.MethodDelete, "/recents/http-route/1"},
	} {
		h.call(request.method, request.path, "", nil, http.StatusUnauthorized)
		response, _ := h.do(request.method, "/api/admin/workbench"+request.path, "not-a-token", nil)
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s %s with a forged token: %d", request.method, request.path, response.StatusCode)
		}
	}
}

// No request names an identity: query strings and bodies are ignored, and an administrator sees and
// clears only their own lists.
func TestWorkbenchListsBelongToTheCaller(t *testing.T) {
	h := newWorkbenchHTTPHarness(t)
	h.addObject(workbenchVectorObject{Kind: store.WorkbenchKindHTTPRoute, ID: 1, TenantID: "t1", OwnerUsername: "alice"})
	h.setClock(1_000)
	h.call(http.MethodPut, "/favorites/http-route/1", "alice", nil, http.StatusOK)
	h.call(http.MethodPost, "/recents/http-route/1", "alice", nil, http.StatusOK)

	h.expectRefs("root", []string{}, []string{})
	var document workbenchDocument
	if err := json.Unmarshal(h.call(http.MethodGet, "?tenantId=t1&username=alice", "root", nil, http.StatusOK),
		&document); err != nil || len(document.Favorites) != 0 || len(document.Recents) != 0 {
		t.Fatalf("a query string named another identity: %+v %v", document, err)
	}
	h.call(http.MethodDelete, "/favorites?username=alice", "root", nil, http.StatusOK)
	h.call(http.MethodDelete, "/recents", "root", map[string]string{"username": "alice"}, http.StatusOK)
	h.expectRefs("alice", []string{"http-route/1"}, []string{"http-route/1"})

	// A body naming alice does not make the write hers: the administrator's own list grows.
	h.setClock(2_000)
	h.call(http.MethodPut, "/favorites/http-route/1", "root", map[string]string{"tenantId": "t1", "username": "alice"},
		http.StatusOK)
	h.expectRefs("root", []string{"http-route/1"}, []string{})
	h.expectRefs("alice", []string{"http-route/1"}, []string{"http-route/1"})
	// bob neither owns nor administers the route.
	h.call(http.MethodPut, "/favorites/http-route/1", "bob", nil, http.StatusNotFound)
	h.expectRefs("bob", []string{}, []string{})

	rows := h.vectorRows()
	want := []workbenchVectorRow{
		{TenantID: "t1", Username: "alice", List: "favorite", Kind: "http-route", ID: 1, AtMs: 1_000},
		{TenantID: "t1", Username: "alice", List: "recent", Kind: "http-route", ID: 1, AtMs: 1_000},
		{TenantID: "t1", Username: "root", List: "favorite", Kind: "http-route", ID: 1, AtMs: 2_000},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows %+v, want %+v", rows, want)
	}
}

func TestWorkbenchValidatesThePathAsText(t *testing.T) {
	h := newWorkbenchHTTPHarness(t)
	h.addObject(workbenchVectorObject{Kind: store.WorkbenchKindHTTPRoute, ID: 42, TenantID: "t1", OwnerUsername: "alice"})
	for _, request := range []struct{ method, path string }{
		{http.MethodPut, "/favorites/http-route/042"},
		{http.MethodPut, "/favorites/http-route/+42"},
		{http.MethodPut, "/favorites/http-route/42.0"},
		{http.MethodPut, "/favorites/Http-Route/42"},
		{http.MethodPost, "/recents/http-route/%2042"},
		{http.MethodDelete, "/recents/peer-service/9007199254740992"},
	} {
		payload := h.call(request.method, request.path, "alice", nil, http.StatusBadRequest)
		var body struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(payload, &body); err != nil || body.Code != workbenchCodeInvalid {
			t.Fatalf("%s %s: %s", request.method, request.path, payload)
		}
	}
	h.call(http.MethodPut, "/favorites/http-route/42", "alice", nil, http.StatusOK)
	h.call(http.MethodPut, "/favorites/http-route/43", "alice", nil, http.StatusNotFound)
}

// Deleting a route, a mapping, a Peer service, a client or an account through the existing
// endpoints removes every reference to it, for every identity.
func TestWorkbenchCascadesThroughDeleteEndpoints(t *testing.T) {
	h := newWorkbenchHTTPHarness(t)
	single := func(kind string, id int64) {
		h.addObject(workbenchVectorObject{Kind: kind, ID: id, TenantID: "t1", OwnerUsername: "alice"})
	}
	single(store.WorkbenchKindHTTPRoute, 1)
	single(store.WorkbenchKindTCPMapping, 2)
	single(store.WorkbenchKindPeerService, 3)
	carrier := h.addClient("t1", "alice")
	for _, object := range []workbenchVectorObject{
		{Kind: store.WorkbenchKindHTTPRoute, ID: 10}, {Kind: store.WorkbenchKindTCPMapping, ID: 11},
		{Kind: store.WorkbenchKindPeerService, ID: 12},
	} {
		object.TenantID, object.OwnerUsername = "t1", "alice"
		h.addService(object, carrier)
	}
	single(store.WorkbenchKindHTTPRoute, 20)
	all := []string{"http-route/1", "tcp-mapping/2", "peer-service/3", "http-route/10", "tcp-mapping/11",
		"peer-service/12", "http-route/20"}
	for i, ref := range all {
		h.setClock(int64(1_000 * (i + 1)))
		for _, user := range []string{"alice", "root"} {
			h.call(http.MethodPut, "/favorites/"+ref, user, nil, http.StatusOK)
			h.call(http.MethodPost, "/recents/"+ref, user, nil, http.StatusOK)
		}
	}
	reversed := func(refs []string) []string {
		out := make([]string, 0, len(refs))
		for i := len(refs) - 1; i >= 0; i-- {
			out = append(out, refs[i])
		}
		return out
	}
	alice := h.token("t1", "alice")
	root := h.token("t1", "root")
	h.expect2xx("delete route", http.MethodDelete, "/api/admin/http-routes/1", alice, nil)
	h.expect2xx("delete mapping", http.MethodDelete, "/api/admin/specus-mappings/2", alice, nil)
	h.expect2xx("delete Peer service", http.MethodDelete, "/api/admin/peer-mesh/services/3", root, nil)
	left := all[3:]
	h.expectRefs("alice", left, reversed(left))
	h.expectRefs("root", left, reversed(left))

	h.expect2xx("delete client", http.MethodDelete, "/api/admin/clients/"+strconv.FormatInt(carrier.ID, 10), root, nil)
	left = all[6:]
	h.expectRefs("alice", left, left)
	h.expectRefs("root", left, left)

	// An account that still owns clients is not deleted (management-accounts.md 7.1): alice's
	// remaining clients go to root first, by data as no endpoint changes an owner.
	clients, err := h.db.ListClients(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range clients {
		if client.TenantID == "t1" && client.OwnerUsername == "alice" {
			client.OwnerUsername = "root"
			if err := h.db.UpdateClient(h.ctx, client); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Deleting the account deletes its rows in the same request; a new account with the same name
	// starts empty, and the old token cannot write rows back meanwhile.
	h.expect2xx("delete account", http.MethodDelete, "/api/admin/users/alice", h.fixtureToken("t1"), nil)
	response, _ := h.do(http.MethodPost, "/api/admin/workbench/recents/http-route/20", alice, nil)
	if response.StatusCode/100 == 2 {
		t.Fatalf("a deleted account wrote: %d", response.StatusCode)
	}
	for _, row := range h.vectorRows() {
		if row.Username == "alice" {
			t.Fatalf("row survived the account: %+v", row)
		}
	}
	h.expect2xx("recreate account", http.MethodPost, "/api/admin/users", h.fixtureToken("t1"),
		map[string]any{"username": "alice", "password": "workbench-test-password", "role": store.ManagementRoleUser})
	h.expectRefs("alice", []string{}, []string{})
	h.expectRefs("root", left, left)
}

// Disabling an account keeps its lists: the account cannot call the API meanwhile and finds them
// again once it is enabled.
func TestWorkbenchDisabledAccountKeepsItsLists(t *testing.T) {
	h := newWorkbenchHTTPHarness(t)
	h.addObject(workbenchVectorObject{Kind: store.WorkbenchKindHTTPRoute, ID: 5, TenantID: "t1", OwnerUsername: "alice"})
	h.call(http.MethodPut, "/favorites/http-route/5", "alice", nil, http.StatusOK)
	admin := h.fixtureToken("t1")
	h.expect2xx("disable", http.MethodPut, "/api/admin/users/alice", admin, map[string]any{"enabled": false})
	response, _ := h.do(http.MethodGet, "/api/admin/workbench", h.token("t1", "alice"), nil)
	if response.StatusCode/100 == 2 {
		t.Fatalf("a disabled account read its lists: %d", response.StatusCode)
	}
	h.expect2xx("enable", http.MethodPut, "/api/admin/users/alice", admin, map[string]any{"enabled": true})
	h.expectRefs("alice", []string{"http-route/5"}, []string{})
}

func TestWorkbenchLimiterKeyCapacity(t *testing.T) {
	limiter := newWorkbenchLimiter()
	for i := 0; i < workbenchRateMaxKeys; i++ {
		if _, ok := limiter.take("key-"+strconv.Itoa(i), 0); !ok {
			t.Fatalf("key %d refused", i)
		}
	}
	if wait, ok := limiter.take("one-more", 0); ok || wait != 1_000 {
		t.Fatalf("a full table admitted a new key: wait=%d ok=%v", wait, ok)
	}
	// Once every entry's TAT is not after now, the entries are as good as absent.
	if _, ok := limiter.take("one-more", 1_000); !ok {
		t.Fatal("expired entries were not evicted")
	}
	if len(limiter.tat) != 1 {
		t.Fatalf("%d entries left", len(limiter.tat))
	}
}
