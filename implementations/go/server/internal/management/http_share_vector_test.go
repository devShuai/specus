package management

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/httpshare"
	"github.com/devShuai/specus/implementations/go/server/internal/httpshare/sharetest"
	"github.com/devShuai/specus/implementations/go/server/internal/nat"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// Binds the share management endpoints, the public exchange and the route/client/user hooks to
// protocol/test-vectors/temporary-http-share-v1.json through the real HTTP handlers and a real
// SQLite store.

type shareAPI struct {
	db     *store.DB
	api    *API
	server *httptest.Server
	tokens *security.LocalTokenService
	users  map[string]sharetest.User
	clock  time.Time
}

func newShareAPI(t *testing.T, world sharetest.World, input sharetest.CaseInput) *shareAPI {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "share.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sharetest.Seed(t, db, world, input.WorldChanges, input.Shares, auth.HashToken)
	// The built-in administrator is named root so that the vector's "admin" is an ordinary user.
	authCfg := config.AuthConfig{JwtSecret: "share-vector-secret", Username: "root", TenantID: "t1"}
	tokens := security.NewLocalTokenService(authCfg)
	sessions := session.NewRegistry()
	api := NewAPI(db, sessions, tokens, nil, nat.NewControlService(db, sessions, 0, ""), nil,
		config.OidcConfig{}, authCfg, config.ClientAuthConfig{}, config.TrafficConfig{}, nil, nil, nil, nil, nil,
		security.NewClientAddressResolver(nil, nil), nil)
	fixture := &shareAPI{db: db, api: api, tokens: tokens, users: world.Users}
	fixture.setNow(sharetest.Now(t, input.Now))
	mux := http.NewServeMux()
	api.Register(mux)
	fixture.server = httptest.NewServer(mux)
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *shareAPI) setNow(now time.Time) {
	f.clock = now
	f.api.HTTPShares().SetClock(func() time.Time { return now })
}

func (f *shareAPI) token(username string) string {
	user := f.users[username]
	return f.tokens.IssueForUser(user.Username, user.TenantID, user.Role)
}

type apiResponse struct {
	status int
	header http.Header
	body   []byte
	code   string
}

func (f *shareAPI) request(t *testing.T, method, path, token, contentType string, body []byte) apiResponse {
	t.Helper()
	request, err := http.NewRequest(method, f.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	var payload struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(data, &payload)
	return apiResponse{status: response.StatusCode, header: response.Header, body: data, code: payload.Code}
}

func jsonBody(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestShareVectorCreate(t *testing.T) {
	vector := sharetest.Load(t)
	for _, c := range vector.Create {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			input := c.Input
			expect := sharetest.ParseExpect(t, c.Expect)
			fixture := newShareAPI(t, vector.World, input)
			fixture.api.HTTPShares().SetRandom(sharetest.NewFixedRandom(t, vector.NewShare.ShareIDBytesHex,
				vector.NewShare.SecretBytesHex))
			if !input.IsReadable() {
				if _, err := fixture.db.ExecStatement(context.Background(),
					`ALTER TABLE http_route_mapping RENAME TO http_route_mapping_unreadable`); err != nil {
					t.Fatal(err)
				}
			}
			token := ""
			if input.Authenticated == nil || *input.Authenticated {
				token = fixture.token(*input.Caller)
			}
			response := fixture.request(t, http.MethodPost, fmt.Sprintf("/api/admin/http-routes/%d/shares", input.RouteID),
				token, "application/json", input.Body)
			if response.status != expect.Status() {
				t.Fatalf("status %d (%s), want %d %s", response.status, response.body, expect.Status(), expect.Code)
			}
			if expect.Status() == http.StatusUnauthorized {
				return
			}
			if response.header.Get("Cache-Control") != "private, no-store" {
				t.Errorf("Cache-Control %q", response.header.Get("Cache-Control"))
			}
			if expect.Body != nil {
				if !sharetest.SameJSON(response.body, expect.Body) {
					t.Errorf("body\n got %s\nwant %s", response.body, expect.Body)
				}
			} else if response.code != expect.Code {
				t.Errorf("code %s, want %s", response.code, expect.Code)
			}
			if input.IsReadable() {
				sharetest.SameAudit(t, c.Name, sharetest.AuditEntries(t, fixture.db, "t1"), expect.Audit, nil)
			}
		})
	}
}

// primeExchangeLimiter leaves the source address waitMs away from its next exchange.
func primeExchangeLimiter(limiter *httpshare.Limiter, source string, now time.Time, waitMs int64) {
	start := now.UnixMilli() - httpshare.ExchangeIntervalMs + waitMs
	for range httpshare.ExchangeBurst {
		limiter.Take(source, start)
	}
}

func TestShareVectorExchange(t *testing.T) {
	vector := sharetest.Load(t)
	for _, c := range vector.Exchange {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			input := c.Input
			expect := sharetest.ParseExpect(t, c.Expect)
			fixture := newShareAPI(t, vector.World, input)
			if input.RateLimitedMs > 0 {
				primeExchangeLimiter(fixture.api.HTTPShares().ExchangeLimiter(), "127.0.0.1", fixture.clock,
					input.RateLimitedMs)
			}
			if !input.IsReadable() {
				if _, err := fixture.db.ExecStatement(context.Background(),
					`ALTER TABLE http_share RENAME TO http_share_unreadable`); err != nil {
					t.Fatal(err)
				}
			}
			contentType := "application/json"
			if input.ContentType != nil {
				contentType = *input.ContentType
			}
			response := fixture.request(t, http.MethodPost, "/api/public/http-shares/exchange", "", contentType, input.Body)
			if response.status != expect.Status() {
				t.Fatalf("status %d (%s), want %d %s", response.status, response.body, expect.Status(), expect.Code)
			}
			if response.header.Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control %q", response.header.Get("Cache-Control"))
			}
			setCookies := response.header.Values("Set-Cookie")
			if expect.Body != nil {
				if !sharetest.SameJSON(response.body, expect.Body) {
					t.Errorf("body\n got %s\nwant %s", response.body, expect.Body)
				}
				if response.header.Get("Referrer-Policy") != "no-referrer" {
					t.Errorf("Referrer-Policy %q", response.header.Get("Referrer-Policy"))
				}
				if len(setCookies) != 1 || !sharetest.SameJSON(sharetest.CookieView(setCookies[0]), expect.SetCookie) {
					t.Errorf("Set-Cookie %q, want %s", setCookies, expect.SetCookie)
				}
			} else {
				if response.code != expect.Code {
					t.Errorf("code %s, want %s", response.code, expect.Code)
				}
				if len(setCookies) != 0 {
					t.Errorf("unexpected Set-Cookie %q", setCookies)
				}
			}
			if expect.RetryAfterSeconds != nil && response.header.Get("Retry-After") != fmt.Sprint(*expect.RetryAfterSeconds) {
				t.Errorf("Retry-After %q, want %d", response.header.Get("Retry-After"), *expect.RetryAfterSeconds)
			}
			if !input.IsReadable() {
				return
			}
			if expect.Revoke != nil {
				state := sharetest.ShareState(t, fixture.db, input.Shares[0].ShareID)
				if state.RevokeReason == nil || *state.RevokeReason != expect.Revoke.Reason || state.RevokedBy != nil {
					t.Errorf("share state %+v, want revoked for %s by the system", state, expect.Revoke.Reason)
				}
			}
			sharetest.SameAudit(t, c.Name, sharetest.AuditEntries(t, fixture.db, "t1"), expect.Audit, nil)
		})
	}
}

// lifecycleRoute tracks a route's current shape for update requests.
type lifecycleRoute struct {
	id          int64
	clientID    int64
	name        string
	enabled     bool
	authEnabled bool
}

func TestShareVectorLifecycle(t *testing.T) {
	vector := sharetest.Load(t)
	for _, c := range vector.Lifecycle {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			fixture := newShareAPI(t, vector.World, sharetest.CaseInput{Shares: c.Input.Shares})
			routes := map[int64]*lifecycleRoute{}
			for _, route := range vector.World.Routes {
				routes[route.RouteID] = &lifecycleRoute{id: route.RouteID, clientID: route.ClientID, name: route.Name,
					enabled: route.Enabled, authEnabled: route.AuthEnabled}
			}
			routeIDs := map[int64]int64{}
			var responses []map[string]any
			var lastAt time.Time
			for i, event := range c.Input.Events {
				at := sharetest.Instant(t, event["at"].(string))
				lastAt = at
				fixture.setNow(at)
				actor, _ := event["actor"].(string)
				token := ""
				if actor != "" {
					token = fixture.token(actor)
				}
				number := func(key string) int64 { return int64(event[key].(float64)) }
				expectStatus := func(response apiResponse, status int) {
					t.Helper()
					if response.status != status {
						t.Fatalf("event %d %v: status %d %s", i, event["kind"], response.status, response.body)
					}
				}
				switch event["kind"] {
				case "revoke":
					response := fixture.request(t, http.MethodPost, fmt.Sprintf("/api/admin/http-routes/%d/shares/%s/revoke",
						number("routeId"), event["shareId"]), token, "application/json", nil)
					record := map[string]any{"httpStatus": response.status}
					if response.status == http.StatusOK {
						var body struct {
							Share httpshare.ShareView `json:"share"`
						}
						_ = json.Unmarshal(response.body, &body)
						record["status"] = body.Share.Status
					} else {
						record["code"] = response.code
					}
					responses = append(responses, record)
				case "route-created":
					route := event["route"].(map[string]any)
					clientID := int64(route["clientId"].(float64))
					response := fixture.request(t, http.MethodPost, fmt.Sprintf("/api/admin/clients/%d/http-routes", clientID),
						token, "application/json", jsonBody(t, map[string]any{"route": route["name"],
							"targetBaseUrl": "http://127.0.0.1:8080", "enabled": route["enabled"],
							"authEnabled": route["authEnabled"], "authUsername": "route-user",
							"authPassword": sharetest.RoutePassword}))
					expectStatus(response, http.StatusCreated)
					var created struct {
						ID int64 `json:"id"`
					}
					_ = json.Unmarshal(response.body, &created)
					vectorID := int64(route["routeId"].(float64))
					routeIDs[vectorID] = created.ID
					routes[vectorID] = &lifecycleRoute{id: created.ID, clientID: clientID, name: route["name"].(string),
						enabled: route["enabled"].(bool), authEnabled: route["authEnabled"].(bool)}
				case "route-updated":
					route := routes[number("routeId")]
					if enabled, ok := event["enabled"].(bool); ok {
						route.enabled = enabled
					}
					if authEnabled, ok := event["authEnabled"].(bool); ok {
						route.authEnabled = authEnabled
					}
					body := map[string]any{"route": route.name, "targetBaseUrl": "http://127.0.0.1:8080",
						"enabled": route.enabled, "authEnabled": route.authEnabled}
					if changed, _ := event["credentialsChanged"].(bool); changed {
						body["authUsername"] = "route-user"
						body["authPassword"] = fmt.Sprintf("changed-password-%d", i)
					}
					expectStatus(fixture.request(t, http.MethodPut, fmt.Sprintf("/api/admin/http-routes/%d", route.id), token,
						"application/json", jsonBody(t, body)), http.StatusOK)
				case "route-deleted":
					route := routes[number("routeId")]
					expectStatus(fixture.request(t, http.MethodDelete, fmt.Sprintf("/api/admin/http-routes/%d", route.id),
						token, "", nil), http.StatusNoContent)
				case "client-disabled":
					expectStatus(fixture.request(t, http.MethodPut, fmt.Sprintf("/api/admin/clients/%d", number("clientId")),
						token, "application/json", jsonBody(t, map[string]any{"enabled": false})), http.StatusOK)
				case "client-deleted":
					expectStatus(fixture.request(t, http.MethodDelete, fmt.Sprintf("/api/admin/clients/%d", number("clientId")),
						token, "", nil), http.StatusNoContent)
				case "user-updated":
					body := map[string]any{}
					for _, key := range []string{"enabled", "role"} {
						if value, ok := event[key]; ok {
							body[key] = value
						}
					}
					expectStatus(fixture.request(t, http.MethodPut, "/api/admin/users/"+event["username"].(string), token,
						"application/json", jsonBody(t, body)), http.StatusOK)
				case "user-deleted":
					expectStatus(fixture.request(t, http.MethodDelete, "/api/admin/users/"+event["username"].(string), token,
						"", nil), http.StatusNoContent)
				case "sweep":
					if err := fixture.api.HTTPShares().Sweep(context.Background()); err != nil {
						t.Fatal(err)
					}
				case "silent-change":
					change := sharetest.WorldChange{Table: event["table"].(string), Key: jsonBody(t, event["key"])}
					change.Set = event["set"].(map[string]any)
					sharetest.Apply(t, fixture.db, change)
				default:
					t.Fatalf("unknown event %v", event["kind"])
				}
			}
			sharetest.SameAudit(t, c.Name, sharetest.AuditEntries(t, fixture.db, "t1"), c.Expect.Audit, routeIDs)
			for shareID, want := range c.Expect.Shares {
				state := sharetest.ShareState(t, fixture.db, shareID)
				status := httpshare.View(state, lastAt.Unix()).Status
				if status != want.Status || deref(state.RevokeReason) != deref(want.RevokeReason) ||
					deref(state.RevokedBy) != deref(want.RevokedBy) {
					t.Errorf("share %s: %s %s %s, want %+v", shareID, status, deref(state.RevokeReason),
						deref(state.RevokedBy), want)
				}
			}
			if len(responses) != len(c.Expect.Responses) {
				t.Fatalf("%d responses, want %d", len(responses), len(c.Expect.Responses))
			}
			for i, want := range c.Expect.Responses {
				got := responses[i]
				if got["httpStatus"] != want.HTTPStatus || want.Status != "" && got["status"] != want.Status ||
					want.Code != "" && got["code"] != want.Code {
					t.Errorf("response %d: %v, want %+v", i, got, want)
				}
			}
		})
	}
}

func deref(value *string) string {
	if value == nil {
		return "<nil>"
	}
	return *value
}

func TestShareManagementListAuditAndTenantAudit(t *testing.T) {
	vector := sharetest.Load(t)
	fixture := newShareAPI(t, vector.World, sharetest.CaseInput{})
	alice := fixture.token("alice")
	created := fixture.request(t, http.MethodPost, "/api/admin/http-routes/42/shares", alice, "application/json",
		[]byte(`{"expiresInSeconds":3600,"label":"review"}`))
	if created.status != http.StatusCreated {
		t.Fatalf("create %d %s", created.status, created.body)
	}
	var body struct {
		Share httpshare.ShareView `json:"share"`
	}
	_ = json.Unmarshal(created.body, &body)
	shareID := body.Share.ShareID

	// The route is disabled behind the hooks' back: listing revokes the share before showing it.
	if _, err := fixture.db.ExecStatement(context.Background(), `UPDATE http_route_mapping SET enabled = 0 WHERE id = 42`); err != nil {
		t.Fatal(err)
	}
	list := fixture.request(t, http.MethodGet, "/api/admin/http-routes/42/shares", alice, "", nil)
	var listed struct {
		Shares []httpshare.ShareView `json:"shares"`
	}
	_ = json.Unmarshal(list.body, &listed)
	if list.status != http.StatusOK || len(listed.Shares) != 1 || listed.Shares[0].Status != httpshare.StatusRevoked ||
		deref(listed.Shares[0].RevokeReason) != httpshare.ReasonRouteDisabled || listed.Shares[0].RevokedBy != nil {
		t.Fatalf("list %d %s", list.status, list.body)
	}
	if got := fixture.request(t, http.MethodGet, "/api/admin/http-routes/42/shares/"+shareID, fixture.token("bob"), "", nil); got.status != http.StatusNotFound || got.code != httpshare.CodeRouteNotFound {
		t.Fatalf("other owner get %d %s", got.status, got.body)
	}
	if got := fixture.request(t, http.MethodGet, "/api/admin/http-routes/50/shares/"+shareID, fixture.token("admin"), "", nil); got.status != http.StatusNotFound || got.code != httpshare.CodeNotFound {
		t.Fatalf("share under another route %d %s", got.status, got.body)
	}
	audit := fixture.request(t, http.MethodGet, "/api/admin/http-routes/42/access-audit?limit=1", alice, "", nil)
	var page struct {
		Entries    []httpshare.AuditView `json:"entries"`
		NextBefore *int64                `json:"nextBefore"`
	}
	_ = json.Unmarshal(audit.body, &page)
	if audit.status != http.StatusOK || len(page.Entries) != 1 || page.Entries[0].Action != httpshare.ActionShareRevoked ||
		page.NextBefore == nil {
		t.Fatalf("audit %d %s", audit.status, audit.body)
	}
	if bytes.Contains(audit.body, []byte("review")) {
		t.Fatalf("the label leaked into the audit: %s", audit.body)
	}
	next := fixture.request(t, http.MethodGet, "/api/admin/http-routes/42/access-audit?before="+
		strconv.FormatInt(*page.NextBefore, 10), alice, "", nil)
	_ = json.Unmarshal(next.body, &page)
	if len(page.Entries) != 1 || page.Entries[0].Action != httpshare.ActionShareCreated || page.NextBefore != nil {
		t.Fatalf("second page %s", next.body)
	}
	if got := fixture.request(t, http.MethodGet, "/api/admin/http-access-audit", alice, "", nil); got.status != http.StatusForbidden || got.code != httpshare.CodeForbidden {
		t.Fatalf("tenant audit for a user %d %s", got.status, got.body)
	}
	if got := fixture.request(t, http.MethodGet, "/api/admin/http-access-audit?routeId=42&limit=500", fixture.token("admin"), "", nil); got.status != http.StatusBadRequest {
		t.Fatalf("bad limit %d", got.status)
	}
	tenant := fixture.request(t, http.MethodGet, "/api/admin/http-access-audit?routeId=42", fixture.token("admin"), "", nil)
	_ = json.Unmarshal(tenant.body, &page)
	if tenant.status != http.StatusOK || len(page.Entries) != 2 {
		t.Fatalf("tenant audit %d %s", tenant.status, tenant.body)
	}
	other := fixture.request(t, http.MethodGet, "/api/admin/http-access-audit", fixture.token("eve"), "", nil)
	_ = json.Unmarshal(other.body, &page)
	if other.status != http.StatusOK || len(page.Entries) != 0 {
		t.Fatalf("other tenant sees %s", other.body)
	}
}
