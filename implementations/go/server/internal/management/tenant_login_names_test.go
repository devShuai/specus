package management

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/nat"
	"github.com/devShuai/specus/implementations/go/server/internal/peermesh"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// Login names are unique per tenant (protocol/spec/management-accounts.md). These tests follow
// Java's ManagementUserServiceTests and ManagementUserServiceIntegrationTests through the real
// routes, the login endpoint and the shared authentication layer.

type tenantLoginHarness struct {
	t      *testing.T
	db     *store.DB
	tokens *security.LocalTokenService
	server *httptest.Server
}

func newTenantLoginHarness(t *testing.T, dbPath string, rateLimit config.LoginRateLimitConfig) *tenantLoginHarness {
	t.Helper()
	db, err := store.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	authConfig := config.AuthConfig{PasswordLoginEnabled: true, Username: "admin", Password: "admin-secret",
		TenantID: "default", JwtSecret: "tenant-login-secret", TokenTTLSeconds: 3600, LoginRateLimit: rateLimit}
	tokens := security.NewLocalTokenService(authConfig)
	sessions := session.NewRegistry()
	mesh := peermesh.New(config.PeerMeshConfig{Enabled: true, CIDR: "100.96.0.0/11", PublicAddress: "203.0.113.10",
		StunTurnPort: 3478, SessionTTLSeconds: 3600}, db, sessions, nil)
	api := NewAPI(db, sessions, tokens, nil, nat.NewControlService(db, sessions, 0, ""), nil,
		config.OidcConfig{}, authConfig, config.ClientAuthConfig{}, config.TrafficConfig{},
		nil, nil, mesh, nil, nil, nil, nil)
	mux := http.NewServeMux()
	api.Register(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return &tenantLoginHarness{t: t, db: db, tokens: tokens, server: server}
}

func (h *tenantLoginHarness) do(method, path, token string, body any) (int, []byte) {
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
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		h.t.Fatal(err)
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(response.Body)
	return response.StatusCode, payload
}

// login answers the token and its claims, or "" when the login was refused with 401.
func (h *tenantLoginHarness) login(username, password, tenantID string) (string, security.Claims) {
	h.t.Helper()
	body := map[string]string{"username": username, "password": password}
	if tenantID != "" {
		body["tenantId"] = tenantID
	}
	status, payload := h.do(http.MethodPost, "/auth/login", "", body)
	if status == http.StatusUnauthorized {
		return "", security.Claims{}
	}
	var token security.TokenResponse
	if status != http.StatusOK || json.Unmarshal(payload, &token) != nil {
		h.t.Fatalf("login %s@%s: status %d body %s", username, tenantID, status, payload)
	}
	claims, ok := h.tokens.ValidateClaims(token.AccessToken)
	if !ok {
		h.t.Fatalf("login %s@%s issued an invalid token", username, tenantID)
	}
	return token.AccessToken, claims
}

func (h *tenantLoginHarness) addUser(accountKey, username, tenantID, password, role string) {
	h.t.Helper()
	now := time.Now()
	if _, err := h.db.InsertManagementUser(context.Background(), store.ManagementUser{AccountKey: accountKey,
		Username: username, TenantID: tenantID, PasswordHash: auth.HashPassword(password), Role: role,
		Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		h.t.Fatal(err)
	}
}

// tenantAdmins adds an administrator to tenant-a and tenant-b and signs both in.
func (h *tenantLoginHarness) tenantAdmins() (string, string) {
	h.t.Helper()
	h.addUser("", "admin-a", "tenant-a", "admin-a-password", store.ManagementRoleAdmin)
	h.addUser("", "admin-b", "tenant-b", "admin-b-password", store.ManagementRoleAdmin)
	adminA, _ := h.login("admin-a", "admin-a-password", "tenant-a")
	adminB, _ := h.login("admin-b", "admin-b-password", "tenant-b")
	if adminA == "" || adminB == "" {
		h.t.Fatal("tenant administrators could not sign in")
	}
	return adminA, adminB
}

func (h *tenantLoginHarness) users(token string) []ManagementUserView {
	h.t.Helper()
	status, payload := h.do(http.MethodGet, "/api/admin/users", token, nil)
	var views []ManagementUserView
	if status != http.StatusOK || json.Unmarshal(payload, &views) != nil {
		h.t.Fatalf("list users: status %d body %s", status, payload)
	}
	return views
}

var uuidAccountKey = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Java createsSameLoginNameInDifferentTenantWithoutGlobalLookup and
// tenantsCanCreateTheSameLoginNameWithoutEnumeration.
func TestTenantsCanCreateTheSameLoginNameWithoutEnumeration(t *testing.T) {
	h := newTenantLoginHarness(t, filepath.Join(t.TempDir(), "tenants.db"), config.LoginRateLimitConfig{})
	adminA, adminB := h.tenantAdmins()
	request := map[string]any{"username": "Shared", "password": "secret-password", "role": "USER", "enabled": true}
	for token, tenant := range map[string]string{adminA: "tenant-a", adminB: "tenant-b"} {
		status, payload := h.do(http.MethodPost, "/api/admin/users", token, request)
		var created ManagementUserView
		if status != http.StatusCreated || json.Unmarshal(payload, &created) != nil {
			t.Fatalf("%s create: status %d body %s", tenant, status, payload)
		}
		if created.Username != "Shared" || created.TenantID != tenant {
			t.Fatalf("%s created %+v", tenant, created)
		}
		stored, err := h.db.FindManagementUserByLogin(context.Background(), tenant, "shared")
		if err != nil || stored == nil || !uuidAccountKey.MatchString(stored.AccountKey) {
			t.Fatalf("%s stored %+v err=%v", tenant, stored, err)
		}
	}
	// A second spelling in the same tenant is still a conflict, and its answer names no tenant.
	status, payload := h.do(http.MethodPost, "/api/admin/users", adminA,
		map[string]any{"username": "SHARED", "password": "secret-password"})
	if status != http.StatusBadRequest || bytes.Contains(payload, []byte("tenant-b")) {
		t.Fatalf("same-tenant conflict: status %d body %s", status, payload)
	}
	for token, tenant := range map[string]string{adminA: "tenant-a", adminB: "tenant-b"} {
		shared := 0
		for _, view := range h.users(token) {
			if view.Username == "Shared" {
				shared++
				if view.TenantID != tenant {
					t.Fatalf("%s lists %+v", tenant, view)
				}
			}
			if view.Username == "admin-a" && tenant != "tenant-a" || view.Username == "admin-b" && tenant != "tenant-b" {
				t.Fatalf("%s lists another tenant's administrator %+v", tenant, view)
			}
		}
		if shared != 1 {
			t.Fatalf("%s lists %d Shared accounts", tenant, shared)
		}
	}
	// Each administrator changes and deletes only the Shared of their own tenant.
	if status, _ := h.do(http.MethodPut, "/api/admin/users/shared", adminA,
		map[string]any{"role": "ADMIN"}); status != http.StatusOK {
		t.Fatalf("tenant-a update status %d", status)
	}
	if status, _ := h.do(http.MethodDelete, "/api/admin/users/Shared", adminA, nil); status != http.StatusNoContent {
		t.Fatalf("tenant-a delete status %d", status)
	}
	if gone, _ := h.db.FindManagementUserByLogin(context.Background(), "tenant-a", "shared"); gone != nil {
		t.Fatalf("tenant-a Shared remained: %+v", gone)
	}
	kept, _ := h.db.FindManagementUserByLogin(context.Background(), "tenant-b", "shared")
	if kept == nil || kept.Role != store.ManagementRoleUser {
		t.Fatalf("tenant-b Shared was touched: %+v", kept)
	}
}

// Java tenantQualifiedLoginAndRefreshResolveOnlyTheMatchingTenant, extended: two tenants each have
// an alice, each signs in to their own tenant and sees only that tenant's data.
func TestTenantQualifiedLoginAndRefreshResolveOnlyTheMatchingTenant(t *testing.T) {
	h := newTenantLoginHarness(t, filepath.Join(t.TempDir(), "tenant-login.db"), config.LoginRateLimitConfig{})
	adminA, adminB := h.tenantAdmins()
	for token, password := range map[string]string{adminA: "alice-a-password", adminB: "alice-b-password"} {
		if status, payload := h.do(http.MethodPost, "/api/admin/users", token,
			map[string]any{"username": "alice", "password": password}); status != http.StatusCreated {
			t.Fatalf("create alice: status %d body %s", status, payload)
		}
	}

	aliceA, claimsA := h.login("alice", "alice-a-password", "tenant-a")
	aliceB, claimsB := h.login("ALICE", "alice-b-password", " tenant-b ")
	if aliceA == "" || claimsA.Username != "alice" || claimsA.TenantID != "tenant-a" || !claimsA.HasTenant {
		t.Fatalf("tenant-a login: %+v", claimsA)
	}
	if aliceB == "" || claimsB.Username != "alice" || claimsB.TenantID != "tenant-b" {
		t.Fatalf("tenant-b login: %+v", claimsB)
	}
	// The wrong tenant, the right password of the other tenant, and no tenant at all are refused:
	// neither alice is in the default tenant nor an account that predates login names.
	for _, attempt := range []struct{ password, tenant string }{
		{"alice-a-password", "tenant-b"},
		{"alice-b-password", "tenant-a"},
		{"alice-a-password", ""},
		{"alice-a-password", "default"},
		{"alice-a-password", "tenant-c"},
	} {
		if token, _ := h.login("alice", attempt.password, attempt.tenant); token != "" {
			t.Fatalf("alice signed in with %+v", attempt)
		}
	}

	// Refresh stays in the token's tenant.
	status, payload := h.do(http.MethodPost, "/auth/refresh", aliceB, nil)
	var refreshed security.TokenResponse
	if status != http.StatusOK || json.Unmarshal(payload, &refreshed) != nil {
		t.Fatalf("refresh: status %d body %s", status, payload)
	}
	if claims, ok := h.tokens.ValidateClaims(refreshed.AccessToken); !ok || claims.TenantID != "tenant-b" ||
		claims.Username != "alice" {
		t.Fatalf("refreshed claims %+v", claims)
	}
	for token, tenant := range map[string]string{aliceA: "tenant-a", refreshed.AccessToken: "tenant-b"} {
		status, payload := h.do(http.MethodGet, "/api/admin/me", token, nil)
		var me ManagementUserView
		if status != http.StatusOK || json.Unmarshal(payload, &me) != nil || me.Username != "alice" ||
			me.TenantID != tenant || me.Admin {
			t.Fatalf("%s me: status %d body %s", tenant, status, payload)
		}
	}

	// Each alice owns a client; neither sees the other's.
	for token, name := range map[string]string{aliceA: "alice-a-client", aliceB: "alice-b-client"} {
		if status, payload := h.do(http.MethodPost, "/api/admin/clients", token,
			map[string]any{"clientName": name, "enabled": true}); status != http.StatusCreated {
			t.Fatalf("create %s: status %d body %s", name, status, payload)
		}
	}
	for token, want := range map[string]string{aliceA: "alice-a-client", aliceB: "alice-b-client"} {
		status, payload := h.do(http.MethodGet, "/api/admin/clients", token, nil)
		var clients []ClientView
		if status != http.StatusOK || json.Unmarshal(payload, &clients) != nil {
			t.Fatalf("list clients: status %d body %s", status, payload)
		}
		if len(clients) != 1 || clients[0].ClientName != want {
			t.Fatalf("want only %s, got %+v", want, clients)
		}
	}

	// A token for tenant-a's alice resolves to no one once that account is gone, even though an
	// alice still exists in tenant-b.
	if status, _ := h.do(http.MethodDelete, "/api/admin/users/alice", adminA, nil); status != http.StatusNoContent {
		t.Fatalf("delete tenant-a alice: %d", status)
	}
	if status, _ := h.do(http.MethodGet, "/api/admin/me", aliceA, nil); status != http.StatusUnauthorized {
		t.Fatalf("deleted tenant-a alice: status %d", status)
	}
	if status, _ := h.do(http.MethodPost, "/auth/refresh", aliceA, nil); status != http.StatusUnauthorized {
		t.Fatalf("deleted tenant-a alice refresh: status %d", status)
	}
	if status, _ := h.do(http.MethodGet, "/api/admin/me", aliceB, nil); status != http.StatusOK {
		t.Fatalf("tenant-b alice after the delete: status %d", status)
	}
}

// Bare login (no tenant) finds the default tenant's login name first, then an account that
// predates tenant-scoped login names; a key that matches two accounts fails closed.
func TestBareLoginFallsBackToUniqueLegacyAccountsOnly(t *testing.T) {
	h := newTenantLoginHarness(t, filepath.Join(t.TempDir(), "bare-login.db"), config.LoginRateLimitConfig{})
	h.addUser("Alice", "Alice", "tenant-a", "secret-password", store.ManagementRoleUser)
	h.addUser("alice", "alice", "tenant-b", "secret-password", store.ManagementRoleUser)
	h.addUser("carol", "carol", "tenant-c", "carol-password", store.ManagementRoleUser)
	h.addUser("", "carol", "default", "default-carol-password", store.ManagementRoleUser)
	for _, spelling := range []string{"alice", "Alice", "ALICE"} {
		if token, _ := h.login(spelling, "secret-password", ""); token != "" {
			t.Fatalf("ambiguous legacy key %q signed in", spelling)
		}
	}
	if token, claims := h.login("alice", "secret-password", "tenant-a"); token == "" || claims.TenantID != "tenant-a" ||
		claims.Username != "Alice" {
		t.Fatalf("tenant-qualified login of an ambiguous key: %+v", claims)
	}
	// The default tenant's carol wins a bare login; tenant-c's legacy carol needs her tenant.
	if token, claims := h.login("carol", "default-carol-password", ""); token == "" || claims.TenantID != "default" {
		t.Fatalf("default carol: %+v", claims)
	}
	if token, _ := h.login("carol", "carol-password", ""); token != "" {
		t.Fatal("a legacy key shadowed by a default-tenant login name signed in")
	}
	if token, claims := h.login("carol", "carol-password", "tenant-c"); token == "" || claims.TenantID != "tenant-c" {
		t.Fatalf("tenant-c carol: %+v", claims)
	}
}

// The account dimension of the login rate limit is the tenant and the login name.
func TestLoginRateLimitCountsSameNamedAccountsOfTenantsApart(t *testing.T) {
	h := newTenantLoginHarness(t, filepath.Join(t.TempDir(), "rate-limit.db"),
		config.LoginRateLimitConfig{Enabled: true, PerIP: 100, PerAccount: 1, WindowSeconds: 60})
	h.addUser("", "alice", "tenant-a", "alice-a-password", store.ManagementRoleUser)
	h.addUser("", "alice", "tenant-b", "alice-b-password", store.ManagementRoleUser)
	if token, _ := h.login("alice", "wrong", "tenant-a"); token != "" {
		t.Fatal("a wrong password signed in")
	}
	status, _ := h.do(http.MethodPost, "/auth/login", "",
		map[string]string{"username": "alice", "password": "alice-a-password", "tenantId": "tenant-a"})
	if status != http.StatusTooManyRequests {
		t.Fatalf("second tenant-a attempt: status %d, want 429", status)
	}
	if token, claims := h.login("alice", "alice-b-password", "tenant-b"); token == "" || claims.TenantID != "tenant-b" {
		t.Fatal("tenant-a's failures throttled tenant-b's alice")
	}
}

// An account created before tenant-scoped login names keeps signing in after the upgrade, with or
// without its tenant, and keeps the clients recorded under its name.
func TestLegacyAccountsStillSignInAfterTheLoginNameMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE specus_management_user (username TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
			password_hash TEXT NOT NULL, oidc_issuer TEXT, oidc_subject TEXT, oidc_identity_key TEXT,
			role TEXT NOT NULL, enabled INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`INSERT INTO specus_management_user VALUES ('Dave', 'default', '` + auth.HashPassword("dave-password") +
			`', NULL, NULL, NULL, 'USER', 1, '2026-07-31T00:00:00Z', '2026-07-31T00:00:00Z')`,
		`INSERT INTO specus_management_user VALUES ('erin', 'tenant-e', '` + auth.HashPassword("erin-password") +
			`', NULL, NULL, NULL, 'ADMIN', 1, '2026-07-31T00:00:00Z', '2026-07-31T00:00:00Z')`,
	} {
		if _, err := raw.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	raw.Close()

	h := newTenantLoginHarness(t, path, config.LoginRateLimitConfig{})
	now := time.Now()
	if err := h.db.InsertClient(context.Background(), store.ClientAccount{ID: 7001, TenantID: "tenant-e",
		OwnerUsername: "erin", ClientName: "erin-client", PasswordHash: "unused", Enabled: true,
		ConnectionRateLimitPerMinute: 60, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if token, claims := h.login("dave", "dave-password", ""); token == "" || claims.Username != "Dave" ||
		claims.TenantID != "default" {
		t.Fatalf("legacy default-tenant account: %+v", claims)
	}
	erin, claims := h.login("Erin", "erin-password", "")
	if erin == "" || claims.Username != "erin" || claims.TenantID != "tenant-e" {
		t.Fatalf("legacy account of another tenant without its tenant: %+v", claims)
	}
	if token, _ := h.login("erin", "erin-password", "tenant-e"); token == "" {
		t.Fatal("legacy account with its tenant was refused")
	}
	status, payload := h.do(http.MethodGet, "/api/admin/clients", erin, nil)
	var clients []ClientView
	if status != http.StatusOK || json.Unmarshal(payload, &clients) != nil || len(clients) != 1 ||
		clients[0].ClientName != "erin-client" {
		t.Fatalf("erin's clients: status %d body %s", status, payload)
	}
	users := h.users(erin)
	if len(users) != 2 || users[1].Username != "erin" || users[1].TenantID != "tenant-e" {
		t.Fatalf("tenant-e users: %+v", users)
	}
	stored, err := h.db.FindManagementUserByLogin(context.Background(), "tenant-e", "ERIN")
	if err != nil || stored == nil || stored.AccountKey != "erin" {
		t.Fatalf("legacy key changed: %+v %v", stored, err)
	}
}
