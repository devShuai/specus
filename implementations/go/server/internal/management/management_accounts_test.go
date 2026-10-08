package management

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// Account lifecycle (protocol/spec/management-accounts.md sections 5-7, issue #199), after Java's
// ManagementAccountsHttpTests: protocol/test-vectors/management-accounts-v1.json replayed through
// the real routes, and the delete-then-recreate path with tokens /auth/login really issued.

const tenantLoginJwtSecret = "tenant-login-secret"

type accountsVector struct {
	Accounts []struct {
		AccountKey string `json:"accountKey"`
		LoginName  string `json:"loginName"`
		TenantID   string `json:"tenantId"`
		Role       string `json:"role"`
		Enabled    bool   `json:"enabled"`
	} `json:"accounts"`
	TokenResolution []struct {
		Name   string            `json:"name"`
		Claims map[string]string `json:"claims"`
		Expect *struct {
			Username string  `json:"username"`
			TenantID string  `json:"tenantId"`
			BuiltIn  bool    `json:"builtIn"`
			UID      *string `json:"uid"`
		} `json:"expect"`
	} `json:"tokenResolution"`
	UserLists []struct {
		Name   string            `json:"name"`
		Caller map[string]string `json:"caller"`
		Expect []struct {
			Username string `json:"username"`
			TenantID string `json:"tenantId"`
			BuiltIn  bool   `json:"builtIn"`
		} `json:"expect"`
	} `json:"userLists"`
}

func readAccountsVector(t *testing.T) accountsVector {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for depth := 0; depth < 8; depth++ {
		data, err := os.ReadFile(filepath.Join(dir, "protocol", "test-vectors", "management-accounts-v1.json"))
		if err == nil {
			var vector accountsVector
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
	t.Fatal("cannot locate protocol/test-vectors/management-accounts-v1.json")
	return accountsVector{}
}

// signLocalToken signs claims as the server's own local token, with iss, iat and exp added.
func signLocalToken(claims map[string]string) string {
	payload := map[string]any{"iss": security.Issuer, "iat": time.Now().Unix(),
		"exp": time.Now().Add(10 * time.Minute).Unix()}
	for name, value := range claims {
		payload[name] = value
	}
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	body, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	key := sha256.Sum256([]byte(tenantLoginJwtSecret))
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func tokenPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]any
	if err != nil || json.Unmarshal(data, &payload) != nil {
		t.Fatalf("token payload: %v", err)
	}
	return payload
}

func (h *tenantLoginHarness) seedVectorAccounts(vector accountsVector) {
	h.t.Helper()
	for _, account := range vector.Accounts {
		h.addUser(account.AccountKey, account.LoginName, account.TenantID, "vector-password", account.Role)
		if !account.Enabled {
			user, _ := h.db.FindManagementUserByLogin(context.Background(), account.TenantID, account.LoginName)
			user.Enabled = false
			if err := h.db.UpdateManagementUser(context.Background(), *user); err != nil {
				h.t.Fatal(err)
			}
		}
	}
}

func TestManagementAccountsVectorTokenResolution(t *testing.T) {
	vector := readAccountsVector(t)
	h := newTenantLoginHarness(t, filepath.Join(t.TempDir(), "accounts-vector.db"), config.LoginRateLimitConfig{})
	h.seedVectorAccounts(vector)
	for _, testCase := range vector.TokenResolution {
		token := signLocalToken(testCase.Claims)
		meStatus, mePayload := h.do(http.MethodGet, "/api/admin/me", token, nil)
		refreshStatus, refreshPayload := h.do(http.MethodPost, "/auth/refresh", token, nil)
		if testCase.Expect == nil {
			if meStatus != http.StatusUnauthorized && meStatus != http.StatusForbidden {
				t.Errorf("%s: me status %d body %s", testCase.Name, meStatus, mePayload)
			}
			if refreshStatus != http.StatusUnauthorized {
				t.Errorf("%s: refresh status %d body %s", testCase.Name, refreshStatus, refreshPayload)
			}
			continue
		}
		var me ManagementUserView
		if meStatus != http.StatusOK || json.Unmarshal(mePayload, &me) != nil {
			t.Errorf("%s: me status %d body %s", testCase.Name, meStatus, mePayload)
			continue
		}
		if me.Username != testCase.Expect.Username || me.TenantID != testCase.Expect.TenantID ||
			me.BuiltIn != testCase.Expect.BuiltIn {
			t.Errorf("%s: me %+v", testCase.Name, me)
		}
		var refreshed security.TokenResponse
		if refreshStatus != http.StatusOK || json.Unmarshal(refreshPayload, &refreshed) != nil {
			t.Errorf("%s: refresh status %d body %s", testCase.Name, refreshStatus, refreshPayload)
			continue
		}
		claims := tokenPayload(t, refreshed.AccessToken)
		if claims["sub"] != testCase.Expect.Username || claims["tenant_id"] != testCase.Expect.TenantID {
			t.Errorf("%s: refreshed claims %v", testCase.Name, claims)
		}
		uid, hasUID := claims["uid"]
		if testCase.Expect.UID == nil && hasUID || testCase.Expect.UID != nil && uid != *testCase.Expect.UID {
			t.Errorf("%s: refreshed uid %v, want %v", testCase.Name, uid, testCase.Expect.UID)
		}
	}
}

func TestManagementAccountsVectorUserLists(t *testing.T) {
	vector := readAccountsVector(t)
	h := newTenantLoginHarness(t, filepath.Join(t.TempDir(), "accounts-lists.db"), config.LoginRateLimitConfig{})
	h.seedVectorAccounts(vector)
	for _, testCase := range vector.UserLists {
		var actual, expected []string
		for _, view := range h.users(signLocalToken(testCase.Caller)) {
			actual = append(actual, fmt.Sprintf("%s@%s builtIn=%v", view.Username, view.TenantID, view.BuiltIn))
		}
		for _, view := range testCase.Expect {
			expected = append(expected, fmt.Sprintf("%s@%s builtIn=%v", view.Username, view.TenantID, view.BuiltIn))
		}
		if strings.Join(actual, "; ") != strings.Join(expected, "; ") {
			t.Errorf("%s: got %v, want %v", testCase.Name, actual, expected)
		}
	}
}

// Java ManagementAccountsHttpTests.deletedAccountTokensDoNotResolveToARecreatedAccountOfTheSameName.
func TestDeletedAccountTokensDoNotResolveToARecreatedAccountOfTheSameName(t *testing.T) {
	h := newTenantLoginHarness(t, filepath.Join(t.TempDir(), "recreate.db"), config.LoginRateLimitConfig{})
	if admin, _ := h.login("admin", "admin-secret", ""); admin == "" {
		t.Fatal("built-in admin login failed")
	} else if _, has := tokenPayload(t, admin)["uid"]; has {
		t.Fatal("the built-in admin's token carries uid")
	}
	adminA, _ := h.tenantAdmins()
	create := map[string]any{"username": "alice", "password": "alice-password", "role": "USER"}
	if status, payload := h.do(http.MethodPost, "/api/admin/users", adminA, create); status != http.StatusCreated {
		t.Fatalf("create alice: status %d body %s", status, payload)
	}
	first, _ := h.login("alice", "alice-password", "tenant-a")
	stored, _ := h.db.FindManagementUserByLogin(context.Background(), "tenant-a", "alice")
	if first == "" || stored == nil || tokenPayload(t, first)["uid"] != stored.AccountKey {
		t.Fatalf("first alice's token does not carry her account key: %v", tokenPayload(t, first))
	}
	firstKey := stored.AccountKey
	if status, _ := h.do(http.MethodDelete, "/api/admin/users/alice", adminA, nil); status != http.StatusNoContent {
		t.Fatalf("delete alice: status %d", status)
	}
	if status, payload := h.do(http.MethodPost, "/api/admin/users", adminA, create); status != http.StatusCreated {
		t.Fatalf("recreate alice: status %d body %s", status, payload)
	}
	stored, _ = h.db.FindManagementUserByLogin(context.Background(), "tenant-a", "alice")
	if stored == nil || stored.AccountKey == firstKey {
		t.Fatalf("recreated alice: %+v", stored)
	}

	// The first alice's token names an account row that is gone; it does not pass to the second.
	if status, _ := h.do(http.MethodGet, "/api/admin/me", first, nil); status != http.StatusUnauthorized &&
		status != http.StatusForbidden {
		t.Fatalf("first alice's token after the recreate: me status %d", status)
	}
	if status, _ := h.do(http.MethodPost, "/auth/refresh", first, nil); status != http.StatusUnauthorized {
		t.Fatalf("first alice's token after the recreate: refresh status %d", status)
	}

	second, _ := h.login("alice", "alice-password", "tenant-a")
	if second == "" || tokenPayload(t, second)["uid"] != stored.AccountKey {
		t.Fatalf("second alice's token: %v", tokenPayload(t, second))
	}
	if status, _ := h.do(http.MethodGet, "/api/admin/me", second, nil); status != http.StatusOK {
		t.Fatalf("second alice: me status %d", status)
	}
	status, payload := h.do(http.MethodPost, "/auth/refresh", second, nil)
	var refreshed security.TokenResponse
	if status != http.StatusOK || json.Unmarshal(payload, &refreshed) != nil ||
		tokenPayload(t, refreshed.AccessToken)["uid"] != stored.AccountKey {
		t.Fatalf("second alice refresh: status %d body %s", status, payload)
	}
}

// Java ManagementAccountsHttpTests.deletingAnAccountReleasesItsEmail, through the delete route.
func TestDeletingAnAccountThroughTheAPIReleasesItsEmail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "emails.db")
	h := newTenantLoginHarness(t, path, config.LoginRateLimitConfig{})
	h.addUser("9e8d7c6b-5a4f-4e3d-a2c1-b0a9f8e7d6c5", "dora", "default", "dora-password", store.ManagementRoleAdmin)
	h.addUser("0f1e2d3c-4b5a-4968-8776-655443322110", "frank", "default", "frank-password", store.ManagementRoleUser)
	h.addUser("1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "grace", "default", "grace-password", store.ManagementRoleUser)
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for key, email := range map[string]string{
		"0f1e2d3c-4b5a-4968-8776-655443322110": "frank@example.com",
		"1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d": "grace@example.com",
	} {
		if _, err := raw.Exec(`INSERT INTO specus_management_user_email (username, email, verified_at, created_at,
			updated_at) VALUES (?, ?, '2026-07-31T00:00:00Z', '2026-07-31T00:00:00Z', '2026-07-31T00:00:00Z')`,
			key, email); err != nil {
			t.Fatal(err)
		}
	}
	raw.Close()
	dora := signLocalToken(map[string]string{"sub": "dora", "tenant_id": "default", "role": "ADMIN",
		"uid": "9e8d7c6b-5a4f-4e3d-a2c1-b0a9f8e7d6c5"})
	if status, payload := h.do(http.MethodDelete, "/api/admin/users/FRANK", dora, nil); status != http.StatusNoContent {
		t.Fatalf("delete frank: status %d body %s", status, payload)
	}
	ctx := context.Background()
	if exists, err := h.db.ManagementEmailExists(ctx, "frank@example.com"); err != nil || exists {
		t.Fatalf("frank's email after the delete: exists=%v err=%v", exists, err)
	}
	if exists, err := h.db.ManagementEmailExists(ctx, "grace@example.com"); err != nil || !exists {
		t.Fatalf("grace's email: exists=%v err=%v", exists, err)
	}
}
