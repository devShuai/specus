package management

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	AccountDeletion struct {
		Actor    map[string]string `json:"actor"`
		Accounts []struct {
			AccountKey string `json:"accountKey"`
			LoginName  string `json:"loginName"`
			TenantID   string `json:"tenantId"`
			Role       string `json:"role"`
		} `json:"accounts"`
		Seed  map[string][]deletionRow `json:"seed"`
		Steps []struct {
			DeleteUser string            `json:"deleteUser"`
			Fixture    string            `json:"fixture"`
			Get        string            `json:"get"`
			As         map[string]string `json:"as"`
			ID         int64             `json:"id"`
			Owner      string            `json:"owner"`
			AccountKey string            `json:"accountKey"`
			LoginName  string            `json:"loginName"`
			TenantID   string            `json:"tenantId"`
			Role       string            `json:"role"`
			Expect     struct {
				Status      int             `json:"status"`
				Clients     *int64          `json:"clients"`
				Credentials *int64          `json:"credentials"`
				Body        json.RawMessage `json:"body"`
			} `json:"expect"`
		} `json:"steps"`
		RowsAfter     map[string][]deletionRow `json:"rowsAfter"`
		AccountsAfter []struct {
			AccountKey string `json:"accountKey"`
			LoginName  string `json:"loginName"`
			TenantID   string `json:"tenantId"`
		} `json:"accountsAfter"`
	} `json:"accountDeletion"`
}

// deletionRow is one row of the accountDeletion seed or rowsAfter, whatever its table.
type deletionRow struct {
	ID             int64  `json:"id"`
	TenantID       string `json:"tenantId"`
	Owner          string `json:"owner"`
	Username       string `json:"username"`
	ClientName     string `json:"clientName"`
	Status         string `json:"status"`
	AttachmentID   int64  `json:"attachmentId"`
	SourceClientID int64  `json:"sourceClientId"`
	TargetClientID int64  `json:"targetClientId"`
	EgressClientID int64  `json:"egressClientId"`
	ClientID       int64  `json:"clientId"`
	Active         *bool  `json:"active"`
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

// deletionTables maps the vector's table names to the store's table and owner column.
var deletionTables = map[string][2]string{
	"clients":        {"specus_client_account", "owner_username"},
	"credentials":    {"specus_client_credential", "owner_username"},
	"diagrams":       {"user_diagram_document", "owner_username"},
	"attachments":    {"transfer_attachment", "owner_username"},
	"downloadGrants": {"transfer_attachment_download_grant", "username"},
	"downloadUsage":  {"transfer_attachment_download_usage", "username"},
	"acls":           {"peer_mesh_acl", "owner_username"},
	"egressPolicies": {"peer_mesh_egress_policy", "owner_username"},
	"devices":        {"peer_mesh_device", "owner_username"},
}

const deletionTimeLayout = "2006-01-02T15:04:05.0000000Z"

// Java ManagementAccountsHttpTests.replaysTheAccountDeletionVector (management-accounts.md 7.1).
func TestManagementAccountsVectorAccountDeletion(t *testing.T) {
	deletion := readAccountsVector(t).AccountDeletion
	path := filepath.Join(t.TempDir(), "account-deletion.db")
	h := newTenantLoginHarness(t, path, config.LoginRateLimitConfig{})
	for _, account := range deletion.Accounts {
		h.addUser(account.AccountKey, account.LoginName, account.TenantID, "vector-password", account.Role)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := raw.Exec(query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	now := time.Now().UTC()
	stamp, later := now.Format(deletionTimeLayout), now.Add(time.Hour).Format(deletionTimeLayout)
	for _, row := range deletion.Seed["clients"] {
		exec(`INSERT INTO specus_client_account (id, tenant_id, owner_username, client_name, password_hash, enabled,
			connection_rate_limit_per_minute, created_at, updated_at) VALUES (?, ?, ?, ?, 'unused', 1, 30, ?, ?)`,
			row.ID, row.TenantID, row.Owner, row.ClientName, stamp, stamp)
	}
	for _, row := range deletion.Seed["credentials"] {
		exec(`INSERT INTO specus_client_credential (id, tenant_id, owner_username, api_key, secret_hash, enabled,
			max_online_instances, created_at, updated_at) VALUES (?, ?, ?, ?, 'unused', 1, 2, ?, ?)`,
			row.ID, row.TenantID, row.Owner, fmt.Sprintf("acct-del-%d", row.ID), stamp, stamp)
	}
	for _, row := range deletion.Seed["diagrams"] {
		exec(`INSERT INTO user_diagram_document (id, tenant_id, owner_username, name, snapshot_data, size_bytes,
			revision, created_at, updated_at) VALUES (?, ?, ?, ?, x'01', 1, 1, ?, ?)`,
			row.ID, row.TenantID, row.Owner, fmt.Sprintf("acct-del-%d", row.ID), stamp, stamp)
	}
	for _, row := range deletion.Seed["attachments"] {
		exec(`INSERT INTO transfer_attachment (id, tenant_id, scope, owner_username, object_key, file_name, mime_type,
			size_bytes, status, created_at, updated_at, upload_expires_at, expires_at)
			VALUES (?, ?, 'ADMIN_CLIENT_MESSAGE', ?, ?, 'file.bin', 'application/octet-stream', 1, ?, ?, ?, ?, ?)`,
			row.ID, row.TenantID, row.Owner, fmt.Sprintf("acct-del/%d", row.ID), row.Status, stamp, stamp, later, later)
	}
	for _, row := range deletion.Seed["downloadGrants"] {
		exec(`INSERT INTO transfer_attachment_download_grant (id, token_hash, tenant_id, username, attachment_id,
			created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			row.ID, fmt.Sprintf("%064d", row.ID), row.TenantID, row.Username, row.AttachmentID, stamp, later)
	}
	for _, row := range deletion.Seed["downloadUsage"] {
		exec(`INSERT INTO transfer_attachment_download_usage (id, tenant_id, username, attachment_id, size_bytes,
			usage_month, created_at) VALUES (?, ?, ?, ?, 1, ?, ?)`,
			row.ID, row.TenantID, row.Username, row.AttachmentID, now.Format("2006-01"), stamp)
	}
	for _, row := range deletion.Seed["acls"] {
		exec(`INSERT INTO peer_mesh_acl (id, tenant_id, owner_username, source_client_id, source_client_name,
			target_client_id, target_client_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			row.ID, row.TenantID, row.Owner, row.SourceClientID, fmt.Sprintf("acct-del-%d", row.SourceClientID),
			row.TargetClientID, fmt.Sprintf("acct-del-%d", row.TargetClientID), stamp, stamp)
	}
	for _, row := range deletion.Seed["egressPolicies"] {
		exec(`INSERT INTO peer_mesh_egress_policy (id, tenant_id, owner_username, egress_client_id, egress_client_name,
			created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			row.ID, row.TenantID, row.Owner, row.EgressClientID, fmt.Sprintf("acct-del-%d", row.EgressClientID),
			stamp, stamp)
	}
	for _, row := range deletion.Seed["devices"] {
		exec(`INSERT INTO peer_mesh_device (id, tenant_id, owner_username, client_id, client_name, virtual_ip, cidr,
			created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, '10.77.0.0/16', ?, ?)`,
			row.ID, row.TenantID, row.Owner, row.ClientID, fmt.Sprintf("acct-del-%d", row.ClientID),
			fmt.Sprintf("10.77.0.%d", row.ID%250), stamp, stamp)
	}

	actor := signLocalToken(deletion.Actor)
	for index, step := range deletion.Steps {
		name := fmt.Sprintf("step %d", index)
		switch {
		case step.DeleteUser != "":
			status, payload := h.do(http.MethodDelete, "/api/admin/users/"+step.DeleteUser, actor, nil)
			if status != step.Expect.Status {
				t.Fatalf("%s: delete %s status %d body %s", name, step.DeleteUser, status, payload)
			}
			if status == http.StatusConflict {
				var body struct {
					Error       string `json:"error"`
					Clients     *int64 `json:"clients"`
					Credentials *int64 `json:"credentials"`
				}
				if json.Unmarshal(payload, &body) != nil || body.Error == "" || body.Clients == nil ||
					body.Credentials == nil || *body.Clients != *step.Expect.Clients ||
					*body.Credentials != *step.Expect.Credentials {
					t.Fatalf("%s: refusal body %s", name, payload)
				}
			}
		case step.Get != "":
			status, payload := h.do(http.MethodGet, step.Get, signLocalToken(step.As), nil)
			var actual, expected any
			if status != step.Expect.Status || json.Unmarshal(payload, &actual) != nil ||
				json.Unmarshal(step.Expect.Body, &expected) != nil || fmt.Sprint(actual) != fmt.Sprint(expected) {
				t.Fatalf("%s: GET %s status %d body %s", name, step.Get, status, payload)
			}
		case step.Fixture == "transfer-client":
			exec(`UPDATE specus_client_account SET owner_username = ? WHERE id = ?`, step.Owner, step.ID)
			exec(`UPDATE peer_mesh_device SET owner_username = ? WHERE client_id = ?`, step.Owner, step.ID)
		case step.Fixture == "delete-client":
			exec(`DELETE FROM specus_client_account WHERE id = ?`, step.ID)
		case step.Fixture == "delete-credential":
			exec(`DELETE FROM specus_client_credential WHERE id = ?`, step.ID)
		case step.Fixture == "create-account":
			h.addUser(step.AccountKey, step.LoginName, step.TenantID, "vector-password", step.Role)
		default:
			t.Fatalf("%s: unknown step", name)
		}
	}

	check := time.Now().UTC().Format(deletionTimeLayout)
	for table, rows := range deletion.RowsAfter {
		target, ok := deletionTables[table]
		if !ok {
			t.Fatalf("unknown table %s", table)
		}
		expected := map[int64]string{}
		for _, row := range rows {
			owner := row.Owner + row.Username
			if row.Active != nil {
				owner += fmt.Sprintf(" active=%v", *row.Active)
			}
			expected[row.ID] = owner
		}
		actual := map[int64]string{}
		for _, row := range deletion.Seed[table] {
			var owner string
			var expiresAt, uploadExpiresAt, status sql.NullString
			var err error
			if table == "attachments" {
				err = raw.QueryRow(`SELECT owner_username, expires_at, upload_expires_at, status
					FROM transfer_attachment WHERE id = ?`, row.ID).Scan(&owner, &expiresAt, &uploadExpiresAt, &status)
			} else {
				err = raw.QueryRow(`SELECT `+target[1]+` FROM `+target[0]+` WHERE id = ?`, row.ID).Scan(&owner)
			}
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				t.Fatalf("%s %d: %v", table, row.ID, err)
			}
			if table == "attachments" {
				active := expiresAt.String > check && (status.String != "PENDING" || uploadExpiresAt.String > check)
				owner += fmt.Sprintf(" active=%v", active)
			}
			actual[row.ID] = owner
		}
		if fmt.Sprint(actual) != fmt.Sprint(expected) {
			t.Errorf("%s after the deletions: %v, want %v", table, actual, expected)
		}
	}
	for _, account := range deletion.AccountsAfter {
		stored, err := h.db.FindManagementUserByLogin(context.Background(), account.TenantID, account.LoginName)
		if err != nil || stored == nil || stored.AccountKey != account.AccountKey {
			t.Errorf("account %s@%s: %+v %v", account.LoginName, account.TenantID, stored, err)
		}
	}
	for _, account := range deletion.Accounts {
		stored, _ := h.db.FindManagementUserByAccountKey(context.Background(), account.AccountKey)
		kept := false
		for _, after := range deletion.AccountsAfter {
			kept = kept || after.AccountKey == account.AccountKey
		}
		if (stored != nil) != kept {
			t.Errorf("account %s: stored=%v, want kept=%v", account.AccountKey, stored != nil, kept)
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
