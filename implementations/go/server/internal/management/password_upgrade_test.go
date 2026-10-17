package management

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
	"modernc.org/sqlite"
)

func TestPasswordLoginReverifiesConcurrentLegitimateUpgrade(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	fn := fmt.Sprintf("specus_test_password_retry_%d", passwordReadBarrierSerial.Add(1))
	if err := sqlite.RegisterScalarFunction(fn, 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		once.Do(func() {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
			}
		})
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return args[0], nil
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "retry.db")
	h := newTenantLoginHarness(t, path, config.LoginRateLimitConfig{})
	now := time.Now()
	user, err := h.db.InsertManagementUser(ctx, store.ManagementUser{Username: "password-retry", TenantID: "default", PasswordHash: auth.HashToken("same-password"), Role: store.ManagementRoleAdmin, Enabled: true, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetMaxOpenConns(1)
	var mode string
	if err := raw.QueryRowContext(ctx, `PRAGMA journal_mode=WAL`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`ALTER TABLE specus_management_user RENAME TO password_retry_fixture`,
		`CREATE VIEW specus_management_user AS SELECT username,login_name,login_name_normalized,tenant_id,password_hash,oidc_issuer,oidc_subject,oidc_identity_key,role,` + fn + `(enabled) AS enabled,created_at,updated_at FROM password_retry_fixture`,
		`CREATE TRIGGER password_retry_update INSTEAD OF UPDATE ON specus_management_user BEGIN UPDATE password_retry_fixture SET password_hash=NEW.password_hash,oidc_issuer=NEW.oidc_issuer,oidc_subject=NEW.oidc_subject,oidc_identity_key=NEW.oidc_identity_key,role=NEW.role,enabled=NEW.enabled,updated_at=NEW.updated_at WHERE username=OLD.username; END`,
	} {
		if _, err := raw.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, "POST", h.server.URL+"/auth/login", bytes.NewBufferString(`{"username":"password-retry","password":"same-password","tenantId":"default"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	type result struct {
		status int
		body   []byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- result{err: err}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		done <- result{resp.StatusCode, body, err}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("retry login did not reach snapshot barrier")
	}
	upgraded := auth.HashPassword("same-password")
	if _, err := raw.ExecContext(ctx, `UPDATE password_retry_fixture SET password_hash=?,role='USER',oidc_identity_key='retry-current-binding',oidc_issuer='retry-issuer',oidc_subject='retry-subject' WHERE username=?`, upgraded, user.AccountKey); err != nil {
		t.Fatal(err)
	}
	unblock()
	got := <-done
	if got.err != nil || got.status != 200 {
		t.Fatalf("legitimate concurrent upgrade rejected rather than reverified: status=%d err=%v", got.status, got.err)
	}
	var token security.TokenResponse
	if err := json.Unmarshal(got.body, &token); err != nil {
		t.Fatal(err)
	}
	claims, ok := h.tokens.ValidateClaims(token.AccessToken)
	if !ok || claims.Role != store.ManagementRoleUser {
		t.Fatalf("retry returned stale role: role=%s valid=%v", claims.Role, ok)
	}
	var hash, role, binding string
	if err := raw.QueryRowContext(ctx, `SELECT password_hash,role,oidc_identity_key FROM password_retry_fixture WHERE username=?`, user.AccountKey).Scan(&hash, &role, &binding); err != nil || hash != upgraded || role != store.ManagementRoleUser || binding != "retry-current-binding" {
		t.Fatalf("retry overwrote latest account metadata/hash: %v", err)
	}
}

func TestPasswordOptionalUpgradeFailureDoesNotFailCurrentAuthentication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade-failure.db")
	h := newTenantLoginHarness(t, path, config.LoginRateLimitConfig{})
	ctx := context.Background()
	now := time.Now()
	user, err := h.db.InsertManagementUser(ctx, store.ManagementUser{Username: "password-upgrade-failure", TenantID: "default", PasswordHash: auth.HashToken("correct-password"), Role: store.ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`CREATE TRIGGER reject_password_upgrade BEFORE UPDATE OF password_hash ON specus_management_user WHEN NEW.password_hash<>OLD.password_hash BEGIN SELECT RAISE(ABORT,'injected optional password upgrade failure'); END`); err != nil {
		t.Fatal(err)
	}
	token, claims := h.login(user.Username, "correct-password", "default")
	if token == "" || claims.Role != store.ManagementRoleUser {
		t.Fatal("optional hash maintenance failure denied otherwise current verified login")
	}
	current, err := h.db.FindManagementUserByAccountKey(ctx, user.AccountKey)
	if err != nil || current == nil || current.PasswordHash != user.PasswordHash || !current.Enabled {
		t.Fatalf("failed maintenance changed account state: %v", err)
	}
}

func TestPasswordCurrentValidationFailureDoesNotIssueToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "validation-failure.db")
	h := newTenantLoginHarness(t, path, config.LoginRateLimitConfig{})
	ctx := context.Background()
	now := time.Now()
	if _, err := h.db.InsertManagementUser(ctx, store.ManagementUser{Username: "password-validation-failure", TenantID: "default", PasswordHash: auth.HashToken("correct-password"), Role: store.ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`CREATE TRIGGER reject_password_validation BEFORE UPDATE OF enabled ON specus_management_user BEGIN SELECT RAISE(ABORT,'injected current identity validation failure'); END`); err != nil {
		t.Fatal(err)
	}
	status, payload := h.do("POST", "/auth/login", "", map[string]string{"username": "password-validation-failure", "password": "correct-password", "tenantId": "default"})
	if status != 500 || bytes.Contains(payload, []byte("accessToken")) {
		t.Fatalf("unverified current identity was issued a token: status=%d", status)
	}
}
