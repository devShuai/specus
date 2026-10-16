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
	"sync/atomic"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
	"modernc.org/sqlite"
)

var passwordReadBarrierSerial atomic.Uint64

// A private SQLite VIEW/UDF holds the SELECT's original snapshot while another connection
// commits. WAL permits that commit. No production callback, sleep or password-hasher switch.
func TestPasswordLoginUsesCurrentStateAfterLookup(t *testing.T) {
	for _, scenario := range []string{"disabled", "demoted", "rotated", "oidc-rebound", "replacement"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			entered, release := make(chan struct{}), make(chan struct{})
			var barrierOnce, releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			fn := fmt.Sprintf("specus_test_password_read_%d", passwordReadBarrierSerial.Add(1))
			if err := sqlite.RegisterScalarFunction(fn, 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
				barrierOnce.Do(func() {
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
			path := filepath.Join(t.TempDir(), "password.db")
			h := newTenantLoginHarness(t, path, config.LoginRateLimitConfig{})
			now := time.Now()
			user, err := h.db.InsertManagementUser(ctx, store.ManagementUser{AccountKey: "password-original-key", Username: "password-user", TenantID: "default", PasswordHash: auth.HashToken("original-password"), Role: store.ManagementRoleAdmin, Enabled: true, CreatedAt: now, UpdatedAt: now})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			raw.SetMaxOpenConns(1)
			var journal string
			if err := raw.QueryRowContext(ctx, `PRAGMA journal_mode=WAL`).Scan(&journal); err != nil || journal != "wal" {
				t.Fatalf("test snapshot requires WAL: %s / %v", journal, err)
			}
			for _, statement := range []string{
				`ALTER TABLE specus_management_user RENAME TO password_management_fixture`,
				`CREATE VIEW specus_management_user AS SELECT username,login_name,login_name_normalized,tenant_id,password_hash,oidc_issuer,oidc_subject,oidc_identity_key,role,` + fn + `(enabled) AS enabled,created_at,updated_at FROM password_management_fixture`,
				`CREATE TRIGGER password_fixture_update INSTEAD OF UPDATE ON specus_management_user BEGIN UPDATE password_management_fixture SET password_hash=NEW.password_hash,oidc_issuer=NEW.oidc_issuer,oidc_subject=NEW.oidc_subject,oidc_identity_key=NEW.oidc_identity_key,role=NEW.role,enabled=NEW.enabled,updated_at=NEW.updated_at WHERE username=OLD.username; END`,
			} {
				if _, err := raw.ExecContext(ctx, statement); err != nil {
					t.Fatal(err)
				}
			}
			body := []byte(`{"username":"password-user","password":"original-password","tenantId":"default"}`)
			req, err := http.NewRequestWithContext(ctx, "POST", h.server.URL+"/auth/login", bytes.NewReader(body))
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
				t.Fatal("actual password lookup did not reach snapshot barrier")
			}
			wantStatus, wantRole, wantEnabled := 200, store.ManagementRoleAdmin, true
			wantHash := user.PasswordHash
			wantOIDC := ""
			switch scenario {
			case "disabled":
				wantStatus, wantEnabled = 401, false
				_, err = raw.ExecContext(ctx, `UPDATE password_management_fixture SET enabled=0 WHERE username=?`, user.AccountKey)
			case "demoted":
				wantRole = store.ManagementRoleUser
				_, err = raw.ExecContext(ctx, `UPDATE password_management_fixture SET role='USER' WHERE username=?`, user.AccountKey)
			case "rotated":
				wantStatus = 401
				wantHash = auth.HashPassword("replacement-password")
				_, err = raw.ExecContext(ctx, `UPDATE password_management_fixture SET password_hash=? WHERE username=?`, wantHash, user.AccountKey)
			case "oidc-rebound":
				wantOIDC = "new-identity-key"
				_, err = raw.ExecContext(ctx, `UPDATE password_management_fixture SET oidc_identity_key=?,oidc_issuer='new-issuer',oidc_subject='new-subject' WHERE username=?`, wantOIDC, user.AccountKey)
			case "replacement":
				wantStatus = 401
				if _, err = raw.ExecContext(ctx, `DELETE FROM password_management_fixture WHERE username=?`, user.AccountKey); err == nil {
					_, err = raw.ExecContext(ctx, `INSERT INTO password_management_fixture(username,login_name,login_name_normalized,tenant_id,password_hash,role,enabled,created_at,updated_at) VALUES('password-replacement-key','password-user','password-user','default',?,'USER',1,?,?)`, auth.HashToken("replacement-password"), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			unblock()
			got := <-done
			if got.err != nil || got.status != wantStatus {
				t.Errorf("stale password login admitted: scenario=%s status=%d want=%d err=%v", scenario, got.status, wantStatus, got.err)
			}
			if got.status == 200 && wantStatus == 200 {
				var token security.TokenResponse
				if err := json.Unmarshal(got.body, &token); err != nil {
					t.Fatal(err)
				}
				claims, ok := h.tokens.ValidateClaims(token.AccessToken)
				if !ok || claims.Role != wantRole {
					t.Errorf("password login issued stale role: got=%s want=%s valid=%v", claims.Role, wantRole, ok)
				}
			}
			if scenario == "replacement" {
				return
			}
			var role, hash, oidc string
			var enabled bool
			if err := raw.QueryRowContext(ctx, `SELECT role,password_hash,COALESCE(oidc_identity_key,''),enabled FROM password_management_fixture WHERE username=?`, user.AccountKey).Scan(&role, &hash, &oidc, &enabled); err != nil {
				t.Fatal(err)
			}
			if role != wantRole || enabled != wantEnabled || oidc != wantOIDC {
				t.Errorf("hash upgrade restored stale account state: role=%s enabled=%v oidcPreserved=%v", role, enabled, oidc == wantOIDC)
			}
			if scenario == "rotated" && hash != wantHash {
				t.Error("hash upgrade reverted concurrent password rotation")
			}
			if scenario == "oidc-rebound" {
				var issuer, subject string
				if err := raw.QueryRowContext(ctx, `SELECT oidc_issuer,oidc_subject FROM password_management_fixture WHERE username=?`, user.AccountKey).Scan(&issuer, &subject); err != nil || issuer != "new-issuer" || subject != "new-subject" {
					t.Errorf("hash upgrade reverted OIDC binding: %v", err)
				}
			}
		})
	}
}
