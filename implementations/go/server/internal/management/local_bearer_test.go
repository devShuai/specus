package management

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestBuiltInBearerRequiresCurrentEnabledPasswordConfiguration(t *testing.T) {
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "built-in-bearer.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	enabled := config.AuthConfig{
		PasswordLoginEnabled: true, Username: "admin", Password: "secret",
		TenantID: "default", JwtSecret: "shared-signing-secret", TokenTTLSeconds: 3600,
	}
	issued := security.NewLocalTokenService(enabled)
	adminToken := issued.IssueForUser("admin", "stale-tenant", store.ManagementRoleAdmin)

	disabled := enabled
	disabled.PasswordLoginEnabled = false
	disabledTokens := security.NewLocalTokenService(disabled)
	disabledAPI := NewAPI(db, session.NewRegistry(), disabledTokens, nil, nil, nil,
		config.OidcConfig{}, disabled, config.ClientAuthConfig{}, config.TrafficConfig{},
		nil, nil, nil, nil, nil, nil)
	if _, ok := disabledAPI.authenticate(context.Background(), adminToken); ok {
		t.Fatal("built-in token remained valid after password login was disabled")
	}

	renamed := enabled
	renamed.Username = "root"
	renamedTokens := security.NewLocalTokenService(renamed)
	renamedAPI := NewAPI(db, session.NewRegistry(), renamedTokens, nil, nil, nil,
		config.OidcConfig{}, renamed, config.ClientAuthConfig{}, config.TrafficConfig{},
		nil, nil, nil, nil, nil, nil)
	if _, ok := renamedAPI.authenticate(context.Background(), adminToken); ok {
		t.Fatal("old built-in username remained privileged after configuration changed")
	}

	userRoleToken := issued.IssueForUser("admin", "default", store.ManagementRoleUser)
	enabledAPI := NewAPI(db, session.NewRegistry(), issued, nil, nil, nil,
		config.OidcConfig{}, enabled, config.ClientAuthConfig{}, config.TrafficConfig{},
		nil, nil, nil, nil, nil, nil)
	if _, ok := enabledAPI.authenticate(context.Background(), userRoleToken); ok {
		t.Fatal("built-in username upgraded a USER token")
	}
}
