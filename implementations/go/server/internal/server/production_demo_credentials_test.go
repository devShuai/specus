package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func demoCredentialTestConfig(databasePath, environment string, seed bool) config.Config {
	cfg := config.Default()
	cfg.Env = environment
	cfg.ConnectionString = databasePath
	cfg.Database.SeedDemoClient = seed
	cfg.Netty.BindAddress = "127.0.0.1"
	cfg.ManagementAddr = "127.0.0.1:0"
	cfg.Auth.Password = "unique-production-admin-password"
	cfg.Auth.JwtSecret = "unique-production-jwt-signing-secret"
	return cfg
}

func insertHistoricalDemoCredentials(t *testing.T, databasePath string) {
	t.Helper()
	db, err := store.Open("sqlite", databasePath)
	if err != nil {
		t.Fatalf("open seed database: %v", err)
	}
	now := time.Now().UTC()
	if err := db.InsertClient(context.Background(), store.ClientAccount{
		ID: 1, TenantID: "default", OwnerUsername: "admin",
		ClientName: DemoClientName, PasswordHash: auth.HashPassword(DemoCredentialPlainSecret), Enabled: true,
		ConnectionRateLimitPerMinute: 30, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		_ = db.Close()
		t.Fatalf("insert historical demo client: %v", err)
	}
	if err := db.InsertCredential(context.Background(), store.ClientCredential{
		ID: 2, TenantID: "default", OwnerUsername: "admin",
		APIKey: DemoCredentialAPIKey, SecretHash: auth.HashPassword(DemoCredentialPlainSecret), Enabled: true,
		MaxOnlineInstances: 2, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		_ = db.Close()
		t.Fatalf("insert historical demo credential: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close seed database: %v", err)
	}
}

func newDemoCredentialTestApp(t *testing.T, cfg config.Config) *App {
	t.Helper()
	app, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	t.Cleanup(func() { _ = app.Close() })
	return app
}

func TestProductionStartupDisablesHistoricalDemoCredentials(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		environment string
		wantEnabled bool
	}{
		{name: "production", environment: "prod", wantEnabled: false},
		{name: "development", environment: "dev", wantEnabled: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "specus.db")
			insertHistoricalDemoCredentials(t, databasePath)
			app := newDemoCredentialTestApp(t,
				demoCredentialTestConfig(databasePath, testCase.environment, true))

			client, err := app.DB().FindClientByName(context.Background(), DemoClientName)
			if err != nil || client == nil || client.Enabled != testCase.wantEnabled {
				t.Fatalf("demo client enabled=%v, want %v (client=%+v err=%v)",
					client != nil && client.Enabled, testCase.wantEnabled, client, err)
			}
			credential, err := app.DB().FindCredentialByAPIKey(context.Background(), DemoCredentialAPIKey)
			if err != nil || credential == nil || credential.Enabled != testCase.wantEnabled {
				t.Fatalf("demo credential enabled=%v, want %v (credential=%+v err=%v)",
					credential != nil && credential.Enabled, testCase.wantEnabled, credential, err)
			}
		})
	}
}

func TestNewEnforcesProductionSecurityBaselineForProgrammaticConfigs(t *testing.T) {
	cfg := demoCredentialTestConfig(filepath.Join(t.TempDir(), "specus.db"), "prod", false)
	cfg.Auth.PasswordLoginEnabled = true
	cfg.Auth.Password = "change-me"
	app, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if app != nil {
		_ = app.Close()
		t.Fatal("server.New returned an app for a published production credential")
	}
	if err == nil {
		t.Fatal("server.New must enforce the production security baseline")
	}
}

func TestDatabaseInitializeHonorsDemoSeedPolicy(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		environment string
		seed        bool
		wantSeeded  bool
	}{
		{name: "production-never-seeds", environment: "prod", seed: true, wantSeeded: false},
		{name: "disabled-in-test", environment: "test", seed: false, wantSeeded: false},
		{name: "enabled-in-test", environment: "test", seed: true, wantSeeded: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "specus.db")
			app := newDemoCredentialTestApp(t,
				demoCredentialTestConfig(databasePath, testCase.environment, testCase.seed))
			if client, _ := app.DB().FindClientByName(context.Background(), DemoClientName); client != nil {
				if err := app.DB().DeleteClient(context.Background(), client.ID); err != nil {
					t.Fatalf("remove startup demo client: %v", err)
				}
			}
			if credential, _ := app.DB().FindCredentialByAPIKey(context.Background(), DemoCredentialAPIKey); credential != nil {
				if err := app.DB().DeleteCredential(context.Background(), credential.ID); err != nil {
					t.Fatalf("remove startup demo credential: %v", err)
				}
			}

			_, server := newHTTPTestServer(t, app)
			response := authRequest(t, server, http.MethodPost, "/api/admin/database/initialize",
				loginToken(t, server, "admin", "unique-production-admin-password"), "")
			response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("database initialize status = %d", response.StatusCode)
			}
			client, err := app.DB().FindClientByName(context.Background(), DemoClientName)
			if err != nil {
				t.Fatalf("find demo client: %v", err)
			}
			credential, err := app.DB().FindCredentialByAPIKey(context.Background(), DemoCredentialAPIKey)
			if err != nil {
				t.Fatalf("find demo credential: %v", err)
			}
			if (client != nil) != testCase.wantSeeded || (credential != nil) != testCase.wantSeeded {
				t.Fatalf("seeded client=%v credential=%v, want both %v",
					client != nil, credential != nil, testCase.wantSeeded)
			}
		})
	}
}
