package config

import "testing"

func TestParseEnvironmentDefaultsToProd(t *testing.T) {
	cases := map[string]Environment{
		"":            EnvProd,
		"   ":         EnvProd,
		"staging":     EnvProd,
		"prod":        EnvProd,
		" DEV ":       EnvDev,
		"development": EnvDev,
		"Test":        EnvTest,
		"testing":     EnvTest,
	}
	for value, want := range cases {
		if got := ParseEnvironment(value); got != want {
			t.Fatalf("ParseEnvironment(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestSeedDemoDataOnlyOutsideProd(t *testing.T) {
	cfg := Default()
	cfg.Database.SeedDemoClient = true

	cfg.Env = ""
	if cfg.SeedDemoDataEnabled() {
		t.Fatal("prod must not seed demo data even when the flag is set")
	}
	cfg.Env = "dev"
	if !cfg.SeedDemoDataEnabled() {
		t.Fatal("dev should seed demo data when the flag is set")
	}
	cfg.Database.SeedDemoClient = false
	if cfg.SeedDemoDataEnabled() {
		t.Fatal("an explicitly disabled flag must stay disabled in dev")
	}
}

func TestSecurityBaselineRefusesKnownDefaultPasswordInProd(t *testing.T) {
	cfg := Default()
	cfg.Auth.PasswordLoginEnabled = true

	for _, password := range []string{
		"admin",
		"Admin",
		"password",
		"123456",
		"12345678",
		" test1234 ",
		"changeme",
		"change_me_admin_password",
		"CHANGE-ME-BEFORE-EXPOSURE",
		" change-me ",
		"specus",
		"demo",
	} {
		cfg.Env = "prod"
		cfg.Auth.Password = password
		if err := cfg.ValidateSecurityBaseline(); err == nil {
			t.Fatalf("prod must refuse the known default password %q", password)
		}
		cfg.Env = "dev"
		if err := cfg.ValidateSecurityBaseline(); err != nil {
			t.Fatalf("dev must tolerate %q: %v", password, err)
		}
	}
}

func TestSecurityBaselineRefusesPublishedJWTPlaceholderInProd(t *testing.T) {
	cfg := Default()
	cfg.Auth.JwtSecret = " Replace-With-A-Long-Random-Secret "

	cfg.Env = "prod"
	if err := cfg.ValidateSecurityBaseline(); err == nil {
		t.Fatal("prod must refuse the published JWT placeholder")
	}
	cfg.Env = "dev"
	if err := cfg.ValidateSecurityBaseline(); err != nil {
		t.Fatalf("dev must tolerate the JWT placeholder: %v", err)
	}
}

func TestSecurityBaselineAllowsStrongOrDisabledPasswordLogin(t *testing.T) {
	cfg := Default()
	cfg.Env = "prod"
	cfg.Auth.PasswordLoginEnabled = true

	cfg.Auth.Password = "8Qb!x2s7Lm#4pTz"
	if err := cfg.ValidateSecurityBaseline(); err != nil {
		t.Fatalf("strong password must be accepted: %v", err)
	}
	// Blank password keeps password login disabled, which is the shipped default.
	cfg.Auth.Password = ""
	if err := cfg.ValidateSecurityBaseline(); err != nil {
		t.Fatalf("blank password must be accepted: %v", err)
	}
	cfg.Auth.Password = "admin"
	cfg.Auth.PasswordLoginEnabled = false
	if err := cfg.ValidateSecurityBaseline(); err != nil {
		t.Fatalf("disabled password login must be accepted: %v", err)
	}
	cfg.Auth.JwtSecret = "a-unique-production-jwt-secret"
	if err := cfg.ValidateSecurityBaseline(); err != nil {
		t.Fatalf("unique JWT secret must be accepted: %v", err)
	}
}

func TestDefaultConfigShipsNoPasswordCredential(t *testing.T) {
	cfg := Default()
	if cfg.Auth.Password != "" {
		t.Fatalf("default auth.password = %q, want empty", cfg.Auth.Password)
	}
	if !cfg.Auth.LoginRateLimit.Enabled {
		t.Fatal("login rate limiting must be enabled by default")
	}
	if cfg.Auth.LoginRateLimit.PerIP <= 0 || cfg.Auth.LoginRateLimit.PerAccount <= 0 {
		t.Fatalf("login rate limit budgets must be positive: %+v", cfg.Auth.LoginRateLimit)
	}
}
