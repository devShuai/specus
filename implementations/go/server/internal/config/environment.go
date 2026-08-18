package config

import (
	"fmt"
	"strings"
)

// Environment is the deployment environment that gates demo data and default-credential checks.
type Environment string

const (
	EnvProd Environment = "prod"
	EnvDev  Environment = "dev"
	EnvTest Environment = "test"
)

// knownDefaultPasswords lists values published in the repository, docs and demo data, plus the
// usual throwaway passwords. Production refuses to start while one of them is configured.
var knownDefaultPasswords = map[string]struct{}{
	"admin":                     {},
	"password":                  {},
	"123456":                    {},
	"12345678":                  {},
	"changeme":                  {},
	"change_me_admin_password":  {},
	"change-me-before-exposure": {},
	"change-me":                 {},
	"specus":                    {},
	"test1234":                  {},
	"demo":                      {},
}

var knownDefaultJWTSecrets = map[string]struct{}{
	"replace-with-a-long-random-secret": {},
}

// ParseEnvironment resolves the configured environment name. Unset or unknown values resolve to
// prod so a typo never disables a production guard.
func ParseEnvironment(value string) Environment {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "dev", "development", "local":
		return EnvDev
	case "test", "testing":
		return EnvTest
	default:
		return EnvProd
	}
}

// Environment returns the resolved deployment environment for this config.
func (c Config) Environment() Environment {
	return ParseEnvironment(c.Env)
}

// AllowsDemoData reports whether convenience seed data may be created.
func (e Environment) AllowsDemoData() bool {
	return e != EnvProd
}

func (e Environment) IsProd() bool {
	return e == EnvProd
}

// SeedDemoDataEnabled reports whether the demo client and credential should be seeded. Prod never
// seeds them regardless of the requested flag.
func (c Config) SeedDemoDataEnabled() bool {
	return c.Database.SeedDemoClient && c.Environment().AllowsDemoData()
}

// ValidateSecurityBaseline fails startup when a production deployment still carries credentials
// that ship with the project or are trivially guessable.
func (c Config) ValidateSecurityBaseline() error {
	if !c.Environment().IsProd() {
		return nil
	}
	password := strings.TrimSpace(c.Auth.Password)
	if c.Auth.PasswordLoginEnabled && password != "" {
		if _, known := knownDefaultPasswords[strings.ToLower(password)]; known {
			return fmt.Errorf(
				"auth.password is a known default credential and is refused in prod; set SPECUS_AUTH_PASSWORD to a unique value or leave it blank to disable password login")
		}
	}
	jwtSecret := strings.TrimSpace(c.Auth.JwtSecret)
	if _, known := knownDefaultJWTSecrets[strings.ToLower(jwtSecret)]; known {
		return fmt.Errorf(
			"auth.jwtSecret is a published placeholder and is refused in prod; set SPECUS_AUTH_JWT_SECRET to a unique random value or leave it blank to use an ephemeral key")
	}
	return nil
}
