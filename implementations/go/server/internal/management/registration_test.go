package management

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/config"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/security"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/store"
)

type recordingRegistrationMailer struct {
	configured bool
	email      string
	username   string
	code       string
}

func (m *recordingRegistrationMailer) Configured() bool { return m.configured }

func (m *recordingRegistrationMailer) SendVerificationCode(
	_ context.Context, email, username, code string, _ int64,
) error {
	m.email, m.username, m.code = email, username, code
	return nil
}

func TestRegistrationRequiresEmailCodeBeforeCreatingUser(t *testing.T) {
	service, db, mailer := newTestRegistrationService(t, 5)
	ctx := context.Background()
	challenge, err := service.Request(ctx, "alice", "Alice@Example.com", "password-1")
	if err != nil {
		t.Fatalf("request registration: %v", err)
	}
	if challenge.RegistrationID == "" || challenge.EmailMasked != "al***@example.com" || len(mailer.code) != 6 {
		t.Fatalf("unexpected challenge=%+v mailer=%+v", challenge, mailer)
	}
	if user, err := db.FindManagementUserByUsername(ctx, "alice"); err != nil || user != nil {
		t.Fatalf("user exists before verification: user=%+v err=%v", user, err)
	}
	stored, err := db.FindRegistrationChallengeByID(ctx, challenge.RegistrationID)
	if err != nil || stored == nil {
		t.Fatalf("stored challenge missing: challenge=%+v err=%v", stored, err)
	}
	if stored.CodeHash == mailer.code || stored.PasswordHash == "password-1" {
		t.Fatalf("challenge stored plaintext secret: %+v", stored)
	}

	user, err := service.Verify(ctx, challenge.RegistrationID, mailer.code)
	if err != nil {
		t.Fatalf("verify registration: %v", err)
	}
	if user.Username != "alice" || user.Role != store.ManagementRoleUser || !user.Enabled {
		t.Fatalf("unexpected registered user: %+v", user)
	}
	if exists, err := db.ManagementEmailExists(ctx, "alice@example.com"); err != nil || !exists {
		t.Fatalf("verified email missing: exists=%v err=%v", exists, err)
	}
	if stored, err := db.FindRegistrationChallengeByID(ctx, challenge.RegistrationID); err != nil || stored != nil {
		t.Fatalf("challenge retained after completion: challenge=%+v err=%v", stored, err)
	}
}

func TestRegistrationDeletesChallengeAfterAttemptLimit(t *testing.T) {
	service, db, _ := newTestRegistrationService(t, 2)
	ctx := context.Background()
	challenge, err := service.Request(ctx, "bob", "bob@example.com", "password-2")
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := service.Verify(ctx, challenge.RegistrationID, "000000"); !errors.Is(err, ErrValidation) {
			t.Fatalf("attempt %d error = %v, want validation", attempt, err)
		}
	}
	if stored, err := db.FindRegistrationChallengeByID(ctx, challenge.RegistrationID); err != nil || stored != nil {
		t.Fatalf("challenge remains after max attempts: challenge=%+v err=%v", stored, err)
	}
}

func newTestRegistrationService(
	t *testing.T, maxAttempts int,
) (*registrationService, *store.DB, *recordingRegistrationMailer) {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "registration.db"))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := config.AuthConfig{
		PasswordLoginEnabled: true,
		RegistrationEnabled:  true,
		Username:             "admin",
		Password:             "admin-password",
		TenantID:             "default",
		JwtSecret:            "test-registration-secret",
		TokenTTLSeconds:      3600,
		Turnstile: config.TurnstileConfig{
			Enabled: true, SiteKey: "site", SecretKey: "secret", VerifyURL: "https://verify.example",
			AllowedHostnames: []string{"tunnel.example.com"},
		},
		EmailVerification: config.EmailVerificationConfig{
			Enabled: true, CodeTTLSeconds: 600, MaxAttempts: maxAttempts, ResendCooldownSeconds: 60,
		},
	}
	tokens := security.NewLocalTokenService(cfg)
	mailer := &recordingRegistrationMailer{configured: true}
	service := newRegistrationService(db, tokens, security.NewTurnstileVerifier(cfg.Turnstile), cfg, mailer)
	return service, db, mailer
}
