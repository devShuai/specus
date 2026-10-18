package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func readRegistrationEmailVectors(t *testing.T, name string) []byte {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	for {
		raw, err = os.ReadFile(filepath.Join(dir, "protocol", "test-vectors", name))
		if err == nil {
			break
		}
		if !os.IsNotExist(err) || filepath.Dir(dir) == dir {
			t.Fatal(err)
		}
		dir = filepath.Dir(dir)
	}
	return raw
}

func TestSharedRegistrationEmailMasks(t *testing.T) {
	raw := readRegistrationEmailVectors(t, "registration-email-mask-v1.json")
	var fixture struct {
		Version int
		Cases   []struct{ Name, Email, Masked string }
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 || len(fixture.Cases) != 24 {
		t.Fatal("unexpected mask vector version/count")
	}
	for _, item := range fixture.Cases {
		t.Run(item.Name, func(t *testing.T) {
			actual := maskRegistrationEmail(item.Email)
			if !utf8.ValidString(actual) || actual != item.Masked {
				t.Fatalf("mask = %q, want %q", actual, item.Masked)
			}
			wire, err := json.Marshal(map[string]string{"emailMasked": actual})
			if err != nil || !utf8.Valid(wire) {
				t.Fatalf("invalid JSON UTF-8: %q %v", wire, err)
			}
			var decoded map[string]string
			if err := json.Unmarshal(wire, &decoded); err != nil || decoded["emailMasked"] != item.Masked {
				t.Fatalf("JSON changed mask: %q %v", wire, err)
			}
		})
	}
}

type recordingRegistrationMailer struct {
	mu         sync.Mutex
	configured bool
	email      string
	username   string
	code       string
	sendCount  int
}

func (m *recordingRegistrationMailer) Configured() bool { return m.configured }

func (m *recordingRegistrationMailer) SendVerificationCode(
	_ context.Context, email, username, code string, _ int64,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.email, m.username, m.code = email, username, code
	m.sendCount++
	return nil
}

func (m *recordingRegistrationMailer) deliverySnapshot() (string, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.email, m.sendCount
}

func TestRegistrationEmailNulPolicyHTTP(t *testing.T) {
	var fixture struct {
		Version int
		Cases   []struct {
			Name, Email, Normalized, Masked string
			Accepted                        bool
		}
	}
	if err := json.Unmarshal(readRegistrationEmailVectors(t, "registration-email-nul-v1.json"), &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 || len(fixture.Cases) != 14 {
		t.Fatal("unexpected NUL vector version/count")
	}
	service, db, mailer := newTestRegistrationService(t, 5)
	// Isolate the external Turnstile call; keep the actual JSON handler, service and SQLite.
	api := &API{registration: service, logger: slog.Default()}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/register", api.handleRegister)
	server := httptest.NewServer(mux)
	defer server.Close()
	for _, item := range fixture.Cases {
		t.Run(item.Name, func(t *testing.T) {
			username := "nul-http-" + item.Name
			_, beforeSend := mailer.deliverySnapshot()
			body, err := json.Marshal(registrationRequest{Username: username, Email: item.Email, Password: "password-1"})
			if err != nil {
				t.Fatal(err)
			}
			if !item.Accepted && !bytes.Contains(body, []byte(`\u0000`)) {
				t.Fatal("raw JSON request lost escaped NUL")
			}
			response, err := server.Client().Post(server.URL+"/auth/register", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var decoded struct{ EmailMasked, Error string }
			if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
				t.Fatal(err)
			}
			delivered, afterSend := mailer.deliverySnapshot()
			if item.Accepted {
				if response.StatusCode != http.StatusAccepted || afterSend != beforeSend+1 || delivered != item.Normalized || decoded.EmailMasked != item.Masked {
					t.Fatalf("unexpected accepted response: status=%d decoded=%+v delivered=%q sends=%d", response.StatusCode, decoded, delivered, afterSend)
				}
			} else {
				if response.StatusCode != http.StatusBadRequest || decoded.Error != "邮箱格式无效" || beforeSend != afterSend {
					t.Fatalf("invalid raw email accepted/sent: status=%d decoded=%+v sends=%d->%d", response.StatusCode, decoded, beforeSend, afterSend)
				}
				pending, err := db.FindRegistrationChallengeByUsernameOrEmail(context.Background(), username, "")
				if err != nil || pending != nil {
					t.Fatalf("rejected email left a challenge: %+v %v", pending, err)
				}
			}
		})
	}
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
	if user, err := db.FindManagementUserByLogin(ctx, "default", "alice"); err != nil || user != nil {
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

func TestRegistrationChallengeUnicodeMasks(t *testing.T) {
	service, db, mailer := newTestRegistrationService(t, 5)
	for _, item := range []struct{ username, email, masked string }{
		{"mask-ascii", "ab@example.test", "a***@example.test"},
		{"mask-chinese", "用@example.test", "用***@example.test"},
		{"mask-emoji", "😀@example.test", "😀***@example.test"},
		{"mask-mixed", "a😀b@example.test", "a😀***@example.test"},
	} {
		challenge, err := service.Request(context.Background(), item.username, item.email, "password-1")
		if err != nil {
			t.Fatalf("%s: %v", item.username, err)
		}
		if challenge.EmailMasked != item.masked || mailer.email != item.email {
			t.Fatalf("%s: response=%+v delivered=%q", item.username, challenge, mailer.email)
		}
		stored, err := db.FindRegistrationChallengeByID(context.Background(), challenge.RegistrationID)
		if err != nil || stored == nil || stored.Email != item.email {
			t.Fatalf("stored email differs: %+v %v", stored, err)
		}
		wire, err := json.Marshal(challenge)
		if err != nil || !utf8.Valid(wire) {
			t.Fatalf("invalid response UTF-8: %q %v", wire, err)
		}
		var decoded registrationChallengeResponse
		if err := json.Unmarshal(wire, &decoded); err != nil || decoded.EmailMasked != item.masked {
			t.Fatalf("wire mask differs: %q %v", wire, err)
		}
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
			AllowedHostnames: []string{"specus.example.com"},
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
