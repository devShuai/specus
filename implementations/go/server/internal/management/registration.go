package management

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/mail"
	"strings"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

const registrationCodeDigits = 6

type registrationService struct {
	db        *store.DB
	tokens    *security.LocalTokenService
	turnstile *security.TurnstileVerifier
	config    config.AuthConfig
	mailer    registrationMailer
}

type registrationChallengeResponse struct {
	RegistrationID     string `json:"registrationId"`
	EmailMasked        string `json:"emailMasked"`
	ExpiresAt          string `json:"expiresAt"`
	ResendAfterSeconds int64  `json:"resendAfterSeconds"`
}

func newRegistrationService(
	db *store.DB,
	tokens *security.LocalTokenService,
	turnstile *security.TurnstileVerifier,
	cfg config.AuthConfig,
	mailer registrationMailer,
) *registrationService {
	return &registrationService{db: db, tokens: tokens, turnstile: turnstile, config: cfg, mailer: mailer}
}

func (s *registrationService) Available() bool {
	return s != nil && s.config.RegistrationEnabled && s.tokens.PasswordLoginEnabled() &&
		s.config.EmailVerification.Enabled && s.mailer != nil && s.mailer.Configured() &&
		s.turnstile != nil && s.turnstile.Enabled() && s.turnstile.Configured()
}

func (s *registrationService) Request(
	ctx context.Context, rawUsername, rawEmail, rawPassword string,
) (registrationChallengeResponse, error) {
	if !s.Available() {
		return registrationChallengeResponse{}, forbidden("当前未开放邮箱验证注册")
	}
	username, err := normalizeUsername(rawUsername)
	if err != nil {
		return registrationChallengeResponse{}, err
	}
	if strings.EqualFold(username, s.adminUsername()) {
		return registrationChallengeResponse{}, validation("该用户名不可用")
	}
	password, err := requirePassword(rawPassword)
	if err != nil {
		return registrationChallengeResponse{}, err
	}
	email, err := normalizeRegistrationEmail(rawEmail)
	if err != nil {
		return registrationChallengeResponse{}, err
	}
	if existing, findErr := s.db.FindManagementUserByUsername(ctx, username); findErr != nil {
		return registrationChallengeResponse{}, findErr
	} else if existing != nil {
		return registrationChallengeResponse{}, conflict("用户名已存在: " + username)
	}
	if exists, existsErr := s.db.ManagementEmailExists(ctx, email); existsErr != nil {
		return registrationChallengeResponse{}, existsErr
	} else if exists {
		return registrationChallengeResponse{}, conflict("该邮箱已注册")
	}

	now := time.Now().UTC()
	if err := s.db.DeleteExpiredRegistrationChallenges(ctx, now); err != nil {
		return registrationChallengeResponse{}, err
	}
	existing, err := s.db.FindRegistrationChallengeByUsernameOrEmail(ctx, username, email)
	if err != nil {
		return registrationChallengeResponse{}, err
	}
	if existing != nil {
		if !strings.EqualFold(existing.Username, username) || !strings.EqualFold(existing.Email, email) {
			return registrationChallengeResponse{}, conflict("用户名或邮箱正在等待验证")
		}
		if existing.ResendAvailableAt.After(now) {
			wait := int64(existing.ResendAvailableAt.Sub(now).Seconds()) + 1
			return registrationChallengeResponse{}, rateLimited(fmt.Sprintf("请在 %d 秒后重新发送验证码", wait))
		}
		if err := s.db.DeleteRegistrationChallenge(ctx, existing.RegistrationID); err != nil {
			return registrationChallengeResponse{}, err
		}
	}

	registrationID, err := randomRegistrationID()
	if err != nil {
		return registrationChallengeResponse{}, unavailable("暂时无法创建注册验证")
	}
	code, err := randomRegistrationCode()
	if err != nil {
		return registrationChallengeResponse{}, unavailable("暂时无法创建注册验证")
	}
	ttlSeconds := maxInt64(60, s.config.EmailVerification.CodeTTLSeconds)
	cooldownSeconds := maxInt64(1, s.config.EmailVerification.ResendCooldownSeconds)
	challenge := store.ManagementRegistrationChallenge{
		RegistrationID:    registrationID,
		Username:          username,
		Email:             email,
		PasswordHash:      auth.HashPassword(password),
		CodeHash:          s.tokens.RegistrationCodeHash(registrationID, code),
		AttemptsRemaining: maxInt(1, s.config.EmailVerification.MaxAttempts),
		ExpiresAt:         now.Add(time.Duration(ttlSeconds) * time.Second),
		ResendAvailableAt: now.Add(time.Duration(cooldownSeconds) * time.Second),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := s.db.InsertRegistrationChallenge(ctx, challenge); err != nil {
		return registrationChallengeResponse{}, conflict("用户名或邮箱正在等待验证")
	}
	if err := s.mailer.SendVerificationCode(ctx, email, username, code, ttlSeconds); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.db.DeleteRegistrationChallenge(cleanupCtx, registrationID)
		return registrationChallengeResponse{}, unavailable("验证码邮件发送失败，请稍后重试")
	}
	return registrationChallengeResponse{
		RegistrationID:     registrationID,
		EmailMasked:        maskRegistrationEmail(email),
		ExpiresAt:          challenge.ExpiresAt.Format(time.RFC3339Nano),
		ResendAfterSeconds: cooldownSeconds,
	}, nil
}

func (s *registrationService) Verify(
	ctx context.Context, rawRegistrationID, rawCode string,
) (store.ManagementUser, error) {
	if !s.Available() {
		return store.ManagementUser{}, forbidden("当前未开放邮箱验证注册")
	}
	registrationID := strings.TrimSpace(rawRegistrationID)
	code := strings.TrimSpace(rawCode)
	if registrationID == "" || len(registrationID) > 64 || !isRegistrationCode(code) {
		return store.ManagementUser{}, validation("验证码无效或已过期")
	}
	challenge, err := s.db.FindRegistrationChallengeByID(ctx, registrationID)
	if err != nil {
		return store.ManagementUser{}, err
	}
	if challenge == nil {
		return store.ManagementUser{}, validation("验证码无效或已过期")
	}
	now := time.Now().UTC()
	if !challenge.ExpiresAt.After(now) || challenge.AttemptsRemaining <= 0 {
		_ = s.db.DeleteRegistrationChallenge(ctx, registrationID)
		return store.ManagementUser{}, validation("验证码无效或已过期")
	}
	actualHash := s.tokens.RegistrationCodeHash(registrationID, code)
	if subtle.ConstantTimeCompare([]byte(challenge.CodeHash), []byte(actualHash)) != 1 {
		remaining := challenge.AttemptsRemaining - 1
		if remaining <= 0 {
			_ = s.db.DeleteRegistrationChallenge(ctx, registrationID)
		} else if err := s.db.UpdateRegistrationChallengeAttempts(ctx, registrationID, remaining, now); err != nil {
			return store.ManagementUser{}, err
		}
		return store.ManagementUser{}, validation("验证码无效或已过期")
	}
	if existing, findErr := s.db.FindManagementUserByUsername(ctx, challenge.Username); findErr != nil {
		return store.ManagementUser{}, findErr
	} else if existing != nil {
		return store.ManagementUser{}, conflict("用户名已存在: " + challenge.Username)
	}
	if exists, existsErr := s.db.ManagementEmailExists(ctx, challenge.Email); existsErr != nil {
		return store.ManagementUser{}, existsErr
	} else if exists {
		return store.ManagementUser{}, conflict("该邮箱已注册")
	}
	user := store.ManagementUser{
		Username:     challenge.Username,
		TenantID:     normalizeTenant(s.config.TenantID),
		PasswordHash: challenge.PasswordHash,
		Role:         store.ManagementRoleUser,
		Enabled:      true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	userEmail := store.ManagementUserEmail{
		Username: user.Username, Email: challenge.Email, VerifiedAt: now, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.db.CompleteVerifiedRegistration(ctx, *challenge, user, userEmail); err != nil {
		return store.ManagementUser{}, conflict("用户名或邮箱已被注册")
	}
	return user, nil
}

func (s *registrationService) RunCleanup(ctx context.Context) {
	if s == nil {
		return
	}
	interval := time.Duration(s.config.EmailVerification.CleanupIntervalMs) * time.Millisecond
	if interval <= 0 {
		interval = time.Hour
	}
	cleanup := func() { _ = s.db.DeleteExpiredRegistrationChallenges(context.Background(), time.Now().UTC()) }
	cleanup()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanup()
		}
	}
}

func (s *registrationService) adminUsername() string {
	if username := strings.TrimSpace(s.config.Username); username != "" {
		return username
	}
	return "admin"
}

func normalizeRegistrationEmail(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return "", validation("邮箱不能为空")
	}
	if len(normalized) > 254 {
		return "", validation("邮箱格式无效")
	}
	address, err := mail.ParseAddress(normalized)
	at := strings.LastIndexByte(normalized, '@')
	dot := strings.LastIndexByte(normalized, '.')
	if err != nil || !strings.EqualFold(address.Address, normalized) || at <= 0 || dot <= at+1 || dot == len(normalized)-1 {
		return "", validation("邮箱格式无效")
	}
	return normalized, nil
}

func randomRegistrationID() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func randomRegistrationCode() (string, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", value.Int64()), nil
}

func isRegistrationCode(code string) bool {
	if len(code) != registrationCodeDigits {
		return false
	}
	for _, char := range code {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func maskRegistrationEmail(email string) string {
	at := strings.IndexByte(email, '@')
	if at <= 0 {
		return "***"
	}
	visible := 2
	if at < visible {
		visible = at
	}
	return email[:visible] + "***" + email[at:]
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
