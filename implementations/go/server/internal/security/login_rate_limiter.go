package security

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
)

// maxTrackedLoginKeys bounds the counter tables so abnormal traffic cannot exhaust memory.
const maxTrackedLoginKeys = 100_000

// LoginRateLimitedMessage is returned for every throttled attempt. Both dimensions share one
// message so the response never reveals whether the account exists.
const LoginRateLimitedMessage = "登录尝试过于频繁,请稍后再试"

// LoginRateLimiter bounds login attempts per source IP and per target account using fixed windows.
// It is independent of the captcha, so deployments running without Turnstile are still protected
// against credential stuffing.
type LoginRateLimiter struct {
	cfg    config.LoginRateLimitConfig
	logger *slog.Logger

	mu       sync.Mutex
	ips      map[string]*loginWindow
	accounts map[string]*loginWindow
}

type loginWindow struct {
	startUnix int64
	count     int
}

func NewLoginRateLimiter(cfg config.LoginRateLimitConfig, logger *slog.Logger) *LoginRateLimiter {
	if logger == nil {
		logger = slog.Default()
	}
	return &LoginRateLimiter{
		cfg:      cfg,
		logger:   logger,
		ips:      make(map[string]*loginWindow),
		accounts: make(map[string]*loginWindow),
	}
}

// Allow records one attempt and reports whether it may proceed. When it returns false the caller
// must answer 429 with the returned Retry-After duration.
func (l *LoginRateLimiter) Allow(clientIP, username string) (bool, time.Duration) {
	if l == nil || !l.cfg.Enabled {
		return true, 0
	}
	window := l.cfg.WindowSeconds
	if window < 1 {
		window = 1
	}
	now := time.Now().Unix()

	l.mu.Lock()
	defer l.mu.Unlock()
	l.purgeLocked(now, window)
	// Count both dimensions before deciding so an exceeded dimension cannot mask the other.
	ipWindow := l.recordLocked(l.ips, loginIPKey(clientIP), now, window)
	accountWindow := l.recordLocked(l.accounts, loginAccountKey(username), now, window)

	ipExceeded := ipWindow.count > positiveLimit(l.cfg.PerIP)
	accountExceeded := accountWindow.count > positiveLimit(l.cfg.PerAccount)
	if !ipExceeded && !accountExceeded {
		return true, 0
	}
	blocking := ipWindow
	dimension := "ip"
	if !ipExceeded {
		blocking, dimension = accountWindow, "account"
	}
	retryAfter := time.Duration(window-(now-blocking.startUnix)) * time.Second
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	l.logger.Warn("login attempt rate limited",
		"ip", loginIPKey(clientIP), "dimension", dimension, "retryAfterSeconds", int64(retryAfter.Seconds()))
	return false, retryAfter
}

// RecordSuccess clears the account budget after a successful login. The source IP budget is kept so
// cracking one account does not unlock the whole source.
func (l *LoginRateLimiter) RecordSuccess(username string) {
	if l == nil || !l.cfg.Enabled {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.accounts, loginAccountKey(username))
}

func (l *LoginRateLimiter) recordLocked(windows map[string]*loginWindow, key string, now, window int64) *loginWindow {
	existing, ok := windows[key]
	if !ok {
		if len(windows) >= maxTrackedLoginKeys {
			// Table is full and this is a new source: treat as exceeded rather than growing.
			return &loginWindow{startUnix: now, count: int(^uint(0) >> 1)}
		}
		created := &loginWindow{startUnix: now, count: 1}
		windows[key] = created
		return created
	}
	if now-existing.startUnix >= window {
		existing.startUnix = now
		existing.count = 1
		return existing
	}
	existing.count++
	return existing
}

func (l *LoginRateLimiter) purgeLocked(now, window int64) {
	for key, value := range l.ips {
		if now-value.startUnix >= window {
			delete(l.ips, key)
		}
	}
	for key, value := range l.accounts {
		if now-value.startUnix >= window {
			delete(l.accounts, key)
		}
	}
}

func positiveLimit(value int) int {
	if value < 1 {
		return 1
	}
	return value
}

func loginIPKey(clientIP string) string {
	trimmed := strings.TrimSpace(clientIP)
	if trimmed == "" {
		return "unknown"
	}
	return trimmed
}

func loginAccountKey(username string) string {
	trimmed := strings.ToLower(strings.TrimSpace(username))
	if trimmed == "" {
		return "unknown"
	}
	return trimmed
}
