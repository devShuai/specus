package security

import (
	"fmt"
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
)

func loginLimiter(perIP, perAccount int) *LoginRateLimiter {
	return NewLoginRateLimiter(config.LoginRateLimitConfig{
		Enabled:       true,
		PerIP:         perIP,
		PerAccount:    perAccount,
		WindowSeconds: 300,
	}, nil)
}

func TestLoginRateLimiterBlocksPerSourceIPAcrossAccounts(t *testing.T) {
	limiter := loginLimiter(3, 100)
	for attempt := 1; attempt <= 3; attempt++ {
		if allowed, _ := limiter.Allow("203.0.113.10", fmt.Sprintf("user-%d", attempt)); !allowed {
			t.Fatalf("attempt %d should be allowed", attempt)
		}
	}
	allowed, retryAfter := limiter.Allow("203.0.113.10", "user-4")
	if allowed {
		t.Fatal("fourth attempt from the same IP should be rate limited")
	}
	if retryAfter <= 0 {
		t.Fatalf("retryAfter = %v, want positive", retryAfter)
	}
	if other, _ := limiter.Allow("203.0.113.11", "user-4"); !other {
		t.Fatal("a different source IP must not inherit another IP's budget")
	}
}

func TestLoginRateLimiterBlocksPerAccountAcrossRotatingIPs(t *testing.T) {
	limiter := loginLimiter(100, 3)
	for attempt := 1; attempt <= 3; attempt++ {
		if allowed, _ := limiter.Allow(fmt.Sprintf("203.0.113.%d", attempt), "victim"); !allowed {
			t.Fatalf("attempt %d should be allowed", attempt)
		}
	}
	if allowed, _ := limiter.Allow("203.0.113.99", "victim"); allowed {
		t.Fatal("account budget must apply across rotating source IPs")
	}
	// Account keys are case-insensitive so casing cannot reset the budget.
	if allowed, _ := limiter.Allow("203.0.113.98", "VICTIM"); allowed {
		t.Fatal("account budget must be case-insensitive")
	}
	if allowed, _ := limiter.Allow("203.0.113.97", "other-account"); !allowed {
		t.Fatal("a different account must not inherit the blocked account's budget")
	}
}

func TestLoginRateLimiterDoesNotRevealAccountExistence(t *testing.T) {
	limiter := loginLimiter(1, 100)
	limiter.Allow("203.0.113.10", "known-account")

	knownAllowed, knownRetry := limiter.Allow("203.0.113.10", "known-account")
	unknownAllowed, unknownRetry := limiter.Allow("203.0.113.10", "does-not-exist")
	if knownAllowed || unknownAllowed {
		t.Fatal("both attempts should be rate limited")
	}
	if knownRetry <= 0 || unknownRetry <= 0 {
		t.Fatalf("retryAfter must be positive: known=%v unknown=%v", knownRetry, unknownRetry)
	}
}

func TestLoginRateLimiterSuccessClearsAccountButKeepsIPBudget(t *testing.T) {
	limiter := loginLimiter(3, 2)
	limiter.Allow("203.0.113.10", "alice")
	limiter.Allow("203.0.113.10", "alice")
	limiter.RecordSuccess("alice")

	if allowed, _ := limiter.Allow("203.0.113.10", "alice"); !allowed {
		t.Fatal("account budget should reset after a successful login")
	}
	if allowed, _ := limiter.Allow("203.0.113.10", "bob"); allowed {
		t.Fatal("source IP budget must survive a successful login")
	}
}

func TestLoginRateLimiterDisabledSkipsThrottling(t *testing.T) {
	limiter := NewLoginRateLimiter(config.LoginRateLimitConfig{
		Enabled: false, PerIP: 1, PerAccount: 1, WindowSeconds: 300,
	}, nil)
	for attempt := 0; attempt < 10; attempt++ {
		if allowed, _ := limiter.Allow("203.0.113.10", "alice"); !allowed {
			t.Fatalf("attempt %d should be allowed while disabled", attempt)
		}
	}
}
