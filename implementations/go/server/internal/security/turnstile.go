package security

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
)

const (
	TurnstileActionLogin    = "login"
	TurnstileActionRegister = "register"
)

var (
	ErrTurnstileRejected    = errors.New("turnstile rejected")
	ErrTurnstileUnavailable = errors.New("turnstile unavailable")
)

type TurnstileVerifier struct {
	config config.TurnstileConfig
	client *http.Client
}

func NewTurnstileVerifier(cfg config.TurnstileConfig) *TurnstileVerifier {
	return &TurnstileVerifier{
		config: cfg,
		client: &http.Client{Timeout: 8 * time.Second},
	}
}

func (v *TurnstileVerifier) Enabled() bool { return v != nil && v.config.Enabled }

func (v *TurnstileVerifier) Configured() bool {
	if v == nil {
		return false
	}
	if !v.config.Enabled {
		return true
	}
	return strings.TrimSpace(v.config.SiteKey) != "" && strings.TrimSpace(v.config.SecretKey) != "" &&
		strings.TrimSpace(v.config.VerifyURL) != "" && hasTurnstileHostname(v.config.AllowedHostnames)
}

func (v *TurnstileVerifier) SiteKey() string {
	if v == nil {
		return ""
	}
	return v.config.SiteKey
}

func (v *TurnstileVerifier) Verify(ctx context.Context, responseToken, expectedAction string) error {
	if v == nil || !v.config.Enabled {
		return nil
	}
	if !v.Configured() {
		return ErrTurnstileUnavailable
	}
	if strings.TrimSpace(responseToken) == "" {
		return ErrTurnstileRejected
	}
	form := url.Values{}
	form.Set("secret", v.config.SecretKey)
	form.Set("response", strings.TrimSpace(responseToken))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.config.VerifyURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return ErrTurnstileUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return ErrTurnstileUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return ErrTurnstileUnavailable
	}
	var result struct {
		Success  bool     `json:"success"`
		Action   string   `json:"action"`
		Hostname string   `json:"hostname"`
		Errors   []string `json:"error-codes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ErrTurnstileUnavailable
	}
	if !result.Success || result.Action != expectedAction ||
		!turnstileHostnameAllowed(result.Hostname, v.config.AllowedHostnames) {
		return ErrTurnstileRejected
	}
	return nil
}

func hasTurnstileHostname(hostnames []string) bool {
	for _, hostname := range hostnames {
		if strings.TrimSpace(hostname) != "" {
			return true
		}
	}
	return false
}

func turnstileHostnameAllowed(hostname string, allowed []string) bool {
	hostname = normalizeTurnstileHostname(hostname)
	for _, candidate := range allowed {
		if hostname != "" && hostname == normalizeTurnstileHostname(candidate) {
			return true
		}
	}
	return false
}

func normalizeTurnstileHostname(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}
