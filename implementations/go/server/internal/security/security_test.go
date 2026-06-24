package security

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/config"
)

func TestLocalTokenRoundTrip(t *testing.T) {
	svc := NewLocalTokenService(config.AuthConfig{
		PasswordLoginEnabled: true,
		Username:             "admin",
		Password:             "secret",
		JwtSecret:            "test-secret",
		TokenTTLSeconds:      3600,
	})
	if !svc.Authenticate("admin", "secret") {
		t.Fatal("valid credentials rejected")
	}
	if svc.Authenticate("admin", "wrong") {
		t.Fatal("invalid credentials accepted")
	}
	token := svc.Issue("admin")
	subject, ok := svc.Validate(token)
	if !ok || subject != "admin" {
		t.Fatalf("validate failed: subject=%q ok=%v", subject, ok)
	}
	if _, ok := svc.Validate(token + "tamper"); ok {
		t.Fatal("tampered token accepted")
	}
	if _, ok := svc.Validate("not.a.jwt"); ok {
		t.Fatal("garbage token accepted")
	}
}

func TestOidcExchange(t *testing.T) {
	var gotForm string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form.Encode()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "abc123",
			"id_token":     "id123",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer idp.Close()

	validator := NewOidcValidator(config.OidcConfig{
		ClientID:      "spa",
		TokenEndpoint: idp.URL,
		RedirectURI:   "http://127.0.0.1:8088/",
	})
	resp, err := validator.Exchange(context.Background(), ExchangeRequest{Code: "the-code", CodeVerifier: "verifier"})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.AccessToken != "abc123" || resp.IDToken != "id123" || resp.TokenType != "Bearer" {
		t.Fatalf("unexpected exchange response: %+v", resp)
	}
	if gotForm == "" || !strings.Contains(gotForm, "grant_type=authorization_code") || !strings.Contains(gotForm, "client_id=spa") {
		t.Fatalf("unexpected token-endpoint form: %q", gotForm)
	}
}

func TestOidcExchangeNotConfigured(t *testing.T) {
	validator := NewOidcValidator(config.OidcConfig{})
	if _, err := validator.Exchange(context.Background(), ExchangeRequest{Code: "x"}); err == nil {
		t.Fatal("expected error when OIDC is unconfigured")
	}
}

func TestLoadTLSConfig(t *testing.T) {
	if cfg, err := LoadTLSConfig(config.TLSConfig{Mode: "disabled"}); err != nil || cfg != nil {
		t.Fatalf("disabled should yield (nil, nil), got (%v, %v)", cfg, err)
	}
	cfg, err := LoadTLSConfig(config.TLSConfig{Mode: "self-signed"})
	if err != nil {
		t.Fatalf("self-signed: %v", err)
	}
	if cfg == nil || len(cfg.Certificates) != 1 {
		t.Fatalf("self-signed should yield one certificate")
	}
	if _, err := LoadTLSConfig(config.TLSConfig{Mode: "bogus"}); err == nil {
		t.Fatal("unknown mode should error")
	}
}
