package security

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
)

func TestTurnstileVerifierValidatesActionAndHostname(t *testing.T) {
	var received url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse siteverify form: %v", err)
		}
		received = r.Form
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"action":"login","hostname":"specus.example.com"}`))
	}))
	defer server.Close()

	verifier := NewTurnstileVerifier(config.TurnstileConfig{
		Enabled: true, SiteKey: "site", SecretKey: "secret", VerifyURL: server.URL,
		AllowedHostnames: []string{"specus.example.com"},
	})
	if err := verifier.Verify(context.Background(), "browser-token", TurnstileActionLogin); err != nil {
		t.Fatalf("verify valid response: %v", err)
	}
	if received.Get("secret") != "secret" || received.Get("response") != "browser-token" {
		t.Fatalf("unexpected siteverify form: %v", received)
	}
	if err := verifier.Verify(context.Background(), "browser-token", TurnstileActionRegister); !errors.Is(err, ErrTurnstileRejected) {
		t.Fatalf("action mismatch error = %v, want rejected", err)
	}
}

func TestTurnstileVerifierRejectsUnexpectedHostname(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"action":"login","hostname":"attacker.example"}`))
	}))
	defer server.Close()
	verifier := NewTurnstileVerifier(config.TurnstileConfig{
		Enabled: true, SiteKey: "site", SecretKey: "secret", VerifyURL: server.URL,
		AllowedHostnames: []string{"specus.example.com"},
	})
	if err := verifier.Verify(context.Background(), "token", TurnstileActionLogin); !errors.Is(err, ErrTurnstileRejected) {
		t.Fatalf("error = %v, want rejected", err)
	}
}

func TestTurnstileVerifierFailsClosedWhenEnabledButIncomplete(t *testing.T) {
	verifier := NewTurnstileVerifier(config.TurnstileConfig{Enabled: true})
	if err := verifier.Verify(context.Background(), "token", TurnstileActionLogin); !errors.Is(err, ErrTurnstileUnavailable) {
		t.Fatalf("error = %v, want unavailable", err)
	}
}
