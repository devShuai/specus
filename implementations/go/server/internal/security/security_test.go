package security

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/config"
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

func TestOidcValidateIdentityReadsTenantClaim(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	const keyID = "test-key"
	jwks := oidcJWKS(key, keyID)
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jwks))
	}))
	defer idp.Close()

	now := time.Now()
	token := oidcRS256Token(t, key, keyID, map[string]any{
		"iss":                "https://issuer.example",
		"sub":                "subject-1",
		"preferred_username": "oidc-user@example.com",
		"aud":                []string{"admin-api"},
		"exp":                now.Add(10 * time.Minute).Unix(),
		"org_id":             "tenant-oidc",
	})
	validator := NewOidcValidator(config.OidcConfig{
		Issuer:      "https://issuer.example",
		Audience:    "admin-api",
		JwkSetURI:   idp.URL,
		TenantClaim: "org_id",
	})

	identity, ok := validator.ValidateIdentity(context.Background(), token)
	if !ok {
		t.Fatal("valid OIDC token was rejected")
	}
	if identity.Username != "oidc-user@example.com" {
		t.Fatalf("username = %q, want oidc-user@example.com", identity.Username)
	}
	if identity.TenantID != "tenant-oidc" {
		t.Fatalf("tenant = %q, want tenant-oidc", identity.TenantID)
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
	if _, err := LoadTLSConfig(config.TLSConfig{Mode: "file", Keystore: "missing-server.p12"}); err == nil {
		t.Fatal("missing PKCS12 keystore should error")
	}
	if _, err := LoadTLSConfig(config.TLSConfig{Mode: "bogus"}); err == nil {
		t.Fatal("unknown mode should error")
	}
}

func TestParsePKCS12PrivateKeySupportsECKeys(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	parsed, err := parsePKCS12PrivateKey(der)
	if err != nil {
		t.Fatalf("parse EC key: %v", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("parsed key type = %T, want *ecdsa.PrivateKey", parsed)
	}
}

func oidcRS256Token(t *testing.T, key *rsa.PrivateKey, keyID string, payload map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": keyID}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := encodedHeader + "." + encodedPayload
	sum := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func oidcJWKS(key *rsa.PrivateKey, keyID string) string {
	exponent := big.NewInt(int64(key.PublicKey.E)).Bytes()
	body, _ := json.Marshal(map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": keyID,
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(exponent),
		}},
	})
	return string(body)
}
