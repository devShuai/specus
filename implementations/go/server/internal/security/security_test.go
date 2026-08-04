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
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
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
	userClaims, ok := svc.ValidateClaims(svc.IssueForUser("admin", "default", "USER"))
	if !ok || userClaims.Role != "USER" {
		t.Fatalf("username must not upgrade a token role: claims=%+v ok=%t", userClaims, ok)
	}
}

func TestOidcExchange(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	const keyID = "exchange-key"
	var gotForm string
	var idp *httptest.Server
	idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(oidcJWKS(key, keyID)))
			return
		}
		_ = r.ParseForm()
		gotForm = r.Form.Encode()
		idToken := oidcRS256Token(t, key, keyID, map[string]any{
			"iss": idp.URL, "sub": "subject-1", "preferred_username": "oidc-user",
			"aud": "spa", "exp": time.Now().Add(time.Minute).Unix(), "nonce": "nonce-1",
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "abc123",
			"id_token":     idToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer idp.Close()

	validator := NewOidcValidator(config.OidcConfig{
		ClientID:      "spa",
		TokenEndpoint: idp.URL,
		JwkSetURI:     idp.URL + "/jwks",
		Issuer:        idp.URL,
		RedirectURI:   "http://127.0.0.1:8088/",
	})
	resp, err := validator.Exchange(context.Background(), ExchangeRequest{
		Code: "the-code", CodeVerifier: "verifier", Nonce: "nonce-1",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.AccessToken != "abc123" || resp.IDToken == "" || resp.TokenType != "Bearer" ||
		resp.Identity.Subject != "subject-1" || resp.Identity.PreferredUsername != "oidc-user" {
		t.Fatalf("unexpected exchange response: %+v", resp)
	}
	if gotForm == "" || !strings.Contains(gotForm, "grant_type=authorization_code") ||
		!strings.Contains(gotForm, "client_id=spa") || !strings.Contains(gotForm, "code_verifier=verifier") ||
		!strings.Contains(gotForm, "redirect_uri=http%3A%2F%2F127.0.0.1%3A8088%2F") {
		t.Fatalf("unexpected token-endpoint form: %q", gotForm)
	}
	if _, err := validator.Exchange(context.Background(), ExchangeRequest{
		Code: "the-code", CodeVerifier: "verifier", Nonce: "different-browser-nonce",
	}); !errors.Is(err, ErrOidcInvalidExchange) {
		t.Fatalf("nonce mismatch error = %v, want ErrOidcInvalidExchange", err)
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
	if identity.Username != "subject-1" || identity.PreferredUsername != "oidc-user@example.com" {
		t.Fatalf("identity = %+v, want subject and preferred username preserved separately", identity)
	}
	if identity.TenantID != "tenant-oidc" {
		t.Fatalf("tenant = %q, want tenant-oidc", identity.TenantID)
	}
	paddedIssuer := oidcRS256Token(t, key, keyID, map[string]any{
		"iss": " https://issuer.example ", "sub": "subject-1", "aud": "admin-api",
		"exp": now.Add(10 * time.Minute).Unix(),
	})
	if _, ok := validator.ValidateIdentity(context.Background(), paddedIssuer); ok {
		t.Fatal("issuer was accepted after whitespace normalization")
	}
	paddedSubject := oidcRS256Token(t, key, keyID, map[string]any{
		"iss": "https://issuer.example", "sub": " subject-1 ", "aud": "admin-api",
		"exp": now.Add(10 * time.Minute).Unix(),
	})
	if normalized, ok := validator.ValidateIdentity(context.Background(), paddedSubject); !ok ||
		normalized.Subject != "subject-1" {
		t.Fatalf("subject normalization differs from Java binding service: identity=%+v ok=%t", normalized, ok)
	}
	withoutAudience := NewOidcValidator(config.OidcConfig{
		Issuer: "https://issuer.example", JwkSetURI: idp.URL,
	})
	if _, ok := withoutAudience.ValidateIdentity(context.Background(), token); ok {
		t.Fatal("direct OIDC bearer was accepted without a configured audience")
	}
	blankIssuer := NewOidcValidator(config.OidcConfig{
		Issuer: " \t ", Audience: "admin-api", JwkSetURI: idp.URL,
	})
	if _, ok := blankIssuer.ValidateIdentity(context.Background(), token); ok {
		t.Fatal("direct OIDC bearer was accepted with a blank issuer configuration")
	}
	blankAudience := NewOidcValidator(config.OidcConfig{
		Issuer: "https://issuer.example", Audience: " \t ", JwkSetURI: idp.URL,
	})
	if _, ok := blankAudience.ValidateIdentity(context.Background(), token); ok {
		t.Fatal("direct OIDC bearer was accepted with a blank audience configuration")
	}

	// Java uses hasText only as a configuration gate. The configured issuer and audience are
	// then passed to validators unchanged, so whitespace is significant rather than normalized.
	paddedIssuerConfig := NewOidcValidator(config.OidcConfig{
		Issuer: " https://issuer.example ", Audience: "admin-api", JwkSetURI: idp.URL,
	})
	if _, ok := paddedIssuerConfig.ValidateIdentity(context.Background(), token); ok {
		t.Fatal("token matched an issuer configuration after trimming the configuration")
	}
	paddedAudienceConfig := NewOidcValidator(config.OidcConfig{
		Issuer: "https://issuer.example", Audience: " admin-api ", JwkSetURI: idp.URL,
	})
	if _, ok := paddedAudienceConfig.ValidateIdentity(context.Background(), token); ok {
		t.Fatal("token matched an audience configuration after trimming the configuration")
	}
	exactPaddedConfigToken := oidcRS256Token(t, key, keyID, map[string]any{
		"iss": " https://issuer.example ", "sub": "subject-1", "aud": " admin-api ",
		"exp": now.Add(10 * time.Minute).Unix(),
	})
	exactPaddedConfig := NewOidcValidator(config.OidcConfig{
		Issuer: " https://issuer.example ", Audience: " admin-api ", JwkSetURI: idp.URL,
	})
	if _, ok := exactPaddedConfig.ValidateIdentity(context.Background(), exactPaddedConfigToken); !ok {
		t.Fatal("token did not match the exact non-blank issuer and audience configuration values")
	}
}

func TestOidcMissingKidTriesAllCandidatesButEmptyKidMatchesExactly(t *testing.T) {
	firstKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"iss": "https://issuer.example", "sub": "subject", "aud": "admin-api",
		"exp": time.Now().Add(time.Minute).Unix(),
	}
	keyedIDP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(oidcJWKSSet(
			oidcTestJWK{key: firstKey, keyID: "first", includeKeyID: true},
			oidcTestJWK{key: secondKey, keyID: "second", includeKeyID: true},
		)))
	}))
	defer keyedIDP.Close()
	keyedValidator := NewOidcValidator(config.OidcConfig{
		Issuer: "https://issuer.example", Audience: "admin-api", JwkSetURI: keyedIDP.URL,
	})
	if _, ok := keyedValidator.ValidateIdentity(context.Background(),
		oidcRS256TokenWithoutKid(t, secondKey, claims)); !ok {
		t.Fatal("token without kid did not try every matching JWKS key")
	}
	if _, ok := keyedValidator.ValidateIdentity(context.Background(),
		oidcRS256Token(t, secondKey, "", claims)); ok {
		t.Fatal("present empty kid incorrectly selected non-empty key IDs")
	}

	anonymousIDP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(oidcJWKSSet(oidcTestJWK{key: secondKey})))
	}))
	defer anonymousIDP.Close()
	anonymousValidator := NewOidcValidator(config.OidcConfig{
		Issuer: "https://issuer.example", Audience: "admin-api", JwkSetURI: anonymousIDP.URL,
	})
	if _, ok := anonymousValidator.ValidateIdentity(context.Background(),
		oidcRS256TokenWithoutKid(t, secondKey, claims)); !ok {
		t.Fatal("missing header kid did not select an anonymous JWKS key")
	}
	if _, ok := anonymousValidator.ValidateIdentity(context.Background(),
		oidcRS256Token(t, secondKey, "", claims)); ok {
		t.Fatal("present empty kid incorrectly matched an absent JWKS kid")
	}

	emptyIDP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(oidcJWKSSet(oidcTestJWK{key: secondKey, includeKeyID: true})))
	}))
	defer emptyIDP.Close()
	emptyValidator := NewOidcValidator(config.OidcConfig{
		Issuer: "https://issuer.example", Audience: "admin-api", JwkSetURI: emptyIDP.URL,
	})
	if _, ok := emptyValidator.ValidateIdentity(context.Background(),
		oidcRS256Token(t, secondKey, "", claims)); !ok {
		t.Fatal("present empty kid did not match an explicit empty JWKS kid")
	}
}

func TestOidcIDTokenRequiresClientAudienceAndAuthorizedParty(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "id-token-key"
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(oidcJWKS(key, keyID)))
	}))
	defer idp.Close()
	validator := NewOidcValidator(config.OidcConfig{
		Issuer: "https://issuer.example", ClientID: "spa-client", Audience: "resource-api", JwkSetURI: idp.URL,
	})
	claims := map[string]any{
		"iss": "https://issuer.example", "sub": "subject", "aud": []string{"spa-client", "other-client"},
		"nonce": "browser-nonce", "exp": time.Now().Add(time.Minute).Unix(),
	}
	if _, ok := validator.ValidateIDToken(context.Background(), oidcRS256Token(t, key, keyID, claims),
		"browser-nonce"); ok {
		t.Fatal("multi-audience ID token without azp was accepted")
	}
	claims["azp"] = "wrong-client"
	if _, ok := validator.ValidateIDToken(context.Background(), oidcRS256Token(t, key, keyID, claims),
		"browser-nonce"); ok {
		t.Fatal("ID token with mismatched azp was accepted")
	}
	claims["azp"] = "spa-client"
	if _, ok := validator.ValidateIDToken(context.Background(), oidcRS256Token(t, key, keyID, claims),
		"browser-nonce"); !ok {
		t.Fatal("ID token with client_id audience and matching azp was rejected")
	}
	claims["azp"] = " spa-client "
	if _, ok := validator.ValidateIDToken(context.Background(), oidcRS256Token(t, key, keyID, claims),
		"browser-nonce"); ok {
		t.Fatal("ID token with whitespace-padded azp was accepted")
	}
	claims["azp"] = "spa-client"
	claims["nonce"] = " browser-nonce "
	if _, ok := validator.ValidateIDToken(context.Background(), oidcRS256Token(t, key, keyID, claims),
		"browser-nonce"); ok {
		t.Fatal("ID token nonce was accepted after trimming the signed claim")
	}
	claims["nonce"] = "browser-nonce"
	if _, ok := validator.ValidateIDToken(context.Background(), oidcRS256Token(t, key, keyID, claims),
		" browser-nonce "); ok {
		t.Fatal("ID token nonce was accepted after trimming the browser value")
	}

	claims["aud"] = "spa-client"
	delete(claims, "azp")
	if _, ok := validator.ValidateIDToken(context.Background(), oidcRS256Token(t, key, keyID, claims),
		"browser-nonce"); !ok {
		t.Fatal("single-audience ID token without azp was rejected")
	}
	claims["azp"] = ""
	if _, ok := validator.ValidateIDToken(context.Background(), oidcRS256Token(t, key, keyID, claims),
		"browser-nonce"); !ok {
		t.Fatal("single-audience ID token with empty azp was rejected")
	}
	claims["azp"] = " \t "
	if _, ok := validator.ValidateIDToken(context.Background(), oidcRS256Token(t, key, keyID, claims),
		"browser-nonce"); !ok {
		t.Fatal("single-audience ID token with blank azp differed from Java")
	}
	claims["azp"] = " spa-client "
	if _, ok := validator.ValidateIDToken(context.Background(), oidcRS256Token(t, key, keyID, claims),
		"browser-nonce"); ok {
		t.Fatal("single-audience ID token matched a non-blank azp after trimming")
	}

	paddedClientIDValidator := NewOidcValidator(config.OidcConfig{
		Issuer: "https://issuer.example", ClientID: " spa-client ", JwkSetURI: idp.URL,
	})
	delete(claims, "azp")
	claims["aud"] = "spa-client"
	if _, ok := paddedClientIDValidator.ValidateIDToken(context.Background(),
		oidcRS256Token(t, key, keyID, claims), "browser-nonce"); ok {
		t.Fatal("ID token matched a clientId configuration after trimming the configuration")
	}
	claims["aud"] = " spa-client "
	claims["azp"] = " spa-client "
	if _, ok := paddedClientIDValidator.ValidateIDToken(context.Background(),
		oidcRS256Token(t, key, keyID, claims), "browser-nonce"); !ok {
		t.Fatal("ID token did not match the exact non-blank clientId configuration value")
	}
	blankClientIDValidator := NewOidcValidator(config.OidcConfig{
		Issuer: "https://issuer.example", ClientID: " \t ", JwkSetURI: idp.URL,
	})
	if _, ok := blankClientIDValidator.ValidateIDToken(context.Background(),
		oidcRS256Token(t, key, keyID, claims), "browser-nonce"); ok {
		t.Fatal("ID token was accepted with a blank clientId configuration")
	}

	claims["aud"] = "resource-api"
	delete(claims, "azp")
	if _, ok := validator.ValidateIDToken(context.Background(), oidcRS256Token(t, key, keyID, claims),
		"browser-nonce"); ok {
		t.Fatal("ID token used resource audience in place of client_id")
	}
}

func TestOidcJWKSRefreshIsSharedAndUnknownKidsAreNegativelyCached(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "shared-key"
	var requests atomic.Int32
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		time.Sleep(25 * time.Millisecond)
		_, _ = w.Write([]byte(oidcJWKS(key, keyID)))
	}))
	defer idp.Close()
	validator := NewOidcValidator(config.OidcConfig{
		Issuer: "https://issuer.example", Audience: "admin-api", JwkSetURI: idp.URL,
	})
	validator.refreshCooldown = 0
	validator.cacheTTL = time.Hour
	claims := map[string]any{
		"iss": "https://issuer.example", "sub": "subject", "aud": "admin-api",
		"exp": time.Now().Add(time.Minute).Unix(),
	}
	token := oidcRS256Token(t, key, keyID, claims)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, ok := validator.ValidateIdentity(context.Background(), token); !ok {
				t.Errorf("valid token rejected during shared refresh")
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := requests.Load(); got != 1 {
		t.Fatalf("concurrent JWKS requests = %d, want 1", got)
	}
	unknown := oidcRS256Token(t, key, "unknown-kid", claims)
	for range 3 {
		if _, ok := validator.ValidateIdentity(context.Background(), unknown); ok {
			t.Fatal("unknown kid token was accepted")
		}
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("JWKS requests after repeated unknown kid = %d, want 2", got)
	}
}

func TestOidcJWKSRefreshOutlivesTriggeringRequestCancellation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "shared-after-cancel"
	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce sync.Once
	var requests atomic.Int32
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		startedOnce.Do(func() { close(started) })
		<-release
		_, _ = w.Write([]byte(oidcJWKS(key, keyID)))
	}))
	defer idp.Close()

	validator := NewOidcValidator(config.OidcConfig{
		Issuer: "https://issuer.example", Audience: "admin-api", JwkSetURI: idp.URL,
	})
	claims := map[string]any{
		"iss": "https://issuer.example", "sub": "subject", "aud": "admin-api",
		"exp": time.Now().Add(time.Minute).Unix(),
	}
	token := oidcRS256Token(t, key, keyID, claims)
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstResult := make(chan bool, 1)
	go func() {
		_, ok := validator.ValidateIdentity(firstCtx, token)
		firstResult <- ok
	}()
	<-started
	cancelFirst()
	if ok := <-firstResult; ok {
		t.Fatal("cancelled triggering request unexpectedly authenticated")
	}

	secondResult := make(chan bool, 1)
	go func() {
		_, ok := validator.ValidateIdentity(context.Background(), token)
		secondResult <- ok
	}()
	releasedAt := time.Now()
	close(release)
	select {
	case ok := <-secondResult:
		if !ok {
			t.Fatal("shared JWKS refresh was cancelled with its triggering request")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent JWKS waiter did not resume")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("JWKS requests = %d, want one shared refresh", got)
	}
	validator.mu.Lock()
	lastRefresh := validator.lastRefresh
	validator.mu.Unlock()
	if lastRefresh.Before(releasedAt) {
		t.Fatalf("lastRefresh = %s, want completion time after %s", lastRefresh, releasedAt)
	}
}

func TestOidcJWKSRetainsOnlyOnePreviousGenerationForFixedOverlap(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const oldKid = "retiring-key"
	const newKid = "current-key"
	var activeMu sync.RWMutex
	activeKey := oldKey
	activeKid := oldKid
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		activeMu.RLock()
		key, kid := activeKey, activeKid
		activeMu.RUnlock()
		_, _ = w.Write([]byte(oidcJWKS(key, kid)))
	}))
	defer idp.Close()

	validator := NewOidcValidator(config.OidcConfig{
		Issuer: "https://issuer.example", Audience: "admin-api", JwkSetURI: idp.URL,
	})
	validator.refreshCooldown = 0
	validator.cacheTTL = time.Hour
	validator.overlapTTL = 5 * time.Minute
	claims := map[string]any{
		"iss": "https://issuer.example", "sub": "subject", "aud": "admin-api",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	oldToken := oidcRS256Token(t, oldKey, oldKid, claims)
	newToken := oidcRS256Token(t, newKey, newKid, claims)
	if _, ok := validator.ValidateIdentity(context.Background(), oldToken); !ok {
		t.Fatal("initial signing key was rejected")
	}
	activeMu.Lock()
	activeKey, activeKid = newKey, newKid
	activeMu.Unlock()
	if _, ok := validator.ValidateIdentity(context.Background(), newToken); !ok {
		t.Fatal("rotated signing key was rejected")
	}
	if _, ok := validator.ValidateIdentity(context.Background(), oldToken); !ok {
		t.Fatal("previous signing key was not retained during overlap")
	}

	validator.mu.Lock()
	originalExpiry := validator.overlapExpires
	_, retained := validator.overlapKeys.byID[oldKid]
	validator.mu.Unlock()
	if !retained || originalExpiry.IsZero() {
		t.Fatal("previous generation was not installed with an overlap deadline")
	}
	unknownToken := oidcRS256Token(t, newKey, "unknown-key", claims)
	if _, ok := validator.ValidateIdentity(context.Background(), unknownToken); ok {
		t.Fatal("unknown kid token was accepted")
	}
	validator.mu.Lock()
	refetchedExpiry := validator.overlapExpires
	validator.mu.Unlock()
	if !refetchedExpiry.Equal(originalExpiry) {
		t.Fatalf("same-generation refresh extended overlap from %s to %s", originalExpiry, refetchedExpiry)
	}

	validator.mu.Lock()
	validator.overlapExpires = time.Now().Add(-time.Second)
	validator.mu.Unlock()
	if _, ok := validator.ValidateIdentity(context.Background(), oldToken); ok {
		t.Fatal("expired previous signing key remained accepted")
	}
}

func TestOidcJWKSResponseSizeIsCapped(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxJWKSResponseBytes+1)))
	}))
	defer idp.Close()
	validator := NewOidcValidator(config.OidcConfig{JwkSetURI: idp.URL})
	if _, err := validator.fetchJWKS(context.Background()); err == nil {
		t.Fatal("oversized JWKS response was accepted")
	}
}

func TestOidcUnknownKidCacheIsBoundedAndPrunesExpiredEntries(t *testing.T) {
	validator := NewOidcValidator(config.OidcConfig{})
	now := time.Now()
	if key := validator.lookupKey(context.Background(), strings.Repeat("x", maxOIDCKeyIDBytes+1), true); key != nil {
		t.Fatal("oversized kid unexpectedly resolved a key")
	}
	if got := len(validator.negativeKids); got != 0 {
		t.Fatalf("oversized kid entered negative cache: size=%d", got)
	}
	for i := range maxNegativeKids + 128 {
		validator.cacheNegativeKidLocked(fmt.Sprintf("kid-%d", i), now)
	}
	if got := len(validator.negativeKids); got != maxNegativeKids {
		t.Fatalf("negative kid cache size = %d, want %d", got, maxNegativeKids)
	}
	validator.negativeKids["kid-0"] = now.Add(-time.Second)
	validator.cacheNegativeKidLocked("replacement-kid", now)
	if _, ok := validator.negativeKids["kid-0"]; ok {
		t.Fatal("expired negative kid entry was not pruned")
	}
	if _, ok := validator.negativeKids["replacement-kid"]; !ok {
		t.Fatal("new negative kid was not cached after expired-entry pruning")
	}
	if got := len(validator.negativeKids); got > maxNegativeKids {
		t.Fatalf("negative kid cache exceeded cap: %d", got)
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

func TestTLSDeploymentGateMatchesJava(t *testing.T) {
	if err := ValidateTLSDeployment(config.TLSConfig{Mode: "disabled", RequireEncryption: true},
		"0.0.0.0", "127.0.0.1:8088"); err == nil {
		t.Fatal("public plaintext control bind should be rejected")
	}
	if err := ValidateTLSDeployment(config.TLSConfig{
		Mode: "disabled", RequireEncryption: true, TerminatedUpstream: true,
	}, "0.0.0.0", "127.0.0.1:8088"); err == nil {
		t.Fatal("upstream termination must not permit a wildcard plaintext backend")
	}
	if err := ValidateTLSDeployment(config.TLSConfig{
		Mode: "disabled", RequireEncryption: true, TerminatedUpstream: true,
	}, "127.0.0.1", "127.0.0.1:8088"); err != nil {
		t.Fatalf("private upstream-terminated backend rejected: %v", err)
	}
	if err := ValidateTLSDeployment(config.TLSConfig{
		Mode: "disabled", RequireEncryption: true, TerminatedUpstream: true,
	}, "127.0.0.1", ":8088"); err == nil {
		t.Fatal("upstream termination must not permit a wildcard management backend")
	}
	if err := ValidateTLSDeployment(config.TLSConfig{
		Mode: "self-signed", RequireEncryption: true,
	}, "127.0.0.1", "127.0.0.1:8088"); err == nil {
		t.Fatal("production self-signed TLS should be rejected")
	}
	if err := ValidateTLSDeployment(config.TLSConfig{Mode: "file", RequireEncryption: true},
		"0.0.0.0", ":8088"); err != nil {
		t.Fatalf("file TLS should satisfy production gate: %v", err)
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
	return oidcRS256TokenWithKid(t, key, keyID, true, payload)
}

func oidcRS256TokenWithoutKid(t *testing.T, key *rsa.PrivateKey, payload map[string]any) string {
	t.Helper()
	return oidcRS256TokenWithKid(t, key, "", false, payload)
}

func oidcRS256TokenWithKid(t *testing.T, key *rsa.PrivateKey, keyID string, includeKid bool,
	payload map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	if includeKid {
		header["kid"] = keyID
	}
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
	return oidcJWKSSet(oidcTestJWK{key: key, keyID: keyID, includeKeyID: true})
}

type oidcTestJWK struct {
	key          *rsa.PrivateKey
	keyID        string
	includeKeyID bool
}

func oidcJWKSSet(keys ...oidcTestJWK) string {
	items := make([]map[string]any, 0, len(keys))
	for _, item := range keys {
		exponent := big.NewInt(int64(item.key.PublicKey.E)).Bytes()
		jwk := map[string]any{
			"kty": "RSA",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(item.key.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(exponent),
		}
		if item.includeKeyID {
			jwk["kid"] = item.keyID
		}
		items = append(items, jwk)
	}
	body, _ := json.Marshal(map[string]any{
		"keys": items,
	})
	return string(body)
}
