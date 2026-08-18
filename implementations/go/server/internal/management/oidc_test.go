package management

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestOIDCCodeExchangeMintsLocalTokenAndBindsIdentity(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "oidc-api-key"
	var tokenForm url.Values
	preferredUsername := "certus-user"
	var idp *httptest.Server
	idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			writeManagementJWKS(w, key, kid)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		tokenForm = r.Form
		idToken := signManagementOIDCToken(t, key, kid, map[string]any{
			"iss": idp.URL, "sub": "immutable-subject", "preferred_username": preferredUsername,
			"aud": "specus-admin", "exp": time.Now().Add(5 * time.Minute).Unix(), "nonce": "browser-nonce",
		})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "upstream-access", "id_token": idToken,
			"token_type": "Bearer", "expires_in": 60,
		})
	}))
	defer idp.Close()

	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "oidc.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	authCfg := config.AuthConfig{Username: "admin", TenantID: "default", JwtSecret: "local-secret", TokenTTLSeconds: 3600}
	oidcCfg := config.OidcConfig{
		Issuer: idp.URL, JwkSetURI: idp.URL + "/jwks", TokenEndpoint: idp.URL + "/token",
		ClientID: "specus-admin", RedirectURI: "https://specus.example/callback", TenantClaim: "tenant_id",
	}
	tokens := security.NewLocalTokenService(authCfg)
	api := NewAPI(db, session.NewRegistry(), tokens, security.NewOidcValidator(oidcCfg), nil, nil,
		oidcCfg, authCfg, config.ClientAuthConfig{}, config.TrafficConfig{}, nil, nil, nil, nil, nil, nil, nil)
	mux := http.NewServeMux()
	api.Register(mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	body := []byte(`{"code":"authorization-code","codeVerifier":"pkce-verifier","nonce":"browser-nonce","redirectUri":"https://evil.example/"}`)
	response, err := http.Post(server.URL+"/oidc/token", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	var result struct {
		AccessToken string `json:"accessToken"`
		IDToken     string `json:"idToken"`
		ExpiresIn   int64  `json:"expiresIn"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	claims, ok := tokens.ValidateClaims(result.AccessToken)
	if !ok || claims.Username != "certus-user" || claims.Role != store.ManagementRoleUser || result.IDToken == "" {
		t.Fatalf("local exchange result invalid: result=%+v claims=%+v ok=%t", result, claims, ok)
	}
	if result.ExpiresIn != tokens.TTLSeconds() || tokenForm.Get("redirect_uri") != oidcCfg.RedirectURI ||
		tokenForm.Get("redirect_uri") == "https://evil.example/" || tokenForm.Get("code_verifier") != "pkce-verifier" {
		t.Fatalf("token exchange did not use canonical server inputs: form=%v result=%+v", tokenForm, result)
	}
	user, err := db.FindManagementUserByUsername(context.Background(), "certus-user")
	if err != nil || user == nil || user.OIDCIssuer != idp.URL || user.OIDCSubject != "immutable-subject" ||
		user.OIDCIdentityKey == "" || user.Role != store.ManagementRoleUser {
		t.Fatalf("OIDC identity was not bound as least privilege: user=%+v err=%v", user, err)
	}

	// Refresh must use the current database authorization, not the stale role/tenant in the JWT.
	user.Role = store.ManagementRoleAdmin
	user.TenantID = "tenant-updated"
	user.UpdatedAt = time.Now()
	if err := db.DeleteManagementUser(context.Background(), user.Username); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertManagementUser(context.Background(), *user); err != nil {
		t.Fatal(err)
	}
	currentRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/api/admin/me", nil)
	currentRequest.Header.Set("Authorization", "Bearer "+result.AccessToken)
	currentResponse, err := http.DefaultClient.Do(currentRequest)
	if err != nil {
		t.Fatal(err)
	}
	var currentMe ManagementUserView
	if err := json.NewDecoder(currentResponse.Body).Decode(&currentMe); err != nil {
		currentResponse.Body.Close()
		t.Fatal(err)
	}
	currentResponse.Body.Close()
	if currentResponse.StatusCode != http.StatusOK || !currentMe.Admin ||
		currentMe.Role != store.ManagementRoleAdmin || currentMe.TenantID != "tenant-updated" {
		t.Fatalf("request did not use current DB authorization: status=%d me=%+v",
			currentResponse.StatusCode, currentMe)
	}
	refresh, _ := http.NewRequest(http.MethodPost, server.URL+"/auth/refresh", nil)
	refresh.Header.Set("Authorization", "Bearer "+result.AccessToken)
	refreshResponse, err := http.DefaultClient.Do(refresh)
	if err != nil {
		t.Fatal(err)
	}
	defer refreshResponse.Body.Close()
	var refreshed security.TokenResponse
	if err := json.NewDecoder(refreshResponse.Body).Decode(&refreshed); err != nil {
		t.Fatal(err)
	}
	refreshedClaims, ok := tokens.ValidateClaims(refreshed.AccessToken)
	if refreshResponse.StatusCode != http.StatusOK || !ok || refreshedClaims.Role != store.ManagementRoleAdmin ||
		refreshedClaims.TenantID != "tenant-updated" {
		t.Fatalf("refresh did not use current DB authorization: status=%d claims=%+v ok=%t",
			refreshResponse.StatusCode, refreshedClaims, ok)
	}

	// A token minted while the user was ADMIN must immediately observe demotion and tenant change.
	user.Role = store.ManagementRoleUser
	user.TenantID = "tenant-demoted"
	user.UpdatedAt = time.Now()
	if err := db.DeleteManagementUser(context.Background(), user.Username); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertManagementUser(context.Background(), *user); err != nil {
		t.Fatal(err)
	}
	demotedRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/api/admin/me", nil)
	demotedRequest.Header.Set("Authorization", "Bearer "+refreshed.AccessToken)
	demotedResponse, err := http.DefaultClient.Do(demotedRequest)
	if err != nil {
		t.Fatal(err)
	}
	var demotedMe ManagementUserView
	if err := json.NewDecoder(demotedResponse.Body).Decode(&demotedMe); err != nil {
		demotedResponse.Body.Close()
		t.Fatal(err)
	}
	demotedResponse.Body.Close()
	if demotedResponse.StatusCode != http.StatusOK || demotedMe.Admin ||
		demotedMe.Role != store.ManagementRoleUser || demotedMe.TenantID != "tenant-demoted" {
		t.Fatalf("stale ADMIN token ignored DB demotion: status=%d me=%+v",
			demotedResponse.StatusCode, demotedMe)
	}

	user.Enabled = false
	user.UpdatedAt = time.Now()
	if err := db.UpdateManagementUser(context.Background(), *user); err != nil {
		t.Fatal(err)
	}
	disabledRefresh, _ := http.NewRequest(http.MethodPost, server.URL+"/auth/refresh", nil)
	disabledRefresh.Header.Set("Authorization", "Bearer "+result.AccessToken)
	disabledResponse, err := http.DefaultClient.Do(disabledRefresh)
	if err != nil {
		t.Fatal(err)
	}
	defer disabledResponse.Body.Close()
	if disabledResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled-user refresh status = %d, want 401", disabledResponse.StatusCode)
	}
	disabledRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/api/admin/me", nil)
	disabledRequest.Header.Set("Authorization", "Bearer "+refreshed.AccessToken)
	disabledMeResponse, err := http.DefaultClient.Do(disabledRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer disabledMeResponse.Body.Close()
	if disabledMeResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled-user management request status = %d, want 401", disabledMeResponse.StatusCode)
	}

	// An external preferred_username can never select the built-in administrator.
	preferredUsername = "AdMiN"
	adminResponse, err := http.Post(server.URL+"/oidc/token", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer adminResponse.Body.Close()
	if adminResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("OIDC built-in admin mapping status = %d, want 403", adminResponse.StatusCode)
	}
}

func TestOIDCDirectBearerRequiresBoundEnabledUserAndUsesCurrentAuthorization(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "direct-key"
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeManagementJWKS(w, key, kid)
	}))
	defer idp.Close()
	oidcCfg := config.OidcConfig{Issuer: idp.URL, JwkSetURI: idp.URL, Audience: "admin-api", TenantClaim: "org"}
	authCfg := config.AuthConfig{Username: "admin", TenantID: "default", JwtSecret: "local-secret", TokenTTLSeconds: 3600}
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "direct.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	api := NewAPI(db, session.NewRegistry(), security.NewLocalTokenService(authCfg),
		security.NewOidcValidator(oidcCfg), nil, nil, oidcCfg, authCfg, config.ClientAuthConfig{},
		config.TrafficConfig{}, nil, nil, nil, nil, nil, nil, nil)
	mux := http.NewServeMux()
	api.Register(mux)
	server := httptest.NewServer(mux)
	defer server.Close()
	token := signManagementOIDCToken(t, key, kid, map[string]any{
		"iss": idp.URL, "sub": "subject-admin", "preferred_username": "display-name",
		"role": "ADMIN", "org": "tenant-a", "aud": "admin-api", "exp": time.Now().Add(time.Minute).Unix(),
	})

	// A valid upstream JWT is insufficient until issuer+sub is explicitly bound locally.
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/api/admin/me", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unbound direct bearer status = %d, want 401", response.StatusCode)
	}

	now := time.Now()
	identityKey := auth.HashPassword(idp.URL + "\x00" + "subject-admin")
	if err := db.InsertManagementUser(context.Background(), store.ManagementUser{
		Username: "local-user", TenantID: "tenant-db", PasswordHash: auth.HashPassword(auth.GeneratePassword()),
		OIDCIssuer: idp.URL, OIDCSubject: "subject-admin", OIDCIdentityKey: identityKey,
		Role: store.ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/admin/me", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var me ManagementUserView
	_ = json.NewDecoder(response.Body).Decode(&me)
	if response.StatusCode != http.StatusOK || me.Username != "local-user" || me.Admin ||
		me.Role != store.ManagementRoleUser || me.TenantID != "tenant-db" {
		t.Fatalf("direct bearer principal mismatch: status=%d me=%+v", response.StatusCode, me)
	}

	refresh, _ := http.NewRequest(http.MethodPost, server.URL+"/auth/refresh", nil)
	refresh.Header.Set("Authorization", "Bearer "+token)
	refreshResponse, err := http.DefaultClient.Do(refresh)
	if err != nil {
		t.Fatal(err)
	}
	defer refreshResponse.Body.Close()
	if refreshResponse.StatusCode != http.StatusBadRequest {
		t.Fatalf("OIDC refresh status = %d, want 400", refreshResponse.StatusCode)
	}
	bound, err := db.FindManagementUserByUsername(context.Background(), "local-user")
	if err != nil || bound == nil {
		t.Fatalf("find bound user: user=%+v err=%v", bound, err)
	}
	bound.Enabled = false
	bound.UpdatedAt = time.Now()
	if err := db.UpdateManagementUser(context.Background(), *bound); err != nil {
		t.Fatal(err)
	}
	disabledRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/api/admin/me", nil)
	disabledRequest.Header.Set("Authorization", "Bearer "+token)
	disabledResponse, err := http.DefaultClient.Do(disabledRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer disabledResponse.Body.Close()
	if disabledResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled direct bearer status = %d, want 401", disabledResponse.StatusCode)
	}
}

func signManagementOIDCToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	payload, _ := json.Marshal(claims)
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	input := encodedHeader + "." + encodedPayload
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func writeManagementJWKS(w http.ResponseWriter, key *rsa.PrivateKey, kid string) {
	exponent := big.NewInt(int64(key.PublicKey.E)).Bytes()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": kid, "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(exponent),
	}}})
}
