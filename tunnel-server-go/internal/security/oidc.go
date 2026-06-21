package security

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/config"
)

// clockSkew is the allowed leeway when checking token exp/nbf.
const clockSkew = 60 * time.Second

// OidcValidator verifies RS256 access tokens against the IdP's JWKS, mirroring the C#
// OidcTokenValidator. JWKS keys are cached and force-refreshed on a signature miss.
type OidcValidator struct {
	cfg        config.OidcConfig
	httpClient *http.Client

	mu       sync.Mutex
	keys     map[string]*rsa.PublicKey
	fetched  time.Time
	cacheTTL time.Duration
}

// NewOidcValidator builds an OIDC validator.
func NewOidcValidator(cfg config.OidcConfig) *OidcValidator {
	return &OidcValidator{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		keys:       make(map[string]*rsa.PublicKey),
		cacheTTL:   5 * time.Minute,
	}
}

// Configured reports whether OIDC is usable (a JWKS URI is set).
func (v *OidcValidator) Configured() bool { return strings.TrimSpace(v.cfg.JwkSetURI) != "" }

// Validate verifies an RS256 token and returns the subject claim, or "" if invalid.
func (v *OidcValidator) Validate(ctx context.Context, token string) (string, bool) {
	if !v.Configured() {
		return "", false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	header, err := decodeJSONSegment(parts[0])
	if err != nil || header["alg"] != "RS256" {
		return "", false
	}
	kid, _ := header["kid"].(string)

	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", false
	}

	key := v.lookupKey(ctx, kid, false)
	if key == nil || !verifyRS256(key, signingInput, signature) {
		// Force-refresh once in case of key rotation.
		key = v.lookupKey(ctx, kid, true)
		if key == nil || !verifyRS256(key, signingInput, signature) {
			return "", false
		}
	}

	claims, err := decodeJSONSegment(parts[1])
	if err != nil {
		return "", false
	}
	if !v.validClaims(claims) {
		return "", false
	}
	return claimSubject(claims), true
}

func (v *OidcValidator) validClaims(claims map[string]any) bool {
	if iss, _ := claims["iss"].(string); strings.TrimSpace(v.cfg.Issuer) != "" && iss != v.cfg.Issuer {
		return false
	}
	if aud := strings.TrimSpace(v.cfg.Audience); aud != "" && !audienceContains(claims["aud"], aud) {
		return false
	}
	now := time.Now()
	if exp, ok := claims["exp"].(float64); ok {
		if now.After(time.Unix(int64(exp), 0).Add(clockSkew)) {
			return false
		}
	}
	if nbf, ok := claims["nbf"].(float64); ok {
		if now.Before(time.Unix(int64(nbf), 0).Add(-clockSkew)) {
			return false
		}
	}
	return true
}

func (v *OidcValidator) lookupKey(ctx context.Context, kid string, forceRefresh bool) *rsa.PublicKey {
	v.mu.Lock()
	stale := forceRefresh || time.Since(v.fetched) > v.cacheTTL || len(v.keys) == 0
	if !stale {
		key := v.keys[kid]
		v.mu.Unlock()
		return key
	}
	v.mu.Unlock()

	keys, err := v.fetchJWKS(ctx)
	if err != nil {
		return nil
	}
	v.mu.Lock()
	v.keys = keys
	v.fetched = time.Now()
	key := v.keys[kid]
	v.mu.Unlock()
	return key
}

func (v *OidcValidator) fetchJWKS(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JwkSetURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks status %d", resp.StatusCode)
	}
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(new(big.Int).SetBytes(eBytes).Int64())}
		keys[k.Kid] = key
	}
	return keys, nil
}

// ExchangeRequest carries the authorization-code exchange inputs.
type ExchangeRequest struct {
	Code         string
	RedirectURI  string
	CodeVerifier string
}

// ExchangeResponse is the token-exchange result returned to the SPA.
type ExchangeResponse struct {
	AccessToken string `json:"accessToken"`
	IDToken     string `json:"idToken,omitempty"`
	TokenType   string `json:"tokenType"`
	ExpiresIn   int64  `json:"expiresIn"`
}

// ErrOidcNotConfigured is returned when token exchange is attempted without configuration.
var ErrOidcNotConfigured = errors.New("OIDC 未配置")

// Exchange performs the OAuth2 authorization_code token exchange against the IdP. Confidential
// clients use HTTP Basic auth; public clients send client_id in the form. Mirrors the C#
// OidcTokenExchangeService.
func (v *OidcValidator) Exchange(ctx context.Context, request ExchangeRequest) (ExchangeResponse, error) {
	if strings.TrimSpace(v.cfg.ClientID) == "" || strings.TrimSpace(v.cfg.TokenEndpoint) == "" {
		return ExchangeResponse{}, ErrOidcNotConfigured
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", request.Code)
	redirect := request.RedirectURI
	if redirect == "" {
		redirect = v.cfg.RedirectURI
	}
	form.Set("redirect_uri", redirect)
	if request.CodeVerifier != "" {
		form.Set("code_verifier", request.CodeVerifier)
	}
	confidential := strings.TrimSpace(v.cfg.ClientSecret) != ""
	if !confidential {
		form.Set("client_id", v.cfg.ClientID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.cfg.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return ExchangeResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if confidential {
		req.SetBasicAuth(v.cfg.ClientID, v.cfg.ClientSecret)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return ExchangeResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ExchangeResponse{}, fmt.Errorf("token endpoint status %d", resp.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return ExchangeResponse{}, err
	}
	tokenType := body.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	return ExchangeResponse{
		AccessToken: body.AccessToken,
		IDToken:     body.IDToken,
		TokenType:   tokenType,
		ExpiresIn:   body.ExpiresIn,
	}, nil
}

func decodeJSONSegment(segment string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func audienceContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, entry := range v {
			if s, ok := entry.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func claimSubject(claims map[string]any) string {
	for _, key := range []string{"preferred_username", "name", "sub"} {
		if value, ok := claims[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}
