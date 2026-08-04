package security

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
)

const (
	// clockSkew is the allowed leeway when checking token exp/nbf.
	clockSkew = 60 * time.Second
	// A JWKS is configuration data, not an unbounded download. One MiB leaves ample room for
	// normal rotation sets while preventing a compromised endpoint from exhausting memory.
	maxJWKSResponseBytes = 1 << 20
	maxNegativeKids      = 4096
	maxOIDCKeyIDBytes    = 256
	jwksRefreshTimeout   = 10 * time.Second
	jwksOverlapTTL       = 5 * time.Minute
)

// OidcValidator verifies RS256 access tokens against the IdP's JWKS, mirroring the C#
// OidcTokenValidator. JWKS keys are cached and force-refreshed on a signature miss.
type OidcValidator struct {
	cfg        config.OidcConfig
	httpClient *http.Client

	mu       sync.Mutex
	keys     oidcKeySet
	fetched  time.Time
	cacheTTL time.Duration

	// overlapKeys retains only the immediately previous JWKS generation, and only for a
	// fixed window. Re-fetching the same current generation must not extend this deadline.
	overlapKeys    oidcKeySet
	overlapExpires time.Time
	overlapTTL     time.Duration

	refreshDone     chan struct{}
	lastRefresh     time.Time
	refreshCooldown time.Duration
	refreshTimeout  time.Duration
	negativeKids    map[string]time.Time
	negativeTTL     time.Duration
}

// oidcKeySet preserves duplicate and absent key IDs so missing-kid selection matches Nimbus:
// a missing header kid considers every key, while a present kid (including "") matches exactly.
type oidcKeySet struct {
	byID      map[string][]*rsa.PublicKey
	anonymous []*rsa.PublicKey
	all       []*rsa.PublicKey
}

func newOIDCKeySet() oidcKeySet {
	return oidcKeySet{byID: make(map[string][]*rsa.PublicKey)}
}

func (s *oidcKeySet) addNamed(kid string, key *rsa.PublicKey) {
	s.byID[kid] = append(s.byID[kid], key)
	s.all = append(s.all, key)
}

func (s *oidcKeySet) addAnonymous(key *rsa.PublicKey) {
	s.anonymous = append(s.anonymous, key)
	s.all = append(s.all, key)
}

// OidcIdentity is the normalized identity extracted from a verified OIDC token.
type OidcIdentity struct {
	// Username is deliberately the immutable JWT subject.  The Java resource-server
	// path uses Jwt.getSubject() for authorization; preferred_username is only used
	// when an authorization-code login is linked to a local management user.
	Username          string
	Subject           string
	PreferredUsername string
	Issuer            string
	TenantID          string
	Role              string
	Nonce             string
}

// NewOidcValidator builds an OIDC validator.
func NewOidcValidator(cfg config.OidcConfig) *OidcValidator {
	return &OidcValidator{
		cfg:             cfg,
		httpClient:      &http.Client{Timeout: 10 * time.Second},
		keys:            newOIDCKeySet(),
		cacheTTL:        5 * time.Minute,
		overlapKeys:     newOIDCKeySet(),
		overlapTTL:      jwksOverlapTTL,
		refreshCooldown: 10 * time.Second,
		refreshTimeout:  jwksRefreshTimeout,
		negativeKids:    make(map[string]time.Time),
		negativeTTL:     30 * time.Second,
	}
}

// Configured reports whether OIDC is usable (a JWKS URI is set).
func (v *OidcValidator) Configured() bool { return strings.TrimSpace(v.cfg.JwkSetURI) != "" }

// Validate verifies an RS256 token and returns the subject claim, or "" if invalid.
func (v *OidcValidator) Validate(ctx context.Context, token string) (string, bool) {
	identity, ok := v.ValidateIdentity(ctx, token)
	if !ok {
		return "", false
	}
	return identity.Username, true
}

// ValidateIdentity verifies an RS256 token and returns the normalized username and tenant claim.
func (v *OidcValidator) ValidateIdentity(ctx context.Context, token string) (OidcIdentity, bool) {
	if strings.TrimSpace(v.cfg.Issuer) == "" || strings.TrimSpace(v.cfg.Audience) == "" {
		return OidcIdentity{}, false
	}
	// Match Java's StringUtils.hasText gate followed by validators built with the original
	// configuration value: surrounding whitespace makes a value present, but is significant.
	return v.validateIdentity(ctx, token, v.cfg.Audience, "", false, false)
}

// ValidateIDToken verifies the ID token returned by the authorization-code flow.  In addition
// to the resource-token checks it binds the response to the browser nonce and always requires the
// OIDC client id as the ID-token audience. Multi-audience ID tokens must also carry a matching azp.
func (v *OidcValidator) ValidateIDToken(ctx context.Context, token, expectedNonce string) (OidcIdentity, bool) {
	if strings.TrimSpace(v.cfg.Issuer) == "" || strings.TrimSpace(v.cfg.ClientID) == "" {
		return OidcIdentity{}, false
	}
	return v.validateIdentity(ctx, token, v.cfg.ClientID, expectedNonce, true, true)
}

func (v *OidcValidator) validateIdentity(ctx context.Context, token, expectedAudience, expectedNonce string,
	requireNonce, requireAuthorizedParty bool) (OidcIdentity, bool) {
	if !v.Configured() {
		return OidcIdentity{}, false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return OidcIdentity{}, false
	}
	header, err := decodeJSONSegment(parts[0])
	if err != nil || header["alg"] != "RS256" {
		return OidcIdentity{}, false
	}
	kid := ""
	kidPresent := false
	if rawKid, present := header["kid"]; present && rawKid != nil {
		var ok bool
		kid, ok = rawKid.(string)
		if !ok {
			return OidcIdentity{}, false
		}
		kidPresent = true
	}

	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return OidcIdentity{}, false
	}

	keys := v.lookupKeys(ctx, kid, kidPresent, false)
	if !verifyRS256Candidates(keys, signingInput, signature) {
		// Force-refresh once in case of key rotation.
		keys = v.lookupKeys(ctx, kid, kidPresent, true)
		if !verifyRS256Candidates(keys, signingInput, signature) {
			return OidcIdentity{}, false
		}
	}

	claims, err := decodeJSONSegment(parts[1])
	if err != nil {
		return OidcIdentity{}, false
	}
	if !v.validClaims(claims, expectedAudience, requireAuthorizedParty) {
		return OidcIdentity{}, false
	}
	subject := claimAsString(claims, "sub")
	issuer := claimAsString(claims, "iss")
	if subject == "" || issuer == "" {
		return OidcIdentity{}, false
	}
	// nonce is an opaque browser binding value. Keep the signed claim and request bytes intact;
	// trimming either side would accept a value that Java's exact comparison rejects.
	nonce := claimAsRawString(claims, "nonce")
	if requireNonce && !constantTimeStringEqual(expectedNonce, nonce) {
		return OidcIdentity{}, false
	}
	return OidcIdentity{
		Username:          subject,
		Subject:           subject,
		PreferredUsername: claimAsString(claims, "preferred_username"),
		Issuer:            issuer,
		TenantID:          claimAsString(claims, tenantClaimName(v.cfg.TenantClaim)),
		Role:              claimAsString(claims, "role"),
		Nonce:             nonce,
	}, true
}

func (v *OidcValidator) validClaims(claims map[string]any, expectedAudience string,
	requireAuthorizedParty bool) bool {
	if strings.TrimSpace(v.cfg.Issuer) == "" {
		return false
	}
	if iss, _ := claims["iss"].(string); iss != v.cfg.Issuer {
		return false
	}
	if strings.TrimSpace(expectedAudience) == "" || !audienceContains(claims["aud"], expectedAudience) {
		return false
	}
	if requireAuthorizedParty {
		// Java treats a missing, empty, or whitespace-only azp as absent for a single-audience
		// ID token. If azp has text, or if aud has multiple entries, comparison stays exact.
		azp := claimAsRawString(claims, "azp")
		multipleAudiences := audienceCount(claims["aud"]) > 1
		if (multipleAudiences && azp != expectedAudience) ||
			(strings.TrimSpace(azp) != "" && azp != expectedAudience) {
			return false
		}
	}
	now := time.Now()
	exp, ok := claims["exp"].(float64)
	if !ok || now.After(time.Unix(int64(exp), 0).Add(clockSkew)) {
		return false
	}
	if nbf, ok := claims["nbf"].(float64); ok {
		if now.Before(time.Unix(int64(nbf), 0).Add(-clockSkew)) {
			return false
		}
	}
	return true
}

func (v *OidcValidator) lookupKey(ctx context.Context, kid string, forceRefresh bool) *rsa.PublicKey {
	keys := v.lookupKeys(ctx, kid, true, forceRefresh)
	if len(keys) == 0 {
		return nil
	}
	return keys[0]
}

func (v *OidcValidator) lookupKeys(ctx context.Context, kid string, kidPresent, forceRefresh bool) []*rsa.PublicKey {
	// A missing kid intentionally selects every already-filtered RSA/RS256 signing key, matching
	// Nimbus JWKMatcher.forJWSHeader. A present kid (including "") remains an exact match.
	if kidPresent && len(kid) > maxOIDCKeyIDBytes {
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		now := time.Now()
		v.mu.Lock()
		v.pruneOverlapLocked(now)
		keys := v.keyCandidatesLocked(kid, kidPresent)
		stale := v.fetched.IsZero() || now.Sub(v.fetched) > v.cacheTTL || len(v.keys.all) == 0
		if expires, found := v.negativeKids[kid]; kidPresent && found {
			if len(keys) == 0 && now.Before(expires) && !stale {
				v.mu.Unlock()
				return nil
			}
			delete(v.negativeKids, kid)
		}
		if !forceRefresh && !stale {
			v.mu.Unlock()
			return keys
		}
		if v.refreshDone != nil {
			done := v.refreshDone
			v.mu.Unlock()
			if !waitForJWKSRefresh(ctx, done) {
				return nil
			}
			// Consume the completed shared refresh instead of starting a second one.
			forceRefresh = false
			continue
		}
		if !v.lastRefresh.IsZero() && now.Sub(v.lastRefresh) < v.refreshCooldown {
			if kidPresent && len(keys) == 0 {
				v.cacheNegativeKidLocked(kid, now)
			}
			v.mu.Unlock()
			return keys
		}
		done := make(chan struct{})
		v.refreshDone = done
		v.mu.Unlock()

		// The shared refresh has a server-owned bounded lifetime. The request that happened to
		// win singleflight may disconnect without cancelling the refresh for every other waiter.
		go v.refreshJWKS(done, kid, kidPresent)
		if !waitForJWKSRefresh(ctx, done) {
			return nil
		}
		forceRefresh = false
	}
}

func waitForJWKSRefresh(ctx context.Context, done <-chan struct{}) bool {
	select {
	case <-ctx.Done():
		return false
	case <-done:
		return true
	}
}

func (v *OidcValidator) refreshJWKS(done chan struct{}, requestedKid string, requestedKidPresent bool) {
	timeout := v.refreshTimeout
	if timeout <= 0 {
		timeout = jwksRefreshTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	keys, err := v.fetchJWKS(ctx)
	cancel()
	completed := time.Now()

	v.mu.Lock()
	defer v.mu.Unlock()
	// lastRefresh is deliberately the completion time: a slow IdP request must receive a full
	// cooldown after it finishes, while a cancelled HTTP caller cannot poison this timestamp.
	v.lastRefresh = completed
	if err == nil {
		v.installJWKSLocked(keys, completed)
		v.fetched = completed
		v.negativeKids = make(map[string]time.Time)
	}
	v.pruneOverlapLocked(completed)
	if requestedKidPresent && len(v.keyCandidatesLocked(requestedKid, true)) == 0 {
		v.cacheNegativeKidLocked(requestedKid, completed)
	}
	if v.refreshDone == done {
		v.refreshDone = nil
	}
	close(done)
}

func (v *OidcValidator) installJWKSLocked(keys oidcKeySet, now time.Time) {
	v.pruneOverlapLocked(now)
	if oidcKeySetsEqual(v.keys, keys) {
		// A cache revalidation is not a new generation. Keep the original overlap deadline so
		// unknown-kid traffic cannot keep retired signing keys alive indefinitely.
		v.keys = keys
		return
	}
	previous := previousOIDCKeyGeneration(v.keys, keys)
	v.keys = keys
	v.overlapKeys = previous
	if len(previous.all) == 0 || v.overlapTTL <= 0 {
		v.overlapKeys = newOIDCKeySet()
		v.overlapExpires = time.Time{}
		return
	}
	v.overlapExpires = now.Add(v.overlapTTL)
}

func (v *OidcValidator) keyCandidatesLocked(kid string, kidPresent bool) []*rsa.PublicKey {
	if kidPresent {
		if keys := v.keys.byID[kid]; len(keys) > 0 {
			return append([]*rsa.PublicKey(nil), keys...)
		}
		return append([]*rsa.PublicKey(nil), v.overlapKeys.byID[kid]...)
	}
	keys := make([]*rsa.PublicKey, 0, len(v.keys.all)+len(v.overlapKeys.all))
	// Current keys are always attempted before the bounded previous generation.
	keys = append(keys, v.keys.all...)
	keys = append(keys, v.overlapKeys.all...)
	return keys
}

func verifyRS256Candidates(keys []*rsa.PublicKey, signingInput string, signature []byte) bool {
	for _, key := range keys {
		if verifyRS256(key, signingInput, signature) {
			return true
		}
	}
	return false
}

func (v *OidcValidator) pruneOverlapLocked(now time.Time) {
	if v.overlapExpires.IsZero() || now.Before(v.overlapExpires) {
		return
	}
	v.overlapKeys = newOIDCKeySet()
	v.overlapExpires = time.Time{}
}

func oidcKeySetsEqual(left, right oidcKeySet) bool {
	if len(left.all) != len(right.all) {
		return false
	}
	leftCounts := oidcKeyFingerprintCounts(left)
	for fingerprint, count := range oidcKeyFingerprintCounts(right) {
		if leftCounts[fingerprint] != count {
			return false
		}
	}
	return true
}

func previousOIDCKeyGeneration(current, next oidcKeySet) oidcKeySet {
	previous := newOIDCKeySet()
	for kid, keys := range current.byID {
		if _, stillCurrent := next.byID[kid]; stillCurrent {
			continue
		}
		for _, key := range keys {
			previous.addNamed(kid, key)
		}
	}
	nextAnonymous := make(map[string]int)
	for _, key := range next.anonymous {
		nextAnonymous[rsaKeyFingerprint(key)]++
	}
	for _, key := range current.anonymous {
		fingerprint := rsaKeyFingerprint(key)
		if nextAnonymous[fingerprint] > 0 {
			nextAnonymous[fingerprint]--
			continue
		}
		previous.addAnonymous(key)
	}
	return previous
}

func oidcKeyFingerprintCounts(keys oidcKeySet) map[string]int {
	counts := make(map[string]int, len(keys.all))
	for kid, candidates := range keys.byID {
		for _, key := range candidates {
			counts[fmt.Sprintf("named:%d:%s:%s", len(kid), kid, rsaKeyFingerprint(key))]++
		}
	}
	for _, key := range keys.anonymous {
		counts["anonymous:"+rsaKeyFingerprint(key)]++
	}
	return counts
}

func rsaKeyFingerprint(key *rsa.PublicKey) string {
	if key == nil || key.N == nil {
		return "nil"
	}
	return fmt.Sprintf("%x:%d", key.N.Bytes(), key.E)
}

func (v *OidcValidator) cacheNegativeKidLocked(kid string, now time.Time) {
	if len(v.negativeKids) >= maxNegativeKids {
		for cachedKid, expires := range v.negativeKids {
			if !now.Before(expires) {
				delete(v.negativeKids, cachedKid)
			}
		}
		if len(v.negativeKids) >= maxNegativeKids {
			return
		}
	}
	v.negativeKids[kid] = now.Add(v.negativeTTL)
}

func (v *OidcValidator) fetchJWKS(ctx context.Context) (oidcKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JwkSetURI, nil)
	if err != nil {
		return oidcKeySet{}, err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return oidcKeySet{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return oidcKeySet{}, fmt.Errorf("jwks status %d", resp.StatusCode)
	}
	if resp.ContentLength > maxJWKSResponseBytes {
		return oidcKeySet{}, errors.New("jwks response exceeds size limit")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSResponseBytes+1))
	if err != nil {
		return oidcKeySet{}, err
	}
	if len(body) > maxJWKSResponseBytes {
		return oidcKeySet{}, errors.New("jwks response exceeds size limit")
	}
	var jwks struct {
		Keys []struct {
			Kty string  `json:"kty"`
			Kid *string `json:"kid"`
			Alg string  `json:"alg"`
			Use string  `json:"use"`
			N   string  `json:"n"`
			E   string  `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return oidcKeySet{}, err
	}
	keys := newOIDCKeySet()
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" ||
			(k.Alg != "" && k.Alg != "RS256") || (k.Use != "" && k.Use != "sig") {
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
		modulus := new(big.Int).SetBytes(nBytes)
		exponent := new(big.Int).SetBytes(eBytes)
		if modulus.BitLen() < 2048 || !exponent.IsInt64() {
			continue
		}
		e := exponent.Int64()
		if e < 3 || e%2 == 0 || int64(int(e)) != e {
			continue
		}
		key := &rsa.PublicKey{N: modulus, E: int(e)}
		if k.Kid == nil {
			keys.addAnonymous(key)
		} else {
			keys.addNamed(*k.Kid, key)
		}
	}
	if len(keys.all) == 0 {
		return oidcKeySet{}, errors.New("jwks contains no usable signing keys")
	}
	return keys, nil
}

// ExchangeRequest carries the authorization-code exchange inputs.
type ExchangeRequest struct {
	Code         string
	CodeVerifier string
	Nonce        string
}

// ExchangeResponse is the token-exchange result returned to the SPA.
type ExchangeResponse struct {
	AccessToken string       `json:"accessToken"`
	IDToken     string       `json:"idToken,omitempty"`
	TokenType   string       `json:"tokenType"`
	ExpiresIn   int64        `json:"expiresIn"`
	Identity    OidcIdentity `json:"-"`
}

// ErrOidcNotConfigured is returned when token exchange is attempted without configuration.
var ErrOidcNotConfigured = errors.New("OIDC 未配置")

// ErrOidcInvalidExchange is returned for malformed inputs or an unverifiable ID token.
var ErrOidcInvalidExchange = errors.New("OIDC 授权响应无效")

// Exchange performs the OAuth2 authorization_code token exchange against the IdP. Confidential
// clients use HTTP Basic auth; public clients send client_id in the form. Mirrors the C#
// OidcTokenExchangeService.
func (v *OidcValidator) Exchange(ctx context.Context, request ExchangeRequest) (ExchangeResponse, error) {
	if strings.TrimSpace(v.cfg.ClientID) == "" || strings.TrimSpace(v.cfg.TokenEndpoint) == "" {
		return ExchangeResponse{}, ErrOidcNotConfigured
	}
	if strings.TrimSpace(request.Code) == "" || strings.TrimSpace(request.CodeVerifier) == "" ||
		strings.TrimSpace(request.Nonce) == "" || strings.TrimSpace(v.cfg.RedirectURI) == "" {
		return ExchangeResponse{}, ErrOidcInvalidExchange
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", request.Code)
	form.Set("redirect_uri", v.cfg.RedirectURI)
	form.Set("code_verifier", request.CodeVerifier)
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
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
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
	if strings.TrimSpace(body.IDToken) == "" {
		return ExchangeResponse{}, ErrOidcInvalidExchange
	}
	identity, ok := v.ValidateIDToken(ctx, body.IDToken, request.Nonce)
	if !ok {
		return ExchangeResponse{}, ErrOidcInvalidExchange
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
		Identity:    identity,
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

func audienceCount(aud any) int {
	switch v := aud.(type) {
	case string:
		if v != "" {
			return 1
		}
	case []any:
		count := 0
		for _, entry := range v {
			if value, ok := entry.(string); ok && value != "" {
				count++
			}
		}
		return count
	}
	return 0
}

func tenantClaimName(value string) string {
	if normalized := strings.TrimSpace(value); normalized != "" {
		return normalized
	}
	return "tenant_id"
}

func constantTimeStringEqual(expected, actual string) bool {
	if expected == "" || actual == "" || len(expected) != len(actual) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func claimAsString(claims map[string]any, key string) string {
	return strings.TrimSpace(claimAsRawString(claims, key))
}

func claimAsRawString(claims map[string]any, key string) string {
	value, ok := claims[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case float64, bool:
		return fmt.Sprint(typed)
	default:
		return ""
	}
}
