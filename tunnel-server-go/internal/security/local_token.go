// Package security implements the local admin JWT (HS256), OIDC RS256 validation, OIDC token
// exchange, and TLS certificate loading. The local token service mirrors the C#
// LocalTokenService: a hand-rolled HS256 JWT with iss=shuai-tunnel.
package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/config"
)

// Issuer is the JWT issuer claim for locally minted admin tokens.
const Issuer = "shuai-tunnel"

// TokenResponse is the JSON body returned to the SPA on login/refresh.
type TokenResponse struct {
	AccessToken string `json:"accessToken"`
	TokenType   string `json:"tokenType"`
	ExpiresIn   int64  `json:"expiresIn"`
}

// LocalTokenService issues and validates HS256 admin tokens and checks admin credentials.
type LocalTokenService struct {
	auth config.AuthConfig
	key  []byte
}

// NewLocalTokenService builds the service. The signing key is SHA-256(JwtSecret), or a random
// 32-byte key when no secret is configured (tokens then do not survive a restart).
func NewLocalTokenService(auth config.AuthConfig) *LocalTokenService {
	var key []byte
	if strings.TrimSpace(auth.JwtSecret) != "" {
		sum := sha256.Sum256([]byte(auth.JwtSecret))
		key = sum[:]
	} else {
		key = make([]byte, 32)
		_, _ = rand.Read(key)
	}
	return &LocalTokenService{auth: auth, key: key}
}

// TTLSeconds returns the token lifetime in seconds (floored at 60).
func (s *LocalTokenService) TTLSeconds() int64 {
	if s.auth.TokenTTLSeconds < 60 {
		return 60
	}
	return s.auth.TokenTTLSeconds
}

// PasswordLoginEnabled reports whether username/password login is available.
func (s *LocalTokenService) PasswordLoginEnabled() bool {
	return s.auth.PasswordLoginEnabled && s.auth.Password != ""
}

// Authenticate validates admin credentials in constant time.
func (s *LocalTokenService) Authenticate(username, password string) bool {
	if !s.PasswordLoginEnabled() {
		return false
	}
	userOK := subtle.ConstantTimeCompare(hash(s.auth.Username), hash(username)) == 1
	passOK := subtle.ConstantTimeCompare(hash(s.auth.Password), hash(password)) == 1
	return userOK && passOK
}

// IssueBody mints a token and wraps it in the API response body.
func (s *LocalTokenService) IssueBody(username string) TokenResponse {
	return TokenResponse{AccessToken: s.Issue(username), TokenType: "Bearer", ExpiresIn: s.TTLSeconds()}
}

// Issue mints a signed HS256 JWT for the given subject.
func (s *LocalTokenService) Issue(username string) string {
	now := time.Now()
	header := encodeSegment(map[string]any{"alg": "HS256", "typ": "JWT"})
	payload := encodeSegment(map[string]any{
		"iss": Issuer,
		"sub": username,
		"iat": now.Unix(),
		"exp": now.Add(time.Duration(s.TTLSeconds()) * time.Second).Unix(),
	})
	signingInput := header + "." + payload
	signature := base64URL(sign(s.key, signingInput))
	return signingInput + "." + signature
}

// Validate verifies a local token and returns the subject (username), or "" if invalid.
func (s *LocalTokenService) Validate(token string) (string, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	signingInput := parts[0] + "." + parts[1]
	expected := sign(s.key, signingInput)
	actual, err := decodeBase64URL(parts[2])
	if err != nil || subtle.ConstantTimeCompare(expected, actual) != 1 {
		return "", false
	}

	headerBytes, err := decodeBase64URL(parts[0])
	if err != nil {
		return "", false
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(headerBytes, &header) != nil || header.Alg != "HS256" {
		return "", false
	}

	payloadBytes, err := decodeBase64URL(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
	}
	if json.Unmarshal(payloadBytes, &claims) != nil {
		return "", false
	}
	if claims.Iss != Issuer || claims.Sub == "" {
		return "", false
	}
	if time.Now().Unix() >= claims.Exp {
		return "", false
	}
	return claims.Sub, true
}

func hash(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

func sign(key []byte, signingInput string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}

func encodeSegment(value map[string]any) string {
	data, _ := json.Marshal(value)
	return base64URL(data)
}

func base64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeBase64URL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}
