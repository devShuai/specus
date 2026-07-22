package peermesh

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/config"
)

type turnCredential struct {
	Username   string
	Credential string
	Realm      string
	Nonce      string
	ExpiresAt  time.Time
}

type turnCredentialService struct {
	cfg           config.PeerMeshConfig
	runtimeSecret []byte
	nonce         string
}

func newTurnCredentialService(cfg config.PeerMeshConfig) *turnCredentialService {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	nonceBytes := make([]byte, 18)
	_, _ = rand.Read(nonceBytes)
	return &turnCredentialService{
		cfg:           cfg,
		runtimeSecret: secret,
		nonce:         base64.RawURLEncoding.EncodeToString(nonceBytes),
	}
}

func (s *turnCredentialService) authRequired() bool { return s != nil && s.cfg.TurnAuthRequired }

func (s *turnCredentialService) realm() string {
	if s == nil || strings.TrimSpace(s.cfg.TurnRealm) == "" {
		return "shuai-tunnel"
	}
	return strings.TrimSpace(s.cfg.TurnRealm)
}

func (s *turnCredentialService) issue(subject string) turnCredential {
	ttl := s.cfg.TurnCredentialTTLSeconds
	if ttl < 60 {
		ttl = 60
	}
	expires := time.Now().Add(time.Duration(ttl) * time.Second)
	safeSubject := sanitizeTurnSubject(subject)
	randomBytes := make([]byte, 4)
	_, _ = rand.Read(randomBytes)
	username := strconv.FormatInt(expires.Unix(), 10) + ":" + safeSubject + ":" + hex.EncodeToString(randomBytes)
	return turnCredential{
		Username:   username,
		Credential: s.credentialForUsername(username),
		Realm:      s.realm(),
		Nonce:      s.nonce,
		ExpiresAt:  expires,
	}
}

func (s *turnCredentialService) credentialForUsername(username string) string {
	mac := hmac.New(sha1.New, s.secret())
	_, _ = mac.Write([]byte(username))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *turnCredentialService) usernameCredentialValid(username, credential string) bool {
	username = strings.TrimSpace(username)
	credential = strings.TrimSpace(credential)
	if username == "" || credential == "" {
		return false
	}
	prefix := username
	if index := strings.IndexByte(prefix, ':'); index >= 0 {
		prefix = prefix[:index]
	}
	expires, err := strconv.ParseInt(strings.TrimSpace(prefix), 10, 64)
	if err != nil {
		return false
	}
	now := time.Now().Unix()
	maxTTL := s.cfg.TurnCredentialTTLSeconds
	if maxTTL < 60 {
		maxTTL = 60
	}
	if expires <= now || expires-now > maxTTL+60 {
		return false
	}
	expected := []byte(s.credentialForUsername(username))
	actual := []byte(credential)
	return len(expected) == len(actual) && subtle.ConstantTimeCompare(expected, actual) == 1
}

func (s *turnCredentialService) longTermKey(username, credential string) []byte {
	digest := md5.Sum([]byte(username + ":" + s.realm() + ":" + credential))
	return digest[:]
}

// generalRelaySubjectPrefix marks credentials issued for public transfer (browser WebRTC).
const generalRelaySubjectPrefix = "public-transfer"

// isGeneralRelaySubject reports whether the credential belongs to the general relay mode.
// Browser WebRTC relays DTLS/SRTP and cannot pass the Peer Mesh specific checks, so those
// allocations must be forwarded with standard TURN semantics under their own quotas.
func (s *turnCredentialService) isGeneralRelaySubject(username string) bool {
	parts := strings.SplitN(strings.TrimSpace(username), ":", 3)
	return len(parts) == 3 && strings.HasPrefix(parts[1], generalRelaySubjectPrefix)
}

func (s *turnCredentialService) peerMeshClientID(username string) int64 {
	parts := strings.SplitN(strings.TrimSpace(username), ":", 3)
	if len(parts) != 3 || !strings.HasPrefix(parts[1], "pm-") {
		return 0
	}
	clientID, err := strconv.ParseInt(strings.TrimPrefix(parts[1], "pm-"), 10, 64)
	if err != nil || clientID <= 0 {
		return 0
	}
	return clientID
}

func (s *turnCredentialService) secret() []byte {
	if configured := strings.TrimSpace(s.cfg.TurnSharedSecret); configured != "" {
		return []byte(configured)
	}
	return s.runtimeSecret
}

func sanitizeTurnSubject(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "peer"
	}
	var builder strings.Builder
	for _, ch := range value {
		if ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || strings.ContainsRune("_.-", ch) {
			builder.WriteRune(ch)
		} else {
			builder.WriteByte('_')
		}
	}
	return builder.String()
}
