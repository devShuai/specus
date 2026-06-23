// Package auth implements client login: HMAC-SHA256 signature verification, per-client
// connection rate limiting, password hashing, and client-id generation. It mirrors the
// C# ClientAccountService / PasswordHasher / ClientIdGenerator.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"sync"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/protocol"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/store"
)

// passwordAlphabet excludes visually ambiguous characters (matches the C# generator).
const passwordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

// Result is the outcome of an authentication attempt.
type Result struct {
	Success bool
	Reason  string
	Account *store.ClientAccount
}

type Session struct {
	ID          int64
	ClientID    int64
	ClientName  string
	AccessToken string
	TokenHash   string
	ExpiresAt   time.Time
}

type SessionStore struct {
	mu                   sync.RWMutex
	byTokenHash          map[string]Session
	tokenHashBySessionID map[int64]string
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		byTokenHash:          make(map[string]Session),
		tokenHashBySessionID: make(map[int64]string),
	}
}

func (s *SessionStore) Create(account store.ClientAccount, ttl time.Duration) Session {
	token := "cs_" + randomHex(32) + randomHex(32)
	session := Session{
		ID:          NewClientID(),
		ClientID:    account.ID,
		ClientName:  account.ClientName,
		AccessToken: token,
		TokenHash:   HashPassword(token),
		ExpiresAt:   time.Now().Add(ttl),
	}
	s.mu.Lock()
	s.byTokenHash[session.TokenHash] = session
	s.tokenHashBySessionID[session.ID] = session.TokenHash
	s.mu.Unlock()
	return session
}

func (s *SessionStore) Find(sessionID int64, accessToken string) (Session, bool) {
	if sessionID <= 0 || accessToken == "" {
		return Session{}, false
	}
	hash := HashPassword(accessToken)
	s.mu.RLock()
	storedHash, ok := s.tokenHashBySessionID[sessionID]
	if !ok || !hmac.Equal([]byte(storedHash), []byte(hash)) {
		s.mu.RUnlock()
		return Session{}, false
	}
	session, ok := s.byTokenHash[hash]
	s.mu.RUnlock()
	return session, ok
}

// HashPassword returns the lowercase hex SHA-256 of the plaintext password (no salt),
// matching the stored password_hash format.
func HashPassword(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// GeneratePassword returns an 18-character password from the unambiguous alphabet.
func GeneratePassword() string {
	const length = 18
	out := make([]byte, length)
	max := big.NewInt(int64(len(passwordAlphabet)))
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			// crypto/rand failure is unrecoverable; fall back to a fixed index is unsafe, so panic.
			panic("auth: secure random source unavailable: " + err.Error())
		}
		out[i] = passwordAlphabet[n.Int64()]
	}
	return string(out)
}

// NewClientID returns a JS-safe random id in [1, 2^53-1] so the JSON UI can round-trip it.
func NewClientID() int64 {
	const maxSafe = int64(1) << 53
	for {
		n, err := rand.Int(rand.Reader, big.NewInt(maxSafe))
		if err != nil {
			panic("auth: secure random source unavailable: " + err.Error())
		}
		if n.Int64() >= 1 {
			return n.Int64()
		}
	}
}

// Authenticator verifies login requests against the store.
type Authenticator struct {
	db       *store.DB
	sessions *SessionStore
	now      func() time.Time
}

// NewAuthenticator builds an Authenticator backed by db.
func NewAuthenticator(db *store.DB, sessions *SessionStore) *Authenticator {
	return &Authenticator{db: db, sessions: sessions, now: time.Now}
}

// Authenticate runs the full login check sequence and returns the result. The error is
// non-nil only on infrastructure failures (e.g. database errors), not auth rejections.
func (a *Authenticator) Authenticate(ctx context.Context, request protocol.LoginRequest) (Result, error) {
	session, ok := a.sessions.Find(request.ClientSessionID, request.AccessToken)
	if !ok {
		return Result{Reason: "客户端访问令牌无效"}, nil
	}
	if session.ExpiresAt.Before(a.now()) {
		return Result{Reason: "客户端访问令牌已过期"}, nil
	}
	account, err := a.db.FindClientByName(ctx, session.ClientName)
	if err != nil {
		return Result{}, err
	}
	if account == nil {
		return Result{Reason: "客户端不存在"}, nil
	}
	if !account.Enabled {
		return Result{Reason: "客户端已停用", Account: account}, nil
	}
	if account.ConnectionRateLimitPerMinute > 0 {
		since := a.now().Add(-time.Minute)
		count, err := a.db.CountConnectionsSince(ctx, account.ID, since)
		if err != nil {
			return Result{}, err
		}
		if count >= account.ConnectionRateLimitPerMinute {
			return Result{Reason: "连接频率超过限制", Account: account}, nil
		}
	}
	return Result{Success: true, Account: account}, nil
}

func randomHex(size int) string {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		sum := sha256.Sum256([]byte(time.Now().String()))
		return hex.EncodeToString(sum[:])
	}
	return hex.EncodeToString(data)
}
