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

	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// passwordAlphabet excludes visually ambiguous characters (matches the C# generator).
const passwordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

const (
	StatusHTTPAuthenticated = "HTTP_AUTHENTICATED"
	StatusNettyOnline       = "NETTY_ONLINE"
	StatusDisconnected      = "DISCONNECTED"
)

// Result is the outcome of an authentication attempt.
type Result struct {
	Success bool
	Reason  string
	Account *store.ClientAccount
	Session Session
}

type Session struct {
	ID                 int64
	TenantID           string
	CredentialID       int64
	ClientID           int64
	ClientName         string
	MachineFingerprint string
	OSUser             string
	AccessToken        string
	TokenHash          string
	ExpiresAt          time.Time
	Status             string
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
	return s.CreateForClient(account, 0, "", "", ttl)
}

func (s *SessionStore) CreateForClient(account store.ClientAccount, credentialID int64,
	machineFingerprint, osUser string, ttl time.Duration) Session {
	token := "cs_" + randomHex(32) + randomHex(32)
	session := Session{
		ID:                 NewClientID(),
		TenantID:           account.TenantID,
		CredentialID:       credentialID,
		ClientID:           account.ID,
		ClientName:         account.ClientName,
		MachineFingerprint: machineFingerprint,
		OSUser:             osUser,
		AccessToken:        token,
		TokenHash:          HashToken(token),
		ExpiresAt:          time.Now().Add(ttl),
		Status:             StatusHTTPAuthenticated,
	}
	s.mu.Lock()
	s.byTokenHash[session.TokenHash] = session
	s.tokenHashBySessionID[session.ID] = session.TokenHash
	s.mu.Unlock()
	return session
}

// Discard removes a session that was registered in memory but whose persistence failed. Without it
// a failed login would leave a usable in-memory token that no database row backs.
func (s *SessionStore) Discard(sessionID int64) {
	if sessionID <= 0 {
		return
	}
	s.mu.Lock()
	if hash, ok := s.tokenHashBySessionID[sessionID]; ok {
		delete(s.byTokenHash, hash)
		delete(s.tokenHashBySessionID, sessionID)
	}
	s.mu.Unlock()
}

func (s *SessionStore) Find(sessionID int64, accessToken string) (Session, bool) {
	if sessionID <= 0 || accessToken == "" {
		return Session{}, false
	}
	hash := HashToken(accessToken)
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

func (s *SessionStore) MarkOnline(sessionID int64) {
	s.updateStatus(sessionID, StatusNettyOnline)
}

func (s *SessionStore) MarkDisconnected(sessionID int64) {
	s.updateStatus(sessionID, StatusDisconnected)
}

func (s *SessionStore) CountOnlineByMachineUser(credentialID int64, machineFingerprint, osUser string) int {
	if credentialID <= 0 || machineFingerprint == "" || osUser == "" {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, session := range s.byTokenHash {
		if session.Status == StatusNettyOnline && session.CredentialID == credentialID &&
			session.MachineFingerprint == machineFingerprint && session.OSUser == osUser {
			count++
		}
	}
	return count
}

// FindOnlineByCredential returns every NETTY_ONLINE session held for the credential.
// Used to reconcile stale in-memory rows against the live control-connection registry.
func (s *SessionStore) FindOnlineByCredential(credentialID int64) []Session {
	if credentialID <= 0 {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var online []Session
	for _, session := range s.byTokenHash {
		if session.Status == StatusNettyOnline && session.CredentialID == credentialID {
			online = append(online, session)
		}
	}
	return online
}

func (s *SessionStore) CountOnlineByCredential(credentialID int64) int {
	if credentialID <= 0 {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, session := range s.byTokenHash {
		if session.Status == StatusNettyOnline && session.CredentialID == credentialID {
			count++
		}
	}
	return count
}

func (s *SessionStore) updateStatus(sessionID int64, status string) {
	if sessionID <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tokenHash, ok := s.tokenHashBySessionID[sessionID]
	if !ok {
		return
	}
	session, ok := s.byTokenHash[tokenHash]
	if !ok {
		return
	}
	session.Status = status
	s.byTokenHash[tokenHash] = session
}

// HashToken returns the lowercase hex SHA-256 of a high-entropy secret.
//
// This is the right primitive for access tokens, session tokens and machine secrets: they are
// generated with full entropy, so there is nothing to guess and an iterated KDF would only add
// latency to every request. Human passwords are the opposite case and go through HashPassword,
// which is salted and deliberately slow.
func HashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// DigestKey derives a deterministic lookup key from non-secret identifiers, such as an OIDC
// issuer and subject pair. It is an index, not a credential.
func DigestKey(value string) string {
	sum := sha256.Sum256([]byte(value))
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
	db                         *store.DB
	sessions                   *SessionStore
	registry                   *session.Registry
	perMachineUserMaxInstances int
	now                        func() time.Time
}

// NewAuthenticator builds an Authenticator backed by db. registry is the live
// control-connection registry used to reconcile stale online sessions before
// the per-machine/per-credential online checks (mirrors the Java server).
func NewAuthenticator(db *store.DB, sessions *SessionStore, perMachineUserMaxInstances int,
	registry *session.Registry) *Authenticator {
	if perMachineUserMaxInstances <= 0 {
		perMachineUserMaxInstances = 1
	}
	return &Authenticator{
		db:                         db,
		sessions:                   sessions,
		registry:                   registry,
		perMachineUserMaxInstances: perMachineUserMaxInstances,
		now:                        time.Now,
	}
}

// Authenticate runs the full login check sequence and returns the result. The error is
// non-nil only on infrastructure failures (e.g. database errors), not auth rejections.
func (a *Authenticator) Authenticate(ctx context.Context, request protocol.LoginRequest) (Result, error) {
	return a.authenticate(ctx, request, false)
}

// AuthenticateData verifies the companion data connection without counting it as a second
// online client instance. The control connection must already have marked the same session online.
func (a *Authenticator) AuthenticateData(ctx context.Context, request protocol.LoginRequest) (Result, error) {
	return a.authenticate(ctx, request, true)
}

func (a *Authenticator) authenticate(ctx context.Context, request protocol.LoginRequest, dataConnection bool) (Result, error) {
	session, ok := a.sessions.Find(request.ClientSessionID, request.AccessToken)
	if !ok {
		return Result{Reason: "客户端访问令牌无效"}, nil
	}
	if session.ExpiresAt.Before(a.now()) {
		a.sessions.MarkDisconnected(session.ID)
		_ = a.db.MarkClientSessionDisconnected(ctx, session.ID, StatusDisconnected, a.now())
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
	if dataConnection && session.Status != StatusNettyOnline {
		return Result{Reason: "数据连接要求控制连接先登录", Account: account}, nil
	}
	if session.CredentialID > 0 {
		credential, err := a.db.GetCredential(ctx, session.CredentialID)
		if err != nil {
			if err == store.ErrNotFound {
				return Result{Reason: "客户端凭证不存在", Account: account}, nil
			}
			return Result{}, err
		}
		if !credential.Enabled {
			return Result{Reason: "客户端凭证已停用", Account: account}, nil
		}
		if !dataConnection {
			a.closeStaleOnlineSessions(ctx, session)
		}
		if !dataConnection && a.sessions.CountOnlineByMachineUser(session.CredentialID, session.MachineFingerprint, session.OSUser) >=
			a.perMachineUserMaxInstances {
			return Result{Reason: "同一台机器和用户已经有在线实例", Account: account}, nil
		}
		// maxOnlineInstances == 0 表示拒绝所有登录（与 Java ClientAuthService.isOnlineLimitExceeded
		// 一致：online >= 0 恒为真）。不做 > 0 守卫，确保 0 语义为"拒绝全部"。
		if !dataConnection &&
			a.sessions.CountOnlineByCredential(session.CredentialID) >= credential.MaxOnlineInstances {
			return Result{Reason: "在线实例数已达上限", Account: account}, nil
		}
	}
	if !dataConnection && account.ConnectionRateLimitPerMinute > 0 {
		since := a.now().Add(-time.Minute)
		count, err := a.db.CountConnectionsSince(ctx, account.ID, since)
		if err != nil {
			return Result{}, err
		}
		if count >= account.ConnectionRateLimitPerMinute {
			return Result{Reason: "连接频率超过限制", Account: account}, nil
		}
	}
	return Result{Success: true, Account: account, Session: session}, nil
}

// closeStaleOnlineSessions marks in-memory NETTY_ONLINE sessions for the same credential as
// disconnected when their control connection is no longer bound in the registry. This mirrors
// the Java ClientAuthService.closeStaleOnlineSessions guard so ghost rows left by an unclean
// disconnect cannot reject a legitimate re-login. The current session is included: on success
// the dispatcher marks it online again. DB rows are synced best-effort.
func (a *Authenticator) closeStaleOnlineSessions(ctx context.Context, current Session) {
	if a.registry == nil || current.CredentialID <= 0 {
		return
	}
	for _, candidate := range a.sessions.FindOnlineByCredential(current.CredentialID) {
		if _, bound := a.registry.Find(candidate.ClientName); bound {
			continue
		}
		a.sessions.MarkDisconnected(candidate.ID)
		_ = a.db.MarkClientSessionDisconnected(ctx, candidate.ID, StatusDisconnected, a.now())
	}
}

func (a *Authenticator) MarkOnline(sessionID int64) {
	a.sessions.MarkOnline(sessionID)
}

func (a *Authenticator) MarkDisconnected(sessionID int64) {
	a.sessions.MarkDisconnected(sessionID)
}

func randomHex(size int) string {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		sum := sha256.Sum256([]byte(time.Now().String()))
		return hex.EncodeToString(sum[:])
	}
	return hex.EncodeToString(data)
}
