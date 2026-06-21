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
	"strconv"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/protocol"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/store"
)

// timestampWindowMs is the allowed clock skew for a login timestamp (±30s).
const timestampWindowMs = 30_000

// passwordAlphabet excludes visually ambiguous characters (matches the C# generator).
const passwordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

// Result is the outcome of an authentication attempt.
type Result struct {
	Success bool
	Reason  string
	Account *store.ClientAccount
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
	db  *store.DB
	now func() time.Time
}

// NewAuthenticator builds an Authenticator backed by db.
func NewAuthenticator(db *store.DB) *Authenticator {
	return &Authenticator{db: db, now: time.Now}
}

// Authenticate runs the full login check sequence and returns the result. The error is
// non-nil only on infrastructure failures (e.g. database errors), not auth rejections.
func (a *Authenticator) Authenticate(ctx context.Context, request protocol.LoginRequest) (Result, error) {
	if request.ClientName == "" {
		return Result{Reason: "缺少 clientName"}, nil
	}
	account, err := a.db.FindClientByName(ctx, request.ClientName)
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
	if !a.validSignature(account, request) {
		return Result{Reason: "签名无效或已过期", Account: account}, nil
	}
	return Result{Success: true, Account: account}, nil
}

func (a *Authenticator) validSignature(account *store.ClientAccount, request protocol.LoginRequest) bool {
	if request.Timestamp == "" || request.Nonce == "" || len(request.CheckSign) != protocol.SignatureLength {
		return false
	}
	timestampMs, err := strconv.ParseInt(request.Timestamp, 10, 64)
	if err != nil {
		return false
	}
	nowMs := a.now().UnixMilli()
	delta := nowMs - timestampMs
	if delta < 0 {
		delta = -delta
	}
	if delta > timestampWindowMs {
		return false
	}
	key, err := hex.DecodeString(account.PasswordHash)
	if err != nil || len(key) != protocol.SignatureLength {
		return false
	}
	expected := protocol.SignLoginWithKey(key, request.ClientName, request.Timestamp, request.Nonce)
	return hmac.Equal(expected, request.CheckSign)
}
