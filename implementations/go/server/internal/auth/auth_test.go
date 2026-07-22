package auth

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/protocol"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/session"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/store"
)

type stubControlSession struct {
	name string
}

func (s *stubControlSession) ClientName() string         { return s.name }
func (s *stubControlSession) LoginTimeMs() int64         { return time.Now().UnixMilli() }
func (s *stubControlSession) Send(protocol.Packet) error { return nil }
func (s *stubControlSession) Close(reason string)        {}

func newTestAuthenticator(t *testing.T) (*Authenticator, *SessionStore, *session.Registry, store.ClientAccount, store.ClientCredential) {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "auth-test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	account := store.ClientAccount{
		ID:         NewClientID(),
		TenantID:   "tenant-a",
		ClientName: "client-a",
		Enabled:    true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	if _, err := db.InsertClientIfAbsent(ctx, account); err != nil {
		t.Fatalf("insert client: %v", err)
	}
	credential := store.ClientCredential{
		ID:                 NewClientID(),
		TenantID:           "tenant-a",
		APIKey:             "ck_test",
		SecretHash:         HashPassword("secret"),
		Enabled:            true,
		MaxOnlineInstances: 5,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	if _, err := db.InsertCredentialIfAbsent(ctx, credential); err != nil {
		t.Fatalf("insert credential: %v", err)
	}
	sessions := NewSessionStore()
	registry := session.NewRegistry()
	return NewAuthenticator(db, sessions, 1, registry), sessions, registry, account, credential
}

// A NETTY_ONLINE session whose control connection is gone must not block a re-login:
// authenticate() reconciles stale rows against the live registry before the online checks.
func TestAuthenticateClosesStaleOnlineSessions(t *testing.T) {
	authenticator, sessions, _, account, credential := newTestAuthenticator(t)
	ctx := context.Background()

	stale := sessions.CreateForClient(account, credential.ID, "machine-1", "alice", time.Hour)
	sessions.MarkOnline(stale.ID)

	relogin := sessions.CreateForClient(account, credential.ID, "machine-1", "alice", time.Hour)
	result, err := authenticator.Authenticate(ctx, protocol.LoginRequest{
		ClientSessionID: relogin.ID,
		AccessToken:     relogin.AccessToken,
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if !result.Success {
		t.Fatalf("re-login should succeed after stale cleanup, got reason %q", result.Reason)
	}
	if online := sessions.CountOnlineByCredential(credential.ID); online != 0 {
		t.Fatalf("stale session should be marked disconnected, %d still online", online)
	}
}

// A NETTY_ONLINE session with a live bound control connection must still block duplicates.
func TestAuthenticateKeepsLiveOnlineSessions(t *testing.T) {
	authenticator, sessions, registry, account, credential := newTestAuthenticator(t)
	ctx := context.Background()

	live := sessions.CreateForClient(account, credential.ID, "machine-1", "alice", time.Hour)
	sessions.MarkOnline(live.ID)
	registry.Replace(&stubControlSession{name: account.ClientName})

	duplicate := sessions.CreateForClient(account, credential.ID, "machine-1", "alice", time.Hour)
	result, err := authenticator.Authenticate(ctx, protocol.LoginRequest{
		ClientSessionID: duplicate.ID,
		AccessToken:     duplicate.AccessToken,
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if result.Success {
		t.Fatal("duplicate login should be rejected while the first connection is live")
	}
	if result.Reason != "同一台机器和用户已经有在线实例" {
		t.Fatalf("unexpected rejection reason %q", result.Reason)
	}
	if online := sessions.CountOnlineByCredential(credential.ID); online != 1 {
		t.Fatalf("live session must stay online, %d online", online)
	}
}
