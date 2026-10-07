package auth

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
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

// A token belongs to the account it was issued for: renaming the account keeps it valid under the
// new name, and an account created later under the old name is never what it logs in as.
func TestAuthenticateResolvesTheTokenAccountByIDNotByName(t *testing.T) {
	authenticator, sessions, _, account, credential := newTestAuthenticator(t)
	ctx := context.Background()
	issued := sessions.CreateForClient(account, credential.ID, "machine-1", "alice", time.Hour)

	renamed := account
	renamed.ClientName = "client-a-renamed"
	if err := authenticator.db.UpdateClientAndRenameReferences(ctx, renamed, account.ClientName); err != nil {
		t.Fatalf("rename: %v", err)
	}
	reuse := store.ClientAccount{ID: NewClientID(), TenantID: account.TenantID, ClientName: account.ClientName,
		Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if _, err := authenticator.db.InsertClientIfAbsent(ctx, reuse); err != nil {
		t.Fatalf("insert client of the old name: %v", err)
	}

	result, err := authenticator.Authenticate(ctx, protocol.LoginRequest{
		ClientName: account.ClientName, ClientSessionID: issued.ID, AccessToken: issued.AccessToken,
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if !result.Success || result.Account.ID != account.ID || result.Account.ClientName != renamed.ClientName {
		t.Fatalf("result = %+v (account %+v), want the renamed account %q", result, result.Account, renamed.ClientName)
	}
	if found, ok := sessions.Find(issued.ID, issued.AccessToken); !ok || found.ClientName != renamed.ClientName {
		t.Fatalf("session after login = %+v, want it renamed to %q", found, renamed.ClientName)
	}

	if err := authenticator.db.DeleteClient(ctx, account.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	result, err = authenticator.Authenticate(ctx, protocol.LoginRequest{
		ClientName: renamed.ClientName, ClientSessionID: issued.ID, AccessToken: issued.AccessToken,
	})
	if err != nil {
		t.Fatalf("authenticate after delete: %v", err)
	}
	if result.Success || result.Reason != "客户端不存在" {
		t.Fatalf("token of a deleted account = %+v, want 客户端不存在", result)
	}
}

// A token is refused when its account moved to another tenant, as Java/.NET look it up by id and tenant.
func TestAuthenticateRefusesTheTokenOfAnotherTenantsAccount(t *testing.T) {
	authenticator, sessions, _, account, credential := newTestAuthenticator(t)
	issued := sessions.CreateForClient(account, credential.ID, "machine-1", "alice", time.Hour)
	other := account
	other.TenantID = "tenant-b"
	stale := sessions.CreateForClient(other, credential.ID, "machine-2", "bob", time.Hour)

	result, err := authenticator.Authenticate(context.Background(), protocol.LoginRequest{
		ClientSessionID: stale.ID, AccessToken: stale.AccessToken,
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if result.Success {
		t.Fatalf("a session of tenant-b logged in as the tenant-a account %+v", result.Account)
	}
	if _, ok := sessions.Find(issued.ID, issued.AccessToken); !ok {
		t.Fatal("the refusal touched the account's own session")
	}
}

func TestSessionStoreRevokeClientForgetsOnlyThatAccountsTokens(t *testing.T) {
	sessions := NewSessionStore()
	first := store.ClientAccount{ID: 11, TenantID: "default", ClientName: "first"}
	second := store.ClientAccount{ID: 12, TenantID: "default", ClientName: "second"}
	a := sessions.CreateForClient(first, 1, "machine-1", "alice", time.Hour)
	b := sessions.CreateForClient(first, 1, "machine-2", "alice", time.Hour)
	c := sessions.CreateForClient(second, 1, "machine-3", "alice", time.Hour)

	revoked := sessions.RevokeClient(first.ID)
	if len(revoked) != 2 {
		t.Fatalf("revoked = %v, want both sessions of the first account", revoked)
	}
	for _, session := range []Session{a, b} {
		if _, ok := sessions.Find(session.ID, session.AccessToken); ok {
			t.Fatalf("session %d of the deleted account is still usable", session.ID)
		}
	}
	if _, ok := sessions.Find(c.ID, c.AccessToken); !ok {
		t.Fatal("revoking the first account dropped the second account's session")
	}

	sessions.RenameClient(second.ID, "second-renamed")
	if found, _ := sessions.Find(c.ID, c.AccessToken); found.ClientName != "second-renamed" {
		t.Fatalf("session after RenameClient = %+v", found)
	}
}
