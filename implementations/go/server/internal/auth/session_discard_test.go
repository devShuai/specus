package auth

import (
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// A login registers the session in memory before it can be persisted. If the row never lands, the
// in-memory token must not stay usable — otherwise a failed login still yields working credentials.
func TestDiscardRemovesAnUnpersistedSession(t *testing.T) {
	sessions := NewSessionStore()
	account := storeAccount()

	session := sessions.CreateForClient(account, 7, "machine", "alice", time.Hour)
	if _, ok := sessions.Find(session.ID, session.AccessToken); !ok {
		t.Fatal("precondition: a freshly created session must be findable")
	}

	sessions.Discard(session.ID)

	if _, ok := sessions.Find(session.ID, session.AccessToken); ok {
		t.Fatal("a discarded session must no longer authenticate")
	}
	// Discarding twice, or discarding an unknown id, is harmless.
	sessions.Discard(session.ID)
	sessions.Discard(0)
	sessions.Discard(-1)
}

func TestDiscardLeavesOtherSessionsIntact(t *testing.T) {
	sessions := NewSessionStore()
	account := storeAccount()

	first := sessions.CreateForClient(account, 7, "machine-a", "alice", time.Hour)
	second := sessions.CreateForClient(account, 7, "machine-b", "bob", time.Hour)

	sessions.Discard(first.ID)

	if _, ok := sessions.Find(first.ID, first.AccessToken); ok {
		t.Fatal("the discarded session must be gone")
	}
	if _, ok := sessions.Find(second.ID, second.AccessToken); !ok {
		t.Fatal("an unrelated session must survive")
	}
}

func storeAccount() store.ClientAccount {
	return store.ClientAccount{
		ID:         101,
		TenantID:   "default",
		ClientName: "Demo client",
		Enabled:    true,
	}
}
