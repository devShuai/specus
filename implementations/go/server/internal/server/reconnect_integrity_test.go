package server

import (
	"context"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
)

// Reconnecting is the normal case, not the exception: a laptop sleeps, a network flaps, a client
// restarts. Every login has to land on the same account and identity and retire the previous
// startup session, otherwise a day of reconnects leaves a pile of accounts, identities and sessions
// that each hold an online-instance slot.
func TestRepeatedReconnectReusesTheAccountAndRetiresOldSessions(t *testing.T) {
	app, ts := newAPIServer(t)
	const (
		apiKey      = "ck_reconnect"
		secret      = "reconnect-secret"
		fingerprint = "machine-reconnect"
		osUser      = "alice"
	)
	insertCredentialForTest(t, app, "tenant-reconnect", osUser, apiKey, secret, 2)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	baseline, err := app.DB().ListClients(ctx)
	if err != nil {
		t.Fatalf("list clients: %v", err)
	}

	const reconnects = 25
	sessionIDs := make([]int64, 0, reconnects)
	var (
		firstClientID   int64
		firstIdentityID int64
	)
	for attempt := 0; attempt < reconnects; attempt++ {
		decoded := clientAuthLoginForTest(t, ts.URL, apiKey, secret, fingerprint, osUser)
		if decoded.ClientSessionID == 0 || decoded.AccessToken == "" {
			t.Fatalf("attempt %d returned no usable session: %+v", attempt, decoded)
		}
		for _, seen := range sessionIDs {
			if seen == decoded.ClientSessionID {
				t.Fatalf("attempt %d reused session id %d", attempt, seen)
			}
		}
		sessionIDs = append(sessionIDs, decoded.ClientSessionID)

		identity, err := app.DB().FindIdentity(ctx, credentialIDForTest(t, app, apiKey), fingerprint, osUser)
		if err != nil || identity == nil {
			t.Fatalf("attempt %d: identity missing: %v", attempt, err)
		}
		if attempt == 0 {
			firstClientID = identity.ClientID
			firstIdentityID = identity.ID
			continue
		}
		if identity.ID != firstIdentityID || identity.ClientID != firstClientID {
			t.Fatalf("attempt %d minted a new identity: identity=%d/%d, want %d/%d",
				attempt, identity.ID, identity.ClientID, firstIdentityID, firstClientID)
		}
	}

	// One account for the whole run.
	clients, err := app.DB().ListClients(ctx)
	if err != nil {
		t.Fatalf("list clients: %v", err)
	}
	if added := len(clients) - len(baseline); added != 1 {
		t.Fatalf("%d reconnects created %d accounts, want 1", reconnects, added)
	}

	// Every session but the newest is closed, so old startup sessions cannot hold instance slots.
	for index, id := range sessionIDs {
		session := getClientSessionForTest(t, app, id)
		if session == nil {
			t.Fatalf("session %d disappeared", id)
		}
		last := index == len(sessionIDs)-1
		if last {
			if session.Status != auth.StatusHTTPAuthenticated {
				t.Fatalf("newest session status = %q, want %q", session.Status, auth.StatusHTTPAuthenticated)
			}
			continue
		}
		if session.Status == auth.StatusHTTPAuthenticated {
			t.Fatalf("session %d (attempt %d) is still %q after a later reconnect",
				id, index, session.Status)
		}
	}
}

func credentialIDForTest(t *testing.T, app *App, apiKey string) int64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	credential, err := app.DB().FindCredentialByAPIKey(ctx, apiKey)
	if err != nil || credential == nil {
		t.Fatalf("find credential %q: %v", apiKey, err)
	}
	return credential.ID
}

// A reconnect must not resurrect the previous token: the old session is retired in the database, so
// it must stop authenticating in memory too.
func TestReconnectDoesNotLeaveThePreviousTokenUsable(t *testing.T) {
	app, ts := newAPIServer(t)
	const (
		apiKey      = "ck_reconnect_token"
		secret      = "reconnect-token-secret"
		fingerprint = "machine-reconnect-token"
		osUser      = "bob"
	)
	insertCredentialForTest(t, app, "tenant-reconnect-token", osUser, apiKey, secret, 2)

	first := clientAuthLoginForTest(t, ts.URL, apiKey, secret, fingerprint, osUser)
	second := clientAuthLoginForTest(t, ts.URL, apiKey, secret, fingerprint, osUser)
	if first.ClientSessionID == second.ClientSessionID {
		t.Fatal("a reconnect must mint a new session")
	}

	stale := getClientSessionForTest(t, app, first.ClientSessionID)
	if stale == nil || stale.Status == auth.StatusHTTPAuthenticated {
		t.Fatalf("the first session was not retired: %+v", stale)
	}
	fresh := getClientSessionForTest(t, app, second.ClientSessionID)
	if fresh == nil || fresh.Status != auth.StatusHTTPAuthenticated {
		t.Fatalf("the second session is not usable: %+v", fresh)
	}
}
