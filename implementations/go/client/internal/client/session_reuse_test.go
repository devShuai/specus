package client

import (
	"io"
	"log"
	"testing"
	"time"
)

func reuseTestClient(t *testing.T) *Client {
	t.Helper()
	return New(Config{ServerBaseURL: "https://specus.example.com"}, log.New(io.Discard, "", 0))
}

// A dropped control channel does not invalidate the runtime session. Reusing a token that is still
// valid avoids a full HTTP login (and a new server-side session row) on every reconnect.
func TestReusableRuntimeKeepsAValidSession(t *testing.T) {
	client := reuseTestClient(t)
	client.applyRuntime(RuntimeConfig{
		ClientName:      "demo",
		ClientSessionID: 42,
		AccessToken:     "token",
		NettyHost:       "specus.example.com",
		NettyPort:       7010,
		TokenExpiresAt:  time.Now().Add(time.Hour),
	})

	runtime, reused := client.reusableRuntime()
	if !reused {
		t.Fatal("a token valid for an hour must be reused across a reconnect")
	}
	if runtime.ClientSessionID != 42 || runtime.AccessToken != "token" {
		t.Fatalf("reused runtime lost its session: %+v", runtime)
	}
}

func TestReusableRuntimeRejectsExpiringOrIncompleteSessions(t *testing.T) {
	cases := map[string]RuntimeConfig{
		"expiring soon": {
			ClientSessionID: 1, AccessToken: "token", NettyHost: "h", NettyPort: 7010,
			TokenExpiresAt: time.Now().Add(5 * time.Second),
		},
		"already expired": {
			ClientSessionID: 1, AccessToken: "token", NettyHost: "h", NettyPort: 7010,
			TokenExpiresAt: time.Now().Add(-time.Minute),
		},
		// No expiry carries no proof of freshness.
		"no expiry": {
			ClientSessionID: 1, AccessToken: "token", NettyHost: "h", NettyPort: 7010,
		},
		"no token": {
			ClientSessionID: 1, NettyHost: "h", NettyPort: 7010,
			TokenExpiresAt: time.Now().Add(time.Hour),
		},
		"no session id": {
			AccessToken: "token", NettyHost: "h", NettyPort: 7010,
			TokenExpiresAt: time.Now().Add(time.Hour),
		},
		"no endpoint": {
			ClientSessionID: 1, AccessToken: "token",
			TokenExpiresAt: time.Now().Add(time.Hour),
		},
	}
	for name, runtime := range cases {
		client := reuseTestClient(t)
		client.applyRuntime(runtime)
		if _, reused := client.reusableRuntime(); reused {
			t.Fatalf("%s must force a fresh HTTP login", name)
		}
	}
}

// A rejected control login means the server no longer accepts the cached session, so replaying it
// would loop forever.
func TestInvalidateRuntimeSessionForcesAFreshLogin(t *testing.T) {
	client := reuseTestClient(t)
	client.applyRuntime(RuntimeConfig{
		ClientName:      "demo",
		ClientSessionID: 42,
		AccessToken:     "token",
		NettyHost:       "specus.example.com",
		NettyPort:       7010,
		TokenExpiresAt:  time.Now().Add(time.Hour),
	})
	if _, reused := client.reusableRuntime(); !reused {
		t.Fatal("precondition: the session should be reusable")
	}

	client.invalidateRuntimeSession()

	if _, reused := client.reusableRuntime(); reused {
		t.Fatal("an invalidated session must not be reused")
	}
	// Configuration learned from the last login stays available for the next attempt.
	if client.currentRuntime().ClientName != "demo" {
		t.Fatal("invalidating the session must not discard the rest of the runtime config")
	}
}
