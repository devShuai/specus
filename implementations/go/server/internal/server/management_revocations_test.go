package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
	"github.com/devShuai/specus/implementations/go/server/internal/wsevents"
)

type revocationClaims struct {
	Subject string `json:"sub"`
	Tenant  string `json:"tenant_id"`
	Role    string `json:"role"`
	UID     string `json:"uid"`
}

func (c revocationClaims) token(app *App) string {
	return app.tokens.IssueForAccount(c.Subject, c.Tenant, c.Role, c.UID)
}

type revocationSocket struct {
	conn   *websocket.Conn
	closed chan error
}

// Drain application frames so Ping can verify registration without sleeps and retain the exact
// remote close code (CloseRead would hide it).
func openRevocationSocket(t *testing.T, ctx context.Context, address string) revocationSocket {
	t.Helper()
	conn, _, err := websocket.Dial(ctx, address, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseNow() })
	closed := make(chan error, 1)
	go func() {
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				closed <- err
				return
			}
		}
	}()
	if err := conn.Ping(ctx); err != nil {
		t.Fatalf("socket registration: %v", err)
	}
	return revocationSocket{conn: conn, closed: closed}
}

func (s revocationSocket) assertClosed(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case err := <-s.closed:
		if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
			t.Fatalf("close status: %v, want 1008", err)
		}
	case <-ctx.Done():
		t.Fatal("revoked socket stayed open")
	}
}

func assertRevocationTicketRefused(t *testing.T, ctx context.Context, address, reason string) {
	t.Helper()
	conn, response, err := websocket.Dial(ctx, address, nil)
	if conn != nil {
		conn.CloseNow()
	}
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("stale ticket handshake: response=%v err=%v", response, err)
	}
	if reason != "" && response.Header.Get("X-Auth-Reason") != reason {
		t.Fatalf("handshake reason: %q, want %q", response.Header.Get("X-Auth-Reason"), reason)
	}
}

func TestManagementWebSocketRevocationVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "protocol", "test-vectors", "management-accounts-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Revocation struct {
			Actor    revocationClaims `json:"actor"`
			Accounts []struct {
				AccountKey string `json:"accountKey"`
				LoginName  string `json:"loginName"`
				TenantID   string `json:"tenantId"`
				Role       string `json:"role"`
				Enabled    bool   `json:"enabled"`
			} `json:"accounts"`
			Bystanders []struct {
				Claims   revocationClaims `json:"claims"`
				Endpoint string           `json:"endpoint"`
			} `json:"bystanders"`
			Cases []struct {
				Name    string           `json:"name"`
				Target  revocationClaims `json:"target"`
				Request struct {
					Method   string          `json:"method"`
					Username string          `json:"username"`
					Body     json.RawMessage `json:"body"`
				} `json:"request"`
				Expect struct {
					Status  int  `json:"status"`
					Revoked bool `json:"revoked"`
				} `json:"expect"`
			} `json:"cases"`
		} `json:"webSocketRevocation"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	v := vector.Revocation
	if len(v.Cases) < 6 || len(v.Bystanders) < 2 {
		t.Fatal("incomplete revocation vector")
	}
	app, ts := newAPIServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, account := range v.Accounts {
		_, err := app.db.InsertManagementUser(ctx, store.ManagementUser{
			AccountKey: account.AccountKey, Username: account.LoginName, TenantID: account.TenantID,
			Role: account.Role, Enabled: account.Enabled, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	var bystanders []revocationSocket
	var bystanderTickets []string
	for _, b := range v.Bystanders {
		bystanders = append(bystanders, openRevocationSocket(t, ctx, webSocketURLFor(t, ts, b.Claims.token(app), b.Endpoint)))
		bystanderTickets = append(bystanderTickets, webSocketURLFor(t, ts, b.Claims.token(app), b.Endpoint))
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var sockets []revocationSocket
			var unused []string
			for _, endpoint := range []string{"connections", "client-messages"} {
				sockets = append(sockets, openRevocationSocket(t, ctx, webSocketURLFor(t, ts, c.Target.token(app), endpoint)))
				unused = append(unused, webSocketURLFor(t, ts, c.Target.token(app), endpoint))
			}
			response := authRequest(t, ts, c.Request.Method, "/api/admin/users/"+c.Request.Username, v.Actor.token(app), string(c.Request.Body))
			response.Body.Close()
			if response.StatusCode != c.Expect.Status {
				t.Fatalf("mutation: %d, want %d", response.StatusCode, c.Expect.Status)
			}
			for i, socket := range sockets {
				if c.Expect.Revoked {
					socket.assertClosed(t, ctx)
					assertRevocationTicketRefused(t, ctx, unused[i], "invalid ticket")
				} else {
					if err := socket.conn.Ping(ctx); err != nil {
						t.Fatalf("unchanged identity closed: %v", err)
					}
					openRevocationSocket(t, ctx, unused[i])
				}
			}
		})
	}
	for i, b := range bystanders {
		if err := b.conn.Ping(ctx); err != nil {
			t.Fatalf("bystander closed: %v", err)
		}
		openRevocationSocket(t, ctx, bystanderTickets[i])
	}
}

func seedRevocationAccount(t *testing.T, app *App) store.ManagementUser {
	t.Helper()
	user, err := app.db.InsertManagementUser(context.Background(), store.ManagementUser{
		AccountKey: "revocation-original-key", Username: "revocation-user", TenantID: "default",
		Role: "USER", Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func TestManagementWebSocketTicketRechecksCurrentIdentity(t *testing.T) {
	for _, endpoint := range []string{"connections", "client-messages"} {
		for _, change := range []string{"disabled", "role-changed", "recreated", "unchanged"} {
			t.Run(endpoint+"/"+change, func(t *testing.T) {
				app, ts := newAPIServer(t)
				user := seedRevocationAccount(t, app)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				token := app.tokens.IssueForAccount(user.Username, user.TenantID, user.Role, user.AccountKey)
				address := webSocketURLFor(t, ts, token, endpoint)
				// Bypass API hooks deliberately: the handshake must consult authoritative state.
				switch change {
				case "disabled":
					user.Enabled = false
				case "role-changed":
					user.Role = "ADMIN"
				case "recreated":
					if err := app.db.DeleteManagementUser(ctx, user); err != nil {
						t.Fatal(err)
					}
					user.AccountKey = "revocation-replacement-key"
					if _, err := app.db.InsertManagementUser(ctx, user); err != nil {
						t.Fatal(err)
					}
				}
				if err := app.db.UpdateManagementUser(ctx, user); err != nil {
					t.Fatal(err)
				}
				if change == "unchanged" {
					openRevocationSocket(t, ctx, address)
				} else {
					assertRevocationTicketRefused(t, ctx, address, "identity revoked")
					assertRevocationTicketRefused(t, ctx, address, "invalid ticket")
				}
			})
		}
	}
}

func TestManagementWebSocketRevocationBetweenCheckAndRegistration(t *testing.T) {
	for _, endpoint := range []string{"connections", "client-messages"} {
		t.Run(endpoint, func(t *testing.T) {
			app, ts := newAPIServer(t)
			user := seedRevocationAccount(t, app)
			var calls atomic.Int32
			check := app.clientMessages.identity
			wrapped := func(ctx context.Context, access wsevents.Access) bool {
				current := check(ctx, access)
				if calls.Add(1) == 1 {
					user.Enabled = false
					if err := app.db.UpdateManagementUser(ctx, user); err != nil {
						t.Error(err)
						return false
					}
					// Simulate the already-committed revocation notification running before registration.
					app.wsHub.CloseIdentity(user.TenantID, user.Username, "account disabled")
					app.clientMessages.closeIdentity(user.TenantID, user.Username, "account disabled")
				}
				return current
			}
			app.wsHub.SetIdentityCheck(wrapped)
			app.clientMessages.identity = wrapped
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			address := webSocketURLFor(t, ts, app.tokens.IssueForAccount(user.Username, user.TenantID, user.Role, user.AccountKey), endpoint)
			conn, _, err := websocket.Dial(ctx, address, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.CloseNow()
			if _, _, err := conn.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
				t.Fatalf("registration race did not close with 1008: %v", err)
			}
			if calls.Load() != 2 {
				t.Fatalf("identity checks = %d", calls.Load())
			}
		})
	}
}

func TestManagementWebSocketRevocationRollsBackWithAccountMutation(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			app, ts := newAPIServer(t)
			user := seedRevocationAccount(t, app)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			token := app.tokens.IssueForAccount(user.Username, user.TenantID, user.Role, user.AccountKey)
			var sockets []revocationSocket
			var unused []string
			for _, endpoint := range []string{"connections", "client-messages"} {
				sockets = append(sockets, openRevocationSocket(t, ctx, webSocketURLFor(t, ts, token, endpoint)))
				unused = append(unused, webSocketURLFor(t, ts, token, endpoint))
			}
			// Failing ticket invalidation must roll back the preceding account mutation; no
			// post-commit close should be emitted for an operation which did not commit.
			_, err := app.db.ExecStatement(ctx, `CREATE TRIGGER fail_revocation BEFORE DELETE ON specus_websocket_ticket
				BEGIN SELECT RAISE(ABORT, 'injected ticket failure'); END`)
			if err != nil {
				t.Fatal(err)
			}
			response := authRequest(t, ts, method, "/api/admin/users/"+user.Username, adminToken(t, ts), `{"enabled":false}`)
			response.Body.Close()
			if response.StatusCode != http.StatusInternalServerError {
				t.Fatalf("mutation status = %d", response.StatusCode)
			}
			current, err := app.db.FindManagementUserByAccountKey(ctx, user.AccountKey)
			if err != nil || current == nil || !current.Enabled {
				t.Fatalf("account mutation was not rolled back: %+v %v", current, err)
			}
			if _, err := app.db.ExecStatement(ctx, "DROP TRIGGER fail_revocation"); err != nil {
				t.Fatal(err)
			}
			for i, socket := range sockets {
				if err := socket.conn.Ping(ctx); err != nil {
					t.Fatalf("rolled-back mutation closed socket: %v", err)
				}
				openRevocationSocket(t, ctx, unused[i])
			}
		})
	}
}

func TestManagementWebSocketRevocationAcrossRedisInstances(t *testing.T) {
	redisURI := os.Getenv("SPECUS_TEST_REDIS_URI")
	if redisURI == "" {
		t.Skip("SPECUS_TEST_REDIS_URI is not configured")
	}
	cfg := config.Default()
	cfg.Auth.JwtSecret = "revocation-integration-shared-signing-key"
	cfg.PublicTransfer.ClusterEnabled = true
	cfg.PublicTransfer.RedisURI = redisURI
	cfg.PublicTransfer.RedisKeyPrefix = "specus:test:revocation:" + randomDiscoveryLeaseID()
	first, firstHTTP := newAPIServerWithConfig(t, cfg)
	// Use the same authoritative database and Redis namespace, but independent application hubs
	// and subscriptions. Only the first instance handles the account mutation.
	second, err := New(first.cfg, first.logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { second.Close() })
	_, secondHTTP := newHTTPTestServer(t, second)
	user := seedRevocationAccount(t, first)
	other := user
	other.TenantID = "other-tenant"
	other.AccountKey = "other-account-key"
	if _, err := first.db.InsertManagementUser(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	token := first.tokens.IssueForAccount(user.Username, user.TenantID, user.Role, user.AccountKey)
	otherToken := first.tokens.IssueForAccount(other.Username, other.TenantID, other.Role, other.AccountKey)
	var targets, bystanders []revocationSocket
	var unused []string
	for _, endpoint := range []string{"connections", "client-messages"} {
		targets = append(targets, openRevocationSocket(t, ctx, webSocketURLFor(t, secondHTTP, token, endpoint)))
		bystanders = append(bystanders, openRevocationSocket(t, ctx, webSocketURLFor(t, secondHTTP, otherToken, endpoint)))
		unused = append(unused, webSocketURLFor(t, secondHTTP, token, endpoint))
	}
	// Invalid tenant binding must never close sockets. A following marker observes that the
	// subscriber processed the preceding malformed event, without relying on a timing sleep.
	coordination := first.publicTransferDiscovery.coordination
	observed := make(chan struct{}, 1)
	second.publicTransferDiscovery.coordination.addListener(func(event publicTransferClusterEvent) {
		if event.kind == clusterEventKindManagementRevocation && string(event.payload) == "marker" {
			observed <- struct{}{}
		}
	})
	malformed, _ := json.Marshal(managementRevocationEvent{TenantID: user.TenantID, Username: user.Username, Reason: "disabled"})
	if err := coordination.publishManagementRevocation(ctx, "wrong-tenant", malformed); err != nil {
		t.Fatal(err)
	}
	if err := coordination.publishManagementRevocation(ctx, "wrong-tenant", []byte("marker")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-observed:
	case <-ctx.Done():
		t.Fatal("Redis subscriber did not receive marker")
	}
	for _, socket := range targets {
		if err := socket.conn.Ping(ctx); err != nil {
			t.Fatalf("invalid tenant binding closed socket: %v", err)
		}
	}
	response := authRequest(t, firstHTTP, http.MethodPut, "/api/admin/users/"+user.Username, adminToken(t, firstHTTP), `{"enabled":false}`)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("disable: %d", response.StatusCode)
	}
	for i, socket := range targets {
		socket.assertClosed(t, ctx)
		assertRevocationTicketRefused(t, ctx, unused[i], "invalid ticket")
		if err := bystanders[i].conn.Ping(ctx); err != nil {
			t.Fatalf("cross-tenant bystander closed: %v", err)
		}
	}
}
