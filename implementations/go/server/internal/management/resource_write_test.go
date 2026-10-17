package management

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// The barrier lives on the server request body, not the client's transport reader. Reaching
// Read proves the real bearer middleware has resolved an identity and entered JSON decoding.
type resourceWriteBarrierBody struct {
	io.ReadCloser
	entered, release chan struct{}
	once             sync.Once
}

func (b *resourceWriteBarrierBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered); <-b.release })
	return b.ReadCloser.Read(p)
}

func TestManagementResourceMutationRejectsRevokedInFlightActor(t *testing.T) {
	for _, scenario := range []struct{ name, method, path, body string }{
		{"client-create", "POST", "/api/admin/clients", `{"clientName":"late-client"}`},
		{"client-patch", "PUT", "/api/admin/clients/1001", `{"enabled":false}`},
		{"credential-create", "POST", "/api/admin/client-credentials", `{"apiKey":"late-key","secret":"late-secret","maxOnlineInstances":1}`},
		{"credential-patch", "PUT", "/api/admin/client-credentials/501", `{"enabled":false}`},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			h := newWorkbenchHTTPHarness(t)
			now := time.Now()
			if err := h.db.InsertClient(h.ctx, store.ClientAccount{ID: 1001, TenantID: "t1", OwnerUsername: "alice", ClientName: "existing-client", PasswordHash: "preserved-hash", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
			if err := h.db.InsertCredential(h.ctx, store.ClientCredential{ID: 501, TenantID: "t1", OwnerUsername: "alice", APIKey: "existing-key", SecretHash: "preserved-secret", Enabled: true, MaxOnlineInstances: 7, CreatedAt: now, UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Body = &resourceWriteBarrierBody{ReadCloser: r.Body, entered: entered, release: release}
				h.server.Config.Handler.ServeHTTP(w, r)
			}))
			defer server.Close()
			defer unblock()
			ctx, cancel := context.WithTimeout(h.ctx, 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, scenario.method, server.URL+scenario.path, strings.NewReader(scenario.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+h.token("t1", "alice"))
			req.Header.Set("Content-Type", "application/json")
			type result struct {
				status int
				body   string
				err    error
			}
			done := make(chan result, 1)
			go func() {
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					done <- result{err: err}
					return
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				done <- result{resp.StatusCode, string(body), err}
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("request did not reach authenticated body barrier")
			}
			user, err := h.db.FindManagementUserByLogin(ctx, "t1", "alice")
			if err != nil || user == nil {
				t.Fatal(err)
			}
			user.Enabled = false
			if err := h.db.UpdateManagementUser(ctx, *user); err != nil {
				t.Fatal(err)
			}
			unblock()
			got := <-done
			if got.err != nil || got.status != http.StatusUnauthorized {
				t.Fatalf("revoked in-flight actor mutated resource: status=%d body=%s err=%v", got.status, got.body, got.err)
			}
			client, err := h.db.GetClient(ctx, 1001)
			if err != nil || !client.Enabled {
				t.Fatalf("rejected client mutation persisted: %+v / %v", client, err)
			}
			credential, err := h.db.GetCredential(ctx, 501)
			if err != nil || !credential.Enabled {
				t.Fatalf("rejected credential mutation persisted: %+v / %v", credential, err)
			}
			created, err := h.db.FindClientByName(ctx, "late-client")
			if err != nil || created != nil {
				t.Fatalf("rejected client created: %+v / %v", created, err)
			}
			createdCredential, err := h.db.FindCredentialByAPIKey(ctx, "late-key")
			if err != nil || createdCredential != nil {
				t.Fatalf("rejected credential created: %+v / %v", createdCredential, err)
			}
		})
	}
}
