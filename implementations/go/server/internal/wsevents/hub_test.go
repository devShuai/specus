package wsevents

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestHubPublishesAndDeliversClusterManagementEvents(t *testing.T) {
	serverConn := make(chan *websocket.Conn, 1)
	serverDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		serverConn <- conn
		<-serverDone
		_ = conn.Close(websocket.StatusNormalClosure, "done")
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial test websocket: %v", err)
	}
	defer client.Close(websocket.StatusNormalClosure, "done")
	accepted := <-serverConn
	defer close(serverDone)

	var receiveCluster func([]byte)
	published := make(chan struct {
		tenant  string
		payload []byte
	}, 1)
	reported := make(chan error, 1)
	hub := NewHub(nil, nil)
	hub.mu.Lock()
	hub.sockets[accepted] = Access{TenantID: "tenant-a", Admin: true}
	hub.mu.Unlock()
	hub.ConfigureCluster(ClusterTransport{
		Publish: func(_ context.Context, tenant string, payload []byte) error {
			published <- struct {
				tenant  string
				payload []byte
			}{tenant: tenant, payload: append([]byte(nil), payload...)}
			return nil
		},
		Subscribe: func(listener func([]byte)) {
			receiveCluster = listener
		},
		Report: func(err error) {
			reported <- err
		},
	})

	event := Event{
		TenantID: "tenant-a",
		Type:     "created",
		Connection: ConnectionView{
			ID:         7,
			ClientName: "alpha",
			Success:    true,
		},
	}
	hub.Broadcast(event)

	var outbound []byte
	select {
	case publication := <-published:
		if publication.tenant != event.TenantID {
			t.Fatalf("published tenant = %q, want %q", publication.tenant, event.TenantID)
		}
		outbound = publication.payload
	case <-ctx.Done():
		t.Fatal("management event was not published to the cluster")
	}
	if receiveCluster == nil {
		t.Fatal("cluster subscription was not registered")
	}
	receiveCluster(outbound)

	_, delivered, err := client.Read(ctx)
	if err != nil {
		t.Fatalf("read clustered management event: %v", err)
	}
	var decoded Event
	if err := json.Unmarshal(delivered, &decoded); err != nil {
		t.Fatalf("decode clustered management event: %v", err)
	}
	if decoded.TenantID != event.TenantID || decoded.Type != event.Type || decoded.Connection.ID != 7 {
		t.Fatalf("unexpected clustered management event: %+v", decoded)
	}

	receiveCluster([]byte(`{"tenantId":"","type":"created","connection":{"id":8}}`))
	select {
	case report := <-reported:
		if report.Error() != "invalid management cluster event payload" {
			t.Fatalf("unexpected cluster validation error: %v", report)
		}
	case <-ctx.Done():
		t.Fatal("invalid management event was not reported")
	}

	hub.mu.Lock()
	hub.cluster.Publish = func(context.Context, string, []byte) error {
		return errors.New("redis unavailable")
	}
	hub.mu.Unlock()
	event.Type = "updated"
	hub.Broadcast(event)
	select {
	case report := <-reported:
		if report.Error() != "redis unavailable" {
			t.Fatalf("unexpected publish failure: %v", report)
		}
	case <-ctx.Done():
		t.Fatal("cluster publish failure was not reported")
	}
	_, delivered, err = client.Read(ctx)
	if err != nil {
		t.Fatalf("read local fallback event: %v", err)
	}
	if err := json.Unmarshal(delivered, &decoded); err != nil {
		t.Fatalf("decode local fallback event: %v", err)
	}
	if decoded.Type != "updated" {
		t.Fatalf("fallback event type = %q, want updated", decoded.Type)
	}
}
