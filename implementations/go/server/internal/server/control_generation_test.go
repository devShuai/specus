package server

import (
	"bufio"
	"context"
	"encoding/json"
	"math"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/control"
	"github.com/devShuai/specus/implementations/go/server/internal/peermesh"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
)

type generationWire struct {
	net     net.Conn
	server  *control.Conn
	packets chan protocol.Packet
}

type generationFixture struct {
	t              *testing.T
	app            *App
	pub, recipient clientAuthLoginForTestResponse
	consumer       *generationWire
	serviceID      string
	managementURL  string
}

func newGenerationFixture(t *testing.T, machineLimit int, beforeStart ...func(*App)) *generationFixture {
	t.Helper()
	cfg := config.Default()
	cfg.PeerMesh.Enabled = true
	cfg.ClientAuth.PerMachineUserMaxInstances = machineLimit
	app, _ := startTestAppWithConfig(t, cfg, beforeStart...)
	_, ts := newHTTPTestServer(t, app)
	insertCredentialForTest(t, app, "default", "admin", "ck_generation", "generation-secret", 8)
	environment := map[string]any{"clientPeerServiceCapabilities": map[string]any{"version": 2, "applications": []string{"http"}}}
	f := &generationFixture{t: t, app: app, managementURL: ts.URL}
	f.pub = clientAuthLoginWithEnvironmentForTest(t, ts.URL, "ck_generation", "generation-secret", "generation-publisher", "admin", environment)
	f.recipient = clientAuthLoginWithEnvironmentForTest(t, ts.URL, "ck_generation", "generation-secret", "generation-recipient", "admin", environment)
	ctx := context.Background()
	access := peermesh.AccessContext{TenantID: "default", Username: "admin", Admin: true, BuiltIn: true}
	for _, login := range []clientAuthLoginForTestResponse{f.pub, f.recipient} {
		account, err := app.db.FindClientByName(ctx, login.ClientName)
		if err != nil || account == nil {
			t.Fatalf("account: %v", err)
		}
		on := true
		if _, err := app.peerMesh.UpdateDevice(ctx, access, account.ID, peermesh.DeviceMutation{Enabled: &on}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := app.peerMesh.SetSharing(ctx, access, true); err != nil {
		t.Fatal(err)
	}
	account, err := app.db.FindClientByName(ctx, f.pub.ClientName)
	if err != nil {
		t.Fatal(err)
	}
	name, application, host := "generation-http", "http", "127.0.0.1"
	port, published, on := 8080, 18080, true
	service, err := app.peerMesh.CreateSharedService(ctx, access, peermesh.ServiceMutation{ClientID: &account.ID, Name: &name, Application: &application, TargetHost: &host, TargetPort: &port, PublishedPort: &published})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.peerMesh.UpdateSharedService(ctx, access, service.ID, peermesh.ServiceMutation{Enabled: &on}); err != nil {
		t.Fatal(err)
	}
	f.serviceID = service.ServiceID
	f.consumer = f.login(f.recipient, protocol.ConnectionRoleControl)
	return f
}

func (f *generationFixture) login(login clientAuthLoginForTestResponse, role string) *generationWire {
	f.t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(f.app.ControlPort())), 3*time.Second)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = conn.Close() })
	request := protocol.LoginRequest{ClientName: login.ClientName, ClientSessionID: login.ClientSessionID, AccessToken: login.AccessToken, ConnectionRole: role}
	if err := protocol.WritePacket(conn, request); err != nil {
		f.t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	packet, err := readProtocolPacket(reader)
	if err != nil {
		f.t.Fatalf("%s login read: %v", role, err)
	}
	answer, ok := packet.(protocol.LoginResponse)
	if !ok || !answer.Success {
		f.t.Fatalf("%s login rejected: %#v", role, packet)
	}
	_ = conn.SetReadDeadline(time.Time{})
	bound, found := f.app.sessions.Find(login.ClientName)
	if role == protocol.ConnectionRoleData {
		bound, found = f.app.sessions.FindData(login.ClientName)
	}
	if !found {
		f.t.Fatal("login response preceded registration")
	}
	server, ok := bound.(*control.Conn)
	if !ok {
		f.t.Fatalf("unexpected bound transport %T", bound)
	}
	wire := &generationWire{net: conn, server: server, packets: make(chan protocol.Packet, 128)}
	f.collect(wire, reader)
	return wire
}

func (f *generationFixture) collect(wire *generationWire, reader *bufio.Reader) {
	readerContext, stop := context.WithCancel(context.Background())
	f.t.Cleanup(stop)
	go func() {
		defer close(wire.packets)
		for {
			packet, err := readProtocolPacket(reader)
			if err != nil {
				return
			}
			select {
			case wire.packets <- packet:
			case <-readerContext.Done():
				return
			}
		}
	}()
}

func (f *generationFixture) report(wire *generationWire, revision int64) protocol.MessageRequest {
	f.t.Helper()
	body, err := json.Marshal(map[string]any{"type": "service-report", "enabled": true, "revision": revision, "services": []map[string]any{{"serviceId": f.serviceID}}})
	if err != nil {
		f.t.Fatal(err)
	}
	request := protocol.MessageRequest{MessageType: protocol.MessageTypePeerControl, Message: string(body)}
	if err := protocol.WritePacket(wire.net, request); err != nil {
		f.t.Fatal(err)
	}
	return request
}

func (f *generationFixture) catalog(count int) int64 {
	f.t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case packet, ok := <-f.consumer.packets:
			if !ok {
				f.t.Fatal("consumer connection closed")
			}
			response, ok := packet.(protocol.MessageResponse)
			if !ok {
				continue
			}
			var message peermesh.ControlMessage
			if err := json.Unmarshal([]byte(response.Message), &message); err != nil {
				f.t.Fatal(err)
			}
			if message.Type != peermesh.TypeServiceCatalog {
				continue
			}
			if message.PublisherSessionID == nil || *message.PublisherSessionID != f.pub.ClientSessionID {
				continue
			}
			if message.Revision == nil || *message.Revision < 1 || len(message.Services) != count {
				f.t.Fatalf("want %d services: %s", count, response.Message)
			}
			return *message.Revision
		case <-deadline:
			f.t.Fatalf("no catalog with %d services after actual transport lifecycle", count)
		}
	}
}

func (f *generationFixture) heartbeat(wire *generationWire) {
	f.t.Helper()
	if err := protocol.WritePacket(wire.net, protocol.HeartbeatRequest{}); err != nil {
		f.t.Fatal(err)
	}
	deadline := time.After(3 * time.Second)
	for {
		select {
		case packet, ok := <-wire.packets:
			if !ok {
				f.t.Fatal("replacement connection was closed")
			}
			if _, ok := packet.(protocol.HeartbeatResponse); ok {
				return
			}
		case <-deadline:
			f.t.Fatal("replacement heartbeat timed out")
		}
	}
}

func TestControlGenerationCurrentCloseWithdrawsWithoutDataConnection(t *testing.T) {
	f := newGenerationFixture(t, 4)
	publisher := f.login(f.pub, protocol.ConnectionRoleControl)
	f.report(publisher, 1)
	first := f.catalog(1)
	_ = publisher.net.Close()
	if withdrawal := f.catalog(0); withdrawal <= first {
		t.Fatal("withdrawal did not advance output clock")
	}
}

func TestControlGenerationDataCloseDoesNotRetirePublisher(t *testing.T) {
	f := newGenerationFixture(t, 4)
	publisher := f.login(f.pub, protocol.ConnectionRoleControl)
	f.report(publisher, 1)
	f.catalog(1)
	data := f.login(f.pub, protocol.ConnectionRoleData)
	_ = data.net.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, found := f.app.sessions.FindData(f.pub.ClientName); !found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("data close was not observed")
		}
		time.Sleep(time.Millisecond)
	}
	f.heartbeat(publisher)
	f.report(publisher, 2)
	f.catalog(1)
	row, err := f.app.db.GetClientSession(context.Background(), f.pub.ClientSessionID)
	if err != nil || row.Status != auth.StatusNettyOnline {
		t.Fatalf("data close retired authenticated control: %+v %v", row, err)
	}
}

func TestControlGenerationLateOldCloseAndQueuedReportCannotAffectSuccessor(t *testing.T) {
	f := newGenerationFixture(t, 4)
	old := f.login(f.pub, protocol.ConnectionRoleControl)
	f.login(f.pub, protocol.ConnectionRoleData)
	stale := f.report(old, math.MaxInt64-1)
	first := f.catalog(1)
	successor := f.login(f.pub, protocol.ConnectionRoleControl)
	data := f.login(f.pub, protocol.ConnectionRoleData)
	// Replay the actual old handler after its successor and companion have been published.
	f.app.dispatcher.OnDisconnect(old.server)
	row, err := f.app.db.GetClientSession(context.Background(), f.pub.ClientSessionID)
	if err != nil || row.Status != auth.StatusNettyOnline || row.ChannelID == nil || *row.ChannelID != successor.server.ChannelID() {
		t.Fatalf("old close changed current native binding: %+v %v", row, err)
	}
	if cached, ok := f.app.clientAuth.Find(f.pub.ClientSessionID, f.pub.AccessToken); !ok || cached.Status != auth.StatusNettyOnline {
		t.Fatal("old close invalidated current auth cache")
	}
	if bound, _ := f.app.sessions.FindData(f.pub.ClientName); bound != data.server {
		t.Fatal("old close detached replacement data")
	}
	f.heartbeat(successor)
	f.heartbeat(data)
	if revision := f.catalog(0); revision <= first {
		t.Fatal("replaced publisher did not withdraw")
	}
	f.report(successor, 1)
	current := f.catalog(1)
	if current <= first {
		t.Fatal("new physical publisher reused output revision")
	}
	if err := f.app.dispatcher.OnPacket(old.server, stale); err == nil {
		t.Fatal("queued old report was admitted as current publisher")
	}
	f.report(successor, 2)
	if revision := f.catalog(1); revision <= current {
		t.Fatal("old report poisoned successor dedupe cursor")
	}
}

func TestControlGenerationReplacementDoesNotConsumeAnotherMachineSlot(t *testing.T) {
	f := newGenerationFixture(t, 1)
	f.login(f.pub, protocol.ConnectionRoleControl)
	successor := f.login(f.pub, protocol.ConnectionRoleControl)
	f.heartbeat(successor)
}

func TestControlGenerationOfflineMarkAndWithdrawalCannotBeOvertakenByNewLogin(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var selected atomic.Pointer[control.Conn]
	f := newGenerationFixture(t, 4, func(app *App) {
		original := app.dispatcher.onControlGone
		app.dispatcher.SetOnControlGone(func(conn *control.Conn) {
			if conn == selected.Load() {
				close(entered)
				<-release
			}
			original(conn)
		})
	})
	t.Cleanup(unblock)
	old := f.login(f.pub, protocol.ConnectionRoleControl)
	selected.Store(old.server)
	f.report(old, math.MaxInt64-1)
	first := f.catalog(1)
	_ = old.net.Close()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("old close did not reach post-offline withdrawal")
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(f.app.ControlPort())), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := protocol.WritePacket(conn, protocol.LoginRequest{ClientName: f.pub.ClientName, ClientSessionID: f.pub.ClientSessionID, AccessToken: f.pub.AccessToken, ConnectionRole: protocol.ConnectionRoleControl}); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err := readProtocolPacket(reader); err == nil {
		t.Fatal("new login published before old offline/catalog teardown completed")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("competing login: %v", err)
	}
	unblock()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	packet, err := readProtocolPacket(reader)
	if err != nil {
		t.Fatal(err)
	}
	if answer, ok := packet.(protocol.LoginResponse); !ok || !answer.Success {
		t.Fatalf("successor after release: %#v", packet)
	}
	_ = conn.SetReadDeadline(time.Time{})
	bound, _ := f.app.sessions.Find(f.pub.ClientName)
	wire := &generationWire{net: conn, server: bound.(*control.Conn), packets: make(chan protocol.Packet, 128)}
	f.collect(wire, reader)
	if revision := f.catalog(0); revision <= first {
		t.Fatal("old current control did not withdraw")
	}
	f.report(wire, 1)
	if revision := f.catalog(1); revision <= first {
		t.Fatal("new report lost after interleaved old teardown")
	}
	f.heartbeat(wire)
}

func TestControlGenerationNativeDisconnectPredicateIsAtomicAndIdempotent(t *testing.T) {
	f := newGenerationFixture(t, 4)
	wire := f.login(f.pub, protocol.ConnectionRoleControl)
	ctx := context.Background()
	for _, candidate := range []struct {
		id      int64
		channel string
	}{{0, wire.server.ChannelID()}, {f.pub.ClientSessionID, ""}, {f.pub.ClientSessionID, "old-channel"}, {-1, "old-channel"}} {
		changed, err := f.app.db.MarkClientSessionDisconnectedForChannel(ctx, candidate.id, candidate.channel, auth.StatusDisconnected, time.Now())
		if err != nil || changed {
			t.Fatalf("foreign/invalid close changed session: %+v %v", candidate, err)
		}
	}
	row, err := f.app.db.GetClientSession(ctx, f.pub.ClientSessionID)
	if err != nil || row.Status != auth.StatusNettyOnline || row.DisconnectedAt != nil {
		t.Fatalf("invalid close changed native row: %+v %v", row, err)
	}
	// Native storage uses the shared seven-fractional-digit (100ns) timestamp format.
	when := time.Now().UTC().Truncate(100 * time.Nanosecond)
	changed, err := f.app.db.MarkClientSessionDisconnectedForChannel(ctx, f.pub.ClientSessionID, wire.server.ChannelID(), auth.StatusDisconnected, when)
	if err != nil || !changed {
		t.Fatalf("current native close rejected: %v", err)
	}
	changed, err = f.app.db.MarkClientSessionDisconnectedForChannel(ctx, f.pub.ClientSessionID, wire.server.ChannelID(), auth.StatusDisconnected, when.Add(time.Hour))
	if err != nil || changed {
		t.Fatalf("duplicate native close was applied again: %v", err)
	}
	row, err = f.app.db.GetClientSession(ctx, f.pub.ClientSessionID)
	if err != nil || row.Status != auth.StatusDisconnected || row.DisconnectedAt == nil || !row.DisconnectedAt.Equal(when) {
		t.Fatalf("native close lost original timestamp: %+v %v", row, err)
	}
}

func TestControlGenerationDifferentAuthSuccessorStillRetiresOldPublisher(t *testing.T) {
	for _, alreadyOffline := range []bool{false, true} {
		t.Run(strconv.FormatBool(alreadyOffline), func(t *testing.T) {
			f := newGenerationFixture(t, 4)
			old := f.login(f.pub, protocol.ConnectionRoleControl)
			f.report(old, 1)
			first := f.catalog(1)
			if alreadyOffline {
				if err := f.app.db.MarkClientSessionDisconnected(context.Background(), f.pub.ClientSessionID, auth.StatusDisconnected, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			login := clientAuthLoginWithEnvironmentForTest(t, f.managementURL, "ck_generation", "generation-secret", "generation-publisher", "admin", map[string]any{"clientPeerServiceCapabilities": map[string]any{"version": 2, "applications": []string{"http"}}})
			if login.ClientSessionID == f.pub.ClientSessionID || login.ClientName != f.pub.ClientName {
				t.Fatal("HTTP restart did not issue a fresh auth session for same device")
			}
			successor := f.login(login, protocol.ConnectionRoleControl)
			data := f.login(login, protocol.ConnectionRoleData)
			f.app.dispatcher.OnDisconnect(old.server)
			if revision := f.catalog(0); revision <= first {
				t.Fatal("old authenticated publisher was not retired")
			}
			f.heartbeat(successor)
			f.heartbeat(data)
			if previous, ok := f.app.clientAuth.Find(f.pub.ClientSessionID, f.pub.AccessToken); !ok || previous.Status != auth.StatusDisconnected {
				t.Fatal("old auth instance leaked an online quota slot")
			}
			row, err := f.app.db.GetClientSession(context.Background(), login.ClientSessionID)
			if err != nil || row.Status != auth.StatusNettyOnline {
				t.Fatalf("different-ID successor was retired: %+v %v", row, err)
			}
		})
	}
}
