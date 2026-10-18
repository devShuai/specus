package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/control"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func dataGenerationRoute(t *testing.T, f *generationFixture) string {
	t.Helper()
	account, err := f.app.db.FindClientByName(context.Background(), f.pub.ClientName)
	if err != nil || account == nil {
		t.Fatalf("publisher account: %v", err)
	}
	now := time.Now().UTC()
	if err := f.app.db.InsertHTTPRoute(context.Background(), store.HTTPRouteMapping{
		ID: auth.NewClientID(), TenantID: account.TenantID, ClientID: account.ID, ClientName: account.ClientName,
		Route: "generation", TargetBaseURL: "http://127.0.0.1:9", Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	return f.managementURL + "/http/" + url.PathEscape(f.pub.ClientName) + "/generation/health"
}

// A protocol device over the successor's real TCP data connection. It answers an HTTP
// OPEN only on that connection, so a 200 response also proves the selected namespace.
func serveGenerationSuccessor(data *generationWire) {
	go func() {
		for packet := range data.packets {
			message, ok := packet.(protocol.NatMessage)
			if !ok || message.Type != protocol.NatOpen || message.Metadata["source"] != "http" {
				continue
			}
			for _, response := range []protocol.NatMessage{
				{Type: protocol.NatOpen, StreamID: message.StreamID, Metadata: map[string]any{"source": "http", "phase": "response", "statusCode": 200, "headers": []string{"Content-Type:text/plain"}}},
				{Type: protocol.NatData, StreamID: message.StreamID, Data: []byte("successor-data-generation")},
				{Type: protocol.NatFin, StreamID: message.StreamID},
			} {
				if err := protocol.WritePacket(data.net, response); err != nil {
					return
				}
			}
		}
	}()
}

func assertGenerationHTTP(t *testing.T, target string) {
	t.Helper()
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(target)
	if err != nil {
		t.Fatalf("successor HTTP flow failed: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "successor-data-generation" {
		t.Fatalf("successor HTTP = %d %q err=%v", response.StatusCode, body, err)
	}
}

func TestDataGenerationQueuedOldDispatcherFrameCannotHijackHTTP(t *testing.T) {
	f := newGenerationFixture(t, 4)
	f.login(f.pub, protocol.ConnectionRoleControl)
	old := f.login(f.pub, protocol.ConnectionRoleData)
	successor := f.login(f.pub, protocol.ConnectionRoleData)
	f.app.dispatcher.OnDisconnect(old.server)
	if err := f.app.dispatcher.OnPacket(old.server, protocol.NatMessage{Type: protocol.NatKeepalive}); err == nil {
		t.Error("queued old DATA handler was admitted")
	}
	serveGenerationSuccessor(successor)
	assertGenerationHTTP(t, dataGenerationRoute(t, f))
}

func TestDataGenerationRawOldHandlerCannotReattachNamespace(t *testing.T) {
	f := newGenerationFixture(t, 4)
	f.login(f.pub, protocol.ConnectionRoleControl)
	old := f.login(f.pub, protocol.ConnectionRoleData)
	successor := f.login(f.pub, protocol.ConnectionRoleData)
	f.app.dispatcher.OnDisconnect(old.server)
	if err := f.app.dispatcher.natHandler(old.server, protocol.NatMessage{Type: protocol.NatKeepalive}); err == nil {
		t.Error("raw old NAT callback recreated its retired namespace")
	}
	serveGenerationSuccessor(successor)
	assertGenerationHTTP(t, dataGenerationRoute(t, f))
}

func TestDataGenerationOldRegisterCannotLeakPublicPort(t *testing.T) {
	f := newGenerationFixture(t, 4)
	f.login(f.pub, protocol.ConnectionRoleControl)
	old := f.login(f.pub, protocol.ConnectionRoleData)
	successor := f.login(f.pub, protocol.ConnectionRoleData)
	f.app.dispatcher.OnDisconnect(old.server)
	port := freeTCPPort(t)
	// Sending on the old closed socket may fail even after an unsafe handler has
	// registered a listener; assert the actual listener state, not just its error.
	_ = f.app.dispatcher.natHandler(old.server, protocol.NatMessage{Type: protocol.NatRegister, Metadata: map[string]any{
		"port": port, "specusPort": 9, "specusAddress": "127.0.0.1", "clientName": f.pub.ClientName,
	}})
	if f.app.remotePorts.HasBinding(port) {
		t.Error("retired REGISTER leaked a public listener")
	}
	serveGenerationSuccessor(successor)
	assertGenerationHTTP(t, dataGenerationRoute(t, f))
}

func TestDataGenerationAdmittedOldFrameCannotOvertakeNewAttachment(t *testing.T) {
	entered, release, completed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var selected atomic.Pointer[control.Conn]
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	f := newGenerationFixture(t, 4, func(app *App) {
		original := app.dispatcher.natHandler
		app.dispatcher.SetNatHandler(func(conn *control.Conn, message protocol.NatMessage) error {
			if conn == selected.Load() && message.Type == protocol.NatKeepalive {
				close(entered)
				<-release
				defer close(completed)
			}
			return original(conn, message)
		})
	})
	t.Cleanup(unblock)
	f.login(f.pub, protocol.ConnectionRoleControl)
	old := f.login(f.pub, protocol.ConnectionRoleData)
	selected.Store(old.server)
	if err := protocol.WritePacket(old.net, protocol.NatMessage{Type: protocol.NatKeepalive}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("old frame did not enter admitted handler")
	}
	// Retire this generation while its admitted callback is suspended, then attach
	// a successor. Replaying the teardown models a close callback ordered ahead
	// of work that was already admitted; it must not let that work recreate state.
	f.app.dispatcher.OnDisconnect(old.server)
	// A slow admitted frame must not hold the lifecycle lease across arbitrary I/O.
	// New data login and HTTP forwarding must work before the old handler is released.
	successor := f.login(f.pub, protocol.ConnectionRoleData)
	serveGenerationSuccessor(successor)
	target := dataGenerationRoute(t, f)
	assertGenerationHTTP(t, target)
	unblock()
	select {
	case <-completed:
	case <-time.After(3 * time.Second):
		t.Fatal("admitted old callback did not finish")
	}
	f.app.dispatcher.OnDisconnect(old.server)
	assertGenerationHTTP(t, target)
}

func TestDataGenerationSuccessorForwardsBeforeOldBrowserCleanupCompletes(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var selected atomic.Pointer[control.Conn]
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	f := newGenerationFixture(t, 4, func(app *App) {
		original := app.dispatcher.onDataBinding
		app.dispatcher.SetOnDataBinding(func(conn *control.Conn) func() {
			finish := original(conn)
			if old := selected.Load(); old != nil && old.ClientName() == conn.ClientName() {
				return func() {
					close(entered)
					<-release
					if finish != nil {
						finish()
					}
				}
			}
			return finish
		})
	})
	t.Cleanup(unblock)
	f.login(f.pub, protocol.ConnectionRoleControl)
	old := f.login(f.pub, protocol.ConnectionRoleData)
	selected.Store(old.server)
	successor := f.login(f.pub, protocol.ConnectionRoleData)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("old-browser cleanup was not reached")
	}
	serveGenerationSuccessor(successor)
	target := dataGenerationRoute(t, f)
	assertGenerationHTTP(t, target)
	unblock()
	assertGenerationHTTP(t, target)
}

func TestDataGenerationLoginResumePreservesLaterBackpressure(t *testing.T) {
	conn := &control.Conn{ReadGate: control.NewReadGate()}
	conn.ReadGate.Pause()
	resume := loginReadResume(conn)
	resume()
	if conn.ReadGate.IsPaused() {
		t.Fatal("login reader was not resumed")
	}
	conn.ReadGate.Pause() // New generation now has its own flow-control pause.
	resume()
	if !conn.ReadGate.IsPaused() {
		t.Fatal("old cleanup completion overrode new backpressure")
	}
	conn.ReadGate.Resume()
}

func TestDataGenerationHTTPFlowDoesNotWaitForControlLifecycleLease(t *testing.T) {
	f := newGenerationFixture(t, 4)
	f.login(f.pub, protocol.ConnectionRoleControl)
	data := f.login(f.pub, protocol.ConnectionRoleData)
	serveGenerationSuccessor(data)
	target := dataGenerationRoute(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	release, err := f.app.sessions.AcquireControlLease(ctx, f.pub.ClientName)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	// A control report/notification may be stalled elsewhere. Data WINDOW_UPDATE,
	// response HEAD/DATA/FIN must still progress while that lifecycle lease is held.
	assertGenerationHTTP(t, target)
}

func dataGenerationFrame(t *testing.T, data *generationWire, kind int) protocol.NatMessage {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case packet, ok := <-data.packets:
			if !ok {
				t.Fatal("data connection closed while waiting for frame")
			}
			if message, ok := packet.(protocol.NatMessage); ok && message.Type == kind {
				return message
			}
		case <-deadline:
			t.Fatalf("no data frame type %d", kind)
		}
	}
}

func TestDataGenerationReplacementReusesListenerAndTCPBudget(t *testing.T) {
	f := newGenerationFixture(t, 4)
	f.login(f.pub, protocol.ConnectionRoleControl)
	old := f.login(f.pub, protocol.ConnectionRoleData)
	port := freeTCPPort(t)
	register := protocol.NatMessage{Type: protocol.NatRegister, Metadata: map[string]any{"port": port, "specusPort": 9, "specusAddress": "127.0.0.1", "clientName": f.pub.ClientName}}
	if err := protocol.WritePacket(old.net, register); err != nil {
		t.Fatal(err)
	}
	if result := dataGenerationFrame(t, old, protocol.NatRegisterResult); result.Metadata["success"] != true {
		t.Fatalf("old registration failed: %#v", result)
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	external, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = external.Close() })
	dataGenerationFrame(t, old, protocol.NatOpen)
	if f.app.remotePorts.ActiveExternalConnections() != 1 {
		t.Fatal("old external did not reserve its TCP budget")
	}
	successor := f.login(f.pub, protocol.ConnectionRoleData)
	if f.app.remotePorts.ActiveExternalConnections() != 0 {
		t.Fatal("retired TCP budget survived successor login")
	}
	if err := protocol.WritePacket(successor.net, register); err != nil {
		t.Fatal(err)
	}
	if result := dataGenerationFrame(t, successor, protocol.NatRegisterResult); result.Metadata["success"] != true {
		t.Fatalf("successor could not reuse retired listener: %#v", result)
	}
	f.app.dispatcher.OnDisconnect(old.server)
	if !f.app.remotePorts.HasBinding(port) {
		t.Fatal("old close removed the successor's listener")
	}
	current, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = current.Close() })
	opened := dataGenerationFrame(t, successor, protocol.NatOpen)
	want := []byte("native-successor-TCP")
	if err := protocol.WritePacket(successor.net, protocol.NatMessage{Type: protocol.NatData, StreamID: opened.StreamID, Data: want}); err != nil {
		t.Fatal(err)
	}
	_ = current.SetReadDeadline(time.Now().Add(3 * time.Second))
	actual := make([]byte, len(want))
	if _, err := io.ReadFull(current, actual); err != nil || string(actual) != string(want) {
		t.Fatalf("successor TCP payload %q err=%v", actual, err)
	}
	_ = current.Close()
	if err := protocol.WritePacket(successor.net, protocol.NatMessage{Type: protocol.NatRST, StreamID: opened.StreamID}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for f.app.remotePorts.ActiveExternalConnections() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("successor TCP budget was not released")
		}
		time.Sleep(time.Millisecond)
	}
}
