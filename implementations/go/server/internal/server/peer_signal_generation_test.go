package server

import (
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/control"
	"github.com/devShuai/specus/implementations/go/server/internal/peermesh"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
)

func peerGenerationMessage(t *testing.T, wire *generationWire, kind string) peermesh.ControlMessage {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case packet, ok := <-wire.packets:
			if !ok {
				t.Fatal("original control connection closed")
			}
			if response, ok := packet.(protocol.MessageResponse); ok {
				var message peermesh.ControlMessage
				if err := json.Unmarshal([]byte(response.Message), &message); err != nil {
					t.Fatal(err)
				}
				if message.Type == kind {
					return message
				}
			}
		case <-deadline:
			t.Fatalf("no %s on original physical control", kind)
		}
	}
}

func TestPeerSignalGenerationHoldsBothOriginalControlsThroughHandler(t *testing.T) {
	type observation struct{ source, target error }
	observed := make(chan observation, 1)
	f := newGenerationFixture(t, 4, func(app *App) {
		original := app.dispatcher.peerControl
		app.dispatcher.SetPeerControlHandler(func(conn *control.Conn, request protocol.MessageRequest) error {
			probe := func(name string) error {
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
				release, err := app.sessions.AcquireControlLease(ctx, name)
				if err == nil {
					release()
				}
				return err
			}
			// Observe the real lifecycle gates from the actual transport handler, not a
			// sleep before login or a mocked registry. A free target gate returns immediately.
			observed <- observation{probe(conn.ClientName()), probe(strings.TrimSpace(request.ToClientName))}
			return original(conn, request)
		})
	})
	source := f.login(f.pub, protocol.ConnectionRoleControl)
	request := protocol.MessageRequest{
		ToClientName: "  " + f.recipient.ClientName + "  ", MessageType: protocol.MessageTypePeerControl,
		Message: `{"type":"candidates","candidates":[{"type":"host","transport":"udp","address":"192.0.2.1","port":53000}]}`,
	}
	if err := protocol.WritePacket(source.net, request); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-observed:
		if !errors.Is(result.source, context.DeadlineExceeded) || !errors.Is(result.target, context.DeadlineExceeded) {
			t.Errorf("native handler did not retain both original controls: source=%v target=%v", result.source, result.target)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("actual Peer route did not reach handler")
	}
	grant := peerGenerationMessage(t, source, peermesh.TypeSessionGrant)
	forwarded := peerGenerationMessage(t, f.consumer, peermesh.TypeCandidates)
	if grant.SessionID == nil || grant.Token == "" || forwarded.SessionID == nil || *grant.SessionID != *forwarded.SessionID || grant.Token != forwarded.Token {
		t.Fatalf("native grant/forwarded identity mismatch: %+v / %+v", grant, forwarded)
	}
	if !f.app.sessions.IsBound(source.server) || !f.app.sessions.IsBound(f.consumer.server) {
		t.Fatal("valid negotiation replaced an original control")
	}
	f.heartbeat(source)
	f.heartbeat(f.consumer)
}

func TestPeerSignalGenerationTargetLogoutWaitsForInFlightSignal(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	f := newGenerationFixture(t, 4, func(app *App) {
		original := app.dispatcher.peerControl
		app.dispatcher.SetPeerControlHandler(func(conn *control.Conn, request protocol.MessageRequest) error {
			close(entered)
			<-release
			return original(conn, request)
		})
	})
	t.Cleanup(unblock)
	source := f.login(f.pub, protocol.ConnectionRoleControl)
	if err := protocol.WritePacket(source.net, protocol.MessageRequest{
		ToClientName: f.recipient.ClientName, MessageType: protocol.MessageTypePeerControl,
		Message: `{"type":"candidates"}`,
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("signal did not enter actual handler")
	}
	if err := protocol.WritePacket(f.consumer.net, protocol.LogoutRequest{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(150 * time.Millisecond)
	waiting := true
	for waiting {
		select {
		case packet, ok := <-f.consumer.packets:
			if !ok {
				t.Fatal("target closed during admitted signal")
			}
			if _, ok := packet.(protocol.LogoutResponse); ok {
				t.Error("target logout overtook admitted signal")
				waiting = false
			}
		case <-deadline:
			waiting = false
		}
	}
	if !f.app.sessions.IsBound(f.consumer.server) {
		t.Error("target unbound while its signal lifecycle lease was held")
	}
	unblock()
	peerGenerationMessage(t, source, peermesh.TypeSessionGrant)
	// The original target receives the admitted signal before its own logout response.
	peerGenerationMessage(t, f.consumer, peermesh.TypeCandidates)
	for {
		select {
		case packet, ok := <-f.consumer.packets:
			if !ok {
				t.Fatal("target closed without logout response")
			}
			if _, ok := packet.(protocol.LogoutResponse); ok {
				f.heartbeat(source)
				return
			}
		case <-time.After(3 * time.Second):
			t.Fatal("target logout did not resume after signal completion")
		}
	}
}

func TestPeerSignalGenerationOppositeDirectionsRetainBothPhysicalControls(t *testing.T) {
	f := newGenerationFixture(t, 4)
	source := f.login(f.pub, protocol.ConnectionRoleControl)
	start := make(chan struct{})
	errors := make(chan error, 2)
	for _, pair := range []struct {
		wire *generationWire
		to   string
	}{{source, f.recipient.ClientName}, {f.consumer, f.pub.ClientName}} {
		go func() {
			<-start
			errors <- protocol.WritePacket(pair.wire.net, protocol.MessageRequest{
				ToClientName: pair.to, MessageType: protocol.MessageTypePeerControl, Message: `{"type":"candidates"}`,
			})
		}()
	}
	close(start)
	for range 2 {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	for _, wire := range []*generationWire{source, f.consumer} {
		seen := map[string]bool{}
		deadline := time.After(5 * time.Second)
		for !seen[peermesh.TypeSessionGrant] || !seen[peermesh.TypeCandidates] {
			select {
			case packet, ok := <-wire.packets:
				if !ok {
					t.Fatal("opposite-direction signal closed an original control")
				}
				if response, ok := packet.(protocol.MessageResponse); ok {
					var message peermesh.ControlMessage
					if err := json.Unmarshal([]byte(response.Message), &message); err != nil {
						t.Fatal(err)
					}
					seen[message.Type] = true
				}
			case <-deadline:
				t.Fatalf("opposite-direction negotiation stalled: %v", seen)
			}
		}
		if !f.app.sessions.IsBound(wire.server) {
			t.Fatal("negotiation replaced a physical control")
		}
		f.heartbeat(wire)
	}
}

func TestPeerSignalGenerationDataLogoutPreservesCompanionControl(t *testing.T) {
	f := newGenerationFixture(t, 4)
	control := f.login(f.pub, protocol.ConnectionRoleControl)
	data := f.login(f.pub, protocol.ConnectionRoleData)
	if err := protocol.WritePacket(data.net, protocol.LogoutRequest{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(3 * time.Second)
	for {
		select {
		case packet, ok := <-data.packets:
			if !ok {
				t.Fatal("valid original DATA logout closed without its success response")
			}
			if answer, ok := packet.(protocol.LogoutResponse); ok {
				if !answer.Success {
					t.Fatal("valid original DATA logout was rejected")
				}
				if _, found := f.app.sessions.FindData(f.pub.ClientName); found {
					t.Fatal("DATA logout did not detach its own binding")
				}
				if !f.app.sessions.IsBound(control.server) {
					t.Fatal("DATA logout detached the companion CONTROL")
				}
				f.heartbeat(control)
				return
			}
		case <-deadline:
			t.Fatal("valid original DATA logout did not complete")
		}
	}
}

func TestPeerSignalGenerationUnresolvedTargetDoesNotSkipServerHandling(t *testing.T) {
	for _, scenario := range []string{"device-report", "close", "invalid-json", "server-only"} {
		t.Run(scenario, func(t *testing.T) {
			completed := make(chan error, 1)
			f := newGenerationFixture(t, 4, func(app *App) {
				original := app.dispatcher.peerControl
				app.dispatcher.SetPeerControlHandler(func(conn *control.Conn, request protocol.MessageRequest) error {
					err := original(conn, request)
					if strings.TrimSpace(request.ToClientName) == "missing-peer-name" {
						completed <- err
					}
					return err
				})
			})
			source := f.login(f.pub, protocol.ConnectionRoleControl)
			body := `{"type":"device-report","natType":"symmetric"}`
			var sessionID int64
			switch scenario {
			case "close":
				if err := protocol.WritePacket(source.net, protocol.MessageRequest{
					ToClientName: f.recipient.ClientName, MessageType: protocol.MessageTypePeerControl, Message: `{"type":"candidates"}`,
				}); err != nil {
					t.Fatal(err)
				}
				grant := peerGenerationMessage(t, source, peermesh.TypeSessionGrant)
				peerGenerationMessage(t, f.consumer, peermesh.TypeCandidates)
				if grant.SessionID == nil {
					t.Fatal("no native grant for close fixture")
				}
				sessionID = *grant.SessionID
				encoded, err := json.Marshal(peermesh.ControlMessage{Type: peermesh.TypeClose, SessionID: &sessionID})
				if err != nil {
					t.Fatal(err)
				}
				body = string(encoded)
			case "invalid-json":
				body = "{"
			case "server-only":
				body = `{"type":"service-catalog"}`
			}
			if err := protocol.WritePacket(source.net, protocol.MessageRequest{
				ToClientName: "missing-peer-name", MessageType: protocol.MessageTypePeerControl, Message: body,
			}); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-completed:
				invalid := scenario == "invalid-json" || scenario == "server-only"
				if invalid != (err != nil) {
					t.Fatalf("unresolved target changed protocol outcome: scenario=%s err=%v", scenario, err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("target prelookup bypassed server-side Peer handling")
			}
			if scenario == "device-report" {
				account, err := f.app.db.FindClientByName(context.Background(), f.pub.ClientName)
				if err != nil || account == nil {
					t.Fatal(err)
				}
				device, err := f.app.db.FindPeerMeshDeviceByClientID(context.Background(), account.TenantID, account.ID)
				if err != nil || device == nil || device.NatType == nil || *device.NatType != "symmetric" {
					t.Fatalf("unresolved target dropped valid device report: %+v / %v", device, err)
				}
			}
			if scenario == "close" {
				row, err := f.app.db.GetPeerMeshSession(context.Background(), sessionID)
				if err != nil || row.Status != peermesh.StatusClosed {
					t.Fatalf("unresolved target dropped valid session close: %+v / %v", row, err)
				}
			}
			if scenario == "device-report" || scenario == "close" {
				f.heartbeat(source)
			}
		})
	}
}

func TestPeerSignalGenerationServerBoundReportDoesNotLeaseItsToName(t *testing.T) {
	type result struct{ probe, handler error }
	completed := make(chan result, 1)
	f := newGenerationFixture(t, 4, func(app *App) {
		original := app.dispatcher.peerControl
		app.dispatcher.SetPeerControlHandler(func(conn *control.Conn, request protocol.MessageRequest) error {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			release, probe := app.sessions.AcquireControlLease(ctx, strings.TrimSpace(request.ToClientName))
			if probe == nil {
				release()
			}
			err := original(conn, request)
			completed <- result{probe, err}
			return err
		})
	})
	source := f.login(f.pub, protocol.ConnectionRoleControl)
	stripe := func(name string) uint32 { h := fnv.New32a(); _, _ = h.Write([]byte(name)); return h.Sum32() % 256 }
	to := "not-a-report-target"
	for i := 0; stripe(to) == stripe(f.pub.ClientName); i++ {
		to = "not-a-report-target-" + strconv.Itoa(i)
	}
	if err := protocol.WritePacket(source.net, protocol.MessageRequest{
		ToClientName: to, MessageType: protocol.MessageTypePeerControl, Message: `{"type":"device-report","natType":"symmetric"}`,
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-completed:
		if result.probe != nil || result.handler != nil {
			t.Fatalf("server-bound report participated in unrelated target lifecycle: probe=%v handler=%v", result.probe, result.handler)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server-bound report stalled")
	}
	f.heartbeat(source)
}

func TestPeerSignalGenerationRejectsForgedServerConfig(t *testing.T) {
	for _, kind := range []string{peermesh.TypeConfig, peermesh.TypeRoster, peermesh.TypeSessionGrant, "PEER-CONFIG", " roster "} {
		t.Run(kind, func(t *testing.T) {
			completed := make(chan error, 1)
			f := newGenerationFixture(t, 4, func(app *App) {
				original := app.dispatcher.peerControl
				app.dispatcher.SetPeerControlHandler(func(conn *control.Conn, request protocol.MessageRequest) error {
					err := original(conn, request)
					completed <- err
					return err
				})
			})
			source := f.login(f.pub, protocol.ConnectionRoleControl)
			body, err := json.Marshal(map[string]any{"type": kind, "token": "client-forged", "enabled": true})
			if err != nil {
				t.Fatal(err)
			}
			if err := protocol.WritePacket(source.net, protocol.MessageRequest{
				ToClientName: f.recipient.ClientName, MessageType: protocol.MessageTypePeerControl, Message: string(body),
			}); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-completed:
				if err == nil {
					t.Fatal("client-originated server-only configuration was accepted")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("forged configuration did not reach protocol admission")
			}
			f.heartbeat(f.consumer)
		})
	}
}

func TestPeerSignalGenerationCloseNotifiesStoredParticipantsNotRequestedThirdParty(t *testing.T) {
	completed := make(chan error, 1)
	f := newGenerationFixture(t, 4, func(app *App) {
		original := app.dispatcher.peerControl
		app.dispatcher.SetPeerControlHandler(func(conn *control.Conn, request protocol.MessageRequest) error {
			err := original(conn, request)
			var message peermesh.ControlMessage
			_ = json.Unmarshal([]byte(request.Message), &message)
			if message.Type == peermesh.TypeClose {
				completed <- err
			}
			return err
		})
	})
	source := f.login(f.pub, protocol.ConnectionRoleControl)
	thirdLogin := clientAuthLoginWithEnvironmentForTest(t, f.managementURL, "ck_generation", "generation-secret", "generation-third-party", "admin", nil)
	thirdAccount, err := f.app.db.FindClientByName(context.Background(), thirdLogin.ClientName)
	if err != nil || thirdAccount == nil {
		t.Fatal(err)
	}
	on := true
	if _, err := f.app.peerMesh.UpdateDevice(context.Background(), peermesh.AccessContext{Username: "admin", TenantID: "default", Admin: true, BuiltIn: true}, thirdAccount.ID, peermesh.DeviceMutation{Enabled: &on}); err != nil {
		t.Fatal(err)
	}
	third := f.login(thirdLogin, protocol.ConnectionRoleControl)
	if err := protocol.WritePacket(source.net, protocol.MessageRequest{ToClientName: f.recipient.ClientName, MessageType: protocol.MessageTypePeerControl, Message: `{"type":"candidates"}`}); err != nil {
		t.Fatal(err)
	}
	grant := peerGenerationMessage(t, source, peermesh.TypeSessionGrant)
	peerGenerationMessage(t, f.consumer, peermesh.TypeCandidates)
	body, err := json.Marshal(peermesh.ControlMessage{Type: peermesh.TypeClose, SessionID: grant.SessionID, TargetClientID: thirdAccount.ID, TargetClientName: thirdAccount.ClientName, Token: "client-input-must-not-forward"})
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WritePacket(source.net, protocol.MessageRequest{ToClientName: thirdLogin.ClientName, MessageType: protocol.MessageTypePeerControl, Message: string(body)}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-completed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("native close did not complete")
	}
	// This barrier is the real handler's return, after every intended socket write.
	row, err := f.app.db.GetPeerMeshSession(context.Background(), *grant.SessionID)
	if err != nil || row.Status != peermesh.StatusClosed {
		t.Fatalf("close did not persist: %+v / %v", row, err)
	}
	for _, wire := range []*generationWire{source, f.consumer} {
		message := peerGenerationMessage(t, wire, peermesh.TypeClose)
		if message.SessionID == nil || *message.SessionID != *grant.SessionID || message.SourceClientID != row.SourceClientID || message.TargetClientID != row.TargetClientID || message.Token != "" || message.Reason != "peer-close" {
			t.Fatalf("close trusted requested third party or client token: %+v", message)
		}
	}
	deadline := time.After(100 * time.Millisecond)
	for {
		select {
		case packet, ok := <-third.packets:
			if !ok {
				t.Fatal("unrelated third party control closed")
			}
			if response, ok := packet.(protocol.MessageResponse); ok {
				var message peermesh.ControlMessage
				_ = json.Unmarshal([]byte(response.Message), &message)
				if message.Type == peermesh.TypeClose {
					t.Fatal("close notification leaked to the client-requested third party")
				}
			}
		case <-deadline:
			f.heartbeat(source)
			f.heartbeat(f.consumer)
			f.heartbeat(third)
			return
		}
	}
}
