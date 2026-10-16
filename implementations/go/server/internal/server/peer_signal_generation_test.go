package server

import (
	"context"
	"encoding/json"
	"errors"
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
