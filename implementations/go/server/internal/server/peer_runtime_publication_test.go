package server

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/control"
	"github.com/devShuai/specus/implementations/go/server/internal/peermesh"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// This file intentionally uses the pre-existing HTTP/TCP fixture and public store methods,
// so exactly these assertions can also run on the pinned pre-fix production tree.
func TestPeerRuntimeSQLRebindCannotAuthorizeOriginalPhysicalControl(t *testing.T) {
	for _, mutation := range []string{"source-channel", "target-channel", "credential-disabled"} {
		t.Run(mutation, func(t *testing.T) {
			entered, release, finished := make(chan struct{}, 1), make(chan struct{}), make(chan error, 1)
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			f := newGenerationFixture(t, 4, func(app *App) {
				original := app.dispatcher.peerControl
				app.dispatcher.SetPeerControlHandler(func(conn *control.Conn, request protocol.MessageRequest) error {
					entered <- struct{}{}
					<-release
					err := original(conn, request)
					finished <- err
					return err
				})
			})
			source := f.login(f.pub, protocol.ConnectionRoleControl)
			request := protocol.MessageRequest{ToClientName: f.recipient.ClientName, MessageType: protocol.MessageTypePeerControl, Message: `{"type":"candidates","sourceKeyEpoch":"source-epoch","candidates":[]}`}
			if err := protocol.WritePacket(source.net, request); err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("real Peer route was not reached")
			}
			ctx := context.Background()
			switch mutation {
			case "source-channel":
				if err := f.app.db.MarkClientSessionOnline(ctx, f.pub.ClientSessionID, "NETTY_ONLINE", "replacement-source-channel", "fixture", time.Now()); err != nil {
					t.Fatal(err)
				}
			case "target-channel":
				if err := f.app.db.MarkClientSessionOnline(ctx, f.recipient.ClientSessionID, "NETTY_ONLINE", "replacement-target-channel", "fixture", time.Now()); err != nil {
					t.Fatal(err)
				}
			case "credential-disabled":
				row, err := f.app.db.GetClientSession(ctx, f.pub.ClientSessionID)
				if err != nil {
					t.Fatal(err)
				}
				credential, err := f.app.db.GetCredential(ctx, row.CredentialID)
				if err != nil {
					t.Fatal(err)
				}
				credential.Enabled = false
				if err := f.app.db.UpdateCredential(ctx, *credential); err != nil {
					t.Fatal(err)
				}
			}
			releaseOnce.Do(func() { close(release) })
			select {
			case err := <-finished:
				if err != nil {
					t.Fatalf("runtime change disconnected original CONTROL: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("original handler did not finish")
			}
			rows, err := f.app.db.ListPeerMeshSessions(ctx, "default", 100)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 0 {
				t.Errorf("stale physical control created SQL authority after %s", mutation)
			}
			// An ordered marker on the same real writer proves that no prior candidates or grant
			// is still in flight; there is no sleep-based absence assertion.
			marker, _ := json.Marshal(peermesh.ControlMessage{Type: "runtime-publication-test-barrier"})
			if err := f.consumer.server.Send(protocol.MessageResponse{ClientName: "server", ToClientName: f.recipient.ClientName, MessageType: protocol.MessageTypePeerControl, Message: string(marker)}); err != nil {
				t.Fatal(err)
			}
			for {
				select {
				case packet, ok := <-f.consumer.packets:
					if !ok {
						t.Fatal("target original CONTROL closed")
					}
					if response, ok := packet.(protocol.MessageResponse); ok {
						var message peermesh.ControlMessage
						if err := json.Unmarshal([]byte(response.Message), &message); err != nil {
							t.Fatal(err)
						}
						if message.Type == peermesh.TypeCandidates || message.Type == peermesh.TypeSessionGrant {
							t.Errorf("stale original transport published authority after %s", mutation)
						}
						if message.Type == "runtime-publication-test-barrier" {
							f.heartbeat(source)
							return
						}
					}
				case <-time.After(3 * time.Second):
					t.Fatal("physical publication barrier not observed")
				}
			}
		})
	}
}

func TestPeerRuntimeManagementTransferRetainsOriginalControlDataAndToken(t *testing.T) {
	f := newGenerationFixture(t, 4)
	source := f.login(f.pub, protocol.ConnectionRoleControl)
	ctx := context.Background()
	before, err := f.app.db.GetClientSession(ctx, f.pub.ClientSessionID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := f.app.db.InsertManagementUser(ctx, store.ManagementUser{Username: "runtime-bob", TenantID: "default", Role: store.ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	root := store.ManagementWriteActor{Username: "admin", TenantID: "default", Admin: true, BuiltIn: true}
	snapshot, err := f.app.db.LoadOwnerTransferSnapshot(ctx, "default", store.OwnerScopeGroup, before.CredentialID)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := store.PreviewOwnerTransfer(root, store.OwnerScopeGroup, before.CredentialID, snapshot)
	if err != nil || preview.Revision == nil {
		t.Fatal("real transfer preview failed")
	}
	request := store.OwnerTransferWrite{Actor: root, Scope: store.OwnerScopeGroup, PathID: before.CredentialID, AuditID: 908001, Body: map[string]any{"scope": store.OwnerScopeGroup, "targetUsername": "runtime-bob", "expectedRevision": *preview.Revision}}
	request.BuiltInTarget.Username = "admin"
	request.BuiltInTarget.TenantID = "default"
	request.BuiltInTarget.Enabled = true
	if out, err := f.app.db.TransferClientOwnership(ctx, request); err != nil || len(out.Response.AffectedClientIDs) != 2 {
		t.Fatalf("real group transfer: %v", err)
	}
	data := f.login(f.pub, protocol.ConnectionRoleData)
	f.heartbeat(source)
	if data.server.ClientSessionID() != before.ID || source.server.ChannelID() != *before.ChannelID {
		t.Fatal("management-only transfer replaced original access identity")
	}
	if err := protocol.WritePacket(source.net, protocol.MessageRequest{ToClientName: f.recipient.ClientName, MessageType: protocol.MessageTypePeerControl, Message: `{"type":"candidates","sourceKeyEpoch":"original-epoch","candidates":[],"dataFrameVersion":2}`}); err != nil {
		t.Fatal(err)
	}
	grant := peerGenerationMessage(t, source, peermesh.TypeSessionGrant)
	forwarded := peerGenerationMessage(t, f.consumer, peermesh.TypeCandidates)
	if grant.SessionID == nil || grant.Token == "" || forwarded.SessionID == nil || *grant.SessionID != *forwarded.SessionID || grant.Token != forwarded.Token || forwarded.SourceKeyEpoch != "original-epoch" {
		t.Fatal("original access lost current-owner peer authorization")
	}
	after, err := f.app.db.GetClientSession(ctx, before.ID)
	if err != nil || after.TokenHash != before.TokenHash || after.IdentityID != before.IdentityID || after.CredentialID != before.CredentialID || after.Status != "NETTY_ONLINE" {
		t.Fatal("transfer mutated retained token/session binding")
	}
}
