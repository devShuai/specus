package management

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/peermesh"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestDeleteClientHTTPPublishesPeerClosureOnlyAfterCommit(t *testing.T) {
	for _, failDelete := range []bool{false, true} {
		t.Run(strconv.FormatBool(failDelete), func(t *testing.T) {
			h := newWorkbenchHTTPHarness(t)
			deleted := h.addClient("t1", "alice")
			peer := h.addClient("t1", "alice")
			for index, account := range []store.ClientAccount{deleted, peer} {
				if err := h.db.InsertPeerMeshDevice(h.ctx, store.PeerMeshDevice{ID: int64(index + 1), TenantID: account.TenantID,
					OwnerUsername: account.OwnerUsername, ClientID: account.ID, ClientName: account.ClientName,
					VirtualIP: "100.96.0." + strconv.Itoa(index+2), CIDR: "100.96.0.0/11", Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
					t.Fatal(err)
				}
			}
			deletedSession := &peerDeleteSession{name: deleted.ClientName}
			peerSession := &peerDeleteSession{name: peer.ClientName}
			h.api.sessions.Replace(deletedSession)
			h.api.sessions.Replace(peerSession)
			now := time.Now().UTC()
			if err := h.db.InsertPeerMeshSession(h.ctx, store.PeerMeshSession{ID: 7001, TenantID: "t1",
				SourceClientID: deleted.ID, SourceClientName: deleted.ClientName, TargetClientID: peer.ID, TargetClientName: peer.ClientName,
				Status: peermesh.StatusActive, PathType: peermesh.PathRelay, StartedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			wantStatus := http.StatusNoContent
			if failDelete {
				connection, err := sql.Open("sqlite", h.dbPath)
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close()
				_, err = connection.Exec(`CREATE TRIGGER fail_account_delete BEFORE DELETE ON specus_client_account
					BEGIN SELECT RAISE(ABORT, 'injected account deletion failure'); END`)
				if err != nil {
					t.Fatal(err)
				}
				wantStatus = http.StatusInternalServerError
			}
			response, payload := h.do(http.MethodDelete, "/api/admin/clients/"+strconv.FormatInt(deleted.ID, 10), h.fixtureToken("t1"), nil)
			if response.StatusCode != wantStatus {
				t.Fatalf("delete status=%d body=%s", response.StatusCode, payload)
			}
			messages := peerSession.messages(t)
			if failDelete {
				if len(messages) != 0 || deletedSession.closeReason() != "" {
					t.Fatal("failed deletion notified or kicked client")
				}
				item, err := h.db.GetPeerMeshSession(h.ctx, 7001)
				if err != nil || item.Status != peermesh.StatusActive {
					t.Fatalf("rollback session=%+v err=%v", item, err)
				}
				return
			}
			closed, roster := false, false
			for _, message := range messages {
				if message.Type == peermesh.TypeClose && message.SessionID != nil && *message.SessionID == 7001 {
					closed = true
				}
				if message.Type == peermesh.TypeRoster {
					roster = true
					for _, device := range message.Peers {
						if device.ClientID == deleted.ID {
							t.Fatal("deleted device advertised")
						}
					}
				}
			}
			if !closed || !roster || deletedSession.closeReason() != store.ReasonAdminDeleted {
				t.Fatalf("close=%t roster=%t reason=%q", closed, roster, deletedSession.closeReason())
			}
		})
	}
}

type peerDeleteSession struct {
	name    string
	mu      sync.Mutex
	packets []protocol.Packet
	closed  string
}

func (s *peerDeleteSession) ClientName() string { return s.name }
func (*peerDeleteSession) LoginTimeMs() int64   { return 1 }
func (s *peerDeleteSession) Send(packet protocol.Packet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packets = append(s.packets, packet)
	return nil
}
func (s *peerDeleteSession) Close(reason string) { s.mu.Lock(); defer s.mu.Unlock(); s.closed = reason }
func (s *peerDeleteSession) closeReason() string { s.mu.Lock(); defer s.mu.Unlock(); return s.closed }
func (s *peerDeleteSession) messages(t *testing.T) []peermesh.ControlMessage {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []peermesh.ControlMessage
	for _, packet := range s.packets {
		if response, ok := packet.(protocol.MessageResponse); ok && response.MessageType == protocol.MessageTypePeerControl {
			var message peermesh.ControlMessage
			if err := json.Unmarshal([]byte(response.Message), &message); err != nil {
				t.Fatal(err)
			}
			out = append(out, message)
		}
	}
	return out
}
