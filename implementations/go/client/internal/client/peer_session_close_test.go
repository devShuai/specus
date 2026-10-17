package client

import (
	"encoding/json"
	"testing"
	"time"
)

// Exercise the real control decoder, both session indexes, and socket-owning egress runtime.
// Only the outbound dialer is injected; this is not a real-network acceptance test.
func TestPeerSessionCloseVectors(t *testing.T) {
	var vector struct {
		Cases []struct {
			Name                 string            `json:"name"`
			Messages             []json.RawMessage `json:"messages"`
			ClosedPeerID         int64             `json:"closedPeerId"`
			ReplacementSessionID int64             `json:"replacementSessionId"`
		} `json:"cases"`
	}
	readEgressVector(t, "peer-session-close-v1.json", &vector)
	if len(vector.Cases) != 13 {
		t.Fatalf("expected 13 shared cases, got %d", len(vector.Cases))
	}
	for _, scenario := range vector.Cases {
		t.Run(scenario.Name, func(t *testing.T) {
			mesh := newEgressMeshHarness(t)
			harness := newEgressHarness(t)
			defer harness.runtime.shutdown(time.Now())
			mesh.egress = harness.runtime
			mesh.runtime = RuntimeConfig{PeerMesh: PeerMeshConfig{ClientID: 1}}
			mesh.sessions = make(map[int64]*peerMeshSession)
			mesh.sessionsByID = make(map[int64]*peerMeshSession)
			install := func(peerID, sessionID int64, port int) {
				session := &peerMeshSession{ID: sessionID, PeerID: peerID, Token: "token"}
				mesh.sessions[peerID] = session
				mesh.sessionsByID[sessionID] = session
				syn := egressSyn(t, "100.96.0.1", port, "203.0.113.10", 443)
				harness.runtime.handleFrame(peerID, egressFrameFor(buildTCPSegment(syn)), flowEpoch)
			}
			install(7, 200, 40000)
			install(9, 300, 40001)
			if harness.dialCount() != 2 {
				t.Fatal("fixture must own two active sockets")
			}
			for _, message := range scenario.Messages {
				mesh.handleControl(nil, string(message), RuntimeConfig{}, nil)
			}
			wantFlows := 2
			if scenario.ClosedPeerID != 0 {
				wantFlows = 1
			}
			harness.runtime.mu.Lock()
			activeFlows := harness.runtime.flows.size()
			harness.runtime.mu.Unlock()
			if activeFlows != wantFlows {
				t.Errorf("active flows = %d, want %d", activeFlows, wantFlows)
			}
			for index, peerID := range []int64{7, 9} {
				closed := scenario.ClosedPeerID == peerID
				if harness.socket(index).isClosed() != closed {
					t.Errorf("peer %d socket closed = %v, want %v", peerID, harness.socket(index).isClosed(), closed)
				}
				if (mesh.sessions[peerID] == nil) != closed {
					t.Errorf("peer %d session removal does not match close", peerID)
				}
				sessionID := int64(200)
				if peerID == 9 {
					sessionID = 300
				}
				if (mesh.sessionsByID[sessionID] == nil) != closed {
					t.Errorf("session index %d removal does not match close", sessionID)
				}
			}
			if scenario.ReplacementSessionID != 0 {
				install(7, scenario.ReplacementSessionID, 40002)
				if harness.dialCount() != 3 {
					t.Fatal("replacement must own a new socket")
				}
				for _, message := range scenario.Messages {
					mesh.handleControl(nil, string(message), RuntimeConfig{}, nil)
				}
				if mesh.sessions[7] == nil || mesh.sessions[7].ID != scenario.ReplacementSessionID || mesh.sessionsByID[scenario.ReplacementSessionID] != mesh.sessions[7] {
					t.Error("replayed close removed replacement session")
				}
				if harness.socket(2).isClosed() {
					t.Error("replayed close revoked replacement flow")
				}
				if harness.socket(1).isClosed() || mesh.sessions[9] == nil {
					t.Error("replayed close affected unrelated peer")
				}
			}
		})
	}
}
