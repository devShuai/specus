package management

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/peermesh"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestPeerCloseHTTPCurrentScopeAndCommitPublication(t *testing.T) {
	for _, scenario := range []string{"single-success", "single-failure", "all-success", "all-failure", "empty-owner-all", "unowned", "invalid-id"} {
		t.Run(scenario, func(t *testing.T) {
			h := newWorkbenchHTTPHarness(t)
			h.addUser(workbenchVectorIdentity{TenantID: "t1", Username: "nobody"})
			source, target := h.addClient("t1", "alice"), h.addClient("t1", "alice")
			otherSource, otherTarget := h.addClient("t1", "bob"), h.addClient("t1", "bob")
			now := time.Now().UTC()
			for _, row := range []store.PeerMeshSession{
				{ID: 7001, SourceClientID: source.ID, SourceClientName: source.ClientName, TargetClientID: target.ID, TargetClientName: target.ClientName},
				{ID: 7002, SourceClientID: source.ID, SourceClientName: source.ClientName, TargetClientID: target.ID, TargetClientName: target.ClientName},
				{ID: 7003, SourceClientID: otherSource.ID, SourceClientName: otherSource.ClientName, TargetClientID: otherTarget.ID, TargetClientName: otherTarget.ClientName},
			} {
				row.TenantID = "t1"
				row.Status = peermesh.StatusActive
				row.PathType = peermesh.PathRelay
				row.StartedAt = now
				row.UpdatedAt = now
				row.ExpiresAt = now.Add(time.Hour)
				row.DirectBytes = 11
				row.RelayBytes = 22
				if err := h.db.InsertPeerMeshSession(h.ctx, row); err != nil {
					t.Fatal(err)
				}
			}
			left, right := &peerDeleteSession{name: source.ClientName}, &peerDeleteSession{name: target.ClientName}
			h.api.sessions.Replace(left)
			h.api.sessions.Replace(right)
			if strings.HasSuffix(scenario, "-failure") {
				raw, err := sql.Open("sqlite", h.dbPath)
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				condition := "NEW.status='CLOSED'"
				if scenario == "all-failure" {
					condition += ` AND (SELECT COUNT(*) FROM peer_mesh_session WHERE status='CLOSED')>=1`
				}
				if _, err := raw.Exec(`CREATE TRIGGER reject_http_close BEFORE UPDATE ON peer_mesh_session WHEN ` + condition + ` BEGIN SELECT RAISE(ABORT,'injected HTTP close failure'); END`); err != nil {
					t.Fatal(err)
				}
			}
			path := "/api/admin/peer-mesh/sessions/7001"
			who := "alice"
			want := http.StatusOK
			if strings.HasPrefix(scenario, "all-") || scenario == "empty-owner-all" {
				path = "/api/admin/peer-mesh/sessions"
			}
			if scenario == "empty-owner-all" {
				who = "nobody"
			}
			if strings.HasSuffix(scenario, "-failure") {
				want = http.StatusInternalServerError
			}
			if scenario == "unowned" {
				who = "bob"
				want = http.StatusNotFound
			}
			if scenario == "invalid-id" {
				path = "/api/admin/peer-mesh/sessions/0"
				want = http.StatusNotFound
			}
			response, body := h.do(http.MethodDelete, path, h.token("t1", who), nil)
			if response.StatusCode != want {
				t.Fatalf("HTTP close=%d want=%d body=%s", response.StatusCode, want, body)
			}
			closed := 0
			for _, id := range []int64{7001, 7002, 7003} {
				row, err := h.db.GetPeerMeshSession(h.ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				expected := id != 7003 && (scenario == "all-success" || (scenario == "single-success" && id == 7001))
				if (row.Status == peermesh.StatusClosed) != expected || row.DirectBytes != 11 || row.RelayBytes != 22 {
					t.Fatalf("HTTP close scope/rollback/counters mismatch: %+v", row)
				}
				if expected {
					closed++
				}
			}
			for _, bound := range []*peerDeleteSession{left, right} {
				messages := bound.messages(t)
				if len(messages) != closed || bound.closeReason() != "" {
					t.Fatalf("HTTP close leaked precommit/forced device reconnect: messages=%d closed=%d reason=%s", len(messages), closed, bound.closeReason())
				}
				for _, message := range messages {
					if message.Type != peermesh.TypeClose {
						t.Fatalf("unexpected close publication: %+v", message)
					}
				}
			}
		})
	}
}
