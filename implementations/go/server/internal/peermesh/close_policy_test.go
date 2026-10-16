package peermesh

import (
	"context"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestPeerPolicyCloseFailureDoesNotRetainOldRelayAuthorization(t *testing.T) {
	f := newCloseCommitFixture(t, 1)
	ctx := context.Background()
	id := f.ids[0]
	token, _ := f.service.getCachedSessionToken(id)
	transferPeerFixtureClient(t, f.db, 1002, "bob")
	if _, err := f.raw.Exec(`CREATE TRIGGER reject_policy_close BEFORE UPDATE ON peer_mesh_session WHEN NEW.status='CLOSED' BEGIN SELECT RAISE(ABORT,'injected policy close failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := f.service.refreshAuthorization(ctx, AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true, BuiltIn: true}); err == nil {
		t.Fatal("policy cleanup failure hidden")
	}
	assertCloseNotCommitted(t, f)
	if f.service.ValidateRelayFrame(ctx, DataFrameHeader{SessionID: id}, 1001, 1002) {
		t.Fatal("old cache authorized a policy-revoked session after failed SQL cleanup")
	}
	if f.service.AuthorizeRelayProbe(ctx, relayProbe{Type: peerProbeTypeCheck, SessionID: id, FromClientID: 1001, ToClientID: 1002, Token: token}) {
		t.Fatal("probe ignored current denied policy")
	}
	now := time.Now()
	if err := f.db.InsertPeerMeshACL(ctx, store.PeerMeshACL{ID: 91001, TenantID: "tenant-a", OwnerUsername: "admin", SourceClientID: 1001, SourceClientName: f.source.ClientName, TargetClientID: 1002, TargetClientName: "close-target-0", Direction: "OUTBOUND", Allowed: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(`DROP TRIGGER reject_policy_close`); err != nil {
		t.Fatal(err)
	}
	if err := f.service.refreshAuthorization(ctx, AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true, BuiltIn: true}); err != nil {
		t.Fatal(err)
	}
	if row := getPeerSession(t, f.db, id); row.Status != StatusActive {
		t.Fatalf("delayed refresh closed newly valid explicit ACL grant: %+v", row)
	}
	if !f.service.ValidateRelayFrame(ctx, DataFrameHeader{SessionID: id}, 1001, 1002) {
		t.Fatal("current explicit permission did not restore relay admission")
	}
}

func TestPeerRelayAdmissionCannotRepopulateCommittedClosure(t *testing.T) {
	f := newCloseCommitFixture(t, 2)
	one, two := f.ids[0], f.ids[1]
	oldOne, oldTwo := *getPeerSession(t, f.db, one), *getPeerSession(t, f.db, two)
	guardOne, guardTwo := f.service.beginRelayCacheAdmission(one), f.service.beginRelayCacheAdmission(two)
	defer f.service.endRelayCacheAdmission(one, guardOne)
	defer f.service.endRelayCacheAdmission(two, guardTwo)
	if _, err := f.service.CloseSessionFromClient(context.Background(), f.source, ControlMessage{SessionID: &one}); err != nil {
		t.Fatal(err)
	}
	if f.service.cacheRelayAdmission(oldOne, guardOne, time.Now(), 999) {
		t.Fatal("pre-close SQL snapshot repopulated authorization and pending bytes")
	}
	if !f.service.cacheRelayAdmission(oldTwo, guardTwo, time.Now(), 0) {
		t.Fatal("closing one ID invalidated unrelated in-flight admission")
	}
	f.service.relayMu.Lock()
	_, cached := f.service.relayAuthorizations[one]
	pending := f.service.pendingRelayBytes[one]
	f.service.relayMu.Unlock()
	if cached || pending != 0 {
		t.Fatalf("committed closure cache resurrected: cached=%v pending=%d", cached, pending)
	}
}

func TestPeerRelayAdmissionBoundAndInvalidatedReplacement(t *testing.T) {
	s := newPeerMeshTestService(nil)
	guards := make([]*relayCacheAdmission, 4096)
	for i := range guards {
		guards[i] = s.beginRelayCacheAdmission(int64(i + 1))
		if guards[i] == nil {
			t.Fatal("unexpected admission capacity")
		}
	}
	if s.beginRelayCacheAdmission(4097) != nil {
		t.Fatal("in-flight admission table exceeded bound")
	}
	s.invalidateRelayAuthorizations([]int64{1})
	fresh := s.beginRelayCacheAdmission(1)
	if fresh == nil || fresh == guards[0] {
		t.Fatal("replacement reused invalidated in-flight identity")
	}
	s.endRelayCacheAdmission(1, guards[0])
	item := store.PeerMeshSession{ID: 1, SourceClientID: 10, TargetClientID: 20, Status: StatusActive, ExpiresAt: time.Now().Add(time.Hour)}
	if s.cacheRelayAdmission(item, guards[0], time.Now(), 5) {
		t.Fatal("old guard became usable after replacement")
	}
	if !s.cacheRelayAdmission(item, fresh, time.Now(), 0) {
		t.Fatal("old cleanup removed current replacement guard")
	}
	s.endRelayCacheAdmission(1, fresh)
	for i := 1; i < len(guards); i++ {
		s.endRelayCacheAdmission(int64(i+1), guards[i])
	}
	if len(s.relayAdmissions) != 0 {
		t.Fatalf("in-flight admission ownership leaked: %d", len(s.relayAdmissions))
	}
}

func TestPeerCloseInvalidIdentifiersCannotSelectAll(t *testing.T) {
	f := newCloseCommitFixture(t, 2)
	access := AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true, BuiltIn: true}
	if _, err := f.service.ForceClose(context.Background(), access, 0); err == nil {
		t.Fatal("zero single ID selected close-all")
	}
	if _, err := f.service.CloseOpenSessionsForDevice(context.Background(), access, 0); err == nil {
		t.Fatal("zero device ID selected close-all")
	}
	assertCloseNotCommitted(t, f)
}
