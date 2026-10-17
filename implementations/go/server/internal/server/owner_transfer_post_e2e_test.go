package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/peermesh"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// Actual App HTTP/password login + original CONTROL/DATA sockets, not a direct
// store transfer. This is a protocol harness, not native-client/platform acceptance.
func TestOwnerTransferPOSTRetainsOriginalControlDataTokenAndCredential(t *testing.T) {
	f := newGenerationFixture(t, 4)
	_, httpServer := newHTTPTestServer(t, f.app)
	token := adminToken(t, httpServer)
	source := f.login(f.pub, protocol.ConnectionRoleControl)
	ctx := context.Background()
	before, err := f.app.db.GetClientSession(ctx, f.pub.ClientSessionID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := f.app.db.InsertManagementUser(ctx, store.ManagementUser{Username: "post-owner-bob", TenantID: "default", Role: store.ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	account, err := f.app.db.FindClientByName(ctx, f.pub.ClientName)
	if err != nil {
		t.Fatal(err)
	}
	response := authRequest(t, httpServer, http.MethodPost, fmt.Sprintf("/api/admin/clients/%d/owner-transfer", account.ID), token, `{"scope":"single"}`)
	var problem map[string]string
	if response.StatusCode != 409 || json.NewDecoder(response.Body).Decode(&problem) != nil || problem["code"] != "CREDENTIAL_SHARED" {
		response.Body.Close()
		t.Fatal("shared credential must reject single transfer")
	}
	response.Body.Close()
	path := fmt.Sprintf("/api/admin/client-credentials/%d/owner-transfer", before.CredentialID)
	response = authRequest(t, httpServer, http.MethodGet, path, token, "")
	var preview store.OwnerTransferPreview
	if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&preview) != nil || preview.Revision == nil || preview.AffectedClientCount != 2 {
		response.Body.Close()
		t.Fatal("public group preview missing")
	}
	response.Body.Close()
	body, _ := json.Marshal(map[string]any{"scope": store.OwnerScopeGroup, "targetUsername": "POST-OWNER-BOB", "expectedRevision": *preview.Revision})
	response = authRequest(t, httpServer, http.MethodPost, path, token, string(body))
	var result store.OwnerTransferResult
	if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&result) != nil || result.TargetUsername != "post-owner-bob" || !result.Changed || !result.AccessRetained || len(result.AffectedClientIDs) != 2 {
		response.Body.Close()
		t.Fatalf("public group result: HTTP %d %+v", response.StatusCode, result)
	}
	response.Body.Close()
	data := f.login(f.pub, protocol.ConnectionRoleData)
	f.heartbeat(source)
	if data.server.ClientSessionID() != before.ID || source.server.ChannelID() != *before.ChannelID {
		t.Fatal("transfer replaced original access binding")
	}
	if err := protocol.WritePacket(source.net, protocol.MessageRequest{ToClientName: f.recipient.ClientName, MessageType: protocol.MessageTypePeerControl, Message: `{"type":"candidates","sourceKeyEpoch":"post-original-epoch","candidates":[],"dataFrameVersion":2}`}); err != nil {
		t.Fatal(err)
	}
	grant := peerGenerationMessage(t, source, peermesh.TypeSessionGrant)
	forwarded := peerGenerationMessage(t, f.consumer, peermesh.TypeCandidates)
	if grant.SessionID == nil || grant.Token == "" || forwarded.SessionID == nil || *grant.SessionID != *forwarded.SessionID || grant.Token != forwarded.Token {
		t.Fatal("retained transport lost current group authorization")
	}
	after, err := f.app.db.GetClientSession(ctx, before.ID)
	if err != nil || after.TokenHash != before.TokenHash || after.IdentityID != before.IdentityID || after.CredentialID != before.CredentialID || after.Status != "NETTY_ONLINE" {
		t.Fatal("public transfer mutated original session/token")
	}
	// The unchanged credential can authenticate a new device, which must inherit the new owner.
	newLogin := clientAuthLoginWithEnvironmentForTest(t, httpServer.URL, "ck_generation", "generation-secret", "post-new-device", "admin", nil)
	newAccount, err := f.app.db.FindClientByName(ctx, newLogin.ClientName)
	if err != nil || newAccount == nil || newAccount.OwnerUsername != "post-owner-bob" {
		t.Fatal("retained credential created old-owner device", err)
	}
}
