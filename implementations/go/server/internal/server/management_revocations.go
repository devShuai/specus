package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/management"
	"github.com/devShuai/specus/implementations/go/server/internal/wsevents"
)

// managementRevocations ends the management WebSockets of an account whose access changed: it was
// deleted, disabled or given another role (management-accounts.md 7.2). The account change has
// committed, and with it the deletion of the identity's unused tickets; the sockets close here and, in
// a cluster, on every other instance through STCE kind 5 (public-transfer-cluster.md 5.2).
type managementRevocations struct {
	hub            *wsevents.Hub
	clientMessages *clientMessagesHub
	// coordination is nil when the instance runs alone.
	coordination *publicTransferCoordination
	logger       *slog.Logger
}

// managementRevocationEvent is the payload of STCE kind 5.
type managementRevocationEvent struct {
	TenantID string `json:"tenantId"`
	Username string `json:"username"`
	Reason   string `json:"reason"`
}

func (m managementRevocations) revoked(tenantID, username, reason string) {
	m.closeLocal(tenantID, username, reason)
	if m.coordination == nil {
		return
	}
	payload, err := json.Marshal(managementRevocationEvent{TenantID: tenantID, Username: username, Reason: reason})
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = m.coordination.publishManagementRevocation(ctx, tenantID, payload)
		cancel()
	}
	if err != nil {
		// The account change stands; the handshake check still refuses new sockets.
		m.logger.Warn("publish management revocation failed; other instances keep their sockets", "err", err)
	}
}

func (m managementRevocations) closeLocal(tenantID, username, reason string) {
	closeReason := revocationCloseReason(reason)
	m.hub.CloseIdentity(tenantID, username, closeReason)
	m.clientMessages.closeIdentity(tenantID, username, closeReason)
}

func (m managementRevocations) handleClusterEvent(event publicTransferClusterEvent) {
	if event.kind != clusterEventKindManagementRevocation {
		return
	}
	var revocation managementRevocationEvent
	if err := json.Unmarshal(event.payload, &revocation); err != nil ||
		strings.TrimSpace(revocation.TenantID) == "" || revocation.Username == "" ||
		event.groupID != managementGroupID(revocation.TenantID) {
		m.logger.Warn("discarding management revocation cluster event with invalid identity binding")
		return
	}
	m.closeLocal(revocation.TenantID, revocation.Username, revocation.Reason)
}

// revocationCloseReason is the reason of the 1008 close; a reason this version does not know still
// closes.
func revocationCloseReason(reason string) string {
	switch reason {
	case management.AccessRevokedDeleted:
		return "account deleted"
	case management.AccessRevokedDisabled:
		return "account disabled"
	case management.AccessRevokedRoleChanged:
		return "account role changed"
	default:
		return "account revoked"
	}
}
