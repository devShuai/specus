package peermesh

import (
	"context"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// OnClientDeleted runs after the deletion transaction commits. The identity snapshot is
// necessary: neither the account nor its device can be looked up at this point.
func (s *Service) OnClientDeleted(ctx context.Context, account store.ClientAccount, closed []store.PeerMeshSession) {
	if s == nil {
		return
	}
	for _, item := range closed {
		s.removeRelaySession(item.ID)
		s.removeCachedSessionToken(item.ID)
		s.sendClose(sessionView(item))
	}
	s.withdrawDeletedClient(ctx, account)
	s.onAuthorizationChanged(ctx, account.TenantID)
	for _, target := range s.rosterRefreshTargets(ctx, account) {
		s.PushConfig(ctx, target)
		s.PushRoster(ctx, target)
	}
	s.pushTenantEgress(ctx, account.TenantID)
}

func (s *Service) withdrawDeletedClient(ctx context.Context, account store.ClientAccount) {
	type withdrawal struct {
		key      catalogKey
		revision int64
	}
	var withdrawals []withdrawal
	s.catalogMu.Lock()
	keys := make(map[catalogKey]struct{})
	for key := range s.catalogs {
		keys[key] = struct{}{}
	}
	for key := range s.catalogRevisions {
		keys[key] = struct{}{}
	}
	for key := range s.reportRevisions {
		keys[key] = struct{}{}
	}
	for key := range keys {
		if key.tenantID != account.TenantID || key.publisherClientID != account.ID {
			continue
		}
		withdrawals = append(withdrawals, withdrawal{key, s.nextCatalogRevisionLocked(key)})
		delete(s.catalogs, key)
		delete(s.catalogRevisions, key)
		delete(s.reportRevisions, key)
		delete(s.serviceReportRates, key.publisherSessionID)
	}
	s.catalogMu.Unlock()
	for _, item := range withdrawals {
		s.fanoutCatalogMode(ctx, account, item.key.publisherSessionID, item.revision, nil, time.Now(), true)
	}
}
