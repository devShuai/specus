package peermesh

import (
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

type relayCacheAdmission struct {
	refs    int
	invalid bool
}

func (s *Service) beginRelayCacheAdmission(id int64) *relayCacheAdmission {
	if id <= 0 {
		return nil
	}
	s.relayMu.Lock()
	defer s.relayMu.Unlock()
	if s.relayAdmissions == nil {
		s.relayAdmissions = map[int64]*relayCacheAdmission{}
	}
	guard := s.relayAdmissions[id]
	if guard == nil {
		if len(s.relayAdmissions) >= 4096 {
			return nil
		}
		guard = &relayCacheAdmission{}
		s.relayAdmissions[id] = guard
	}
	guard.refs++
	return guard
}
func (s *Service) endRelayCacheAdmission(id int64, guard *relayCacheAdmission) {
	if guard == nil {
		return
	}
	s.relayMu.Lock()
	defer s.relayMu.Unlock()
	guard.refs--
	if guard.refs == 0 && s.relayAdmissions[id] == guard {
		delete(s.relayAdmissions, id)
	}
}
func (s *Service) invalidateRelayAdmissionLocked(id int64) {
	if guard := s.relayAdmissions[id]; guard != nil {
		guard.invalid = true
		delete(s.relayAdmissions, id)
	}
}

// A committed ACL/owner change invalidates the optimization independently of SQL cleanup.
// A failed close retains grant tokens/counters; subsequent slow admission checks current policy.
func (s *Service) invalidateRelayAuthorizations(ids []int64) {
	s.relayMu.Lock()
	defer s.relayMu.Unlock()
	for _, id := range ids {
		delete(s.relayAuthorizations, id)
		s.invalidateRelayAdmissionLocked(id)
	}
}

func (s *Service) cacheRelayAdmission(item store.PeerMeshSession, guard *relayCacheAdmission, now time.Time, bytes int64) bool {
	s.relayMu.Lock()
	defer s.relayMu.Unlock()
	if guard == nil || guard.invalid || s.relayAdmissions[item.ID] != guard {
		return false
	}
	s.relayAuthorizations[item.ID] = relayAuthorization{sourceClientID: item.SourceClientID, targetClientID: item.TargetClientID, active: item.Status == StatusActive, sessionExpiresAt: item.ExpiresAt, cacheExpiresAt: now.Add(relayAuthorizationCacheTTL)}
	if bytes > 0 {
		s.pendingRelayBytes[item.ID] = saturatedAdd(s.pendingRelayBytes[item.ID], bytes)
	}
	return true
}

func peerSessionReferences(item store.PeerMeshSession) (store.PeerClientReference, store.PeerClientReference) {
	return store.PeerClientReference{ID: item.SourceClientID, TenantID: item.TenantID, ClientName: item.SourceClientName}, store.PeerClientReference{ID: item.TargetClientID, TenantID: item.TenantID, ClientName: item.TargetClientName}
}
