package peermesh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

type catalogKey struct {
	tenantID           string
	publisherClientID  int64
	publisherSessionID int64
}

type catalogSnapshot struct {
	revision            int64
	instanceID          string
	generatedAt         time.Time
	expiresAt           time.Time
	services            []AdvertisedService
	publisherClientName string
	stats               []ServiceStats
	mdns                []MdnsCandidate
}

var (
	serviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)
	pathPattern      = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
	peerServiceApps  = []string{"http", "https", "ssh", "tcp", "udp"}
)

func (s *Service) SharingStatus(ctx context.Context, access AccessContext) (ServiceSharingView, error) {
	configured, row, err := s.configuredSharing(ctx, access.TenantID)
	if err != nil {
		return ServiceSharingView{}, err
	}
	count, err := s.db.CountEnabledPeerMeshSharedServices(ctx, access.TenantID)
	if err != nil {
		return ServiceSharingView{}, err
	}
	view := ServiceSharingView{
		DeploymentEnabled:           s.Enabled(),
		ConfiguredEnabled:           configured,
		EffectiveEnabled:            s.Enabled() && configured,
		PeerServiceDiscoveryVersion: peerServiceDiscoveryVersion,
		SupportedApplications:       peerServiceApps,
		EnabledServiceCount:         count,
	}
	if row != nil {
		updated := row.UpdatedAt.UTC().Format(time.RFC3339Nano)
		view.UpdatedAt = &updated
		view.UpdatedBy = row.UpdatedBy
		view.MdnsImportEnabled = row.MdnsImportEnabled
	}
	return view, nil
}

func (s *Service) SetSharing(ctx context.Context, access AccessContext, enabled bool) (ServiceSharingView, error) {
	return s.SetSharingOptions(ctx, access, &enabled, nil)
}

func (s *Service) SetSharingOptions(ctx context.Context, access AccessContext, enabled *bool, mdnsImportEnabled *bool) (ServiceSharingView, error) {
	if !access.Admin {
		return ServiceSharingView{}, errForbidden("只有管理员可以修改 Peer 服务共享")
	}
	if enabled == nil && mdnsImportEnabled == nil {
		return ServiceSharingView{}, errors.New("enabled or mdnsImportEnabled is required")
	}
	if enabled != nil && *enabled && !s.Enabled() {
		return ServiceSharingView{}, errors.New("部署端未启用 Peer Mesh，不能开启服务共享")
	}
	previous, row, err := s.configuredSharing(ctx, access.TenantID)
	if err != nil {
		return ServiceSharingView{}, err
	}
	nextEnabled := previous
	nextMdns := false
	if row != nil {
		nextMdns = row.MdnsImportEnabled
	}
	if enabled != nil {
		nextEnabled = *enabled
	}
	if mdnsImportEnabled != nil {
		nextMdns = *mdnsImportEnabled
	}
	now := time.Now()
	if err := s.db.UpsertPeerMeshServiceSharing(ctx, store.PeerMeshServiceSharing{
		TenantID:          access.TenantID,
		Enabled:           nextEnabled,
		MdnsImportEnabled: nextMdns,
		UpdatedBy:         &access.Username,
		UpdatedAt:         now,
	}); err != nil {
		return ServiceSharingView{}, err
	}
	s.audit("sharing-toggle", access.TenantID, nil, nil, "", map[bool]string{true: "enabled", false: "updated"}[nextEnabled])
	if previous && enabled != nil && !*enabled {
		s.withdrawTenant(ctx, access.TenantID)
	}
	s.pushTenantConfigs(ctx, access.TenantID)
	return s.SharingStatus(ctx, access)
}

func (s *Service) ListSharedServices(ctx context.Context, access AccessContext) ([]SharedServiceView, error) {
	var clientIDs []int64
	if !access.Admin {
		clients, err := s.db.ListClients(ctx)
		if err != nil {
			return nil, err
		}
		for _, client := range clients {
			if client.TenantID == access.TenantID && client.OwnerUsername == access.Username {
				clientIDs = append(clientIDs, client.ID)
			}
		}
		if len(clientIDs) == 0 {
			return []SharedServiceView{}, nil
		}
	}
	rows, err := s.db.ListPeerMeshSharedServices(ctx, access.TenantID, clientIDs)
	if err != nil {
		return nil, err
	}
	views := make([]SharedServiceView, 0, len(rows))
	for _, row := range rows {
		views = append(views, s.sharedServiceView(ctx, row, access.Admin))
	}
	return views, nil
}

func (s *Service) CreateSharedService(ctx context.Context, access AccessContext, mutation ServiceMutation) (SharedServiceView, error) {
	if !access.Admin {
		return SharedServiceView{}, errForbidden("只有管理员可以修改 Peer 服务共享")
	}
	if mutation.ClientID == nil {
		return SharedServiceView{}, errors.New("clientId is required")
	}
	account, err := s.findTenantClient(ctx, access.TenantID, *mutation.ClientID)
	if err != nil {
		return SharedServiceView{}, err
	}
	serviceID := ""
	if mutation.ServiceID != nil {
		serviceID, err = requireServiceID(*mutation.ServiceID)
		if err != nil {
			return SharedServiceView{}, err
		}
	} else {
		serviceID = fmt.Sprintf("%d", auth.NewClientID())
		if len(serviceID) < 8 {
			serviceID = fmt.Sprintf("svc-%d", auth.NewClientID())
		}
	}
	existing, err := s.db.FindPeerMeshSharedServiceByServiceID(ctx, access.TenantID, account.ID, serviceID)
	if err != nil {
		return SharedServiceView{}, err
	}
	if existing != nil {
		return SharedServiceView{}, errors.New("serviceId already exists on this client")
	}
	now := time.Now()
	row := store.PeerMeshSharedService{
		ID:         auth.NewClientID(),
		TenantID:   access.TenantID,
		ClientID:   account.ID,
		ClientName: account.ClientName,
		ServiceID:  serviceID,
		CreatedAt:  now,
	}
	if err := applyServiceMutation(&row, mutation, true); err != nil {
		return SharedServiceView{}, err
	}
	row.UpdatedAt = now
	if err := s.rejectPortConflict(ctx, row); err != nil {
		return SharedServiceView{}, err
	}
	if err := s.db.InsertPeerMeshSharedService(ctx, row); err != nil {
		return SharedServiceView{}, err
	}
	s.PushConfig(ctx, *account)
	return s.sharedServiceView(ctx, row, true), nil
}

func (s *Service) UpdateSharedService(ctx context.Context, access AccessContext, id int64, mutation ServiceMutation) (SharedServiceView, error) {
	if !access.Admin {
		return SharedServiceView{}, errForbidden("只有管理员可以修改 Peer 服务共享")
	}
	row, err := s.db.GetPeerMeshSharedService(ctx, access.TenantID, id)
	if err != nil || row == nil {
		if err != nil {
			return SharedServiceView{}, err
		}
		return SharedServiceView{}, errors.New("service not found")
	}
	if err := applyServiceMutation(row, mutation, false); err != nil {
		return SharedServiceView{}, err
	}
	row.UpdatedAt = time.Now()
	if err := s.rejectPortConflict(ctx, *row); err != nil {
		return SharedServiceView{}, err
	}
	if err := s.db.UpdatePeerMeshSharedService(ctx, *row); err != nil {
		return SharedServiceView{}, err
	}
	account, err := s.findTenantClient(ctx, row.TenantID, row.ClientID)
	if err != nil {
		return SharedServiceView{}, err
	}
	s.PushConfig(ctx, *account)
	s.withdrawClient(ctx, row.TenantID, row.ClientID)
	return s.sharedServiceView(ctx, *row, true), nil
}

func (s *Service) DeleteSharedService(ctx context.Context, access AccessContext, id int64) error {
	if !access.Admin {
		return errForbidden("只有管理员可以修改 Peer 服务共享")
	}
	row, err := s.db.GetPeerMeshSharedService(ctx, access.TenantID, id)
	if err != nil || row == nil {
		if err != nil {
			return err
		}
		return errors.New("service not found")
	}
	if err := s.db.DeletePeerMeshSharedService(ctx, access.TenantID, id); err != nil {
		return err
	}
	account, err := s.findTenantClient(ctx, row.TenantID, row.ClientID)
	if err != nil {
		return err
	}
	s.PushConfig(ctx, *account)
	s.withdrawClient(ctx, row.TenantID, row.ClientID)
	return nil
}

func (s *Service) OnClientDisconnected(ctx context.Context, clientName string, sessionID int64) {
	if s == nil || sessionID <= 0 {
		return
	}
	account, err := s.db.FindClientByName(ctx, clientName)
	if err != nil || account == nil {
		return
	}
	s.withdrawSession(ctx, *account, sessionID)
	key := catalogKey{account.TenantID, account.ID, sessionID}
	s.catalogMu.Lock()
	delete(s.catalogRevisions, key)
	delete(s.serviceReportRates, sessionID)
	s.catalogMu.Unlock()
}

func (s *Service) handleServiceReport(ctx context.Context, source store.ClientAccount, report ControlMessage, publisherSessionID int64) error {
	if publisherSessionID <= 0 {
		online, err := s.db.GetOnlineClientSession(ctx, source.TenantID, source.ID, "NETTY_ONLINE")
		if err != nil {
			return err
		}
		if online == nil {
			return errors.New("publisher session is required")
		}
		publisherSessionID = online.ID
	}
	publisherSession, err := s.db.GetClientSession(ctx, publisherSessionID)
	if err != nil {
		return err
	}
	if publisherSession.TenantID != source.TenantID || publisherSession.ClientID != source.ID ||
		publisherSession.Status != "NETTY_ONLINE" {
		return errors.New("publisher session is not current")
	}
	if publisherSession.PeerServiceDiscoveryVersion < peerServiceDiscoveryVersion {
		return errors.New("publisher does not support peer service discovery v2")
	}
	if err := s.enforceServiceReportRate(publisherSessionID, time.Now()); err != nil {
		return err
	}
	revision := int64(0)
	if report.Revision != nil {
		revision = *report.Revision
	}
	if revision < 1 {
		return errors.New("revision must be >= 1")
	}
	key := catalogKey{source.TenantID, source.ID, publisherSessionID}
	if !s.acceptCatalogRevision(key, revision) {
		return nil
	}
	enabled := report.Enabled != nil && *report.Enabled
	if !enabled || !s.effectiveSharing(ctx, source) {
		s.catalogMu.Lock()
		delete(s.catalogs, key)
		s.catalogMu.Unlock()
		s.fanoutCatalog(ctx, source, publisherSessionID, revision, nil, time.Now())
		return nil
	}
	roster, err := s.AllowedRoster(ctx, source)
	if err != nil {
		return err
	}
	hasPeer := false
	for _, item := range roster {
		if item.Online {
			hasPeer = true
			break
		}
	}
	if !hasPeer {
		return nil
	}
	advertised, err := s.advertisedFromReport(ctx, source, report.Services)
	if err != nil {
		return err
	}
	now := time.Now()
	expiresAt := now.Add(5 * time.Minute)
	s.catalogMu.Lock()
	s.catalogs[key] = catalogSnapshot{
		revision: revision, instanceID: report.InstanceID, generatedAt: now, expiresAt: expiresAt,
		services: advertised, publisherClientName: source.ClientName, stats: copyServiceStats(report.Stats, advertised),
		mdns: sanitizeMdnsCandidates(report.MdnsCandidates),
	}
	s.audit("service-report", source.TenantID, &source.ID, &publisherSessionID, "", "published")
	s.catalogMu.Unlock()
	s.fanoutCatalog(ctx, source, publisherSessionID, revision, advertised, expiresAt)
	return nil
}

func (s *Service) enforceServiceReportRate(sessionID int64, now time.Time) error {
	const maxWindows = 4096
	const limit = 20
	cutoff := now.Add(-time.Minute)
	s.catalogMu.Lock()
	defer s.catalogMu.Unlock()
	stamps, exists := s.serviceReportRates[sessionID]
	if !exists && len(s.serviceReportRates) >= maxWindows {
		s.audit("service-report", "", nil, &sessionID, "", "rate-table-full")
		return errors.New("service-report rate limited")
	}
	kept := stamps[:0]
	for _, stamp := range stamps {
		if !stamp.Before(cutoff) {
			kept = append(kept, stamp)
		}
	}
	if len(kept) >= limit {
		s.serviceReportRates[sessionID] = kept
		s.audit("service-report", "", nil, &sessionID, "", "rate-limited")
		return errors.New("service-report rate limited")
	}
	s.serviceReportRates[sessionID] = append(kept, now)
	return nil
}

func (s *Service) advertisedFromReport(ctx context.Context, source store.ClientAccount, reported []AdvertisedService) ([]AdvertisedService, error) {
	if len(reported) > 32 {
		return nil, errors.New("at most 32 services per session")
	}
	definitions, err := s.db.ListPeerMeshSharedServices(ctx, source.TenantID, []int64{source.ID})
	if err != nil {
		return nil, err
	}
	byID := map[string]store.PeerMeshSharedService{}
	for _, item := range definitions {
		if item.Enabled {
			byID[item.ServiceID] = item
		}
	}
	seen := map[string]struct{}{}
	var advertised []AdvertisedService
	for _, item := range reported {
		id, err := requireServiceID(item.ServiceID)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[id]; dup {
			return nil, fmt.Errorf("duplicate serviceId: %s", id)
		}
		seen[id] = struct{}{}
		definition, ok := byID[id]
		if !ok {
			continue
		}
		advertised = append(advertised, advertisedFromDefinition(definition))
	}
	return advertised, nil
}

func (s *Service) fanoutCatalog(ctx context.Context, publisher store.ClientAccount, publisherSessionID, revision int64, services []AdvertisedService, expiresAt time.Time) {
	s.fanoutCatalogMode(ctx, publisher, publisherSessionID, revision, services, expiresAt, false)
}

func (s *Service) fanoutCatalogMode(ctx context.Context, publisher store.ClientAccount, publisherSessionID, revision int64,
	services []AdvertisedService, expiresAt time.Time, includeDenied bool) {
	clients, err := s.db.ListClients(ctx)
	if err != nil {
		return
	}
	for _, recipient := range clients {
		if recipient.ID == publisher.ID || recipient.TenantID != publisher.TenantID {
			continue
		}
		ok, err := s.CanPeer(ctx, publisher, recipient)
		if err != nil || (!ok && !includeDenied) {
			continue
		}
		bound, found := s.sessions.Find(recipient.ClientName)
		if !found || bound == nil {
			continue
		}
		visible := make([]AdvertisedService, 0, len(services))
		for _, service := range services {
			if ok && s.visibleTo(ctx, publisher, recipient, service) {
				visible = append(visible, service)
			}
		}
		sessionID := publisherSessionID
		_ = s.sendSignal(bound, "server", recipient.ClientName, ControlMessage{
			Type: TypeServiceCatalog, PublisherClientID: publisher.ID, PublisherClientName: publisher.ClientName,
			PublisherSessionID: &sessionID, Revision: &revision, ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano),
			Services: visible, CreatedAtMillis: time.Now().UnixMilli(),
		})
	}
}

func (s *Service) onAuthorizationChanged(ctx context.Context, tenantID string) {
	type changed struct {
		key      catalogKey
		snapshot catalogSnapshot
	}
	var snapshots []changed
	s.catalogMu.Lock()
	for key, snapshot := range s.catalogs {
		if key.tenantID != tenantID {
			continue
		}
		snapshot.revision = s.nextCatalogRevisionLocked(key)
		s.catalogs[key] = snapshot
		snapshots = append(snapshots, changed{key: key, snapshot: snapshot})
	}
	s.catalogMu.Unlock()
	for _, item := range snapshots {
		publisher, err := s.findTenantClient(ctx, tenantID, item.key.publisherClientID)
		if err == nil && publisher != nil {
			s.fanoutCatalogMode(ctx, *publisher, item.key.publisherSessionID, item.snapshot.revision,
				item.snapshot.services, item.snapshot.expiresAt, true)
		}
	}
}

func (s *Service) pushCurrentCatalogs(ctx context.Context, recipient store.ClientAccount) {
	bound, found := s.sessions.Find(recipient.ClientName)
	if !found || bound == nil {
		return
	}
	type current struct {
		key      catalogKey
		snapshot catalogSnapshot
	}
	now := time.Now()
	var snapshots []current
	s.catalogMu.Lock()
	for key, snapshot := range s.catalogs {
		if key.tenantID == recipient.TenantID && key.publisherClientID != recipient.ID && snapshot.expiresAt.After(now) {
			snapshot.services = append([]AdvertisedService(nil), snapshot.services...)
			snapshots = append(snapshots, current{key: key, snapshot: snapshot})
		}
	}
	s.catalogMu.Unlock()
	for _, item := range snapshots {
		publisher, err := s.findTenantClient(ctx, item.key.tenantID, item.key.publisherClientID)
		if err != nil || publisher == nil {
			continue
		}
		allowed, err := s.CanPeer(ctx, *publisher, recipient)
		if err != nil || !allowed {
			continue
		}
		visible := make([]AdvertisedService, 0, len(item.snapshot.services))
		for _, service := range item.snapshot.services {
			if s.visibleTo(ctx, *publisher, recipient, service) {
				visible = append(visible, service)
			}
		}
		if len(visible) == 0 {
			continue
		}
		sessionID := item.key.publisherSessionID
		revision := item.snapshot.revision
		_ = s.sendSignal(bound, "server", recipient.ClientName, ControlMessage{
			Type: TypeServiceCatalog, PublisherClientID: publisher.ID, PublisherClientName: publisher.ClientName,
			PublisherSessionID: &sessionID, Revision: &revision,
			ExpiresAt: item.snapshot.expiresAt.UTC().Format(time.RFC3339Nano), Services: visible,
			CreatedAtMillis: time.Now().UnixMilli(),
		})
	}
}

func (s *Service) visibleTo(ctx context.Context, publisher, recipient store.ClientAccount, service AdvertisedService) bool {
	definition, err := s.db.FindPeerMeshSharedServiceByServiceID(ctx, publisher.TenantID, publisher.ID, service.ServiceID)
	if err != nil || definition == nil || !definition.Enabled {
		return false
	}
	if strings.EqualFold(definition.Visibility, "OWNER") {
		return normalizeOwner(publisher.OwnerUsername) == normalizeOwner(recipient.OwnerUsername)
	}
	allowed := decodeClientIDs(definition.AllowedClientIDs)
	if len(allowed) == 0 {
		return true
	}
	for _, id := range allowed {
		if id == recipient.ID {
			return true
		}
	}
	return false
}

func (s *Service) withdrawSession(ctx context.Context, publisher store.ClientAccount, sessionID int64) {
	key := catalogKey{publisher.TenantID, publisher.ID, sessionID}
	s.catalogMu.Lock()
	delete(s.catalogs, key)
	delete(s.serviceReportRates, sessionID)
	revision := s.nextCatalogRevisionLocked(key)
	s.catalogMu.Unlock()
	s.fanoutCatalog(ctx, publisher, sessionID, revision, nil, time.Now())
}

func (s *Service) acceptCatalogRevision(key catalogKey, revision int64) bool {
	s.catalogMu.Lock()
	defer s.catalogMu.Unlock()
	if _, exists := s.catalogRevisions[key]; !exists && len(s.catalogRevisions) >= 4096 {
		return false
	}
	if previous := s.catalogRevisions[key]; revision <= previous {
		return false
	}
	s.catalogRevisions[key] = revision
	return true
}

func (s *Service) nextCatalogRevisionLocked(key catalogKey) int64 {
	if _, exists := s.catalogRevisions[key]; !exists && len(s.catalogRevisions) >= 4096 {
		return int64(^uint64(0) >> 1)
	}
	next := s.catalogRevisions[key] + 1
	if next < 1 {
		next = 1
	}
	s.catalogRevisions[key] = next
	return next
}

func (s *Service) expireServiceCatalogs(ctx context.Context, now time.Time) {
	type expiredCatalog struct {
		key      catalogKey
		revision int64
	}
	var expired []expiredCatalog
	s.catalogMu.Lock()
	for key, snapshot := range s.catalogs {
		if snapshot.expiresAt.After(now) {
			continue
		}
		delete(s.catalogs, key)
		expired = append(expired, expiredCatalog{key: key, revision: s.nextCatalogRevisionLocked(key)})
	}
	s.catalogMu.Unlock()
	for _, item := range expired {
		publisher, err := s.findTenantClient(ctx, item.key.tenantID, item.key.publisherClientID)
		if err == nil && publisher != nil {
			s.fanoutCatalog(ctx, *publisher, item.key.publisherSessionID, item.revision, nil, now)
		}
	}
}

func (s *Service) withdrawClient(ctx context.Context, tenantID string, clientID int64) {
	account, err := s.findTenantClient(ctx, tenantID, clientID)
	if err != nil || account == nil {
		return
	}
	s.catalogMu.Lock()
	var keys []catalogKey
	for key := range s.catalogs {
		if key.tenantID == tenantID && key.publisherClientID == clientID {
			keys = append(keys, key)
		}
	}
	s.catalogMu.Unlock()
	for _, key := range keys {
		s.withdrawSession(ctx, *account, key.publisherSessionID)
	}
}

func (s *Service) withdrawTenant(ctx context.Context, tenantID string) {
	s.catalogMu.Lock()
	var keys []catalogKey
	for key := range s.catalogs {
		if key.tenantID == tenantID {
			keys = append(keys, key)
		}
	}
	s.catalogMu.Unlock()
	for _, key := range keys {
		account, err := s.findTenantClient(ctx, tenantID, key.publisherClientID)
		if err != nil || account == nil {
			continue
		}
		s.withdrawSession(ctx, *account, key.publisherSessionID)
	}
}

func (s *Service) pushTenantConfigs(ctx context.Context, tenantID string) {
	clients, err := s.db.ListClients(ctx)
	if err != nil {
		return
	}
	for _, client := range clients {
		if client.TenantID == tenantID {
			s.PushConfig(ctx, client)
		}
	}
}

func (s *Service) configuredSharing(ctx context.Context, tenantID string) (bool, *store.PeerMeshServiceSharing, error) {
	row, err := s.db.GetPeerMeshServiceSharing(ctx, tenantID)
	if err != nil {
		return false, nil, err
	}
	if row == nil {
		return false, nil, nil
	}
	return row.Enabled, row, nil
}

func (s *Service) effectiveSharing(ctx context.Context, account store.ClientAccount) bool {
	if !s.Enabled() {
		return false
	}
	configured, _, err := s.configuredSharing(ctx, account.TenantID)
	if err != nil || !configured {
		return false
	}
	device, err := s.db.FindPeerMeshDeviceByClientID(ctx, account.TenantID, account.ID)
	return err == nil && device != nil && device.Enabled
}

func (s *Service) localServicesFor(ctx context.Context, account store.ClientAccount, clientProtocolVersion int) []LocalPeerService {
	out := []LocalPeerService{}
	if s.db == nil || clientProtocolVersion < 2 {
		return out
	}
	rows, err := s.db.ListPeerMeshSharedServices(ctx, account.TenantID, []int64{account.ID})
	if err != nil {
		return out
	}
	for _, row := range rows {
		allowedPeerVirtualIPs := s.allowedPeerVirtualIPs(ctx, account, row)
		out = append(out, LocalPeerService{
			ServiceID:             row.ServiceID,
			Name:                  row.Name,
			Description:           row.Description,
			Transport:             row.Transport,
			Application:           row.Application,
			TargetHost:            row.TargetHost,
			TargetPort:            row.TargetPort,
			PublishedPort:         row.PublishedPort,
			Path:                  row.Path,
			Enabled:               row.Enabled,
			Visibility:            row.Visibility,
			AllowedPeerVirtualIPs: allowedPeerVirtualIPs,
		})
	}
	return out
}

func (s *Service) allowedPeerVirtualIPs(ctx context.Context, publisher store.ClientAccount, definition store.PeerMeshSharedService) []string {
	if !definition.Enabled {
		return []string{}
	}
	clients, err := s.db.ListClients(ctx)
	if err != nil {
		return []string{}
	}
	explicit := decodeClientIDs(definition.AllowedClientIDs)
	allowed := make([]string, 0)
	for _, recipient := range clients {
		if recipient.ID == publisher.ID || recipient.TenantID != publisher.TenantID {
			continue
		}
		canPeer, err := s.CanPeer(ctx, publisher, recipient)
		if err != nil || !canPeer {
			continue
		}
		visible := normalizeOwner(publisher.OwnerUsername) == normalizeOwner(recipient.OwnerUsername)
		if !strings.EqualFold(definition.Visibility, "OWNER") {
			visible = len(explicit) == 0 || slices.Contains(explicit, recipient.ID)
		}
		if !visible {
			continue
		}
		device, err := s.db.FindPeerMeshDeviceByClientID(ctx, publisher.TenantID, recipient.ID)
		if err == nil && device != nil && device.Enabled && strings.TrimSpace(device.VirtualIP) != "" {
			allowed = append(allowed, strings.TrimSpace(device.VirtualIP))
		}
	}
	slices.Sort(allowed)
	return slices.Compact(allowed)
}

func (s *Service) sharingStatusFor(account store.ClientAccount, device *store.PeerMeshDevice) ServiceSharingStatus {
	configured := false
	if s.db != nil {
		if row, err := s.db.GetPeerMeshServiceSharing(context.Background(), account.TenantID); err == nil && row != nil {
			configured = row.Enabled
		}
	}
	mdns := false
	if s.db != nil {
		if row, err := s.db.GetPeerMeshServiceSharing(context.Background(), account.TenantID); err == nil && row != nil {
			mdns = row.MdnsImportEnabled
		}
	}
	deviceEnabled := s.Enabled() && device != nil && device.Enabled
	effective := s.Enabled() && configured && deviceEnabled
	return ServiceSharingStatus{
		DeploymentEnabled: s.Enabled(),
		ConfiguredEnabled: configured,
		EffectiveEnabled:  effective,
		MdnsImportEnabled: mdns && effective,
	}
}

func (s *Service) audit(action, tenantID string, clientID, sessionID *int64, serviceID, reason string) {
	if s == nil {
		return
	}
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	s.audits = append([]AuditEvent{{
		At:        time.Now().UTC().Format(time.RFC3339Nano),
		Action:    action,
		TenantID:  tenantID,
		ClientID:  clientID,
		SessionID: sessionID,
		ServiceID: serviceID,
		Reason:    reason,
	}}, s.audits...)
	if len(s.audits) > 80 {
		s.audits = s.audits[:80]
	}
}

func (s *Service) RecentAudits(access AccessContext) []AuditEvent {
	if s == nil {
		return []AuditEvent{}
	}
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	out := make([]AuditEvent, 0)
	for _, event := range s.audits {
		if event.TenantID == access.TenantID {
			out = append(out, event)
			if len(out) >= 50 {
				break
			}
		}
	}
	return out
}

func (s *Service) sharedServiceView(ctx context.Context, row store.PeerMeshSharedService, includeTarget bool) SharedServiceView {
	view := SharedServiceView{
		ID: row.ID, ServiceID: row.ServiceID, ClientID: row.ClientID, ClientName: row.ClientName,
		Name: row.Name, Description: row.Description, Transport: row.Transport, Application: row.Application,
		PublishedPort: row.PublishedPort, Path: row.Path, Enabled: row.Enabled, Visibility: row.Visibility,
		AllowedClientIDs: decodeClientIDs(row.AllowedClientIDs),
		CreatedAt:        row.CreatedAt.UTC().Format(time.RFC3339Nano), UpdatedAt: row.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
	if includeTarget {
		host := row.TargetHost
		view.TargetHost = &host
		view.TargetPort = row.TargetPort
	}
	if device, err := s.db.FindPeerMeshDeviceByClientID(ctx, row.TenantID, row.ClientID); err == nil && device != nil && device.VirtualIP != "" {
		address := device.VirtualIP + ":" + fmt.Sprintf("%d", row.PublishedPort)
		view.PublishedAddress = &address
	}
	s.catalogMu.Lock()
	for key, snapshot := range s.catalogs {
		if key.tenantID != row.TenantID || key.publisherClientID != row.ClientID {
			continue
		}
		advertised := false
		for _, item := range snapshot.services {
			if item.ServiceID == row.ServiceID {
				advertised = true
				break
			}
		}
		stats := statsFor(snapshot.stats, row.ServiceID)
		view.Instances = append(view.Instances, ServiceInstanceView{
			PublisherSessionID: key.publisherSessionID,
			InstanceID:         snapshot.instanceID,
			Online:             advertised,
			Advertised:         advertised,
			Revision:           snapshot.revision,
			LastReportedAt:     snapshot.generatedAt.UTC().Format(time.RFC3339Nano),
			ExpiresAt:          snapshot.expiresAt.UTC().Format(time.RFC3339Nano),
			BytesIn:            stats.BytesIn,
			BytesOut:           stats.BytesOut,
			ActiveConnections:  stats.ActiveConnections,
			TotalConnections:   stats.TotalConnections,
		})
	}
	s.catalogMu.Unlock()
	return view
}

func (s *Service) rejectPortConflict(ctx context.Context, row store.PeerMeshSharedService) error {
	if !row.Enabled {
		return nil
	}
	items, err := s.db.ListPeerMeshSharedServices(ctx, row.TenantID, []int64{row.ClientID})
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.ID != row.ID && item.Enabled && item.PublishedPort == row.PublishedPort {
			return errors.New("publishedPort already used by another enabled service")
		}
	}
	return nil
}

func advertisedFromDefinition(row store.PeerMeshSharedService) AdvertisedService {
	return AdvertisedService{
		ServiceID: row.ServiceID, Name: row.Name, Description: row.Description,
		Transport: row.Transport, Application: row.Application, PublishedPort: row.PublishedPort, Path: row.Path,
	}
}

func applyServiceMutation(row *store.PeerMeshSharedService, mutation ServiceMutation, creating bool) error {
	if creating || mutation.Name != nil {
		name, err := requireName(valueOr(mutation.Name, row.Name))
		if err != nil {
			return err
		}
		row.Name = name
	}
	if mutation.Description != nil || creating {
		row.Description = strings.TrimSpace(valueOr(mutation.Description, row.Description))
		if len(row.Description) > 200 {
			return errors.New("description exceeds 200 characters")
		}
	}
	if creating || mutation.Application != nil {
		application, err := requireApplication(valueOr(mutation.Application, row.Application))
		if err != nil {
			return err
		}
		row.Application = application
	}
	transport, err := requireTransportForApplication(valueOr(mutation.Transport, row.Transport), row.Application)
	if err != nil {
		return err
	}
	row.Transport = transport
	if creating || mutation.TargetHost != nil {
		host, err := requireTargetHost(valueOr(mutation.TargetHost, row.TargetHost))
		if err != nil {
			return err
		}
		row.TargetHost = host
	}
	if creating || mutation.TargetPort != nil {
		port, err := requirePort(intOr(mutation.TargetPort, row.TargetPort), "targetPort")
		if err != nil {
			return err
		}
		row.TargetPort = port
	}
	if creating || mutation.PublishedPort != nil {
		port, err := requirePort(intOr(mutation.PublishedPort, row.PublishedPort), "publishedPort")
		if err != nil {
			return err
		}
		row.PublishedPort = port
	}
	if creating || mutation.Path != nil {
		path, err := requirePath(valueOr(mutation.Path, row.Path), row.Application)
		if err != nil {
			return err
		}
		row.Path = path
	}
	if creating || mutation.Visibility != nil {
		row.Visibility = requireVisibility(valueOr(mutation.Visibility, row.Visibility))
	}
	if mutation.Enabled != nil {
		row.Enabled = *mutation.Enabled
	} else if creating {
		row.Enabled = false
	}
	if creating || mutation.AllowedClientIDs != nil {
		encoded, err := encodeClientIDs(mutation.AllowedClientIDs)
		if err != nil {
			return err
		}
		row.AllowedClientIDs = encoded
	}
	return nil
}

func requireServiceID(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if !serviceIDPattern.MatchString(value) {
		return "", errors.New("invalid serviceId")
	}
	return value, nil
}

func requireName(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > 80 {
		return "", errors.New("name is required")
	}
	return value, nil
}

func requireTransportForApplication(transport, application string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(transport))
	if value == "" {
		if application == "udp" {
			value = "udp"
		} else {
			value = "tcp"
		}
	}
	if value != "tcp" && value != "udp" {
		return "", errors.New("transport must be tcp or udp")
	}
	if application == "udp" && value != "udp" {
		return "", errors.New("udp application requires udp transport")
	}
	if application != "udp" && value == "udp" {
		return "", errors.New("http/https/ssh/tcp applications require tcp transport")
	}
	return value, nil
}

func encodeClientIDs(ids []int64) (string, error) {
	seen := map[int64]struct{}{}
	var out []string
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, strconv.FormatInt(id, 10))
	}
	if len(out) > 32 {
		return "", errors.New("at most 32 allowedClientIds")
	}
	return strings.Join(out, ","), nil
}

func decodeClientIDs(raw string) []int64 {
	if strings.TrimSpace(raw) == "" {
		return []int64{}
	}
	var out []int64
	seen := map[int64]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		id, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
		if err != nil || id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func sanitizeMdnsCandidates(raw []MdnsCandidate) []MdnsCandidate {
	var out []MdnsCandidate
	seen := map[string]struct{}{}
	for _, item := range raw {
		if len(out) >= 32 {
			break
		}
		name, err := requireName(item.Name)
		if err != nil {
			continue
		}
		application, err := requireApplication(item.Application)
		if err != nil {
			continue
		}
		transport, err := requireTransportForApplication(item.Transport, application)
		if err != nil {
			continue
		}
		host, err := requireTargetHost(item.TargetHost)
		if err != nil {
			continue
		}
		port, err := requirePort(item.TargetPort, "targetPort")
		if err != nil {
			continue
		}
		key := application + ":" + host + ":" + strconv.Itoa(port)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, MdnsCandidate{Name: name, Transport: transport, Application: application, TargetHost: host, TargetPort: port})
	}
	return out
}

func requireApplication(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	for _, item := range peerServiceApps {
		if item == value {
			return value, nil
		}
	}
	return "", errors.New("unsupported application")
}

func requirePort(port int, field string) (int, error) {
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("%s must be 1..65535", field)
	}
	return port, nil
}

func requireTargetHost(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	lower := strings.ToLower(value)
	if value == "" || strings.ContainsAny(lower, "/@?#") || strings.Contains(lower, "://") {
		return "", errors.New("targetHost must be a local address, not a URL")
	}
	if strings.EqualFold(value, "localhost") || value == "127.0.0.1" || value == "::1" {
		return value, nil
	}
	ip := net.ParseIP(value)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return "", errors.New("targetHost must be a unicast IP or localhost")
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return value, nil
	}
	return "", errors.New("targetHost must be loopback or a local interface address")
}

func requirePath(raw, application string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		if application == "http" || application == "https" {
			return "/", nil
		}
		return "", nil
	}
	if strings.Contains(value, "://") || strings.Contains(value, "..") || strings.Contains(value, "\\") || strings.Contains(value, " ") {
		return "", errors.New("path must be a safe relative HTTP path")
	}
	if !pathPattern.MatchString(value) {
		return "", errors.New("path contains unsupported characters")
	}
	return value, nil
}

func requireVisibility(raw string) string {
	value := strings.ToUpper(strings.TrimSpace(raw))
	if value == "ACL" {
		return "ACL"
	}
	return "OWNER"
}

func EncodePeerServiceApplications(apps []string) string {
	return encodeApplications(apps)
}

func NormalizePeerServiceVersion(version int) int {
	return normalizePeerServiceVersion(version)
}

func decodeApplications(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		for _, allowed := range peerServiceApps {
			if part == allowed {
				out = append(out, part)
				break
			}
		}
	}
	return out
}

func encodeApplications(apps []string) string {
	return strings.Join(decodeApplications(strings.Join(apps, ",")), ",")
}

func normalizePeerServiceVersion(version int) int {
	if version < 1 {
		return 0
	}
	if version > peerServiceDiscoveryVersion {
		return peerServiceDiscoveryVersion
	}
	return version
}

func (s *Service) ImportCandidates(ctx context.Context, access AccessContext, clientID int64) (ImportResult, error) {
	return s.ImportCandidatesFrom(ctx, access, clientID, "tcp-http")
}

func (s *Service) ImportCandidatesFrom(ctx context.Context, access AccessContext, clientID int64, source string) (ImportResult, error) {
	if !access.Admin {
		return ImportResult{}, errForbidden("只有管理员可以修改 Peer 服务共享")
	}
	account, err := s.findTenantClient(ctx, access.TenantID, clientID)
	if err != nil {
		return ImportResult{}, err
	}
	if strings.EqualFold(source, "mdns") {
		return s.importMdns(ctx, access, *account)
	}
	existing, err := s.db.ListPeerMeshSharedServices(ctx, account.TenantID, []int64{account.ID})
	if err != nil {
		return ImportResult{}, err
	}
	used := map[string]struct{}{}
	for _, row := range existing {
		used[row.TargetHost+":"+fmt.Sprintf("%d", row.TargetPort)] = struct{}{}
	}
	result := ImportResult{Services: []SharedServiceView{}}
	mappings, err := s.db.ListSpecusMappings(ctx, &account.ID)
	if err != nil {
		return ImportResult{}, err
	}
	for _, mapping := range mappings {
		if s.importCandidate(ctx, access, *account, mapping.TargetAddress, mapping.TargetPort, mapping.ListenPort,
			fmt.Sprintf("tcp-%d", mapping.ListenPort), "tcp", "", used, &result) {
			continue
		}
		result.Skipped++
	}
	routes, err := s.db.ListHTTPRoutes(ctx, &account.ID)
	if err != nil {
		return ImportResult{}, err
	}
	for _, route := range routes {
		host, port, application, path, ok := parseHTTPCandidate(route.TargetBaseURL)
		if !ok || !s.importCandidate(ctx, access, *account, host, port, port, route.Route, application, path, used, &result) {
			result.Skipped++
		}
	}
	return result, nil
}

func (s *Service) importCandidate(ctx context.Context, access AccessContext, account store.ClientAccount,
	host string, targetPort, publishedPort int, name, application, path string,
	used map[string]struct{}, result *ImportResult) bool {
	normalized, err := requireTargetHost(host)
	if err != nil {
		return false
	}
	key := normalized + ":" + fmt.Sprintf("%d", targetPort)
	if _, exists := used[key]; exists {
		return false
	}
	used[key] = struct{}{}
	view, err := s.CreateSharedService(ctx, access, ServiceMutation{
		ClientID: &account.ID, Name: &name, Application: &application,
		TargetHost: &normalized, TargetPort: &targetPort, PublishedPort: &publishedPort, Path: &path,
	})
	if err != nil {
		delete(used, key)
		return false
	}
	result.Created++
	result.Services = append(result.Services, view)
	return true
}

func (s *Service) importMdns(ctx context.Context, access AccessContext, account store.ClientAccount) (ImportResult, error) {
	status := s.sharingStatusFor(account, nil)
	if !status.MdnsImportEnabled && !s.mdnsConfigured(ctx, account.TenantID) {
		return ImportResult{}, errors.New("mDNS 候选导入未开启")
	}
	existing, err := s.db.ListPeerMeshSharedServices(ctx, account.TenantID, []int64{account.ID})
	if err != nil {
		return ImportResult{}, err
	}
	used := map[string]struct{}{}
	for _, row := range existing {
		used[row.TargetHost+":"+fmt.Sprintf("%d", row.TargetPort)] = struct{}{}
	}
	result := ImportResult{Services: []SharedServiceView{}}
	s.catalogMu.Lock()
	var candidates []MdnsCandidate
	for key, snapshot := range s.catalogs {
		if key.tenantID == account.TenantID && key.publisherClientID == account.ID {
			candidates = append(candidates, snapshot.mdns...)
		}
	}
	s.catalogMu.Unlock()
	for _, candidate := range candidates {
		transport := candidate.Transport
		application := candidate.Application
		name := candidate.Name
		host := candidate.TargetHost
		port := candidate.TargetPort
		if !s.importCandidateWithTransport(ctx, access, account, host, port, port, name, transport, application, "", used, &result) {
			result.Skipped++
		}
	}
	return result, nil
}

func (s *Service) mdnsConfigured(ctx context.Context, tenantID string) bool {
	row, err := s.db.GetPeerMeshServiceSharing(ctx, tenantID)
	return err == nil && row != nil && row.Enabled && row.MdnsImportEnabled && s.Enabled()
}

func (s *Service) importCandidateWithTransport(ctx context.Context, access AccessContext, account store.ClientAccount,
	host string, targetPort, publishedPort int, name, transport, application, path string,
	used map[string]struct{}, result *ImportResult) bool {
	normalized, err := requireTargetHost(host)
	if err != nil {
		return false
	}
	key := normalized + ":" + fmt.Sprintf("%d", targetPort)
	if _, exists := used[key]; exists {
		return false
	}
	used[key] = struct{}{}
	view, err := s.CreateSharedService(ctx, access, ServiceMutation{
		ClientID: &account.ID, Name: &name, Transport: &transport, Application: &application,
		TargetHost: &normalized, TargetPort: &targetPort, PublishedPort: &publishedPort, Path: &path,
	})
	if err != nil {
		delete(used, key)
		return false
	}
	result.Created++
	result.Services = append(result.Services, view)
	return true
}

func parseHTTPCandidate(raw string) (host string, port int, application, path string, ok bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return "", 0, "", "", false
	}
	application = "http"
	if strings.EqualFold(parsed.Scheme, "https") {
		application = "https"
	}
	host = parsed.Hostname()
	targetPort := 80
	if application == "https" {
		targetPort = 443
	}
	if rawPort := parsed.Port(); rawPort != "" {
		if parsedPort, err := strconv.Atoi(rawPort); err == nil {
			targetPort = parsedPort
		}
	}
	path = parsed.Path
	if path == "" {
		path = "/"
	}
	return host, targetPort, application, path, host != ""
}

func copyServiceStats(raw []ServiceStats, advertised []AdvertisedService) []ServiceStats {
	ids := map[string]struct{}{}
	for _, item := range advertised {
		ids[item.ServiceID] = struct{}{}
	}
	var out []ServiceStats
	for _, item := range raw {
		if _, ok := ids[item.ServiceID]; !ok {
			continue
		}
		if item.BytesIn < 0 {
			item.BytesIn = 0
		}
		if item.BytesOut < 0 {
			item.BytesOut = 0
		}
		out = append(out, item)
	}
	return out
}

func statsFor(stats []ServiceStats, serviceID string) ServiceStats {
	for _, item := range stats {
		if item.ServiceID == serviceID {
			return item
		}
	}
	return ServiceStats{ServiceID: serviceID}
}

func valueOr(ptr *string, fallback string) string {
	if ptr == nil {
		return fallback
	}
	return *ptr
}

func intOr(ptr *int, fallback int) int {
	if ptr == nil {
		return fallback
	}
	return *ptr
}

type ForbiddenError struct{ Msg string }

func (e ForbiddenError) Error() string { return e.Msg }

func errForbidden(message string) error { return ForbiddenError{Msg: message} }
