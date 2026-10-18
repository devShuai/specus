package peermesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// ReconcileOwnership runs after a durable audit read has released its connection. It reads
// CURRENT policy, never applies historical owners, never provisions missing Peer devices and
// never disconnects the client's control/data transport. Error means no receipt may be written.
func (s *Service) ReconcileOwnership(ctx context.Context, tenant string, affected []int64) error {
	if len(affected) == 0 {
		return nil
	} // an empty credential group is not the entire tenant
	rows, err := s.db.PeerSessionsAffectedByOwnership(ctx, tenant, affected)
	if err != nil {
		return err
	}
	ids := make([]int64, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	s.invalidateRelayAuthorizations(ids)
	closed, err := s.db.CloseUnauthorizedPeerMeshSessions(ctx, tenant, ids)
	if err != nil {
		return err
	}
	var failures []error
	for _, view := range s.committedPeerClosures(closed) {
		if err := s.sendOwnershipClose(ctx, view); err != nil {
			failures = append(failures, err)
		}
	}
	clients, err := s.db.ListClients(ctx)
	if err != nil {
		return errors.Join(append(failures, err)...)
	}
	for _, client := range clients {
		if client.TenantID != tenant {
			continue
		}
		bound, ok := s.sessions.Find(client.ClientName)
		if !ok || bound == nil {
			continue
		}
		if err := s.pushOwnershipConfiguration(ctx, client, bound); err != nil {
			failures = append(failures, err)
		}
	}
	if err := s.pushOwnershipCatalogs(ctx, tenant, clients); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func (s *Service) sendOwnershipClose(ctx context.Context, view SessionView) error {
	message := ControlMessage{Type: TypeClose, SessionID: &view.ID, SourceClientID: view.SourceClientID, SourceClientName: view.SourceClientName, TargetClientID: view.TargetClientID, TargetClientName: view.TargetClientName, Status: StatusClosed, Reason: "owner-transfer", CreatedAtMillis: time.Now().UnixMilli()}
	var failures []error
	for _, name := range []string{view.SourceClientName, view.TargetClientName} {
		if bound, ok := s.sessions.Find(name); ok && bound != nil {
			if err := s.sendOwnershipSignal(ctx, bound, name, message); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

func (s *Service) pushOwnershipConfiguration(ctx context.Context, client store.ClientAccount, bound session.Session) error {
	cfg, err := s.buildRuntimeConfig(ctx, client, false)
	if err != nil {
		return err
	}
	online, err := s.db.GetOnlineClientSession(ctx, client.TenantID, client.ID, auth.StatusNettyOnline)
	if err != nil {
		return err
	}
	version := 0
	if online != nil {
		version = online.PeerServiceDiscoveryVersion
	}
	cfg.LocalServices, err = s.localServicesForChecked(ctx, client, version)
	if err != nil {
		return err
	}
	sharing, err := s.db.GetPeerMeshServiceSharing(ctx, client.TenantID)
	if err != nil {
		return err
	}
	cfg.ServiceSharing.ConfiguredEnabled = sharing != nil && sharing.Enabled
	cfg.ServiceSharing.EffectiveEnabled = cfg.ServiceSharing.ConfiguredEnabled && cfg.Enabled
	cfg.ServiceSharing.MdnsImportEnabled = sharing != nil && sharing.MdnsImportEnabled && cfg.ServiceSharing.EffectiveEnabled
	if err := s.sendOwnershipSignal(ctx, bound, client.ClientName, ControlMessage{Type: TypeConfig, SourceClientID: client.ID, SourceClientName: client.ClientName, TargetClientID: client.ID, TargetClientName: client.ClientName, PeerMesh: &cfg, CreatedAtMillis: time.Now().UnixMilli()}); err != nil {
		return err
	}
	peers, err := s.AllowedRoster(ctx, client)
	if err != nil {
		return err
	}
	if err := s.sendOwnershipSignal(ctx, bound, client.ClientName, ControlMessage{Type: TypeRoster, SourceClientID: client.ID, SourceClientName: client.ClientName, Peers: peers, CreatedAtMillis: time.Now().UnixMilli()}); err != nil {
		return err
	}
	if online == nil || online.ClientEgressVersion < 1 {
		return nil
	}
	capabilities := &EgressCapabilities{Version: online.ClientEgressVersion}
	config, err := s.BuildEgressConfig(ctx, client, capabilities)
	if err != nil {
		return err
	}
	catalog, err := s.BuildEgressCatalog(ctx, client, capabilities)
	if err != nil {
		return err
	}
	for _, message := range []*ControlMessage{config, catalog} {
		if message != nil {
			message.SourceClientID = client.ID
			message.SourceClientName = client.ClientName
			message.TargetClientID = client.ID
			message.TargetClientName = client.ClientName
			message.CreatedAtMillis = time.Now().UnixMilli()
			if err := s.sendOwnershipSignal(ctx, bound, client.ClientName, *message); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) pushOwnershipCatalogs(ctx context.Context, tenant string, clients []store.ClientAccount) error {
	sharing, err := s.db.GetPeerMeshServiceSharing(ctx, tenant)
	if err != nil {
		return err
	}
	sharingEnabled := s.Enabled() && sharing != nil && sharing.Enabled
	type current struct {
		key      catalogKey
		snapshot catalogSnapshot
	}
	var snapshots []current
	s.catalogMu.Lock()
	for key, snapshot := range s.catalogs {
		if key.tenantID == tenant {
			snapshot.services = append([]AdvertisedService(nil), snapshot.services...)
			snapshot.revision = s.nextCatalogRevisionLocked(key)
			if snapshot.revision < 1 {
				s.catalogMu.Unlock()
				return errors.New("ownership catalog revision unavailable")
			}
			s.catalogs[key] = snapshot
			snapshots = append(snapshots, current{key, snapshot})
		}
	}
	s.catalogMu.Unlock()
	for _, item := range snapshots {
		publisher, err := s.findTenantClient(ctx, tenant, item.key.publisherClientID)
		publisherExists := true
		if errors.Is(err, store.ErrNotFound) {
			publisherExists = false
			publisher = &store.ClientAccount{ID: item.key.publisherClientID, TenantID: tenant, ClientName: item.snapshot.publisherClientName}
			err = nil
		}
		if err != nil {
			return err
		}
		online, err := s.db.GetClientSession(ctx, item.key.publisherSessionID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		currentPublisher := publisherExists && err == nil && online != nil && online.TenantID == tenant && online.ClientID == publisher.ID && online.Status == auth.StatusNettyOnline && online.ExpiresAt.After(time.Now())
		for _, recipient := range clients {
			if recipient.TenantID != tenant || recipient.ID == publisher.ID {
				continue
			}
			bound, ok := s.sessions.Find(recipient.ClientName)
			if !ok || bound == nil {
				continue
			}
			allowed := false
			if sharingEnabled && currentPublisher {
				allowed, err = s.CanPeer(ctx, recipient, *publisher)
				if err != nil {
					return err
				}
			}
			visible := []AdvertisedService{}
			if allowed && item.snapshot.expiresAt.After(time.Now()) {
				for _, advertised := range item.snapshot.services {
					definition, err := s.db.FindPeerMeshSharedServiceByServiceID(ctx, tenant, publisher.ID, advertised.ServiceID)
					if err != nil {
						return err
					}
					if definition == nil || !definition.Enabled {
						continue
					}
					permitted := normalizeOwner(publisher.OwnerUsername) == normalizeOwner(recipient.OwnerUsername)
					if !strings.EqualFold(definition.Visibility, "OWNER") {
						ids := decodeClientIDs(definition.AllowedClientIDs)
						permitted = len(ids) == 0 || slices.Contains(ids, recipient.ID)
					}
					if permitted {
						visible = append(visible, advertised)
					}
				}
			}
			id, revision := item.key.publisherSessionID, item.snapshot.revision
			message := ControlMessage{Type: TypeServiceCatalog, PublisherClientID: publisher.ID, PublisherClientName: publisher.ClientName, PublisherSessionID: &id, Revision: &revision, ExpiresAt: item.snapshot.expiresAt.UTC().Format(time.RFC3339Nano), Services: visible, CreatedAtMillis: time.Now().UnixMilli()}
			if err := s.sendOwnershipSignal(ctx, bound, recipient.ClientName, message); err != nil {
				return fmt.Errorf("ownership catalog delivery: %w", err)
			}
		}
	}
	return nil
}

func (s *Service) sendOwnershipSignal(ctx context.Context, bound session.Session, name string, signal ControlMessage) error {
	sender, ok := bound.(interface {
		SendContext(context.Context, protocol.Packet) error
	})
	if !ok {
		return errors.New("ownership notification requires bounded transport delivery")
	}
	data, err := json.Marshal(signal)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return sender.SendContext(ctx, protocol.MessageResponse{ClientName: "server", ToClientName: name, MessageType: protocol.MessageTypePeerControl, Message: string(data)})
}
