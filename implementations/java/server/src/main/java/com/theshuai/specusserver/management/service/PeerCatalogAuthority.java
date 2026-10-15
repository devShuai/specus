package com.theshuai.specusserver.management.service;

import com.theshuai.common.peermesh.PeerAdvertisedService;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerServiceDiscovery;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.ClientControlSessionAuthority;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

/** A fresh worker transaction holds ordered credential/client, policy, exact control session,
 * sharing and definition locks until network acceptance. Informational roster hints never grant
 * catalog access. Empty withdrawals deliberately need no remaining publisher or peer permission. */
@Service
public class PeerCatalogAuthority {
    private final ClientAccountRepository accounts;
    private final ClientControlSessionAuthority controls;
    private final PeerMeshService peers;
    @PersistenceContext private EntityManager entities;
    public PeerCatalogAuthority(ClientAccountRepository accounts, ClientControlSessionAuthority controls, PeerMeshService peers) {
        this.accounts = accounts; this.controls = controls; this.peers = peers;
    }

    @Transactional
    public void publish(String tenant, long publisherId, long recipientId, PeerControlMessage catalog,
                        PeerCatalogPublicationService.Binding from, PeerCatalogPublicationService.Binding to,
                        Consumer<PeerControlMessage> writer) {
        var parents = accounts.lockCurrentAll(List.of(publisherId, recipientId), tenant);
        var recipient = parents.get(recipientId);
        if (recipient == null || !recipient.isEnabled() || !to.matches(recipient)) throw denied();
        if (!controls.discoveryAllowed(recipient, to.authentication(), to.channel().id().asLongText())) throw denied();
        var publisher = parents.get(publisherId);
        List<PeerAdvertisedService> visible = List.of();
        if (catalog.getServices() != null && !catalog.getServices().isEmpty() && peers.isEnabled()
                && publisher != null && from != null && from.matches(publisher)
                && Objects.equals(from.authentication(), catalog.getPublisherSessionId())
                && publisher.getClientName().equals(catalog.getPublisherClientName())
                && Instant.parse(catalog.getExpiresAt()).isAfter(Instant.now())) {
            // A consumer initiates toward the publisher, not publisher -> consumer.
            boolean allowed = peers.canPeerCurrent(recipient, publisher)
                    && controls.discoveryAllowed(publisher, from.authentication(), from.channel().id().asLongText());
            if (allowed && sharingEnabled(tenant)) visible = visibleServices(tenant, publisher, recipient, catalog.getServices());
        }
        catalog.setServices(visible);
        if (publisher != null) catalog.setPublisherClientName(publisher.getClientName());
        if (!to.matches(recipient)) return;
        if (!visible.isEmpty() && !from.matches(publisher)) return;
        writer.accept(catalog);
    }

    private boolean sharingEnabled(String tenant) {
        var rows = entities.createNativeQuery("select enabled,tenant_id from peer_mesh_service_sharing where tenant_id=?1" + sharingReadLock())
                .setParameter(1, tenant).getResultList();
        if (rows.size() != 1) return false;
        Object[] row = (Object[]) rows.getFirst();
        return tenant.equals(row[1]) && bool(row[0]);
    }
    private List<PeerAdvertisedService> visibleServices(String tenant, ClientAccount publisher, ClientAccount recipient,
                                                        List<PeerAdvertisedService> offered) {
        // Plain native current locking rows bypass both an earlier MySQL RR view and JPA's L1.
        // Existing definition edits/deletes block on these locks; new rows cannot authorize an
        // unreported service because only IDs in the committed publisher snapshot are considered.
        var rows = entities.createNativeQuery("""
                select tenant_id,client_id,service_id,name,description,transport,application,published_port,path,
                       enabled,visibility,allowed_client_ids
                  from peer_mesh_shared_service where tenant_id=?1 and client_id=?2 order by id
                """ + rowLock()).setParameter(1, tenant).setParameter(2, publisher.getId()).getResultList();
        Map<String,Object[]> definitions = new LinkedHashMap<>();
        for (Object value : rows) {
            Object[] row = (Object[]) value;
            if (tenant.equals(row[0]) && Objects.equals(publisher.getId(), ((Number) row[1]).longValue())) definitions.put((String) row[2], row);
        }
        List<PeerAdvertisedService> visible = new ArrayList<>();
        for (PeerAdvertisedService reported : offered) {
            Object[] row = definitions.get(reported.getServiceId());
            if (row == null || !bool(row[9])) continue;
            if (PeerServiceDiscovery.VISIBILITY_OWNER.equals(row[10])) {
                if (!owner(publisher).equals(owner(recipient))) continue;
            } else if (PeerServiceDiscovery.VISIBILITY_ACL.equals(row[10])) {
                if (!allowedRecipient((String) row[11], recipient.getId())) continue;
            } else continue; // Unknown visibility must never broaden access.
            var service = new PeerAdvertisedService(); service.setServiceId((String) row[2]); service.setName((String) row[3]);
            service.setDescription((String) row[4]); service.setTransport((String) row[5]); service.setApplication((String) row[6]);
            service.setPublishedPort(((Number) row[7]).intValue()); service.setPath((String) row[8]);
            // Do not advertise a new listener/protocol until the publisher has reported it.
            if (!Objects.equals(reported.getTransport(), service.getTransport()) || !Objects.equals(reported.getApplication(), service.getApplication())
                    || reported.getPublishedPort() != service.getPublishedPort() || !Objects.equals(reported.getPath(), service.getPath())) continue;
            visible.add(service);
        }
        return List.copyOf(visible);
    }
    private String rowLock() { return entities.unwrap(Session.class).doReturningWork(c -> c.getMetaData().supportsSelectForUpdate() ? " for update" : ""); }
    private String sharingReadLock() {
        return entities.unwrap(Session.class).doReturningWork(c -> {
            if (!c.getMetaData().supportsSelectForUpdate()) return "";
            String product=c.getMetaData().getDatabaseProductName().toLowerCase(Locale.ROOT);
            // Shared readers keep unrelated publishers independent while still fencing a toggle.
            return product.contains("mysql") || product.contains("mariadb") ? " lock in share mode" : " for share";
        });
    }
    private static boolean bool(Object value) { return value instanceof Boolean flag ? flag : value instanceof Number number && number.intValue() != 0; }
    private static boolean allowedRecipient(String raw, long recipient) {
        if (raw == null || raw.isBlank()) return true;
        boolean matched=false;
        for (String part : raw.split(",",-1)) {
            try { long id=Long.parseLong(part.trim()); if(id<=0)return false; matched |= id==recipient; }
            catch(NumberFormatException malformed) { return false; }
        }
        return matched;
    }
    private static String owner(ClientAccount account) { String value=account.getOwnerUsername(); return value == null || value.isBlank() ? "admin" : value.trim(); }
    private static IllegalArgumentException denied() { return new IllegalArgumentException("catalog consumer control connection is no longer current"); }
}
