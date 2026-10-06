package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.repository.ManagementWorkbenchItemRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Removes workbench references when what they point at goes away (protocol/spec/service-workbench.md
 * sections 3 and 5.4). Called by the existing delete paths inside their own transaction, so a
 * reference never outlives its object or its account: an id handed out again later, or an account
 * recreated under the same name, starts without them. Disabling an account or changing a client's
 * owner deletes nothing.
 */
@Component
public class WorkbenchReferences {
    public static final String HTTP_ROUTE = "http-route";
    public static final String TCP_MAPPING = "tcp-mapping";
    public static final String PEER_SERVICE = "peer-service";

    private final ManagementWorkbenchItemRepository repository;

    public WorkbenchReferences(ManagementWorkbenchItemRepository repository) {
        this.repository = repository;
    }

    /** An HTTP route, TCP mapping or Peer service is deleted: every identity's reference goes. */
    @Transactional
    public void forgetObject(String kind, long objectId) {
        repository.deleteByObject(kind, objectId);
    }

    /**
     * A client is deleted: every identity's reference to any route, mapping or Peer service it
     * carries goes, although those rows themselves stay behind. Call before the services' rows
     * would ever be removed, as the lookup goes through them.
     */
    @Transactional
    public void forgetClientServices(long clientId) {
        repository.deleteByClient(clientId);
    }

    /** An account is deleted: both lists of that identity go. */
    @Transactional
    public void forgetIdentity(String tenantId, String username) {
        repository.deleteByIdentity(tenantId, username);
    }
}
