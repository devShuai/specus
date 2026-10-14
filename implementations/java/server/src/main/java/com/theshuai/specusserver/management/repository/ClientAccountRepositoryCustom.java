package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ClientAccount;
import java.util.Optional;
import java.util.Collection;
import java.util.Map;

public interface ClientAccountRepositoryCustom {
    /** Caller write transaction required; credential locks precede the client lock. Returns a
     * detached current scalar snapshot, not a cached entity or an older RR snapshot. */
    Optional<ClientAccount> lockCurrent(Long id, String tenantId);
    /** All stable linked credentials in global order, then all clients in ID order. Call before
     * holding any per-client/credential lock in a multi-client operation. Missing clients omitted. */
    Map<Long, ClientAccount> lockCurrentAll(Collection<Long> ids, String tenantId);
}
