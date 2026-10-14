package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ClientAccount;
import java.util.Optional;

public interface ClientAccountRepositoryCustom {
    /** Caller write transaction required; credential locks precede the client lock. Returns a
     * detached current scalar snapshot, not a cached entity or an older RR snapshot. */
    Optional<ClientAccount> lockCurrent(Long id, String tenantId);
}
