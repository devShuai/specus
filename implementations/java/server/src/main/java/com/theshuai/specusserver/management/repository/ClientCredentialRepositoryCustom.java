package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ClientCredential;
import java.util.Optional;

public interface ClientCredentialRepositoryCustom {
    /** Requires the caller's write transaction. Returns a detached, current locking-read snapshot;
     * save explicitly after mutation. Never trust a prior entity or repeatable-read snapshot. */
    Optional<ClientCredential> lockCurrent(Long id, String tenantId);
}
