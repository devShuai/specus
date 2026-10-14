package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ClientCredential;
import java.util.Optional;

public interface ClientCredentialRepositoryCustom {
    /** Requires the caller's write transaction; lock and reload, never trust a prior entity snapshot. */
    Optional<ClientCredential> lockCurrent(Long id, String tenantId);
}
