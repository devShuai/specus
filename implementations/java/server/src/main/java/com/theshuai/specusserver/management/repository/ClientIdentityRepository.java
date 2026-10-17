package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ClientIdentity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.List;

public interface ClientIdentityRepository extends JpaRepository<ClientIdentity, Long> {
    /** Stable edges only: identity creation allocates a NEW client ID under its credential.
     * Do not lock foreign identity rows while holding only the authenticating credential.
     * No current owner/status decision may be made from this plain snapshot read. */
    @Transactional(propagation = Propagation.MANDATORY)
    @Query(value = "select credential_id,tenant_id from specus_client_identity where client_id=:clientId", nativeQuery = true)
    List<Object[]> findCredentialBindings(@Param("clientId") Long clientId);

    Optional<ClientIdentity> findByCredentialIdAndMachineFingerprintAndOsUser(Long credentialId,
                                                                               String machineFingerprint,
                                                                               String osUser);
}
