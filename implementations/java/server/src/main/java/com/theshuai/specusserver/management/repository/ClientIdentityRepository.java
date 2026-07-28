package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ClientIdentity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ClientIdentityRepository extends JpaRepository<ClientIdentity, Long> {
    Optional<ClientIdentity> findByCredentialIdAndMachineFingerprintAndOsUser(Long credentialId,
                                                                               String machineFingerprint,
                                                                               String osUser);
}
