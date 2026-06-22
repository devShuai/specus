package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.ClientSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface ClientSessionRepository extends JpaRepository<ClientSession, Long> {
    Optional<ClientSession> findByTokenHash(String tokenHash);

    long countByCredentialIdAndStatus(Long credentialId, String status);

    long countByCredentialIdAndMachineFingerprintAndOsUserAndStatus(Long credentialId,
                                                                     String machineFingerprint,
                                                                     String osUser,
                                                                     String status);

    @Modifying
    @Query("update ClientSession s set s.status = :status, s.disconnectedAt = :disconnectedAt where s.status = :onlineStatus")
    int closeSessionsByStatus(@Param("onlineStatus") String onlineStatus,
                              @Param("status") String status,
                              @Param("disconnectedAt") String disconnectedAt);
}
