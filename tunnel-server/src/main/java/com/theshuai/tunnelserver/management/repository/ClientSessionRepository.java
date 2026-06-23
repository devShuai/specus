package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.ClientSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface ClientSessionRepository extends JpaRepository<ClientSession, Long> {
    Optional<ClientSession> findByTokenHash(String tokenHash);

    long countByCredentialIdAndStatus(Long credentialId, String status);

    List<ClientSession> findByCredentialIdAndStatus(Long credentialId, String status);

    long countByCredentialIdAndMachineFingerprintAndOsUserAndStatus(Long credentialId,
                                                                     String machineFingerprint,
                                                                     String osUser,
                                                                     String status);

    List<ClientSession> findByCredentialIdAndMachineFingerprintAndOsUserAndStatus(Long credentialId,
                                                                                  String machineFingerprint,
                                                                                  String osUser,
                                                                                  String status);

    @Modifying
    @Query("update ClientSession s set s.status = :status, s.disconnectedAt = :disconnectedAt where s.status = :onlineStatus")
    int closeSessionsByStatus(@Param("onlineStatus") String onlineStatus,
                              @Param("status") String status,
                              @Param("disconnectedAt") String disconnectedAt);

    @Modifying
    @Query("""
            update ClientSession s
               set s.status = :status, s.disconnectedAt = :disconnectedAt
             where s.credentialId = :credentialId
               and s.machineFingerprint = :machineFingerprint
               and s.osUser = :osUser
               and s.status = :httpStatus
            """)
    int closeHttpAuthenticatedSessions(@Param("credentialId") Long credentialId,
                                       @Param("machineFingerprint") String machineFingerprint,
                                       @Param("osUser") String osUser,
                                       @Param("httpStatus") String httpStatus,
                                       @Param("status") String status,
                                       @Param("disconnectedAt") String disconnectedAt);
}
