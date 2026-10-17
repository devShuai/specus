package com.theshuai.specusserver.management.repository;

import java.util.List;
import java.util.Optional;

public interface ClientSessionRepositoryCustom {
    /** Caller holds the credential and client locks first. No JPA cached/partial entity escapes. */
    Optional<SessionSnapshot> lockCurrent(Long id, String tenantId);
    List<SessionSnapshot> lockOnline(Long credentialId, String tenantId);
    void markOnline(SessionSnapshot session, String clientName, String channelId, String address, String now);
    void markDisconnected(SessionSnapshot session, String now);
    int disconnectChannel(Long sessionId, String channelId, String now);

    record SessionSnapshot(Long id, String tenantId, Long credentialId, Long identityId, Long clientId,
                           String clientName, String tokenHash, String machineFingerprint, String osUser,
                           String status, String expiresAt, String channelId, String nettyConnectedAt) {}
}
