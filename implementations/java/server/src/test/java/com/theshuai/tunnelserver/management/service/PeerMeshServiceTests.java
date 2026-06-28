package com.theshuai.tunnelserver.management.service;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerDataFrameHeader;
import com.theshuai.tunnelserver.config.PeerMeshProperties;
import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.PeerMeshAcl;
import com.theshuai.tunnelserver.management.model.PeerMeshDevice;
import com.theshuai.tunnelserver.management.model.PeerMeshSession;
import com.theshuai.tunnelserver.management.repository.ClientAccountRepository;
import com.theshuai.tunnelserver.management.repository.PeerMeshAclRepository;
import com.theshuai.tunnelserver.management.repository.PeerMeshDeviceRepository;
import com.theshuai.tunnelserver.management.repository.PeerMeshSessionRepository;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PeerMeshServiceTests {

    private final PeerMeshDeviceRepository deviceRepository = mock(PeerMeshDeviceRepository.class);
    private final PeerMeshAclRepository aclRepository = mock(PeerMeshAclRepository.class);
    private final PeerMeshSessionRepository sessionRepository = mock(PeerMeshSessionRepository.class);
    private final ClientAccountRepository clientAccountRepository = mock(ClientAccountRepository.class);
    private final PeerMeshProperties properties = new PeerMeshProperties();
    private final PeerMeshService service = new PeerMeshService(
            properties,
            deviceRepository,
            aclRepository,
            sessionRepository,
            clientAccountRepository
    );

    @Test
    void sameOwnerCanPeerByDefault() {
        mockDeviceEnabled(1L);
        mockDeviceEnabled(2L);
        assertThat(service.canPeer(client(1, "alice", "a"), client(2, "alice", "b"))).isTrue();
    }

    @Test
    void crossOwnerDeniedWithoutAcl() {
        mockDeviceEnabled(1L);
        mockDeviceEnabled(2L);
        when(aclRepository.findByTenantIdAndSourceClientIdAndTargetClientId("tenant-a", 1L, 2L))
                .thenReturn(Optional.empty());

        assertThat(service.canPeer(client(1, "alice", "a"), client(2, "bob", "b"))).isFalse();
    }

    @Test
    void crossOwnerAllowedWithExplicitAcl() {
        mockDeviceEnabled(1L);
        mockDeviceEnabled(2L);
        PeerMeshAcl acl = new PeerMeshAcl();
        acl.setAllowed(true);
        when(aclRepository.findByTenantIdAndSourceClientIdAndTargetClientId("tenant-a", 1L, 2L))
                .thenReturn(Optional.of(acl));

        assertThat(service.canPeer(client(1, "alice", "a"), client(2, "bob", "b"))).isTrue();
    }

    @Test
    void loginConfigAllocatesVirtualIpButLeavesDeviceDisabledByDefault() {
        properties.setEnabled(true);
        when(deviceRepository.findByTenantIdAndClientId("tenant-a", 1L)).thenReturn(Optional.empty());
        when(deviceRepository.findByTenantIdAndVirtualIp(any(), any())).thenReturn(Optional.empty());
        when(deviceRepository.save(any(PeerMeshDevice.class))).thenAnswer(invocation -> invocation.getArgument(0));

        ClientEnvironmentInfo environment = new ClientEnvironmentInfo();
        environment.setPeerPublicKey("public-key");
        ClientAuthLoginResponse.PeerMeshConfig config = service.buildLoginConfig(client(1, "alice", "a"), environment, "127.0.0.1");

        assertThat(config.isEnabled()).isFalse();
        assertThat(config.getVirtualIp()).startsWith("100.");
        assertThat(config.getCidr()).isEqualTo("100.96.0.0/11");
        assertThat(config.getClientPublicKey()).isEqualTo("public-key");
        assertThat(config.getStunPort()).isEqualTo(3478);
    }

    @Test
    void trafficReportAccumulatesDirectAndRelayBytes() {
        PeerMeshSession session = activeSession();
        when(sessionRepository.findById(100L)).thenReturn(Optional.of(session));
        when(sessionRepository.save(any(PeerMeshSession.class))).thenAnswer(invocation -> invocation.getArgument(0));

        PeerControlMessage report = new PeerControlMessage();
        report.setSessionId(100L);
        report.setDirectBytes(120);
        report.setRelayBytes(30);

        var view = service.reportTraffic(client(1, "alice", "a"), report);

        assertThat(view.directBytes()).isEqualTo(120);
        assertThat(view.relayBytes()).isEqualTo(30);
        assertThat(view.lastTrafficAt()).isNotBlank();
        assertThat(view.status()).isEqualTo(PeerMeshService.STATUS_ACTIVE);
    }

    @Test
    void expiredTrafficReportClosesSessionWithoutAddingBytes() {
        PeerMeshSession session = activeSession();
        session.setExpiresAt(Instant.now().minusSeconds(5).toString());
        when(sessionRepository.findById(100L)).thenReturn(Optional.of(session));
        when(sessionRepository.save(any(PeerMeshSession.class))).thenAnswer(invocation -> invocation.getArgument(0));

        PeerControlMessage report = new PeerControlMessage();
        report.setSessionId(100L);
        report.setDirectBytes(120);

        var view = service.reportTraffic(client(1, "alice", "a"), report);

        assertThat(view.status()).isEqualTo(PeerMeshService.STATUS_CLOSED);
        assertThat(view.directBytes()).isZero();
        assertThat(view.closedAt()).isNotBlank();
    }

    @Test
    void closeSessionMarksSessionClosed() {
        PeerMeshSession session = activeSession();
        when(sessionRepository.findById(100L)).thenReturn(Optional.of(session));
        when(sessionRepository.save(any(PeerMeshSession.class))).thenAnswer(invocation -> invocation.getArgument(0));

        PeerControlMessage close = new PeerControlMessage();
        close.setSessionId(100L);

        var view = service.closeSession(client(2, "alice", "b"), close);

        assertThat(view.status()).isEqualTo(PeerMeshService.STATUS_CLOSED);
        assertThat(view.closedAt()).isNotBlank();
    }

    @Test
    void relayFrameRequiresActiveMatchingSession() {
        PeerMeshSession session = activeSession();
        when(sessionRepository.findById(100L)).thenReturn(Optional.of(session));
        when(sessionRepository.save(any(PeerMeshSession.class))).thenAnswer(invocation -> invocation.getArgument(0));

        boolean allowed = service.authorizeRelayFrame(new PeerDataFrameHeader(100L, 1L, 2L, 7L), 512);

        assertThat(allowed).isTrue();
        assertThat(session.getRelayBytes()).isEqualTo(512);
    }

    @Test
    void relayFrameRejectsWrongPeerPair() {
        PeerMeshSession session = activeSession();
        when(sessionRepository.findById(100L)).thenReturn(Optional.of(session));

        boolean allowed = service.authorizeRelayFrame(new PeerDataFrameHeader(100L, 1L, 99L, 7L), 512);

        assertThat(allowed).isFalse();
        assertThat(session.getRelayBytes()).isZero();
    }

    @Test
    void relayFrameRejectsExpiredSessionAndClosesIt() {
        PeerMeshSession session = activeSession();
        session.setExpiresAt(Instant.now().minusSeconds(5).toString());
        when(sessionRepository.findById(100L)).thenReturn(Optional.of(session));
        when(sessionRepository.save(any(PeerMeshSession.class))).thenAnswer(invocation -> invocation.getArgument(0));

        boolean allowed = service.authorizeRelayFrame(new PeerDataFrameHeader(100L, 1L, 2L, 7L), 512);

        assertThat(allowed).isFalse();
        assertThat(session.getStatus()).isEqualTo(PeerMeshService.STATUS_CLOSED);
        assertThat(session.getRelayBytes()).isZero();
    }

    @Test
    void relayFrameRejectsNegotiatingSession() {
        PeerMeshSession session = activeSession();
        session.setStatus(PeerMeshService.STATUS_NEGOTIATING);
        when(sessionRepository.findById(100L)).thenReturn(Optional.of(session));

        boolean allowed = service.authorizeRelayFrame(new PeerDataFrameHeader(100L, 1L, 2L, 7L), 512);

        assertThat(allowed).isFalse();
        assertThat(session.getRelayBytes()).isZero();
    }

    private ClientAccount client(long id, String owner, String name) {
        ClientAccount account = new ClientAccount();
        account.setId(id);
        account.setTenantId("tenant-a");
        account.setOwnerUsername(owner);
        account.setClientName(name);
        account.setEnabled(true);
        return account;
    }

    private void mockDeviceEnabled(long clientId) {
        PeerMeshDevice device = new PeerMeshDevice();
        device.setClientId(clientId);
        device.setEnabled(true);
        when(deviceRepository.findByTenantIdAndClientId("tenant-a", clientId)).thenReturn(Optional.of(device));
    }

    private PeerMeshSession activeSession() {
        Instant now = Instant.now();
        PeerMeshSession session = new PeerMeshSession();
        session.setId(100L);
        session.setTenantId("tenant-a");
        session.setSourceClientId(1L);
        session.setSourceClientName("a");
        session.setTargetClientId(2L);
        session.setTargetClientName("b");
        session.setPathType(PeerMeshService.PATH_DIRECT);
        session.setStatus(PeerMeshService.STATUS_ACTIVE);
        session.setStartedAt(now.toString());
        session.setUpdatedAt(now.toString());
        session.setExpiresAt(now.plusSeconds(60).toString());
        return session;
    }
}
