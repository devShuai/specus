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
import com.theshuai.tunnelserver.management.repository.ClientSessionRepository;
import com.theshuai.tunnelserver.management.repository.PeerMeshAclRepository;
import com.theshuai.tunnelserver.management.repository.PeerMeshDeviceRepository;
import com.theshuai.tunnelserver.management.repository.PeerMeshSessionRepository;
import com.theshuai.tunnelserver.management.security.ManagementContext;
import com.theshuai.tunnelserver.peer.TurnCredentialService;
import com.theshuai.tunnelserver.management.tenant.TenantContext;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PeerMeshServiceTests {

    private final PeerMeshDeviceRepository deviceRepository = mock(PeerMeshDeviceRepository.class);
    private final PeerMeshAclRepository aclRepository = mock(PeerMeshAclRepository.class);
    private final PeerMeshSessionRepository sessionRepository = mock(PeerMeshSessionRepository.class);
    private final ClientAccountRepository clientAccountRepository = mock(ClientAccountRepository.class);
    private final TurnCredentialService turnCredentialService = mock(TurnCredentialService.class);
    private final ClientSessionRepository clientSessionRepository = mock(ClientSessionRepository.class);
    private final PeerMeshProperties properties = new PeerMeshProperties();
    private final PeerMeshService service = new PeerMeshService(
            properties,
            deviceRepository,
            aclRepository,
            sessionRepository,
            clientAccountRepository,
            turnCredentialService,
            clientSessionRepository
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
        when(turnCredentialService.issue(any())).thenReturn(new TurnCredentialService.TurnCredential(
                "ice-user", "ice-cred", "shuai-tunnel", "nonce", Instant.now().plusSeconds(3600)));

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
    void createSessionReusesCachedOpenSessionForSamePeerPair() {
        mockDeviceEnabled(1L);
        mockDeviceEnabled(2L);
        AtomicReference<PeerMeshSession> saved = new AtomicReference<>();
        when(sessionRepository.findOpenBetweenClients("tenant-a", 1L, 2L, PeerMeshService.STATUS_CLOSED))
                .thenAnswer(invocation -> saved.get() == null ? List.of() : List.of(saved.get()));
        when(sessionRepository.findOpenBetweenClients("tenant-a", 2L, 1L, PeerMeshService.STATUS_CLOSED))
                .thenAnswer(invocation -> saved.get() == null ? List.of() : List.of(saved.get()));
        when(sessionRepository.save(any(PeerMeshSession.class))).thenAnswer(invocation -> {
            PeerMeshSession session = invocation.getArgument(0);
            saved.set(session);
            return session;
        });

        var first = service.createSession(client(1, "alice", "a"), client(2, "alice", "b"), PeerMeshService.PATH_DIRECT);
        var second = service.createSession(client(1, "alice", "a"), client(2, "alice", "b"), PeerMeshService.PATH_DIRECT);
        var reverse = service.createSession(client(2, "alice", "b"), client(1, "alice", "a"), PeerMeshService.PATH_DIRECT);

        assertThat(second.session().id()).isEqualTo(first.session().id());
        assertThat(second.token()).isEqualTo(first.token());
        assertThat(reverse.session().id()).isEqualTo(first.session().id());
        assertThat(reverse.token()).isEqualTo(first.token());
        verify(sessionRepository, times(1)).save(any(PeerMeshSession.class));
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

    @Test
    void pathStatsAggregatesDirectRatioAndNatTypes() {
        when(sessionRepository.findByStatusNotAndExpiresAtLessThanEqualOrderByExpiresAtAsc(any(), any(), any()))
                .thenReturn(List.of());
        // 先把各 aggregate mock 建好再传入 thenReturn:若在 thenReturn(...) 参数里内联调用
        // pathAggregate/natAggregate(内部又有 when()),会在外层 when() 的 stubbing 未完成时嵌套打桩,
        // 触发 Mockito UnfinishedStubbing。
        var directActive = pathAggregate(PeerMeshService.PATH_DIRECT, PeerMeshService.STATUS_ACTIVE, 3, 2, 12.5, 900, 0);
        var relayActive = pathAggregate(PeerMeshService.PATH_RELAY, PeerMeshService.STATUS_ACTIVE, 1, 1, 80.0, 10, 400);
        var directClosed = pathAggregate(PeerMeshService.PATH_DIRECT, PeerMeshService.STATUS_CLOSED, 1, 0, null, 0, 0);
        when(sessionRepository.aggregatePathTypes("tenant-a")).thenReturn(List.of(directActive, relayActive, directClosed));
        var natUnknown = natAggregate(null, 2);
        var natSymmetric = natAggregate("SYMMETRIC_NAT", 1);
        when(deviceRepository.aggregateNatTypes("tenant-a")).thenReturn(List.of(natUnknown, natSymmetric));

        var stats = service.pathStats(new ManagementContext(new TenantContext("tenant-a"), "admin", true));

        assertThat(stats.totalSessions()).isEqualTo(5);
        assertThat(stats.reportedSessions()).isEqualTo(3);
        assertThat(stats.activeSessions()).isEqualTo(4);
        assertThat(stats.activeDirectSessions()).isEqualTo(3);
        assertThat(stats.activeRelaySessions()).isEqualTo(1);
        assertThat(stats.activeDirectRatio()).isEqualTo(0.75);
        assertThat(stats.pathTypes()).hasSize(3);
        assertThat(stats.natTypes())
                .extracting("natType", "devices")
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple("UNKNOWN", 2L),
                        org.assertj.core.groups.Tuple.tuple("SYMMETRIC_NAT", 1L)
                );
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

    private PeerMeshSessionRepository.PathTypeAggregate pathAggregate(
            String pathType,
            String status,
            long sessions,
            long reportedSessions,
            Double avgRttMillis,
            long directBytes,
            long relayBytes) {
        PeerMeshSessionRepository.PathTypeAggregate aggregate = mock(PeerMeshSessionRepository.PathTypeAggregate.class);
        when(aggregate.getPathType()).thenReturn(pathType);
        when(aggregate.getStatus()).thenReturn(status);
        when(aggregate.getSessions()).thenReturn(sessions);
        when(aggregate.getReportedSessions()).thenReturn(reportedSessions);
        when(aggregate.getAvgRttMillis()).thenReturn(avgRttMillis);
        when(aggregate.getDirectBytes()).thenReturn(directBytes);
        when(aggregate.getRelayBytes()).thenReturn(relayBytes);
        return aggregate;
    }

    private PeerMeshDeviceRepository.NatTypeAggregate natAggregate(String natType, long devices) {
        PeerMeshDeviceRepository.NatTypeAggregate aggregate = mock(PeerMeshDeviceRepository.NatTypeAggregate.class);
        when(aggregate.getNatType()).thenReturn(natType);
        when(aggregate.getDevices()).thenReturn(devices);
        return aggregate;
    }
}
