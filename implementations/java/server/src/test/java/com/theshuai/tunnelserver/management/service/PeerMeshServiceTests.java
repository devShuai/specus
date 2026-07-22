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
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
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
    private final PlatformTransactionManager transactionManager = transactionManager();
    private final PeerMeshService service = new PeerMeshService(
            properties,
            deviceRepository,
            aclRepository,
            sessionRepository,
            clientAccountRepository,
            turnCredentialService,
            clientSessionRepository,
            transactionManager,
            new SimpleMeterRegistry()
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
    void loginConfigCanAdvertiseStandaloneStunSeparatelyFromTurn() {
        properties.setEnabled(true);
        properties.setPublicAddress("turn.example.com");
        properties.setStandaloneStunAddress("stun.example.com");
        properties.setStandaloneStunPort(5349);
        properties.setStandaloneStunAlternateAddress("stun-backup.example.com");
        PeerMeshDevice device = new PeerMeshDevice();
        device.setId(10L);
        device.setClientId(1L);
        device.setClientName("a");
        device.setOwnerUsername("alice");
        device.setVirtualIp("100.96.0.10");
        device.setCidr("100.96.0.0/11");
        device.setEnabled(true);
        when(deviceRepository.findByTenantIdAndClientId("tenant-a", 1L)).thenReturn(Optional.of(device));
        when(deviceRepository.save(any(PeerMeshDevice.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(turnCredentialService.issue(any())).thenReturn(new TurnCredentialService.TurnCredential(
                "ice-user", "ice-cred", "shuai-tunnel", "nonce", Instant.now().plusSeconds(3600)));

        ClientAuthLoginResponse.PeerMeshConfig config =
                service.buildLoginConfig(client(1, "alice", "a"), new ClientEnvironmentInfo(), "request.example.com");

        assertThat(config.getStunHost()).isEqualTo("stun.example.com");
        assertThat(config.getStunPort()).isEqualTo(5349);
        assertThat(config.getPublicStunServers())
                .containsExactly("stun:stun-backup.example.com:5349");
        assertThat(config.getTurnHost()).isEqualTo("turn.example.com");
        assertThat(config.getTurnPort()).isEqualTo(3478);
    }

    @Test
    void incompleteStandaloneStunFallsBackToEmbeddedEndpoint() {
        properties.setEnabled(true);
        properties.setPublicAddress("relay.example.com");
        properties.setStunTurnPort(4444);
        properties.setStandaloneStunAddress("stun.example.com");
        properties.setStandaloneStunPort(0);
        PeerMeshDevice device = new PeerMeshDevice();
        device.setId(10L);
        device.setClientId(1L);
        device.setClientName("a");
        device.setOwnerUsername("alice");
        device.setVirtualIp("100.96.0.10");
        device.setCidr("100.96.0.0/11");
        device.setEnabled(true);
        when(deviceRepository.findByTenantIdAndClientId("tenant-a", 1L)).thenReturn(Optional.of(device));
        when(deviceRepository.save(any(PeerMeshDevice.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(turnCredentialService.issue(any())).thenReturn(new TurnCredentialService.TurnCredential(
                "ice-user", "ice-cred", "shuai-tunnel", "nonce", Instant.now().plusSeconds(3600)));

        ClientAuthLoginResponse.PeerMeshConfig config =
                service.buildLoginConfig(client(1, "alice", "a"), new ClientEnvironmentInfo(), "request.example.com");

        assertThat(config.getStunHost()).isEqualTo("relay.example.com");
        assertThat(config.getStunPort()).isEqualTo(4444);
    }

    @Test
    void deviceReportPersistsRfc5780BehaviorFields() {
        PeerMeshDevice device = new PeerMeshDevice();
        device.setId(10L);
        device.setTenantId("tenant-a");
        device.setClientId(1L);
        device.setClientName("a");
        device.setOwnerUsername("alice");
        device.setVirtualIp("100.96.0.10");
        device.setCidr("100.96.0.0/11");
        device.setCreatedAt(Instant.now().toString());
        device.setUpdatedAt(Instant.now().toString());
        when(deviceRepository.findByTenantIdAndClientId("tenant-a", 1L)).thenReturn(Optional.of(device));
        when(deviceRepository.save(any(PeerMeshDevice.class))).thenAnswer(invocation -> invocation.getArgument(0));

        PeerControlMessage report = new PeerControlMessage();
        report.setNatType("PORT_RESTRICTED_NAT");
        report.setNatMappingBehavior("ENDPOINT_INDEPENDENT");
        report.setNatFilteringBehavior("ADDRESS_AND_PORT_DEPENDENT");
        report.setNatBehaviorDiscovery("RFC5780");
        report.setLastEndpoint("198.51.100.20:52000");

        var view = service.reportDevice(client(1, "alice", "a"), report);

        assertThat(view.natType()).isEqualTo("PORT_RESTRICTED_NAT");
        assertThat(view.natMappingBehavior()).isEqualTo("ENDPOINT_INDEPENDENT");
        assertThat(view.natFilteringBehavior()).isEqualTo("ADDRESS_AND_PORT_DEPENDENT");
        assertThat(view.natBehaviorDiscovery()).isEqualTo("RFC5780");
        assertThat(view.lastEndpoint()).isEqualTo("198.51.100.20:52000");
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

        boolean allowed = service.authorizeRelayFrame(
                new PeerDataFrameHeader(100L, 7L), 1L, 2L, 512);

        assertThat(allowed).isTrue();
        assertThat(session.getRelayBytes()).isEqualTo(512);
    }

    @Test
    void relayFrameRejectsWrongPeerPair() {
        PeerMeshSession session = activeSession();
        when(sessionRepository.findById(100L)).thenReturn(Optional.of(session));

        boolean allowed = service.authorizeRelayFrame(
                new PeerDataFrameHeader(100L, 7L), 1L, 99L, 512);

        assertThat(allowed).isFalse();
        assertThat(session.getRelayBytes()).isZero();
    }

    @Test
    void relayFrameRejectsExpiredSessionAndClosesIt() {
        PeerMeshSession session = activeSession();
        session.setExpiresAt(Instant.now().minusSeconds(5).toString());
        when(sessionRepository.findById(100L)).thenReturn(Optional.of(session));
        when(sessionRepository.save(any(PeerMeshSession.class))).thenAnswer(invocation -> invocation.getArgument(0));

        boolean allowed = service.authorizeRelayFrame(
                new PeerDataFrameHeader(100L, 7L), 1L, 2L, 512);

        assertThat(allowed).isFalse();
        assertThat(session.getStatus()).isEqualTo(PeerMeshService.STATUS_CLOSED);
        assertThat(session.getRelayBytes()).isZero();
    }

    @Test
    void relayFrameRejectsNegotiatingSession() {
        PeerMeshSession session = activeSession();
        session.setStatus(PeerMeshService.STATUS_NEGOTIATING);
        when(sessionRepository.findById(100L)).thenReturn(Optional.of(session));

        boolean allowed = service.authorizeRelayFrame(
                new PeerDataFrameHeader(100L, 7L), 1L, 2L, 512);

        assertThat(allowed).isFalse();
        assertThat(session.getRelayBytes()).isZero();
    }

    @Test
    void relayHotPathActivatesNegotiatingSessionOnFirstFrame() {
        // 探针在 NEGOTIATING 就放行，业务帧却等 path-report 才被授权，两者之间的时间窗会
        // 丢掉客户端探测成功后立刻 flush 的数据帧——表现为"中继已连通但文件发送失败"。
        // 身份校验通过后应直接激活会话，而不是丢帧等待一条状态上报。
        PeerMeshSession session = activeSession();
        session.setStatus(PeerMeshService.STATUS_NEGOTIATING);
        when(sessionRepository.findById(100L)).thenReturn(Optional.of(session));
        when(sessionRepository.save(any(PeerMeshSession.class))).thenAnswer(invocation -> invocation.getArgument(0));

        boolean allowed = service.authorizeRelayFrameForRelay(
                new PeerDataFrameHeader(100L, 7L), 1L, 2L, 512);
        service.flushRelayTraffic();

        assertThat(allowed).isTrue();
        assertThat(session.getStatus()).isEqualTo(PeerMeshService.STATUS_ACTIVE);
        assertThat(session.getPathType()).isEqualTo(PeerMeshService.PATH_RELAY);
        assertThat(session.getRelayBytes()).isEqualTo(512);
    }

    @Test
    void relayHotPathRejectsClosedSessionAndMismatchedClients() {
        PeerMeshSession closed = activeSession();
        closed.setStatus(PeerMeshService.STATUS_CLOSED);
        when(sessionRepository.findById(100L)).thenReturn(Optional.of(closed));

        assertThat(service.authorizeRelayFrameForRelay(
                new PeerDataFrameHeader(100L, 7L), 1L, 2L, 512)).isFalse();

        PeerMeshSession negotiating = activeSession();
        negotiating.setStatus(PeerMeshService.STATUS_NEGOTIATING);
        when(sessionRepository.findById(100L)).thenReturn(Optional.of(negotiating));

        // 身份不匹配的帧不得激活会话
        assertThat(service.authorizeRelayFrameForRelay(
                new PeerDataFrameHeader(100L, 7L), 1L, 99L, 512)).isFalse();
        assertThat(negotiating.getStatus()).isEqualTo(PeerMeshService.STATUS_NEGOTIATING);
    }

    @Test
    void relayHotPathAllowsUnidentifiedPeersWhenTurnAuthDisabled() {
        // TURN 认证关闭时 allocation 上没有 clientId，调用方传 0/0；此时若坚持要求身份匹配，
        // 全部中继载荷都会被拒，中继完全不可用。
        PeerMeshSession session = activeSession();
        when(sessionRepository.findById(100L)).thenReturn(Optional.of(session));
        when(sessionRepository.save(any(PeerMeshSession.class))).thenAnswer(invocation -> invocation.getArgument(0));

        boolean allowed = service.authorizeRelayFrameForRelay(
                new PeerDataFrameHeader(100L, 7L), 0L, 0L, 256);

        assertThat(allowed).isTrue();
    }

    @Test
    void relayHotPathUsesExplicitTransactionAndFlushesTraffic() {
        PeerMeshSession session = activeSession();
        when(sessionRepository.findById(100L)).thenReturn(Optional.of(session));
        when(sessionRepository.save(any(PeerMeshSession.class))).thenAnswer(invocation -> invocation.getArgument(0));
        clearInvocations(transactionManager);

        boolean allowed = service.authorizeRelayFrameForRelay(
                new PeerDataFrameHeader(100L, 7L), 1L, 2L, 512);
        service.flushRelayTraffic();

        assertThat(allowed).isTrue();
        assertThat(session.getRelayBytes()).isEqualTo(512);
        verify(transactionManager, times(2)).getTransaction(any());
        verify(transactionManager, times(2)).commit(any());
    }

    @Test
    void relayTrafficFlushRestoresBatchAfterRepositoryFailure() {
        PeerMeshSession session = activeSession();
        when(sessionRepository.findById(100L))
                .thenReturn(Optional.of(session))
                .thenThrow(new IllegalStateException("database unavailable"))
                .thenReturn(Optional.of(session));
        when(sessionRepository.save(any(PeerMeshSession.class))).thenAnswer(invocation -> invocation.getArgument(0));
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        PeerMeshService retryingService = new PeerMeshService(
                properties,
                deviceRepository,
                aclRepository,
                sessionRepository,
                clientAccountRepository,
                turnCredentialService,
                clientSessionRepository,
                transactionManager(),
                meterRegistry);

        assertThat(retryingService.authorizeRelayFrameForRelay(
                new PeerDataFrameHeader(100L, 7L), 1L, 2L, 512)).isTrue();
        retryingService.flushRelayTraffic();

        assertThat(meterRegistry.get("tunnel.peer_mesh.relay.traffic.flush.failures").counter().count())
                .isEqualTo(1);
        assertThat(meterRegistry.get("tunnel.peer_mesh.relay.traffic.pending.bytes").gauge().value())
                .isEqualTo(512);

        retryingService.flushRelayTraffic();

        assertThat(session.getRelayBytes()).isEqualTo(512);
        assertThat(meterRegistry.get("tunnel.peer_mesh.relay.traffic.pending.bytes").gauge().value())
                .isZero();
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
        var ipv4Active = addressFamilyAggregate("IPv4", PeerMeshService.STATUS_ACTIVE,
                PeerMeshService.PATH_DIRECT, 2, 2);
        var ipv6Active = addressFamilyAggregate("IPv6", PeerMeshService.STATUS_ACTIVE,
                PeerMeshService.PATH_RELAY, 1, 1);
        when(sessionRepository.aggregateAddressFamilies("tenant-a"))
                .thenReturn(List.of(ipv4Active, ipv6Active));
        var natUnknown = natAggregate(null, 2);
        var natSymmetric = natAggregate("SYMMETRIC_NAT", 1);
        when(deviceRepository.aggregateNatTypes("tenant-a")).thenReturn(List.of(natUnknown, natSymmetric));
        var classifiedBehavior = natBehaviorAggregate(
                "ENDPOINT_INDEPENDENT",
                "ADDRESS_AND_PORT_DEPENDENT",
                "RFC5780",
                1);
        var incompleteBehavior = natBehaviorAggregate(
                "ADDRESS_DEPENDENT",
                "UNSUPPORTED",
                "BASIC",
                1);
        when(deviceRepository.aggregateNatBehaviors("tenant-a"))
                .thenReturn(List.of(classifiedBehavior, incompleteBehavior));

        var stats = service.pathStats(new ManagementContext(new TenantContext("tenant-a"), "admin", true));

        assertThat(stats.totalSessions()).isEqualTo(5);
        assertThat(stats.reportedSessions()).isEqualTo(3);
        assertThat(stats.activeSessions()).isEqualTo(4);
        assertThat(stats.activeDirectSessions()).isEqualTo(3);
        assertThat(stats.activeRelaySessions()).isEqualTo(1);
        assertThat(stats.activeDirectRatio()).isEqualTo(0.75);
        assertThat(stats.pathTypes()).hasSize(3);
        assertThat(stats.addressFamilies())
                .extracting("addressFamily", "status", "pathType", "sessions", "reportedSessions")
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple(
                                "IPv4", PeerMeshService.STATUS_ACTIVE, PeerMeshService.PATH_DIRECT, 2L, 2L),
                        org.assertj.core.groups.Tuple.tuple(
                                "IPv6", PeerMeshService.STATUS_ACTIVE, PeerMeshService.PATH_RELAY, 1L, 1L));
        assertThat(stats.natTypes())
                .extracting("natType", "devices")
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple("UNKNOWN", 2L),
                        org.assertj.core.groups.Tuple.tuple("SYMMETRIC_NAT", 1L)
                );
        assertThat(stats.natBehaviorDevices()).isEqualTo(2);
        assertThat(stats.natBehaviorClassifiedDevices()).isEqualTo(1);
        assertThat(stats.natBehaviorSuccessRatio()).isEqualTo(0.5);
        assertThat(stats.natMappingBehaviors())
                .extracting("behavior", "devices")
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple("ENDPOINT_INDEPENDENT", 1L),
                        org.assertj.core.groups.Tuple.tuple("ADDRESS_DEPENDENT", 1L));
        assertThat(stats.natFilteringBehaviors())
                .extracting("behavior", "devices")
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple("ADDRESS_AND_PORT_DEPENDENT", 1L),
                        org.assertj.core.groups.Tuple.tuple("UNSUPPORTED", 1L));
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

    private PeerMeshSessionRepository.AddressFamilyAggregate addressFamilyAggregate(
            String addressFamily,
            String status,
            String pathType,
            long sessions,
            long reportedSessions) {
        PeerMeshSessionRepository.AddressFamilyAggregate aggregate =
                mock(PeerMeshSessionRepository.AddressFamilyAggregate.class);
        when(aggregate.getAddressFamily()).thenReturn(addressFamily);
        when(aggregate.getStatus()).thenReturn(status);
        when(aggregate.getPathType()).thenReturn(pathType);
        when(aggregate.getSessions()).thenReturn(sessions);
        when(aggregate.getReportedSessions()).thenReturn(reportedSessions);
        return aggregate;
    }

    private PeerMeshDeviceRepository.NatTypeAggregate natAggregate(String natType, long devices) {
        PeerMeshDeviceRepository.NatTypeAggregate aggregate = mock(PeerMeshDeviceRepository.NatTypeAggregate.class);
        when(aggregate.getNatType()).thenReturn(natType);
        when(aggregate.getDevices()).thenReturn(devices);
        return aggregate;
    }

    private static PlatformTransactionManager transactionManager() {
        PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        return manager;
    }

    private PeerMeshDeviceRepository.NatBehaviorAggregate natBehaviorAggregate(
            String mapping,
            String filtering,
            String discovery,
            long devices) {
        PeerMeshDeviceRepository.NatBehaviorAggregate aggregate =
                mock(PeerMeshDeviceRepository.NatBehaviorAggregate.class);
        when(aggregate.getMappingBehavior()).thenReturn(mapping);
        when(aggregate.getFilteringBehavior()).thenReturn(filtering);
        when(aggregate.getDiscovery()).thenReturn(discovery);
        when(aggregate.getDevices()).thenReturn(devices);
        return aggregate;
    }
}
