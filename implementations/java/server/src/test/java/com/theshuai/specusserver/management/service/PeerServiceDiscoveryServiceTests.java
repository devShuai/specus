package com.theshuai.specusserver.management.service;

import com.theshuai.common.peermesh.PeerAdvertisedService;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerServiceDiscovery;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.PeerMeshDevice;
import com.theshuai.specusserver.management.model.PeerMeshServiceSharing;
import com.theshuai.specusserver.management.model.PeerMeshSharedService;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.ClientSessionRepository;
import com.theshuai.specusserver.management.repository.PeerMeshDeviceRepository;
import com.theshuai.specusserver.management.repository.PeerMeshServiceSharingRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.repository.PeerMeshSharedServiceRepository;
import com.theshuai.specusserver.management.repository.SpecusMappingRepository;
import com.theshuai.specusserver.management.model.SpecusMapping;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.session.SessionUtil;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.common.session.Session;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PeerServiceDiscoveryServiceTests {
    private final PeerMeshService peerMeshService = mock(PeerMeshService.class);
    private final PeerMeshServiceSharingRepository sharingRepository = mock(PeerMeshServiceSharingRepository.class);
    private final PeerMeshSharedServiceRepository serviceRepository = mock(PeerMeshSharedServiceRepository.class);
    private final PeerMeshDeviceRepository deviceRepository = mock(PeerMeshDeviceRepository.class);
    private final ClientAccountRepository clientAccountRepository = mock(ClientAccountRepository.class);
    private final ClientSessionRepository clientSessionRepository = mock(ClientSessionRepository.class);
    private final SpecusMappingRepository specusMappingRepository = mock(SpecusMappingRepository.class);
    private final HttpRouteMappingRepository httpRouteMappingRepository = mock(HttpRouteMappingRepository.class);
    private final PeerServiceDiscoveryService service = new PeerServiceDiscoveryService(
            peerMeshService, sharingRepository, serviceRepository, deviceRepository, clientAccountRepository,
            clientSessionRepository, specusMappingRepository, httpRouteMappingRepository);

    {
        when(specusMappingRepository.findByTenantIdAndClientIdOrderByIdDesc(any(), any())).thenReturn(List.of());
        when(httpRouteMappingRepository.findByTenantIdAndClientIdOrderByIdDesc(any(), any())).thenReturn(List.of());
    }

    @Test
    void sharingDefaultsToOffWhenTableEmpty() {
        when(peerMeshService.isEnabled()).thenReturn(true);
        when(sharingRepository.findById("tenant-a")).thenReturn(Optional.empty());
        when(serviceRepository.countByTenantIdAndEnabledTrue("tenant-a")).thenReturn(0L);

        var status = service.sharingStatus(admin());

        assertThat(status.deploymentEnabled()).isTrue();
        assertThat(status.configuredEnabled()).isFalse();
        assertThat(status.effectiveEnabled()).isFalse();
        assertThat(status.enabledServiceCount()).isZero();
        assertThat(status.mdnsImportEnabled()).isFalse();
    }

    @Test
    void nonAdminCannotToggleSharingOrMutateServices() {
        assertThatThrownBy(() -> service.setSharing(user(), true))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("403");
        assertThatThrownBy(() -> service.createService(user(), mutation("ssh", "127.0.0.1", 22, 2222, false)))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void cannotEnableSharingWhenDeploymentDisabled() {
        when(peerMeshService.isEnabled()).thenReturn(false);
        assertThatThrownBy(() -> service.setSharing(admin(), true))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("部署端未启用");
    }

    @Test
    void createServicePersistsDisabledByDefault() {
        when(clientAccountRepository.findByIdAndTenantId(1L, "tenant-a")).thenReturn(Optional.of(client(1, "alice", "a")));
        when(serviceRepository.findByTenantIdAndClientIdAndServiceId(any(), any(), any())).thenReturn(Optional.empty());
        when(serviceRepository.findByTenantIdAndClientIdOrderByNameAsc("tenant-a", 1L)).thenReturn(List.of());
        when(serviceRepository.save(any(PeerMeshSharedService.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(deviceRepository.findByTenantIdAndClientId("tenant-a", 1L)).thenReturn(Optional.of(device(1, "a", true)));

        var view = service.createService(admin(), new PeerServiceDiscoveryService.ServiceMutation(
                1L, null, "ssh", "local", "tcp", "ssh", "127.0.0.1", 22, 2222, null, null, "OWNER", null));

        assertThat(view.enabled()).isFalse();
        assertThat(view.targetHost()).isEqualTo("127.0.0.1");
        assertThat(view.publishedPort()).isEqualTo(2222);
        assertThat(view.serviceId()).isNotBlank();
    }

    @Test
    void rejectsPublicTargetAndUnsafePath() {
        when(clientAccountRepository.findByIdAndTenantId(1L, "tenant-a")).thenReturn(Optional.of(client(1, "alice", "a")));
        when(serviceRepository.findByTenantIdAndClientIdAndServiceId(any(), any(), any())).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.createService(admin(),
                mutation("http", "evil.example", 80, 8080, false)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.createService(admin(),
                new PeerServiceDiscoveryService.ServiceMutation(
                        1L, null, "web", "", "tcp", "http", "127.0.0.1", 80, 8080, "javascript:alert(1)", false, "OWNER", null)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void serviceReportRateAndStateTablesAreBounded() {
        for (int index = 0; index < PeerServiceDiscovery.REPORT_RATE_LIMIT; index++) {
            service.enforceRateLimit(7001L);
        }
        for (int index = 0; index < 100; index++) {
            assertThatThrownBy(() -> service.enforceRateLimit(7001L))
                    .isInstanceOf(RateLimitedException.class);
        }
        assertThat(service.recentAudits(admin())).hasSizeLessThanOrEqualTo(50);

        for (long sessionId = 10_000L; service.reportRateWindowCount() < 4096; sessionId++) {
            service.enforceRateLimit(sessionId);
        }
        assertThatThrownBy(() -> service.enforceRateLimit(99_999L))
                .isInstanceOf(RateLimitedException.class);
        assertThat(service.reportRateWindowCount()).isEqualTo(4096);
    }

    @Test
    void reportIsIgnoredWhenSharingOffAndDoesNotAdvertiseTargetHost() {
        ClientAccount publisher = client(1, "alice", "a");
        PeerMeshSharedService definition = definition(publisher);
        when(sharingRepository.findById("tenant-a")).thenReturn(Optional.empty());
        when(peerMeshService.isEnabled()).thenReturn(true);
        when(deviceRepository.findByTenantIdAndClientId("tenant-a", 1L)).thenReturn(Optional.of(device(1, "a", true)));
        when(serviceRepository.findByTenantIdAndClientIdOrderByNameAsc("tenant-a", 1L)).thenReturn(List.of(definition));

        PeerControlMessage report = reportMessage(definition.getServiceId());
        var deliveries = service.acceptReport(publisher, report, 99L);

        assertThat(deliveries).isEmpty();
        assertThat(service.currentCatalog("tenant-a", 1L, 99L)).isNull();
    }

    @Test
    void olderRevisionIsIgnoredAndCatalogRewritesFromPersistedDefinition() {
        ClientAccount publisher = client(1, "alice", "a");
        ClientAccount peer = client(2, "alice", "b");
        PeerMeshSharedService definition = definition(publisher);
        PeerMeshServiceSharing sharing = new PeerMeshServiceSharing();
        sharing.setTenantId("tenant-a");
        sharing.setEnabled(true);
        when(sharingRepository.findById("tenant-a")).thenReturn(Optional.of(sharing));
        when(peerMeshService.isEnabled()).thenReturn(true);
        when(deviceRepository.findByTenantIdAndClientId("tenant-a", 1L)).thenReturn(Optional.of(device(1, "a", true)));
        when(serviceRepository.findByTenantIdAndClientIdOrderByNameAsc("tenant-a", 1L)).thenReturn(List.of(definition));
        when(serviceRepository.findByTenantIdAndClientIdAndServiceId("tenant-a", 1L, definition.getServiceId()))
                .thenReturn(Optional.of(definition));
        when(peerMeshService.allowedRoster(publisher)).thenReturn(List.of(new PeerMeshService.PeerRosterItem(
                2L, "b", "100.96.0.2", "pk", true, false, false, false, false, 0, 1, List.of("ssh"))));
        when(clientAccountRepository.findByTenantIdOrderByIdDesc("tenant-a")).thenReturn(List.of(publisher, peer));
        when(clientAccountRepository.findByIdAndTenantId(1L, "tenant-a")).thenReturn(Optional.of(publisher));
        when(peerMeshService.canPeer(publisher, peer)).thenReturn(true);

        PeerControlMessage first = reportMessage(definition.getServiceId());
        first.setRevision(2L);
        service.acceptReport(publisher, first, 99L);
        PeerControlMessage stale = reportMessage(definition.getServiceId());
        stale.setRevision(1L);
        var ignored = service.acceptReport(publisher, stale, 99L);
        assertThat(ignored).isEmpty();
        assertThat(service.currentCatalog("tenant-a", 1L, 99L).revision()).isEqualTo(2L);
        assertThat(service.currentCatalog("tenant-a", 1L, 99L).services())
                .allSatisfy(item -> {
                    assertThat(item.getName()).isEqualTo("local-ssh");
                    assertThat(item.getPublishedPort()).isEqualTo(2222);
                });
        assertThat(service.catalogsForRecipient(peer))
                .singleElement()
                .satisfies(delivery -> {
                    assertThat(delivery.recipient()).isSameAs(peer);
                    assertThat(delivery.catalog().getPublisherSessionId()).isEqualTo(99L);
                    assertThat(delivery.catalog().getRevision()).isEqualTo(2L);
                    assertThat(delivery.catalog().getServices()).hasSize(1);
                });
    }

    @Test
    void withdrawalKeepsRevisionTombstoneAndServerBoundsClientTtl() {
        ClientAccount publisher = client(1, "alice", "a");
        ClientAccount peer = client(2, "alice", "b");
        PeerMeshSharedService definition = definition(publisher);
        PeerMeshServiceSharing sharing = new PeerMeshServiceSharing();
        sharing.setTenantId("tenant-a");
        sharing.setEnabled(true);
        when(sharingRepository.findById("tenant-a")).thenReturn(Optional.of(sharing));
        when(peerMeshService.isEnabled()).thenReturn(true);
        when(deviceRepository.findByTenantIdAndClientId("tenant-a", 1L)).thenReturn(Optional.of(device(1, "a", true)));
        when(serviceRepository.findByTenantIdAndClientIdOrderByNameAsc("tenant-a", 1L)).thenReturn(List.of(definition));
        when(serviceRepository.findByTenantIdAndClientIdAndServiceId("tenant-a", 1L, definition.getServiceId()))
                .thenReturn(Optional.of(definition));
        when(peerMeshService.allowedRoster(publisher)).thenReturn(List.of(new PeerMeshService.PeerRosterItem(
                2L, "b", "100.96.0.2", "pk", true, false, false, false, false, 0, 2, List.of("ssh"))));
        when(clientAccountRepository.findByTenantIdOrderByIdDesc("tenant-a")).thenReturn(List.of(publisher, peer));
        when(peerMeshService.canPeer(publisher, peer)).thenReturn(true);

        PeerControlMessage published = reportMessage(definition.getServiceId());
        published.setRevision(2L);
        published.setGeneratedAt("2099-01-01T00:00:00Z");
        published.setExpiresAt("2099-01-01T01:00:00Z");
        service.acceptReport(publisher, published, 99L);
        var snapshot = service.currentCatalog("tenant-a", 1L, 99L);
        assertThat(snapshot.expiresAt()).isBefore(Instant.now().plusSeconds(301));

        PeerControlMessage withdrawal = reportMessage(definition.getServiceId());
        withdrawal.setRevision(3L);
        withdrawal.setEnabled(false);
        var deliveries = service.acceptReport(publisher, withdrawal, 99L);
        assertThat(deliveries).allSatisfy(item -> assertThat(item.catalog().getRevision()).isEqualTo(3L));
        assertThat(service.currentCatalog("tenant-a", 1L, 99L)).isNull();

        assertThat(service.acceptReport(publisher, published, 99L)).isEmpty();
        assertThat(service.currentCatalog("tenant-a", 1L, 99L)).isNull();

        service.onClientDisconnected(publisher, 99L);
        assertThat(service.trackedCatalogRevisionCount()).isZero();
    }

    @Test
    void authorizationChangesLoginAndDisconnectSynchronizeThreePeersAndPublisherSessions() {
        ClientAccount publisher = client(1, "alice", "publisher-sync");
        ClientAccount peerB = client(2, "bob", "peer-b-sync");
        ClientAccount peerC = client(3, "carol", "peer-c-sync");
        PeerMeshSharedService definition = definition(publisher);
        definition.setVisibility("ACL");
        definition.setAllowedClientIds("[2,3]");
        PeerMeshServiceSharing sharing = new PeerMeshServiceSharing();
        sharing.setTenantId("tenant-a");
        sharing.setEnabled(true);

        when(sharingRepository.findById("tenant-a")).thenReturn(Optional.of(sharing));
        when(peerMeshService.isEnabled()).thenReturn(true);
        when(deviceRepository.findByTenantIdAndClientId("tenant-a", publisher.getId()))
                .thenReturn(Optional.of(device(publisher.getId(), publisher.getClientName(), true)));
        when(serviceRepository.findByTenantIdAndClientIdOrderByNameAsc("tenant-a", publisher.getId()))
                .thenReturn(List.of(definition));
        when(serviceRepository.findByTenantIdAndClientIdAndServiceId(
                "tenant-a", publisher.getId(), definition.getServiceId())).thenReturn(Optional.of(definition));
        when(serviceRepository.findByIdAndTenantId(definition.getId(), "tenant-a")).thenReturn(Optional.of(definition));
        when(serviceRepository.save(any(PeerMeshSharedService.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(clientAccountRepository.findByTenantIdOrderByIdDesc("tenant-a"))
                .thenReturn(List.of(publisher, peerB, peerC));
        when(clientAccountRepository.findByIdAndTenantId(publisher.getId(), "tenant-a"))
                .thenReturn(Optional.of(publisher));
        when(peerMeshService.allowedRoster(publisher)).thenReturn(List.of(
                new PeerMeshService.PeerRosterItem(peerB.getId(), peerB.getClientName(), "100.96.0.2", "pk-b",
                        true, false, false, false, false, 0, 2, List.of("http")),
                new PeerMeshService.PeerRosterItem(peerC.getId(), peerC.getClientName(), "100.96.0.3", "pk-c",
                        true, false, false, false, false, 0, 2, List.of("http"))));
        when(peerMeshService.canPeer(publisher, peerB)).thenReturn(true);
        when(peerMeshService.canPeer(publisher, peerC)).thenReturn(true);

        EmbeddedChannel channelB = new EmbeddedChannel();
        EmbeddedChannel channelC = new EmbeddedChannel();
        SessionUtil.bindControlSession(new Session(peerB.getClientName()), channelB);
        SessionUtil.bindControlSession(new Session(peerC.getClientName()), channelC);
        try {
            PeerControlMessage report = reportMessage(definition.getServiceId());
            report.setRevision(1L);
            service.acceptReport(publisher, report, 101L);
            report.setRevision(1L);
            service.acceptReport(publisher, report, 102L);

            var visibilityUpdate = new PeerServiceDiscoveryService.ServiceMutation(
                    null, null, null, null, null, null, null, null, null, null, null, "ACL", List.of(2L));
            var filtered = service.updateService(admin(), definition.getId(), visibilityUpdate).catalogs();
            assertThat(filtered).filteredOn(delivery -> delivery.recipient() == peerB).hasSize(2)
                    .allSatisfy(delivery -> assertThat(delivery.catalog().getServices()).hasSize(1));
            assertThat(filtered).filteredOn(delivery -> delivery.recipient() == peerC).hasSize(2)
                    .allSatisfy(delivery -> assertThat(delivery.catalog().getServices()).isEmpty());
            service.updateService(admin(), definition.getId(), new PeerServiceDiscoveryService.ServiceMutation(
                    null, null, null, null, null, null, null, null, null, null, null, "ACL", List.of(2L, 3L)));

            when(peerMeshService.canPeer(publisher, peerB)).thenReturn(false);
            var revoked = service.onAuthorizationChanged("tenant-a");
            assertThat(revoked).filteredOn(delivery -> delivery.recipient() == peerB)
                    .hasSize(2)
                    .allSatisfy(delivery -> assertThat(delivery.catalog().getServices()).isEmpty());
            assertThat(revoked).filteredOn(delivery -> delivery.recipient() == peerC)
                    .hasSize(2)
                    .allSatisfy(delivery -> assertThat(delivery.catalog().getServices()).hasSize(1));
            assertThat(service.catalogsForRecipient(peerB)).hasSize(2)
                    .allSatisfy(delivery -> assertThat(delivery.catalog().getServices()).isEmpty());

            when(peerMeshService.canPeer(publisher, peerB)).thenReturn(true);
            assertThat(service.catalogsForRecipient(peerB)).hasSize(2)
                    .allSatisfy(delivery -> assertThat(delivery.catalog().getServices()).hasSize(1));

            long authorizationRevision = service.currentCatalog("tenant-a", publisher.getId(), 101L).revision();
            report.setRevision(2L);
            assertThat(service.acceptReport(publisher, report, 101L)).isNotEmpty();
            assertThat(service.currentCatalog("tenant-a", publisher.getId(), 101L).revision())
                    .isGreaterThan(authorizationRevision);

            var disconnected = service.onClientDisconnected(publisher, 101L);
            assertThat(disconnected).allSatisfy(delivery -> {
                assertThat(delivery.catalog().getPublisherSessionId()).isEqualTo(101L);
                assertThat(delivery.catalog().getServices()).isEmpty();
            });
            assertThat(service.currentCatalog("tenant-a", publisher.getId(), 101L)).isNull();
            assertThat(service.currentCatalog("tenant-a", publisher.getId(), 102L)).isNotNull();
        } finally {
            channelB.close();
            channelC.close();
        }
    }

    private static ManagementContext admin() {
        return new ManagementContext(new TenantContext("tenant-a"), "admin", true);
    }

    private static ManagementContext user() {
        return new ManagementContext(new TenantContext("tenant-a"), "alice", false);
    }

    private static ClientAccount client(long id, String owner, String name) {
        ClientAccount account = new ClientAccount();
        account.setId(id);
        account.setTenantId("tenant-a");
        account.setOwnerUsername(owner);
        account.setClientName(name);
        account.setEnabled(true);
        return account;
    }

    private static PeerMeshDevice device(long clientId, String name, boolean enabled) {
        PeerMeshDevice device = new PeerMeshDevice();
        device.setClientId(clientId);
        device.setClientName(name);
        device.setVirtualIp("100.96.0." + clientId);
        device.setEnabled(enabled);
        return device;
    }

    @Test
    void importCandidatesCreatesDisabledTcpMapping() {
        when(clientAccountRepository.findByIdAndTenantId(1L, "tenant-a")).thenReturn(Optional.of(client(1, "alice", "a")));
        when(serviceRepository.findByTenantIdAndClientIdAndServiceId(any(), any(), any())).thenReturn(Optional.empty());
        when(serviceRepository.findByTenantIdAndClientIdOrderByNameAsc("tenant-a", 1L)).thenReturn(List.of());
        when(serviceRepository.save(any(PeerMeshSharedService.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(deviceRepository.findByTenantIdAndClientId("tenant-a", 1L)).thenReturn(Optional.of(device(1, "a", true)));
        SpecusMapping mapping = new SpecusMapping();
        mapping.setTargetAddress("127.0.0.1");
        mapping.setTargetPort(22);
        mapping.setListenPort(2222);
        when(specusMappingRepository.findByTenantIdAndClientIdOrderByIdDesc("tenant-a", 1L)).thenReturn(List.of(mapping));

        var result = service.importCandidates(admin(), 1L);

        assertThat(result.created()).isEqualTo(1);
        assertThat(result.services()).hasSize(1);
        assertThat(result.services().getFirst().enabled()).isFalse();
        assertThat(result.services().getFirst().targetHost()).isEqualTo("127.0.0.1");
        assertThat(result.services().getFirst().application()).isEqualTo("tcp");
    }

    @Test
    void aclVisibilityHidesServiceFromClientsNotOnAllowList() {
        ClientAccount publisher = client(1, "alice", "a");
        ClientAccount allowed = client(2, "bob", "b");
        ClientAccount other = client(3, "carol", "c");
        PeerMeshSharedService definition = definition(publisher);
        definition.setVisibility("ACL");
        definition.setAllowedClientIds("2");
        PeerMeshServiceSharing sharing = new PeerMeshServiceSharing();
        sharing.setTenantId("tenant-a");
        sharing.setEnabled(true);
        when(sharingRepository.findById("tenant-a")).thenReturn(Optional.of(sharing));
        when(peerMeshService.isEnabled()).thenReturn(true);
        when(deviceRepository.findByTenantIdAndClientId("tenant-a", 1L)).thenReturn(Optional.of(device(1, "a", true)));
        when(serviceRepository.findByTenantIdAndClientIdOrderByNameAsc("tenant-a", 1L)).thenReturn(List.of(definition));
        when(serviceRepository.findByTenantIdAndClientIdAndServiceId("tenant-a", 1L, definition.getServiceId()))
                .thenReturn(Optional.of(definition));
        when(peerMeshService.allowedRoster(publisher)).thenReturn(List.of(
                new PeerMeshService.PeerRosterItem(2L, "b", "100.96.0.2", "pk", true, false, false, false, false, 0, 1, List.of()),
                new PeerMeshService.PeerRosterItem(3L, "c", "100.96.0.3", "pk", true, false, false, false, false, 0, 1, List.of())));
        when(clientAccountRepository.findByTenantIdOrderByIdDesc("tenant-a")).thenReturn(List.of(publisher, allowed, other));
        when(peerMeshService.canPeer(publisher, allowed)).thenReturn(true);
        when(peerMeshService.canPeer(publisher, other)).thenReturn(true);

        PeerAdvertisedService advertised = fromDefinition(definition);
        assertThat(service.visibleTo(publisher, allowed, advertised)).isTrue();
        assertThat(service.visibleTo(publisher, other, advertised)).isFalse();
    }

    private static PeerAdvertisedService fromDefinition(PeerMeshSharedService row) {
        PeerAdvertisedService service = new PeerAdvertisedService();
        service.setServiceId(row.getServiceId());
        service.setName(row.getName());
        service.setTransport(row.getTransport());
        service.setApplication(row.getApplication());
        service.setPublishedPort(row.getPublishedPort());
        return service;
    }

    @Test
    void rejectsUdpApplicationWithTcpTransport() {
        when(clientAccountRepository.findByIdAndTenantId(1L, "tenant-a")).thenReturn(Optional.of(client(1, "alice", "a")));
        when(serviceRepository.findByTenantIdAndClientIdAndServiceId(any(), any(), any())).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.createService(admin(),
                new PeerServiceDiscoveryService.ServiceMutation(
                        1L, null, "dns", "", "tcp", "udp", "127.0.0.1", 53, 5353, null, false, "OWNER", null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("udp");
    }

    private static PeerMeshSharedService definition(ClientAccount account) {
        PeerMeshSharedService row = new PeerMeshSharedService();
        row.setId(11L);
        row.setTenantId(account.getTenantId());
        row.setClientId(account.getId());
        row.setClientName(account.getClientName());
        row.setServiceId("svc-ssh001");
        row.setName("local-ssh");
        row.setTransport("tcp");
        row.setApplication("ssh");
        row.setTargetHost("127.0.0.1");
        row.setTargetPort(22);
        row.setPublishedPort(2222);
        row.setEnabled(true);
        row.setVisibility("OWNER");
        row.setCreatedAt(Instant.now().toString());
        row.setUpdatedAt(Instant.now().toString());
        return row;
    }

    private static PeerServiceDiscoveryService.ServiceMutation mutation(String application,
                                                                        String host,
                                                                        int targetPort,
                                                                        int publishedPort,
                                                                        boolean enabled) {
        return new PeerServiceDiscoveryService.ServiceMutation(
                1L, null, "svc", "", "tcp", application, host, targetPort, publishedPort, null, enabled, "OWNER", null);
    }

    private static PeerControlMessage reportMessage(String serviceId) {
        PeerAdvertisedService advertised = new PeerAdvertisedService();
        advertised.setServiceId(serviceId);
        advertised.setName("client-supplied-name");
        advertised.setTransport("tcp");
        advertised.setApplication("ssh");
        advertised.setPublishedPort(2222);
        PeerControlMessage report = new PeerControlMessage();
        report.setType(PeerControlMessage.TYPE_SERVICE_REPORT);
        report.setEnabled(true);
        report.setRevision(1L);
        report.setServices(List.of(advertised));
        report.setGeneratedAt(Instant.now().toString());
        report.setExpiresAt(Instant.now().plusSeconds(60).toString());
        return report;
    }
}
