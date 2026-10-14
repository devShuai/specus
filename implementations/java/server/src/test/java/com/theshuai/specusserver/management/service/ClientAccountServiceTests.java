package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.ClientIdentity;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.model.PeerMeshAcl;
import com.theshuai.specusserver.management.model.PeerMeshDevice;
import com.theshuai.specusserver.management.model.ResourceTrafficUsage;
import com.theshuai.specusserver.management.model.TrafficUsage;
import com.theshuai.specusserver.management.model.SpecusMapping;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.ClientIdentityRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.repository.PeerMeshAclRepository;
import com.theshuai.specusserver.management.repository.PeerMeshDeviceRepository;
import com.theshuai.specusserver.management.repository.ResourceTrafficUsageRepository;
import com.theshuai.specusserver.management.repository.TrafficUsageRepository;
import com.theshuai.specusserver.management.repository.SpecusMappingRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.service.ClientAccountService.ClientMutation;
import com.theshuai.specusserver.management.tenant.TenantContext;
import jakarta.persistence.EntityManager;
import com.theshuai.specusserver.management.model.PeerMeshEgressPolicy;
import com.theshuai.specusserver.management.model.PeerMeshSharedService;
import com.theshuai.specusserver.management.model.PeerMeshSession;
import com.theshuai.specusserver.management.repository.PeerMeshEgressPolicyRepository;
import com.theshuai.specusserver.management.repository.PeerMeshSharedServiceRepository;
import com.theshuai.specusserver.management.repository.PeerMeshSessionRepository;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import io.netty.channel.embedded.EmbeddedChannel;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.session.SessionUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {
                "spring.datasource.url=jdbc:sqlite:file:target/test-client-account?mode=memory&cache=shared",
                "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "specus.netty.port=0",
                "specus.database.seed-demo-client=false"
        }
)
class ClientAccountServiceTests {
    @Autowired private ClientAccountService clientAccountService;
    @Autowired private ClientAccountRepository clientAccountRepository;
    @Autowired private ClientIdentityRepository clientIdentityRepository;
    @Autowired private SpecusMappingRepository specusMappingRepository;
    @Autowired private HttpRouteMappingRepository httpRouteMappingRepository;
    @Autowired private PeerMeshDeviceRepository peerMeshDeviceRepository;
    @Autowired private PeerMeshAclRepository peerMeshAclRepository;
    @Autowired private TrafficUsageRepository trafficUsageRepository;
    @Autowired private ResourceTrafficUsageRepository resourceTrafficUsageRepository;
    @Autowired private EntityManager entityManager;
    @Autowired private PeerMeshEgressPolicyRepository egressRepository;
    @Autowired private PeerMeshSharedServiceRepository sharedServiceRepository;
    @Autowired private PeerMeshSessionRepository peerSessionRepository;
    @Autowired private PlatformTransactionManager transactionManager;
    @Autowired private com.theshuai.specusserver.management.repository.ManagementUserRepository managementUsers;

    @AfterEach
    void tearDown() {
        peerSessionRepository.deleteAll();
        sharedServiceRepository.deleteAll();
        egressRepository.deleteAll();
        resourceTrafficUsageRepository.deleteAll();
        trafficUsageRepository.deleteAll();
        peerMeshAclRepository.deleteAll();
        peerMeshDeviceRepository.deleteAll();
        httpRouteMappingRepository.deleteAll();
        specusMappingRepository.deleteAll();
        clientIdentityRepository.deleteAll();
        clientAccountRepository.deleteAll();
        managementUsers.deleteAll();
    }

    @Test
    void nameAvailabilityIsGlobalAndAllowsCurrentClient() {
        ClientAccount first = createClient(TenantContext.defaultTenant(), "office-pc");
        createClient(new TenantContext("another-tenant"), "warehouse-pc");
        ManagementContext context = new ManagementContext(TenantContext.defaultTenant(), "admin", true);

        assertThat(clientAccountService.checkClientNameAvailability(context, " office-pc ", first.getId()).available())
                .isTrue();
        assertThat(clientAccountService.checkClientNameAvailability(context, "new-name", first.getId()).available())
                .isTrue();
        assertThat(clientAccountService.checkClientNameAvailability(context, "warehouse-pc", first.getId()).available())
                .isFalse();

        assertThatThrownBy(() -> clientAccountService.updateClient(
                TenantContext.defaultTenant(), first.getId(), new ClientMutation("warehouse-pc", true, 30)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("已存在");
    }

    @Test
    void renamePropagatesToOperationalClientNameReferences() {
        ClientAccount source = createClient(TenantContext.defaultTenant(), "source-old");
        ClientAccount target = createClient(TenantContext.defaultTenant(), "target");
        String now = "2026-07-14T00:00:00Z";

        ClientIdentity identity = new ClientIdentity();
        identity.setId(ClientIdGenerator.newId());
        identity.setTenantId(TenantContext.DEFAULT_TENANT_ID);
        identity.setCredentialId(ClientIdGenerator.newId());
        identity.setClientId(source.getId());
        identity.setClientName(source.getClientName());
        identity.setMachineFingerprint("machine-source");
        identity.setOsUser("tester");
        identity.setFirstSeenAt(now);
        identity.setLastSeenAt(now);
        clientIdentityRepository.save(identity);

        SpecusMapping specus = new SpecusMapping();
        specus.setId(ClientIdGenerator.newId());
        specus.setTenantId(TenantContext.DEFAULT_TENANT_ID);
        specus.setClientId(source.getId());
        specus.setClientName(source.getClientName());
        specus.setListenPort(31101);
        specus.setTargetAddress("127.0.0.1");
        specus.setTargetPort(8080);
        specus.setCreatedAt(now);
        specus.setUpdatedAt(now);
        specusMappingRepository.save(specus);

        HttpRouteMapping route = new HttpRouteMapping();
        route.setId(ClientIdGenerator.newId());
        route.setTenantId(TenantContext.DEFAULT_TENANT_ID);
        route.setClientId(source.getId());
        route.setClientName(source.getClientName());
        route.setRoute("app");
        route.setTargetBaseUrl("http://127.0.0.1:8080");
        route.setCreatedAt(now);
        route.setUpdatedAt(now);
        httpRouteMappingRepository.save(route);

        PeerMeshDevice device = new PeerMeshDevice();
        device.setId(ClientIdGenerator.newId());
        device.setTenantId(TenantContext.DEFAULT_TENANT_ID);
        device.setOwnerUsername("admin");
        device.setClientId(source.getId());
        device.setClientName(source.getClientName());
        device.setVirtualIp("100.96.0.10");
        device.setCidr("100.96.0.0/11");
        device.setCreatedAt(now);
        device.setUpdatedAt(now);
        peerMeshDeviceRepository.save(device);

        PeerMeshAcl acl = new PeerMeshAcl();
        acl.setId(ClientIdGenerator.newId());
        acl.setTenantId(TenantContext.DEFAULT_TENANT_ID);
        acl.setOwnerUsername("admin");
        acl.setSourceClientId(source.getId());
        acl.setSourceClientName(source.getClientName());
        acl.setTargetClientId(target.getId());
        acl.setTargetClientName(target.getClientName());
        acl.setCreatedAt(now);
        acl.setUpdatedAt(now);
        peerMeshAclRepository.save(acl);

        TrafficUsage traffic = new TrafficUsage();
        traffic.setTenantId(TenantContext.DEFAULT_TENANT_ID);
        traffic.setClientId(source.getId());
        traffic.setClientName(source.getClientName());
        traffic.setUsageDate("2026-07-14");
        traffic.setUpdatedAt(now);
        trafficUsageRepository.save(traffic);

        ResourceTrafficUsage resourceTraffic = new ResourceTrafficUsage();
        resourceTraffic.setTenantId(TenantContext.DEFAULT_TENANT_ID);
        resourceTraffic.setClientId(source.getId());
        resourceTraffic.setClientName(source.getClientName());
        resourceTraffic.setResourceType("TCP_SPECUS");
        resourceTraffic.setResourceKey("31101");
        resourceTraffic.setResourceName("SSH");
        resourceTraffic.setUsageDate("2026-07-14");
        resourceTraffic.setUpdatedAt(now);
        resourceTrafficUsageRepository.save(resourceTraffic);

        clientAccountService.updateClient(
                TenantContext.defaultTenant(), source.getId(), new ClientMutation("source-new", true, 30));
        entityManager.clear();

        assertThat(clientIdentityRepository.findById(identity.getId()).orElseThrow().getClientName()).isEqualTo("source-new");
        assertThat(specusMappingRepository.findById(specus.getId()).orElseThrow().getClientName()).isEqualTo("source-new");
        assertThat(httpRouteMappingRepository.findById(route.getId()).orElseThrow().getClientName()).isEqualTo("source-new");
        assertThat(peerMeshDeviceRepository.findById(device.getId()).orElseThrow().getClientName()).isEqualTo("source-new");
        assertThat(peerMeshAclRepository.findById(acl.getId()).orElseThrow().getSourceClientName()).isEqualTo("source-new");
        assertThat(trafficUsageRepository.findById(traffic.getId()).orElseThrow().getClientName()).isEqualTo("source-new");
        assertThat(resourceTrafficUsageRepository.findById(resourceTraffic.getId()).orElseThrow().getClientName()).isEqualTo("source-new");
    }

    @Test
    void deleteCleansBothAclDirectionsAndPeerReferencesWithoutWideningAllowLists() {
        ClientAccount removed = createClient(TenantContext.defaultTenant(), "removed");
        ClientAccount kept = createClient(TenantContext.defaultTenant(), "kept");
        ClientAccount other = createClient(TenantContext.defaultTenant(), "other");
        PeerMeshDevice device = saveDevice(removed, removed.getTenantId());
        PeerMeshDevice foreignDevice = saveDevice(removed, "foreign");
        saveAcl(removed, kept, removed.getTenantId());
        saveAcl(kept, removed, removed.getTenantId());
        PeerMeshAcl unrelated = saveAcl(kept, other, kept.getTenantId());
        PeerMeshAcl foreignAcl = saveAcl(removed, kept, "foreign");
        PeerMeshEgressPolicy ownPolicy = savePolicy(removed, kept.getId().toString());
        PeerMeshEgressPolicy otherPolicy = savePolicy(kept, removed.getId() + "," + other.getId());
        PeerMeshSharedService ownService = saveService(removed, "own", "");
        PeerMeshSharedService lastRecipient = saveService(kept, "last", removed.getId().toString());
        PeerMeshSharedService remaining = saveService(kept, "remaining", removed.getId() + "," + other.getId());
        PeerMeshSharedService allPeers = saveService(kept, "all", "");
        PeerMeshSession session = saveSession(removed, kept);

        clientAccountService.deleteClient(TenantContext.defaultTenant(), removed.getId());

        assertThat(clientAccountRepository.findById(removed.getId())).isEmpty();
        assertThat(peerMeshDeviceRepository.findById(device.getId())).isEmpty();
        assertThat(peerMeshDeviceRepository.findById(foreignDevice.getId())).isPresent();
        assertThat(peerMeshAclRepository.findAll()).extracting(PeerMeshAcl::getId)
                .containsExactlyInAnyOrder(unrelated.getId(), foreignAcl.getId());
        assertThat(egressRepository.findById(ownPolicy.getId())).isEmpty();
        assertThat(egressRepository.findById(otherPolicy.getId()).orElseThrow().getAllowedConsumerClientIds())
                .isEqualTo(other.getId().toString());
        assertThat(sharedServiceRepository.findById(ownService.getId())).isEmpty();
        PeerMeshSharedService disabled = sharedServiceRepository.findById(lastRecipient.getId()).orElseThrow();
        assertThat(disabled.getAllowedClientIds()).isEmpty();
        assertThat(disabled.isEnabled()).isFalse();
        assertThat(sharedServiceRepository.findById(remaining.getId()).orElseThrow().getAllowedClientIds())
                .isEqualTo(other.getId().toString());
        assertThat(sharedServiceRepository.findById(allPeers.getId()).orElseThrow().isEnabled()).isTrue();
        PeerMeshSession history = peerSessionRepository.findById(session.getId()).orElseThrow();
        assertThat(history.getStatus()).isEqualTo(PeerMeshService.STATUS_CLOSED);
        assertThat(history.getClosedAt()).isNotBlank();
        assertThat(history.getSourceClientName()).isEqualTo("removed");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void replaysSharedClientPeerDeletionVector(boolean rollback) throws Exception {
        Path root = Path.of("").toAbsolutePath();
        while (root != null && !Files.exists(root.resolve("protocol/test-vectors/client-peer-deletion-v1.json"))) {
            root = root.getParent();
        }
        assertThat(root).as("repository vector root").isNotNull();
        JsonNode vector = new ObjectMapper().readTree(Files.readString(
                root.resolve("protocol/test-vectors/client-peer-deletion-v1.json")));
        assertThat(vector.path("version").asInt()).isEqualTo(1);
        assertThat(vector.path("setup").size()).isEqualTo(7);
        assertThat(vector.path("checks").size()).isEqualTo(23);
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        transaction.executeWithoutResult(status -> {
            for (JsonNode sql : vector.path("setup")) {
                entityManager.createNativeQuery(sql.asText().replace("client_account", "specus_client_account")).executeUpdate();
            }
            if (rollback) {
                entityManager.createNativeQuery("CREATE TRIGGER fail_vector_delete BEFORE DELETE ON specus_client_account "
                        + "WHEN OLD.id=1001 BEGIN SELECT RAISE(ABORT,'injected failure'); END").executeUpdate();
            }
        });
        try {
            Runnable deletion = () -> clientAccountService.deleteClient(
                    com.theshuai.specusserver.management.ManagementActorFixtures.admin(managementUsers,
                            vector.path("tenantId").asText(), vector.path("actor").asText()), vector.path("clientId").asLong());
            if (rollback) assertThatThrownBy(deletion::run).isInstanceOf(RuntimeException.class);
            else deletion.run();
            transaction.executeWithoutResult(status -> {
                for (JsonNode check : vector.path("checks")) {
                    Number count = (Number) entityManager.createNativeQuery(check.path("query").asText()
                            .replace("client_account", "specus_client_account")).getSingleResult();
                    assertThat(count.longValue()).as(check.path("name").asText())
                            .isEqualTo(check.path(rollback ? "retained" : "deleted").asLong());
                }
            });
        } finally {
            transaction.executeWithoutResult(status -> {
                entityManager.createNativeQuery("DROP TRIGGER IF EXISTS fail_vector_delete").executeUpdate();
                entityManager.createNativeQuery("DELETE FROM management_workbench_item WHERE tenant_id='tenant-a'").executeUpdate();
            });
        }
    }

    @Test
    void deleteRollsBackClientPeerRowsAndSessionTogether() {
        ClientAccount removed = createClient(TenantContext.defaultTenant(), "rollback-removed");
        ClientAccount kept = createClient(TenantContext.defaultTenant(), "rollback-kept");
        PeerMeshDevice device = saveDevice(removed, removed.getTenantId());
        PeerMeshAcl acl = saveAcl(removed, kept, removed.getTenantId());
        PeerMeshEgressPolicy policy = savePolicy(kept, removed.getId().toString());
        PeerMeshSharedService service = saveService(kept, "rollback", removed.getId().toString());
        PeerMeshSession session = saveSession(removed, kept);
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            clientAccountService.deleteClient(TenantContext.defaultTenant(), removed.getId());
            status.setRollbackOnly();
        });
        assertThat(clientAccountRepository.findById(removed.getId())).isPresent();
        assertThat(peerMeshDeviceRepository.findById(device.getId())).isPresent();
        assertThat(peerMeshAclRepository.findById(acl.getId())).isPresent();
        assertThat(egressRepository.findById(policy.getId()).orElseThrow().getAllowedConsumerClientIds())
                .isEqualTo(removed.getId().toString());
        assertThat(sharedServiceRepository.findById(service.getId()).orElseThrow().isEnabled()).isTrue();
        assertThat(peerSessionRepository.findById(session.getId()).orElseThrow().getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void deletingAnOnlineClientClosesItOnlyAfterCommit() {
        ClientAccount removed = createClient(TenantContext.defaultTenant(), "online-delete");
        EmbeddedChannel channel = new EmbeddedChannel();
        SessionUtil.bindSession(new Session(removed.getClientName()), channel);
        try {
            new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
                clientAccountService.deleteClient(TenantContext.defaultTenant(), removed.getId());
                assertThat(channel.isOpen()).isTrue();
                status.setRollbackOnly();
            });
            assertThat(channel.isOpen()).isTrue();
            assertThat(clientAccountService.findClientByName(removed.getClientName())).isPresent();
            new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
                clientAccountService.deleteClient(TenantContext.defaultTenant(), removed.getId());
                assertThat(channel.isOpen()).isTrue();
            });
            assertThat(channel.isOpen()).isFalse();
            assertThat(clientAccountService.findClientByName(removed.getClientName())).isEmpty();
        } finally {
            SessionUtil.unBindSession(channel);
            channel.finishAndReleaseAll();
        }
    }

    private PeerMeshDevice saveDevice(ClientAccount account, String tenant) {
        PeerMeshDevice row = new PeerMeshDevice();
        row.setId(ClientIdGenerator.newId()); row.setTenantId(tenant); row.setOwnerUsername("admin");
        row.setClientId(account.getId()); row.setClientName(account.getClientName());
        row.setVirtualIp("100.96.0.10"); row.setCidr("100.96.0.0/11");
        row.setCreatedAt("2026-10-13T00:00:00Z"); row.setUpdatedAt(row.getCreatedAt());
        return peerMeshDeviceRepository.save(row);
    }

    private PeerMeshAcl saveAcl(ClientAccount source, ClientAccount target, String tenant) {
        PeerMeshAcl row = new PeerMeshAcl();
        row.setId(ClientIdGenerator.newId()); row.setTenantId(tenant); row.setOwnerUsername("admin");
        row.setSourceClientId(source.getId()); row.setSourceClientName(source.getClientName());
        row.setTargetClientId(target.getId()); row.setTargetClientName(target.getClientName());
        row.setCreatedAt("2026-10-13T00:00:00Z"); row.setUpdatedAt(row.getCreatedAt());
        return peerMeshAclRepository.save(row);
    }

    private PeerMeshEgressPolicy savePolicy(ClientAccount account, String allowed) {
        PeerMeshEgressPolicy row = new PeerMeshEgressPolicy();
        row.setId(ClientIdGenerator.newId()); row.setTenantId(account.getTenantId()); row.setOwnerUsername("admin");
        row.setEgressClientId(account.getId()); row.setEgressClientName(account.getClientName());
        row.setAllowedConsumerClientIds(allowed); row.setEnabled(true);
        row.setCreatedAt("2026-10-13T00:00:00Z"); row.setUpdatedAt(row.getCreatedAt());
        return egressRepository.save(row);
    }

    private PeerMeshSharedService saveService(ClientAccount account, String name, String allowed) {
        PeerMeshSharedService row = new PeerMeshSharedService();
        row.setId(ClientIdGenerator.newId()); row.setTenantId(account.getTenantId());
        row.setClientId(account.getId()); row.setClientName(account.getClientName());
        row.setServiceId(name); row.setName(name); row.setApplication("http");
        row.setTargetHost("127.0.0.1"); row.setTargetPort(8080); row.setPublishedPort(8080);
        row.setVisibility("ACL"); row.setAllowedClientIds(allowed); row.setEnabled(true);
        row.setCreatedAt("2026-10-13T00:00:00Z"); row.setUpdatedAt(row.getCreatedAt());
        return sharedServiceRepository.save(row);
    }

    private PeerMeshSession saveSession(ClientAccount source, ClientAccount target) {
        PeerMeshSession row = new PeerMeshSession();
        row.setId(ClientIdGenerator.newId()); row.setTenantId(source.getTenantId());
        row.setSourceClientId(source.getId()); row.setSourceClientName(source.getClientName());
        row.setTargetClientId(target.getId()); row.setTargetClientName(target.getClientName());
        row.setPathType("DIRECT"); row.setStatus("ACTIVE");
        row.setStartedAt("2026-10-13T00:00:00Z"); row.setUpdatedAt(row.getStartedAt());
        row.setExpiresAt("2099-01-01T00:00:00.000000000Z");
        return peerSessionRepository.save(row);
    }

    private ClientAccount createClient(TenantContext tenant, String clientName) {
        clientAccountService.createClient(tenant, new ClientMutation(clientName, true, 30));
        return clientAccountRepository.findByClientName(clientName).orElseThrow();
    }
}
