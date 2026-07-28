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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
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

    @AfterEach
    void tearDown() {
        resourceTrafficUsageRepository.deleteAll();
        trafficUsageRepository.deleteAll();
        peerMeshAclRepository.deleteAll();
        peerMeshDeviceRepository.deleteAll();
        httpRouteMappingRepository.deleteAll();
        specusMappingRepository.deleteAll();
        clientIdentityRepository.deleteAll();
        clientAccountRepository.deleteAll();
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

    private ClientAccount createClient(TenantContext tenant, String clientName) {
        clientAccountService.createClient(tenant, new ClientMutation(clientName, true, 30));
        return clientAccountRepository.findByClientName(clientName).orElseThrow();
    }
}
