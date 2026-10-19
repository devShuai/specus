package com.theshuai.specusserver.management.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.management.model.*;
import com.theshuai.specusserver.management.repository.*;
import jakarta.persistence.EntityManager;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Actual persisted metadata and the real Spring Data query; only unrelated policy/runtime inputs are mocked. */
@Execution(ExecutionMode.SAME_THREAD)
class PeerEgressSessionOrderJpaTests {
    @TempDir static Path temporary;
    private static SessionFactory factory;
    private static EntityManager entityManager;
    private static ClientSessionRepository sessions;

    @BeforeAll
    static void database() {
        factory = new Configuration().addAnnotatedClass(ClientSession.class)
                .setProperty("hibernate.connection.driver_class", "org.sqlite.JDBC")
                .setProperty("hibernate.connection.url", "jdbc:sqlite:" + temporary.resolve("session-order.db"))
                .setProperty("hibernate.dialect", "org.hibernate.community.dialect.SQLiteDialect")
                .setProperty("hibernate.hbm2ddl.auto", "create-drop")
                .setProperty("hibernate.show_sql", "false")
                .buildSessionFactory();
        entityManager = factory.createEntityManager();
        entityManager.getTransaction().begin();
        String ddl = (String) entityManager.createNativeQuery(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='specus_client_session'", String.class).getSingleResult();
        for (String column : List.of("tenant_id", "status")) {
            String changed = ddl.replaceFirst("(?i)\\b" + column + "(\\s+[^ ,]+)", column + "$1 collate nocase");
            assertThat(changed).as("owned collation fixture: " + column).isNotEqualTo(ddl);
            ddl = changed;
        }
        // Real repository queries now return collation-equivalent candidates;
        // the service must filter exact identity before considering timestamps.
        entityManager.createNativeQuery("DROP TABLE specus_client_session", Integer.class).executeUpdate();
        entityManager.createNativeQuery(ddl, Integer.class).executeUpdate();
        entityManager.getTransaction().commit();
        sessions = new JpaRepositoryFactory(entityManager).getRepository(ClientSessionRepository.class);
    }

    @AfterAll
    static void close() {
        if (entityManager != null) entityManager.close();
        if (factory != null) factory.close();
    }

    @BeforeEach
    @AfterEach
    void resetPersistenceContext() {
        if (entityManager.getTransaction().isActive()) entityManager.getTransaction().rollback();
        // Bulk HQL deletion does not evict entities loaded by the previous catalogue.
        // Each vector must start independently, including after a failing assertion.
        entityManager.clear();
    }

    static Stream<Arguments> orderingCases() throws Exception {
        return vectorCases("peer-egress-session-order-v1.json", 26);
    }

    static Stream<Arguments> scopeCases() throws Exception {
        return vectorCases("peer-egress-session-scope-v1.json", 8);
    }

    private static Stream<Arguments> vectorCases(String vectorFile, int expectedCases) throws Exception {
        for (Path directory = Path.of("").toAbsolutePath(); directory != null; directory = directory.getParent()) {
            Path path = directory.resolve("protocol/test-vectors/" + vectorFile);
            if (!Files.isRegularFile(path)) continue;
            JsonNode root = JsonUtil.readString(Files.readString(path));
            assertThat(root.path("consumerIpv6DataPlaneEnabled").asBoolean()).isFalse();
            assertThat(root.path("cases")).hasSize(expectedCases);
            List<Arguments> examples = new ArrayList<>();
            root.path("cases").forEach(example -> examples.add(Arguments.of(example.path("name").asText(), example.toString())));
            return examples.stream();
        }
        throw new IllegalStateException("Shared session ordering vector not found");
    }

    @ParameterizedTest(name = "persisted session order {0}")
    @MethodSource("orderingCases")
    void actualRepositoryAndCatalogueFollowSharedOrder(String name, String json) {
        assertCatalogue(name, json, "tenant-a", 1002L);
    }

    @ParameterizedTest(name = "persisted exact scope {0}")
    @MethodSource("scopeCases")
    void actualRepositoryAndCatalogueIgnoreCollationEquivalentScope(String name, String json) {
        assertCatalogue(name, json, "default", 2002L);
    }

    private void assertCatalogue(String name, String json, String tenant, long egressId) {
        JsonNode example = JsonUtil.readString(json);
        entityManager.getTransaction().begin();
        entityManager.createQuery("delete from ClientSession").executeUpdate();
        for (JsonNode row : example.path("sessions")) {
            ClientSession session = new ClientSession();
            session.setId(row.path("id").asLong());
            session.setTenantId(row.path("tenantId").asText());
            session.setCredentialId(1L);
            session.setIdentityId(1L);
            session.setClientId(row.path("clientId").asLong());
            session.setClientName("order-egress");
            session.setTokenHash("session-order-" + session.getId());
            session.setStatus(row.path("status").asText());
            session.setMachineFingerprint("fixture-machine");
            session.setOsUser("fixture-user");
            session.setHttpLoginAt(row.path("httpLoginAt").asText());
            session.setNettyConnectedAt(row.path("connectedAt").isNull() ? null : row.path("connectedAt").asText());
            session.setExpiresAt("2026-10-19T00:00:00Z");
            session.setClientEgressVersion(row.path("version").asInt());
            session.setClientEgressDomainTargets(row.path("domainTargetCapable").asBoolean());
            session.setClientEgressIpv6Targets(row.path("ipv6TargetCapable").asBoolean());
            entityManager.persist(session);
        }
        entityManager.getTransaction().commit();
        entityManager.clear(); // Catalogue must read stored columns, not these Java objects.
        if (tenant.equals("default") && (name.contains("-case-") || name.equals("matching-corrupt-time-remains-unknown"))) {
            assertThat(sessions.findByTenantIdAndClientIdInAndStatus(tenant, List.of(egressId), "NETTY_ONLINE"))
                    .as("fixture must really return collation-equivalent candidates: " + name)
                    .hasSize(name.equals("only-case-foreign-is-not-online") ? 1 : 2);
        }

        var policies = mock(PeerMeshEgressPolicyRepository.class);
        var activity = mock(PeerMeshEgressActivityRepository.class);
        var switches = mock(PeerMeshEgressSwitchRepository.class);
        var devices = mock(PeerMeshDeviceRepository.class);
        var accounts = mock(ClientAccountRepository.class);
        var mesh = mock(PeerMeshService.class);
        ClientAccount consumer = account(1001L, "order-consumer", tenant);
        ClientAccount egress = account(egressId, "order-egress", tenant);
        PeerMeshEgressPolicy policy = new PeerMeshEgressPolicy();
        policy.setTenantId(tenant);
        policy.setEgressClientId(egress.getId());
        policy.setEgressClientName(egress.getClientName());
        policy.setEnabled(true);
        policy.setScope(com.theshuai.common.peeregress.PeerEgressPolicy.SCOPE_PUBLIC);
        policy.setAllowedConsumerClientIds(com.theshuai.common.peermesh.PeerServiceDiscovery.encodeClientIds(List.of(consumer.getId())));
        policy.setDestinationRules("[]");
        policy.setDomainRules("[]");
        PeerMeshEgressSwitch enabled = new PeerMeshEgressSwitch();
        enabled.setTenantId(tenant);
        enabled.setEnabled(true);
        PeerMeshDevice device = new PeerMeshDevice();
        device.setEnabled(true);
        when(mesh.isEnabled()).thenReturn(true);
        when(mesh.canPeer(any(), any())).thenReturn(true);
        when(switches.findById(tenant)).thenReturn(Optional.of(enabled));
        when(accounts.findByTenantIdOrderByIdDesc(tenant)).thenReturn(List.of(consumer, egress));
        when(accounts.findByIdAndTenantId(egress.getId(), tenant)).thenReturn(Optional.of(egress));
        when(devices.findByTenantIdAndClientId(tenant, egress.getId())).thenReturn(Optional.of(device));
        when(policies.findByTenantIdAndEnabledTrueOrderByEgressClientNameAsc(tenant)).thenReturn(List.of(policy));
        var service = new PeerEgressService(policies, activity, switches, devices, accounts, sessions, mesh);
        var catalog = service.buildEgressCatalog(consumer, 1);
        assertThat(catalog.getEgresses()).hasSize(1);
        var entry = catalog.getEgresses().getFirst();
        var expected = example.path("expected");
        assertThat(entry.getEgressVersion()).as(name + ": version").isEqualTo(expected.path("version").asInt());
        assertThat(entry.isDomainTargetCapable()).as(name + ": domain").isEqualTo(expected.path("domainTargetCapable").asBoolean());
        assertThat(entry.isIpv6TargetCapable()).as(name + ": IPv6").isEqualTo(expected.path("ipv6TargetCapable").asBoolean());
    }

    private static ClientAccount account(long id, String name, String tenant) {
        ClientAccount account = new ClientAccount();
        account.setId(id);
        account.setTenantId(tenant);
        account.setClientName(name);
        account.setOwnerUsername("fixture-owner");
        account.setEnabled(true);
        return account;
    }
}
