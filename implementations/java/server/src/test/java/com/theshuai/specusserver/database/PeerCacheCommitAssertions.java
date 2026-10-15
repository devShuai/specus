package com.theshuai.specusserver.database;

import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerDataFrameHeader;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.service.PeerMeshService;
import org.junit.jupiter.api.function.Executable;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import javax.sql.DataSource;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

/** Actual transactions and real services; reflection observes caches, never fabricates entries. */
public final class PeerCacheCommitAssertions {
    private enum Case { CREATE_COMMIT, CREATE_ROLLBACK, REUSE_IN_TRANSACTION, CLOSE_COMMIT, CLOSE_ROLLBACK,
        RELAY_COMMIT, RELAY_ROLLBACK, PATH_COMMIT, PATH_ROLLBACK, RETAIN_ACCEPTED_TRAFFIC }
    private record Fixture(ClientAccount source, ClientAccount target) {}

    public static void verify(ConfigurableApplicationContext context, DataSource independent) throws Exception {
        var service = context.getBean(PeerMeshService.class);
        var jdbc = context.getBean(JdbcTemplate.class);
        var tx = new TransactionTemplate(context.getBean(PlatformTransactionManager.class));
        List<Executable> cases = new ArrayList<>();
        for (Case selected : Case.values()) cases.add(() -> {
            var fixture = fixture(context, 6_100_000 + selected.ordinal() * 10);
            if (selected == Case.CREATE_COMMIT || selected == Case.CREATE_ROLLBACK || selected == Case.REUSE_IN_TRANSACTION) {
                var granted = tx.execute(status -> {
                    var a = grant(service, fixture);
                    assertFalse(cache(service, "sessionTokenCache").containsKey(a.session().id()), "uncommitted token must not enter shared cache");
                    if (selected == Case.REUSE_IN_TRANSACTION) {
                        var b = grant(service, fixture);
                        assertEquals(a.session().id(), b.session().id()); assertEquals(a.token(), b.token());
                    }
                    if (selected == Case.CREATE_ROLLBACK) status.setRollbackOnly();
                    return a;
                });
                assertNotNull(granted);
                assertEquals(selected != Case.CREATE_ROLLBACK, cache(service, "sessionTokenCache").containsKey(granted.session().id()));
                assertEquals(selected == Case.CREATE_ROLLBACK ? 0 : 1,
                        jdbc.queryForObject("select count(*) from peer_mesh_session where id=?", Integer.class, granted.session().id()));
                return;
            }
            var granted = grant(service, fixture); long id = granted.session().id();
            assertTrue(cache(service, "sessionTokenCache").containsKey(id));
            var header = new PeerDataFrameHeader(id, 7L);
            if (selected == Case.RELAY_COMMIT || selected == Case.RELAY_ROLLBACK) {
                tx.executeWithoutResult(status -> {
                    assertTrue(service.authorizeRelayFrameForRelay(header, fixture.source().getId(), fixture.target().getId(), 512));
                    assertFalse(cache(service, "relayAuthorizationCache").containsKey(id), "uncommitted activation must not enter shared relay cache");
                    assertFalse(cache(service, "pendingRelayBytes").containsKey(id), "rolled-back activation must not publish accounting");
                    if (selected == Case.RELAY_ROLLBACK) status.setRollbackOnly();
                });
                assertEquals(selected == Case.RELAY_COMMIT, cache(service, "relayAuthorizationCache").containsKey(id));
                assertEquals(selected == Case.RELAY_COMMIT ? "ACTIVE" : "NEGOTIATING", status(jdbc, id));
                return;
            }
            assertTrue(service.authorizeRelayFrameForRelay(header, fixture.source().getId(), fixture.target().getId(), 512));
            Object authorization = cache(service, "relayAuthorizationCache").get(id);
            assertNotNull(authorization);
            var unrelated = fixture(context, 6_200_000 + selected.ordinal() * 10);
            var other = grant(service, unrelated);
            assertTrue(service.validateRelayFrameForRelay(new PeerDataFrameHeader(other.session().id(), 8L), unrelated.source().getId(), unrelated.target().getId()));
            Object otherAuthorization = cache(service, "relayAuthorizationCache").get(other.session().id());
            boolean rollback = selected == Case.CLOSE_ROLLBACK || selected == Case.PATH_ROLLBACK;
            tx.executeWithoutResult(status -> {
                PeerControlMessage report = new PeerControlMessage(); report.setSessionId(id);
                if (selected == Case.PATH_COMMIT || selected == Case.PATH_ROLLBACK) service.reportPath(fixture.source(), report);
                else service.closeSession(fixture.source(), report);
                assertSame(authorization, cache(service, "relayAuthorizationCache").get(id), "invalidation must wait for commit");
                assertTrue(cache(service, "sessionTokenCache").containsKey(id));
                if (rollback) status.setRollbackOnly();
            });
            assertSame(otherAuthorization, cache(service, "relayAuthorizationCache").get(other.session().id()), "unrelated session stays warm");
            assertEquals(rollback, cache(service, "relayAuthorizationCache").containsKey(id));
            if (selected == Case.CLOSE_COMMIT || selected == Case.CLOSE_ROLLBACK || selected == Case.RETAIN_ACCEPTED_TRAFFIC) {
                assertEquals(rollback ? "ACTIVE" : "CLOSED", status(jdbc, id));
                assertEquals(rollback, cache(service, "sessionTokenCache").containsKey(id));
            }
            if (selected == Case.RETAIN_ACCEPTED_TRAFFIC) {
                assertEquals(512, ((AtomicLong) cache(service, "pendingRelayBytes").get(id)).get(), "closing must not discard accepted traffic");
                service.flushRelayTraffic();
                assertEquals(512, jdbc.queryForObject("select relay_bytes from peer_mesh_session where id=?", Long.class, id));
            }
        });
        assertAll("Peer cache effects follow actual commit/rollback", cases);
        assertAll("late committed callbacks must not resurrect revoked sessions",
                () -> verifyLatePublication(context, independent, false),
                () -> verifyLatePublication(context, independent, true),
                () -> verifySuspendedToken(context, independent));
        assertFalse(service.validateRelayFrameForRelay(new PeerDataFrameHeader(6_999_999L, 1L), 1, 2));
        assertFalse(cache(service, "sessionCacheFences").containsKey(6_999_999L), "invalid IDs must not leak publication fences");
    }

    private static void verifyLatePublication(ConfigurableApplicationContext context, DataSource independent, boolean relay) throws Exception {
        boolean sqlite;
        try (var connection = independent.getConnection()) { sqlite = connection.getMetaData().getDatabaseProductName().contains("SQLite"); }
        // The callback runs after the real DB commit has released its writer, including SQLite pool1.
        // Release the transaction's connection before starting the independent writer on pool1.
        if (sqlite) return;
        var service = context.getBean(PeerMeshService.class);
        var fixture = fixture(context, relay ? 6_400_000 : 6_300_000);
        var existing = relay ? grant(service, fixture) : null;
        var tx = new TransactionTemplate(context.getBean(PlatformTransactionManager.class));
        CountDownLatch committed = new CountDownLatch(1), publish = new CountDownLatch(1);
        AtomicReference<PeerMeshService.PeerSessionGrant> granted = new AtomicReference<>();
        try (var executor = Executors.newSingleThreadExecutor()) {
            var future = executor.submit(() -> tx.execute(status -> {
                TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                    @Override public void afterCommit() {
                        committed.countDown();
                        try { assertTrue(publish.await(15, TimeUnit.SECONDS)); }
                        catch (InterruptedException failure) { Thread.currentThread().interrupt(); throw new AssertionError(failure); }
                    }
                });
                if (relay) {
                    granted.set(existing);
                    assertTrue(service.authorizeRelayFrameForRelay(new PeerDataFrameHeader(existing.session().id(), 7L),
                            fixture.source().getId(), fixture.target().getId(), 512));
                } else granted.set(grant(service, fixture));
                return granted.get();
            }));
            try {
                assertTrue(committed.await(15, TimeUnit.SECONDS), "actual create commit must precede delayed cache publication");
                PeerControlMessage close = new PeerControlMessage(); close.setSessionId(granted.get().session().id());
                service.closeSession(fixture.source(), close);
                assertEquals("CLOSED", status(context.getBean(JdbcTemplate.class), close.getSessionId()));
            } finally { publish.countDown(); }
            assertNotNull(future.get(15, TimeUnit.SECONDS));
        }
        long id = granted.get().session().id();
        assertFalse(cache(service, "sessionTokenCache").containsKey(id), "older committed callback must not resurrect a revoked token");
        assertFalse(cache(service, "relayAuthorizationCache").containsKey(id));
        if (relay) {
            assertEquals(512, ((AtomicLong) cache(service, "pendingRelayBytes").get(id)).get(), "late revocation must retain accepted traffic");
            service.flushRelayTraffic();
            assertEquals(512, context.getBean(JdbcTemplate.class).queryForObject("select relay_bytes from peer_mesh_session where id=?", Long.class, id));
            assertFalse(cache(service, "pendingRelayBytes").containsKey(id), "drained closed counters must be released");
        }
    }

    private static Fixture fixture(ConfigurableApplicationContext context, long base) {
        var jdbc = context.getBean(JdbcTemplate.class); String now = Instant.now().toString();
        for (long id : List.of(base + 1, base + 2)) {
            jdbc.update("insert into specus_client_account(id,tenant_id,owner_username,client_name,password_hash,enabled,connection_rate_limit_per_minute,created_at,updated_at) values (?,'default','peer-cache-owner',?,'fixture-only',true,30,?,?)", id, "peer-cache-" + id, now, now);
            jdbc.update("insert into peer_mesh_device(id,tenant_id,owner_username,client_id,client_name,virtual_ip,cidr,enabled,created_at,updated_at) values (?,'default','peer-cache-owner',?,?,?,'100.111.0.0/16',true,?,?)", id, id, "peer-cache-" + id, "100.111." + (base / 100_000) + "." + (base % 1000 + id - base), now, now);
        }
        var repository = context.getBean(ClientAccountRepository.class);
        return new Fixture(repository.findById(base + 1).orElseThrow(), repository.findById(base + 2).orElseThrow());
    }
    private static void verifySuspendedToken(ConfigurableApplicationContext context, DataSource independent) throws Exception {
        try (var connection = independent.getConnection()) {
            if (connection.getMetaData().getDatabaseProductName().contains("SQLite")) return; // genuine pool1 has no second writer connection
        }
        var service = context.getBean(PeerMeshService.class); var fixture = fixture(context, 6_500_000);
        var manager = context.getBean(PlatformTransactionManager.class);
        var inner = new TransactionTemplate(manager);
        inner.setPropagationBehavior(org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        var granted = new TransactionTemplate(manager).execute(status -> {
            var grant = grant(service, fixture);
            assertEquals(grant.token(), ReflectionTestUtils.invokeMethod(service, "pendingOrCachedSessionToken", grant.session().id()));
            inner.executeWithoutResult(innerStatus -> assertNull(
                    ReflectionTestUtils.invokeMethod(service, "pendingOrCachedSessionToken", grant.session().id()),
                    "a suspended outer transaction's token must not escape into REQUIRES_NEW"));
            status.setRollbackOnly(); return grant;
        });
        assertNotNull(granted);
        assertFalse(cache(service, "sessionTokenCache").containsKey(granted.session().id()));
        assertFalse(cache(service, "sessionCacheFences").containsKey(granted.session().id()));
    }
    private static PeerMeshService.PeerSessionGrant grant(PeerMeshService service, Fixture fixture) {
        return service.createSession(fixture.source(), fixture.target(), PeerMeshService.PATH_DIRECT);
    }
    private static String status(JdbcTemplate jdbc, long id) { return jdbc.queryForObject("select status from peer_mesh_session where id=?", String.class, id); }
    private static Map<?, ?> cache(PeerMeshService service, String field) { return (Map<?, ?>) ReflectionTestUtils.getField(service, field); }
}
