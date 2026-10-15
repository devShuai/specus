package com.theshuai.specusserver.database;

import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerDataFrameHeader;
import com.theshuai.common.peermesh.PeerUdpProbe;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.PeerMeshSessionRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.service.PeerMeshService;
import com.theshuai.specusserver.management.tenant.TenantContext;
import org.junit.jupiter.api.function.Executable;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import javax.sql.DataSource;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.sql.SQLException;
import org.aopalliance.intercept.MethodInterceptor;
import org.springframework.aop.framework.Advised;
import static org.junit.jupiter.api.Assertions.*;

/** Current session writes after genuine earlier JPA/L1 and provider snapshots. SQL mutations
 * are concurrency fixtures, not ownership-transfer POST acceptance. */
public final class PeerSessionCurrentAssertions {
    enum Case { PATH_CLOSED, PATH_EXPIRED, PATH_COUNTERS, PATH_METADATA, TRAFFIC_COUNTERS, TRAFFIC_CLOSED,
        CLOSE_COUNTERS, CLOSE_ALREADY_CLOSED, CLOSE_METADATA, RECORD_COUNTERS, RECORD_CLOSED,
        FLUSH_COUNTERS, FLUSH_CLOSED, FLUSH_ROLLBACK, AUTHORIZE_CLOSED, SLOW_CLOSED, PROBE_CLOSED,
        REUSE_CLOSED, ADMIN_DISABLED, ADMIN_DEMOTED, TENANT_CHANGED, SOURCE_OWNER_MANAGEMENT,
        RUNTIME_OWNER_REVOKED, RUNTIME_EXPLICIT_RETAINED, RUNTIME_SOURCE_DISABLED, RUNTIME_TARGET_DISABLED, PROBE_ACTIVE,
        REVOKE_OWNER, REVOKE_EXPLICIT, REVOKE_DIRECTION, REVOKE_DEVICE, REVOKE_DISABLED_ACTOR }
    private static final String OWNER = "session-current-owner", OTHER = "session-current-other", KEY = "session-current-owner-key";
    public static void verify(ConfigurableApplicationContext context, DataSource independent) throws Exception {
        var jdbc = context.getBean(JdbcTemplate.class); var other = new JdbcTemplate(independent);
        boolean sqlite;
        try (var connection = independent.getConnection()) { sqlite = connection.getMetaData().getDatabaseProductName().contains("SQLite"); }
        var mutation = sqlite ? jdbc : other;
        var service = context.getBean(PeerMeshService.class); var accounts = context.getBean(ClientAccountRepository.class);
        var sessions = context.getBean(PeerMeshSessionRepository.class);
        var tx = new TransactionTemplate(context.getBean(PlatformTransactionManager.class));
        var cases = new ArrayList<Executable>();
        for (Case selected : Case.values()) cases.add(() -> {
            long base = 6_700_000 + selected.ordinal() * 10, source = base + 1, target = base + 2;
            String now = Instant.now().toString();
            boolean admin = selected == Case.ADMIN_DISABLED || selected == Case.ADMIN_DEMOTED || selected == Case.TENANT_CHANGED;
            jdbc.update("delete from specus_management_user where username=?", KEY);
            jdbc.update("insert into specus_management_user(username,tenant_id,login_name,login_name_normalized,password_hash,role,enabled,created_at,updated_at) values (?,'default',?,?,'fixture-only',?,true,?,?)", KEY, OWNER, OWNER, admin ? "ADMIN" : "USER", now, now);
            for (long id : List.of(source, target)) {
                String owner = selected == Case.ADMIN_DEMOTED ? OTHER : OWNER;
                jdbc.update("insert into specus_client_account(id,tenant_id,owner_username,client_name,password_hash,enabled,connection_rate_limit_per_minute,created_at,updated_at) values (?,'default',?,?,'fixture-only',true,30,?,?)", id, owner, "session-current-" + id, now, now);
                jdbc.update("insert into peer_mesh_device(id,tenant_id,owner_username,client_id,client_name,virtual_ip,cidr,enabled,created_at,updated_at) values (?,'default',?,?,?,?,'100.112.0.0/16',true,?,?)", id, owner, id, "session-current-" + id, "100.112.67." + (selected.ordinal() * 2 + id - base), now, now);
            }
            var actor = new ManagementContext(TenantContext.defaultTenant(), OWNER, admin, KEY);
            var a = accounts.findById(source).orElseThrow(); var b = accounts.findById(target).orElseThrow();
            var granted = service.createSession(a, b, PeerMeshService.PATH_DIRECT); long id = granted.session().id();
            jdbc.update("update peer_mesh_session set status='ACTIVE' where id=?", id);
            if (selected == Case.REVOKE_DIRECTION) {
                jdbc.update("update specus_client_account set owner_username=? where id=?", OTHER, source);
                jdbc.update("insert into peer_mesh_acl(id,tenant_id,owner_username,source_client_id,source_client_name,target_client_id,target_client_name,allowed,direction,created_at,updated_at) values (?,'default',?,?,?,?,?,true,'OUTBOUND',?,?)", base + 5, OWNER, source, a.getClientName(), target, b.getClientName(), now, now);
            }
            if (selected.name().startsWith("FLUSH") || selected == Case.PATH_CLOSED || selected == Case.TRAFFIC_CLOSED
                    || selected == Case.AUTHORIZE_CLOSED || selected == Case.PROBE_CLOSED)
                assertTrue(service.authorizeRelayFrameForRelay(new PeerDataFrameHeader(id, 1), source, target, 512));
            tx.executeWithoutResult(status -> {
                sessions.findById(id).orElseThrow(); accounts.findById(source).orElseThrow(); accounts.findById(target).orElseThrow();
                switch (selected) {
                    case PATH_CLOSED, TRAFFIC_CLOSED, CLOSE_ALREADY_CLOSED, RECORD_CLOSED, FLUSH_CLOSED, AUTHORIZE_CLOSED, SLOW_CLOSED, PROBE_CLOSED, REUSE_CLOSED -> mutation.update("update peer_mesh_session set status='CLOSED',closed_at='2026-01-01T00:00:00Z' where id=?", id);
                    case PATH_EXPIRED -> mutation.update("update peer_mesh_session set expires_at='2020-01-01T00:00:00Z' where id=?", id);
                    case PATH_COUNTERS, TRAFFIC_COUNTERS, CLOSE_COUNTERS, RECORD_COUNTERS, FLUSH_COUNTERS -> mutation.update("update peer_mesh_session set direct_bytes=1000,relay_bytes=2000 where id=?", id);
                    case PATH_METADATA, CLOSE_METADATA -> mutation.update("update peer_mesh_session set source_client_name='current-session-source',token_hash='current-hash',expires_at='2099-01-01T00:00:00Z' where id=?", id);
                    case ADMIN_DISABLED -> mutation.update("update specus_management_user set enabled=false where username=?", KEY);
                    case ADMIN_DEMOTED -> mutation.update("update specus_management_user set role='USER' where username=?", KEY);
                    case TENANT_CHANGED -> mutation.update("update peer_mesh_session set tenant_id='DEFAULT' where id=?", id);
                    case SOURCE_OWNER_MANAGEMENT -> mutation.update("update specus_client_account set owner_username=? where id in (?,?)", OTHER, source, target);
                    case RUNTIME_OWNER_REVOKED, RUNTIME_EXPLICIT_RETAINED, REVOKE_OWNER, REVOKE_EXPLICIT -> {
                        mutation.update("update specus_client_account set owner_username=? where id=?", OTHER, source);
                        if (selected == Case.RUNTIME_EXPLICIT_RETAINED || selected == Case.REVOKE_EXPLICIT) mutation.update("insert into peer_mesh_acl(id,tenant_id,owner_username,source_client_id,source_client_name,target_client_id,target_client_name,allowed,direction,created_at,updated_at) values (?,'default',?,?,?,?,?,true,'OUTBOUND',?,?)", base + 5, OWNER, source, a.getClientName(), target, b.getClientName(), now, now);
                    }
                    case RUNTIME_SOURCE_DISABLED -> mutation.update("update specus_client_account set enabled=false where id=?", source);
                    case RUNTIME_TARGET_DISABLED -> mutation.update("update specus_client_account set enabled=false where id=?", target);
                    case REVOKE_DEVICE -> mutation.update("update peer_mesh_device set enabled=false where client_id=?", source);
                    case REVOKE_DIRECTION -> mutation.update("update peer_mesh_acl set direction='INBOUND' where id=?", base + 5);
                    case REVOKE_DISABLED_ACTOR -> {
                        mutation.update("update specus_management_user set enabled=false where username=?", KEY);
                        mutation.update("update specus_client_account set owner_username=? where id=?", OTHER, source);
                    }
                    case FLUSH_ROLLBACK, PROBE_ACTIVE -> {}
                }
                PeerControlMessage report = new PeerControlMessage(); report.setSessionId(id); report.setStatus("ACTIVE"); report.setPathType("DIRECT"); report.setDirectBytes(7); report.setRelayBytes(11);
                switch (selected) {
                    case TRAFFIC_COUNTERS, TRAFFIC_CLOSED -> service.reportTraffic(a, report);
                    case CLOSE_COUNTERS, CLOSE_ALREADY_CLOSED, CLOSE_METADATA -> service.closeSession(a, report);
                    case RECORD_COUNTERS, RECORD_CLOSED -> service.recordRelayTraffic(id, 11);
                    case FLUSH_COUNTERS, FLUSH_CLOSED, FLUSH_ROLLBACK -> { service.flushRelayTraffic(); if (selected == Case.FLUSH_ROLLBACK) status.setRollbackOnly(); }
                    case AUTHORIZE_CLOSED -> assertFalse(service.authorizeRelayFrame(new PeerDataFrameHeader(id, 1), source, target, 11));
                    case SLOW_CLOSED -> assertFalse(service.validateRelayFrameForRelay(new PeerDataFrameHeader(id, 1), source, target));
                    case PROBE_CLOSED, PROBE_ACTIVE -> {
                        var probe = new PeerUdpProbe(); probe.setSessionId(id); probe.setFromClientId(source); probe.setToClientId(target); probe.setToken(granted.token()); probe.setType(PeerUdpProbe.TYPE_CHECK);
                        assertEquals(selected == Case.PROBE_ACTIVE, service.authorizeRelayProbeForRelay(probe));
                    }
                    case REUSE_CLOSED -> assertNotEquals(id, service.createSession(a, b, PeerMeshService.PATH_DIRECT).session().id(), "closed current row cannot be reused through an older snapshot");
                    case ADMIN_DISABLED, ADMIN_DEMOTED, TENANT_CHANGED, SOURCE_OWNER_MANAGEMENT -> {
                        assertThrows(RuntimeException.class, () -> service.closeSession(actor, id)); status.setRollbackOnly();
                    }
                    case RUNTIME_SOURCE_DISABLED -> { assertThrows(RuntimeException.class, () -> service.reportPath(a, report)); status.setRollbackOnly(); }
                    case REVOKE_OWNER, REVOKE_EXPLICIT, REVOKE_DIRECTION, REVOKE_DEVICE, REVOKE_DISABLED_ACTOR -> {
                        var closed = service.closeUnauthorizedSessions(actor);
                        assertEquals(selected != Case.REVOKE_EXPLICIT, closed.stream().anyMatch(row -> row.id() == id));
                    }
                    default -> service.reportPath(a, report);
                }
            });
            Map<String,Object> current = jdbc.queryForMap("select status,closed_at,source_client_name,token_hash,expires_at,direct_bytes,relay_bytes from peer_mesh_session where id=?", id);
            switch (selected) {
                case PATH_CLOSED, TRAFFIC_CLOSED, CLOSE_ALREADY_CLOSED, RECORD_CLOSED, FLUSH_CLOSED, AUTHORIZE_CLOSED, SLOW_CLOSED, PROBE_CLOSED, REUSE_CLOSED -> {
                    assertEquals("CLOSED", current.get("status"), selected.toString()); assertEquals("2026-01-01T00:00:00Z", current.get("closed_at"));
                }
                case PATH_EXPIRED, RUNTIME_OWNER_REVOKED, RUNTIME_TARGET_DISABLED, REVOKE_OWNER, REVOKE_DIRECTION, REVOKE_DEVICE, REVOKE_DISABLED_ACTOR -> assertEquals("CLOSED", current.get("status"), selected.toString());
                case ADMIN_DISABLED, ADMIN_DEMOTED, TENANT_CHANGED, SOURCE_OWNER_MANAGEMENT, RUNTIME_SOURCE_DISABLED, RUNTIME_EXPLICIT_RETAINED, REVOKE_EXPLICIT -> assertEquals("ACTIVE", current.get("status"));
                default -> {}
            }
            switch (selected) {
                case PATH_COUNTERS, CLOSE_COUNTERS -> { assertEquals(1000, ((Number) current.get("direct_bytes")).longValue()); assertEquals(2000, ((Number) current.get("relay_bytes")).longValue()); }
                case TRAFFIC_COUNTERS -> { assertEquals(1007, ((Number) current.get("direct_bytes")).longValue()); assertEquals(2011, ((Number) current.get("relay_bytes")).longValue()); }
                case RECORD_COUNTERS -> assertEquals(2011, ((Number) current.get("relay_bytes")).longValue());
                case FLUSH_COUNTERS -> assertEquals(2512, ((Number) current.get("relay_bytes")).longValue());
                case FLUSH_CLOSED -> {
                    assertEquals(512, ((Number) current.get("relay_bytes")).longValue());
                    assertFalse(service.validateRelayFrameForRelay(new PeerDataFrameHeader(id, 1), source, target), "committed flush of CLOSED row must evict a warm relay cache");
                    assertFalse(((Map<?,?>) ReflectionTestUtils.getField(service, "sessionTokenCache")).containsKey(id));
                }
                case FLUSH_ROLLBACK -> {
                    assertEquals(0, ((Number) current.get("relay_bytes")).longValue());
                    var pending = (Map<?,?>) ReflectionTestUtils.getField(service, "pendingRelayBytes");
                    assertEquals(512, ((AtomicLong) pending.get(id)).get(), "outer rollback must restore accepted bytes exactly once");
                }
                case PATH_METADATA, CLOSE_METADATA -> { assertEquals("current-session-source", current.get("source_client_name")); assertEquals("current-hash", current.get("token_hash")); assertEquals("2099-01-01T00:00:00Z", current.get("expires_at")); }
                default -> {}
            }
            if (selected == Case.PATH_CLOSED || selected == Case.TRAFFIC_CLOSED || selected == Case.AUTHORIZE_CLOSED || selected == Case.PROBE_CLOSED) {
                assertFalse(((Map<?,?>) ReflectionTestUtils.getField(service, "sessionTokenCache")).containsKey(id), "observing a current CLOSED row must evict its warm token after commit");
                assertFalse(service.validateRelayFrameForRelay(new PeerDataFrameHeader(id, 1), source, target));
            }
        });
        assertAll("current Peer session writes and authority", cases);
        verifyConcurrentTraffic(context, independent, sqlite);
    }

    private static void verifyConcurrentTraffic(ConfigurableApplicationContext context, DataSource independent, boolean sqlite) throws Exception {
        if (sqlite) return; // Genuine SQLite pool1 transaction matrix above, no concurrent-row claim.
        var jdbc = context.getBean(JdbcTemplate.class); var accounts = context.getBean(ClientAccountRepository.class);
        var service = context.getBean(PeerMeshService.class); String now = Instant.now().toString();
        for (long id : List.of(6_800_001L,6_800_002L,6_800_003L,6_800_004L)) {
            jdbc.update("insert into specus_client_account(id,tenant_id,owner_username,client_name,password_hash,enabled,connection_rate_limit_per_minute,created_at,updated_at) values (?,'default',?,?,'fixture-only',true,30,?,?)", id, OWNER, "session-concurrent-" + id, now, now);
            jdbc.update("insert into peer_mesh_device(id,tenant_id,owner_username,client_id,client_name,virtual_ip,cidr,enabled,created_at,updated_at) values (?,'default',?,?,?,?,'100.112.0.0/16',true,?,?)", id, OWNER, id, "session-concurrent-" + id, "100.112.68." + (id - 6_800_000), now, now);
        }
        var a = accounts.findById(6_800_001L).orElseThrow(); var b = accounts.findById(6_800_002L).orElseThrow();
        long id = service.createSession(a,b,PeerMeshService.PATH_DIRECT).session().id();
        long unrelated = service.createSession(accounts.findById(6_800_003L).orElseThrow(),accounts.findById(6_800_004L).orElseThrow(),PeerMeshService.PATH_DIRECT).session().id();
        CountDownLatch held = new CountDownLatch(1), competing = new CountDownLatch(1), resume = new CountDownLatch(1);
        AtomicReference<Thread> first = new AtomicReference<>(), second = new AtomicReference<>(); AtomicBoolean observed = new AtomicBoolean();
        Advised rows = assertInstanceOf(Advised.class, context.getBean(PeerMeshSessionRepository.class));
        Advised parents = assertInstanceOf(Advised.class, accounts);
        MethodInterceptor rowObserver = invocation -> {
            Object result = invocation.proceed();
            if (Thread.currentThread() == first.get() && invocation.getMethod().getName().equals("lockCurrent")
                    && ((Number) invocation.getArguments()[0]).longValue() == id && observed.compareAndSet(false,true)) {
                held.countDown(); assertTrue(resume.await(15,TimeUnit.SECONDS));
            }
            return result;
        };
        MethodInterceptor parentObserver = invocation -> {
            if (Thread.currentThread() == second.get() && invocation.getMethod().getName().equals("lockCurrentAll")) competing.countDown();
            return invocation.proceed();
        };
        rows.addAdvice(0,rowObserver); parents.addAdvice(0,parentObserver);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var report = new PeerControlMessage(); report.setSessionId(id); report.setDirectBytes(7); report.setRelayBytes(11);
            var one = executor.submit(() -> { first.set(Thread.currentThread()); return service.reportTraffic(a,report); });
            try {
                assertTrue(held.await(15,TimeUnit.SECONDS));
                var two = executor.submit(() -> { second.set(Thread.currentThread()); return service.reportTraffic(b,report); });
                assertTrue(competing.await(15,TimeUnit.SECONDS));
                try (var connection = independent.getConnection(); var sql = connection.createStatement()) {
                    boolean mysql = !connection.getMetaData().getDatabaseProductName().contains("PostgreSQL");
                    sql.execute(mysql ? "set innodb_lock_wait_timeout=1" : "set lock_timeout='200ms'");
                    SQLException blocked = assertThrows(SQLException.class, () -> sql.executeUpdate("update peer_mesh_session set direct_bytes=99 where id=" + id));
                    if (mysql) assertEquals(1205,blocked.getErrorCode()); else assertEquals("55P03",blocked.getSQLState());
                    assertEquals(1,sql.executeUpdate("update peer_mesh_session set direct_bytes=100 where id=" + unrelated), "unrelated session must remain writable");
                }
                resume.countDown(); assertNotNull(one.get(15,TimeUnit.SECONDS)); assertNotNull(two.get(15,TimeUnit.SECONDS));
            } finally { resume.countDown(); }
        } finally { resume.countDown(); rows.removeAdvice(rowObserver); parents.removeAdvice(parentObserver); }
        assertEquals(14,jdbc.queryForObject("select direct_bytes from peer_mesh_session where id=?",Long.class,id));
        assertEquals(22,jdbc.queryForObject("select relay_bytes from peer_mesh_session where id=?",Long.class,id));
        assertEquals(100,jdbc.queryForObject("select direct_bytes from peer_mesh_session where id=?",Long.class,unrelated));
    }
}
