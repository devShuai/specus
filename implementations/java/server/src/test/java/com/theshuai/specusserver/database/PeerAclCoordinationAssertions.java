package com.theshuai.specusserver.database;

import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.ClientCredentialRepository;
import com.theshuai.specusserver.management.repository.PeerMeshAclRepository;
import com.theshuai.specusserver.management.repository.PeerMeshDeviceRepository;
import com.theshuai.specusserver.management.model.PeerMeshAcl;
import com.theshuai.specusserver.management.security.ManagementWriteAuthority;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.management.service.PeerMeshService;
import com.theshuai.specusserver.security.PasswordService;
import org.junit.jupiter.api.function.Executable;
import org.aopalliance.intercept.MethodInterceptor;
import org.springframework.aop.framework.Advised;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import javax.sql.DataSource;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.LinkedHashSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.sql.SQLException;
import static org.junit.jupiter.api.Assertions.*;

/** Current actor/client/ACL/device state after real older JPA reads. SQL is fixture mutation,
 * not transfer-POST acceptance. SQLite serializes its writer; other providers commit independently. */
public final class PeerAclCoordinationAssertions {
    enum Case { DISABLED_CREATE, DISABLED_DELETE, DELETED_CREATE, DELETED_DELETE,
        DEMOTED_CREATE, DEMOTED_DELETE, PROMOTED_CREATE, PROMOTED_DELETE,
        SOURCE_OWNER_CREATE, TARGET_OWNER_CREATE, SOURCE_RENAME_CREATE, TARGET_RENAME_CREATE,
        CURRENT_DIRECTION, ACL_OWNER_DELETE, ACL_TENANT_DELETE, POLICY_OWNER_DELETE,
        SESSION_SOURCE_OWNER, SESSION_TARGET_OWNER, SESSION_DISABLED_SOURCE, SESSION_DISABLED_TARGET,
        SESSION_DELETED_SOURCE, SESSION_DELETED_TARGET, SESSION_TENANT_SOURCE, SESSION_TENANT_TARGET,
        SESSION_EXPLICIT, SESSION_NAME, SESSION_DEVICE_DISABLED, SESSION_ACL_REVOKED, SESSION_DIRECTION,
        CREATE_NEW, CREATE_NEW_DIRECTION, SESSION_REVERSE_INBOUND, SESSION_REVERSE_OUTBOUND,
        SESSION_BOTH, SESSION_REUSE_REVOKED, SESSION_TARGET_NAME }
    private static final String ALICE = "peer-acl-alice", KEY = "peer-acl-alice-key", BOB = "peer-acl-bob";

    public static void verify(ConfigurableApplicationContext context, DataSource independent) throws Exception {
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class), other = new JdbcTemplate(independent);
        boolean sqlite;
        try (var connection = independent.getConnection()) { sqlite = connection.getMetaData().getDatabaseProductName().toLowerCase(java.util.Locale.ROOT).contains("sqlite"); }
        JdbcTemplate mutation = sqlite ? jdbc : other;
        var service = context.getBean(PeerMeshService.class);
        var accounts = context.getBean(ClientAccountRepository.class);
        var devices = context.getBean(PeerMeshDeviceRepository.class);
        var acls = context.getBean(PeerMeshAclRepository.class);
        ArrayList<Executable> cases = new ArrayList<>();
        for (Case selected : Case.values()) cases.add(() -> {
            long base = 5_100_000L + selected.ordinal() * 40, source = base + 1, target = base + 2, acl = base + 5;
            String now = Instant.now().toString();
            jdbc.update("delete from specus_management_user where username=?", KEY);
            boolean demoted = selected.name().startsWith("DEMOTED");
            jdbc.update("insert into specus_management_user(username,tenant_id,login_name,login_name_normalized,password_hash,role,enabled,created_at,updated_at) values (?,'default',?,?,?, ?,true,?,?)",
                    KEY, ALICE, ALICE, PasswordService.hashToken("fixture-only-password"), demoted ? "ADMIN" : "USER", now, now);
            ManagementContext actor = new ManagementContext(TenantContext.defaultTenant(), ALICE, demoted, KEY);
            for (long id : new long[]{source, target}) {
                jdbc.update("insert into specus_client_account(id,tenant_id,owner_username,client_name,password_hash,enabled,connection_rate_limit_per_minute,created_at,updated_at) values (?,'default',?,?,?,true,30,?,?)",
                        id, ALICE, "peer-acl-client-" + id, PasswordService.hashToken("client-fixture"), now, now);
                long credential = base + 20 + (id == source ? 0 : 1);
                jdbc.update("insert into specus_client_credential(id,tenant_id,owner_username,api_key,secret_hash,enabled,max_online_instances,created_at,updated_at) values (?,'default',?,?,?,true,3,?,?)",
                        credential, ALICE, "peer-acl-key-" + credential, PasswordService.hashToken("credential-fixture"), now, now);
                jdbc.update("insert into specus_client_identity(id,tenant_id,credential_id,client_id,client_name,machine_fingerprint,os_user,first_seen_at,last_seen_at) values (?,'default',?,?,?,?, 'fixture-user',?,?)",
                        base + 24 + (id == source ? 0 : 1), credential, id, "peer-acl-client-" + id, "peer-acl-machine-" + id, now, now);
                jdbc.update("insert into peer_mesh_device(id,tenant_id,owner_username,client_id,client_name,virtual_ip,cidr,enabled,created_at,updated_at) values (?,'default',?,?,? ,?,'100.110.0.0/16',true,?,?)",
                        base + 10 + (id == source ? 0 : 1), ALICE, id, "peer-acl-client-" + id,
                        "100.110." + (40 + selected.ordinal()) + "." + (id == source ? 1 : 2), now, now);
            }
            jdbc.update("insert into peer_mesh_acl(id,tenant_id,owner_username,source_client_id,source_client_name,target_client_id,target_client_name,allowed,direction,created_at,updated_at) values (?,'default',?,?,?,?,?,false,'OUTBOUND',?,?)",
                    acl, ALICE, source, "peer-acl-client-" + source, target, "peer-acl-client-" + target, now, now);
            if (selected == Case.DEMOTED_DELETE || selected == Case.PROMOTED_DELETE)
                jdbc.update("update peer_mesh_acl set owner_username=? where id=?", BOB, acl);
            if (selected == Case.DEMOTED_CREATE || selected == Case.PROMOTED_CREATE)
                jdbc.update("update specus_client_account set owner_username=? where id=?", BOB, target);
            if (selected == Case.SESSION_ACL_REVOKED || selected == Case.SESSION_DIRECTION || selected == Case.SESSION_REUSE_REVOKED
                    || selected == Case.SESSION_REVERSE_INBOUND || selected == Case.SESSION_REVERSE_OUTBOUND || selected == Case.SESSION_BOTH) {
                jdbc.update("update specus_client_account set owner_username=? where id=?", BOB, source);
                jdbc.update("update peer_mesh_acl set allowed=true where id=?", acl);
            }
            if (selected == Case.SESSION_EXPLICIT) jdbc.update("update peer_mesh_acl set allowed=true where id=?", acl);
            boolean freshAcl = selected == Case.CREATE_NEW || selected == Case.CREATE_NEW_DIRECTION;
            if (freshAcl) jdbc.update("delete from peer_mesh_acl where id=?", acl);
            if (selected == Case.SESSION_REVERSE_INBOUND || selected == Case.SESSION_REVERSE_OUTBOUND)
                jdbc.update("update peer_mesh_acl set source_client_id=?,source_client_name=?,target_client_id=?,target_client_name=?,direction=? where id=?",
                        target, "peer-acl-client-" + target, source, "peer-acl-client-" + source,
                        selected == Case.SESSION_REVERSE_INBOUND ? "INBOUND" : "OUTBOUND", acl);
            if (selected == Case.SESSION_BOTH) jdbc.update("update peer_mesh_acl set direction='BOTH' where id=?", acl);
            if (selected == Case.SESSION_REUSE_REVOKED) assertNotNull(service.createSession(accounts.findById(source).orElseThrow(),
                    accounts.findById(target).orElseThrow(), PeerMeshService.PATH_DIRECT).token());
            new TransactionTemplate(context.getBean(PlatformTransactionManager.class)).executeWithoutResult(status -> {
                var oldSource = accounts.findById(source).orElseThrow(); var oldTarget = accounts.findById(target).orElseThrow();
                assertTrue(devices.findByTenantIdAndClientId("default", source).orElseThrow().isEnabled());
                if (!freshAcl) acls.findById(acl).orElseThrow(); // real earlier L1 and MySQL RR state
                boolean deny = true;
                switch (selected) {
                    case DISABLED_CREATE, DISABLED_DELETE -> mutation.update("update specus_management_user set enabled=false where username=?", KEY);
                    case DELETED_CREATE, DELETED_DELETE -> mutation.update("delete from specus_management_user where username=?", KEY);
                    case DEMOTED_CREATE, DEMOTED_DELETE -> mutation.update("update specus_management_user set role='USER' where username=?", KEY);
                    case PROMOTED_CREATE, PROMOTED_DELETE -> { mutation.update("update specus_management_user set role='ADMIN' where username=?", KEY); deny = false; }
                    case SOURCE_OWNER_CREATE, SESSION_SOURCE_OWNER, SESSION_EXPLICIT -> { mutation.update("update specus_client_account set owner_username=? where id=?", BOB, source); deny = selected != Case.SESSION_EXPLICIT; }
                    case TARGET_OWNER_CREATE, SESSION_TARGET_OWNER -> mutation.update("update specus_client_account set owner_username=? where id=?", BOB, target);
                    case SOURCE_RENAME_CREATE, SESSION_NAME -> { mutation.update("update specus_client_account set client_name=? where id=?", "current-source-" + base, source); deny = false; }
                    case TARGET_RENAME_CREATE -> { mutation.update("update specus_client_account set client_name=? where id=?", "current-target-" + base, target); deny = false; }
                    case CURRENT_DIRECTION -> { mutation.update("update peer_mesh_acl set direction='INBOUND' where id=?", acl); deny = false; }
                    case ACL_OWNER_DELETE -> mutation.update("update peer_mesh_acl set owner_username=? where id=?", BOB, acl);
                    case ACL_TENANT_DELETE -> mutation.update("update peer_mesh_acl set tenant_id='DEFAULT' where id=?", acl);
                    case POLICY_OWNER_DELETE -> { mutation.update("update specus_client_account set owner_username=? where id=?", BOB, source); deny = false; }
                    case SESSION_DISABLED_SOURCE -> mutation.update("update specus_client_account set enabled=false where id=?", source);
                    case SESSION_DISABLED_TARGET -> mutation.update("update specus_client_account set enabled=false where id=?", target);
                    case SESSION_DELETED_SOURCE -> mutation.update("delete from specus_client_account where id=?", source);
                    case SESSION_DELETED_TARGET -> mutation.update("delete from specus_client_account where id=?", target);
                    case SESSION_TENANT_SOURCE -> mutation.update("update specus_client_account set tenant_id='DEFAULT' where id=?", source);
                    case SESSION_TENANT_TARGET -> mutation.update("update specus_client_account set tenant_id='DEFAULT' where id=?", target);
                    case SESSION_DEVICE_DISABLED -> mutation.update("update peer_mesh_device set enabled=false where client_id=?", source);
                    case SESSION_ACL_REVOKED -> mutation.update("update peer_mesh_acl set allowed=false where id=?", acl);
                    case SESSION_DIRECTION -> mutation.update("update peer_mesh_acl set direction='INBOUND' where id=?", acl);
                    case CREATE_NEW, CREATE_NEW_DIRECTION, SESSION_REVERSE_INBOUND, SESSION_BOTH -> deny = false;
                    case SESSION_REVERSE_OUTBOUND -> {}
                    case SESSION_REUSE_REVOKED -> mutation.update("update peer_mesh_acl set allowed=false where id=?", acl);
                    case SESSION_TARGET_NAME -> { mutation.update("update specus_client_account set client_name=? where id=?", "current-target-" + base, target); deny = false; }
                }
                Runnable operation;
                if (selected.name().startsWith("SESSION")) operation = () -> {
                    var granted = service.createSession(oldSource, oldTarget, PeerMeshService.PATH_DIRECT);
                    if (selected == Case.SESSION_NAME) assertEquals("current-source-" + base, granted.session().sourceClientName());
                    if (selected == Case.SESSION_TARGET_NAME) assertEquals("current-target-" + base, granted.session().targetClientName());
                };
                else if (selected.name().endsWith("DELETE")) operation = () -> service.deleteAcl(actor, acl);
                else operation = () -> {
                    var updated = service.createAcl(actor, new PeerMeshService.AclMutation(source, target, true,
                            selected == Case.CREATE_NEW_DIRECTION ? "inbound" : null));
                    if (!freshAcl) assertEquals(acl, updated.id());
                    else {
                        assertEquals(selected == Case.CREATE_NEW_DIRECTION ? "INBOUND" : "OUTBOUND", updated.direction());
                        assertEquals(updated.id(), service.createAcl(actor, new PeerMeshService.AclMutation(source, target, false, null)).id());
                    }
                    if (selected == Case.CURRENT_DIRECTION) assertEquals("INBOUND", updated.direction());
                    if (selected == Case.SOURCE_RENAME_CREATE) assertEquals("current-source-" + base, updated.sourceClientName());
                    if (selected == Case.TARGET_RENAME_CREATE) assertEquals("current-target-" + base, updated.targetClientName());
                };
                if (deny) {
                    assertThrows(RuntimeException.class, operation::run, selected.toString());
                    assertEquals(selected == Case.SESSION_REUSE_REVOKED ? 1 : 0,
                            jdbc.queryForObject("select count(*) from peer_mesh_session where source_client_id=? and target_client_id=?", Integer.class, source, target));
                    assertEquals(1, jdbc.queryForObject("select count(*) from peer_mesh_acl where id=?", Integer.class, acl));
                    status.setRollbackOnly(); // include the SQLite in-writer fixture mutation in explicit rollback
                } else operation.run();
            });
        });
        assertAll("current Peer ACL writes and new session authorization", cases);
        verifyIdCollision(context);
        verifyOppositeEndpoints(context, independent, sqlite);
    }

    private static void verifyIdCollision(ConfigurableApplicationContext context) {
        long base = 5_100_000L + Case.CREATE_NEW_DIRECTION.ordinal() * 40, source = base + 1, target = base + 2;
        var jdbc = context.getBean(JdbcTemplate.class);
        var before = jdbc.queryForList("select * from peer_mesh_acl where source_client_id=? and target_client_id=?", source, target);
        assertEquals(1, before.size());
        long id = ((Number) before.getFirst().get("id")).longValue();
        var requested = new PeerMeshAcl();
        requested.setId(id); requested.setTenantId("default"); requested.setOwnerUsername(BOB);
        requested.setSourceClientId(target); requested.setSourceClientName("collision-source");
        requested.setTargetClientId(source); requested.setTargetClientName("collision-target");
        requested.setAllowed(true); requested.setDirection("BOTH");
        requested.setCreatedAt(Instant.now().toString()); requested.setUpdatedAt(requested.getCreatedAt());
        var transaction = new TransactionTemplate(context.getBean(PlatformTransactionManager.class));
        assertThrows(RuntimeException.class, () -> transaction.executeWithoutResult(status -> {
            context.getBean(ManagementWriteAuthority.class).current(new ManagementContext(TenantContext.defaultTenant(), ALICE, false, KEY));
            context.getBean(ClientAccountRepository.class).lockCurrentAll(List.of(source, target), "default");
            context.getBean(PeerMeshAclRepository.class).upsertCurrent(requested, true);
        }), "a colliding generated ID must fail, never update an unrelated ACL through ANY-key upsert");
        assertEquals(before, jdbc.queryForList("select * from peer_mesh_acl where source_client_id=? and target_client_id=?", source, target));
        assertEquals(0, jdbc.queryForObject("select count(*) from peer_mesh_acl where source_client_id=? and target_client_id=?", Integer.class, target, source));
    }

    private static void verifyOppositeEndpoints(ConfigurableApplicationContext context, DataSource independent, boolean sqlite) throws Exception {
        if (sqlite) return; // SQLite pool1 already exercised above; no row-level concurrency claim.
        long base = 5_100_000L + Case.SESSION_TARGET_NAME.ordinal() * 40;
        long source = base + 1, target = base + 2, low = base + 20, high = base + 21;
        var accounts = context.getBean(ClientAccountRepository.class);
        var first = accounts.findById(source).orElseThrow(); var second = accounts.findById(target).orElseThrow();
        var service = context.getBean(PeerMeshService.class);
        CountDownLatch heldLow = new CountDownLatch(1), reverseAtLow = new CountDownLatch(1), resume = new CountDownLatch(1);
        AtomicReference<Thread> forward = new AtomicReference<>(), reverse = new AtomicReference<>();
        List<Long> forwardLocks = new CopyOnWriteArrayList<>(), reverseLocks = new CopyOnWriteArrayList<>();
        Advised proxy = assertInstanceOf(Advised.class, context.getBean(ClientCredentialRepository.class));
        MethodInterceptor observe = invocation -> {
            boolean lock = invocation.getMethod().getName().equals("lockCurrent");
            long id = lock ? ((Number) invocation.getArguments()[0]).longValue() : -1;
            if (lock && Thread.currentThread() == reverse.get() && id == low) reverseAtLow.countDown();
            Object result = invocation.proceed();
            if (lock && Thread.currentThread() == forward.get()) {
                forwardLocks.add(id);
                if (id == low) { heldLow.countDown(); assertTrue(resume.await(15, TimeUnit.SECONDS)); }
            }
            if (lock && Thread.currentThread() == reverse.get()) reverseLocks.add(id);
            return result;
        };
        proxy.addAdvice(0, observe);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var a = executor.submit(() -> { forward.set(Thread.currentThread()); return service.createSession(first, second, PeerMeshService.PATH_DIRECT); });
            try {
                assertTrue(heldLow.await(15, TimeUnit.SECONDS), "forward must hold real lower credential before higher");
                var b = executor.submit(() -> { reverse.set(Thread.currentThread()); return service.createSession(second, first, PeerMeshService.PATH_DIRECT); });
                assertTrue(reverseAtLow.await(15, TimeUnit.SECONDS), "opposite endpoint request must attempt lower credential first");
                try (var connection = independent.getConnection(); var sql = connection.createStatement()) {
                    boolean mysql = !connection.getMetaData().getDatabaseProductName().contains("PostgreSQL");
                    sql.execute(mysql ? "set innodb_lock_wait_timeout=1" : "set lock_timeout='200ms'");
                    SQLException held = assertThrows(SQLException.class, () -> sql.executeUpdate("update specus_client_credential set max_online_instances=4 where id=" + low));
                    if (mysql) assertEquals(1205, held.getErrorCode()); else assertEquals("55P03", held.getSQLState());
                    assertEquals(1, sql.executeUpdate("update specus_client_credential set max_online_instances=4 where id=" + high),
                            "reverse request must not hold higher while waiting for lower");
                }
                resume.countDown();
                assertNotNull(a.get(15, TimeUnit.SECONDS).token()); assertNotNull(b.get(15, TimeUnit.SECONDS).token());
            } finally { resume.countDown(); }
        } finally { resume.countDown(); proxy.removeAdvice(observe); }
        assertEquals(List.of(low, high), new ArrayList<>(new LinkedHashSet<>(forwardLocks)));
        assertEquals(List.of(low, high), new ArrayList<>(new LinkedHashSet<>(reverseLocks)));
    }
}
