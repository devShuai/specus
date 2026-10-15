package com.theshuai.specusserver.database;

import com.theshuai.common.clientauth.ClientAuthLoginRequest;
import com.theshuai.common.clientauth.ClientAuthSigner;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.specusserver.config.ClientAuthProperties;
import com.theshuai.specusserver.config.NettyServerProperties;
import com.theshuai.specusserver.management.repository.*;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementWriteAuthority;
import com.theshuai.specusserver.management.service.*;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.security.PasswordService;
import com.theshuai.specusserver.security.TlsProperties;
import com.theshuai.specusserver.session.ClientHttpRouteCapabilities;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

/** Runs against a fresh, owned real-provider database. Fixtures commit between actual signature
 * authentication and transaction entry; no Java transfer endpoint is implied by these SQL changes. */
final class ClientCredentialAuthAssertions {
    static void verify(ConfigurableApplicationContext context, DataSource independent, boolean zeroAffectedRows) throws Exception {
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class), writer = new JdbcTemplate(independent);
        PlatformTransactionManager manager = context.getBean(PlatformTransactionManager.class);
        String stamp = Instant.now().toString(), secret = "provider-auth-secret";
        for (int mutation = 0; mutation < 7; mutation++) {
            long id = 910501L + mutation;
            String key = "provider-auth-key-" + id, host = "provider-auth-" + id;
            jdbc.update("insert into specus_client_credential(id,tenant_id,owner_username,api_key,secret_hash,enabled,max_online_instances,created_at,updated_at) values (?,?,?,?,?,true,2,?,?)",
                    id, "default", "alice", key, PasswordService.hashToken(secret), stamp, stamp);
            if (zeroAffectedRows) assertEquals(0, writer.update(
                    "update specus_client_credential set enabled=enabled where id=?", id), "real MySQL driver must report unchanged rows as zero");
            int selected = mutation;
            PlatformTransactionManager boundary = new PlatformTransactionManager() {
                @Override public TransactionStatus getTransaction(TransactionDefinition definition) {
                    String sql = switch (selected) {
                        case 0 -> "update specus_client_credential set owner_username='bob' where id=?";
                        case 1 -> "update specus_client_credential set max_online_instances=11 where id=?";
                        case 2 -> "update specus_client_credential set enabled=false where id=?";
                        case 3 -> "update specus_client_credential set api_key='rotated-provider-key' where id=?";
                        case 4 -> "update specus_client_credential set secret_hash='" + PasswordService.hashToken("rotated-provider-secret") + "' where id=?";
                        case 5 -> "update specus_client_credential set tenant_id='foreign' where id=?";
                        default -> "delete from specus_client_credential where id=?";
                    };
                    assertEquals(1, writer.update(sql, id), "independent fixture must commit before login transaction");
                    return manager.getTransaction(definition);
                }
                @Override public void commit(TransactionStatus status) { manager.commit(status); }
                @Override public void rollback(TransactionStatus status) { manager.rollback(status); }
            };
            // Real production service and all real repositories. Only transaction entry is wrapped;
            // credential SQL, nonce consumption, authentication and provisioning are not mocked.
            ClientAuthService login = new ClientAuthService(
                    context.getBean(ClientCredentialRepository.class), context.getBean(ClientIdentityRepository.class),
                    context.getBean(ClientSessionRepository.class), context.getBean(ClientAccountRepository.class),
                    context.getBean(ConnectionRecordRepository.class), context.getBean(SpecusMappingRepository.class),
                    context.getBean(HttpRouteMappingRepository.class), context.getBean(PeerMeshService.class),
                    context.getBean(ClientAuthNonceService.class), context.getBean(ClientAuthProperties.class),
                    context.getBean(NettyServerProperties.class), context.getBean(TlsProperties.class),
                    context.getBean(ClientHttpRouteCapabilities.class), boundary, "");
            ClientEnvironmentInfo environment = new ClientEnvironmentInfo();
            environment.setMachineFingerprint(host); environment.setHostname(host); environment.setOsUser("provider-user");
            ClientAuthLoginRequest request = new ClientAuthLoginRequest();
            request.setApiKey(key); request.setTimestamp(Long.toString(System.currentTimeMillis()));
            request.setNonce(UUID.randomUUID().toString()); request.setEnvironment(environment);
            request.setSignature(ClientAuthSigner.signApiKey(key, request.getTimestamp(), request.getNonce(), environment, secret));
            if (mutation < 2) {
                var response = login.login(request, "localhost");
                assertEquals(mutation == 0 ? "bob" : "alice", jdbc.queryForObject(
                        "select owner_username from specus_client_account where id=?", String.class, response.getClientId()));
                assertEquals(mutation == 1 ? 11 : 2, response.getMaxOnlineInstances());
            } else {
                assertThrows(IllegalArgumentException.class, () -> login.login(request, "localhost"));
                assertEquals(0, jdbc.queryForObject("select count(*) from specus_client_identity where credential_id=?", Integer.class, id));
                assertEquals(0, jdbc.queryForObject("select count(*) from specus_client_session where credential_id=?", Integer.class, id));
                assertEquals(0, jdbc.queryForObject("select count(*) from specus_client_account where client_name like ?", Integer.class, host + "%"));
            }
        }
        var credentials = context.getBean(ClientCredentialRepository.class);
        // MySQL/MariaDB management writers can have an earlier REPEATABLE READ snapshot;
        // PostgreSQL defaults to READ COMMITTED but can still have a stale JPA cache entry.
        long snapshotId = 910590L;
        jdbc.update("insert into specus_client_credential(id,tenant_id,owner_username,api_key,secret_hash,enabled,max_online_instances,created_at,updated_at) values (?,?,?,?,?,true,2,?,?)",
                snapshotId, "default", "snapshot-alice", "snapshot-key", PasswordService.hashToken(secret), stamp, stamp);
        TransactionTemplate snapshotTransaction = new TransactionTemplate(manager);
        snapshotTransaction.setIsolationLevel(zeroAffectedRows ? TransactionDefinition.ISOLATION_REPEATABLE_READ
                : TransactionDefinition.ISOLATION_READ_COMMITTED);
        snapshotTransaction.executeWithoutResult(status -> {
            var cached = credentials.findById(snapshotId).orElseThrow();
            assertEquals("snapshot-alice", cached.getOwnerUsername());
            assertEquals(1, writer.update("update specus_client_credential set owner_username='snapshot-bob', api_key='snapshot-current-key', secret_hash=?, enabled=false, max_online_instances=17, updated_at=? where id=?",
                    PasswordService.hashToken("snapshot-current-secret"), "2026-10-14T01:02:03Z", snapshotId));
            var current = credentials.lockCurrent(snapshotId, "default").orElseThrow();
            assertEquals("snapshot-bob", current.getOwnerUsername(), "the locking read must bypass an older transaction snapshot and cached entity");
            assertEquals("snapshot-current-key", current.getApiKey());
            assertEquals(PasswordService.hashToken("snapshot-current-secret"), current.getSecretHash());
            assertFalse(current.isEnabled());
            assertEquals(17, current.getMaxOnlineInstances());
            assertEquals("2026-10-14T01:02:03Z", current.getUpdatedAt());
            assertEquals("default", current.getTenantId());
            assertEquals(stamp, current.getCreatedAt());
            var result = context.getBean(ClientCredentialService.class).update(TenantContext.defaultTenant(), snapshotId,
                    new ClientCredentialService.CredentialMutation(null, null, null, 19));
            assertEquals("snapshot-bob", result.credential().ownerUsername());
        });
        assertEquals("snapshot-bob", writer.queryForObject("select owner_username from specus_client_credential where id=?", String.class, snapshotId));
        assertEquals("snapshot-current-key", writer.queryForObject("select api_key from specus_client_credential where id=?", String.class, snapshotId));
        assertEquals(PasswordService.hashToken("snapshot-current-secret"), writer.queryForObject("select secret_hash from specus_client_credential where id=?", String.class, snapshotId));
        assertFalse(writer.queryForObject("select enabled from specus_client_credential where id=?", Boolean.class, snapshotId));
        assertEquals(19, writer.queryForObject("select max_online_instances from specus_client_credential where id=?", Integer.class, snapshotId));
        CountDownLatch locked = new CountDownLatch(1), resume = new CountDownLatch(1);
        try (var worker = Executors.newSingleThreadExecutor()) {
            var transaction = worker.submit(() -> new TransactionTemplate(manager).execute(status -> {
                var current = credentials.lockCurrent(910501L, "default").orElseThrow();
                assertEquals("bob", current.getOwnerUsername()); locked.countDown();
                try { assertTrue(resume.await(10, TimeUnit.SECONDS)); }
                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new AssertionError(interrupted); }
                return current.getOwnerUsername();
            }));
            try {
                assertTrue(locked.await(10, TimeUnit.SECONDS));
                try (var connection = independent.getConnection(); var sql = connection.createStatement()) {
                    if (zeroAffectedRows) sql.execute("set innodb_lock_wait_timeout=1");
                    else sql.execute("set lock_timeout='200ms'");
                    SQLException blocked = assertThrows(SQLException.class, () -> sql.executeUpdate(
                            "update specus_client_credential set owner_username='after-commit' where id=910501"));
                    if (zeroAffectedRows) assertEquals(1205, blocked.getErrorCode());
                    else assertEquals("55P03", blocked.getSQLState());
                }
            } finally { resume.countDown(); }
            assertEquals("bob", transaction.get(15, TimeUnit.SECONDS));
        }
        assertEquals(1, writer.update("update specus_client_credential set owner_username='after-commit' where id=910501"));
        assertEquals("after-commit", jdbc.queryForObject("select owner_username from specus_client_credential where id=910501", String.class));
        verifyManagementWrites(context, independent, zeroAffectedRows);
        ManagementResourceWriteAssertions.verify(context, independent, zeroAffectedRows);
        ManagementLoginAssertions.verify(context, independent, zeroAffectedRows);
        ClientRuntimeCoordinationAssertions.verify(context, independent);
        ClientOwnerTransferWriteAssertions.verify(context, independent);
        ClientOwnershipLockAssertions.verify(context, independent);
        PeerAclCoordinationAssertions.verify(context, independent);
        PeerCacheCommitAssertions.verify(context, independent);
        PeerSessionCurrentAssertions.verify(context, independent);
        PeerSignalCommitAssertions.verify(context, independent);
        PeerReadSnapshotAssertions.verify(context, independent);
        ClientMessageRelayAssertions.verify(context, independent);
        ManagementMessageAssertions.verify(context, independent);
        com.theshuai.specusserver.management.service.PeerCatalogCacheAssertions.verify(context, independent);
        com.theshuai.specusserver.management.service.PeerCatalogCommitAssertions.verify(context, independent);
        com.theshuai.specusserver.management.service.PeerCatalogPublicationAssertions.verify(context, independent);
        com.theshuai.specusserver.management.service.PeerCatalogRevisionAssertions.verify(context, independent);
    }

    private static void verifyManagementWrites(ConfigurableApplicationContext context, DataSource independent,
                                               boolean mysql) throws Exception {
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class), writer = new JdbcTemplate(independent);
        var service = context.getBean(ClientCredentialService.class);
        var manager = context.getBean(PlatformTransactionManager.class);
        var authority = context.getBean(ManagementWriteAuthority.class);
        assertTrue(context.getBean(DataSource.class).unwrap(com.zaxxer.hikari.HikariDataSource.class).getMaximumPoolSize() >= 2,
                "two concurrent caller transactions require separate pool connections");
        String stamp = Instant.now().toString();
        for (int change = 0; change < 6; change++) {
            String key = "write-actor-" + change, login = "write-user-" + change;
            jdbc.update("insert into specus_management_user(username,tenant_id,login_name,login_name_normalized,password_hash,role,enabled,created_at,updated_at) values (?,'default',?,?,?,'ADMIN',true,?,?)",
                    key, login, login, PasswordService.hashToken("write-password"), stamp, stamp);
            long id = 910600L + change;
            jdbc.update("insert into specus_client_credential(id,tenant_id,owner_username,api_key,secret_hash,enabled,max_online_instances,created_at,updated_at) values (?,'default','different-owner',?,?,true,2,?,?)",
                    id, "write-key-" + change, PasswordService.hashToken("write-secret"), stamp, stamp);
            ManagementContext resolved = new ManagementContext(TenantContext.defaultTenant(), login, true, key);
            TransactionTemplate transaction = new TransactionTemplate(manager);
            transaction.setIsolationLevel(mysql ? TransactionDefinition.ISOLATION_REPEATABLE_READ : TransactionDefinition.ISOLATION_READ_COMMITTED);
            int selected = change;
            RuntimeException rejected = assertThrows(RuntimeException.class, () -> transaction.executeWithoutResult(status -> {
                assertTrue(context.getBean(ManagementUserRepository.class).findById(key).orElseThrow().isEnabled());
                String sql = switch (selected) {
                    case 0 -> "update specus_management_user set enabled=false where username=?";
                    case 1 -> "delete from specus_management_user where username=?";
                    case 2 -> "update specus_management_user set username='replacement-writer' where username=?";
                    case 3 -> "update specus_management_user set tenant_id='foreign' where username=?";
                    case 4 -> "update specus_management_user set login_name='renamed-writer',login_name_normalized='renamed-writer' where username=?";
                    default -> "update specus_management_user set role='USER' where username=?";
                };
                assertEquals(1, writer.update(sql, key));
                service.update(resolved, id, new ClientCredentialService.CredentialMutation(null, null, null, 9));
            }));
            if (change == 5) assertInstanceOf(IllegalArgumentException.class, rejected);
            else assertEquals(403, assertInstanceOf(ResponseStatusException.class, rejected).getStatusCode().value());
            assertEquals(2, writer.queryForObject("select max_online_instances from specus_client_credential where id=?", Integer.class, id));
            assertEquals("different-owner", writer.queryForObject("select owner_username from specus_client_credential where id=?", String.class, id));
        }
        ManagementContext actor = new ManagementContext(TenantContext.defaultTenant(), "write-user-5", false, "write-actor-5");
        jdbc.update("update specus_management_user set role='ADMIN' where username='write-actor-5'");
        service.update(actor, 910605L, new ClientCredentialService.CredentialMutation(null, null, null, 9));
        assertEquals(9, writer.queryForObject("select max_online_instances from specus_client_credential where id=910605", Integer.class));
        jdbc.update("insert into specus_management_user(username,tenant_id,login_name,login_name_normalized,password_hash,role,enabled,created_at,updated_at) values ('write-other','default','write-other','write-other',?,'USER',true,?,?)",
                PasswordService.hashToken("write-password"), stamp, stamp);
        var other = new ManagementContext(TenantContext.defaultTenant(), "write-other", false, "write-other");
        CountDownLatch locked = new CountDownLatch(1), resume = new CountDownLatch(1);
        try (var worker = Executors.newSingleThreadExecutor(); var unrelatedWorker = Executors.newSingleThreadExecutor()) {
            var transaction = worker.submit(() -> new TransactionTemplate(manager).execute(status -> {
                assertTrue(authority.current(actor).isAdmin()); locked.countDown();
                try { assertTrue(resume.await(10, TimeUnit.SECONDS)); }
                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new AssertionError(interrupted); }
                return true;
            }));
            try {
                assertTrue(locked.await(10, TimeUnit.SECONDS));
                assertFalse(unrelatedWorker.submit(() -> new TransactionTemplate(manager).execute(status ->
                        authority.current(other).isAdmin())).get(5, TimeUnit.SECONDS),
                        "another account in the same tenant must not wait on a global/tenant lock");
                try (var connection = independent.getConnection(); var sql = connection.createStatement()) {
                    sql.execute(mysql ? "set innodb_lock_wait_timeout=1" : "set lock_timeout='200ms'");
                    SQLException blocked = assertThrows(SQLException.class, () -> sql.executeUpdate(
                            "update specus_management_user set enabled=false where username='write-actor-5'"));
                    if (mysql) assertEquals(1205, blocked.getErrorCode());
                    else assertEquals("55P03", blocked.getSQLState());
                }
            } finally { resume.countDown(); }
            assertTrue(transaction.get(15, TimeUnit.SECONDS));
        }
        assertEquals(1, writer.update("update specus_management_user set enabled=false where username='write-actor-5'"));
    }
}
