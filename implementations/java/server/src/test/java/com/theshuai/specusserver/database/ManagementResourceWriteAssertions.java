package com.theshuai.specusserver.database;

import com.theshuai.specusserver.management.ManagementActorFixtures;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.service.*;
import com.theshuai.specusserver.security.PasswordService;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.time.Instant;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

/** Real production services and independent caller transactions; no repository/auth mocks. */
final class ManagementResourceWriteAssertions {
    static void prepareLegacyPasswordSchema(ConfigurableApplicationContext context, boolean mysql) {
        ManagementActorFixtures.admin(context.getBean(ManagementUserRepository.class), "default", "legacy-password-user");
        context.getBean(JdbcTemplate.class).execute(mysql
                ? "alter table specus_management_user modify password_hash varchar(64) not null"
                : "alter table specus_management_user alter column password_hash type varchar(64)");
    }

    static void verifyPasswordSchemaUpgrade(ConfigurableApplicationContext context) {
        var repository = context.getBean(ManagementUserRepository.class);
        var admin = ManagementActorFixtures.admin(repository, "default", "password-storage-admin");
        var users = context.getBean(ManagementUserService.class);
        users.createUser(admin, new ManagementUserService.UserMutation("new-password-user", "Storage-new-password-1", null, true));
        users.updateUser(admin, "legacy-password-user", new ManagementUserService.UserMutation(null, "Storage-legacy-password-1", null, null));
        for (String login : new String[]{"new-password-user", "legacy-password-user"}) {
            String hash = repository.findByTenantIdAndLoginNameNormalized("default", login).orElseThrow().getPasswordHash();
            assertTrue(hash.length() > 64, "exercise the real versioned human-password encoding, not a short fixture digest");
            String password = login.startsWith("new-") ? "Storage-new-password-1" : "Storage-legacy-password-1";
            assertTrue(PasswordService.matches(password, hash));
            assertTrue(users.authenticate(login, password, "default").isPresent());
        }
    }

    static void verify(ConfigurableApplicationContext context, DataSource independent, boolean mysql) throws Exception {
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class), writer = new JdbcTemplate(independent);
        var manager = context.getBean(PlatformTransactionManager.class);
        var clients = context.getBean(ClientAccountService.class);
        var credentials = context.getBean(ClientCredentialService.class);
        var users = context.getBean(ManagementUserService.class);
        var userRepository = context.getBean(ManagementUserRepository.class);
        ManagementContext admin = ManagementActorFixtures.admin(userRepository, "default", "resource-admin-a");
        ManagementContext other = ManagementActorFixtures.admin(userRepository, "default", "resource-admin-b");
        ManagementContext target = ManagementActorFixtures.admin(userRepository, "default", "resource-target");
        String stamp = Instant.now().toString();
        jdbc.update("insert into specus_client_account(id,tenant_id,owner_username,client_name,password_hash,enabled,connection_rate_limit_per_minute,created_at,updated_at) values (920001,'default','resource-target','resource-old-client',?,true,30,?,?)",
                PasswordService.hashToken("old-resource-token"), stamp, stamp);
        TransactionTemplate snapshot = new TransactionTemplate(manager);
        snapshot.setIsolationLevel(mysql ? TransactionDefinition.ISOLATION_REPEATABLE_READ : TransactionDefinition.ISOLATION_READ_COMMITTED);
        snapshot.executeWithoutResult(status -> {
            assertEquals("resource-target", context.getBean(ClientAccountRepository.class).findById(920001L).orElseThrow().getOwnerUsername());
            assertEquals(1, writer.update("update specus_client_account set owner_username='resource-bob',client_name='resource-current-client',password_hash=?,enabled=false,connection_rate_limit_per_minute=87 where id=920001",
                    PasswordService.hashToken("current-resource-token")));
            var changed = clients.updateClient(admin.tenant(), 920001L, new ClientAccountService.ClientMutation(null, null, 19));
            assertEquals("resource-bob", changed.client().ownerUsername());
            assertEquals("resource-current-client", changed.client().clientName());
            assertFalse(changed.client().enabled());
        });
        assertEquals("resource-bob", writer.queryForObject("select owner_username from specus_client_account where id=920001", String.class));
        assertEquals(PasswordService.hashToken("current-resource-token"), writer.queryForObject("select password_hash from specus_client_account where id=920001", String.class));
        assertEquals(19, writer.queryForObject("select connection_rate_limit_per_minute from specus_client_account where id=920001", Integer.class));
        assertEquals(stamp, writer.queryForObject("select created_at from specus_client_account where id=920001", String.class));

        snapshot.executeWithoutResult(status -> {
            assertTrue(userRepository.findById(target.accountKey()).orElseThrow().isEnabled());
            assertEquals(1, writer.update("update specus_management_user set role='USER',enabled=false,oidc_issuer='https://resource-fixture.invalid',oidc_subject='current-subject',oidc_identity_key=? where username=?",
                    "b".repeat(64), target.accountKey()));
            users.updateUser(admin, target.username(), new ManagementUserService.UserMutation(null, "Resource-new-password-1", null, null));
        });
        assertEquals("USER", writer.queryForObject("select role from specus_management_user where username=?", String.class, target.accountKey()));
        assertFalse(writer.queryForObject("select enabled from specus_management_user where username=?", Boolean.class, target.accountKey()));
        assertEquals("https://resource-fixture.invalid", writer.queryForObject("select oidc_issuer from specus_management_user where username=?", String.class, target.accountKey()));
        assertEquals("current-subject", writer.queryForObject("select oidc_subject from specus_management_user where username=?", String.class, target.accountKey()));
        assertEquals("b".repeat(64), writer.queryForObject("select oidc_identity_key from specus_management_user where username=?", String.class, target.accountKey()));
        assertTrue(PasswordService.matches("Resource-new-password-1", writer.queryForObject("select password_hash from specus_management_user where username=?", String.class, target.accountKey())));
        writer.update("update specus_management_user set enabled=true where username=?", target.accountKey());
        assertThrows(IllegalArgumentException.class, () -> clients.updateClient(target, 920001L, new ClientAccountService.ClientMutation(null, null, 90)));
        assertThrows(IllegalArgumentException.class, () -> clients.deleteClient(target, 920001L));

        for (boolean credential : new boolean[]{true, false}) {
            AtomicLong id = new AtomicLong();
            try (var creator = Executors.newSingleThreadExecutor()) {
                AccountStillOwnsResourcesException blocked = assertThrows(AccountStillOwnsResourcesException.class,
                        () -> snapshot.executeWithoutResult(status -> {
                            assertEquals(0, jdbc.queryForObject("select count(*) from specus_client_credential where owner_username='resource-target'", Integer.class));
                            assertEquals(0, jdbc.queryForObject("select count(*) from specus_client_account where owner_username='resource-target'", Integer.class));
                            try {
                                id.set(creator.submit(() -> credential
                                        ? credentials.create(target, new ClientCredentialService.CredentialMutation("resource-count-key", "Resource-count-secret", true, 2)).credential().id()
                                        : clients.createClient(target, new ClientAccountService.ClientMutation("resource-count-client", true, 30)).client().id()).get(10, TimeUnit.SECONDS));
                            } catch (Exception failure) { throw new AssertionError("independent production resource creation failed", failure); }
                            users.deleteUser(admin, target.username());
                        }));
                assertEquals(credential ? 1 : 0, blocked.credentials());
                assertEquals(credential ? 0 : 1, blocked.clients());
            }
            assertEquals(1, writer.queryForObject("select count(*) from specus_management_user where username=?", Integer.class, target.accountKey()));
            assertEquals(1, writer.update("delete from " + (credential ? "specus_client_credential" : "specus_client_account") + " where id=?", id.get()));
        }
        // PostgreSQL RR must reject its older snapshot rather than silently miss a new resource.
        if (!mysql) {
            TransactionTemplate repeatable = new TransactionTemplate(manager);
            repeatable.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
            try (var creator = Executors.newSingleThreadExecutor()) {
                RuntimeException rejected = assertThrows(RuntimeException.class, () -> repeatable.executeWithoutResult(status -> {
                    assertEquals(0, jdbc.queryForObject("select count(*) from specus_client_credential where owner_username='resource-target'", Integer.class));
                    try { creator.submit(() -> credentials.create(target, new ClientCredentialService.CredentialMutation("resource-rr-key", "Resource-rr-secret", true, 2))).get(10, TimeUnit.SECONDS); }
                    catch (Exception failure) { throw new AssertionError(failure); }
                    users.deleteUser(admin, target.username());
                }));
                Throwable cause = rejected;
                while (cause.getCause() != null) cause = cause.getCause();
                assertEquals("40001", assertInstanceOf(SQLException.class, cause).getSQLState());
            }
            assertEquals(1, writer.queryForObject("select count(*) from specus_management_user where username=?", Integer.class, target.accountKey()));
            writer.update("delete from specus_client_credential where api_key='resource-rr-key'");
        }
        // Both operations update only passwords. Inconsistent actor-first lock ordering used to
        // permit an AB/BA deadlock; canonical key order lets both legitimate requests commit.
        CyclicBarrier start = new CyclicBarrier(2);
        try (var workers = Executors.newFixedThreadPool(2)) {
            var first = workers.submit(() -> { start.await(10, TimeUnit.SECONDS); return users.updateUser(admin, other.username(), new ManagementUserService.UserMutation(null, "Resource-b-password-1", null, null)); });
            var second = workers.submit(() -> { start.await(10, TimeUnit.SECONDS); return users.updateUser(other, admin.username(), new ManagementUserService.UserMutation(null, "Resource-a-password-1", null, null)); });
            assertEquals(other.username(), first.get(15, TimeUnit.SECONDS).username());
            assertEquals(admin.username(), second.get(15, TimeUnit.SECONDS).username());
        }
        assertTrue(PasswordService.matches("Resource-a-password-1", writer.queryForObject("select password_hash from specus_management_user where username=?", String.class, admin.accountKey())));
        assertTrue(PasswordService.matches("Resource-b-password-1", writer.queryForObject("select password_hash from specus_management_user where username=?", String.class, other.accountKey())));
        verifyCredentialBeforeClient(context, independent, mysql, admin);
        for (int index = 0; index < 4; index++) {
            writer.update("insert into peer_mesh_device(id,tenant_id,owner_username,client_id,client_name,virtual_ip,cidr,enabled,created_at,updated_at) values (?,?,?,?,?,?,?,false,?,?)",
                    920101L + index, index == 2 ? "foreign" : "default", index == 1 ? other.username() : target.username(),
                    index == 3 ? 920001L : 989989L + index, "resource-delete-device-" + index,
                    "100.120.9." + (index + 1), "100.120.0.0/16", stamp, stamp);
        }
        assertEquals(target.username(), users.deleteUser(admin, target.username()));
        assertEquals(0, writer.queryForObject("select count(*) from peer_mesh_device where id=920101", Integer.class));
        for (long retained : new long[]{920102L, 920103L, 920104L})
            assertEquals(1, writer.queryForObject("select count(*) from peer_mesh_device where id=?", Integer.class, retained),
                    "only current-tenant/current-owner orphan devices go; preserve other owners/tenants and existing-client references");
    }

    private static void verifyCredentialBeforeClient(ConfigurableApplicationContext context, DataSource independent,
                                                     boolean mysql, ManagementContext admin) throws Exception {
        JdbcTemplate writer = new JdbcTemplate(independent);
        long clientId = writer.queryForObject("select client_id from specus_client_identity where credential_id=910501", Long.class);
        var manager = context.getBean(PlatformTransactionManager.class);
        CountDownLatch held = new CountDownLatch(1), release = new CountDownLatch(1);
        try (var workers = Executors.newFixedThreadPool(2)) {
            var holder = workers.submit(() -> new TransactionTemplate(manager).execute(status -> {
                context.getBean(com.theshuai.specusserver.management.repository.ClientCredentialRepository.class).lockCurrent(910501L, "default").orElseThrow();
                held.countDown();
                try { assertTrue(release.await(15, TimeUnit.SECONDS)); }
                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new AssertionError(interrupted); }
                return true;
            }));
            try {
                assertTrue(held.await(10, TimeUnit.SECONDS));
                var rename = workers.submit(() -> context.getBean(ClientAccountService.class).updateClient(admin, clientId,
                        new ClientAccountService.ClientMutation("credential-ordered-client", null, null)));
                boolean maria = mysql && writer.queryForObject("select @@version", String.class).contains("MariaDB");
                String waitQuery = !mysql
                        ? "select count(*) from pg_stat_activity where datname=current_database() and wait_event_type='Lock' and query like '%specus_client_credential%' and pid<>pg_backend_pid()"
                        : maria ? "select count(*) from information_schema.innodb_trx where trx_state='LOCK WAIT' and trx_query like '%specus_client_credential%'"
                        : "select count(*) from performance_schema.data_lock_waits w join performance_schema.data_locks l on l.engine_lock_id=w.requesting_engine_lock_id where l.object_schema=database() and l.object_name='specus_client_credential'";
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
                while (writer.queryForObject(waitQuery, Integer.class) == 0) {
                    if (rename.isDone()) { rename.get(); fail("rename must wait for the credential lock"); }
                    assertTrue(System.nanoTime() < deadline, "must observe an actual database credential-lock waiter, not infer it from a sleeping thread");
                    Thread.sleep(20);
                }
                try (var connection = independent.getConnection(); var sql = connection.createStatement()) {
                    sql.execute(mysql ? "set innodb_lock_wait_timeout=1" : "set lock_timeout='200ms'");
                    assertEquals(mysql ? 0 : 1, sql.executeUpdate("update specus_client_account set enabled=enabled where id=" + clientId),
                            "the waiting rename must not already hold the client lock (credential comes first)");
                }
                release.countDown();
                assertEquals("credential-ordered-client", rename.get(10, TimeUnit.SECONDS).client().clientName());
            } finally { release.countDown(); }
            assertTrue(holder.get(10, TimeUnit.SECONDS));
        }
    }
}
