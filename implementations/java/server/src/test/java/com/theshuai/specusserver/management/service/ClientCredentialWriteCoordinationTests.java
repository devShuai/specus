package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementWriteAuthority;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.security.PasswordService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/** Contexts are deliberately resolved before independently committed changes. These real
 * SQLite/JPA writes must authorize again, not trust request-time roles or a reused login name. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "spring.datasource.url=jdbc:sqlite:file:target/test-credential-writes?mode=memory&cache=shared",
        "spring.jpa.hibernate.ddl-auto=create-drop", "specus.netty.port=0",
        "specus.database.seed-demo-client=false", "specus.auth.username=write-root",
        "specus.auth.password=write-root-password"
})
class ClientCredentialWriteCoordinationTests {
    @Autowired ClientCredentialService service;
    @Autowired JdbcTemplate jdbc;
    @Autowired AuthProperties auth;
    @Autowired ManagementWriteAuthority authority;
    @Autowired PlatformTransactionManager transactions;
    static final ManagementContext ALICE = new ManagementContext(TenantContext.defaultTenant(), "alice", false, "alice-key");
    enum ActorChange { DISABLED, DELETED, REPLACED, TENANT, LOGIN }
    enum Mutation { CREATE, UPDATE, DELETE }

    @BeforeEach
    void seed() {
        auth.setPasswordLoginEnabled(true);
        jdbc.execute("drop trigger if exists credential_write_failure");
        jdbc.update("delete from specus_client_credential");
        jdbc.update("delete from specus_management_user");
        String now = Instant.now().toString();
        jdbc.update("insert into specus_management_user(username,tenant_id,login_name,login_name_normalized,password_hash,role,enabled,created_at,updated_at) values (?,?,?,?,?,'USER',true,?,?)",
                "alice-key", "default", "alice", "alice", PasswordService.hashToken("password"), now, now);
        jdbc.update("insert into specus_client_credential(id,tenant_id,owner_username,api_key,secret_hash,enabled,max_online_instances,created_at,updated_at) values (501,'default','alice','write-key',?,true,2,?,?)",
                PasswordService.hashToken("write-secret"), now, now);
    }

    @ParameterizedTest
    @EnumSource(ActorChange.class)
    void revokedOrReplacedActorCannotCreateUpdateOrDelete(ActorChange change) {
        switch (change) {
            case DISABLED -> jdbc.update("update specus_management_user set enabled=false where username='alice-key'");
            case DELETED -> jdbc.update("delete from specus_management_user where username='alice-key'");
            case REPLACED -> jdbc.update("update specus_management_user set username='replacement-key' where username='alice-key'");
            case TENANT -> jdbc.update("update specus_management_user set tenant_id='foreign' where username='alice-key'");
            case LOGIN -> jdbc.update("update specus_management_user set login_name='renamed', login_name_normalized='renamed' where username='alice-key'");
        }
        for (Mutation mutation : Mutation.values()) {
            var denied = assertThrows(ResponseStatusException.class, () -> mutate(mutation, ALICE), mutation.name());
            assertEquals(HttpStatus.FORBIDDEN, denied.getStatusCode());
            assertUnchanged();
        }
    }

    @ParameterizedTest
    @EnumSource(value = Mutation.class, names = {"UPDATE", "DELETE"})
    void transferredCredentialIsNotVisibleToItsFormerOwner(Mutation mutation) {
        jdbc.update("update specus_client_credential set owner_username='bob' where id=501");
        assertThrows(IllegalArgumentException.class, () -> mutate(mutation, ALICE));
        assertEquals("bob", jdbc.queryForObject("select owner_username from specus_client_credential where id=501", String.class));
        assertEquals(2, jdbc.queryForObject("select max_online_instances from specus_client_credential where id=501", Integer.class));
    }

    @Test
    void currentRoleRatherThanResolvedRoleControlsResourceVisibility() {
        jdbc.update("update specus_client_credential set owner_username='bob' where id=501");
        ManagementContext oldAdmin = new ManagementContext(ALICE.tenant(), "alice", true, "alice-key");
        assertThrows(IllegalArgumentException.class, () -> mutate(Mutation.UPDATE, oldAdmin));
        assertThrows(IllegalArgumentException.class, () -> mutate(Mutation.DELETE, oldAdmin));
        jdbc.update("update specus_management_user set role='ADMIN' where username='alice-key'");
        mutate(Mutation.UPDATE, ALICE);
        assertEquals(7, jdbc.queryForObject("select max_online_instances from specus_client_credential where id=501", Integer.class));
        assertEquals("bob", jdbc.queryForObject("select owner_username from specus_client_credential where id=501", String.class));
    }

    @Test
    void ordinaryOwnerCanPerformAllThreeOperations() {
        mutate(Mutation.CREATE, ALICE);
        assertEquals("alice", jdbc.queryForObject("select owner_username from specus_client_credential where api_key='new-write-key'", String.class));
        mutate(Mutation.UPDATE, ALICE);
        assertEquals(7, jdbc.queryForObject("select max_online_instances from specus_client_credential where id=501", Integer.class));
        mutate(Mutation.DELETE, ALICE);
        assertEquals(0, jdbc.queryForObject("select count(*) from specus_client_credential where id=501", Integer.class));
    }

    @Test
    void onlyTheEnabledConfiguredBuiltinCanUseAnUnboundContext() {
        ManagementContext builtin = new ManagementContext(ALICE.tenant(), "write-root", true);
        mutate(Mutation.UPDATE, builtin);
        assertThrows(ResponseStatusException.class, () -> mutate(Mutation.CREATE,
                new ManagementContext(ALICE.tenant(), "alice", true)));
        assertThrows(ResponseStatusException.class, () -> mutate(Mutation.CREATE,
                new ManagementContext(new TenantContext("foreign"), "write-root", true)));
        auth.setPasswordLoginEnabled(false);
        try { assertThrows(ResponseStatusException.class, () -> mutate(Mutation.DELETE, builtin)); }
        finally { auth.setPasswordLoginEnabled(true); }
    }

    @Test
    void lateWriteFailureRollsBackTheCredential() {
        jdbc.execute("create trigger credential_write_failure before update on specus_client_credential when new.max_online_instances=7 begin select raise(abort,'intentional credential mutation failure'); end");
        try {
            RuntimeException failure = assertThrows(RuntimeException.class, () -> mutate(Mutation.UPDATE, ALICE));
            Throwable root = failure;
            while (root.getCause() != null) root = root.getCause();
            assertTrue(root.getMessage().contains("intentional credential mutation failure"));
            assertUnchanged();
        } finally { jdbc.execute("drop trigger if exists credential_write_failure"); }
        mutate(Mutation.UPDATE, ALICE);
    }

    @Test
    void authorityCannotBeUsedOutsideTheWritersTransaction() {
        assertThrows(IllegalTransactionStateException.class, () -> authority.current(ALICE));
    }

    @Test
    void sqliteKeepsTheActorAndCredentialProtectedUntilCommit() throws Exception {
        CountDownLatch changed = new CountDownLatch(1), resume = new CountDownLatch(1);
        try (var worker = Executors.newSingleThreadExecutor()) {
            var transaction = worker.submit(() -> new TransactionTemplate(transactions).execute(status -> {
                mutate(Mutation.UPDATE, ALICE); changed.countDown();
                try { assertTrue(resume.await(10, TimeUnit.SECONDS)); }
                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new AssertionError(interrupted); }
                return true;
            }));
            try {
                assertTrue(changed.await(10, TimeUnit.SECONDS));
                try (var connection = DriverManager.getConnection("jdbc:sqlite:file:target/test-credential-writes?mode=memory&cache=shared");
                     var sql = connection.createStatement()) {
                    sql.execute("pragma busy_timeout=100");
                    for (String update : new String[]{
                            "update specus_management_user set enabled=false where username='alice-key'",
                            "update specus_client_credential set owner_username='bob' where id=501"}) {
                        SQLException blocked = assertThrows(SQLException.class, () -> sql.executeUpdate(update));
                        int primary = blocked.getErrorCode() & 255;
                        assertTrue(primary == 5 || primary == 6, "expected SQLite BUSY/LOCKED");
                    }
                }
            } finally { resume.countDown(); }
            assertTrue(transaction.get(15, TimeUnit.SECONDS));
        }
        assertEquals(1, jdbc.update("update specus_management_user set enabled=false where username='alice-key'"));
        assertEquals(7, jdbc.queryForObject("select max_online_instances from specus_client_credential where id=501", Integer.class));
    }

    private void mutate(Mutation mutation, ManagementContext context) {
        switch (mutation) {
            case CREATE -> service.create(context, new ClientCredentialService.CredentialMutation("new-write-key", "new-write-secret", true, 3));
            case UPDATE -> service.update(context, 501, new ClientCredentialService.CredentialMutation(null, null, null, 7));
            case DELETE -> service.delete(context, 501);
        }
    }

    private void assertUnchanged() {
        assertEquals(1, jdbc.queryForObject("select count(*) from specus_client_credential", Integer.class));
        assertEquals("alice", jdbc.queryForObject("select owner_username from specus_client_credential where id=501", String.class));
        assertEquals(2, jdbc.queryForObject("select max_online_instances from specus_client_credential where id=501", Integer.class));
    }
}
