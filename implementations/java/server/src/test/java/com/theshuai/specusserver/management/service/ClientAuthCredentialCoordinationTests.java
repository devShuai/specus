package com.theshuai.specusserver.management.service;

import com.theshuai.common.clientauth.ClientAuthLoginRequest;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.clientauth.ClientAuthSigner;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.specusserver.management.model.ClientCredential;
import com.theshuai.specusserver.management.repository.ClientCredentialRepository;
import com.theshuai.specusserver.security.PasswordService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.ArgumentMatchers.any;

/** Real SQLite/JPA login, with a second connection committing after the actual credential read.
 * SQL is a deterministic ownership/policy fixture, NOT a delivered Java transfer API. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "spring.datasource.url=" + ClientAuthCredentialCoordinationTests.URL,
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "specus.netty.port=0", "specus.database.seed-demo-client=false"
})
class ClientAuthCredentialCoordinationTests {
    static final String URL = "jdbc:sqlite:file:target/test-client-auth-coordination?mode=memory&cache=shared";
    static final String KEY = "coordination-api-key", SECRET = "coordination-signing-secret";
    static final long ID = 501L;
    @Autowired ClientAuthService service;
    @Autowired JdbcTemplate jdbc;
    @Autowired ClientCredentialRepository credentials;
    @MockitoSpyBean PlatformTransactionManager transactions;

    enum Mutation { OWNER, LIMIT, DISABLED, KEY_ROTATED, SECRET_ROTATED, TENANT_MOVED, DELETED }

    @BeforeEach
    void seed() {
        jdbc.execute("drop trigger if exists auth_fail_session");
        // Each test has a distinct fingerprint. Remove its prior rows before resetting the key.
        jdbc.update("delete from specus_client_session");
        jdbc.update("delete from specus_client_identity");
        jdbc.update("delete from specus_client_account");
        jdbc.update("delete from specus_client_auth_nonce");
        jdbc.update("delete from specus_client_credential");
        ClientCredential credential = new ClientCredential();
        credential.setId(ID); credential.setTenantId("default"); credential.setOwnerUsername("alice");
        credential.setApiKey(KEY); credential.setSecretHash(PasswordService.hashToken(SECRET));
        credential.setEnabled(true); credential.setMaxOnlineInstances(2);
        credential.setCreatedAt(Instant.now().toString()); credential.setUpdatedAt(credential.getCreatedAt());
        credentials.saveAndFlush(credential);
    }

    @ParameterizedTest
    @EnumSource(Mutation.class)
    void committedChangeAfterActualReadMustNotProvisionFromTheOldObject(Mutation mutation) throws Exception {
        CountDownLatch read = new CountDownLatch(1), resume = new CountDownLatch(1);
        AtomicBoolean fired = new AtomicBoolean();
        AtomicReference<Thread> loginThread = new AtomicReference<>();
        doAnswer(invocation -> {
            TransactionDefinition definition = invocation.getArgument(0);
            if (Thread.currentThread() == loginThread.get() && !definition.isReadOnly()
                    && definition.getPropagationBehavior() == TransactionDefinition.PROPAGATION_REQUIRED
                    && fired.compareAndSet(false, true)) {
                // Pause at the real write-transaction entry, AFTER credential lookup/signature
                // and the separate nonce transaction. Repository queries/results are not mocked.
                read.countDown();
                assertTrue(resume.await(10, TimeUnit.SECONDS), "credential read was never resumed");
            }
            return invocation.callRealMethod();
        }).when(transactions).getTransaction(any());
        var request = request("new-device");
        try (var worker = Executors.newSingleThreadExecutor()) {
            var login = worker.submit(() -> { loginThread.set(Thread.currentThread()); return service.login(request, "localhost"); });
            try {
                assertTrue(read.await(10, TimeUnit.SECONDS), "actual credential query not reached");
                assertEquals(1, count("specus_client_auth_nonce"), "signature/nonce must complete before this barrier");
                // This must COMMIT while login is paused: no production read/transaction may be
                // kept locked by this fixture. No sleeps or probabilistic retry are involved.
                try (Connection writer = DriverManager.getConnection(URL); var sql = writer.createStatement()) {
                    sql.execute("pragma busy_timeout=1000");
                    String update = switch (mutation) {
                        case OWNER -> "update specus_client_credential set owner_username='bob' where id=501";
                        case LIMIT -> "update specus_client_credential set max_online_instances=11 where id=501";
                        case DISABLED -> "update specus_client_credential set enabled=0 where id=501";
                        case KEY_ROTATED -> "update specus_client_credential set api_key='replacement-key' where id=501";
                        case SECRET_ROTATED -> "update specus_client_credential set secret_hash='" + PasswordService.hashToken("replacement-secret") + "' where id=501";
                        case TENANT_MOVED -> "update specus_client_credential set tenant_id='foreign' where id=501";
                        case DELETED -> "delete from specus_client_credential where id=501";
                    };
                    assertEquals(1, sql.executeUpdate(update), "independent mutation must affect the row");
                }
                resume.countDown();
                if (mutation == Mutation.OWNER || mutation == Mutation.LIMIT) {
                    ClientAuthLoginResponse response = login.get(15, TimeUnit.SECONDS);
                    assertEquals(mutation == Mutation.OWNER ? "bob" : "alice", jdbc.queryForObject(
                            "select owner_username from specus_client_account where id=?", String.class, response.getClientId()));
                    assertEquals(mutation == Mutation.LIMIT ? 11 : 2, response.getMaxOnlineInstances());
                    assertEquals(1, count("specus_client_identity"));
                    assertEquals(1, count("specus_client_session"));
                } else {
                    ExecutionException refused = assertThrows(ExecutionException.class, () -> login.get(15, TimeUnit.SECONDS));
                    assertInstanceOf(IllegalArgumentException.class, refused.getCause(), "current invalid credential must be an auth refusal");
                    assertEquals(0, count("specus_client_account"));
                    assertEquals(0, count("specus_client_identity"));
                    assertEquals(0, count("specus_client_session"));
                }
                assertEquals(1, count("specus_client_auth_nonce"), "the original nonce stays consumed even on refusal");
            } finally { resume.countDown(); }
        }
    }

    @Test
    void ordinaryLoginStillCreatesExactlyOneIdentityAndSession() {
        var response = service.login(request("ordinary-device"), "localhost");
        assertEquals("default", response.getTenantId());
        assertEquals("alice", jdbc.queryForObject("select owner_username from specus_client_account where id=?", String.class, response.getClientId()));
        assertEquals(1, count("specus_client_identity"));
        assertEquals(1, count("specus_client_session"));
    }

    @Test
    void loginMustNotImplicitlyTransferAnExistingClient() {
        var first = service.login(request("existing-device"), "localhost");
        jdbc.update("update specus_client_credential set owner_username='bob' where id=?", ID);
        var second = service.login(request("existing-device"), "localhost");
        assertEquals(first.getClientId(), second.getClientId());
        assertEquals("alice", jdbc.queryForObject("select owner_username from specus_client_account where id=?", String.class, first.getClientId()));
        assertEquals(1, count("specus_client_identity"));
    }

    @Test
    void credentialLockRequiresTheCallersWriteTransaction() {
        assertThrows(IllegalTransactionStateException.class, () -> credentials.lockCurrent(ID, "default"));
        assertEquals(0, count("specus_client_identity"));
    }

    @Test
    void actualDatabaseLockIsHeldUntilTheCallerCommits() throws Exception {
        CountDownLatch locked = new CountDownLatch(1), resume = new CountDownLatch(1);
        try (var worker = Executors.newSingleThreadExecutor()) {
            var transaction = worker.submit(() -> new TransactionTemplate(transactions).execute(status -> {
                var current = credentials.lockCurrent(ID, "default").orElseThrow();
                assertEquals("alice", current.getOwnerUsername());
                locked.countDown();
                try { assertTrue(resume.await(10, TimeUnit.SECONDS), "locked transaction not resumed"); }
                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new AssertionError(interrupted); }
                return current.getOwnerUsername();
            }));
            try {
                assertTrue(locked.await(10, TimeUnit.SECONDS), "actual write lock not acquired");
                try (Connection writer = DriverManager.getConnection(URL); var sql = writer.createStatement()) {
                    sql.execute("pragma busy_timeout=100");
                    SQLException blocked = assertThrows(SQLException.class, () -> sql.executeUpdate(
                            "update specus_client_credential set owner_username='bob' where id=501"));
                    int primary = blocked.getErrorCode() & 255;
                    assertTrue(primary == 5 || primary == 6, "expected SQLite BUSY/LOCKED, not an arbitrary SQL error");
                }
            } finally { resume.countDown(); }
            assertEquals("alice", transaction.get(15, TimeUnit.SECONDS));
        }
        try (Connection writer = DriverManager.getConnection(URL); var sql = writer.createStatement()) {
            assertEquals(1, sql.executeUpdate("update specus_client_credential set owner_username='bob' where id=501"));
        }
        assertEquals("bob", jdbc.queryForObject("select owner_username from specus_client_credential where id=501", String.class));
    }

    @Test
    void lateSessionInsertFailureRollsBackClientAndIdentityButNotTheConsumedNonce() {
        jdbc.execute("create trigger auth_fail_session before insert on specus_client_session begin select raise(abort,'intentional auth session failure'); end");
        try {
            RuntimeException failure = assertThrows(RuntimeException.class, () -> service.login(request("rollback-device"), "localhost"));
            Throwable cause = failure;
            while (cause.getCause() != null) cause = cause.getCause();
            assertTrue(cause.getMessage().contains("intentional auth session failure"), "must reach the intended late session fault");
            assertEquals(0, count("specus_client_account"));
            assertEquals(0, count("specus_client_identity"));
            assertEquals(0, count("specus_client_session"));
            assertEquals(1, count("specus_client_auth_nonce"));
        } finally { jdbc.execute("drop trigger auth_fail_session"); }
    }

    private long count(String table) { return jdbc.queryForObject("select count(*) from " + table, Long.class); }

    private static ClientAuthLoginRequest request(String fingerprint) {
        ClientEnvironmentInfo environment = new ClientEnvironmentInfo();
        environment.setMachineFingerprint(fingerprint); environment.setOsUser("coord-user"); environment.setHostname("coord-host");
        ClientAuthLoginRequest request = new ClientAuthLoginRequest();
        request.setApiKey(KEY); request.setTimestamp(Long.toString(System.currentTimeMillis())); request.setNonce(UUID.randomUUID().toString());
        request.setEnvironment(environment);
        request.setSignature(ClientAuthSigner.signApiKey(KEY, request.getTimestamp(), request.getNonce(), environment, SECRET));
        return request;
    }
}
