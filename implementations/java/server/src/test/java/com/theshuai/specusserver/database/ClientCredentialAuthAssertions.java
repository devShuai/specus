package com.theshuai.specusserver.database;

import com.theshuai.common.clientauth.ClientAuthLoginRequest;
import com.theshuai.common.clientauth.ClientAuthSigner;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.specusserver.config.ClientAuthProperties;
import com.theshuai.specusserver.config.NettyServerProperties;
import com.theshuai.specusserver.management.repository.*;
import com.theshuai.specusserver.management.service.*;
import com.theshuai.specusserver.security.PasswordService;
import com.theshuai.specusserver.security.TlsProperties;
import com.theshuai.specusserver.session.ClientHttpRouteCapabilities;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

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
    }
}
