package com.theshuai.specusserver.database;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.theshuai.common.clientauth.ClientAuthLoginRequest;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.clientauth.ClientAuthSigner;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.specusserver.management.repository.ClientCredentialRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.management.service.ClientAuthService;
import com.theshuai.specusserver.management.service.ClientOwnerTransferException;
import com.theshuai.specusserver.management.service.ClientOwnerTransferService;
import com.theshuai.specusserver.management.service.ClientOwnerTransferWriter;
import com.theshuai.specusserver.security.PasswordService;
import org.aopalliance.intercept.MethodInterceptor;
import org.springframework.aop.framework.Advised;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import javax.sql.DataSource;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

/** Native malformed links are fixtures, not a supported reassociation operation. Real services,
 * real row locks and executed observers test failure-closed behavior without timing sleeps. */
public final class ClientOwnershipLockAssertions {
    static final ManagementContext ADMIN = new ManagementContext(TenantContext.defaultTenant(), "ownership-lock-admin", true, "ownership-lock-admin-key");
    private static final String TARGET = "ownership-lock-target";
    private record Fixture(long low, long high, ClientAuthLoginResponse first, ClientAuthLoginResponse second,
                           ClientEnvironmentInfo secondEnvironment, ObjectNode request) {}

    public static void verify(ConfigurableApplicationContext context, DataSource independent) throws Exception {
        assertAll("malformed ownership bindings and global credential order",
                () -> verifyAuthentication(context), () -> verifyOrder(context));
        verifyConcurrentDenial(context, independent);
        verifyNewMemberAfterDiscovery(context, independent);
    }

    public static void verifyAuthentication(ConfigurableApplicationContext context) {
        assertAll("malformed binding variants",
                () -> {
                    var fixture = fixture(context, 3_100_000);
                    assertDenied(context, fixture, fixture.high(), fixture.secondEnvironment(), fixture.second().getAccessToken());
                },
                () -> {
                    var fixture = fixture(context, 3_150_000);
                    context.getBean(JdbcTemplate.class).update("update specus_client_identity set credential_id=?,tenant_id='DEFAULT' where credential_id=?", fixture.low(), fixture.high());
                    assertDenied(context, fixture, fixture.low(), environment(fixture.low()), fixture.first().getAccessToken());
                });
    }

    private static void assertDenied(ConfigurableApplicationContext context, Fixture fixture, long credential,
                                     ClientEnvironmentInfo environment, String token) {
        var auth = context.getBean(ClientAuthService.class);
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class);
        String before = state(jdbc, fixture);
        assertAll("corrupt shared client must not authenticate through either transport",
                () -> assertThrows(IllegalArgumentException.class, () -> login(auth, credential, environment)),
                () -> {
                    LoginRequestPacket packet = new LoginRequestPacket(); packet.setAccessToken(token);
                    assertFalse(auth.authenticateNetty(packet, "corrupt-credential-channel", "loopback", false).success());
                });
        assertEquals(before, state(jdbc, fixture), "denial must not write lastSeen, a token or online state");
    }

    public static void verifyOrder(ConfigurableApplicationContext context) {
        var fixture = fixture(context, 3_200_000);
        Advised proxy = assertInstanceOf(Advised.class, context.getBean(ClientCredentialRepository.class));
        List<Long> executed = new ArrayList<>();
        MethodInterceptor observe = invocation -> {
            Object result = invocation.proceed();
            if (invocation.getMethod().getName().equals("lockCurrent")) executed.add(((Number) invocation.getArguments()[0]).longValue());
            return result;
        };
        proxy.addAdvice(0, observe);
        try {
            var failure = assertThrows(ClientOwnerTransferException.class, () -> context.getBean(ClientOwnerTransferWriter.class)
                    .transferCredential(ADMIN, Long.toString(fixture.high()), fixture.request()));
            assertEquals("INCONSISTENT_CREDENTIAL_GROUP", failure.code());
            assertEquals(List.of(fixture.low(), fixture.high()), new ArrayList<>(new LinkedHashSet<>(executed)),
                    "all first-acquired related credentials must be globally ordered, not selected credential first");
        } finally { proxy.removeAdvice(observe); }
    }

    private static void verifyConcurrentDenial(ConfigurableApplicationContext context, DataSource independent) throws Exception {
        String product;
        try (var connection = independent.getConnection()) { product = connection.getMetaData().getDatabaseProductName(); }
        if (product.toLowerCase(java.util.Locale.ROOT).contains("sqlite")) return; // actual SQLite pool1 matrix above; no row-level concurrency claim
        boolean mysql = !product.contains("PostgreSQL");
        var fixture = fixture(context, 3_300_000);
        var auth = context.getBean(ClientAuthService.class);
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class);
        String before = state(jdbc, fixture);
        CountDownLatch firstLocked = new CountDownLatch(1), resume = new CountDownLatch(1);
        AtomicReference<Thread> transferThread = new AtomicReference<>();
        Advised proxy = assertInstanceOf(Advised.class, context.getBean(ClientCredentialRepository.class));
        MethodInterceptor afterLow = invocation -> {
            Object result = invocation.proceed();
            if (Thread.currentThread() == transferThread.get() && invocation.getMethod().getName().equals("lockCurrent")
                    && ((Number) invocation.getArguments()[0]).longValue() == fixture.low()) {
                firstLocked.countDown(); assertTrue(resume.await(15, TimeUnit.SECONDS));
            }
            return result;
        };
        proxy.addAdvice(0, afterLow);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var group = executor.submit(() -> {
                transferThread.set(Thread.currentThread());
                return assertThrows(ClientOwnerTransferException.class, () -> context.getBean(ClientOwnerTransferWriter.class)
                        .transferCredential(ADMIN, Long.toString(fixture.high()), fixture.request()));
            });
            try {
                assertTrue(firstLocked.await(15, TimeUnit.SECONDS), "must observe the real lower credential lock before selected higher credential");
                var deniedHttp = executor.submit(() -> assertThrows(IllegalArgumentException.class,
                        () -> login(auth, fixture.high(), fixture.secondEnvironment())));
                deniedHttp.get(5, TimeUnit.SECONDS);
                var deniedNetty = executor.submit(() -> {
                    LoginRequestPacket packet = new LoginRequestPacket(); packet.setAccessToken(fixture.second().getAccessToken());
                    return auth.authenticateNetty(packet, "concurrent-corrupt-channel", "loopback", false);
                });
                assertFalse(deniedNetty.get(5, TimeUnit.SECONDS).success());
                try (var connection = independent.getConnection(); var sql = connection.createStatement()) {
                    sql.execute(mysql ? "set innodb_lock_wait_timeout=1" : "set lock_timeout='200ms'");
                    SQLException held = assertThrows(SQLException.class, () -> sql.executeUpdate("update specus_client_credential set max_online_instances=4 where id=" + fixture.low()));
                    if (mysql) assertEquals(1205, held.getErrorCode()); else assertEquals("55P03", held.getSQLState());
                    assertEquals(1, sql.executeUpdate("update specus_client_credential set max_online_instances=4 where id=" + fixture.high()),
                            "both rejected logins must release the higher credential without waiting for lower credential");
                }
            } finally { resume.countDown(); }
            assertEquals("INCONSISTENT_CREDENTIAL_GROUP", group.get(15, TimeUnit.SECONDS).code());
        } finally { resume.countDown(); proxy.removeAdvice(afterLow); }
        assertEquals(before, state(jdbc, fixture), "no identity/session/owner/audit changes on concurrent rejection");
    }

    private static Fixture fixture(ConfigurableApplicationContext context, long low) {
        return fixture(context, low, true);
    }
    private static Fixture fixture(ConfigurableApplicationContext context, long low, boolean corrupt) {
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class);
        String now = Instant.now().toString();
        if (jdbc.queryForObject("select count(*) from specus_management_user where username=?", Integer.class, ADMIN.accountKey()) == 0) {
            for (String key : List.of(ADMIN.accountKey(), "ownership-lock-target-key")) {
                boolean actor = key.equals(ADMIN.accountKey()); String login = actor ? ADMIN.username() : TARGET;
                jdbc.update("insert into specus_management_user(username,tenant_id,login_name,login_name_normalized,password_hash,role,enabled,created_at,updated_at) values (?,'default',?,?,?,?,true,?,?)",
                        key, login, login, PasswordService.hashToken("fixture-password"), actor ? "ADMIN" : "USER", now, now);
            }
        }
        var auth = context.getBean(ClientAuthService.class);
        for (long id : List.of(low, low + 1)) jdbc.update("insert into specus_client_credential(id,tenant_id,owner_username,api_key,secret_hash,enabled,max_online_instances,created_at,updated_at) values (?,'default','old-owner',?,?,true,3,?,?)",
                id, "ownership-lock-key-" + id, PasswordService.hashToken("ownership-lock-secret"), now, now);
        ClientEnvironmentInfo first = environment(low), second = environment(low + 1);
        var a = login(auth, low, first); var b = login(auth, low + 1, second);
        String revision = context.getBean(ClientOwnerTransferService.class).previewCredential(ADMIN, Long.toString(low + 1)).revision();
        if (corrupt) {
            jdbc.update("update specus_client_identity set client_id=?,client_name=? where credential_id=?", a.getClientId(), a.getClientName(), low + 1);
            jdbc.update("update specus_client_session set client_id=?,client_name=? where credential_id=?", a.getClientId(), a.getClientName(), low + 1);
        }
        ObjectNode request = new ObjectMapper().createObjectNode().put("scope", "credential-group")
                .put("targetUsername", TARGET).put("expectedRevision", revision);
        return new Fixture(low, low + 1, a, b, second, request);
    }

    private static void verifyNewMemberAfterDiscovery(ConfigurableApplicationContext context, DataSource independent) throws Exception {
        try (var connection = independent.getConnection()) {
            if (connection.getMetaData().getDatabaseProductName().toLowerCase(java.util.Locale.ROOT).contains("sqlite")) return;
        }
        var fixture = fixture(context, 3_400_000, false);
        var auth = context.getBean(ClientAuthService.class);
        AtomicReference<ClientAuthLoginResponse> created = new AtomicReference<>();
        Advised proxy = assertInstanceOf(Advised.class, context.getBean(ClientCredentialRepository.class));
        Thread submittingThread = Thread.currentThread();
        try (var executor = Executors.newSingleThreadExecutor()) {
            MethodInterceptor beforeSelectedLock = invocation -> {
                if (Thread.currentThread() == submittingThread && invocation.getMethod().getName().equals("lockCurrent")
                        && ((Number) invocation.getArguments()[0]).longValue() == fixture.high() && created.get() == null) {
                    // The writer's actor/target and discovery snapshot are already read. Commit
                    // a genuine HMAC new-device creation on another transaction BEFORE its row lock.
                    created.set(executor.submit(() -> login(auth, fixture.high(), environment(3_400_100))).get(15, TimeUnit.SECONDS));
                }
                return invocation.proceed();
            };
            proxy.addAdvice(0, beforeSelectedLock);
            try {
                var failure = assertThrows(ClientOwnerTransferException.class, () -> context.getBean(ClientOwnerTransferWriter.class)
                        .transferCredential(ADMIN, Long.toString(fixture.high()), fixture.request()));
                assertEquals("TRANSFER_PREVIEW_CHANGED", failure.code());
                assertNotNull(created.get(), "actual independent new-device login must commit");
                assertNotEquals(fixture.second().getClientId(), created.get().getClientId());
            } finally { proxy.removeAdvice(beforeSelectedLock); }
        }
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class);
        var current = context.getBean(ClientOwnerTransferService.class).previewCredential(ADMIN, Long.toString(fixture.high()));
        assertEquals(2, current.affectedClientCount());
        assertTrue(current.affectedClients().stream().anyMatch(client -> client.id() == created.get().getClientId()));
        assertEquals("old-owner", jdbc.queryForObject("select owner_username from specus_client_account where id=?", String.class, created.get().getClientId()));
        assertEquals(0, jdbc.queryForObject("select count(*) from client_owner_transfer_audit where path_id=?", Integer.class, fixture.high()));
    }

    private static ClientEnvironmentInfo environment(long id) {
        ClientEnvironmentInfo environment = new ClientEnvironmentInfo();
        environment.setMachineFingerprint("ownership-lock-machine-" + id); environment.setHostname("ownership-lock-host-" + id);
        environment.setOsUser("lock-user"); return environment;
    }
    private static ClientAuthLoginResponse login(ClientAuthService service, long id, ClientEnvironmentInfo environment) {
        String key = "ownership-lock-key-" + id;
        ClientAuthLoginRequest request = new ClientAuthLoginRequest(); request.setApiKey(key);
        request.setEnvironment(environment); request.setTimestamp(Long.toString(System.currentTimeMillis()));
        request.setNonce(UUID.randomUUID().toString());
        request.setSignature(ClientAuthSigner.signApiKey(key, request.getTimestamp(), request.getNonce(), environment, "ownership-lock-secret"));
        return service.login(request, "localhost");
    }
    private static String state(JdbcTemplate jdbc, Fixture fixture) {
        return jdbc.queryForList("select id,credential_id,client_id,client_name,last_seen_at from specus_client_identity where credential_id in (?,?) order by id", fixture.low(), fixture.high()).toString()
                + jdbc.queryForList("select id,credential_id,client_id,client_name,status from specus_client_session where credential_id in (?,?) order by id", fixture.low(), fixture.high())
                + jdbc.queryForList("select id,owner_username from specus_client_account where id in (?,?) order by id", fixture.first().getClientId(), fixture.second().getClientId())
                + jdbc.queryForObject("select count(*) from client_owner_transfer_audit where path_id=?", Integer.class, fixture.high());
    }
}
