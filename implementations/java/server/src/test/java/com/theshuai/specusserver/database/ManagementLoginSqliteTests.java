package com.theshuai.specusserver.database;

import com.theshuai.specusserver.management.service.ManagementUserService;
import com.theshuai.specusserver.security.PasswordService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import java.time.Instant;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

/** The supported SQLite default pool remains ONE connection; no pool-size workaround. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "spring.datasource.url=" + ManagementLoginSqliteTests.URL,
        "spring.datasource.hikari.maximum-pool-size=1", "spring.jpa.hibernate.ddl-auto=create-drop",
        "specus.netty.port=0", "specus.database.seed-demo-client=false"
})
@Import(ManagementLoginAssertions.ProofConfiguration.class)
class ManagementLoginSqliteTests {
    static final String URL = "jdbc:sqlite:file:target/test-management-login?mode=memory&cache=shared";
    @Autowired ConfigurableApplicationContext context;
    @Autowired JdbcTemplate jdbc;
    @Autowired ManagementUserService users;
    @Autowired ManagementLoginAssertions.AccountObservation observer;

    @BeforeEach
    void reset() {
        observer.clear();
        jdbc.execute("drop trigger if exists management_login_upgrade_failure");
        jdbc.update("delete from specus_management_user");
    }

    @Test
    void currentAccountAndActualLegacyUpgradeUseSeparateReleasedReaderAndWriterTransactions() {
        ManagementLoginAssertions.verifyPasswordCases(context, new DriverManagerDataSource(URL));
    }

    @Test
    void concurrentLegitimateLegacyLoginsBothSucceedWithoutHoldingTheOnlyConnectionDuringCpuWork() throws Exception {
        ManagementLoginAssertions.verifyConcurrentPasswords(context, new DriverManagerDataSource(URL));
    }

    @Test
    void optionalUpgradeFailureRollsBackThenAuthenticatesAgainstTheSameCurrentAccount() {
        seed("failure-user");
        failPasswordWrites();
        try {
            var failure = assertThrows(DataAccessException.class, () -> jdbc.update(
                    "update specus_management_user set password_hash='probe' where username='failure-user'"));
            assertTrue(root(failure).getMessage().contains("intentional management password upgrade failure"));
            assertEquals("failure-user", users.authenticate("failure-user", "Failure-password-1", "default").orElseThrow().accountKey());
            assertEquals(PasswordService.hashToken("Failure-password-1"), jdbc.queryForObject(
                    "select password_hash from specus_management_user where username='failure-user'", String.class));
        } finally { jdbc.execute("drop trigger if exists management_login_upgrade_failure"); }
        assertTrue(users.authenticate("failure-user", "Failure-password-1", "default").isPresent());
        assertTrue(jdbc.queryForObject("select password_hash from specus_management_user where username='failure-user'", String.class).startsWith("$pbkdf2-sha256$"));
    }

    @Test
    void optionalUpgradeFailureMustNotBypassAConcurrentDisableBeforeItsFallback() {
        seed("failure-revoked-user");
        failPasswordWrites();
        observer.once("failure-revoked-user", 2, () -> {
            JdbcTemplate independent = new JdbcTemplate(new DriverManagerDataSource(URL));
            assertEquals(1, independent.update("update specus_management_user set enabled=false where username='failure-revoked-user'"));
        });
        try {
            assertTrue(users.authenticate("failure-revoked-user", "Failure-password-1", "default").isEmpty());
            assertFalse(jdbc.queryForObject("select enabled from specus_management_user where username='failure-revoked-user'", Boolean.class));
        } finally { observer.clear(); jdbc.execute("drop trigger if exists management_login_upgrade_failure"); }
    }

    @Test
    void incorrectPasswordNeverChangesTheHashOrReturnsAnAccount() {
        seed("wrong-password-user");
        assertTrue(users.authenticate("wrong-password-user", "Incorrect-password", "default").isEmpty());
        assertEquals(PasswordService.hashToken("Failure-password-1"), jdbc.queryForObject(
                "select password_hash from specus_management_user where username='wrong-password-user'", String.class));
    }

    @Test
    void oidcImportBindsOnlyOnceAndRejectsASecondImmutableIdentityOrCorruptBindingFields() {
        seed("oidc-import-user");
        var first = users.resolveOrProvisionOidcUser("https://sqlite-oidc.invalid", "first-subject", "oidc-import-user").orElseThrow();
        assertEquals("oidc-import-user", first.accountKey());
        assertEquals(first.accountKey(), users.resolveOrProvisionOidcUser("https://sqlite-oidc.invalid", "first-subject", "renamed-profile").orElseThrow().accountKey());
        assertTrue(users.resolveOrProvisionOidcUser("https://sqlite-oidc.invalid", "second-subject", "oidc-import-user").isEmpty());
        jdbc.update("update specus_management_user set oidc_subject='corrupt-subject' where username='oidc-import-user'");
        assertTrue(users.resolveOrProvisionOidcUser("https://sqlite-oidc.invalid", "first-subject", "oidc-import-user").isEmpty());
        assertTrue(users.resolveBoundOidcUser("https://sqlite-oidc.invalid", "first-subject").isEmpty());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void concurrentOidcFirstLoginsSerializeSafelyOnTheSingleConnectionPool(boolean sameIdentity) throws Exception {
        CyclicBarrier start = new CyclicBarrier(2);
        try (var workers = Executors.newFixedThreadPool(2)) {
            var first = workers.submit(() -> { start.await(10, TimeUnit.SECONDS); return users.resolveOrProvisionOidcUser("https://sqlite-race.invalid", "first", "sqlite-race-user"); });
            var second = workers.submit(() -> { start.await(10, TimeUnit.SECONDS); return users.resolveOrProvisionOidcUser("https://sqlite-race.invalid", sameIdentity ? "first" : "second", "sqlite-race-user"); });
            var one = first.get(15, TimeUnit.SECONDS); var two = second.get(15, TimeUnit.SECONDS);
            assertEquals(sameIdentity ? 2 : 1, (one.isPresent() ? 1 : 0) + (two.isPresent() ? 1 : 0));
            if (sameIdentity) assertEquals(one.get().accountKey(), two.get().accountKey());
            assertEquals(1, jdbc.queryForObject("select count(*) from specus_management_user where login_name_normalized='sqlite-race-user'", Integer.class));
        }
    }

    private void seed(String key) {
        String now = Instant.now().toString();
        jdbc.update("insert into specus_management_user(username,tenant_id,login_name,login_name_normalized,password_hash,role,enabled,created_at,updated_at) values (?,'default',?,?,?,'USER',true,?,?)",
                key, key, key, PasswordService.hashToken("Failure-password-1"), now, now);
    }

    private void failPasswordWrites() {
        jdbc.execute("create trigger management_login_upgrade_failure before update of password_hash on specus_management_user begin select raise(abort,'intentional management password upgrade failure'); end");
    }

    private static Throwable root(Throwable failure) {
        while (failure.getCause() != null) failure = failure.getCause();
        return failure;
    }
}
