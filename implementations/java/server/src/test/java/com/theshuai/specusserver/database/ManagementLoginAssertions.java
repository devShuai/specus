package com.theshuai.specusserver.database;

import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.service.ManagementPasswordVerifier;
import com.theshuai.specusserver.management.service.ManagementUserService;
import com.theshuai.specusserver.management.model.ManagementUser;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.management.security.ManagementWriteAuthority;
import com.theshuai.specusserver.config.AuthProperties;
import org.springframework.aop.framework.Advised;
import org.aopalliance.intercept.MethodInterceptor;
import com.theshuai.specusserver.security.PasswordService;
import org.junit.jupiter.api.function.Executable;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.time.Instant;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.Optional;
import java.util.function.BiConsumer;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static org.junit.jupiter.api.Assertions.*;

/** Real password derivation and repositories. Only the deterministic observation boundary after
 * real CPU verification is controlled; the independent connection commits actual row changes. */
final class ManagementLoginAssertions {
    @TestConfiguration(proxyBeanMethods = false)
    static class ProofConfiguration {
        @Bean @Primary ControlledVerifier observedManagementPasswordVerifier() { return new ControlledVerifier(); }
        @Bean AccountObservation accountObservation() { return new AccountObservation(); }
        @Bean @Primary ControlledAuthority observedManagementWriteAuthority(AuthProperties auth, AccountObservation observer) {
            return new ControlledAuthority(auth, observer);
        }
    }

    static class AccountObservation {
        private record Pending(String key, AtomicInteger remaining, Runnable action) {}
        private final AtomicReference<Pending> pending = new AtomicReference<>();
        void once(String key, int occurrence, Runnable action) {
            assertTrue(pending.compareAndSet(null, new Pending(key, new AtomicInteger(occurrence), action)));
        }
        void before(String key) {
            Pending selected = pending.get();
            if (selected != null && selected.key().equals(key) && selected.remaining().decrementAndGet() == 0
                    && pending.compareAndSet(selected, null)) selected.action().run();
        }
        void clear() { pending.set(null); }
    }

    static class ControlledAuthority extends ManagementWriteAuthority {
        private final AccountObservation observer;
        ControlledAuthority(AuthProperties auth, AccountObservation observer) { super(auth); this.observer = observer; }
        @Override public Optional<ManagementUser> lockCurrentAccount(String key, String tenant) {
            observer.before(key);
            return super.lockCurrentAccount(key, tenant);
        }
    }

    static class ControlledVerifier extends ManagementPasswordVerifier {
        private final AtomicReference<Runnable> afterVerification = new AtomicReference<>();
        private final AtomicReference<BiConsumer<String, PasswordService.Verification>> during = new AtomicReference<>();
        void once(Runnable action) { assertTrue(afterVerification.compareAndSet(null, action)); }
        void during(BiConsumer<String, PasswordService.Verification> action) { assertTrue(during.compareAndSet(null, action)); }
        void clear() { afterVerification.set(null); during.set(null); }
        @Override public PasswordService.Verification verify(String password, String hash) {
            var result = super.verify(password, hash);
            Runnable observation = afterVerification.getAndSet(null);
            if (observation != null) { assertTrue(result.matches(), "must finish real password verification first"); observation.run(); }
            var repeated = during.get();
            if (repeated != null) repeated.accept(hash, result);
            return result;
        }
    }

    static void verify(ConfigurableApplicationContext context, DataSource independent, boolean mysql) throws Exception {
        verifyPasswordCases(context, independent);
        verifyOidcCurrentAccount(context, independent);
        verifyConcurrentPasswords(context, independent);
        verifyConcurrentOidc(context, independent);
        verifyOptionalUpgradeFailure(context, independent, mysql);
    }

    static void verifyPasswordCases(ConfigurableApplicationContext context, DataSource independent) {
        var service = context.getBean(ManagementUserService.class);
        var verifier = context.getBean(ControlledVerifier.class);
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class), writer = new JdbcTemplate(independent);
        ArrayList<Executable> cases = new ArrayList<>();
        for (int mutation = 0; mutation < 8; mutation++) {
            int selected = mutation;
            cases.add(() -> {
                String key = "login-key-" + selected, login = "login-user-" + selected, password = "Login-password-1";
                String now = Instant.now().toString();
                jdbc.update("insert into specus_management_user(username,tenant_id,login_name,login_name_normalized,password_hash,role,enabled,created_at,updated_at) values (?,'default',?,?,?,'ADMIN',true,?,?)",
                        key, login, login, PasswordService.hashToken(password), now, now);
                verifier.once(() -> {
                    String sql = switch (selected) {
                        case 0 -> "update specus_management_user set role='USER' where username=?";
                        case 1 -> "update specus_management_user set enabled=false where username=?";
                        case 2 -> "delete from specus_management_user where username=?";
                        case 3 -> "update specus_management_user set username='replacement-login-key' where username=?";
                        case 4 -> "update specus_management_user set tenant_id='foreign' where username=?";
                        case 5 -> "update specus_management_user set login_name='renamed-login-user',login_name_normalized='renamed-login-user' where username=?";
                        case 6 -> "update specus_management_user set password_hash='" + PasswordService.hashToken("Different-password-1") + "' where username=?";
                        default -> "update specus_management_user set oidc_issuer='https://login-fixture.invalid',oidc_subject='linked-subject',oidc_identity_key='" + "c".repeat(64) + "' where username=?";
                    };
                    assertEquals(1, writer.update(sql, key));
                });
                try {
                    var result = service.authenticate(login, password, "default");
                    if (selected == 0 || selected == 7) {
                        assertTrue(result.isPresent());
                        assertEquals(selected == 0 ? ManagementRole.USER : ManagementRole.ADMIN, result.orElseThrow().role());
                        assertTrue(writer.queryForObject("select password_hash from specus_management_user where username=?", String.class, key).startsWith("$pbkdf2-sha256$"), "successful legacy login must actually persist its hash upgrade");
                    } else assertTrue(result.isEmpty(), "a proof for a revoked/replaced/renamed/moved/reset account cannot mint a fresh login");
                    if (selected == 2 || selected == 3)
                        assertEquals(0, writer.queryForObject("select count(*) from specus_management_user where username=?", Integer.class, key), "never recreate the old account key");
                    if (selected == 6)
                        assertEquals(PasswordService.hashToken("Different-password-1"), writer.queryForObject("select password_hash from specus_management_user where username=?", String.class, key));
                    if (selected == 7) {
                        assertEquals("linked-subject", writer.queryForObject("select oidc_subject from specus_management_user where username=?", String.class, key));
                        assertEquals("c".repeat(64), writer.queryForObject("select oidc_identity_key from specus_management_user where username=?", String.class, key));
                    }
                } finally { verifier.clear(); }
            });
        }
        assertAll("actual password proof versus current account", cases);
    }

    private static void verifyOidcCurrentAccount(ConfigurableApplicationContext context, DataSource independent) {
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class), writer = new JdbcTemplate(independent);
        var service = context.getBean(ManagementUserService.class);
        var observer = context.getBean(AccountObservation.class);
        ArrayList<Executable> cases = new ArrayList<>();
        for (boolean bound : new boolean[]{true, false}) for (int mutation = 0; mutation < 8; mutation++) {
            int selected = mutation;
            cases.add(() -> {
                String suffix = (bound ? "bound-" : "import-") + selected;
                String key = "oidc-key-" + suffix, login = "oidc-user-" + suffix;
                String issuer = "https://oidc-login-fixture.invalid", subject = "subject-" + suffix;
                String identity = identityKey(issuer, subject), now = Instant.now().toString();
                jdbc.update("insert into specus_management_user(username,tenant_id,login_name,login_name_normalized,password_hash,role,enabled,created_at,updated_at,oidc_issuer,oidc_subject,oidc_identity_key) values (?,'default',?,?,?,'ADMIN',true,?,?,?,?,?)",
                        key, login, login, PasswordService.hashToken("Oidc-password"), now, now,
                        bound ? issuer : null, bound ? subject : null, bound ? identity : null);
                observer.once(key, 1, () -> {
                    String sql = switch (selected) {
                        case 0 -> "update specus_management_user set role='USER' where username=?";
                        case 1 -> "update specus_management_user set enabled=false where username=?";
                        case 2 -> "delete from specus_management_user where username=?";
                        case 3 -> "update specus_management_user set username='replacement-" + suffix + "' where username=?";
                        case 4 -> "update specus_management_user set tenant_id='foreign' where username=?";
                        case 5 -> "update specus_management_user set login_name='renamed-" + suffix + "',login_name_normalized='renamed-" + suffix + "' where username=?";
                        case 6 -> "update specus_management_user set oidc_issuer='https://other-issuer.invalid',oidc_subject='other',oidc_identity_key='" + identityKey("https://other-issuer.invalid", suffix) + "' where username=?";
                        default -> "update specus_management_user set oidc_issuer='https://corrupt-issuer.invalid',oidc_subject='corrupt',oidc_identity_key='" + identity + "' where username=?";
                    };
                    assertEquals(1, writer.update(sql, key));
                });
                try {
                    var result = service.resolveOrProvisionOidcUser(issuer, subject, bound ? login + "-profile-renamed" : login);
                    if (selected == 0 || (selected == 5 && bound)) {
                        assertTrue(result.isPresent());
                        assertEquals(selected == 0 ? ManagementRole.USER : ManagementRole.ADMIN, result.get().role());
                        assertEquals(selected == 5 ? "renamed-" + suffix : login, result.get().username());
                        assertEquals(key, result.get().accountKey());
                    } else assertTrue(result.isEmpty(), "old OIDC lookup cannot authorize a revoked/replaced/moved/conflicting current binding");
                    assertEquals(selected == 2 ? 0 : 1, writer.queryForObject("select count(*) from specus_management_user where username in (?,?)", Integer.class, key, "replacement-" + suffix));
                } finally { observer.clear(); }
            });
        }
        assertAll("bound/imported OIDC proof versus current locked account", cases);
    }

    static void verifyConcurrentPasswords(ConfigurableApplicationContext context, DataSource independent) throws Exception {
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class), writer = new JdbcTemplate(independent);
        var service = context.getBean(ManagementUserService.class);
        var verifier = context.getBean(ControlledVerifier.class);
        String legacy = PasswordService.hashToken("Concurrent-password-1"), now = Instant.now().toString();
        jdbc.update("insert into specus_management_user(username,tenant_id,login_name,login_name_normalized,password_hash,role,enabled,created_at,updated_at) values ('concurrent-password-key','default','concurrent-password','concurrent-password',?,'USER',true,?,?)", legacy, now, now);
        CyclicBarrier verified = new CyclicBarrier(2);
        verifier.during((hash, proof) -> {
            assertFalse(TransactionSynchronizationManager.isActualTransactionActive(), "password CPU must not hold a reader or writer transaction");
            if (hash.equals(legacy)) try { verified.await(10, TimeUnit.SECONDS); }
            catch (Exception failure) { throw new AssertionError(failure); }
        });
        try (var workers = Executors.newFixedThreadPool(2)) {
            var first = workers.submit(() -> service.authenticate("concurrent-password", "Concurrent-password-1", "default"));
            var second = workers.submit(() -> service.authenticate("concurrent-password", "Concurrent-password-1", "default"));
            assertEquals("concurrent-password-key", first.get(15, TimeUnit.SECONDS).orElseThrow().accountKey());
            assertEquals("concurrent-password-key", second.get(15, TimeUnit.SECONDS).orElseThrow().accountKey());
        } finally { verifier.clear(); }
        String upgraded = writer.queryForObject("select password_hash from specus_management_user where username='concurrent-password-key'", String.class);
        assertTrue(upgraded.startsWith("$pbkdf2-sha256$"));
        assertTrue(service.authenticate("concurrent-password", "Concurrent-password-1", "default").isPresent());
        assertEquals(upgraded, writer.queryForObject("select password_hash from specus_management_user where username='concurrent-password-key'", String.class), "current-cost hashes must not be rewritten");
    }

    private static void verifyConcurrentOidc(ConfigurableApplicationContext context, DataSource independent) throws Exception {
        var service = context.getBean(ManagementUserService.class);
        JdbcTemplate writer = new JdbcTemplate(independent);
        var repository = context.getBean(ManagementUserRepository.class);
        Advised proxy = assertInstanceOf(Advised.class, repository);
        for (boolean sameIdentity : new boolean[]{true, false}) {
            String login = sameIdentity ? "concurrent-oidc-same" : "concurrent-oidc-different";
            CyclicBarrier insert = new CyclicBarrier(2);
            MethodInterceptor boundary = invocation -> {
                if (invocation.getMethod().getName().equals("saveAndFlush") && invocation.getArguments()[0] instanceof ManagementUser user
                        && login.equals(user.getLoginName())) insert.await(10, TimeUnit.SECONDS);
                return invocation.proceed();
            };
            proxy.addAdvice(boundary);
            try (var workers = Executors.newFixedThreadPool(2)) {
                var first = workers.submit(() -> service.resolveOrProvisionOidcUser("https://concurrent-oidc.invalid", "subject-" + login, login));
                var second = workers.submit(() -> service.resolveOrProvisionOidcUser("https://concurrent-oidc.invalid", sameIdentity ? "subject-" + login : "competing-" + login, login));
                var one = first.get(15, TimeUnit.SECONDS); var two = second.get(15, TimeUnit.SECONDS);
                assertEquals(sameIdentity ? 2 : 1, (one.isPresent() ? 1 : 0) + (two.isPresent() ? 1 : 0));
                if (sameIdentity) assertEquals(one.orElseThrow().accountKey(), two.orElseThrow().accountKey());
                assertEquals(1, writer.queryForObject("select count(*) from specus_management_user where tenant_id='default' and login_name_normalized=?", Integer.class, login));
            } finally { proxy.removeAdvice(boundary); }
        }
    }

    private static String identityKey(String issuer, String subject) {
        return PasswordService.hashToken(issuer + "\0" + subject);
    }

    private static void verifyOptionalUpgradeFailure(ConfigurableApplicationContext context, DataSource independent,
                                                     boolean mysql) {
        JdbcTemplate writer = new JdbcTemplate(independent);
        var service = context.getBean(ManagementUserService.class);
        var observer = context.getBean(AccountObservation.class);
        String now = Instant.now().toString();
        for (int index = 0; index < 2; index++) {
            String key = "provider-upgrade-failure-" + index;
            writer.update("insert into specus_management_user(username,tenant_id,login_name,login_name_normalized,password_hash,role,enabled,created_at,updated_at) values (?,'default',?,?,?,'USER',true,?,?)",
                    key, key, key, PasswordService.hashToken("Upgrade-failure-password-1"), now, now);
        }
        if (mysql) writer.execute("""
                create trigger management_login_upgrade_failure before update on specus_management_user for each row
                begin if new.password_hash <> old.password_hash then
                  signal sqlstate '45000' set message_text='intentional management password upgrade failure';
                end if; end
                """);
        else {
            writer.execute("""
                    create function management_login_upgrade_fail() returns trigger language plpgsql as $$
                    begin if new.password_hash is distinct from old.password_hash then
                      raise exception 'intentional management password upgrade failure';
                    end if; return new; end $$
                    """);
            writer.execute("create trigger management_login_upgrade_failure before update on specus_management_user for each row execute function management_login_upgrade_fail()");
        }
        try {
            var failure = assertThrows(org.springframework.dao.DataAccessException.class, () -> writer.update(
                    "update specus_management_user set password_hash='probe' where username='provider-upgrade-failure-0'"));
            Throwable root = failure; while (root.getCause() != null) root = root.getCause();
            assertTrue(root.getMessage().contains("intentional management password upgrade failure"));
            assertTrue(service.authenticate("provider-upgrade-failure-0", "Upgrade-failure-password-1", "default").isPresent());
            assertEquals(PasswordService.hashToken("Upgrade-failure-password-1"), writer.queryForObject(
                    "select password_hash from specus_management_user where username='provider-upgrade-failure-0'", String.class));
            observer.once("provider-upgrade-failure-1", 2, () -> assertEquals(1, writer.update(
                    "update specus_management_user set enabled=false where username='provider-upgrade-failure-1'")));
            assertTrue(service.authenticate("provider-upgrade-failure-1", "Upgrade-failure-password-1", "default").isEmpty());
            assertFalse(writer.queryForObject("select enabled from specus_management_user where username='provider-upgrade-failure-1'", Boolean.class));
        } finally {
            observer.clear();
            writer.execute(mysql ? "drop trigger management_login_upgrade_failure"
                    : "drop trigger management_login_upgrade_failure on specus_management_user");
            if (!mysql) writer.execute("drop function management_login_upgrade_fail()");
        }
    }
}
