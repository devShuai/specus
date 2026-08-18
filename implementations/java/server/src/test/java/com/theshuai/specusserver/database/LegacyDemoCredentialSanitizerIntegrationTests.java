package com.theshuai.specusserver.database;

import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.ClientCredential;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.ClientCredentialRepository;
import com.theshuai.specusserver.security.PasswordService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {
                "spring.datasource.url=jdbc:sqlite:file:target/test-legacy-demo-sanitizer?mode=memory&cache=shared",
                "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "specus.env=prod",
                "specus.database.seed-demo-client=false",
                "specus.netty.port=0"
        }
)
class LegacyDemoCredentialSanitizerIntegrationTests {
    private static final String ROTATED_SECRET = "a-unique-rotated-secret";

    @Autowired private LegacyDemoCredentialSanitizer sanitizer;
    @Autowired private ClientAccountRepository clientAccountRepository;
    @Autowired private ClientCredentialRepository clientCredentialRepository;
    @Autowired private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void setUp() {
        dropFailureTrigger();
        clientCredentialRepository.deleteAll();
        clientAccountRepository.deleteAll();
    }

    @AfterEach
    void tearDown() {
        dropFailureTrigger();
    }

    @Test
    void prodDisablesOnlyExactPublishedCredentialsAndIsIdempotent() {
        saveAccount(1L, LegacyDemoCredentialSanitizer.DEMO_CLIENT_NAME,
                LegacyDemoCredentialSanitizer.DEMO_SECRET);
        saveAccount(2L, "operator-client", LegacyDemoCredentialSanitizer.DEMO_SECRET);
        saveCredential(11L, LegacyDemoCredentialSanitizer.DEMO_API_KEY,
                LegacyDemoCredentialSanitizer.DEMO_SECRET);
        saveCredential(12L, "operator-key", LegacyDemoCredentialSanitizer.DEMO_SECRET);

        var first = sanitizer.sanitize();

        assertThat(first.disabledAccounts()).isEqualTo(1);
        assertThat(first.disabledCredentials()).isEqualTo(1);
        assertThat(clientAccountRepository.findByClientName(LegacyDemoCredentialSanitizer.DEMO_CLIENT_NAME))
                .get().extracting(ClientAccount::isEnabled).isEqualTo(false);
        assertThat(clientCredentialRepository.findByApiKey(LegacyDemoCredentialSanitizer.DEMO_API_KEY))
                .get().extracting(ClientCredential::isEnabled).isEqualTo(false);
        assertThat(clientAccountRepository.findByClientName("operator-client"))
                .get().extracting(ClientAccount::isEnabled).isEqualTo(true);
        assertThat(clientCredentialRepository.findByApiKey("operator-key"))
                .get().extracting(ClientCredential::isEnabled).isEqualTo(true);

        var second = sanitizer.sanitize();
        assertThat(second.disabledAccounts()).isZero();
        assertThat(second.disabledCredentials()).isZero();
    }

    @Test
    void prodLeavesRotatedDemoIdentifiersEnabled() {
        saveAccount(1L, LegacyDemoCredentialSanitizer.DEMO_CLIENT_NAME, ROTATED_SECRET);
        saveCredential(11L, LegacyDemoCredentialSanitizer.DEMO_API_KEY, ROTATED_SECRET);

        var result = sanitizer.sanitize();

        assertThat(result.disabledAccounts()).isZero();
        assertThat(result.disabledCredentials()).isZero();
        assertThat(clientAccountRepository.findByClientName(LegacyDemoCredentialSanitizer.DEMO_CLIENT_NAME))
                .get().extracting(ClientAccount::isEnabled).isEqualTo(true);
        assertThat(clientCredentialRepository.findByApiKey(LegacyDemoCredentialSanitizer.DEMO_API_KEY))
                .get().extracting(ClientCredential::isEnabled).isEqualTo(true);
    }

    @Test
    void devAndTestLeavePublishedCredentialsEnabled() {
        saveAccount(1L, LegacyDemoCredentialSanitizer.DEMO_CLIENT_NAME,
                LegacyDemoCredentialSanitizer.DEMO_SECRET);
        saveCredential(11L, LegacyDemoCredentialSanitizer.DEMO_API_KEY,
                LegacyDemoCredentialSanitizer.DEMO_SECRET);

        var devResult = new LegacyDemoCredentialSanitizer(
                clientAccountRepository, clientCredentialRepository, "dev").sanitize();
        var testResult = new LegacyDemoCredentialSanitizer(
                clientAccountRepository, clientCredentialRepository, "test").sanitize();

        assertThat(devResult.disabledAccounts()).isZero();
        assertThat(devResult.disabledCredentials()).isZero();
        assertThat(testResult.disabledAccounts()).isZero();
        assertThat(testResult.disabledCredentials()).isZero();
        assertThat(clientAccountRepository.findByClientName(LegacyDemoCredentialSanitizer.DEMO_CLIENT_NAME))
                .get().extracting(ClientAccount::isEnabled).isEqualTo(true);
        assertThat(clientCredentialRepository.findByApiKey(LegacyDemoCredentialSanitizer.DEMO_API_KEY))
                .get().extracting(ClientCredential::isEnabled).isEqualTo(true);
    }

    @Test
    void failureDisablingCredentialRollsBackAccountUpdate() {
        saveAccount(1L, LegacyDemoCredentialSanitizer.DEMO_CLIENT_NAME,
                LegacyDemoCredentialSanitizer.DEMO_SECRET);
        saveCredential(11L, LegacyDemoCredentialSanitizer.DEMO_API_KEY,
                LegacyDemoCredentialSanitizer.DEMO_SECRET);
        jdbcTemplate.execute("""
                create trigger fail_legacy_demo_credential_update
                before update of enabled on specus_client_credential
                when new.api_key = 'demo-client' and new.enabled = 0
                begin
                  select raise(abort, 'forced sanitizer failure');
                end
                """);

        assertThatThrownBy(sanitizer::sanitize).isInstanceOf(RuntimeException.class);

        assertThat(enabledValue("specus_client_account", "client_name", "Demo client")).isEqualTo(1);
        assertThat(enabledValue("specus_client_credential", "api_key", "demo-client")).isEqualTo(1);
    }

    private void saveAccount(long id, String name, String secret) {
        String now = Instant.now().toString();
        ClientAccount account = new ClientAccount();
        account.setId(id);
        account.setTenantId("default");
        account.setOwnerUsername("admin");
        account.setClientName(name);
        account.setPasswordHash(PasswordService.hashToken(secret));
        account.setEnabled(true);
        account.setConnectionRateLimitPerMinute(30);
        account.setCreatedAt(now);
        account.setUpdatedAt(now);
        clientAccountRepository.saveAndFlush(account);
    }

    private void saveCredential(long id, String apiKey, String secret) {
        String now = Instant.now().toString();
        ClientCredential credential = new ClientCredential();
        credential.setId(id);
        credential.setTenantId("default");
        credential.setOwnerUsername("admin");
        credential.setApiKey(apiKey);
        credential.setSecretHash(PasswordService.hashToken(secret));
        credential.setEnabled(true);
        credential.setMaxOnlineInstances(2);
        credential.setCreatedAt(now);
        credential.setUpdatedAt(now);
        clientCredentialRepository.saveAndFlush(credential);
    }

    private int enabledValue(String table, String keyColumn, String key) {
        Integer value = jdbcTemplate.queryForObject(
                "select enabled from " + table + " where " + keyColumn + " = ?",
                Integer.class,
                key);
        return value == null ? -1 : value;
    }

    private void dropFailureTrigger() {
        jdbcTemplate.execute("drop trigger if exists fail_legacy_demo_credential_update");
    }
}
