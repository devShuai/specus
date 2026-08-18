package com.theshuai.specusserver.database;

import com.theshuai.specusserver.config.DeploymentEnvironment;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.ClientCredential;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.ClientCredentialRepository;
import com.theshuai.specusserver.security.PasswordService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Disables the credentials created by older releases that seeded a publicly documented client.
 * Records are retained for referential integrity and audit history. A name alone is never enough:
 * the stored digest must still match the shipped {@code test1234} secret, so credentials that an
 * operator rotated are left untouched.
 */
@Slf4j
@Component
public class LegacyDemoCredentialSanitizer {
    static final String DEMO_CLIENT_NAME = "Demo client";
    static final String DEMO_API_KEY = "demo-client";
    static final String DEMO_SECRET = "test1234";

    private final ClientAccountRepository clientAccountRepository;
    private final ClientCredentialRepository clientCredentialRepository;
    private final DeploymentEnvironment environment;

    public LegacyDemoCredentialSanitizer(ClientAccountRepository clientAccountRepository,
                                         ClientCredentialRepository clientCredentialRepository,
                                         @Value("${specus.env:}") String environmentName) {
        this.clientAccountRepository = clientAccountRepository;
        this.clientCredentialRepository = clientCredentialRepository;
        this.environment = DeploymentEnvironment.parse(environmentName);
    }

    /**
     * Applies the production-only migration in its own transaction. Keeping this on a separate
     * Spring bean is intentional: startup invokes {@link DatabaseInitializer} from
     * {@code @PostConstruct}, where a self-invoked transactional method would not be intercepted.
     */
    @Transactional
    public SanitizationResult sanitize() {
        if (!environment.isProd()) {
            return SanitizationResult.NONE;
        }

        String updatedAt = Instant.now().toString();
        int disabledAccounts = disableLegacyAccount(updatedAt);
        int disabledCredentials = disableLegacyCredential(updatedAt);
        if (disabledAccounts > 0 || disabledCredentials > 0) {
            log.warn("[security-baseline] disabled legacy demo credentials: accounts={}, credentials={}",
                    disabledAccounts, disabledCredentials);
        }
        return new SanitizationResult(disabledAccounts, disabledCredentials);
    }

    private int disableLegacyAccount(String updatedAt) {
        ClientAccount account = clientAccountRepository.findByClientName(DEMO_CLIENT_NAME).orElse(null);
        if (account == null
                || !DEMO_CLIENT_NAME.equals(account.getClientName())
                || !account.isEnabled()
                || !PasswordService.tokenMatches(DEMO_SECRET, account.getPasswordHash())) {
            return 0;
        }
        account.setEnabled(false);
        account.setUpdatedAt(updatedAt);
        // Flush here so a failure while updating the credential proves that the surrounding
        // transaction rolls this first update back as well.
        clientAccountRepository.saveAndFlush(account);
        return 1;
    }

    private int disableLegacyCredential(String updatedAt) {
        ClientCredential credential = clientCredentialRepository.findByApiKey(DEMO_API_KEY).orElse(null);
        if (credential == null
                || !DEMO_API_KEY.equals(credential.getApiKey())
                || !credential.isEnabled()
                || !PasswordService.tokenMatches(DEMO_SECRET, credential.getSecretHash())) {
            return 0;
        }
        credential.setEnabled(false);
        credential.setUpdatedAt(updatedAt);
        clientCredentialRepository.saveAndFlush(credential);
        return 1;
    }

    public record SanitizationResult(int disabledAccounts, int disabledCredentials) {
        private static final SanitizationResult NONE = new SanitizationResult(0, 0);
    }
}
