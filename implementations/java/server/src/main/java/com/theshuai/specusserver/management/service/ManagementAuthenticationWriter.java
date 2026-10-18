package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.model.ManagementUser;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.management.security.ManagementWriteAuthority;
import com.theshuai.specusserver.security.PasswordService;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

/** Short, fresh account write transactions. CPU password derivation and retries belong outside
 * these locks; no stale full-entity password save or login-name based account resurrection. */
@Component
@Transactional(propagation = Propagation.REQUIRES_NEW)
public class ManagementAuthenticationWriter {
    @PersistenceContext private EntityManager entities;
    private final ManagementUserRepository users;
    private final ManagementWriteAuthority authority;

    public ManagementAuthenticationWriter(ManagementUserRepository users, ManagementWriteAuthority authority) {
        this.users = users; this.authority = authority;
    }

    /** End the reader's EntityManager/connection BEFORE CPU verification and the writer. An
     * untransactional query inside NOT_SUPPORTED synchronization can otherwise retain the only
     * SQLite pool connection while REQUIRES_NEW waits for that same connection. */
    @Transactional(propagation = Propagation.REQUIRES_NEW, readOnly = true)
    public Optional<ManagementUser> passwordCandidate(String normalized, String requestedTenant, String defaultTenant) {
        String nameKey = normalized.toLowerCase(Locale.ROOT);
        if (requestedTenant != null) return users.findByTenantIdAndLoginNameNormalized(requestedTenant, nameKey);
        return users.findByTenantIdAndLoginNameNormalized(defaultTenant, nameKey).or(() -> {
            var matches = users.findAllByUsernameIgnoreCase(normalized);
            return matches.size() == 1 ? Optional.of(matches.getFirst()) : Optional.empty();
        });
    }

    public PasswordResult acceptPassword(String key, String tenant, String login, String expectedHash, String upgradedHash) {
        var candidate = authority.lockCurrentAccount(key, tenant)
                .filter(ManagementUser::isEnabled).filter(user -> login.equals(canonicalLogin(user)));
        if (candidate.isEmpty()) return new PasswordResult(PasswordState.DENIED, null);
        ManagementUser current = candidate.get();
        if (!expectedHash.equals(current.getPasswordHash()))
            return new PasswordResult(PasswordState.REVERIFY, current);
        if (upgradedHash != null) {
            // The locked proof is current. Touch ONLY this column, never old role/enabled/OIDC
            // fields. A failed optional upgrade rolls this whole fresh transaction back.
            entities.createNativeQuery("""
                    update specus_management_user set password_hash=?1
                     where username=?2 and tenant_id=?3 and password_hash=?4
                    """).setParameter(1, upgradedHash).setParameter(2, key).setParameter(3, tenant)
                    .setParameter(4, expectedHash).executeUpdate();
            current.setPasswordHash(upgradedHash);
        }
        return new PasswordResult(PasswordState.ACCEPTED, current);
    }

    public OidcResult resolveOidc(String issuer, String subject, String identityKey,
                                  String preferred, String tenant, boolean allowProvision) {
        // SQLite must reserve its writer before its first snapshot read. Row-locking providers
        // lock only the selected account, not the whole tenant or unrelated client logins.
        authority.reserveWriter();
        var bound = users.findByOidcIdentityKey(identityKey);
        if (bound.isPresent()) {
            ManagementUser selected = bound.get();
            return new OidcResult(true, authority.lockCurrentAccount(selected.getUsername(), selected.getTenantId())
                    .filter(ManagementUser::isEnabled).filter(user -> sameIdentity(user, issuer, subject, identityKey)));
        }
        var imported = users.findByTenantIdAndLoginNameNormalized(tenant, preferred.toLowerCase(Locale.ROOT));
        if (imported.isPresent()) {
            ManagementUser selected = imported.get();
            String selectedLogin = canonicalLogin(selected);
            var locked = authority.lockCurrentAccount(selected.getUsername(), tenant)
                    .filter(ManagementUser::isEnabled).filter(user -> selectedLogin.equals(canonicalLogin(user)))
                    .filter(user -> preferred.toLowerCase(Locale.ROOT).equals(user.getLoginNameNormalized()));
            if (locked.isEmpty()) return new OidcResult(true, Optional.empty());
            ManagementUser current = locked.get();
            if (StringUtils.hasText(current.getOidcIssuer()) || StringUtils.hasText(current.getOidcSubject())
                    || StringUtils.hasText(current.getOidcIdentityKey()))
                return new OidcResult(true, sameIdentity(current, issuer, subject, identityKey) ? locked : Optional.empty());
            users.bindOidcIdentityIfUnbound(current.getUsername(), issuer, subject, identityKey, Instant.now().toString());
            return new OidcResult(true, authority.lockCurrentAccount(current.getUsername(), tenant)
                    .filter(ManagementUser::isEnabled).filter(user -> selectedLogin.equals(canonicalLogin(user)))
                    .filter(user -> sameIdentity(user, issuer, subject, identityKey)));
        }
        if (!allowProvision) return new OidcResult(false, Optional.empty());
        String now = Instant.now().toString();
        ManagementUser created = new ManagementUser();
        created.setUsername(UUID.randomUUID().toString()); created.setTenantId(tenant);
        created.setLoginName(preferred); created.setLoginNameNormalized(preferred.toLowerCase(Locale.ROOT));
        created.setPasswordHash(PasswordService.hash(PasswordService.generatePassword()));
        created.setOidcIssuer(issuer); created.setOidcSubject(subject); created.setOidcIdentityKey(identityKey);
        created.setRole(ManagementRole.USER); created.setEnabled(true); created.setCreatedAt(now); created.setUpdatedAt(now);
        // Materialize unique alias/identity conflicts before returning; the caller may resolve
        // a committed race winner only AFTER this transaction rolls back, never inside it.
        return new OidcResult(false, Optional.of(users.saveAndFlush(created)));
    }

    private static String canonicalLogin(ManagementUser user) {
        return StringUtils.hasText(user.getLoginName()) ? user.getLoginName() : user.getUsername();
    }

    private static boolean sameIdentity(ManagementUser user, String issuer, String subject, String key) {
        return key.equals(user.getOidcIdentityKey()) && issuer.equals(user.getOidcIssuer()) && subject.equals(user.getOidcSubject());
    }

    public enum PasswordState { ACCEPTED, REVERIFY, DENIED }
    public record PasswordResult(PasswordState state, ManagementUser account) {}
    public record OidcResult(boolean existingAccount, Optional<ManagementUser> account) {}
}
