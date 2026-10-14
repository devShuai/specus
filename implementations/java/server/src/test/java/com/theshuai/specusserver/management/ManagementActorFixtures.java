package com.theshuai.specusserver.management;

import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.model.ManagementUser;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import java.time.Instant;
import java.util.Locale;
import java.util.UUID;

/** Bootstrap a real, account-key-bound fixture administrator instead of forging a context role.
 * Never revive or promote an existing account: permission-revocation fixtures must stay revoked. */
public final class ManagementActorFixtures {
    private ManagementActorFixtures() {}

    public static ManagementContext admin(ManagementUserRepository repository, String tenant, String login) {
        ManagementUser actor = repository.findByTenantIdAndLoginNameNormalized(tenant, login.toLowerCase(Locale.ROOT))
                .orElseGet(() -> {
                    ManagementUser user = new ManagementUser();
                    user.setUsername("fixture-" + UUID.randomUUID()); user.setTenantId(tenant);
                    user.setLoginName(login); user.setLoginNameNormalized(login.toLowerCase(Locale.ROOT));
                    user.setPasswordHash("0".repeat(64)); user.setRole(ManagementRole.ADMIN); user.setEnabled(true);
                    user.setCreatedAt(Instant.now().toString()); user.setUpdatedAt(user.getCreatedAt());
                    return repository.saveAndFlush(user);
                });
        if (!actor.isEnabled() || actor.getRole() != ManagementRole.ADMIN)
            throw new IllegalStateException("fixture administrator was revoked; do not silently restore it");
        return new ManagementContext(new TenantContext(tenant), actor.getLoginName(), true, actor.getUsername());
    }
}
