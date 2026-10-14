package com.theshuai.specusserver.management.security;

import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.model.ManagementUser;
import com.theshuai.specusserver.management.tenant.TenantContext;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Optional;
import java.util.TreeSet;

/** Revalidates a resolved identity inside the resource writer's transaction. Account row locks
 * are held through commit; credential locks must follow them, never the other way around.
 * No tenant/global mutex: unrelated accounts and client logins stay independent on row-locking DBs. */
@Component
@Transactional(propagation = Propagation.MANDATORY)
public class ManagementWriteAuthority {
    @PersistenceContext private EntityManager entities;
    private final AuthProperties auth;

    public ManagementWriteAuthority(AuthProperties auth) { this.auth = auth; }

    /** Must precede snapshot reads on SQLite. Other providers acquire no tuple locks here. */
    public void reserveWriter() {
        entities.createNativeQuery("update specus_management_user set enabled=enabled where 1=0").executeUpdate();
    }

    public ManagementContext current(ManagementContext resolved) {
        reserveWriter();
        checkShape(resolved);
        return validate(resolved, resolved.accountKey() == null ? null
                : lockUser(resolved.accountKey(), resolved.tenant().tenantId()).orElse(null));
    }

    /** Acquire actor and target together in key order. Locking the actor first and only later
     * discovering the target deadlocks when two administrators edit one another. */
    public UserWrite currentAndTarget(ManagementContext resolved, String requestedLogin) {
        reserveWriter();
        checkShape(resolved);
        String tenant = resolved.tenant().tenantId();
        String normalized = requestedLogin == null ? "" : requestedLogin.trim().toLowerCase(Locale.ROOT);
        var candidates = entities.createNativeQuery("""
                select username, tenant_id, login_name_normalized from specus_management_user
                 where tenant_id=?1 and login_name_normalized=?2
                """).setParameter(1, tenant).setParameter(2, normalized).getResultList();
        String targetKey = null;
        for (Object candidate : candidates) {
            Object[] row = (Object[]) candidate;
            if (tenant.equals(row[1]) && normalized.equals(row[2])) targetKey = (String) row[0];
        }
        var keys = new TreeSet<String>();
        if (resolved.accountKey() != null) keys.add(resolved.accountKey());
        if (targetKey != null) keys.add(targetKey);
        var locked = new HashMap<String, ManagementUser>();
        for (String key : keys) lockUser(key, tenant).ifPresent(user -> locked.put(key, user));
        ManagementContext actor = validate(resolved, locked.get(resolved.accountKey()));
        // A missing/replaced/renamed target must not be rebound by its reusable login name.
        ManagementUser target = locked.get(targetKey);
        if (target != null && !normalized.equals(target.getLoginNameNormalized())) target = null;
        return new UserWrite(actor, Optional.ofNullable(target));
    }

    private static void checkShape(ManagementContext resolved) {
        if (resolved == null || resolved.tenant() == null || resolved.username() == null) throw denied();
    }

    private ManagementContext validate(ManagementContext resolved, ManagementUser user) {
        if (resolved.accountKey() == null) {
            if (!resolved.isAdmin() || !auth.isPasswordLoginEnabled() || !StringUtils.hasText(auth.getPassword())
                    || !resolved.username().equals(auth.getUsername())
                    || !resolved.tenant().tenantId().equals(TenantContext.normalize(auth.getTenantId()))) throw denied();
            return new ManagementContext(resolved.tenant(), auth.getUsername(), true);
        }
        if (user == null || !user.isEnabled() || !resolved.accountKey().equals(user.getUsername())
                || !resolved.tenant().tenantId().equals(user.getTenantId())
                || !resolved.username().equals(user.getLoginName())) throw denied();
        return new ManagementContext(resolved.tenant(), resolved.username(), user.getRole() == ManagementRole.ADMIN, resolved.accountKey());
    }

    private Optional<ManagementUser> lockUser(String key, String tenant) {
        // Also publish a row version: a PostgreSQL REPEATABLE READ caller with an earlier
        // snapshot must abort rather than delete an account while missing resources created
        // since its snapshot. MySQL current locking reads cover its own RR semantics. Ignore
        // unchanged-row counts (MySQL can report zero). Keys are always acquired in order.
        entities.createNativeQuery("update specus_management_user set enabled=enabled where username=?1 and tenant_id=?2")
                .setParameter(1, key).setParameter(2, tenant).executeUpdate();
        String lock = entities.unwrap(Session.class).doReturningWork(connection ->
                connection.getMetaData().supportsSelectForUpdate() ? " for update" : "");
        var rows = entities.createNativeQuery("""
                select username, tenant_id, login_name, login_name_normalized, password_hash,
                       oidc_issuer, oidc_subject, oidc_identity_key, role, enabled, created_at, updated_at
                  from specus_management_user where username=?1 and tenant_id=?2
                """ + lock).setParameter(1, key).setParameter(2, tenant)
                .getResultList();
        if (rows.isEmpty()) return Optional.empty();
        Object[] row = (Object[]) rows.getFirst();
        if (!key.equals(row[0]) || !tenant.equals(row[1])) return Optional.empty();
        // Scalar locking read, not a cached entity or a plain refresh of an older RR snapshot.
        ManagementUser user = new ManagementUser();
        user.setUsername((String) row[0]); user.setTenantId((String) row[1]);
        user.setLoginName((String) row[2]); user.setLoginNameNormalized((String) row[3]);
        user.setPasswordHash((String) row[4]); user.setOidcIssuer((String) row[5]);
        user.setOidcSubject((String) row[6]); user.setOidcIdentityKey((String) row[7]);
        user.setRole(ManagementRole.parse((String) row[8]));
        user.setEnabled(row[9] instanceof Boolean value ? value : ((Number) row[9]).intValue() != 0);
        user.setCreatedAt((String) row[10]); user.setUpdatedAt((String) row[11]);
        return Optional.of(user);
    }

    public record UserWrite(ManagementContext actor, Optional<ManagementUser> target) {}

    private static ResponseStatusException denied() {
        return new ResponseStatusException(HttpStatus.FORBIDDEN, "账号已变更、已禁用或权限已撤销");
    }
}
