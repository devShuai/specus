package com.theshuai.specusserver.management.security;

import com.theshuai.specusserver.config.AuthProperties;
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
        if (resolved == null || resolved.tenant() == null || resolved.username() == null) throw denied();
        if (resolved.accountKey() == null) {
            if (!resolved.isAdmin() || !auth.isPasswordLoginEnabled() || !StringUtils.hasText(auth.getPassword())
                    || !resolved.username().equals(auth.getUsername())
                    || !resolved.tenant().tenantId().equals(TenantContext.normalize(auth.getTenantId()))) throw denied();
            return new ManagementContext(resolved.tenant(), auth.getUsername(), true);
        }
        String lock = entities.unwrap(Session.class).doReturningWork(connection ->
                connection.getMetaData().supportsSelectForUpdate() ? " for update" : "");
        var rows = entities.createNativeQuery("""
                select username, tenant_id, login_name, enabled, role
                  from specus_management_user where username=?1 and tenant_id=?2
                """ + lock).setParameter(1, resolved.accountKey()).setParameter(2, resolved.tenant().tenantId())
                .getResultList();
        if (rows.isEmpty()) throw denied();
        Object[] row = (Object[]) rows.getFirst();
        boolean enabled = row[3] instanceof Boolean value ? value : ((Number) row[3]).intValue() != 0;
        // Compare exact identity fields in Java as well: case-insensitive SQL collations must not
        // bind a deleted/recreated account or another tenant's same-named account to this request.
        if (!enabled || !resolved.accountKey().equals(row[0]) || !resolved.tenant().tenantId().equals(row[1])
                || !resolved.username().equals(row[2])) throw denied();
        return new ManagementContext(resolved.tenant(), resolved.username(), "ADMIN".equals(row[4]), resolved.accountKey());
    }

    private static ResponseStatusException denied() {
        return new ResponseStatusException(HttpStatus.FORBIDDEN, "账号已变更、已禁用或权限已撤销");
    }
}
