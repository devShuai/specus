package com.theshuai.specusserver.management.security;

import com.theshuai.specusserver.management.tenant.TenantContext;

/**
 * @param accountKey the key of the account row the request resolved to, the {@code uid} of its
 *                   tokens; {@code null} for the built-in administrator, which has no row
 */
public record ManagementContext(
        TenantContext tenant,
        String username,
        boolean admin,
        String accountKey
) {
    public ManagementContext(TenantContext tenant, String username, boolean admin) {
        this(tenant, username, admin, null);
    }

    public boolean isAdmin() {
        return admin;
    }
}
