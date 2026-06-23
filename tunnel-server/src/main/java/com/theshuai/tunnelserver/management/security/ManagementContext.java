package com.theshuai.tunnelserver.management.security;

import com.theshuai.tunnelserver.management.tenant.TenantContext;

public record ManagementContext(
        TenantContext tenant,
        String username,
        boolean admin
) {
    public boolean isAdmin() {
        return admin;
    }
}
