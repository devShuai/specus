package com.theshuai.specusserver.management.security;

import com.theshuai.specusserver.management.tenant.TenantContext;

public record ManagementContext(
        TenantContext tenant,
        String username,
        boolean admin
) {
    public boolean isAdmin() {
        return admin;
    }
}
