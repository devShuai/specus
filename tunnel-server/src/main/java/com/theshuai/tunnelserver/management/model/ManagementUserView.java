package com.theshuai.tunnelserver.management.model;

public record ManagementUserView(
        String username,
        String tenantId,
        ManagementRole role,
        boolean admin,
        boolean builtIn,
        boolean enabled,
        String createdAt,
        String updatedAt
) {
}
