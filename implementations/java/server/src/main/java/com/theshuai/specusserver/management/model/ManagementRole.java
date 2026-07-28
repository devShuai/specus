package com.theshuai.specusserver.management.model;

public enum ManagementRole {
    ADMIN,
    USER;

    public static ManagementRole parse(String value) {
        if (value == null || value.isBlank()) {
            return USER;
        }
        try {
            return ManagementRole.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException ignored) {
            return USER;
        }
    }
}
