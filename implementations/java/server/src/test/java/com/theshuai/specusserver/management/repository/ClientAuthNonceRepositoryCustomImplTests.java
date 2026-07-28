package com.theshuai.specusserver.management.repository;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientAuthNonceRepositoryCustomImplTests {
    @Test
    void mysqlAndMariaDbUseInsertIgnore() {
        assertTrue(ClientAuthNonceRepositoryCustomImpl.insertSqlFor("MySQL")
                .startsWith("insert ignore"));
        assertTrue(ClientAuthNonceRepositoryCustomImpl.insertSqlFor("MariaDB")
                .startsWith("insert ignore"));
    }

    @Test
    void sqliteAndPostgresUseOnConflict() {
        assertTrue(ClientAuthNonceRepositoryCustomImpl.insertSqlFor("SQLite")
                .contains("on conflict (id) do nothing"));
        assertTrue(ClientAuthNonceRepositoryCustomImpl.insertSqlFor("PostgreSQL")
                .contains("on conflict (id) do nothing"));
    }

    @Test
    void unsupportedDatabaseFailsClosed() {
        assertThrows(IllegalStateException.class,
                () -> ClientAuthNonceRepositoryCustomImpl.insertSqlFor("UnknownDB"));
    }
}
