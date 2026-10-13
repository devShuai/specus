package com.theshuai.specusserver.database;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.UncategorizedSQLException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.jdbc.support.SQLExceptionSubclassTranslator;

import java.sql.SQLException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** {@code JdbcTemplate} on a real in-memory SQLite database, with and without the SQLite translation. */
class SqliteSqlExceptionTranslatorTests {
    private final SqliteSqlExceptionTranslator translator =
            new SqliteSqlExceptionTranslator(new SQLExceptionSubclassTranslator());
    private SingleConnectionDataSource dataSource;
    private JdbcTemplate jdbc;

    @BeforeEach
    void openDatabase() {
        dataSource = new SingleConnectionDataSource("jdbc:sqlite::memory:", true);
        jdbc = new JdbcTemplate(dataSource);
        jdbc.setExceptionTranslator(translator);
        jdbc.execute("create table probe (id integer primary key, code text not null)");
        jdbc.execute("create unique index uk_probe_code on probe (code)");
        jdbc.update("insert into probe (id, code) values (1, 'a')");
    }

    @AfterEach
    void closeDatabase() {
        dataSource.destroy();
    }

    @Test
    void aUniqueViolationIsADuplicateKey() {
        assertThatThrownBy(() -> jdbc.update("insert into probe (id, code) values (2, 'a')"))
                .isInstanceOf(DuplicateKeyException.class)
                .hasMessageContaining("UNIQUE constraint failed: probe.code");
        assertThatThrownBy(() -> jdbc.update("insert into probe (id, code) values (1, 'b')"))
                .isInstanceOf(DuplicateKeyException.class);
    }

    @Test
    void anyOtherViolationIsADataIntegrityViolation() {
        assertThatThrownBy(() -> jdbc.update("insert into probe (id, code) values (2, null)"))
                .isExactlyInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("NOT NULL constraint failed: probe.code");
    }

    @Test
    void withoutTheTranslatorTheViolationIsUncategorized() {
        JdbcTemplate plain = new JdbcTemplate(dataSource);

        assertThatThrownBy(() -> plain.update("insert into probe (id, code) values (2, 'a')"))
                .isInstanceOf(UncategorizedSQLException.class);
    }

    @Test
    void otherExceptionsGetTheDefaultTranslation() {
        assertThat(translator.translate("insert", "insert", new SQLException("duplicate", "23505")))
                .isInstanceOf(DuplicateKeyException.class);
        // MySQL's ER_HANDSHAKE_ERROR is 1043, whose low byte is SQLITE_CONSTRAINT.
        assertThat(translator.translate("connect", null, new SQLException("Bad handshake", "08S01", 1043)))
                .isInstanceOf(DataAccessResourceFailureException.class);
        assertThatThrownBy(() -> jdbc.update("insert into missing (id) values (1)"))
                .isInstanceOf(UncategorizedSQLException.class);
    }
}
