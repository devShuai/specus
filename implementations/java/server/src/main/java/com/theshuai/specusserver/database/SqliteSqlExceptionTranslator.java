package com.theshuai.specusserver.database;

import org.hibernate.exception.ConstraintViolationException.ConstraintKind;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.support.AbstractFallbackSQLExceptionTranslator;
import org.springframework.jdbc.support.SQLExceptionTranslator;

import java.sql.SQLException;

/**
 * Translates SQLite's constraint violations ahead of another translator.
 *
 * <p>The xerial driver's exceptions carry no SQL state, so Spring's default translator left a
 * violated constraint as an {@code UncategorizedSQLException}. It is translated here the way Spring
 * translates SQL state 23 elsewhere: a unique or primary key violation becomes a
 * {@link DuplicateKeyException}, any other a {@link DataIntegrityViolationException}. Every other
 * exception, from SQLite or any other database, goes to the fallback.
 */
class SqliteSqlExceptionTranslator extends AbstractFallbackSQLExceptionTranslator {
    SqliteSqlExceptionTranslator(SQLExceptionTranslator fallback) {
        setFallbackTranslator(fallback);
    }

    @Override
    protected DataAccessException doTranslate(String task, String sql, SQLException ex) {
        ConstraintKind kind = SqliteConstraintViolations.kind(ex);
        if (kind == null) {
            return null;
        }
        String message = buildMessage(task, sql, ex);
        return kind == ConstraintKind.UNIQUE
                ? new DuplicateKeyException(message, ex)
                : new DataIntegrityViolationException(message, ex);
    }
}
