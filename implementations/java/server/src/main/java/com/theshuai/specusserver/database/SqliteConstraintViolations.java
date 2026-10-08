package com.theshuai.specusserver.database;

import org.hibernate.exception.ConstraintViolationException.ConstraintKind;
import org.sqlite.SQLiteException;

import java.sql.SQLException;

/**
 * Reads a violated constraint out of the xerial SQLite driver's exception.
 *
 * <p>The driver reports every violation with result code SQLITE_CONSTRAINT and no SQL state; the
 * extended result code says which kind of constraint failed, and the message carries SQLite's own
 * text in parentheses after the code's description, e.g. {@code [SQLITE_CONSTRAINT_UNIQUE] A UNIQUE
 * constraint failed (UNIQUE constraint failed: specus_http_media_capture.deduplication_key)}.
 * Exceptions from any other driver are never read as a violation, whatever their error code.
 */
final class SqliteConstraintViolations {
    private static final int SQLITE_CONSTRAINT = 19;
    private static final String NAME_PREFIX = "constraint failed: ";

    private SqliteConstraintViolations() {
    }

    /** The kind of constraint the exception reports as violated, or {@code null} when it reports none. */
    static ConstraintKind kind(SQLException exception) {
        if (!(exception instanceof SQLiteException sqlite) || sqlite.getErrorCode() != SQLITE_CONSTRAINT) {
            return null;
        }
        return switch (sqlite.getResultCode()) {
            case SQLITE_CONSTRAINT_UNIQUE, SQLITE_CONSTRAINT_PRIMARYKEY, SQLITE_CONSTRAINT_ROWID -> ConstraintKind.UNIQUE;
            case SQLITE_CONSTRAINT_NOTNULL -> ConstraintKind.NOT_NULL;
            case SQLITE_CONSTRAINT_FOREIGNKEY -> ConstraintKind.FOREIGN_KEY;
            case SQLITE_CONSTRAINT_CHECK -> ConstraintKind.CHECK;
            default -> ConstraintKind.OTHER;
        };
    }

    /**
     * What SQLite names as violated, or {@code null}. SQLite names the {@code table.column} list of a
     * unique, primary key or not-null constraint rather than the index, the name of a named check
     * constraint or the expression of an unnamed one, and nothing for a foreign key.
     */
    static String constraintName(SQLException exception) {
        if (kind(exception) == null) {
            return null;
        }
        String message = exception.getMessage();
        String prefix = ((SQLiteException) exception).getResultCode() + " (";
        if (message == null || !message.startsWith(prefix) || !message.endsWith(")")) {
            return null;
        }
        String detail = message.substring(prefix.length(), message.length() - 1);
        int start = detail.indexOf(NAME_PREFIX);
        return start < 0 ? null : detail.substring(start + NAME_PREFIX.length());
    }
}
