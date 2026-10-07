package com.theshuai.specusserver.database;

import org.hibernate.community.dialect.SQLiteDialect;
import org.hibernate.dialect.DatabaseVersion;
import org.hibernate.engine.jdbc.dialect.spi.DialectResolutionInfo;
import org.hibernate.exception.ConstraintViolationException;
import org.hibernate.exception.ConstraintViolationException.ConstraintKind;
import org.hibernate.exception.spi.SQLExceptionConversionDelegate;
import org.hibernate.exception.spi.ViolatedConstraintNameExtractor;

/**
 * The community {@link SQLiteDialect}, with SQLite's constraint violations translated.
 *
 * <p>The inherited conversion maps SQLITE_BUSY, SQLITE_IOERR and a few other result codes, but not
 * SQLITE_CONSTRAINT. The xerial driver throws a plain {@link java.sql.SQLException} without SQL state,
 * so Hibernate's fallbacks by exception type and by SQL state miss it as well: a duplicate key became
 * a {@code GenericJDBCException}, which Spring turns into a {@code JpaSystemException}, and no
 * {@code catch (DataIntegrityViolationException ...)} guarding an insert race ever fired on SQLite.
 * Here every SQLITE_CONSTRAINT becomes a {@link ConstraintViolationException}, which Spring translates
 * to {@code DataIntegrityViolationException} as it does on MySQL and PostgreSQL.
 *
 * <p>{@code application.yml} names this class; {@link SqliteDialectConfiguration} puts it in place of
 * the community dialect where a deployment still names that one.
 */
public class SpecusSqliteDialect extends SQLiteDialect {
    // The inherited extractor keeps the parenthesis the driver closes its message with.
    private static final ViolatedConstraintNameExtractor CONSTRAINT_NAME =
            SqliteConstraintViolations::constraintName;

    public SpecusSqliteDialect() {
    }

    public SpecusSqliteDialect(DialectResolutionInfo info) {
        super(info);
    }

    public SpecusSqliteDialect(DatabaseVersion version) {
        super(version);
    }

    @Override
    public ViolatedConstraintNameExtractor getViolatedConstraintNameExtractor() {
        return CONSTRAINT_NAME;
    }

    @Override
    public SQLExceptionConversionDelegate buildSQLExceptionConversionDelegate() {
        SQLExceptionConversionDelegate inherited = super.buildSQLExceptionConversionDelegate();
        return (sqlException, message, sql) -> {
            ConstraintKind kind = SqliteConstraintViolations.kind(sqlException);
            if (kind != null) {
                return new ConstraintViolationException(message, sqlException, sql, kind,
                        getViolatedConstraintNameExtractor().extractConstraintName(sqlException));
            }
            return inherited == null ? null : inherited.convert(sqlException, message, sql);
        };
    }
}
