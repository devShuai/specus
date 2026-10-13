package com.theshuai.specusserver.database;

import org.hibernate.JDBCException;
import org.hibernate.exception.ConstraintViolationException;
import org.hibernate.exception.ConstraintViolationException.ConstraintKind;
import org.hibernate.exception.LockAcquisitionException;
import org.hibernate.exception.spi.SQLExceptionConversionDelegate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sqlite.SQLiteErrorCode;
import org.sqlite.SQLiteException;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/** The dialect's conversion of what the xerial driver throws on a real in-memory SQLite database. */
class SpecusSqliteDialectTests {
    private final SQLExceptionConversionDelegate conversion =
            new SpecusSqliteDialect().buildSQLExceptionConversionDelegate();
    private Connection connection;

    @BeforeEach
    void openDatabase() throws SQLException {
        connection = DriverManager.getConnection("jdbc:sqlite::memory:");
        execute("pragma foreign_keys = on");
        execute("create table parent (id integer primary key)");
        execute("""
                create table child (
                    id integer primary key,
                    code text not null,
                    amount integer constraint ck_child_amount check (amount >= 0),
                    parent_id integer references parent (id)
                )""");
        execute("create unique index uk_child_code on child (code)");
        execute("create unique index uk_child_parent_amount on child (parent_id, amount)");
        execute("""
                create trigger child_no_frozen before insert on child when new.code = 'frozen'
                begin select raise(abort, 'frozen codes are refused'); end""");
        execute("insert into parent (id) values (1)");
        execute("insert into child (id, code, amount, parent_id) values (1, 'a', 1, 1)");
    }

    @AfterEach
    void closeDatabase() throws SQLException {
        connection.close();
    }

    @Test
    void aUniqueIndexViolationNamesTheIndexedColumns() {
        ConstraintViolationException violation =
                violation("insert into child (id, code) values (2, 'a')");

        assertThat(violation.getKind()).isEqualTo(ConstraintKind.UNIQUE);
        assertThat(violation.getConstraintName()).isEqualTo("child.code");
    }

    @Test
    void aMultiColumnUniqueIndexViolationNamesEveryColumn() {
        ConstraintViolationException violation =
                violation("insert into child (id, code, amount, parent_id) values (2, 'b', 1, 1)");

        assertThat(violation.getKind()).isEqualTo(ConstraintKind.UNIQUE);
        assertThat(violation.getConstraintName()).isEqualTo("child.parent_id, child.amount");
    }

    @Test
    void aPrimaryKeyViolationIsAUniqueViolation() {
        ConstraintViolationException violation =
                violation("insert into child (id, code) values (1, 'b')");

        assertThat(violation.getKind()).isEqualTo(ConstraintKind.UNIQUE);
        assertThat(violation.getConstraintName()).isEqualTo("child.id");
    }

    @Test
    void aNotNullViolationNamesTheColumn() {
        ConstraintViolationException violation =
                violation("insert into child (id, code) values (2, null)");

        assertThat(violation.getKind()).isEqualTo(ConstraintKind.NOT_NULL);
        assertThat(violation.getConstraintName()).isEqualTo("child.code");
    }

    @Test
    void aCheckViolationNamesTheConstraint() {
        ConstraintViolationException violation =
                violation("insert into child (id, code, amount) values (2, 'b', -1)");

        assertThat(violation.getKind()).isEqualTo(ConstraintKind.CHECK);
        assertThat(violation.getConstraintName()).isEqualTo("ck_child_amount");
    }

    @Test
    void aForeignKeyViolationHasNoName() {
        ConstraintViolationException violation =
                violation("insert into child (id, code, parent_id) values (2, 'b', 99)");

        assertThat(violation.getKind()).isEqualTo(ConstraintKind.FOREIGN_KEY);
        assertThat(violation.getConstraintName()).isNull();
    }

    @Test
    void anAbortFromATriggerIsAnotherKindOfViolation() {
        ConstraintViolationException violation =
                violation("insert into child (id, code) values (2, 'frozen')");

        assertThat(violation.getKind()).isEqualTo(ConstraintKind.OTHER);
        assertThat(violation.getConstraintName()).isNull();
    }

    @Test
    void otherErrorsKeepTheInheritedConversion() {
        SQLException missingTable = failure("insert into missing (id) values (1)");
        SQLiteException busy = new SQLiteException("[SQLITE_BUSY] The database file is locked (database is locked)",
                SQLiteErrorCode.SQLITE_BUSY);

        assertThat(conversion.convert(missingTable, "could not execute statement", "insert")).isNull();
        assertThat(conversion.convert(busy, "could not execute statement", "insert"))
                .isInstanceOf(LockAcquisitionException.class);
    }

    @Test
    void aConstraintErrorCodeFromAnotherDriverIsNotAViolation() {
        // MySQL's ER_HANDSHAKE_ERROR is 1043, whose low byte is SQLITE_CONSTRAINT.
        SQLException mysql = new SQLException("Bad handshake", "08S01", 1043);

        assertThat(conversion.convert(mysql, "could not execute statement", "insert")).isNull();
    }

    private ConstraintViolationException violation(String sql) {
        SQLException failure = failure(sql);
        JDBCException converted = conversion.convert(failure, "could not execute statement", sql);

        assertThat(converted).isInstanceOf(ConstraintViolationException.class);
        assertThat((Throwable) converted.getSQLException()).isSameAs(failure);
        assertThat(converted.getSQL()).isEqualTo(sql);
        return (ConstraintViolationException) converted;
    }

    private SQLException failure(String sql) {
        SQLException failure = catchThrowableOfType(SQLException.class, () -> execute(sql));
        assertThat((Throwable) failure).as("failure of %s", sql).isNotNull();
        return failure;
    }

    private void execute(String sql) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }
}
