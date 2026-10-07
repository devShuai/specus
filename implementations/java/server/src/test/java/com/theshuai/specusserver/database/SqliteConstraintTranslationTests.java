package com.theshuai.specusserver.database;

import com.theshuai.specusserver.management.repository.HttpMediaCaptureRepository;
import jakarta.persistence.EntityManagerFactory;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.exception.ConstraintViolationException;
import org.hibernate.exception.ConstraintViolationException.ConstraintKind;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;

import static com.theshuai.specusserver.database.SqliteConstraintTestSupport.capture;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * Violated unique indexes on a real SQLite database, with the dialect {@code application.yml} names.
 * {@code HttpMediaCaptureSqliteRaceTests} shares this context.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {
                "spring.datasource.url=jdbc:sqlite:file:target/test-sqlite-constraint-translation?mode=memory&cache=shared",
                "spring.jpa.hibernate.ddl-auto=update",
                "specus.netty.port=0"
        }
)
class SqliteConstraintTranslationTests {
    @Autowired private EntityManagerFactory entityManagerFactory;
    @Autowired private HttpMediaCaptureRepository captureRepository;
    @Autowired private JdbcTemplate jdbcTemplate;

    @BeforeEach
    @AfterEach
    void clearCaptures() {
        captureRepository.deleteAll();
    }

    @Test
    void theDefaultDialectTranslatesConstraintViolations() {
        assertThat(entityManagerFactory.unwrap(SessionFactoryImplementor.class).getJdbcServices().getDialect())
                .isExactlyInstanceOf(SpecusSqliteDialect.class);
    }

    @Test
    void aJpaSaveThatViolatesAUniqueIndexIsADataIntegrityViolation() {
        captureRepository.saveAndFlush(capture("jpa-duplicate"));

        DataIntegrityViolationException failure = catchThrowableOfType(DataIntegrityViolationException.class,
                () -> captureRepository.saveAndFlush(capture("jpa-duplicate")));

        assertThat(failure).isNotNull();
        assertThat(failure.getCause()).isInstanceOfSatisfying(ConstraintViolationException.class, violation -> {
            assertThat(violation.getKind()).isEqualTo(ConstraintKind.UNIQUE);
            assertThat(violation.getConstraintName()).isEqualTo("specus_http_media_capture.deduplication_key");
        });
        assertThat(captureRepository.findAll()).hasSize(1);
    }

    @Test
    void aJdbcTemplateInsertThatViolatesAUniqueIndexIsADuplicateKey() {
        jdbcTemplate.execute("create table if not exists constraint_translation_probe (id integer primary key, code text unique)");
        jdbcTemplate.update("delete from constraint_translation_probe");
        jdbcTemplate.update("insert into constraint_translation_probe (id, code) values (1, 'a')");

        assertThatThrownBy(() -> jdbcTemplate.update("insert into constraint_translation_probe (id, code) values (2, 'a')"))
                .isInstanceOf(DuplicateKeyException.class);
    }
}
