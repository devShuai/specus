package com.theshuai.specusserver.database;

import com.theshuai.specusserver.database.JpaUniqueKeys.Key;
import com.theshuai.specusserver.database.JpaUniqueKeys.Mapping;
import com.theshuai.specusserver.database.JpaUniqueKeys.SqliteUniqueIndex;
import com.theshuai.specusserver.management.repository.HttpMediaCaptureRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

import static com.theshuai.specusserver.database.SqliteConstraintTestSupport.capture;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The server's own start on a fresh SQLite database, with the schema left to {@code ddl-auto=update}. */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {
                "spring.datasource.url=jdbc:sqlite:file:target/test-sqlite-unique-index-startup?mode=memory&cache=shared",
                "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
                "spring.jpa.hibernate.ddl-auto=update",
                "specus.netty.port=0"
        }
)
class SqliteUniqueIndexStartupTests {
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private HttpMediaCaptureRepository captureRepository;

    @Test
    void startupEnforcesEveryUniqueKeyOfTheMapping() {
        List<Key> declared;
        try (Mapping mapping = JpaUniqueKeys.bind()) {
            declared = mapping.tableLevel;
        }
        List<SqliteUniqueIndex> indexes = JpaUniqueKeys.sqliteUniqueIndexes(jdbcTemplate);

        assertThat(declared).isNotEmpty().allMatch(key -> JpaUniqueKeys.enforced(indexes, key));
    }

    /**
     * Two captures racing for one range can no longer both be stored, so the keyed lookup keeps
     * finding a single row, and the loser sees the DataIntegrityViolationException
     * HttpMediaCaptureService.open() catches: the community dialect configured above is replaced
     * by SpecusSqliteDialect, which translates SQLITE_CONSTRAINT.
     */
    @Test
    void aSecondCaptureWithTheSameDeduplicationKeyIsRejected() {
        captureRepository.saveAndFlush(capture("dedup-startup-test"));

        assertThatThrownBy(() -> captureRepository.saveAndFlush(capture("dedup-startup-test")))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasRootCauseMessage("[SQLITE_CONSTRAINT_UNIQUE] A UNIQUE constraint failed "
                        + "(UNIQUE constraint failed: specus_http_media_capture.deduplication_key)");
        assertThat(captureRepository.findByTenantIdAndDeduplicationKey("default", "dedup-startup-test")).isPresent();
    }
}
