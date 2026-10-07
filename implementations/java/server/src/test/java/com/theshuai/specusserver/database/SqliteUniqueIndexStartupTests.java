package com.theshuai.specusserver.database;

import com.theshuai.specusserver.database.JpaUniqueKeys.Key;
import com.theshuai.specusserver.database.JpaUniqueKeys.Mapping;
import com.theshuai.specusserver.database.JpaUniqueKeys.SqliteUniqueIndex;
import com.theshuai.specusserver.management.model.HttpMediaCapture;
import com.theshuai.specusserver.management.repository.HttpMediaCaptureRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

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
     * finding a single row. The community SQLite dialect does not translate SQLITE_CONSTRAINT,
     * so the loser sees a JpaSystemException rather than the DataIntegrityViolationException
     * HttpMediaCaptureService.open() catches.
     */
    @Test
    void aSecondCaptureWithTheSameDeduplicationKeyIsRejected() {
        captureRepository.saveAndFlush(capture("dedup-startup-test"));

        assertThatThrownBy(() -> captureRepository.saveAndFlush(capture("dedup-startup-test")))
                .isInstanceOf(DataAccessException.class)
                .hasRootCauseMessage("[SQLITE_CONSTRAINT_UNIQUE] A UNIQUE constraint failed "
                        + "(UNIQUE constraint failed: specus_http_media_capture.deduplication_key)");
        assertThat(captureRepository.findByTenantIdAndDeduplicationKey("default", "dedup-startup-test")).isPresent();
    }

    private static HttpMediaCapture capture(String deduplicationKey) {
        HttpMediaCapture capture = new HttpMediaCapture();
        capture.setTenantId("default");
        capture.setClientId(1L);
        capture.setClientName("client");
        capture.setRoute("media");
        capture.setSourceUrl("https://example.test/video.mp4");
        capture.setResourceKey("resource");
        capture.setDeduplicationKey(deduplicationKey);
        capture.setMethod("GET");
        capture.setStatusCode(206);
        capture.setMediaKind("video");
        capture.setCapturedBytes(0);
        capture.setObjectKey("object");
        capture.setState("STARTING");
        capture.setCapturedAt("2026-10-07T00:00:00Z");
        capture.setExpiresAt("2026-10-08T00:00:00Z");
        return capture;
    }
}
