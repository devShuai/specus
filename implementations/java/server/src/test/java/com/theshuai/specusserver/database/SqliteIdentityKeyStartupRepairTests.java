package com.theshuai.specusserver.database;

import com.theshuai.specusserver.management.model.HttpMediaCapture;
import com.theshuai.specusserver.management.repository.HttpMediaCaptureRepository;
import com.theshuai.specusserver.management.service.HttpMediaCaptureService;
import jakarta.persistence.EntityManagerFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;

import static com.theshuai.specusserver.database.SqliteIdentityKeySchemaTests.identityTables;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * A database created by Hibernate's default column order, as ddl-auto=create made it before the
 * order was pinned: the startup repair gives every untyped id its type, and a capture saved after
 * it keeps the id Hibernate reports.
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:sqlite::memory:",
        "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.jpa.properties.hibernate.column_ordering_strategy=default",
        "specus.netty.port=0",
        "specus.database.seed-demo-client=false"
})
class SqliteIdentityKeyStartupRepairTests {
    @Autowired
    private EntityManagerFactory entityManagerFactory;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private HttpMediaCaptureRepository captureRepository;

    @Test
    void startupTypesTheIdsHibernateCreatedWithoutOne() {
        for (String table : identityTables(entityManagerFactory)) {
            assertThat(jdbcTemplate.queryForObject(
                    "select type from pragma_table_info(?) where pk = 1", String.class, table))
                    .as(table).isEqualToIgnoringCase("integer");
        }
        // Rebuilt from Hibernate's definition, which puts an integer column before the id.
        assertThat(jdbcTemplate.queryForObject(
                "select sql from sqlite_master where type = 'table' and name = 'specus_http_media_capture'",
                String.class))
                .contains("status_code integer not null")
                .contains(", id integer,");

        HttpMediaCapture saved = captureRepository.saveAndFlush(capture());

        assertThat(jdbcTemplate.queryForList("select id from specus_http_media_capture", Long.class))
                .containsExactly(saved.getId());
        assertThat(captureRepository.findByIdAndTenantId(saved.getId(), "default")).isPresent();
        assertThat(captureRepository.findByTenantIdOrderByIdDesc("default", PageRequest.of(0, 10)).getContent())
                .extracting(HttpMediaCapture::getId).containsExactly(saved.getId());
    }

    private static HttpMediaCapture capture() {
        HttpMediaCapture capture = new HttpMediaCapture();
        capture.setTenantId("default");
        capture.setClientId(7L);
        capture.setClientName("client-a");
        capture.setRoute("video");
        capture.setSourceUrl("https://media.example.test/movie.mp4");
        capture.setResourceKey("resource");
        capture.setMethod("GET");
        capture.setStatusCode(200);
        capture.setMediaKind("MEDIA_FILE");
        capture.setObjectKey("objects/movie.mp4");
        capture.setState(HttpMediaCaptureService.STATE_STARTING);
        capture.setCapturedAt("2026-10-01T00:00:00Z");
        capture.setExpiresAt("2026-10-08T00:00:00Z");
        return capture;
    }
}
