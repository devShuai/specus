package com.theshuai.specusserver.database;

import com.theshuai.specusserver.management.model.HttpMediaCapture;
import jakarta.persistence.EntityManagerFactory;
import org.hibernate.dialect.Dialect;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.springframework.jdbc.core.JdbcTemplate;

/** Shared by the tests that violate a unique index on a real SQLite database. */
public final class SqliteConstraintTestSupport {
    private SqliteConstraintTestSupport() {
    }

    /**
     * Creates the media deduplication index {@code HttpMediaCapture} declares. Hibernate's SQLite
     * dialect leaves out every {@code @Index(unique = true)}, so the schema it creates lacks it.
     */
    public static void createMediaDeduplicationIndex(JdbcTemplate jdbcTemplate) {
        jdbcTemplate.execute("create unique index if not exists uk_http_media_deduplication"
                + " on specus_http_media_capture (deduplication_key)");
    }

    static Dialect dialectOf(EntityManagerFactory entityManagerFactory) {
        return entityManagerFactory.unwrap(SessionFactoryImplementor.class).getJdbcServices().getDialect();
    }

    static HttpMediaCapture capture(String deduplicationKey) {
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
