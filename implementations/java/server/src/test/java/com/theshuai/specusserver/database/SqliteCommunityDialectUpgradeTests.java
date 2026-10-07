package com.theshuai.specusserver.database;

import com.theshuai.specusserver.management.repository.HttpMediaCaptureRepository;
import jakarta.persistence.EntityManagerFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;

import static com.theshuai.specusserver.database.SqliteConstraintTestSupport.capture;
import static com.theshuai.specusserver.database.SqliteConstraintTestSupport.createMediaDeduplicationIndex;
import static com.theshuai.specusserver.database.SqliteConstraintTestSupport.dialectOf;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** A deployment that names the community dialect, as the README used to tell SQLite deployments to. */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {
                "spring.datasource.url=jdbc:sqlite:file:target/test-sqlite-community-dialect?mode=memory&cache=shared",
                "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
                "spring.jpa.hibernate.ddl-auto=update",
                "specus.netty.port=0"
        }
)
class SqliteCommunityDialectUpgradeTests {
    @Autowired private EntityManagerFactory entityManagerFactory;
    @Autowired private HttpMediaCaptureRepository captureRepository;
    @Autowired private JdbcTemplate jdbcTemplate;

    @Test
    void theCommunityDialectIsReplacedAndViolationsAreTranslated() {
        createMediaDeduplicationIndex(jdbcTemplate);
        captureRepository.saveAndFlush(capture("community-duplicate"));

        assertThat(dialectOf(entityManagerFactory)).isExactlyInstanceOf(SpecusSqliteDialect.class);
        assertThatThrownBy(() -> captureRepository.saveAndFlush(capture("community-duplicate")))
                .isInstanceOf(DataIntegrityViolationException.class);
    }
}
