package com.theshuai.specusserver.database;

import com.theshuai.specusserver.SpecusServerApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

/** Explicit opt-in proof, not a default/skipped test: -Dtest=MySqlCredentialAuthProof,
 * -Dspecus.test.mysql.port and -Dspecus.test.mysql.data-directory. The caller must start an owned
 * loopback MySQL instance; verify @@datadir BEFORE creating a fresh random test database. */
class MySqlCredentialAuthProof {
    @Test
    void actualMySqlDriverAndDatabaseHonorAuthenticationBoundary() throws Exception {
        int port = Integer.parseInt(System.getProperty("specus.test.mysql.port", "0"));
        assertTrue(port > 0 && port <= 65535, "an explicitly owned MySQL port is required");
        Path expected = Path.of(System.getProperty("specus.test.mysql.data-directory")).toRealPath();
        String prefix = "jdbc:mysql://127.0.0.1:" + port + "/";
        String options = "?nullDatabaseMeansCurrent=true&useAffectedRows=true";
        JdbcTemplate admin = new JdbcTemplate(new DriverManagerDataSource(prefix + options, "root", ""));
        String actual = admin.queryForObject("select @@datadir", String.class);
        assertNotNull(actual);
        assertTrue(Files.isSameFile(expected, Path.of(actual)), "refuse writes to a non-owned database instance");
        String database = "specus_owner_auth_test_" + UUID.randomUUID().toString().replace("-", "");
        admin.execute("create database " + database + " character set utf8mb4 collate utf8mb4_unicode_ci");
        String url = prefix + database + options;
        try (var context = new SpringApplicationBuilder(SpecusServerApplication.class).web(WebApplicationType.NONE).run(
                "--spring.datasource.url=" + url,
                "--spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver", "--spring.datasource.username=root",
                "--spring.datasource.hikari.maximum-pool-size=4",
                "--spring.jpa.database-platform=org.hibernate.dialect.MySQLDialect", "--spring.jpa.hibernate.ddl-auto=update",
                "--spring.jpa.properties.hibernate.hbm2ddl.halt_on_error=true", "--specus.elasticsearch.uris=",
                "--specus.netty.port=0", "--specus.database.seed-demo-client=false",
                "--specus.client-packages.github-release-fallback-enabled=false",
                "--specus.client-packages.data-directory=" + expected.getParent().resolve(database + "-packages"))) {
            ClientCredentialAuthAssertions.verify(context, new DriverManagerDataSource(url, "root", ""), true);
        }
    }
}
