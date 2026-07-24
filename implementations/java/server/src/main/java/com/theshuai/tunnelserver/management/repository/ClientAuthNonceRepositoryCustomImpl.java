package com.theshuai.tunnelserver.management.repository;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Locale;

@Slf4j
public class ClientAuthNonceRepositoryCustomImpl implements ClientAuthNonceRepositoryCustom {
    private static final String MYSQL_INSERT_SQL = """
            insert ignore into tunnel_client_auth_nonce(id, api_key_hash, expires_at)
            values (?, ?, ?)
            """;
    private static final String ON_CONFLICT_INSERT_SQL = """
            insert into tunnel_client_auth_nonce(id, api_key_hash, expires_at)
            values (?, ?, ?)
            on conflict (id) do nothing
            """;

    private final JdbcTemplate jdbcTemplate;
    private final DataSource dataSource;
    private String insertSql;

    public ClientAuthNonceRepositoryCustomImpl(JdbcTemplate jdbcTemplate, DataSource dataSource) {
        this.jdbcTemplate = jdbcTemplate;
        this.dataSource = dataSource;
    }

    @PostConstruct
    void detectDatabaseDialect() {
        try (Connection connection = dataSource.getConnection()) {
            String productName = connection.getMetaData().getDatabaseProductName();
            insertSql = insertSqlFor(productName);
            log.info("[client-auth] nonce insert dialect detected: {}", productName);
        } catch (SQLException e) {
            throw new IllegalStateException("无法检测 nonce 存储数据库类型", e);
        }
    }

    @Override
    public int insertIfAbsent(String id, String apiKeyHash, String expiresAt) {
        return jdbcTemplate.update(insertSql, id, apiKeyHash, expiresAt);
    }

    static String insertSqlFor(String productName) {
        String normalized = productName == null ? "" : productName.toLowerCase(Locale.ROOT);
        if (normalized.contains("mysql") || normalized.contains("mariadb")) {
            return MYSQL_INSERT_SQL;
        }
        if (normalized.contains("postgres") || normalized.contains("sqlite")) {
            return ON_CONFLICT_INSERT_SQL;
        }
        throw new IllegalStateException("不支持的 nonce 存储数据库: " + productName);
    }
}
