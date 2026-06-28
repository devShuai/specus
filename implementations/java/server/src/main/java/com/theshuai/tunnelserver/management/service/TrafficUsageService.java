package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.HttpRouteMapping;
import com.theshuai.tunnelserver.management.model.ResourceTrafficUsage;
import com.theshuai.tunnelserver.management.model.TrafficUsage;
import com.theshuai.tunnelserver.management.model.TunnelMapping;
import com.theshuai.tunnelserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.tunnelserver.management.repository.ResourceTrafficUsageRepository;
import com.theshuai.tunnelserver.management.repository.TrafficUsageRepository;
import com.theshuai.tunnelserver.management.repository.TunnelMappingRepository;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;

@Slf4j
@Service
public class TrafficUsageService {
    public static final String RESOURCE_TYPE_TCP_TUNNEL = "TCP_TUNNEL";
    public static final String RESOURCE_TYPE_HTTP_ROUTE = "HTTP_ROUTE";

    /** Dialect 标记，{@link #upsertDialect} 持有的可能值。 */
    private static final String DIALECT_POSTGRES = "postgres";
    private static final String DIALECT_MYSQL = "mysql";
    private static final String DIALECT_SQLITE = "sqlite";
    private static final String DIALECT_UNKNOWN = "unknown";

    private final ClientAccountService clientAccountService;
    private final TrafficUsageRepository trafficUsageRepository;
    private final ResourceTrafficUsageRepository resourceTrafficUsageRepository;
    private final TunnelMappingRepository tunnelMappingRepository;
    private final HttpRouteMappingRepository httpRouteMappingRepository;
    private final JdbcTemplate jdbcTemplate;
    private final DataSource dataSource;
    private final Map<String, TrafficCounter> counters = new ConcurrentHashMap<>();
    /**
     * S1.3 零分配：原来用 {@code Map<ResourceCounterKey, TrafficCounter>}，每次
     * {@code recordResourceUpload/Download} 都 {@code new ResourceCounterKey(...)} 一个三字段 record
     * 来做 lookup。改成两级 {@code Map<clientName, Map<resourceKey, TrafficCounter>>}：
     * 外层 key 复用调用方传入的 {@code clientName} String，内层 key 复用 {@code tcpKey/httpKey}
     * 已经拼好的 {@code resourceKey} String（前缀 {@code "tcp:"} / {@code "http:"} 天然不冲突），
     * 这样 hot path 上不再为 lookup 额外分配对象。
     */
    private final Map<String, Map<String, TrafficCounter>> resourceCounters = new ConcurrentHashMap<>();
    /**
     * S1.2 UPSERT 路径用：启动时探测一次 Connection metadata，确定走哪段 dialect-specific SQL。
     * 探测失败时退回 {@link #DIALECT_UNKNOWN}，flush 仍走原有 find-then-save 路径。
     */
    private volatile String upsertDialect = DIALECT_UNKNOWN;

    public TrafficUsageService(ClientAccountService clientAccountService,
                               TrafficUsageRepository trafficUsageRepository,
                               ResourceTrafficUsageRepository resourceTrafficUsageRepository,
                               TunnelMappingRepository tunnelMappingRepository,
                               HttpRouteMappingRepository httpRouteMappingRepository,
                               JdbcTemplate jdbcTemplate,
                               DataSource dataSource) {
        this.clientAccountService = clientAccountService;
        this.trafficUsageRepository = trafficUsageRepository;
        this.resourceTrafficUsageRepository = resourceTrafficUsageRepository;
        this.tunnelMappingRepository = tunnelMappingRepository;
        this.httpRouteMappingRepository = httpRouteMappingRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.dataSource = dataSource;
    }

    @PostConstruct
    void detectDialect() {
        try (Connection connection = dataSource.getConnection()) {
            String productName = connection.getMetaData().getDatabaseProductName();
            String normalized = productName == null ? "" : productName.toLowerCase();
            if (normalized.contains("postgres")) {
                upsertDialect = DIALECT_POSTGRES;
            } else if (normalized.contains("mysql") || normalized.contains("mariadb")) {
                upsertDialect = DIALECT_MYSQL;
            } else if (normalized.contains("sqlite")) {
                upsertDialect = DIALECT_SQLITE;
            } else {
                upsertDialect = DIALECT_UNKNOWN;
            }
            log.info("[traffic-usage] UPSERT dialect detected: product='{}' → {}",
                    productName, upsertDialect);
        } catch (SQLException e) {
            log.warn("[traffic-usage] dialect detect failed, falling back to JPA save-by-find: {}", e.getMessage());
            upsertDialect = DIALECT_UNKNOWN;
        }
    }

    public void recordUpload(String clientName, long bytes) {
        if (clientName != null && bytes > 0) {
            counters.computeIfAbsent(clientName, key -> new TrafficCounter()).upload.add(bytes);
        }
    }

    public void recordDownload(String clientName, long bytes) {
        if (clientName != null && bytes > 0) {
            counters.computeIfAbsent(clientName, key -> new TrafficCounter()).download.add(bytes);
        }
    }

    public void recordTcpUpload(String clientName, int listenPort, long bytes) {
        recordUpload(clientName, bytes);
        if (listenPort > 0) {
            recordResourceUpload(clientName, RESOURCE_TYPE_TCP_TUNNEL, tcpKey(listenPort), bytes);
        }
    }

    public void recordTcpDownload(String clientName, int listenPort, long bytes) {
        recordDownload(clientName, bytes);
        if (listenPort > 0) {
            recordResourceDownload(clientName, RESOURCE_TYPE_TCP_TUNNEL, tcpKey(listenPort), bytes);
        }
    }

    public void recordHttpUpload(String clientName, String route, long bytes) {
        recordUpload(clientName, bytes);
        recordResourceUpload(clientName, RESOURCE_TYPE_HTTP_ROUTE, httpKey(route), bytes);
    }

    public void recordHttpDownload(String clientName, String route, long bytes) {
        recordDownload(clientName, bytes);
        recordResourceDownload(clientName, RESOURCE_TYPE_HTTP_ROUTE, httpKey(route), bytes);
    }

    @Scheduled(fixedDelayString = "${tunnel.traffic.flush-interval-ms:5000}")
    @Transactional
    public synchronized void flush() {
        counters.forEach(this::flushCounter);
        resourceCounters.forEach((clientName, inner) ->
                inner.forEach((resourceKey, counter) ->
                        flushResourceCounter(clientName, inferResourceType(resourceKey), resourceKey, counter)));
    }

    @PreDestroy
    public void flushBeforeShutdown() {
        flush();
    }

    private void flushCounter(String clientName, TrafficCounter counter) {
        long uploadBytes = counter.upload.sumThenReset();
        long downloadBytes = counter.download.sumThenReset();
        if (uploadBytes == 0 && downloadBytes == 0) {
            return;
        }

        try {
            ClientAccount account = clientAccountService.findClientByName(clientName).orElse(null);
            if (account == null) {
                return;
            }
            String usageDate = LocalDate.now(ZoneOffset.UTC).toString();
            String updatedAt = Instant.now().toString();
            if (!upsertTrafficUsage(account, usageDate, uploadBytes, downloadBytes, updatedAt)) {
                // Dialect 不支持 UPSERT，退回原有 find-then-save 路径
                TrafficUsage usage = trafficUsageRepository
                        .findByTenantIdAndClientIdAndUsageDate(account.getTenantId(), account.getId(), usageDate)
                        .orElseGet(TrafficUsage::new);
                usage.setTenantId(account.getTenantId());
                usage.setClientId(account.getId());
                usage.setClientName(account.getClientName());
                usage.setUsageDate(usageDate);
                usage.setUploadBytes(usage.getUploadBytes() + uploadBytes);
                usage.setDownloadBytes(usage.getDownloadBytes() + downloadBytes);
                usage.setUpdatedAt(updatedAt);
                trafficUsageRepository.save(usage);
            }
        } catch (RuntimeException e) {
            counter.upload.add(uploadBytes);
            counter.download.add(downloadBytes);
            throw e;
        }
    }

    /**
     * S1.2 用 dialect-specific UPSERT 一条 SQL 完成「不存在则插入，已存在则累加」，
     * 替代 find-then-save 的两次 round trip + 并发窗口。返回 {@code true} 表示走了 UPSERT 路径，
     * {@code false} 表示当前 dialect 未识别，调用方应退回原 JPA 路径。
     *
     * <p>Postgres / SQLite 都用 ON CONFLICT；MySQL 用 ON DUPLICATE KEY UPDATE。两套 SQL 都依赖
     * 表上 {@code (client_id, usage_date)} 的唯一约束（{@link TrafficUsage} 已定义）。
     */
    private boolean upsertTrafficUsage(ClientAccount account,
                                       String usageDate,
                                       long uploadBytes,
                                       long downloadBytes,
                                       String updatedAt) {
        String sql = switch (upsertDialect) {
            case DIALECT_POSTGRES, DIALECT_SQLITE -> """
                    INSERT INTO tunnel_traffic_usage
                        (tenant_id, client_id, client_name, usage_date,
                         upload_bytes, download_bytes, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (client_id, usage_date) DO UPDATE SET
                        tenant_id      = EXCLUDED.tenant_id,
                        client_name    = EXCLUDED.client_name,
                        upload_bytes   = tunnel_traffic_usage.upload_bytes + EXCLUDED.upload_bytes,
                        download_bytes = tunnel_traffic_usage.download_bytes + EXCLUDED.download_bytes,
                        updated_at     = EXCLUDED.updated_at
                    """;
            case DIALECT_MYSQL -> """
                    INSERT INTO tunnel_traffic_usage
                        (tenant_id, client_id, client_name, usage_date,
                         upload_bytes, download_bytes, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON DUPLICATE KEY UPDATE
                        tenant_id      = VALUES(tenant_id),
                        client_name    = VALUES(client_name),
                        upload_bytes   = upload_bytes + VALUES(upload_bytes),
                        download_bytes = download_bytes + VALUES(download_bytes),
                        updated_at     = VALUES(updated_at)
                    """;
            default -> null;
        };
        if (sql == null) {
            return false;
        }
        try {
            jdbcTemplate.update(sql,
                    account.getTenantId(),
                    account.getId(),
                    account.getClientName(),
                    usageDate,
                    uploadBytes,
                    downloadBytes,
                    updatedAt);
            return true;
        } catch (DataAccessException e) {
            log.warn("[traffic-usage] UPSERT failed, will fall back to find-then-save: {}", e.getMessage());
            return false;
        }
    }

    private void recordResourceUpload(String clientName, String resourceType, String resourceKey, long bytes) {
        if (clientName != null && bytes > 0) {
            resourceCounters.computeIfAbsent(clientName, k -> new ConcurrentHashMap<>())
                    .computeIfAbsent(resourceKey, k -> new TrafficCounter()).upload.add(bytes);
        }
    }

    private void recordResourceDownload(String clientName, String resourceType, String resourceKey, long bytes) {
        if (clientName != null && bytes > 0) {
            resourceCounters.computeIfAbsent(clientName, k -> new ConcurrentHashMap<>())
                    .computeIfAbsent(resourceKey, k -> new TrafficCounter()).download.add(bytes);
        }
    }

    private void flushResourceCounter(String clientName, String resourceType, String resourceKey, TrafficCounter counter) {
        long uploadBytes = counter.upload.sumThenReset();
        long downloadBytes = counter.download.sumThenReset();
        if (uploadBytes == 0 && downloadBytes == 0) {
            return;
        }

        try {
            ClientAccount account = clientAccountService.findClientByName(clientName).orElse(null);
            if (account == null) {
                return;
            }
            ResourceDescriptor descriptor = resolveResource(account, resourceType, resourceKey);
            String usageDate = LocalDate.now(ZoneOffset.UTC).toString();
            String updatedAt = Instant.now().toString();
            if (!upsertResourceTrafficUsage(account, descriptor, resourceType, resourceKey,
                    usageDate, uploadBytes, downloadBytes, updatedAt)) {
                // Dialect 未识别，退回原 JPA find-then-save 路径
                ResourceTrafficUsage usage = resourceTrafficUsageRepository
                        .findByTenantIdAndClientIdAndResourceTypeAndResourceKeyAndUsageDate(
                                account.getTenantId(), account.getId(), resourceType, resourceKey, usageDate)
                        .orElseGet(ResourceTrafficUsage::new);
                usage.setTenantId(account.getTenantId());
                usage.setClientId(account.getId());
                usage.setClientName(account.getClientName());
                usage.setResourceType(resourceType);
                usage.setResourceKey(resourceKey);
                usage.setResourceId(descriptor.resourceId());
                usage.setResourceName(descriptor.resourceName());
                usage.setUsageDate(usageDate);
                usage.setUploadBytes(usage.getUploadBytes() + uploadBytes);
                usage.setDownloadBytes(usage.getDownloadBytes() + downloadBytes);
                usage.setUpdatedAt(updatedAt);
                resourceTrafficUsageRepository.save(usage);
            }
        } catch (RuntimeException e) {
            counter.upload.add(uploadBytes);
            counter.download.add(downloadBytes);
            throw e;
        }
    }

    /**
     * 资源维度的 UPSERT。唯一约束在 {@link ResourceTrafficUsage} 上是
     * {@code (tenant_id, client_id, resource_type, resource_key, usage_date)}，五列复合键。
     */
    private boolean upsertResourceTrafficUsage(ClientAccount account,
                                               ResourceDescriptor descriptor,
                                               String resourceType,
                                               String resourceKey,
                                               String usageDate,
                                               long uploadBytes,
                                               long downloadBytes,
                                               String updatedAt) {
        String sql = switch (upsertDialect) {
            case DIALECT_POSTGRES, DIALECT_SQLITE -> """
                    INSERT INTO tunnel_resource_traffic_usage
                        (tenant_id, client_id, client_name, resource_type, resource_key,
                         resource_id, resource_name, usage_date,
                         upload_bytes, download_bytes, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (tenant_id, client_id, resource_type, resource_key, usage_date) DO UPDATE SET
                        client_name    = EXCLUDED.client_name,
                        resource_id    = EXCLUDED.resource_id,
                        resource_name  = EXCLUDED.resource_name,
                        upload_bytes   = tunnel_resource_traffic_usage.upload_bytes + EXCLUDED.upload_bytes,
                        download_bytes = tunnel_resource_traffic_usage.download_bytes + EXCLUDED.download_bytes,
                        updated_at     = EXCLUDED.updated_at
                    """;
            case DIALECT_MYSQL -> """
                    INSERT INTO tunnel_resource_traffic_usage
                        (tenant_id, client_id, client_name, resource_type, resource_key,
                         resource_id, resource_name, usage_date,
                         upload_bytes, download_bytes, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON DUPLICATE KEY UPDATE
                        client_name    = VALUES(client_name),
                        resource_id    = VALUES(resource_id),
                        resource_name  = VALUES(resource_name),
                        upload_bytes   = upload_bytes + VALUES(upload_bytes),
                        download_bytes = download_bytes + VALUES(download_bytes),
                        updated_at     = VALUES(updated_at)
                    """;
            default -> null;
        };
        if (sql == null) {
            return false;
        }
        try {
            jdbcTemplate.update(sql,
                    account.getTenantId(),
                    account.getId(),
                    account.getClientName(),
                    resourceType,
                    resourceKey,
                    descriptor.resourceId(),
                    descriptor.resourceName(),
                    usageDate,
                    uploadBytes,
                    downloadBytes,
                    updatedAt);
            return true;
        } catch (DataAccessException e) {
            log.warn("[resource-traffic-usage] UPSERT failed, will fall back: {}", e.getMessage());
            return false;
        }
    }

    private ResourceDescriptor resolveResource(ClientAccount account, String resourceType, String resourceKey) {
        if (RESOURCE_TYPE_TCP_TUNNEL.equals(resourceType)) {
            int listenPort = parseTcpKey(resourceKey);
            TunnelMapping mapping = tunnelMappingRepository.findByListenPort(listenPort)
                    .filter(row -> Objects.equals(row.getClientId(), account.getId()))
                    .filter(row -> Objects.equals(row.getTenantId(), account.getTenantId()))
                    .orElse(null);
            if (mapping != null) {
                return new ResourceDescriptor(mapping.getId(),
                        mapping.getListenPort() + " -> " + mapping.getTargetAddress() + ":" + mapping.getTargetPort());
            }
            return new ResourceDescriptor(null, "端口 " + listenPort);
        }
        if (RESOURCE_TYPE_HTTP_ROUTE.equals(resourceType)) {
            String route = parseHttpKey(resourceKey);
            HttpRouteMapping mapping = httpRouteMappingRepository
                    .findByTenantIdAndClientIdAndRoute(account.getTenantId(), account.getId(), route)
                    .orElse(null);
            if (mapping != null) {
                return new ResourceDescriptor(mapping.getId(), mapping.getRoute() + " -> " + mapping.getTargetBaseUrl());
            }
            return new ResourceDescriptor(null, route);
        }
        return new ResourceDescriptor(null, resourceKey);
    }

    private static String tcpKey(int listenPort) {
        return "tcp:" + listenPort;
    }

    private static int parseTcpKey(String resourceKey) {
        if (resourceKey != null && resourceKey.startsWith("tcp:")) {
            return Integer.parseInt(resourceKey.substring("tcp:".length()));
        }
        return 0;
    }

    private static String httpKey(String route) {
        return "http:" + (route == null ? "" : route);
    }

    private static String parseHttpKey(String resourceKey) {
        if (resourceKey != null && resourceKey.startsWith("http:")) {
            return resourceKey.substring("http:".length());
        }
        return resourceKey == null ? "" : resourceKey;
    }

    /**
     * S1.3 两级 map 用 {@code resourceKey}（前缀 {@code "tcp:"} / {@code "http:"}）做内层 key，
     * flush 时需要从 key 反推 {@code resourceType} 以走 {@link #resolveResource}。
     */
    private static String inferResourceType(String resourceKey) {
        if (resourceKey == null) {
            return RESOURCE_TYPE_TCP_TUNNEL;
        }
        return resourceKey.startsWith("http:") ? RESOURCE_TYPE_HTTP_ROUTE : RESOURCE_TYPE_TCP_TUNNEL;
    }

    private record ResourceDescriptor(Long resourceId, String resourceName) {
    }

    private static class TrafficCounter {
        private final LongAdder upload = new LongAdder();
        private final LongAdder download = new LongAdder();
    }
}
