package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.ConnectionStat;
import com.theshuai.tunnelserver.management.model.ConnectionStatView;
import com.theshuai.tunnelserver.management.repository.ConnectionRecordRepository;
import com.theshuai.tunnelserver.management.repository.ConnectionStatRepository;
import com.theshuai.tunnelserver.management.repository.ConnectionStatRow;
import com.theshuai.tunnelserver.management.tenant.TenantContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;

/**
 * Archives expired connection-record detail instead of discarding it: rows older than the retained
 * window are rolled up into per-natural-month totals (kept indefinitely) and only then deleted from
 * the hot table. Detail is retained for a rolling {@code detailRetentionDays} window from today.
 * A month straddling the cutoff is archived incrementally as its days age out — counts are merged,
 * and archived rows are deleted in the same transaction, so totals never double-count.
 */
@Service
@Slf4j
public class ConnectionArchiveService {
    private final ConnectionRecordRepository connectionRecordRepository;
    private final ConnectionStatRepository connectionStatRepository;
    private final int detailRetentionDays;

    public ConnectionArchiveService(ConnectionRecordRepository connectionRecordRepository,
                                    ConnectionStatRepository connectionStatRepository,
                                    @Value("${tunnel.connection-record.detail-retention-days:60}") int detailRetentionDays) {
        this.connectionRecordRepository = connectionRecordRepository;
        this.connectionStatRepository = connectionStatRepository;
        this.detailRetentionDays = detailRetentionDays;
    }

    @Scheduled(
            fixedDelayString = "${tunnel.connection-record.archive-interval-ms:3600000}",
            initialDelayString = "${tunnel.connection-record.archive-interval-ms:3600000}")
    @Transactional
    public void archive() {
        if (detailRetentionDays <= 0) {
            return;
        }
        // Start of the rolling retention window. Comparing the full ISO connectedAt against this
        // 10-char date is correct: any timestamp on/after this day is a longer string that sorts
        // after it, so only earlier days are archived. (Avoids millisecond-precision pitfalls.)
        String cutoff = LocalDate.now(ZoneOffset.UTC).minusDays(detailRetentionDays).toString();

        List<ConnectionStatRow> monthlyRows = connectionRecordRepository.aggregateMonthlyBefore(cutoff);
        if (monthlyRows.isEmpty()) {
            return;
        }

        String now = Instant.now().toString();
        for (ConnectionStatRow row : monthlyRows) {
            long total = row.total() == null ? 0L : row.total();
            long success = row.success() == null ? 0L : row.success();
            upsert(row.tenantId(), row.clientId(), row.clientName(), row.month(), total, success, now);
        }

        int purged = connectionRecordRepository.deleteByConnectedAtBefore(cutoff);
        log.info("[archive] rolled up {} month-bucket(s), purged {} detail row(s) before {}",
                monthlyRows.size(), purged, cutoff);
    }

    @Transactional(readOnly = true)
    public List<ConnectionStatView> listStats(String clientName, int limit) {
        return listStats(TenantContext.defaultTenant(), clientName, limit);
    }

    @Transactional(readOnly = true)
    public List<ConnectionStatView> listStats(TenantContext tenant, String clientName, int limit) {
        Pageable pageable = PageRequest.of(0, Math.max(1, Math.min(limit, 500)));
        List<ConnectionStat> stats = StringUtils.hasText(clientName)
                ? connectionStatRepository.findByTenantIdAndClientNameOrderByStatMonthDesc(
                        tenant.tenantId(), clientName.trim(), pageable)
                : connectionStatRepository.findByTenantIdOrderByStatMonthDescClientNameAsc(tenant.tenantId(), pageable);
        return stats.stream().map(this::toView).toList();
    }

    private void upsert(String tenantId, Long clientId, String clientName, String month, long total, long success, String now) {
        ConnectionStat stat = connectionStatRepository
                .findByTenantIdAndClientNameAndStatMonth(tenantId, clientName, month)
                .orElseGet(ConnectionStat::new);
        if (stat.getId() == null) {
            stat.setTenantId(tenantId);
            stat.setClientName(clientName);
            stat.setStatMonth(month);
        }
        stat.setClientId(clientId);
        stat.setTotalCount(stat.getTotalCount() + total);
        stat.setSuccessCount(stat.getSuccessCount() + success);
        stat.setFailureCount(stat.getFailureCount() + (total - success));
        stat.setUpdatedAt(now);
        connectionStatRepository.save(stat);
    }

    private ConnectionStatView toView(ConnectionStat stat) {
        return new ConnectionStatView(
                stat.getId(),
                stat.getClientId(),
                stat.getClientName(),
                stat.getStatMonth(),
                stat.getTotalCount(),
                stat.getSuccessCount(),
                stat.getFailureCount(),
                stat.getUpdatedAt()
        );
    }
}
