package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.ConnectionRecord;
import com.theshuai.tunnelserver.management.model.ConnectionStat;
import com.theshuai.tunnelserver.management.model.ConnectionStatView;
import com.theshuai.tunnelserver.management.repository.ConnectionRecordRepository;
import com.theshuai.tunnelserver.management.repository.ConnectionStatRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {
                // Shared-cache in-memory SQLite so the archive job's connection sees the test's inserts.
                "spring.datasource.url=jdbc:sqlite:file:target/test-archive?mode=memory&cache=shared",
                "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "tunnel.netty.port=0",
                "tunnel.database.seed-demo-client=false",
                "tunnel.connection-record.detail-retention-days=60"
        }
)
class ConnectionArchiveServiceTests {

    private static final String CLIENT = "ArchiveClient";

    @Autowired
    private ConnectionArchiveService connectionArchiveService;
    @Autowired
    private ConnectionRecordRepository connectionRecordRepository;
    @Autowired
    private ConnectionStatRepository connectionStatRepository;

    @Test
    void rollsUpDetailOlderThan60DaysIntoMonthlyTotalsThenPurges() {
        connectionRecordRepository.deleteAll();
        connectionStatRepository.deleteAll();

        LocalDate today = LocalDate.now(ZoneOffset.UTC);
        // Both clearly older than the 60-day window and in two distinct natural months.
        LocalDate oldMonthA = today.minusMonths(4);
        LocalDate oldMonthB = today.minusMonths(3);
        // Inside the 60-day window -> must be retained as raw detail.
        LocalDate recent = today.minusDays(5);

        String monthA = oldMonthA.toString().substring(0, 7);
        String monthB = oldMonthB.toString().substring(0, 7);
        String recentMonth = recent.toString().substring(0, 7);

        // monthA: 2 success + 1 failure; monthB: 1 success.
        save(oldMonthA, true);
        save(oldMonthA, true);
        save(oldMonthA, false);
        save(oldMonthB, true);
        // recent detail must survive.
        save(recent, true);
        save(recent, false);

        connectionArchiveService.archive();

        // Only the recent (within 60 days) detail remains.
        assertThat(connectionRecordRepository.count()).isEqualTo(2);

        ConnectionStat statA = requireStat(monthA);
        assertThat(statA.getTotalCount()).isEqualTo(3);
        assertThat(statA.getSuccessCount()).isEqualTo(2);
        assertThat(statA.getFailureCount()).isEqualTo(1);

        ConnectionStat statB = requireStat(monthB);
        assertThat(statB.getTotalCount()).isEqualTo(1);
        assertThat(statB.getSuccessCount()).isEqualTo(1);
        assertThat(statB.getFailureCount()).isEqualTo(0);

        // The recent month is still raw detail, not archived yet.
        assertThat(connectionStatRepository.findByClientNameAndStatMonth(CLIENT, recentMonth)).isEmpty();

        List<ConnectionStatView> stats = connectionArchiveService.listStats(CLIENT, 100);
        assertThat(stats).extracting(ConnectionStatView::month).containsExactlyInAnyOrder(monthA, monthB);
    }

    private void save(LocalDate date, boolean success) {
        ConnectionRecord record = new ConnectionRecord();
        record.setClientId(1L);
        record.setClientName(CLIENT);
        record.setConnectedAt(date + "T08:00:00.000Z");
        record.setSuccess(success);
        connectionRecordRepository.save(record);
    }

    private ConnectionStat requireStat(String month) {
        Optional<ConnectionStat> stat = connectionStatRepository.findByClientNameAndStatMonth(CLIENT, month);
        assertThat(stat).as("stat for %s", month).isPresent();
        return stat.orElseThrow();
    }
}
