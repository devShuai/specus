package com.theshuai.specusserver.productmetrics;

import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Reads and writes the four product metrics tables with plain SQL. Called inside the service's
 * transactions, it shares their connection; the counters only ever move by atomic upserts
 * ({@code ON CONFLICT ... DO UPDATE} on SQLite/PostgreSQL, {@code ON DUPLICATE KEY UPDATE} on
 * MySQL), never by read-then-write.
 */
@Component
@Slf4j
public class ProductMetricsStore {
    /** The milestone columns {@link #setMilestone} accepts. */
    public static final List<String> MILESTONE_COLUMNS = List.of("signed_in_at", "credential_created_at",
            "client_online_at");

    private final JdbcTemplate jdbc;
    private final boolean mysql;

    public ProductMetricsStore(JdbcTemplate jdbc, DataSource dataSource) {
        this.jdbc = jdbc;
        this.mysql = isMySql(dataSource);
    }

    private static boolean isMySql(DataSource dataSource) {
        try (Connection connection = dataSource.getConnection()) {
            String product = connection.getMetaData().getDatabaseProductName();
            String normalized = product == null ? "" : product.toLowerCase(java.util.Locale.ROOT);
            return normalized.contains("mysql") || normalized.contains("mariadb");
        } catch (SQLException e) {
            log.warn("[product-metrics] database product detection failed: {}", e.getMessage());
            return false;
        }
    }

    public record SwitchRow(String tenantId, boolean enabled, String updatedBy, Long updatedAt, Long purgedAt) {
    }

    public record ProgressRow(String tenantId, String username, long startedAt, Long signedInAt,
                              Long credentialCreatedAt, Long clientOnlineAt) {
    }

    public record OnboardingCount(String tenantId, String cohortDay, String reachedStep, String durationBucket,
                                  long users) {
    }

    public record TransferCount(String tenantId, String day, String mode, String path, String sizeBucket,
                                String attempt, String outcome, long count) {
    }

    private static final RowMapper<SwitchRow> SWITCH = (rs, row) -> new SwitchRow(rs.getString(1),
            rs.getBoolean(2), rs.getString(3), nullableLong(rs, 4), nullableLong(rs, 5));
    private static final RowMapper<ProgressRow> PROGRESS = (rs, row) -> new ProgressRow(rs.getString(1),
            rs.getString(2), rs.getLong(3), nullableLong(rs, 4), nullableLong(rs, 5), nullableLong(rs, 6));
    private static final RowMapper<OnboardingCount> ONBOARDING = (rs, row) -> new OnboardingCount(rs.getString(1),
            rs.getString(2), rs.getString(3), rs.getString(4), rs.getLong(5));
    private static final RowMapper<TransferCount> TRANSFER = (rs, row) -> new TransferCount(rs.getString(1),
            rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7),
            rs.getLong(8));

    private static Long nullableLong(ResultSet rs, int column) throws SQLException {
        long value = rs.getLong(column);
        return rs.wasNull() ? null : value;
    }

    // -- switch -------------------------------------------------------------------------------------

    public Optional<SwitchRow> findSwitch(String tenantId) {
        return jdbc.query("SELECT tenant_id, enabled, updated_by, updated_at, purged_at FROM product_metrics_switch"
                + " WHERE tenant_id = ?", SWITCH, tenantId).stream().findFirst();
    }

    public List<SwitchRow> switches() {
        return jdbc.query("SELECT tenant_id, enabled, updated_by, updated_at, purged_at FROM product_metrics_switch",
                SWITCH);
    }

    /**
     * Writes the whole switch row, inserting it when absent, in one upsert (an UPDATE that changes
     * nothing may report no affected row, so "update, else insert" could collide).
     */
    public void saveSwitch(SwitchRow row) {
        String sql = mysql
                ? "INSERT INTO product_metrics_switch (tenant_id, enabled, updated_by, updated_at, purged_at)"
                + " VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE enabled = VALUES(enabled),"
                + " updated_by = VALUES(updated_by), updated_at = VALUES(updated_at), purged_at = VALUES(purged_at)"
                : "INSERT INTO product_metrics_switch (tenant_id, enabled, updated_by, updated_at, purged_at)"
                + " VALUES (?, ?, ?, ?, ?) ON CONFLICT (tenant_id) DO UPDATE SET enabled = excluded.enabled,"
                + " updated_by = excluded.updated_by, updated_at = excluded.updated_at, purged_at = excluded.purged_at";
        jdbc.update(sql, row.tenantId(), row.enabled(), row.updatedBy(), row.updatedAt(), row.purgedAt());
    }

    // -- onboarding progress ------------------------------------------------------------------------

    /** Starts a progress row and reports whether it did; an existing row is left untouched. */
    public boolean insertProgressIfAbsent(ProgressRow row) {
        String sql = mysql
                ? "INSERT INTO product_metrics_onboarding_progress (tenant_id, username, started_at, signed_in_at,"
                + " credential_created_at, client_online_at) VALUES (?, ?, ?, ?, ?, ?)"
                + " ON DUPLICATE KEY UPDATE tenant_id = tenant_id"
                : "INSERT INTO product_metrics_onboarding_progress (tenant_id, username, started_at, signed_in_at,"
                + " credential_created_at, client_online_at) VALUES (?, ?, ?, ?, ?, ?)"
                + " ON CONFLICT (tenant_id, username) DO NOTHING";
        return jdbc.update(sql, row.tenantId(), row.username(), row.startedAt(), row.signedInAt(),
                row.credentialCreatedAt(), row.clientOnlineAt()) == 1;
    }

    public Optional<ProgressRow> findProgress(String tenantId, String username) {
        return jdbc.query("SELECT tenant_id, username, started_at, signed_in_at, credential_created_at,"
                + " client_online_at FROM product_metrics_onboarding_progress WHERE tenant_id = ? AND username = ?",
                PROGRESS, tenantId, username).stream().findFirst();
    }

    /** Progress rows of one tenant, or of every tenant when {@code tenantId} is null. */
    public List<ProgressRow> progressRows(String tenantId) {
        String sql = "SELECT tenant_id, username, started_at, signed_in_at, credential_created_at, client_online_at"
                + " FROM product_metrics_onboarding_progress";
        return tenantId == null ? jdbc.query(sql, PROGRESS) : jdbc.query(sql + " WHERE tenant_id = ?", PROGRESS,
                tenantId);
    }

    /** Records a milestone unless one is recorded: the first occurrence wins, also across instances. */
    public boolean setMilestone(String tenantId, String username, String column, long at) {
        if (!MILESTONE_COLUMNS.contains(column)) {
            throw new IllegalArgumentException("unknown milestone column");
        }
        return jdbc.update("UPDATE product_metrics_onboarding_progress SET " + column + " = ?"
                + " WHERE tenant_id = ? AND username = ? AND " + column + " IS NULL", at, tenantId, username) == 1;
    }

    /** Deletes one account's progress row and returns how many rows went. */
    public int deleteProgress(String tenantId, String username) {
        return jdbc.update("DELETE FROM product_metrics_onboarding_progress WHERE tenant_id = ? AND username = ?",
                tenantId, username);
    }

    public void deleteTenantProgress(String tenantId) {
        jdbc.update("DELETE FROM product_metrics_onboarding_progress WHERE tenant_id = ?", tenantId);
    }

    // -- daily counts -------------------------------------------------------------------------------

    public void addOnboardingCount(OnboardingCount row) {
        String sql = mysql
                ? "INSERT INTO product_metrics_onboarding_daily (tenant_id, cohort_day, reached_step, duration_bucket,"
                + " users) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE users = users + VALUES(users)"
                : "INSERT INTO product_metrics_onboarding_daily (tenant_id, cohort_day, reached_step, duration_bucket,"
                + " users) VALUES (?, ?, ?, ?, ?) ON CONFLICT (tenant_id, cohort_day, reached_step, duration_bucket)"
                + " DO UPDATE SET users = product_metrics_onboarding_daily.users + excluded.users";
        jdbc.update(sql, row.tenantId(), row.cohortDay(), row.reachedStep(), row.durationBucket(), row.users());
    }

    public void addTransferCount(TransferCount row) {
        String sql = mysql
                ? "INSERT INTO product_metrics_transfer_daily (tenant_id, day, mode, path, size_bucket, attempt,"
                + " outcome, count) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE count = count + VALUES(count)"
                : "INSERT INTO product_metrics_transfer_daily (tenant_id, day, mode, path, size_bucket, attempt,"
                + " outcome, count) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                + " ON CONFLICT (tenant_id, day, mode, path, size_bucket, attempt, outcome)"
                + " DO UPDATE SET count = product_metrics_transfer_daily.count + excluded.count";
        jdbc.update(sql, row.tenantId(), row.day(), row.mode(), row.path(), row.sizeBucket(), row.attempt(),
                row.outcome(), row.count());
    }

    /** Cohort counters of a tenant (null: every tenant) with fromDay <= cohort_day <= toDay (null: open). */
    public List<OnboardingCount> onboardingCounts(String tenantId, String fromDay, String toDay) {
        List<Object> args = new ArrayList<>();
        String where = dayFilter("cohort_day", tenantId, fromDay, toDay, args);
        return jdbc.query("SELECT tenant_id, cohort_day, reached_step, duration_bucket, users"
                + " FROM product_metrics_onboarding_daily" + where, ONBOARDING, args.toArray());
    }

    /** Transfer counters filtered like {@link #onboardingCounts}. */
    public List<TransferCount> transferCounts(String tenantId, String fromDay, String toDay) {
        List<Object> args = new ArrayList<>();
        String where = dayFilter("day", tenantId, fromDay, toDay, args);
        return jdbc.query("SELECT tenant_id, day, mode, path, size_bucket, attempt, outcome, count"
                + " FROM product_metrics_transfer_daily" + where, TRANSFER, args.toArray());
    }

    public void deleteTenantCounts(String tenantId) {
        jdbc.update("DELETE FROM product_metrics_onboarding_daily WHERE tenant_id = ?", tenantId);
        jdbc.update("DELETE FROM product_metrics_transfer_daily WHERE tenant_id = ?", tenantId);
    }

    public void deleteCountsBefore(String cutoffDay) {
        jdbc.update("DELETE FROM product_metrics_onboarding_daily WHERE cohort_day < ?", cutoffDay);
        jdbc.update("DELETE FROM product_metrics_transfer_daily WHERE day < ?", cutoffDay);
    }

    private static String dayFilter(String column, String tenantId, String fromDay, String toDay, List<Object> args) {
        List<String> clauses = new ArrayList<>();
        if (tenantId != null) {
            clauses.add("tenant_id = ?");
            args.add(tenantId);
        }
        if (fromDay != null) {
            clauses.add(column + " >= ?");
            args.add(fromDay);
        }
        if (toDay != null) {
            clauses.add(column + " <= ?");
            args.add(toDay);
        }
        return clauses.isEmpty() ? "" : " WHERE " + String.join(" AND ", clauses);
    }
}
