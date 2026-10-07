package com.theshuai.specusserver.productmetrics;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * The four tables of the opt-in product metrics (protocol/spec/product-metrics.md section 6),
 * declared as entities only so Hibernate's schema update creates them like every other table.
 * Every read and write goes through {@link ProductMetricsStore}: the counters need atomic upserts
 * that JPA cannot express. Times are epoch milliseconds, days are UTC {@code YYYY-MM-DD} text; the
 * two daily tables carry no user column. Table and column names match the Go, .NET and C servers.
 */
public final class ProductMetricsTables {
    private ProductMetricsTables() {
    }

    /** The per-tenant switch; no row means off. */
    @Entity(name = "ProductMetricsSwitch")
    @Table(name = "product_metrics_switch")
    @Getter
    @Setter
    @NoArgsConstructor
    public static class Switch {
        @Id
        @Column(name = "tenant_id", nullable = false, length = 80)
        private String tenantId;

        @Column(name = "enabled", nullable = false)
        private boolean enabled;

        @Column(name = "updated_by", length = 80)
        private String updatedBy;

        @Column(name = "updated_at")
        private Long updatedAt;

        @Column(name = "purged_at")
        private Long purgedAt;
    }

    /** Onboarding progress of one account, kept only for the 14-day window. */
    @Entity(name = "ProductMetricsOnboardingProgress")
    @Table(name = "product_metrics_onboarding_progress")
    @Getter
    @Setter
    @NoArgsConstructor
    public static class OnboardingProgress {
        @EmbeddedId
        private AccountKey key;

        @Column(name = "started_at", nullable = false)
        private long startedAt;

        @Column(name = "signed_in_at")
        private Long signedInAt;

        @Column(name = "credential_created_at")
        private Long credentialCreatedAt;

        @Column(name = "client_online_at")
        private Long clientOnlineAt;
    }

    @Embeddable
    public record AccountKey(
            @Column(name = "tenant_id", nullable = false, length = 80) String tenantId,
            @Column(name = "username", nullable = false, length = 80) String username) {
    }

    /** Closed onboarding rows folded into a cohort-day counter. */
    @Entity(name = "ProductMetricsOnboardingDaily")
    @Table(name = "product_metrics_onboarding_daily")
    @Getter
    @Setter
    @NoArgsConstructor
    public static class OnboardingDaily {
        @EmbeddedId
        private CohortKey key;

        @Column(name = "users", nullable = false)
        private long users;
    }

    @Embeddable
    public record CohortKey(
            @Column(name = "tenant_id", nullable = false, length = 80) String tenantId,
            @Column(name = "cohort_day", nullable = false, length = 10) String cohortDay,
            @Column(name = "reached_step", nullable = false, length = 32) String reachedStep,
            @Column(name = "duration_bucket", nullable = false, length = 16) String durationBucket) {
    }

    /** Reported transfer attempts counted per day and closed-field combination. */
    @Entity(name = "ProductMetricsTransferDaily")
    @Table(name = "product_metrics_transfer_daily")
    @Getter
    @Setter
    @NoArgsConstructor
    public static class TransferDaily {
        @EmbeddedId
        private TransferKey key;

        @Column(name = "count", nullable = false)
        private long count;
    }

    @Embeddable
    public record TransferKey(
            @Column(name = "tenant_id", nullable = false, length = 80) String tenantId,
            @Column(name = "day", nullable = false, length = 10) String day,
            @Column(name = "mode", nullable = false, length = 16) String mode,
            @Column(name = "path", nullable = false, length = 16) String path,
            @Column(name = "size_bucket", nullable = false, length = 16) String sizeBucket,
            @Column(name = "attempt", nullable = false, length = 32) String attempt,
            @Column(name = "outcome", nullable = false, length = 16) String outcome) {
    }
}
