namespace Specus.Server.Data.Entities;

// Opt-in product metrics (protocol/spec/product-metrics.md section 6). Table and column names match
// the Go, Java and C servers. Times are epoch milliseconds; days are UTC "yyyy-MM-dd" text, so day
// ranges and the retention cutoff are plain string comparisons. The two daily tables carry no user
// column; the progress row is the only data with an account name and lives at most for the
// onboarding window plus one sweep.

/// <summary>The per-tenant switch; a tenant without a row is off.</summary>
public sealed class ProductMetricsSwitch
{
    public string TenantId { get; set; } = "default";
    public bool Enabled { get; set; }
    public string? UpdatedBy { get; set; }
    public long? UpdatedAt { get; set; }
    public long? PurgedAt { get; set; }
}

/// <summary>Onboarding progress of one account during its 14-day window.</summary>
public sealed class ProductMetricsOnboardingProgress
{
    public string TenantId { get; set; } = "default";
    public string Username { get; set; } = string.Empty;
    public long StartedAt { get; set; }
    public long? SignedInAt { get; set; }
    public long? CredentialCreatedAt { get; set; }
    public long? ClientOnlineAt { get; set; }
}

/// <summary>Closed onboarding rows folded into a cohort-day counter.</summary>
public sealed class ProductMetricsOnboardingDaily
{
    public string TenantId { get; set; } = "default";
    public string CohortDay { get; set; } = string.Empty;
    public string ReachedStep { get; set; } = string.Empty;
    public string DurationBucket { get; set; } = string.Empty;
    public long Users { get; set; }
}

/// <summary>Reported transfer attempts counted per day and closed-field combination.</summary>
public sealed class ProductMetricsTransferDaily
{
    public string TenantId { get; set; } = "default";
    public string Day { get; set; } = string.Empty;
    public string Mode { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string SizeBucket { get; set; } = string.Empty;
    public string Attempt { get; set; } = string.Empty;
    public string Outcome { get; set; } = string.Empty;
    public long Count { get; set; }
}
