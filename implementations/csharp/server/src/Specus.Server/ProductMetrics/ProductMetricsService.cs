using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using static Specus.Server.ProductMetrics.ProductMetricsModel;

namespace Specus.Server.ProductMetrics;

/// <summary>
/// Server side of the opt-in product metrics (protocol/spec/product-metrics.md): the tenant switch,
/// the onboarding milestones observed on the server's own write paths, transfer-outcome ingest, the
/// retention sweep, purge and the summary. A singleton: every operation opens its own scope and
/// database context, so the control channel and the HTTP endpoints share it. Every count lives in
/// the shared database; only the rate limiter is per process. Logs carry the tenant and the
/// operation, never a username, request body, credential, file name or address.
/// </summary>
public sealed class ProductMetricsService
{
    private readonly IServiceScopeFactory _scopes;
    private readonly ProductMetricsClock _clock;
    private readonly ProductMetricsRateLimiter _limiter;
    private readonly IOptionsMonitor<ProductMetricsOptions> _options;
    private readonly ILogger<ProductMetricsService> _logger;

    public ProductMetricsService(IServiceScopeFactory scopes, ProductMetricsClock clock,
        ProductMetricsRateLimiter limiter, IOptionsMonitor<ProductMetricsOptions> options,
        ILogger<ProductMetricsService> logger)
    {
        _scopes = scopes;
        _clock = clock;
        _limiter = limiter;
        _options = options;
        _logger = logger;
    }

    private bool Allowed => _options.CurrentValue.Allowed;

    private bool Collecting(ProductMetricsSwitch? row) => Allowed && row is { Enabled: true };

    private ProductMetricsResult Unavailable(string operation, string tenantId, Exception error)
    {
        _logger.LogWarning("[product-metrics] storage failed: operation={Operation} tenant={TenantId} error={Error}",
            operation, tenantId, error.GetType().Name);
        return ProductMetricsResult.Code(StatusCodes.Status503ServiceUnavailable, "PRODUCT_METRICS_UNAVAILABLE");
    }

    private static bool IsStoreFailure(Exception error, CancellationToken cancellationToken) =>
        !(error is OperationCanceledException && cancellationToken.IsCancellationRequested);

    private async Task<T> WithDbAsync<T>(Func<SpecusDbContext, Task<T>> work)
    {
        await using var scope = _scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        return await work(db).ConfigureAwait(false);
    }

    private static Task<ProductMetricsSwitch?> FindSwitchAsync(SpecusDbContext db, string tenantId,
        CancellationToken cancellationToken) =>
        db.ProductMetricsSwitches.AsNoTracking().FirstOrDefaultAsync(row => row.TenantId == tenantId,
            cancellationToken);

    // -- settings (7.1, 7.2) ------------------------------------------------------------------------

    private Dictionary<string, object?> SettingsView(ProductMetricsSwitch? row, bool admin)
    {
        var view = new Dictionary<string, object?>
        {
            ["schemaVersion"] = SchemaVersion,
            ["enabled"] = Collecting(row),
            ["disclosureVersion"] = DisclosureVersion,
            ["retentionDays"] = RetentionDays,
            ["onboardingWindowDays"] = WindowDays,
            ["updatedAt"] = row?.UpdatedAt is long updatedAt ? Instant(updatedAt) : null,
        };
        if (admin)
        {
            view["updatedBy"] = row?.UpdatedBy;
        }
        return view;
    }

    public async Task<ProductMetricsResult> GetSettingsAsync(ManagementContext context,
        CancellationToken cancellationToken)
    {
        try
        {
            var row = await WithDbAsync(db => FindSwitchAsync(db, context.TenantId, cancellationToken))
                .ConfigureAwait(false);
            return ProductMetricsResult.Ok(SettingsView(row, context.IsAdmin));
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            return Unavailable("settings", context.TenantId, error);
        }
    }

    /// <summary>
    /// PUT /settings. Switching off drops the tenant's progress rows without folding them. Any change
    /// of state clears the purge mark, so while the switch is off the mark only stands for a purge
    /// made after switching off; an unchanged state keeps updatedAt/updatedBy and the mark.
    /// </summary>
    public async Task<ProductMetricsResult> PutSettingsAsync(ManagementContext context, ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken)
    {
        if (!context.IsAdmin)
        {
            return ProductMetricsResult.Forbidden;
        }
        var update = ParseSettingsUpdate(body.Span);
        if (update is null)
        {
            return ProductMetricsResult.Code(StatusCodes.Status400BadRequest, "PRODUCT_METRICS_INVALID");
        }
        if (update.Enabled && update.Disclosure != DisclosureVersion.ToString(CultureInfo.InvariantCulture))
        {
            return ProductMetricsResult.Code(StatusCodes.Status400BadRequest, "PRODUCT_METRICS_DISCLOSURE_REQUIRED");
        }
        if (update.Enabled && !Allowed)
        {
            return ProductMetricsResult.Code(StatusCodes.Status409Conflict, "PRODUCT_METRICS_NOT_ALLOWED");
        }
        var tenant = context.TenantId;
        var now = _clock.NowMs();
        try
        {
            var saved = await WithDbAsync(async db =>
            {
                await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken)
                    .ConfigureAwait(false);
                var row = await db.ProductMetricsSwitches.FirstOrDefaultAsync(item => item.TenantId == tenant,
                    cancellationToken).ConfigureAwait(false);
                if (row is null)
                {
                    row = new ProductMetricsSwitch { TenantId = tenant };
                    db.ProductMetricsSwitches.Add(row);
                }
                if (row.Enabled != update.Enabled)
                {
                    row.Enabled = update.Enabled;
                    row.UpdatedBy = context.Username;
                    row.UpdatedAt = now;
                    row.PurgedAt = null;
                }
                await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                if (!update.Enabled)
                {
                    await db.ProductMetricsOnboardingProgress.Where(item => item.TenantId == tenant)
                        .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
                }
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                return row;
            }).ConfigureAwait(false);
            return ProductMetricsResult.Ok(SettingsView(saved, true));
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            return Unavailable("put-settings", tenant, error);
        }
    }

    // -- purge (7.3) --------------------------------------------------------------------------------

    public async Task<ProductMetricsResult> PurgeAsync(ManagementContext context, CancellationToken cancellationToken)
    {
        if (!context.IsAdmin)
        {
            return ProductMetricsResult.Forbidden;
        }
        var tenant = context.TenantId;
        var now = _clock.NowMs();
        try
        {
            var saved = await WithDbAsync(async db =>
            {
                await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken)
                    .ConfigureAwait(false);
                await DeleteTenantRowsAsync(db, tenant, cancellationToken).ConfigureAwait(false);
                var row = await db.ProductMetricsSwitches.FirstOrDefaultAsync(item => item.TenantId == tenant,
                    cancellationToken).ConfigureAwait(false);
                if (row is null)
                {
                    row = new ProductMetricsSwitch { TenantId = tenant };
                    db.ProductMetricsSwitches.Add(row);
                }
                row.PurgedAt = now;
                await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                return row;
            }).ConfigureAwait(false);
            return ProductMetricsResult.Ok(new Dictionary<string, object?>
            {
                ["purged"] = true,
                ["enabled"] = Collecting(saved),
            });
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            return Unavailable("purge", tenant, error);
        }
    }

    private static async Task DeleteTenantRowsAsync(SpecusDbContext db, string tenant,
        CancellationToken cancellationToken)
    {
        await db.ProductMetricsOnboardingProgress.Where(item => item.TenantId == tenant)
            .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        await db.ProductMetricsOnboardingDaily.Where(item => item.TenantId == tenant)
            .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        await db.ProductMetricsTransferDaily.Where(item => item.TenantId == tenant)
            .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
    }

    // -- ingest (7.4) -------------------------------------------------------------------------------

    /// <summary>
    /// POST /transfer-outcomes after authentication; <paramref name="body"/> holds at most
    /// MaxBodyBytes + 1 raw bytes. Size, schema, switch, limiter, count: a refusal at any step leaves
    /// the limiter alone. Counting is one transaction of atomic upserts.
    /// </summary>
    public async Task<ProductMetricsResult> IngestAsync(ManagementContext context, ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken)
    {
        switch (ParseIngest(body.Span, out var events))
        {
            case IngestRefusal.TooLarge:
                return ProductMetricsResult.Code(StatusCodes.Status413PayloadTooLarge, "PRODUCT_METRICS_TOO_LARGE");
            case IngestRefusal.Invalid:
                return ProductMetricsResult.Code(StatusCodes.Status400BadRequest, "PRODUCT_METRICS_INVALID");
        }
        var tenant = context.TenantId;
        var now = _clock.NowMs();
        var day = DayOf(now);
        var counts = events.GroupBy(item => item).Select(group => (Event: group.Key, Count: (long)group.Count()))
            .ToList();
        try
        {
            return await WithDbAsync(async db =>
            {
                await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken)
                    .ConfigureAwait(false);
                if (!Collecting(await FindSwitchAsync(db, tenant, cancellationToken).ConfigureAwait(false)))
                {
                    return ProductMetricsResult.Ok(new Dictionary<string, object?>
                    {
                        ["collecting"] = false,
                        ["accepted"] = 0,
                    });
                }
                if (!_limiter.TryAdmit(tenant, context.Username, events.Count, now))
                {
                    return ProductMetricsResult.Code(StatusCodes.Status429TooManyRequests,
                        "PRODUCT_METRICS_RATE_LIMITED");
                }
                foreach (var (item, count) in counts)
                {
                    await AddTransferCountAsync(db, new ProductMetricsTransferDaily
                    {
                        TenantId = tenant, Day = day, Mode = item.Mode, Path = item.Path,
                        SizeBucket = item.SizeBucket, Attempt = item.Attempt, Outcome = item.Outcome, Count = count,
                    }, cancellationToken).ConfigureAwait(false);
                }
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                return ProductMetricsResult.Ok(new Dictionary<string, object?>
                {
                    ["collecting"] = true,
                    ["accepted"] = events.Count,
                });
            }).ConfigureAwait(false);
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            return Unavailable("ingest", tenant, error);
        }
    }

    // -- onboarding milestones (4.1) ----------------------------------------------------------------

    internal static string ReachedStep(ProductMetricsOnboardingProgress row) =>
        row.ClientOnlineAt is not null ? StepClientOnline
        : row.CredentialCreatedAt is not null ? StepCredentialCreated
        : row.SignedInAt is not null ? StepSignedIn
        : StepAccountCreated;

    /// <summary>
    /// Records one onboarding milestone, called after the write path it belongs to succeeded.
    /// Returns the effect ("ignored", "started", "recorded", "completed", "expired"), which only tests
    /// read. Never throws: a metrics failure must not fail the write it observes.
    /// </summary>
    public async Task<string> MilestoneAsync(string? tenantId, string? username, string step,
        CancellationToken cancellationToken = default)
    {
        var tenant = ManagementContext.NormalizeTenant(tenantId);
        try
        {
            return await RecordMilestoneAsync(tenant, username, step, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error)
        {
            _logger.LogWarning("[product-metrics] milestone failed: tenant={TenantId} step={Step} error={Error}",
                tenant, step, error.GetType().Name);
            return "ignored";
        }
    }

    private async Task<string> RecordMilestoneAsync(string tenant, string? username, string step,
        CancellationToken cancellationToken)
    {
        if (!Allowed || string.IsNullOrWhiteSpace(username))
        {
            return "ignored";
        }
        return await WithDbAsync(async db =>
        {
            if (!Collecting(await FindSwitchAsync(db, tenant, cancellationToken).ConfigureAwait(false)))
            {
                return "ignored";
            }
            var now = _clock.NowMs();
            if (step == StepAccountCreated)
            {
                return await InsertProgressIfAbsentAsync(db, tenant, username, now, cancellationToken)
                    .ConfigureAwait(false) ? "started" : "ignored";
            }
            if (step is not (StepSignedIn or StepCredentialCreated or StepClientOnline or StepServicePublished))
            {
                return "ignored";
            }
            var progress = await db.ProductMetricsOnboardingProgress.AsNoTracking()
                .FirstOrDefaultAsync(row => row.TenantId == tenant && row.Username == username, cancellationToken)
                .ConfigureAwait(false);
            if (progress is null)
            {
                return "ignored";
            }
            if (now >= progress.StartedAt + WindowMs)
            {
                await CloseAsync(db, tenant, username, null, cancellationToken).ConfigureAwait(false);
                return "expired";
            }
            if (step == StepServicePublished)
            {
                return await CloseAsync(db, tenant, username, now, cancellationToken).ConfigureAwait(false)
                    ? "completed" : "ignored";
            }
            var rows = db.ProductMetricsOnboardingProgress.Where(row => row.TenantId == tenant && row.Username == username);
            var updated = step switch
            {
                StepSignedIn => await rows.Where(row => row.SignedInAt == null)
                    .ExecuteUpdateAsync(set => set.SetProperty(row => row.SignedInAt, now), cancellationToken)
                    .ConfigureAwait(false),
                StepCredentialCreated => await rows.Where(row => row.CredentialCreatedAt == null)
                    .ExecuteUpdateAsync(set => set.SetProperty(row => row.CredentialCreatedAt, now), cancellationToken)
                    .ConfigureAwait(false),
                _ => await rows.Where(row => row.ClientOnlineAt == null)
                    .ExecuteUpdateAsync(set => set.SetProperty(row => row.ClientOnlineAt, now), cancellationToken)
                    .ConfigureAwait(false),
            };
            return updated == 1 ? "recorded" : "ignored";
        }).ConfigureAwait(false);
    }

    /// <summary>
    /// Folds one progress row into its cohort counter: completed when <paramref name="completedAt"/> is
    /// set, otherwise at the furthest recorded step. The counter moves only after exactly one row was
    /// deleted, so a completion racing the sweep or another instance counts once.
    /// </summary>
    private async Task<bool> CloseAsync(SpecusDbContext db, string tenant, string username, long? completedAt,
        CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        var row = await db.ProductMetricsOnboardingProgress.AsNoTracking()
            .FirstOrDefaultAsync(item => item.TenantId == tenant && item.Username == username, cancellationToken)
            .ConfigureAwait(false);
        if (row is null)
        {
            return false;
        }
        var removed = await db.ProductMetricsOnboardingProgress
            .Where(item => item.TenantId == tenant && item.Username == username)
            .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        if (removed != 1)
        {
            return false;
        }
        var reached = ReachedStep(row);
        var bucket = NoDuration;
        if (completedAt is long completed)
        {
            var duration = DurationBucket(Math.Max(0, completed - row.StartedAt) / 1000);
            if (duration is null)
            {
                return false; // unreachable: such a row expires instead of completing
            }
            reached = StepServicePublished;
            bucket = duration;
        }
        await AddOnboardingCountAsync(db, new ProductMetricsOnboardingDaily
        {
            TenantId = tenant, CohortDay = DayOf(row.StartedAt), ReachedStep = reached, DurationBucket = bucket,
            Users = 1,
        }, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return true;
    }

    /// <summary>service_published for the owner of the client a route or mapping was created on.</summary>
    public async Task ServicePublishedAsync(long clientId, CancellationToken cancellationToken = default)
    {
        try
        {
            var account = await WithDbAsync(db => db.ClientAccounts.AsNoTracking()
                .Where(item => item.Id == clientId)
                .Select(item => new { item.TenantId, item.OwnerUsername })
                .FirstOrDefaultAsync(cancellationToken)).ConfigureAwait(false);
            if (account is not null)
            {
                await MilestoneAsync(account.TenantId, account.OwnerUsername, StepServicePublished, cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        catch (Exception error)
        {
            _logger.LogWarning("[product-metrics] service lookup failed: error={Error}", error.GetType().Name);
        }
    }

    /// <summary>Drops a deleted account's progress row without folding it into any count.</summary>
    public async Task<string> UserDeletedAsync(string? tenantId, string username,
        CancellationToken cancellationToken = default)
    {
        var tenant = ManagementContext.NormalizeTenant(tenantId);
        try
        {
            var removed = await WithDbAsync(db => db.ProductMetricsOnboardingProgress
                .Where(row => row.TenantId == tenant && row.Username == username)
                .ExecuteDeleteAsync(cancellationToken)).ConfigureAwait(false);
            return removed > 0 ? "deleted" : "ignored";
        }
        catch (Exception error)
        {
            _logger.LogWarning("[product-metrics] progress removal failed: tenant={TenantId} error={Error}", tenant,
                error.GetType().Name);
            return "ignored";
        }
    }

    // -- retention (9) ------------------------------------------------------------------------------

    /// <summary>
    /// The four retention steps of section 9; idempotent and independent of when it runs. Step 4 only
    /// reaches tenants purged since they switched off: switching off clears the mark a purge made
    /// while collecting.
    /// </summary>
    public Task SweepAsync(CancellationToken cancellationToken) => WithDbAsync(async db =>
    {
        var now = _clock.NowMs();
        var switches = await db.ProductMetricsSwitches.AsNoTracking().ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        var collecting = switches.ToDictionary(row => row.TenantId, Collecting, StringComparer.Ordinal);
        var progress = await db.ProductMetricsOnboardingProgress.AsNoTracking().ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        foreach (var row in progress.OrderBy(row => row.TenantId, StringComparer.Ordinal)
                     .ThenBy(row => row.Username, StringComparer.Ordinal))
        {
            if (!collecting.GetValueOrDefault(row.TenantId))
            {
                await db.ProductMetricsOnboardingProgress
                    .Where(item => item.TenantId == row.TenantId && item.Username == row.Username)
                    .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
            }
            else if (now >= row.StartedAt + WindowMs)
            {
                await CloseAsync(db, row.TenantId, row.Username, null, cancellationToken).ConfigureAwait(false);
            }
        }
        var cutoff = DayOf(now - (RetentionDays - 1) * DayMs);
        await db.Database.ExecuteSqlRawAsync("DELETE FROM product_metrics_onboarding_daily WHERE cohort_day < {0}",
            [cutoff], cancellationToken).ConfigureAwait(false);
        await db.Database.ExecuteSqlRawAsync("DELETE FROM product_metrics_transfer_daily WHERE day < {0}",
            [cutoff], cancellationToken).ConfigureAwait(false);
        foreach (var row in switches.Where(row => !row.Enabled && row.PurgedAt is not null))
        {
            await DeleteTenantRowsAsync(db, row.TenantId, cancellationToken).ConfigureAwait(false);
        }
        return true;
    });

    // -- summary (7.5) ------------------------------------------------------------------------------

    private static DateOnly? ParseDay(string? text) =>
        text is { Length: 10 }
        && DateOnly.TryParseExact(text, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var day)
            ? day
            : null;

    /// <summary>GET /summary?from&amp;to for the tenant's ADMIN; a present but malformed date is a range error.</summary>
    public async Task<ProductMetricsResult> SummaryAsync(ManagementContext context, IQueryCollection query,
        CancellationToken cancellationToken)
    {
        if (!context.IsAdmin)
        {
            return ProductMetricsResult.Forbidden;
        }
        var now = _clock.NowMs();
        var today = DateOnly.ParseExact(DayOf(now), "yyyy-MM-dd", CultureInfo.InvariantCulture);
        var to = today;
        if (query.TryGetValue("to", out var toText))
        {
            if (ParseDay(toText.ToString()) is not DateOnly parsed)
            {
                return ProductMetricsResult.Code(StatusCodes.Status400BadRequest, "PRODUCT_METRICS_RANGE");
            }
            to = parsed;
        }
        var from = to.AddDays(-29);
        if (query.TryGetValue("from", out var fromText))
        {
            if (ParseDay(fromText.ToString()) is not DateOnly parsed)
            {
                return ProductMetricsResult.Code(StatusCodes.Status400BadRequest, "PRODUCT_METRICS_RANGE");
            }
            from = parsed;
        }
        if (from > to || to.DayNumber - from.DayNumber + 1 > MaxRangeDays || to > today
            || from < today.AddDays(-(RetentionDays - 1)))
        {
            return ProductMetricsResult.Code(StatusCodes.Status400BadRequest, "PRODUCT_METRICS_RANGE");
        }
        var tenant = context.TenantId;
        var low = from.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        var high = to.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        try
        {
            return await WithDbAsync(async db =>
            {
                var row = await FindSwitchAsync(db, tenant, cancellationToken).ConfigureAwait(false);
                var cohorts = (await db.ProductMetricsOnboardingDaily.AsNoTracking()
                        .Where(item => item.TenantId == tenant).ToListAsync(cancellationToken).ConfigureAwait(false))
                    .Where(item => InRange(item.CohortDay, low, high)).ToList();
                var progress = await db.ProductMetricsOnboardingProgress.AsNoTracking()
                    .Where(item => item.TenantId == tenant).ToListAsync(cancellationToken).ConfigureAwait(false);
                var transfers = (await db.ProductMetricsTransferDaily.AsNoTracking()
                        .Where(item => item.TenantId == tenant).ToListAsync(cancellationToken).ConfigureAwait(false))
                    .Where(item => InRange(item.Day, low, high)).ToList();
                return ProductMetricsResult.Ok(new Dictionary<string, object?>
                {
                    ["schemaVersion"] = SchemaVersion,
                    ["enabled"] = Collecting(row),
                    ["from"] = low,
                    ["to"] = high,
                    ["generatedAt"] = Instant(now),
                    ["onboarding"] = Onboarding(cohorts, progress, low, high, now),
                    ["transfers"] = Transfers(transfers),
                });
            }).ConfigureAwait(false);
        }
        catch (Exception error) when (IsStoreFailure(error, cancellationToken))
        {
            return Unavailable("summary", tenant, error);
        }
    }

    private static bool InRange(string day, string low, string high) =>
        string.CompareOrdinal(day, low) >= 0 && string.CompareOrdinal(day, high) <= 0;

    private static Dictionary<string, object?> Onboarding(List<ProductMetricsOnboardingDaily> cohorts,
        List<ProductMetricsOnboardingProgress> progress, string low, string high, long now)
    {
        var reached = new Dictionary<string, long>(StringComparer.Ordinal);
        var durations = new Dictionary<string, long>(StringComparer.Ordinal);
        long pending = 0;
        foreach (var row in cohorts)
        {
            reached[row.ReachedStep] = reached.GetValueOrDefault(row.ReachedStep) + row.Users;
            if (row.DurationBucket != NoDuration)
            {
                durations[row.DurationBucket] = durations.GetValueOrDefault(row.DurationBucket) + row.Users;
            }
        }
        foreach (var row in progress.Where(row => InRange(DayOf(row.StartedAt), low, high)))
        {
            var step = ReachedStep(row);
            reached[step] = reached.GetValueOrDefault(step) + 1;
            if (now < row.StartedAt + WindowMs)
            {
                pending++;
            }
        }
        var steps = new List<Dictionary<string, object?>>();
        long? previous = null;
        for (var index = 0; index < Steps.Count; index++)
        {
            var users = Steps.Skip(index).Sum(later => reached.GetValueOrDefault(later));
            steps.Add(new Dictionary<string, object?>
            {
                ["step"] = Steps[index],
                ["users"] = users,
                ["fromPreviousRateBp"] = previous is long before ? RateBp(users, before) : null,
            });
            previous = users;
        }
        var cohortUsers = (long)steps[0]["users"]!;
        var completed = (long)steps[^1]["users"]!;
        var completers = DurationBuckets.Sum(name => durations.GetValueOrDefault(name));
        string? median = null;
        var position = (completers + 1) / 2; // the ceil(n/2)-th completer, counted from 1
        foreach (var name in DurationBuckets)
        {
            if (completers == 0)
            {
                break;
            }
            var users = durations.GetValueOrDefault(name);
            if (position <= users)
            {
                median = name;
                break;
            }
            position -= users;
        }
        return new Dictionary<string, object?>
        {
            ["windowDays"] = WindowDays,
            ["cohortUsers"] = cohortUsers,
            ["pendingUsers"] = pending,
            ["final"] = pending == 0,
            ["steps"] = steps,
            ["completed"] = completed,
            ["completionRateBp"] = RateBp(completed, cohortUsers),
            ["durations"] = DurationBuckets.Select(name => new Dictionary<string, object?>
            {
                ["bucket"] = name,
                ["users"] = durations.GetValueOrDefault(name),
            }).ToList(),
            ["medianDurationBucket"] = median,
        };
    }

    private static Dictionary<string, object?> Tally(IEnumerable<ProductMetricsTransferDaily> rows,
        Dictionary<string, object?> into)
    {
        long success = 0, failure = 0, cancelled = 0;
        foreach (var row in rows)
        {
            switch (row.Outcome)
            {
                case "success": success += row.Count; break;
                case "failure": failure += row.Count; break;
                case "cancelled": cancelled += row.Count; break;
            }
        }
        into["success"] = success;
        into["failure"] = failure;
        into["cancelled"] = cancelled;
        into["successRateBp"] = RateBp(success, success + failure);
        return into;
    }

    private static Dictionary<string, object?> Transfers(List<ProductMetricsTransferDaily> rows)
    {
        var cells = new List<Dictionary<string, object?>>();
        foreach (var path in Paths)
        {
            foreach (var size in SizeBuckets)
            {
                var matching = rows.Where(row => row.Path == path && row.SizeBucket == size).ToList();
                if (matching.Sum(row => row.Count) > 0)
                {
                    cells.Add(Tally(matching, new Dictionary<string, object?> { ["path"] = path, ["sizeBucket"] = size }));
                }
            }
        }
        return new Dictionary<string, object?>
        {
            ["cells"] = cells,
            ["byMode"] = Modes.Select(mode => Tally(rows.Where(row => row.Mode == mode),
                new Dictionary<string, object?> { ["mode"] = mode })).ToList(),
            ["byAttempt"] = Attempts.Select(attempt => Tally(rows.Where(row => row.Attempt == attempt),
                new Dictionary<string, object?> { ["attempt"] = attempt })).ToList(),
            ["total"] = Tally(rows, new Dictionary<string, object?>()),
        };
    }

    // -- SQL ----------------------------------------------------------------------------------------

    private static string Dialect(SpecusDbContext db)
    {
        var provider = db.Database.ProviderName ?? string.Empty;
        if (provider.Contains("Npgsql", StringComparison.OrdinalIgnoreCase)
            || provider.Contains("PostgreSQL", StringComparison.OrdinalIgnoreCase))
        {
            return "postgresql";
        }
        return provider.Contains("MySql", StringComparison.OrdinalIgnoreCase) ? "mysql" : "sqlite";
    }

    /// <summary>Starts a progress row and reports whether it did; an existing row is left untouched.</summary>
    private static async Task<bool> InsertProgressIfAbsentAsync(SpecusDbContext db, string tenant, string username,
        long startedAt, CancellationToken cancellationToken)
    {
        var sql = Dialect(db) == "mysql"
            ? "INSERT INTO product_metrics_onboarding_progress (tenant_id, username, started_at) "
              + "VALUES ({0}, {1}, {2}) ON DUPLICATE KEY UPDATE tenant_id = tenant_id"
            : "INSERT INTO product_metrics_onboarding_progress (tenant_id, username, started_at) "
              + "VALUES ({0}, {1}, {2}) ON CONFLICT (tenant_id, username) DO NOTHING";
        var inserted = await db.Database.ExecuteSqlRawAsync(sql, [tenant, username, startedAt], cancellationToken)
            .ConfigureAwait(false);
        return inserted == 1;
    }

    internal static Task<int> AddOnboardingCountAsync(SpecusDbContext db, ProductMetricsOnboardingDaily row,
        CancellationToken cancellationToken)
    {
        var sql = Dialect(db) switch
        {
            "mysql" => "INSERT INTO product_metrics_onboarding_daily (tenant_id, cohort_day, reached_step, "
                       + "duration_bucket, users) VALUES ({0}, {1}, {2}, {3}, {4}) "
                       + "ON DUPLICATE KEY UPDATE users = users + VALUES(users)",
            _ => "INSERT INTO product_metrics_onboarding_daily (tenant_id, cohort_day, reached_step, duration_bucket, "
                 + "users) VALUES ({0}, {1}, {2}, {3}, {4}) "
                 + "ON CONFLICT (tenant_id, cohort_day, reached_step, duration_bucket) "
                 + "DO UPDATE SET users = product_metrics_onboarding_daily.users + excluded.users",
        };
        return db.Database.ExecuteSqlRawAsync(sql,
            [row.TenantId, row.CohortDay, row.ReachedStep, row.DurationBucket, row.Users], cancellationToken);
    }

    internal static Task<int> AddTransferCountAsync(SpecusDbContext db, ProductMetricsTransferDaily row,
        CancellationToken cancellationToken)
    {
        var sql = Dialect(db) switch
        {
            "mysql" => "INSERT INTO product_metrics_transfer_daily (tenant_id, day, mode, path, size_bucket, attempt, "
                       + "outcome, count) VALUES ({0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}) "
                       + "ON DUPLICATE KEY UPDATE count = count + VALUES(count)",
            _ => "INSERT INTO product_metrics_transfer_daily (tenant_id, day, mode, path, size_bucket, attempt, outcome, "
                 + "count) VALUES ({0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}) "
                 + "ON CONFLICT (tenant_id, day, mode, path, size_bucket, attempt, outcome) "
                 + "DO UPDATE SET count = product_metrics_transfer_daily.count + excluded.count",
        };
        return db.Database.ExecuteSqlRawAsync(sql,
            [row.TenantId, row.Day, row.Mode, row.Path, row.SizeBucket, row.Attempt, row.Outcome, row.Count],
            cancellationToken);
    }
}
