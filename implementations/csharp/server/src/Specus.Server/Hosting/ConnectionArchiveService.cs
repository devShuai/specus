using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;

namespace Specus.Server.Hosting;

public sealed class ConnectionArchiveService : BackgroundService
{
    private static readonly TimeSpan DefaultInterval = TimeSpan.FromHours(1);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IOptions<ConnectionRecordOptions> _options;
    private readonly ILogger<ConnectionArchiveService> _logger;

    public ConnectionArchiveService(
        IServiceScopeFactory scopeFactory,
        IOptions<ConnectionRecordOptions> options,
        ILogger<ConnectionArchiveService> logger)
    {
        _scopeFactory = scopeFactory;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_options.Value.DetailRetentionDays <= 0)
        {
            _logger.LogInformation("Connection archive disabled: detail retention days is {RetentionDays}",
                _options.Value.DetailRetentionDays);
            return;
        }

        using var timer = new PeriodicTimer(ResolveInterval(_options.Value.ArchiveIntervalMs));
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                var archived = await ArchiveAsync(stoppingToken).ConfigureAwait(false);
                if (archived > 0)
                {
                    _logger.LogInformation("Archived {Count} old connection records", archived);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Connection archive failed");
            }
        }
    }

    public async Task<long> ArchiveAsync(CancellationToken cancellationToken = default)
    {
        var retentionDays = _options.Value.DetailRetentionDays;
        if (retentionDays <= 0)
        {
            return 0;
        }

        var cutoff = CalculateCutoff(DateTimeOffset.UtcNow, retentionDays);
        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        return await ArchiveAsync(db, cutoff, cancellationToken).ConfigureAwait(false);
    }

    public static DateTimeOffset CalculateCutoff(DateTimeOffset now, int retentionDays)
    {
        if (retentionDays <= 0)
        {
            return DateTimeOffset.MinValue;
        }

        var day = now.ToUniversalTime().Date.AddDays(-retentionDays);
        return new DateTimeOffset(day, TimeSpan.Zero);
    }

    internal static async Task<long> ArchiveAsync(
        SpecusDbContext db,
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default)
    {
        if (cutoff == DateTimeOffset.MinValue)
        {
            return 0;
        }

        var rows = await db.ConnectionRecords
            .Where(r => r.ConnectedAt < cutoff)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        if (rows.Count == 0)
        {
            return 0;
        }

        var now = DateTimeOffset.UtcNow;
        var buckets = new Dictionary<(string TenantId, string ClientName, string StatMonth), ArchiveBucket>();
        foreach (var row in rows)
        {
            var key = (
                TenantId: NormalizeTenant(row.TenantId),
                row.ClientName,
                StatMonth: row.ConnectedAt.ToUniversalTime().ToString("yyyy-MM", CultureInfo.InvariantCulture));
            if (!buckets.TryGetValue(key, out var bucket))
            {
                bucket = new ArchiveBucket(key.TenantId, key.ClientName, key.StatMonth);
                buckets[key] = bucket;
            }
            bucket.ClientId ??= row.ClientId;
            bucket.Total++;
            if (row.Success)
            {
                bucket.Success++;
            }
            else
            {
                bucket.Failure++;
            }
        }

        foreach (var bucket in buckets.Values)
        {
            var stat = await db.ConnectionStats
                .FirstOrDefaultAsync(s =>
                    s.TenantId == bucket.TenantId
                    && s.ClientName == bucket.ClientName
                    && s.StatMonth == bucket.StatMonth,
                    cancellationToken)
                .ConfigureAwait(false);
            if (stat is null)
            {
                db.ConnectionStats.Add(new ConnectionStat
                {
                    TenantId = bucket.TenantId,
                    ClientId = bucket.ClientId,
                    ClientName = bucket.ClientName,
                    StatMonth = bucket.StatMonth,
                    TotalCount = bucket.Total,
                    SuccessCount = bucket.Success,
                    FailureCount = bucket.Failure,
                    UpdatedAt = now,
                });
            }
            else
            {
                stat.ClientId ??= bucket.ClientId;
                stat.TotalCount += bucket.Total;
                stat.SuccessCount += bucket.Success;
                stat.FailureCount += bucket.Failure;
                stat.UpdatedAt = now;
            }
        }

        db.ConnectionRecords.RemoveRange(rows);
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return rows.Count;
    }

    private static TimeSpan ResolveInterval(int archiveIntervalMs) =>
        archiveIntervalMs > 0
            ? TimeSpan.FromMilliseconds(archiveIntervalMs)
            : DefaultInterval;

    private static string NormalizeTenant(string? tenantId) =>
        string.IsNullOrWhiteSpace(tenantId) ? "default" : tenantId;

    private sealed class ArchiveBucket(string tenantId, string clientName, string statMonth)
    {
        public string TenantId { get; } = tenantId;
        public string ClientName { get; } = clientName;
        public string StatMonth { get; } = statMonth;
        public long? ClientId { get; set; }
        public long Total { get; set; }
        public long Success { get; set; }
        public long Failure { get; set; }
    }
}
