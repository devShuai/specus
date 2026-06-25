using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Data.Entities;

namespace ShuaiTunnel.Server.Hosting;

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
        var db = scope.ServiceProvider.GetRequiredService<TunnelDbContext>();
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
        TunnelDbContext db,
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
        var buckets = rows
            .GroupBy(r => new
            {
                TenantId = NormalizeTenant(r.TenantId),
                r.ClientName,
                StatMonth = r.ConnectedAt.ToUniversalTime().ToString("yyyy-MM", CultureInfo.InvariantCulture),
            })
            .Select(g => new
            {
                g.Key.TenantId,
                g.Key.ClientName,
                g.Key.StatMonth,
                ClientId = g.Select(r => r.ClientId).FirstOrDefault(id => id.HasValue),
                Total = (long)g.Count(),
                Success = (long)g.Count(r => r.Success),
                Failure = (long)g.Count(r => !r.Success),
            })
            .ToList();

        foreach (var bucket in buckets)
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
}
