using System.Collections.Concurrent;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Data.Entities;

namespace ShuaiTunnel.Server.Nat;

public sealed class TrafficUsageService : BackgroundService
{
    private readonly ConcurrentDictionary<string, TrafficCounter> _counters = new(StringComparer.Ordinal);
    private readonly IServiceProvider _services;
    private readonly TrafficOptions _options;
    private readonly ILogger<TrafficUsageService> _logger;

    public TrafficUsageService(IServiceProvider services, IOptions<TrafficOptions> options,
        ILogger<TrafficUsageService> logger)
    {
        _services = services;
        _options = options.Value;
        _logger = logger;
    }

    public void RecordUpload(string? clientName, long bytes)
    {
        if (!string.IsNullOrEmpty(clientName) && bytes > 0)
        {
            _counters.GetOrAdd(clientName, _ => new TrafficCounter()).AddUpload(bytes);
        }
    }

    public void RecordDownload(string? clientName, long bytes)
    {
        if (!string.IsNullOrEmpty(clientName) && bytes > 0)
        {
            _counters.GetOrAdd(clientName, _ => new TrafficCounter()).AddDownload(bytes);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var delay = TimeSpan.FromMilliseconds(Math.Max(100, _options.FlushIntervalMs));
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(delay, stoppingToken).ConfigureAwait(false);
                await FlushAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "traffic usage flush failed");
            }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await FlushAsync(CancellationToken.None).ConfigureAwait(false);
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task FlushAsync(CancellationToken cancellationToken)
    {
        foreach (var (clientName, counter) in _counters)
        {
            var (upload, download) = counter.SnapshotAndReset();
            if (upload == 0 && download == 0)
            {
                continue;
            }

            try
            {
                await FlushCounterAsync(clientName, upload, download, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch
            {
                counter.AddUpload(upload);
                counter.AddDownload(download);
                throw;
            }
        }
    }

    private async Task FlushCounterAsync(string clientName, long upload, long download,
        CancellationToken cancellationToken)
    {
        await using var scope = _services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<TunnelDbContext>();
        var account = await db.ClientAccounts.AsNoTracking()
            .FirstOrDefaultAsync(c => c.ClientName == clientName, cancellationToken)
            .ConfigureAwait(false);
        if (account is null)
        {
            return;
        }

        var usageDate = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        var usage = await db.TrafficUsages
            .FirstOrDefaultAsync(u => u.ClientId == account.Id && u.UsageDate == usageDate, cancellationToken)
            .ConfigureAwait(false);
        if (usage is null)
        {
            usage = new TrafficUsage
            {
                ClientId = account.Id,
                ClientName = account.ClientName,
                UsageDate = usageDate,
            };
            db.TrafficUsages.Add(usage);
        }

        usage.UploadBytes += upload;
        usage.DownloadBytes += download;
        usage.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    private sealed class TrafficCounter
    {
        private long _upload;
        private long _download;

        public void AddUpload(long bytes) => Interlocked.Add(ref _upload, bytes);
        public void AddDownload(long bytes) => Interlocked.Add(ref _download, bytes);

        public (long Upload, long Download) SnapshotAndReset() =>
            (Interlocked.Exchange(ref _upload, 0), Interlocked.Exchange(ref _download, 0));
    }
}
