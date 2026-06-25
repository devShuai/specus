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
    public const string ResourceTypeTcpTunnel = "TCP_TUNNEL";
    public const string ResourceTypeHttpRoute = "HTTP_ROUTE";

    private readonly ConcurrentDictionary<string, TrafficCounter> _counters = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<ResourceCounterKey, TrafficCounter> _resourceCounters = new();
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

    public void RecordTcpUpload(string? clientName, int listenPort, long bytes)
    {
        RecordUpload(clientName, bytes);
        if (!string.IsNullOrEmpty(clientName) && listenPort > 0 && bytes > 0)
        {
            RecordResourceUpload(clientName, ResourceTypeTcpTunnel, TcpKey(listenPort), bytes);
        }
    }

    public void RecordTcpDownload(string? clientName, int listenPort, long bytes)
    {
        RecordDownload(clientName, bytes);
        if (!string.IsNullOrEmpty(clientName) && listenPort > 0 && bytes > 0)
        {
            RecordResourceDownload(clientName, ResourceTypeTcpTunnel, TcpKey(listenPort), bytes);
        }
    }

    public void RecordHttpUpload(string? clientName, string? route, long bytes)
    {
        RecordUpload(clientName, bytes);
        if (!string.IsNullOrEmpty(clientName) && bytes > 0)
        {
            RecordResourceUpload(clientName, ResourceTypeHttpRoute, HttpKey(route), bytes);
        }
    }

    public void RecordHttpDownload(string? clientName, string? route, long bytes)
    {
        RecordDownload(clientName, bytes);
        if (!string.IsNullOrEmpty(clientName) && bytes > 0)
        {
            RecordResourceDownload(clientName, ResourceTypeHttpRoute, HttpKey(route), bytes);
        }
    }

    private void RecordResourceUpload(string clientName, string resourceType, string resourceKey, long bytes) =>
        _resourceCounters.GetOrAdd(new ResourceCounterKey(clientName, resourceType, resourceKey), _ => new TrafficCounter())
            .AddUpload(bytes);

    private void RecordResourceDownload(string clientName, string resourceType, string resourceKey, long bytes) =>
        _resourceCounters.GetOrAdd(new ResourceCounterKey(clientName, resourceType, resourceKey), _ => new TrafficCounter())
            .AddDownload(bytes);

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

        foreach (var (key, counter) in _resourceCounters)
        {
            var (upload, download) = counter.SnapshotAndReset();
            if (upload == 0 && download == 0)
            {
                continue;
            }

            try
            {
                await FlushResourceCounterAsync(key, upload, download, cancellationToken)
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
            .FirstOrDefaultAsync(u => u.ClientId == account.Id
                                      && u.UsageDate == usageDate
                                      && (u.TenantId == account.TenantId
                                          || u.TenantId == null
                                          || u.TenantId == string.Empty), cancellationToken)
            .ConfigureAwait(false);
        if (usage is null)
        {
            usage = new TrafficUsage
            {
                TenantId = account.TenantId,
                ClientId = account.Id,
                ClientName = account.ClientName,
                UsageDate = usageDate,
            };
            db.TrafficUsages.Add(usage);
        }

        usage.TenantId = account.TenantId;
        usage.ClientName = account.ClientName;
        usage.UploadBytes += upload;
        usage.DownloadBytes += download;
        usage.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task FlushResourceCounterAsync(ResourceCounterKey key, long upload, long download,
        CancellationToken cancellationToken)
    {
        await using var scope = _services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<TunnelDbContext>();
        var account = await db.ClientAccounts.AsNoTracking()
            .FirstOrDefaultAsync(c => c.ClientName == key.ClientName, cancellationToken)
            .ConfigureAwait(false);
        if (account is null)
        {
            return;
        }

        var (resourceId, resourceName) = await ResolveResourceAsync(db, account, key, cancellationToken)
            .ConfigureAwait(false);
        var usageDate = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        var usage = await db.ResourceTrafficUsages
            .FirstOrDefaultAsync(u => u.TenantId == account.TenantId
                                      && u.ClientId == account.Id
                                      && u.ResourceType == key.ResourceType
                                      && u.ResourceKey == key.ResourceKey
                                      && u.UsageDate == usageDate, cancellationToken)
            .ConfigureAwait(false);
        if (usage is null)
        {
            usage = new ResourceTrafficUsage
            {
                TenantId = account.TenantId,
                ClientId = account.Id,
                ClientName = account.ClientName,
                ResourceType = key.ResourceType,
                ResourceKey = key.ResourceKey,
                UsageDate = usageDate,
            };
            db.ResourceTrafficUsages.Add(usage);
        }

        usage.ResourceId = resourceId;
        usage.ResourceName = resourceName;
        usage.UploadBytes += upload;
        usage.DownloadBytes += download;
        usage.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<(long? ResourceId, string ResourceName)> ResolveResourceAsync(TunnelDbContext db,
        ClientAccount account, ResourceCounterKey key, CancellationToken cancellationToken)
    {
        if (key.ResourceType == ResourceTypeTcpTunnel)
        {
            var listenPort = ParseTcpKey(key.ResourceKey);
            var mapping = await db.TunnelMappings.AsNoTracking()
                .FirstOrDefaultAsync(row => row.ClientId == account.Id && row.ListenPort == listenPort,
                    cancellationToken)
                .ConfigureAwait(false);
            return mapping is null
                ? (null, $"端口 {listenPort}")
                : (mapping.Id, $"{mapping.ListenPort} -> {mapping.TargetAddress}:{mapping.TargetPort}");
        }

        if (key.ResourceType == ResourceTypeHttpRoute)
        {
            var route = ParseHttpKey(key.ResourceKey);
            var mapping = await db.HttpRouteMappings.AsNoTracking()
                .FirstOrDefaultAsync(row => row.ClientId == account.Id && row.Route == route, cancellationToken)
                .ConfigureAwait(false);
            return mapping is null
                ? (null, route)
                : (mapping.Id, $"{mapping.Route} -> {mapping.TargetBaseUrl}");
        }

        return (null, key.ResourceKey);
    }

    private static string TcpKey(int listenPort) => $"tcp:{listenPort}";

    private static string HttpKey(string? route) => $"http:{route ?? string.Empty}";

    private static int ParseTcpKey(string key) =>
        key.StartsWith("tcp:", StringComparison.Ordinal) && int.TryParse(key.AsSpan(4), out var port) ? port : 0;

    private static string ParseHttpKey(string key) =>
        key.StartsWith("http:", StringComparison.Ordinal) ? key[5..] : key;

    private sealed record ResourceCounterKey(string ClientName, string ResourceType, string ResourceKey);

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
