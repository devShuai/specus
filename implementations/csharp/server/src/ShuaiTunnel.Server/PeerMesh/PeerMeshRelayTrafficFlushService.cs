using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;

namespace ShuaiTunnel.Server.PeerMesh;

public sealed class PeerMeshRelayTrafficFlushService : BackgroundService
{
    private static readonly TimeSpan DefaultInterval = TimeSpan.FromSeconds(5);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly PeerMeshOptions _options;
    private readonly ILogger<PeerMeshRelayTrafficFlushService> _logger;

    public PeerMeshRelayTrafficFlushService(IServiceScopeFactory scopeFactory, IOptions<PeerMeshOptions> options,
        ILogger<PeerMeshRelayTrafficFlushService> logger)
    {
        _scopeFactory = scopeFactory;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var timer = new PeriodicTimer(Interval);
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                await FlushAsync(stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal host shutdown path.
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
        await FlushAsync(CancellationToken.None).ConfigureAwait(false);
    }

    private TimeSpan Interval => _options.RelayTrafficFlushIntervalMs > 0
        ? TimeSpan.FromMilliseconds(_options.RelayTrafficFlushIntervalMs)
        : DefaultInterval;

    private async Task FlushAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var service = scope.ServiceProvider.GetRequiredService<PeerMeshService>();
            await service.FlushRelayTrafficAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Peer mesh relay traffic flush failed");
        }
    }
}
