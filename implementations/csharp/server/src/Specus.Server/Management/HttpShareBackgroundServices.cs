using Specus.Server.Http;

namespace Specus.Server.Management;

/// <summary>
/// Runs the share sweep every 30 seconds (the contract allows at most 60), the first time soon
/// after start. Conditional updates make it safe on every instance at once.
/// </summary>
public sealed class HttpShareSweeper : BackgroundService
{
    private static readonly TimeSpan FirstRunDelay = TimeSpan.FromSeconds(5);

    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<HttpShareSweeper> _logger;

    public HttpShareSweeper(IServiceScopeFactory scopes, ILogger<HttpShareSweeper> logger)
    {
        _scopes = scopes;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(FirstRunDelay, stoppingToken).ConfigureAwait(false);
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(HttpShareProtocol.SweepIntervalSeconds));
            do
            {
                await SweepOnceAsync(stoppingToken).ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    public async Task SweepOnceAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = _scopes.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<HttpShareService>().SweepAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            _logger.LogWarning(error, "http share sweep failed");
        }
    }
}

/// <summary>
/// Keeps in-flight share streams honest (spec §6.6): every second it cuts streams whose share has
/// expired, and every two seconds it re-reads each share that has streams here — one query per
/// share — and cuts them when the share was revoked (possibly on another instance), expired or
/// lapsed. A revoke anywhere therefore ends the streams on this instance within five seconds.
/// </summary>
public sealed class HttpShareStreamMonitor : BackgroundService
{
    private readonly IServiceScopeFactory _scopes;
    private readonly HttpShareStreamRegistry _streams;
    private readonly HttpShareClock _clock;
    private readonly ILogger<HttpShareStreamMonitor> _logger;

    public HttpShareStreamMonitor(IServiceScopeFactory scopes, HttpShareStreamRegistry streams,
        HttpShareClock clock, ILogger<HttpShareStreamMonitor> logger)
    {
        _scopes = scopes;
        _streams = streams;
        _clock = clock;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(HttpShareProtocol.StreamExpiryTickSeconds));
        var ticks = 0L;
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                _streams.CutExpired(_clock.NowMs);
                if (++ticks % HttpShareProtocol.StreamRecheckSeconds == 0)
                {
                    await RecheckAsync(stoppingToken).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    public async Task RecheckAsync(CancellationToken cancellationToken)
    {
        var shareIds = _streams.ActiveShareIds();
        if (shareIds.Count == 0)
        {
            return;
        }
        await using var scope = _scopes.CreateAsyncScope();
        var shares = scope.ServiceProvider.GetRequiredService<HttpShareService>();
        foreach (var shareId in shareIds)
        {
            try
            {
                if (await shares.HasEndedAsync(shareId, cancellationToken).ConfigureAwait(false))
                {
                    _streams.Cut(shareId);
                }
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                // A failed read is not proof that the share ended; the next recheck tries again.
                _logger.LogWarning(error, "recheck of http share {ShareId} failed", shareId);
            }
        }
    }
}
