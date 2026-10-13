namespace Specus.Server.PeerMesh;

public sealed class PeerClientDeletionDispatchService(IServiceScopeFactory scopeFactory, PeerMeshServiceState state,
    ILogger<PeerClientDeletionDispatchService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(100));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                if (state.ClientDeletions.IsEmpty) continue;
                try
                {
                    await using var scope = scopeFactory.CreateAsyncScope();
                    var service = scope.ServiceProvider.GetRequiredService<PeerMeshService>();
                    await service.DrainClientDeletionsAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { throw; }
                catch (Exception error) { logger.LogWarning(error, "Peer client deletion dispatch failed; retrying"); }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }
}
