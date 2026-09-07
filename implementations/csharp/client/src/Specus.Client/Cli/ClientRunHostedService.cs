using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Specus.Client.Cli;

internal sealed class ClientExitStatus
{
    public int Code { get; set; }
}

// Keep process lifecycle outside the shared core: WPF must not exit on a login rejection.
internal sealed class ClientRunHostedService(
    Func<CancellationToken, Task> run,
    IHostApplicationLifetime lifetime,
    ClientExitStatus exitStatus,
    ILogger<ClientRunHostedService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await run(stoppingToken).ConfigureAwait(false);
            if (!stoppingToken.IsCancellationRequested && !lifetime.ApplicationStopping.IsCancellationRequested)
            {
                exitStatus.Code = 1;
                logger.LogError("Client stopped reconnecting; check the preceding rejection reason and configuration.");
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested
            || lifetime.ApplicationStopping.IsCancellationRequested) { }
        catch (Exception ex)
        {
            exitStatus.Code = ex is Specus.Client.Configuration.HttpLoginFailure failure ? failure.ExitCode : 1;
            logger.LogError("Client runtime failed ({type}); use --debug for diagnostic details.", ex.GetType().Name);
            if (ex is Specus.Client.Configuration.HttpLoginFailure) logger.LogError("{Reason}", ex.Message);
            logger.LogDebug(ex, "Client runtime failure");
        }
        finally
        {
            lifetime.StopApplication();
        }
    }
}
