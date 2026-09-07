using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Specus.Client.Configuration;

namespace Specus.Client.Updates;

public interface IClientUpdateService
{
    Task<ClientUpdateCheck> CheckAsync(Uri serverBaseUri, ClientUpdateTarget target,
        string currentVersion, CancellationToken cancellationToken = default);

    Task<ClientUpdateInstallationPlan> DownloadAndPrepareAsync(ClientUpdateCheck update,
        ClientUpdateInstallationRequest installation, IProgress<ClientUpdateProgress>? progress = null,
        CancellationToken cancellationToken = default);
}

internal sealed class ClientUpdateHostedService : BackgroundService
{
    private readonly SpecusClientConfig _config;
    private readonly IClientUpdateService _updates;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger<ClientUpdateHostedService> _logger;

    private readonly string _currentVersion;

    public ClientUpdateHostedService(SpecusClientConfig config, IClientUpdateService updates,
        IHostApplicationLifetime lifetime, ILogger<ClientUpdateHostedService> logger,
        string? currentVersion = null)
    {
        _config = config;
        _updates = updates;
        _lifetime = lifetime;
        _logger = logger;
        // Injectable so tests can exercise the loop without depending on the version the test
        // host happens to report, which is a placeholder and would trip the skip below.
        _currentVersion = currentVersion ?? ClientVersion.Current;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_config.UpdateEnabled || string.Equals(
                Environment.GetEnvironmentVariable("SPECUS_SKIP_UPDATE_ONCE"), "1",
                StringComparison.Ordinal))
        {
            return;
        }

        // A development build reports 0.0.0-dev, which compares as older than every release, so
        // the check would always claim an update is available for a build that is newer than any
        // of them. Skipping keeps that noise out of local runs without touching the release path.
        if (ClientVersion.IsPlaceholder(_currentVersion))
        {
            _logger.LogDebug("update check skipped: development build {Version}", _currentVersion);
            return;
        }

        var interval = TimeSpan.FromHours(_config.UpdateCheckIntervalHours);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (await CheckAndInstallAsync(stoppingToken).ConfigureAwait(false))
                {
                    return;
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "client update check failed; the running version is unchanged");
            }

            await Task.Delay(interval, stoppingToken).ConfigureAwait(false);
        }
    }

    private async Task<bool> CheckAndInstallAsync(CancellationToken cancellationToken)
    {
        var update = await _updates.CheckAsync(new Uri(_config.ServerBaseUrl),
            ClientUpdateTarget.CSharpCommandLine, _currentVersion, cancellationToken)
            .ConfigureAwait(false);
        if (!update.UpdateAvailable)
        {
            _logger.LogDebug("client is up to date ({version})", _currentVersion);
            return false;
        }

        _logger.LogInformation("client update available: {current} -> {latest}{mandatory}",
            _currentVersion, update.LatestVersion, update.Mandatory ? " (required)" : string.Empty);
        if (!_config.AutoUpdate)
        {
            _logger.LogInformation("Update available; restart with --auto-update to authorize installation. The tunnel remains connected.");
            return false;
        }

        var request = ClientUpdateRuntime.CreateCurrentProcessRequest();
        var progress = new Progress<ClientUpdateProgress>(value =>
            _logger.LogInformation("downloading update: {received}/{total} bytes",
                value.BytesReceived, value.TotalBytes));
        var plan = await _updates.DownloadAndPrepareAsync(update, request, progress, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            ClientUpdateService.LaunchPreparedUpdate(plan);
        }
        catch
        {
            ClientUpdateService.CleanupPreparedUpdate(plan);
            throw;
        }

        _logger.LogInformation("verified update prepared; stopping client for atomic replacement");
        _lifetime.StopApplication();
        return true;
    }

}
