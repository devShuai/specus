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

    public ClientUpdateHostedService(SpecusClientConfig config, IClientUpdateService updates,
        IHostApplicationLifetime lifetime, ILogger<ClientUpdateHostedService> logger)
    {
        _config = config;
        _updates = updates;
        _lifetime = lifetime;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_config.UpdateEnabled || string.Equals(
                Environment.GetEnvironmentVariable("SPECUS_SKIP_UPDATE_ONCE"), "1",
                StringComparison.Ordinal))
        {
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
            ClientUpdateTarget.CSharpCommandLine, ClientVersion.Current, cancellationToken)
            .ConfigureAwait(false);
        if (!update.UpdateAvailable)
        {
            _logger.LogDebug("client is up to date ({version})", ClientVersion.Current);
            return false;
        }

        _logger.LogInformation("client update available: {current} -> {latest}{mandatory}",
            ClientVersion.Current, update.LatestVersion, update.Mandatory ? " (required)" : string.Empty);
        if (!_config.AutoUpdate && !ConfirmUpdate(update))
        {
            _logger.LogInformation("client update was deferred");
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

    private static bool ConfirmUpdate(ClientUpdateCheck update)
    {
        if (Console.IsInputRedirected || Console.IsOutputRedirected)
        {
            return false;
        }
        Console.WriteLine();
        Console.WriteLine(update.Mandatory
            ? $"发现必须更新 {Safe(update.LatestVersion)}，安装后将自动重启客户端。"
            : $"发现新版本 {Safe(update.LatestVersion)}，安装后将自动重启客户端。");
        if (!string.IsNullOrWhiteSpace(update.ChangelogUrl))
        {
            Console.WriteLine($"更新说明: {Safe(update.ChangelogUrl)}");
        }
        Console.Write("现在安装？[y/N] ");
        var answer = Console.ReadLine();
        return string.Equals(answer?.Trim(), "y", StringComparison.OrdinalIgnoreCase)
            || string.Equals(answer?.Trim(), "yes", StringComparison.OrdinalIgnoreCase);
    }

    private static string Safe(string? value) => ClientUpdateDisplay.Sanitize(value) ?? string.Empty;
}
