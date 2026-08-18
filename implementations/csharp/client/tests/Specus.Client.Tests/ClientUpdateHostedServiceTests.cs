using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Client.Configuration;
using Specus.Client.Updates;

namespace Specus.Client.Tests;

public sealed class ClientUpdateHostedServiceTests
{
    [Fact]
    public async Task UnexpectedUpdateFailureDoesNotTerminateTheTunnelHostService()
    {
        var updates = new ThrowingUpdateService();
        var config = new SpecusClientConfig
        {
            ServerBaseUrl = "https://specus.example",
            UpdateEnabled = true,
            UpdateCheckIntervalHours = 1,
        };
        var service = new ClientUpdateHostedService(config, updates, new TestLifetime(),
            NullLogger<ClientUpdateHostedService>.Instance);

        await service.StartAsync(CancellationToken.None);
        await updates.Called.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Task.Delay(50);

        Assert.NotNull(service.ExecuteTask);
        Assert.False(service.ExecuteTask!.IsCompleted);
        await service.StopAsync(CancellationToken.None);
    }

    private sealed class ThrowingUpdateService : IClientUpdateService
    {
        public TaskCompletionSource Called { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<ClientUpdateCheck> CheckAsync(Uri serverBaseUri, ClientUpdateTarget target,
            string currentVersion, CancellationToken cancellationToken = default)
        {
            Called.TrySetResult();
            throw new ArgumentException("injected unexpected metadata failure");
        }

        public Task<ClientUpdateInstallationPlan> DownloadAndPrepareAsync(ClientUpdateCheck update,
            ClientUpdateInstallationRequest installation,
            IProgress<ClientUpdateProgress>? progress = null,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("not reached");
    }

    private sealed class TestLifetime : IHostApplicationLifetime
    {
        private readonly CancellationTokenSource _started = new();
        private readonly CancellationTokenSource _stopping = new();
        private readonly CancellationTokenSource _stopped = new();

        public CancellationToken ApplicationStarted => _started.Token;
        public CancellationToken ApplicationStopping => _stopping.Token;
        public CancellationToken ApplicationStopped => _stopped.Token;

        public void StopApplication() => _stopping.Cancel();
    }
}
