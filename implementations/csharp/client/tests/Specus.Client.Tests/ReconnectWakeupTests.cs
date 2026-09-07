using Specus.Client.Runtime;

namespace Specus.Client.Tests;

public class ReconnectWakeupTests
{
    [Fact]
    public async Task NetworkHintCancelsInFlightLoginWithoutCreatingParallelLoopsOrRestartingAfterStop()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var handler = new PendingLoginHandler();
        using var http = new HttpClient(handler);
        var config = new Specus.Client.Configuration.SpecusClientConfig
        {
            ServerBaseUrl = "http://localhost:1", ApiKey = "fixture", Secret = "fixture",
        };
        var auth = new Specus.Client.Configuration.ClientAuthService(config, http,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<Specus.Client.Configuration.ClientAuthService>.Instance);
        await using var client = new Specus.Client.Control.SpecusControlClient(config, auth,
            new Specus.Client.DirectHttp.DirectHttpForwarder(http), Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance);
        var running = client.RunAsync(cancellation.Token);
        await handler.First.Task.WaitAsync(cancellation.Token);
        for (int i = 0; i < 50; i++) client.RequestReconnect();
        await handler.Second.Task.WaitAsync(cancellation.Token);
        cancellation.Cancel();
        await running;
        client.RequestReconnect();
        Assert.Equal(2, handler.Calls);
        Assert.Equal(1, handler.MaxConcurrent);
    }

    private sealed class PendingLoginHandler : HttpMessageHandler
    {
        public TaskCompletionSource First { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Second { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Calls, MaxConcurrent;
        private int _active;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            MaxConcurrent = Math.Max(MaxConcurrent, Interlocked.Increment(ref _active));
            int call = Interlocked.Increment(ref Calls);
            (call == 1 ? First : Second).TrySetResult();
            try { await Task.Delay(Timeout.Infinite, token); throw new InvalidOperationException(); }
            finally { Interlocked.Decrement(ref _active); }
        }
    }

    [Fact]
    public async Task HintIsRetainedUntilWaitAndBurstIsCoalesced()
    {
        var wakeup = new ReconnectWakeup();
        Assert.True(wakeup.Request());
        Assert.False(wakeup.Request());
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        await wakeup.WaitAsync(TimeSpan.FromMinutes(1), cancellation.Token);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            wakeup.WaitAsync(TimeSpan.FromMinutes(1), cancellation.Token));
    }

    [Theory]
    [InlineData(1, 1, 2)]
    [InlineData(3, 6, 8)]
    [InlineData(100, 45, 60)]
    public void BackoffHasBoundedJitter(int attempt, int minimum, int maximum)
    {
        Assert.InRange(ReconnectWakeup.DelaySeconds(attempt, 0), minimum, maximum);
        Assert.Equal(maximum, ReconnectWakeup.DelaySeconds(attempt, 1));
    }
}
