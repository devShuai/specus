using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Authentication;
using ShuaiTunnel.Server.Configuration;

namespace ShuaiTunnel.IntegrationTests;

public sealed class LoginExecutorTests
{
    [Fact]
    public void TryEnqueueReturnsFalseWhenQueueIsFull()
    {
        var executor = new LoginExecutor(
            Options.Create(new LoginExecutorOptions
            {
                ExecutorMaxSize = 1,
                ExecutorQueueCapacity = 1,
            }),
            NullLogger<LoginExecutor>.Instance);

        Assert.True(executor.TryEnqueue(() => Task.CompletedTask));
        Assert.False(executor.TryEnqueue(() => Task.CompletedTask));
    }
}
