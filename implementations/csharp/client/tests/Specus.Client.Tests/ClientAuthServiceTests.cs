using Specus.Client.Configuration;

namespace Specus.Client.Tests;

public sealed class ClientAuthServiceTests
{
    [Fact]
    public void DefaultManagementClientUsesPlatformCertificateValidationAndBoundedTimeouts()
    {
        using var handler = ClientAuthService.BuildDefaultHandler();
        using var client = ClientAuthService.BuildDefaultClient();

        Assert.Null(handler.SslOptions.RemoteCertificateValidationCallback);
        Assert.Equal(TimeSpan.FromSeconds(10), handler.ConnectTimeout);
        Assert.Equal(TimeSpan.FromSeconds(20), client.Timeout);
        Assert.False(handler.AllowAutoRedirect);
    }
}
