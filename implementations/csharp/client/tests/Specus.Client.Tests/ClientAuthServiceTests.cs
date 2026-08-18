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

    [Fact]
    public void HeadlessClientDefaultsToTextOnlyCapability()
    {
        var capabilities = ClientMessageCapabilities.TextOnlyDefault();

        Assert.True(capabilities.SendMessages);
        Assert.True(capabilities.ReceiveMessages);
        Assert.False(capabilities.Attachments);
        Assert.False(capabilities.MediaPreview);
        Assert.Equal(0, capabilities.MaxAttachmentBytes);
    }

    [Fact]
    public void DesktopCanExplicitlyAdvertiseVerifiedStxferReceiveCapability()
    {
        var capabilities = ClientMessageCapabilities.DesktopFileTransfer();

        Assert.True(capabilities.SendMessages);
        Assert.True(capabilities.ReceiveMessages);
        Assert.True(capabilities.Attachments);
        Assert.False(capabilities.MediaPreview);
        Assert.Equal(ClientMessageCapabilities.DesktopMaxAttachmentBytes, capabilities.MaxAttachmentBytes);
    }
}
