using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Client.Configuration;

namespace Specus.Client.Tests;

public sealed class SpecusClientConfigLoaderTests
{
    [Fact]
    public void LoadNormalizesPeerMeshOptions()
    {
        var path = Path.Combine(Path.GetTempPath(), $"specus-client-{Guid.NewGuid():N}.jsonc");
        try
        {
            File.WriteAllText(path, """
            {
              "$schema": "https://specus.devshuai.com/schemas/client-startup-config.schema.json",
              // JSONC comments are allowed in client.jsonc.
              "serverBaseUrl": " http://127.0.0.1:8088/ ",
              "apiKey": " demo-client ",
              "secret": " test1234 ",
              "peerMeshDevice": " auto ",
              "peerMeshTunName": " mesh0 ",
              "peerMeshMtu": 4096,
            }
            """);

            var config = SpecusClientConfigLoader.Load(path);

            Assert.Equal("http://127.0.0.1:8088/", config.ServerBaseUrl);
            Assert.Equal("demo-client", config.ApiKey);
            Assert.Equal("test1234", config.Secret);
            Assert.Equal("auto", config.PeerMeshDevice);
            Assert.Equal("mesh0", config.PeerMeshTunName);
            Assert.Equal(SpecusClientConfig.MaxPeerMeshMtu, config.PeerMeshMtu);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void LoadDefaultsPeerMeshOptions()
    {
        var path = Path.Combine(Path.GetTempPath(), $"specus-client-{Guid.NewGuid():N}.jsonc");
        try
        {
            File.WriteAllText(path, """
            {
              "serverBaseUrl": "http://127.0.0.1:8088",
              "apiKey": "demo-client",
              "secret": "test1234"
            }
            """);

            var config = SpecusClientConfigLoader.Load(path);

            Assert.Equal(SpecusClientConfig.DefaultPeerMeshDevice, config.PeerMeshDevice);
            Assert.Equal(SpecusClientConfig.DefaultPeerMeshTunName, config.PeerMeshTunName);
            Assert.Equal(SpecusClientConfig.DefaultPeerMeshMtu, config.PeerMeshMtu);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData("https://login.specus.test")]
    [InlineData("http://127.0.0.1:8088")]
    public void MissingControlTlsSwitchFollowsRuntimeSignalNotLoginUrlScheme(string serverBaseUrl)
    {
        var config = LoadJson($$"""
        {
          "serverBaseUrl": "{{serverBaseUrl}}",
          "apiKey": "demo-client",
          "secret": "test1234",
          "controlTls": { "enabled": null }
        }
        """);

        Assert.Null(config.ControlTls.Enabled);
        Assert.False(config.ControlTls.ResolveEnabled(runtimeNettyTls: false));
        Assert.True(config.ControlTls.ResolveEnabled(runtimeNettyTls: true));
    }

    [Fact]
    public void MissingControlTlsSwitchTreatsTlsOptionsAsAnOptIn()
    {
        var config = LoadJson("""
        {
          "serverBaseUrl": "http://127.0.0.1:8088",
          "apiKey": "demo-client",
          "secret": "test1234",
          "controlTls": { "serverName": "control.specus.test" }
        }
        """);

        Assert.True(config.ControlTls.ResolveEnabled(runtimeNettyTls: false));
    }

    [Theory]
    [InlineData("http://127.0.0.1:8088", "{ \"enabled\": false, \"caCertificatePath\": \"ca.pem\" }")]
    [InlineData("https://login.specus.test", "{ \"caCertificatePath\": \"ca.pem\", \"insecureSkipVerify\": true }")]
    [InlineData("https://login.specus.test", "{ \"serverName\": \"control.specus.test:443\" }")]
    public void InvalidControlTlsCombinationsFailDuringConfigLoad(
        string serverBaseUrl,
        string controlTls)
    {
        var error = Assert.Throws<InvalidDataException>(() => LoadJson($$"""
        {
          "serverBaseUrl": "{{serverBaseUrl}}",
          "apiKey": "demo-client",
          "secret": "test1234",
          "controlTls": {{controlTls}}
        }
        """));

        Assert.Contains("controlTls", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(@"DESKTOP\shshi", "shshi")]
    [InlineData(@"DOMAIN\admin", "admin")]
    [InlineData("root", "root")]
    [InlineData("/users/alice", "alice")]
    [InlineData("  bob  ", "bob")]
    [InlineData("", "unknown")]
    public void NormalizeOsUserMatchesJavaStyleUsername(string input, string expected)
    {
        Assert.Equal(expected, ClientEnvironmentInfo.NormalizeOsUser(input));
    }

    [Fact]
    public void CollectedEnvironmentAdvertisesOnlyImplementedMessageCapabilities()
    {
        var environment = ClientEnvironmentInfo.Collect(NullLogger.Instance);

        Assert.True(environment.ClientMessageCapabilities.SendMessages);
        Assert.True(environment.ClientMessageCapabilities.ReceiveMessages);
        Assert.False(environment.ClientMessageCapabilities.Attachments);
        Assert.False(environment.ClientMessageCapabilities.MediaPreview);
        Assert.Equal(0L, environment.ClientMessageCapabilities.MaxAttachmentBytes);

        using var json = JsonDocument.Parse(JsonSerializer.Serialize(environment));
        var capabilities = json.RootElement.GetProperty("clientMessageCapabilities");
        Assert.True(capabilities.GetProperty("sendMessages").GetBoolean());
        Assert.True(capabilities.GetProperty("receiveMessages").GetBoolean());
        Assert.False(capabilities.GetProperty("attachments").GetBoolean());
        Assert.False(capabilities.GetProperty("mediaPreview").GetBoolean());
        Assert.Equal(0L, capabilities.GetProperty("maxAttachmentBytes").GetInt64());
    }

    [Fact]
    public void CollectedEnvironmentUsesExplicitDesktopAttachmentOverride()
    {
        var environment = ClientEnvironmentInfo.Collect(
            NullLogger.Instance,
            ClientMessageCapabilities.DesktopFileTransfer());

        Assert.True(environment.ClientMessageCapabilities.Attachments);
        Assert.Equal(
            ClientMessageCapabilities.DesktopMaxAttachmentBytes,
            environment.ClientMessageCapabilities.MaxAttachmentBytes);

        using var json = JsonDocument.Parse(JsonSerializer.Serialize(environment));
        var capabilities = json.RootElement.GetProperty("clientMessageCapabilities");
        Assert.True(capabilities.GetProperty("attachments").GetBoolean());
        Assert.Equal(
            ClientMessageCapabilities.DesktopMaxAttachmentBytes,
            capabilities.GetProperty("maxAttachmentBytes").GetInt64());
    }

    [Fact]
    public void NatControlSnapshotDistinguishesMissingAndEmptyHttpRoutesLikeJava()
    {
        var missing = JsonSerializer.Deserialize<SpecusConfigSnapshot>(
            """{"specusConfigList":[]}""",
            SpecusClientConfigLoader.JsonOptions);
        var empty = JsonSerializer.Deserialize<SpecusConfigSnapshot>(
            """{"specusConfigList":[],"httpSpecusConfigList":[]}""",
            SpecusClientConfigLoader.JsonOptions);

        Assert.NotNull(missing);
        Assert.Null(missing!.HttpSpecusConfigList);
        Assert.NotNull(empty);
        Assert.NotNull(empty!.HttpSpecusConfigList);
        Assert.Empty(empty.HttpSpecusConfigList);
    }

    [Fact]
    public void RuntimeControlTlsSignalIsBackwardCompatible()
    {
        var secured = JsonSerializer.Deserialize<SpecusRuntimeState>(
            """{"nettyTls":true}""", SpecusClientConfigLoader.JsonOptions);
        var legacy = JsonSerializer.Deserialize<SpecusRuntimeState>(
            """{}""", SpecusClientConfigLoader.JsonOptions);

        Assert.True(secured!.NettyTls);
        Assert.False(legacy!.NettyTls);
    }

    private static SpecusClientConfig LoadJson(string json)
    {
        var path = Path.Combine(Path.GetTempPath(), $"specus-client-{Guid.NewGuid():N}.jsonc");
        try
        {
            File.WriteAllText(path, json);
            return SpecusClientConfigLoader.Load(path);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
