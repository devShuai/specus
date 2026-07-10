using System.Text.Json;
using ShuaiTunnel.Server.Configuration;

namespace ShuaiTunnel.IntegrationTests;

public sealed class SecureDefaultConfigurationTests
{
    [Fact]
    public void AppSettingsUseLocalSqliteAndDoNotEmbedServiceCredentials()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        var root = document.RootElement;
        var tunnel = root.GetProperty("Tunnel");

        Assert.Equal("Data Source=tunnel.db",
            root.GetProperty("ConnectionStrings").GetProperty("Tunnel").GetString());
        Assert.Equal("sqlite", tunnel.GetProperty("Database").GetProperty("Provider").GetString());
        Assert.Equal(string.Empty,
            tunnel.GetProperty("Elasticsearch").GetProperty("Uris").GetString());
        Assert.Equal(string.Empty,
            tunnel.GetProperty("Elasticsearch").GetProperty("Username").GetString());
        Assert.Equal(string.Empty,
            tunnel.GetProperty("Elasticsearch").GetProperty("Password").GetString());
        Assert.False(tunnel.GetProperty("Auth").GetProperty("PasswordLoginEnabled").GetBoolean());
        Assert.Equal(string.Empty, tunnel.GetProperty("Auth").GetProperty("Password").GetString());

        var raw = File.ReadAllText(path);
        Assert.DoesNotContain("192.168.", raw, StringComparison.Ordinal);
    }

    [Fact]
    public void AuthOptionFallbackIsDisabledUntilASecretIsConfigured()
    {
        var options = new AuthOptions();

        Assert.False(options.PasswordLoginEnabled);
        Assert.Equal(string.Empty, options.Password);
    }
}
