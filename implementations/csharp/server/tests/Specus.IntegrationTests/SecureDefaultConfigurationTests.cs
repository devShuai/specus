using System.Text.Json;
using Specus.Server.Configuration;

namespace Specus.IntegrationTests;

public sealed class SecureDefaultConfigurationTests
{
    [Fact]
    public void AppSettingsUseLocalSqliteAndDoNotEmbedServiceCredentials()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        var root = document.RootElement;
        var specus = root.GetProperty("Specus");

        Assert.Equal("Data Source=specus.db",
            root.GetProperty("ConnectionStrings").GetProperty("Specus").GetString());
        Assert.Equal("sqlite", specus.GetProperty("Database").GetProperty("Provider").GetString());
        Assert.Equal(string.Empty,
            specus.GetProperty("Elasticsearch").GetProperty("Uris").GetString());
        Assert.Equal(string.Empty,
            specus.GetProperty("Elasticsearch").GetProperty("Username").GetString());
        Assert.Equal(string.Empty,
            specus.GetProperty("Elasticsearch").GetProperty("Password").GetString());
        var auth = specus.GetProperty("Auth");
        Assert.True(auth.GetProperty("PasswordLoginEnabled").GetBoolean());
        Assert.True(auth.GetProperty("RegistrationEnabled").GetBoolean());
        Assert.False(auth.GetProperty("TurnstileEnabled").GetBoolean());
        Assert.False(auth.GetProperty("EmailVerificationEnabled").GetBoolean());
        Assert.Equal("admin", auth.GetProperty("Username").GetString());
        // The shipped configuration must not carry a usable password; operators opt in explicitly.
        Assert.Equal(string.Empty, auth.GetProperty("Password").GetString());
        Assert.True(auth.GetProperty("LoginRateLimitEnabled").GetBoolean());
        Assert.True(auth.GetProperty("LoginRateLimitPerIp").GetInt32() > 0);
        Assert.True(auth.GetProperty("LoginRateLimitPerAccount").GetInt32() > 0);
        // Unset environment resolves to prod, which refuses demo data and default credentials.
        Assert.Equal(DeploymentEnvironment.Prod,
            DeploymentEnvironments.Parse(specus.GetProperty("Env").GetString()));
        Assert.Equal(string.Empty, auth.GetProperty("TurnstileSecretKey").GetString());
        Assert.Equal(string.Empty, auth.GetProperty("SmtpPassword").GetString());

        var raw = File.ReadAllText(path);
        Assert.DoesNotContain("192.168.", raw, StringComparison.Ordinal);
    }

    [Fact]
    public void AuthOptionFallbackShipsNoUsablePasswordCredential()
    {
        var options = new AuthOptions();

        Assert.True(options.PasswordLoginEnabled);
        Assert.True(options.RegistrationEnabled);
        Assert.False(options.TurnstileEnabled);
        Assert.False(options.EmailVerificationEnabled);
        Assert.Equal("admin", options.Username);
        // Blank keeps password login disabled until an operator sets a unique value.
        Assert.Equal(string.Empty, options.Password);
        Assert.True(options.LoginRateLimitEnabled);
    }
}
