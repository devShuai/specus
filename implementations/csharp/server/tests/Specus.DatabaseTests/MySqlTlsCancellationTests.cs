using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MySql.Data.MySqlClient;

namespace Specus.IntegrationTests;

public sealed class MySqlTlsCancellationTests
{
    [Fact]
    public async Task NativeCancellationStopsHostDuringAnActuallyStalledTlsHandshake()
    {
        await MySqlTlsCancellationProviderProof.VerifyAsync(Settings().ConnectionString);
    }

    [Fact]
    public void ActualDriverIsIdentifiableLocalSourceBuildNotOracleSignedBinary()
    {
        var assembly = typeof(MySqlConnection).Assembly;
        Assert.Equal("26.7.0+specus.tls-cancel.1", assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion);
        Assert.Empty(assembly.GetName().GetPublicKeyToken()!);
        Assert.Contains(assembly.GetCustomAttributes<AssemblyMetadataAttribute>(), a => a.Key == "SpecusLocalPatch");
    }

    [Fact]
    public async Task TrustedCaStillConnectsAndUntrustedCaIsRejected()
    {
        var settings = Settings(); settings.SslMode = MySqlSslMode.VerifyCA;
        settings.SslCa = CaFile();
        await using (var trusted = new MySqlConnection(settings.ConnectionString))
        {
            await trusted.OpenAsync();
            await using var command = trusted.CreateCommand(); command.CommandText = "SHOW SESSION STATUS LIKE 'Ssl_cipher'";
            await using var reader = await command.ExecuteReaderAsync(); Assert.True(await reader.ReadAsync()); Assert.NotEmpty(reader.GetString(1));
        }
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Untrusted-Specus-Test-CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var badCa = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        var pemPath = Path.Combine(Path.GetTempPath(), "specus-untrusted-ca-" + Guid.NewGuid().ToString("N") + ".pem");
        try
        {
            await File.WriteAllTextAsync(pemPath, badCa.ExportCertificatePem()); settings.SslCa = pemPath;
            await using var untrusted = new MySqlConnection(settings.ConnectionString);
            var error = await Record.ExceptionAsync(() => untrusted.OpenAsync());
            Assert.NotNull(error); Assert.IsNotAssignableFrom<OperationCanceledException>(error);
            Assert.Equal(System.Data.ConnectionState.Closed, untrusted.State);
        }
        finally { File.Delete(pemPath); }
    }

    [Fact]
    public async Task VerifyFullStillRejectsTrustedCertificateForWrongHost()
    {
        var settings = Settings(); settings.SslMode = MySqlSslMode.VerifyFull;
        settings.SslCa = CaFile();
        await using var connection = new MySqlConnection(settings.ConnectionString);
        var error = await Record.ExceptionAsync(() => connection.OpenAsync());
        Assert.NotNull(error); Assert.IsNotAssignableFrom<OperationCanceledException>(error);
        Assert.Equal(System.Data.ConnectionState.Closed, connection.State);
    }

    [Fact]
    public async Task AlreadyCanceledOpenKeepsOriginalCallerToken()
    {
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await using var connection = new MySqlConnection(Settings().ConnectionString);
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => connection.OpenAsync(cancellation.Token));
        Assert.Equal(cancellation.Token, error.CancellationToken);
        Assert.Equal(System.Data.ConnectionState.Closed, connection.State);
    }

    private static string CaFile()
    {
        var file = Environment.GetEnvironmentVariable("SPECUS_TEST_MYSQL_CA_FILE");
        if (string.IsNullOrWhiteSpace(file))
        {
            var directory = Environment.GetEnvironmentVariable("SPECUS_TEST_MYSQL_EXPECTED_DATA_DIR");
            Assert.False(string.IsNullOrWhiteSpace(directory), "Supply the owned MySQL CA file; certificate regressions must not skip.");
            file = Path.Combine(directory!, "ca.pem");
        }
        Assert.True(File.Exists(file), "Owned MySQL CA file is missing.");
        return file;
    }

    private static MySqlConnectionStringBuilder Settings()
    {
        var value = Environment.GetEnvironmentVariable("SPECUS_TEST_MYSQL_CONNECTION");
        Assert.False(string.IsNullOrWhiteSpace(value));
        var settings = new MySqlConnectionStringBuilder(value) { SslMode = MySqlSslMode.Required, Pooling = false };
        Assert.Contains(settings.Server, new[] { "127.0.0.1", "localhost" });
        return settings;
    }
}
