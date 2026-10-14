using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using MySql.Data.MySqlClient;
using Specus.Server.Data;
using Specus.Server.Data.MySql;

namespace Specus.IntegrationTests;

public sealed class MySqlDatabaseCompatibilityTests
{
    [Fact]
    public void DefaultsToUnicodeAndPreservesConnectionSecurityAndCustomInterceptors()
    {
        const string original = "server=localhost;database=proof;user=proof;password=test-only;SslMode=VerifyFull;Pooling=false;ConnectionTimeout=7;CommandInterceptors=Custom.Existing, Custom";
        var prepared = MySqlDatabaseCompatibility.PrepareConnectionString(original);
        var settings = new MySqlConnectionStringBuilder(prepared);
        Assert.Equal("utf8mb4", settings.CharacterSet);
        Assert.Equal(MySqlSslMode.VerifyFull, settings.SslMode);
        Assert.False(settings.Pooling);
        Assert.Equal(7u, settings.ConnectionTimeout);
        Assert.Equal("test-only", settings.Password);
        Assert.Contains("Custom.Existing, Custom", settings.CommandInterceptors, StringComparison.Ordinal);
        Assert.Contains(typeof(MariaDbBootstrapCommandInterceptor).FullName!, settings.CommandInterceptors, StringComparison.Ordinal);
        Assert.Equal(prepared, MySqlDatabaseCompatibility.PrepareConnectionString(prepared));
    }

    [Theory]
    [InlineData("utf8mb4")]
    [InlineData("latin1")]
    public void ExplicitCharacterSetIsNotSilentlyReplaced(string charset)
    {
        var settings = new MySqlConnectionStringBuilder(MySqlDatabaseCompatibility.PrepareConnectionString(
            $"server=localhost;database=proof;CharacterSet={charset}"));
        Assert.Equal(charset, settings.CharacterSet);
    }

    [Fact]
    public void RepeatedConfigurationDoesNotAcquireTheMigrationLockTwice()
    {
        var builder = new DbContextOptionsBuilder<SpecusDbContext>();
        MySqlDatabaseCompatibility.Configure(builder, "server=localhost;database=proof");
        MySqlDatabaseCompatibility.Configure(builder, "server=localhost;database=proof");
        var interceptors = builder.Options.FindExtension<CoreOptionsExtension>()!.Interceptors!;
        Assert.Single(interceptors.OfType<MariaDbMigrationLockInterceptor>());
        using var db = new SpecusDbContext(builder.Options);
        Assert.False(db.Database.HasPendingModelChanges());
    }

    [Fact]
    public void DesignTimeFactoryUsesTheSameSafeConnectionDefaultsWithoutModelDrift()
    {
        using var db = new MySqlDesignTimeDbContextFactory().CreateDbContext([]);
        var settings = new MySqlConnectionStringBuilder(db.Database.GetConnectionString());
        Assert.Equal("utf8mb4", settings.CharacterSet);
        Assert.Contains(typeof(MariaDbBootstrapCommandInterceptor).FullName!, settings.CommandInterceptors, StringComparison.Ordinal);
        Assert.False(db.Database.HasPendingModelChanges());
    }
}
