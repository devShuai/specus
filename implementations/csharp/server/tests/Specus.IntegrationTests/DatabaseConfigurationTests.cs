using Specus.Server.Configuration;

namespace Specus.IntegrationTests;

public sealed class DatabaseConfigurationTests
{
    [Fact]
    public void ConvertsJavaPostgresJdbcSettings()
    {
        var result = DatabaseConfiguration.Resolve(new DatabaseOptions
        {
            Url = "jdbc:postgresql://db.internal:5433/specus?sslmode=Require&currentSchema=public",
            Username = "specus_user",
            Password = "secret",
            Driver = "org.postgresql.Driver",
            PoolSize = 12,
            BatchSize = 64,
        }, existingConnectionString: null);

        Assert.Equal("postgres", result.Provider);
        Assert.Contains("Host=\"db.internal\"", result.ConnectionString, StringComparison.Ordinal);
        Assert.Contains("Port=5433", result.ConnectionString, StringComparison.Ordinal);
        Assert.Contains("Database=\"specus\"", result.ConnectionString, StringComparison.Ordinal);
        Assert.Contains("SSL Mode=\"Require\"", result.ConnectionString, StringComparison.Ordinal);
        Assert.Contains("Search Path=\"public\"", result.ConnectionString, StringComparison.Ordinal);
        Assert.Contains("Username=\"specus_user\"", result.ConnectionString, StringComparison.Ordinal);
        Assert.Contains("Password=\"secret\"", result.ConnectionString, StringComparison.Ordinal);
        Assert.Contains("Maximum Pool Size=12", result.ConnectionString, StringComparison.Ordinal);
        Assert.Equal(12, result.PoolSize);
        Assert.Equal(64, result.BatchSize);
    }

    [Fact]
    public void ConvertsJavaMySqlJdbcSettingsAndInfersProviderFromDialect()
    {
        var result = DatabaseConfiguration.Resolve(new DatabaseOptions
        {
            Url = "jdbc:mysql://mysql.internal:3307/specus?useUnicode=true&characterEncoding=UTF-8"
                  + "&connectionCollation=utf8mb4_unicode_ci&useSSL=false&serverTimezone=Asia/Shanghai"
                  + "&allowPublicKeyRetrieval=true",
            Username = "specus_user",
            Password = "secret",
            Dialect = "org.hibernate.dialect.MySQLDialect",
            PoolSize = 8,
            BatchSize = 20,
        }, existingConnectionString: null);

        Assert.Equal("mysql", result.Provider);
        Assert.Contains("Server=\"mysql.internal\"", result.ConnectionString, StringComparison.Ordinal);
        Assert.Contains("Port=3307", result.ConnectionString, StringComparison.Ordinal);
        Assert.Contains("Database=\"specus\"", result.ConnectionString, StringComparison.Ordinal);
        Assert.Contains("SslMode=\"None\"", result.ConnectionString, StringComparison.Ordinal);
        Assert.Contains("Character Set=\"utf8mb4\"", result.ConnectionString, StringComparison.Ordinal);
        Assert.Contains("AllowPublicKeyRetrieval=\"true\"", result.ConnectionString, StringComparison.Ordinal);
        Assert.Contains("User ID=\"specus_user\"", result.ConnectionString, StringComparison.Ordinal);
        Assert.Contains("MaximumPoolSize=8", result.ConnectionString, StringComparison.Ordinal);
        Assert.Equal(20, result.BatchSize);
    }

    [Fact]
    public void ConvertsJavaSqliteJdbcSettings()
    {
        var result = DatabaseConfiguration.Resolve(new DatabaseOptions
        {
            Url = "jdbc:sqlite:./data/specus.db",
            Driver = "org.sqlite.JDBC",
        }, existingConnectionString: null);

        Assert.Equal("sqlite", result.Provider);
        Assert.Equal("Data Source=\"./data/specus.db\"", result.ConnectionString);
    }

    [Fact]
    public void PreservesDotNetConnectionStringWhenJavaUrlIsAbsent()
    {
        var result = DatabaseConfiguration.Resolve(new DatabaseOptions
        {
            Provider = "sqlite",
            Url = string.Empty,
        }, "Data Source=legacy.db");

        Assert.Equal("sqlite", result.Provider);
        Assert.Equal("Data Source=legacy.db", result.ConnectionString);
    }
}
