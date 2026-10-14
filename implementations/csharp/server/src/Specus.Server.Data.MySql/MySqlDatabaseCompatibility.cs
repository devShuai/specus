using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using MySql.Data.MySqlClient;

namespace Specus.Server.Data.MySql;

/// <summary>Keep the shared MySQL migration model while adapting actual MariaDB protocol differences.</summary>
public static class MySqlDatabaseCompatibility
{
    public static string PrepareConnectionString(string connectionString)
    {
        var settings = new MySqlConnectionStringBuilder(connectionString);
        // The driver otherwise inherits a latin1 server handshake even for utf8mb4 tables,
        // replacing Unicode with '?' before strict SQL mode can detect data loss.
        if (string.IsNullOrWhiteSpace(settings.CharacterSet)) settings.CharacterSet = "utf8mb4";

        var type = typeof(MariaDbBootstrapCommandInterceptor);
        var interceptors = (settings.CommandInterceptors ?? string.Empty).Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        if (!interceptors.Any(value => value.Split(',')[0].Trim().Equals(type.FullName, StringComparison.Ordinal)))
            interceptors.Add($"{type.FullName}, {type.Assembly.GetName().Name}");
        settings.CommandInterceptors = string.Join('|', interceptors);
        return settings.ConnectionString;
    }

    public static void Configure(DbContextOptionsBuilder options, string connectionString, int? batchSize = null)
    {
        options.UseMySQL(PrepareConnectionString(connectionString), mysql =>
        {
            mysql.MigrationsAssembly(typeof(MySqlDatabaseCompatibility).Assembly.GetName().Name);
            if (batchSize.HasValue) mysql.MaxBatchSize(batchSize.Value);
        });
        var existing = options.Options.FindExtension<CoreOptionsExtension>()?.Interceptors;
        if (existing?.Contains(MariaDbMigrationLockInterceptor.Instance) != true)
            options.AddInterceptors(MariaDbMigrationLockInterceptor.Instance);
    }
}
