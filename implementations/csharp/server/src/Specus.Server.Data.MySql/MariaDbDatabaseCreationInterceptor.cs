using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Specus.Server.Data.MySql;

/// <summary>Give only a newly created MariaDB application database a Unicode default.</summary>
public sealed class MariaDbDatabaseCreationInterceptor : DbCommandInterceptor
{
    internal string DatabaseName { get; }
    private readonly string originalSql;
    private readonly string unicodeSql;

    internal MariaDbDatabaseCreationInterceptor(string databaseName)
    {
        DatabaseName = databaseName;
        // Quote the configured identifier exactly as the provider does; never interpret
        // a connection-string database name as a SQL fragment.
        string identifier = "`" + databaseName.Replace("`", "``", StringComparison.Ordinal) + "`";
        originalSql = $"CREATE DATABASE {identifier}";
        unicodeSql = $"CREATE DATABASE {identifier} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;";
    }

    private void ConfigureNewDatabase(DbCommand command, CommandEventData data, InterceptionResult<int> result)
    {
        if (!result.HasResult && data.CommandSource == CommandSource.Migrations
            && (command.CommandText.Trim() == originalSql || command.CommandText.Trim() == originalSql + ";")
            && command.Connection?.ServerVersion.Contains("MariaDB", StringComparison.OrdinalIgnoreCase) == true)
            command.CommandText = unicodeSql;
        // Never ALTER an existing database/table, change global defaults, override
        // explicit CREATE options, or rewrite ordinary application SQL / MySQL DDL.
    }

    public override InterceptionResult<int> NonQueryExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<int> result)
    {
        ConfigureNewDatabase(command, eventData, result);
        return result;
    }

    public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command, CommandEventData eventData,
        InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        ConfigureNewDatabase(command, eventData, result);
        return ValueTask.FromResult(result);
    }
}
