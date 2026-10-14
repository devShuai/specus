using System.Data;
using MySql.Data.MySqlClient;

namespace Specus.IntegrationTests;

/// <summary>
/// Test-only: defeat MariaDB's automatic Connector/NET metadata mask on one
/// diagnostic connection, before the driver's initial server-properties query.
/// Never returns a fake reader/result or changes global settings.
/// Native production bootstrap tests do not register this hook.
/// </summary>
public sealed class UnmaskedMariaDbMetadataInterceptor : BaseCommandInterceptor
{
    private bool unmasked;

    public override bool ExecuteReader(string sql, CommandBehavior behavior, ref MySqlDataReader returnValue)
    {
        // Run before any bootstrap hook can supply an actual metadata reader. The
        // driver invokes multiple hooks even after one returns a reader, so executing
        // SET from SHOW COLLATION itself would depend on interceptor iteration order.
        if (!unmasked && sql.TrimStart().StartsWith("SELECT @@max_allowed_packet", StringComparison.OrdinalIgnoreCase)
            && ActiveConnection.ServerVersion.Contains("MariaDB", StringComparison.OrdinalIgnoreCase))
        {
            unmasked = true;
            using var command = new MySqlCommand("SET SESSION old_mode=''", ActiveConnection);
            command.ExecuteNonQuery();
        }
        return false;
    }
}
