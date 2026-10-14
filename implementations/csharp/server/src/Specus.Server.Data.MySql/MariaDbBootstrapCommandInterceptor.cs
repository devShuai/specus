using System.Data;
using MySql.Data.MySqlClient;

namespace Specus.Server.Data.MySql;

/// <summary>Public driver hook, restricted to MariaDB connection initialization.</summary>
public sealed class MariaDbBootstrapCommandInterceptor : BaseCommandInterceptor
{
    private bool initializing = true;

    public override void Init(MySqlConnection connection)
    {
        base.Init(connection);
        connection.StateChange += OnStateChanged;
    }

    private void OnStateChanged(object? sender, StateChangeEventArgs state)
    {
        if (state.CurrentState is not (ConnectionState.Open or ConnectionState.Closed)) return;
        initializing = false;
        // A reopened connection gets a new driver interceptor. Do not retain old handlers.
        ActiveConnection.StateChange -= OnStateChanged;
    }

    public override bool ExecuteReader(string sql, CommandBehavior behavior, ref MySqlDataReader returnValue)
    {
        if (!initializing || !sql.Trim().Equals("SHOW COLLATION", StringComparison.OrdinalIgnoreCase)
            || !ActiveConnection.ServerVersion.Contains("MariaDB", StringComparison.OrdinalIgnoreCase)) return false;

        // MariaDB's generic UCA entries have no per-charset ID/charset; the driver cannot
        // convert those NULL IDs to integers. Preserve every real per-charset mapping.
        // After the Open event ordinary user SHOW COLLATION remains completely untouched.
        using var command = new MySqlCommand("SHOW COLLATION WHERE Id IS NOT NULL AND Charset IS NOT NULL", ActiveConnection)
        {
            CommandTimeout = ActiveConnection.ConnectionTimeout,
        };
        returnValue = command.ExecuteReader(behavior);
        return true;
    }
}
