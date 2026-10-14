using System.Data.Common;
using System.Diagnostics;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Specus.Server.Data.MySql;

/// <summary>Acquire a real MariaDB migration lock without unsupported negative SQL timeouts.</summary>
public sealed class MariaDbMigrationLockInterceptor : DbCommandInterceptor
{
    internal static readonly MariaDbMigrationLockInterceptor Instance = new();
    private const string Original = "SELECT GET_LOCK('__EFMigrationsLock',-1);";

    private static bool Applies(DbCommand command, CommandEventData data) => data.CommandSource == CommandSource.Migrations
        && command.CommandText.Trim() == Original
        && command.Connection?.ServerVersion.Contains("MariaDB", StringComparison.OrdinalIgnoreCase) == true;

    private static DbCommand PollCommand(DbCommand original)
    {
        var command = original.Connection!.CreateCommand();
        command.CommandText = "SELECT GET_LOCK('__EFMigrationsLock',0)";
        command.CommandTimeout = 1;
        command.Transaction = original.Transaction;
        return command;
    }

    private static long ActualResult(object? result)
    {
        if (result is null or DBNull) throw new InvalidOperationException("MariaDB migration lock acquisition returned NULL.");
        var actual = Convert.ToInt64(result);
        if (actual is not (0 or 1)) throw new InvalidOperationException("Unexpected MariaDB migration lock result.");
        return actual;
    }

    private static void CheckDeadline(DbCommand command, long started)
    {
        if (command.CommandTimeout > 0 && Stopwatch.GetElapsedTime(started) >= TimeSpan.FromSeconds(command.CommandTimeout))
            throw new TimeoutException("MariaDB migration lock was not acquired; refusing unlocked migration.");
    }

    public override InterceptionResult<object> ScalarExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<object> result)
    {
        if (!Applies(command, eventData) || result.HasResult) return result;
        long started = Stopwatch.GetTimestamp();
        while (true)
        {
            CheckDeadline(command, started);
            using var poll = PollCommand(command);
            long actual = ActualResult(poll.ExecuteScalar());
            // Suppress only the incompatible vendor SQL, after the server truly acquired
            // the same named lock on the same connection. Never treat 0/NULL as success.
            if (actual == 1) return InterceptionResult<object>.SuppressWithResult(actual);
            Thread.Sleep(50);
        }
    }

    public override async ValueTask<InterceptionResult<object>> ScalarExecutingAsync(DbCommand command, CommandEventData eventData,
        InterceptionResult<object> result, CancellationToken cancellationToken = default)
    {
        if (!Applies(command, eventData) || result.HasResult) return result;
        long started = Stopwatch.GetTimestamp();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CheckDeadline(command, started);
            await using var poll = PollCommand(command);
            // GET_LOCK(...,0) never waits. Cancellation is observed between bounded
            // roundtrips: cancelling a long blocking driver read can leave SSL reads pending.
            long actual = ActualResult(await poll.ExecuteScalarAsync(CancellationToken.None).ConfigureAwait(false));
            if (actual == 1)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    poll.CommandText = "SELECT RELEASE_LOCK('__EFMigrationsLock')";
                    if (ActualResult(await poll.ExecuteScalarAsync(CancellationToken.None).ConfigureAwait(false)) != 1)
                        throw new InvalidOperationException("Unable to release cancelled MariaDB migration lock.");
                    cancellationToken.ThrowIfCancellationRequested();
                }
                return InterceptionResult<object>.SuppressWithResult(actual);
            }
            await Task.Delay(50, cancellationToken).ConfigureAwait(false);
        }
    }
}
