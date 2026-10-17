using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Sqlite.Migrations.Internal;
using Microsoft.EntityFrameworkCore.Storage;

namespace Specus.Server.Data.Migrations;

// EF 10.0.11 disposes its explicit SQLite migration lock before its pending
// transaction. A failed migration can therefore roll back the lock's DELETE,
// leaving the database permanently locked. Keep the upstream lock protocol;
// only end our migration transaction before releasing a successfully acquired lock.
// This provider adaptation is version-sensitive and covered by recovery and
// competing-context tests. No lock is removed on startup or after failed acquisition.
#pragma warning disable EF1001 // SQLite's provider implementation is internal; pinned to EF 10.0.11.
public sealed class SpecusSqliteHistoryRepository(HistoryRepositoryDependencies dependencies)
    : SqliteHistoryRepository(dependencies)
{
    public override IMigrationsDatabaseLock AcquireDatabaseLock()
    {
        var callerTransaction = Dependencies.Connection.CurrentTransaction;
        var acquired = base.AcquireDatabaseLock();
        return new TransactionSafeLock(acquired, this, Dependencies.Connection,
            endMigrationTransaction: callerTransaction is null);
    }

    public override async Task<IMigrationsDatabaseLock> AcquireDatabaseLockAsync(
        CancellationToken cancellationToken = default)
    {
        var callerTransaction = Dependencies.Connection.CurrentTransaction;
        var acquired = await base.AcquireDatabaseLockAsync(cancellationToken).ConfigureAwait(false);
        return new TransactionSafeLock(acquired, this, Dependencies.Connection,
            endMigrationTransaction: callerTransaction is null);
    }

    private sealed class TransactionSafeLock(IMigrationsDatabaseLock acquired,
        IHistoryRepository repository, IRelationalConnection connection,
        bool endMigrationTransaction) : IMigrationsDatabaseLock
    {
        private bool _releaseAttempted;

        IHistoryRepository IMigrationsDatabaseLock.HistoryRepository => repository;

        public void Dispose()
        {
            if (_releaseAttempted) return;
            // Acquired without a caller transaction, on this non-thread-safe context.
            // A still-current transaction is the migration's uncommitted transaction;
            // successful commits already clear CurrentTransaction. Never commit on failure.
            if (endMigrationTransaction && connection.CurrentTransaction is { } transaction)
            {
                transaction.Rollback();
                transaction.Dispose();
            }
            // Keep the logical lock until rollback/disposal has succeeded. If either
            // fails, fail closed rather than let another migrator enter uncertain state.
            // DELETE can commit before an observer/logger reports an exception.
            // Never retry an uncertain release: a subsequent owner may already hold
            // this row. If DELETE did not commit, retaining the lock fails closed.
            _releaseAttempted = true;
            acquired.Dispose();
        }

        public async ValueTask DisposeAsync()
        {
            if (_releaseAttempted) return;
            if (endMigrationTransaction && connection.CurrentTransaction is { } transaction)
            {
                await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
                await transaction.DisposeAsync().ConfigureAwait(false);
            }
            _releaseAttempted = true;
            await acquired.DisposeAsync().ConfigureAwait(false);
        }
    }
}
#pragma warning restore EF1001
