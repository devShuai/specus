using System.Data.Common;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Specus.Server.Data;
using Specus.Server.Data.Entities;

namespace Specus.IntegrationTests;

public sealed class SqliteMigrationLockRecoveryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RefusedDowngradePreservesRowsAndReopensWithoutAStaleLock(bool asynchronous)
    {
        var path = NewDatabasePath();
        try
        {
            string[] history;
            await using (var db = Context(path))
            {
                await db.Database.MigrateAsync();
                db.ClientSessions.Add(Session(901));
                await db.SaveChangesAsync();
                history = (await db.Database.GetAppliedMigrationsAsync()).ToArray();
                const string previous = "20261013031414_BindManagementWebSocketAccount";
                if (asynchronous)
                    await Assert.ThrowsAsync<NotSupportedException>(() => db.GetService<IMigrator>().MigrateAsync(previous));
                else
                    Assert.Throws<NotSupportedException>(() => db.GetService<IMigrator>().Migrate(previous));
                Assert.Null(db.Database.CurrentTransaction);
                Assert.Equal(history, await db.Database.GetAppliedMigrationsAsync());
                Assert.True((await db.ClientSessions.AsNoTracking().SingleAsync()).ClientEgressIpv6Targets);
                Assert.Equal(0, await LockCountAsync(path));
            }
            // A different connection/context must recover, not just a cached service.
            await using var reopened = Context(path);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await reopened.Database.MigrateAsync(deadline.Token);
            Assert.Equal(history, await reopened.Database.GetAppliedMigrationsAsync());
            Assert.True((await reopened.ClientSessions.AsNoTracking().SingleAsync()).ClientEgressIpv6Targets);
            Assert.False(reopened.Database.HasPendingModelChanges());
        }
        finally { DeleteOwnedDatabase(path); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancelledContenderAndDoubleDisposeCannotReleaseAnotherContextsLock(bool asynchronous)
    {
        var path = NewDatabasePath();
        try
        {
            await using var owner = Context(path);
            await owner.Database.MigrateAsync();
            await owner.Database.OpenConnectionAsync();
            var repository = owner.GetService<IHistoryRepository>();
            var held = asynchronous
                ? await repository.AcquireDatabaseLockAsync()
                : repository.AcquireDatabaseLock();
            try
            {
                var witness = new ContendedInsertWitness();
                await using var contender = Context(path, witness);
                using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var attempt = contender.Database.MigrateAsync(cancellation.Token);
                // Witness the actual INSERT OR IGNORE returning zero, not a sleep
                // or an assumption that the contender has reached the lock boundary.
                await witness.Blocked.Task.WaitAsync(TimeSpan.FromSeconds(10));
                Assert.False(attempt.IsCompleted);
                cancellation.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => attempt);
                Assert.Equal(1, await LockCountAsync(path));
                if (asynchronous) await held.DisposeAsync(); else held.Dispose();
                Assert.Equal(0, await LockCountAsync(path));

                await contender.Database.OpenConnectionAsync();
                await using (var nextOwner = await contender.GetService<IHistoryRepository>().AcquireDatabaseLockAsync())
                {
                    Assert.Equal(1, await LockCountAsync(path));
                    // A repeated release by the OLD owner must not delete the NEW owner's row.
                    if (asynchronous) held.Dispose(); else await held.DisposeAsync();
                    Assert.Equal(1, await LockCountAsync(path));
                }
                Assert.Equal(0, await LockCountAsync(path));
                using var recovery = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await contender.Database.MigrateAsync(recovery.Token);
            }
            finally { await held.DisposeAsync(); }
        }
        finally { DeleteOwnedDatabase(path); }
    }

    [Fact]
    public async Task ExplicitCallerTransactionIsNotRolledBackByLockRelease()
    {
        var path = NewDatabasePath();
        try
        {
            await using (var db = Context(path))
            {
                await db.Database.MigrateAsync();
                await using var caller = await db.Database.BeginTransactionAsync();
                var held = await db.GetService<IHistoryRepository>().AcquireDatabaseLockAsync();
                db.ClientSessions.Add(Session(902));
                await db.SaveChangesAsync();
                await held.DisposeAsync();
                Assert.Same(caller, db.Database.CurrentTransaction);
                await caller.CommitAsync();
            }
            await using var reopened = Context(path);
            Assert.True((await reopened.ClientSessions.AsNoTracking().SingleAsync()).ClientEgressIpv6Targets);
            Assert.Equal(0, await LockCountAsync(path));
        }
        finally { DeleteOwnedDatabase(path); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReleaseRollsBackUncommittedMigrationWritesBeforeDeletingLock(bool asynchronous)
    {
        var path = NewDatabasePath();
        try
        {
            await using (var db = Context(path))
            {
                await db.Database.MigrateAsync();
                await db.Database.OpenConnectionAsync();
                var held = await db.GetService<IHistoryRepository>().AcquireDatabaseLockAsync();
                try
                {
                    // The lock was acquired BEFORE this transaction, as EF's migrator does.
                    await using var pending = await db.Database.BeginTransactionAsync();
                    db.ClientSessions.Add(Session(903));
                    await db.SaveChangesAsync();
                    if (asynchronous) await held.DisposeAsync(); else held.Dispose();
                    Assert.Null(db.Database.CurrentTransaction);
                }
                finally { await held.DisposeAsync(); }
            }
            await using var reopened = Context(path);
            Assert.Empty(await reopened.ClientSessions.AsNoTracking().ToArrayAsync());
            Assert.Equal(0, await LockCountAsync(path));
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await reopened.Database.MigrateAsync(deadline.Token);
        }
        finally { DeleteOwnedDatabase(path); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PostDeleteCallbackFailureCannotMakeRetryDeleteTheNextOwnersLock(bool asynchronous)
    {
        var path = NewDatabasePath();
        try
        {
            var witness = new ReleasedThenThrowWitness();
            await using var owner = Context(path, witness);
            await owner.Database.MigrateAsync();
            await owner.Database.OpenConnectionAsync();
            var held = await owner.GetService<IHistoryRepository>().AcquireDatabaseLockAsync();
            try
            {
                witness.Armed = true;
                if (asynchronous)
                    await Assert.ThrowsAsync<ReleaseCallbackException>(async () => await held.DisposeAsync());
                else
                    Assert.Throws<ReleaseCallbackException>(() => held.Dispose());
                Assert.Equal(0, await LockCountAsync(path)); // DELETE really committed before the callback failed.

                await using var nextContext = Context(path);
                await nextContext.Database.OpenConnectionAsync();
                await using var nextOwner = await nextContext.GetService<IHistoryRepository>().AcquireDatabaseLockAsync();
                Assert.Equal(1, await LockCountAsync(path));
                // Disposal has an uncertain result. It must NOT blindly retry DELETE,
                // even when the old caller observed an exception instead of success.
                if (asynchronous) held.Dispose(); else await held.DisposeAsync();
                Assert.Equal(1, await LockCountAsync(path));
            }
            finally { await held.DisposeAsync(); }
        }
        finally { DeleteOwnedDatabase(path); }
    }

    private static SpecusDbContext Context(string path, DbCommandInterceptor? interceptor = null)
    {
        var options = new DbContextOptionsBuilder<SpecusDbContext>()
            .UseSqlite(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ConnectionString);
        if (interceptor is not null) options.AddInterceptors(interceptor);
        return new SpecusDbContext(options.Options);
    }

    private static ClientSession Session(long id) => new()
    {
        Id = id, TenantId = "sqlite-recovery", CredentialId = 1, IdentityId = 1, ClientId = 1,
        ClientName = "current", TokenHash = "sqlite-recovery-token", Status = "NETTY_ONLINE",
        MachineFingerprint = "fixture-machine", OsUser = "fixture-user",
        ClientEgressVersion = 1, ClientEgressIpv6Targets = true,
        HttpLoginAt = DateTimeOffset.Parse("2026-10-18T00:01:00Z"),
        ExpiresAt = DateTimeOffset.Parse("2026-10-19T00:00:00Z"),
    };

    private static async Task<long> LockCountAsync(string path)
    {
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = path, Pooling = false }.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM \"__EFMigrationsLock\"";
        return Convert.ToInt64(await command.ExecuteScalarAsync());
    }

    private static string NewDatabasePath() => Path.Combine(Path.GetTempPath(),
        $"specus-sqlite-migration-lock-{Guid.NewGuid():N}.db");

    private static void DeleteOwnedDatabase(string path)
    {
        if (Path.GetDirectoryName(Path.GetFullPath(path)) != Path.TrimEndingDirectorySeparator(Path.GetTempPath())
            || !Path.GetFileName(path).StartsWith("specus-sqlite-migration-lock-", StringComparison.Ordinal))
            throw new InvalidOperationException("Refuse cleanup outside the owned temporary database");
        foreach (var suffix in new[] { "", "-wal", "-shm", "-journal" }) File.Delete(path + suffix);
    }

    private sealed class ReleaseCallbackException : Exception { }

    private sealed class ReleasedThenThrowWitness : DbCommandInterceptor
    {
        public bool Armed { get; set; }

        private void Observe(DbCommand command)
        {
            if (Armed && command.CommandText.StartsWith("DELETE FROM \"__EFMigrationsLock\"", StringComparison.Ordinal))
            {
                Assert.Null(command.Transaction);
                Armed = false;
                throw new ReleaseCallbackException();
            }
        }

        public override object? ScalarExecuted(DbCommand command, CommandExecutedEventData eventData, object? result)
        {
            Observe(command);
            return result;
        }

        public override ValueTask<object?> ScalarExecutedAsync(DbCommand command, CommandExecutedEventData eventData,
            object? result, CancellationToken cancellationToken = default)
        {
            Observe(command);
            return ValueTask.FromResult(result);
        }
    }

    private sealed class ContendedInsertWitness : DbCommandInterceptor
    {
        public TaskCompletionSource<bool> Blocked { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        private void Observe(DbCommand command, object? result)
        {
            if (command.CommandText.Contains("INSERT OR IGNORE INTO \"__EFMigrationsLock\"", StringComparison.Ordinal)
                && result is not null && Convert.ToInt64(result) == 0)
                Blocked.TrySetResult(true);
        }

        public override object? ScalarExecuted(DbCommand command, CommandExecutedEventData eventData, object? result)
        {
            Observe(command, result);
            return result;
        }

        public override ValueTask<object?> ScalarExecutedAsync(DbCommand command, CommandExecutedEventData eventData,
            object? result, CancellationToken cancellationToken = default)
        {
            Observe(command, result);
            return ValueTask.FromResult(result);
        }
    }
}
