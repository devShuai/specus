using System.Reflection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;

namespace Specus.IntegrationTests;

public sealed class DatabaseInitializerTests
{
    [Fact]
    public void BackfillConnectionStatTenantSqlQuotesPostgresPascalCaseId()
    {
        var sql = BuildConnectionStatTenantBackfillSql("Npgsql.EntityFrameworkCore.PostgreSQL");

        Assert.Contains("c.\"Id\" = specus_connection_stat.client_id", sql);
        Assert.DoesNotContain("c.Id = specus_connection_stat.client_id", sql);
    }

    [Fact]
    public void BackfillConnectionStatTenantSqlKeepsPlainIdForSqlite()
    {
        var sql = BuildConnectionStatTenantBackfillSql("Microsoft.EntityFrameworkCore.Sqlite");

        Assert.Contains("c.Id = specus_connection_stat.client_id", sql);
    }

    [Fact]
    public void BackfillConnectionRecordTenantSqlQuotesPostgresPascalCaseId()
    {
        var sql = BuildConnectionRecordTenantBackfillSql("Npgsql.EntityFrameworkCore.PostgreSQL");

        Assert.Contains("c.\"Id\" = specus_connection_record.client_id", sql);
        Assert.DoesNotContain("c.Id = specus_connection_record.client_id", sql);
    }

    [Fact]
    public async Task BackfillConnectionRecordTenantMapsKnownClientsAndDefaultsAnonymousFailures()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = CreateContext(connection);
        await db.Database.ExecuteSqlRawAsync("""
            CREATE TABLE specus_client_account (
              Id INTEGER PRIMARY KEY,
              tenant_id TEXT NOT NULL
            );
            CREATE TABLE specus_connection_record (
              id INTEGER PRIMARY KEY,
              client_id INTEGER,
              tenant_id TEXT
            );
            INSERT INTO specus_client_account (Id, tenant_id) VALUES (10, 'tenant-a');
            INSERT INTO specus_connection_record (id, client_id, tenant_id) VALUES
              (1, 10, NULL),
              (2, NULL, '   '),
              (3, NULL, 'tenant-b');
            """);

        await DatabaseInitializer.BackfillConnectionRecordTenantAsync(db, CancellationToken.None);

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, tenant_id FROM specus_connection_record ORDER BY id";
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal(1, reader.GetInt64(0));
        Assert.Equal("tenant-a", reader.GetString(1));
        Assert.True(await reader.ReadAsync());
        Assert.Equal(2, reader.GetInt64(0));
        Assert.Equal("default", reader.GetString(1));
        Assert.True(await reader.ReadAsync());
        Assert.Equal(3, reader.GetInt64(0));
        Assert.Equal("tenant-b", reader.GetString(1));
        Assert.False(await reader.ReadAsync());
    }

    [Fact]
    public async Task StartupCompatibilityAddsAndBackfillsPeerMeshAclDirection()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new SpecusDbContext(new DbContextOptionsBuilder<SpecusDbContext>()
            .UseSqlite(connection)
            .Options);
        await db.Database.ExecuteSqlRawAsync("""
            CREATE TABLE peer_mesh_acl (
              id INTEGER PRIMARY KEY,
              tenant_id TEXT NOT NULL,
              owner_username TEXT NOT NULL,
              source_client_id INTEGER NOT NULL,
              source_client_name TEXT NOT NULL,
              target_client_id INTEGER NOT NULL,
              target_client_name TEXT NOT NULL,
              allowed INTEGER NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            INSERT INTO peer_mesh_acl (
              id, tenant_id, owner_username, source_client_id, source_client_name,
              target_client_id, target_client_name, allowed, created_at, updated_at
            ) VALUES (1, 'tenant-a', 'alice', 10, 'source', 11, 'target', 1, 'now', 'now');
            """);

        await DatabaseInitializer.EnsurePeerMeshTablesAsync(db, CancellationToken.None);

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT direction FROM peer_mesh_acl WHERE id = 1";
        Assert.Equal("OUTBOUND", await command.ExecuteScalarAsync());
    }

    [Fact]
    public async Task ProdDisablesOnlyExactLegacyDemoCredentialsAndIsIdempotent()
    {
        await using var connection = await OpenDatabaseAsync();
        await using var db = CreateContext(connection);
        var legacyHash = PasswordHasher.Hash(DatabaseInitializer.DemoCredentialSecret);
        var now = DateTimeOffset.UtcNow;
        db.AddRange(
            ClientAccount(1, DatabaseInitializer.DemoClientName, legacyHash, now),
            ClientAccount(2, "Unrelated client", legacyHash, now),
            ClientCredential(3, DatabaseInitializer.DemoCredentialApiKey, legacyHash, now),
            ClientCredential(4, "unrelated-key", legacyHash, now));
        await db.SaveChangesAsync();

        var first = await DatabaseInitializer.DisableLegacyDemoCredentialsAsync(
            db, DeploymentEnvironment.Prod, CancellationToken.None);

        Assert.Equal(1, first.ClientAccounts);
        Assert.Equal(1, first.ClientCredentials);
        db.ChangeTracker.Clear();
        Assert.False((await db.ClientAccounts.SingleAsync(row => row.Id == 1)).Enabled);
        Assert.True((await db.ClientAccounts.SingleAsync(row => row.Id == 2)).Enabled);
        Assert.False((await db.ClientCredentials.SingleAsync(row => row.Id == 3)).Enabled);
        Assert.True((await db.ClientCredentials.SingleAsync(row => row.Id == 4)).Enabled);

        var second = await DatabaseInitializer.DisableLegacyDemoCredentialsAsync(
            db, DeploymentEnvironment.Prod, CancellationToken.None);

        Assert.Equal(0, second.ClientAccounts);
        Assert.Equal(0, second.ClientCredentials);
    }

    [Fact]
    public async Task ProdPreservesRotatedAndNearMatchDemoCredentials()
    {
        await using var connection = await OpenDatabaseAsync();
        await using var db = CreateContext(connection);
        var legacyHash = PasswordHasher.Hash(DatabaseInitializer.DemoCredentialSecret);
        var rotatedHash = PasswordHasher.Hash("operator-rotated-secret");
        var now = DateTimeOffset.UtcNow;
        db.AddRange(
            ClientAccount(1, DatabaseInitializer.DemoClientName, rotatedHash, now),
            ClientAccount(2, "demo client", legacyHash, now),
            ClientCredential(3, DatabaseInitializer.DemoCredentialApiKey, rotatedHash, now),
            ClientCredential(4, "Demo-Client", legacyHash, now));
        await db.SaveChangesAsync();

        var result = await DatabaseInitializer.DisableLegacyDemoCredentialsAsync(
            db, DeploymentEnvironment.Prod, CancellationToken.None);

        Assert.Equal(0, result.ClientAccounts);
        Assert.Equal(0, result.ClientCredentials);
        Assert.All(await db.ClientAccounts.ToListAsync(), row => Assert.True(row.Enabled));
        Assert.All(await db.ClientCredentials.ToListAsync(), row => Assert.True(row.Enabled));
    }

    [Theory]
    [InlineData(DeploymentEnvironment.Dev)]
    [InlineData(DeploymentEnvironment.Test)]
    public async Task NonProdPreservesExactLegacyDemoCredentials(DeploymentEnvironment environment)
    {
        await using var connection = await OpenDatabaseAsync();
        await using var db = CreateContext(connection);
        var legacyHash = PasswordHasher.Hash(DatabaseInitializer.DemoCredentialSecret);
        var now = DateTimeOffset.UtcNow;
        db.AddRange(
            ClientAccount(1, DatabaseInitializer.DemoClientName, legacyHash, now),
            ClientCredential(2, DatabaseInitializer.DemoCredentialApiKey, legacyHash, now));
        await db.SaveChangesAsync();

        var result = await DatabaseInitializer.DisableLegacyDemoCredentialsAsync(
            db, environment, CancellationToken.None);

        Assert.Equal(0, result.ClientAccounts);
        Assert.Equal(0, result.ClientCredentials);
        Assert.True((await db.ClientAccounts.SingleAsync()).Enabled);
        Assert.True((await db.ClientCredentials.SingleAsync()).Enabled);
    }

    [Fact]
    public async Task ProdCleanupRollsBackBothRowsAndPropagatesDatabaseFailure()
    {
        await using var connection = await OpenDatabaseAsync();
        await using var db = CreateContext(connection);
        var legacyHash = PasswordHasher.Hash(DatabaseInitializer.DemoCredentialSecret);
        var now = DateTimeOffset.UtcNow;
        db.AddRange(
            ClientAccount(1, DatabaseInitializer.DemoClientName, legacyHash, now),
            ClientCredential(2, DatabaseInitializer.DemoCredentialApiKey, legacyHash, now));
        await db.SaveChangesAsync();
        await db.Database.ExecuteSqlRawAsync("""
            CREATE TRIGGER reject_demo_credential_update
            BEFORE UPDATE OF enabled ON specus_client_credential
            WHEN OLD.api_key = 'demo-client'
            BEGIN
              SELECT RAISE(ABORT, 'forced cleanup failure');
            END;
            """);

        await Assert.ThrowsAsync<DbUpdateException>(() =>
            DatabaseInitializer.DisableLegacyDemoCredentialsAsync(
                db, DeploymentEnvironment.Prod, CancellationToken.None));

        db.ChangeTracker.Clear();
        Assert.True((await db.ClientAccounts.AsNoTracking().SingleAsync()).Enabled);
        Assert.True((await db.ClientCredentials.AsNoTracking().SingleAsync()).Enabled);
    }

    private static string BuildConnectionStatTenantBackfillSql(string providerName)
    {
        var method = typeof(DatabaseInitializer).GetMethod(
            "BuildConnectionStatTenantBackfillSql",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        return Assert.IsType<string>(method.Invoke(null, [providerName]));
    }

    private static string BuildConnectionRecordTenantBackfillSql(string providerName)
    {
        var method = typeof(DatabaseInitializer).GetMethod(
            "BuildConnectionRecordTenantBackfillSql",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        return Assert.IsType<string>(method.Invoke(null, [providerName]));
    }

    private static async Task<SqliteConnection> OpenDatabaseAsync()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = CreateContext(connection);
        await db.Database.EnsureCreatedAsync();
        return connection;
    }

    private static SpecusDbContext CreateContext(SqliteConnection connection) =>
        new(new DbContextOptionsBuilder<SpecusDbContext>()
            .UseSqlite(connection)
            .Options);

    private static ClientAccount ClientAccount(long id, string name, string passwordHash,
        DateTimeOffset now) => new()
    {
        Id = id,
        TenantId = "default",
        OwnerUsername = "admin",
        ClientName = name,
        PasswordHash = passwordHash,
        Enabled = true,
        ConnectionRateLimitPerMinute = 30,
        CreatedAt = now,
        UpdatedAt = now,
    };

    private static ClientCredential ClientCredential(long id, string apiKey, string secretHash,
        DateTimeOffset now) => new()
    {
        Id = id,
        TenantId = "default",
        OwnerUsername = "admin",
        ApiKey = apiKey,
        SecretHash = secretHash,
        Enabled = true,
        MaxOnlineInstances = 2,
        CreatedAt = now,
        UpdatedAt = now,
    };
}
