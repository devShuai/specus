using System.Reflection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Hosting;

namespace ShuaiTunnel.IntegrationTests;

public sealed class DatabaseInitializerTests
{
    [Fact]
    public void BackfillConnectionStatTenantSqlQuotesPostgresPascalCaseId()
    {
        var sql = BuildConnectionStatTenantBackfillSql("Npgsql.EntityFrameworkCore.PostgreSQL");

        Assert.Contains("c.\"Id\" = tunnel_connection_stat.client_id", sql);
        Assert.DoesNotContain("c.Id = tunnel_connection_stat.client_id", sql);
    }

    [Fact]
    public void BackfillConnectionStatTenantSqlKeepsPlainIdForSqlite()
    {
        var sql = BuildConnectionStatTenantBackfillSql("Microsoft.EntityFrameworkCore.Sqlite");

        Assert.Contains("c.Id = tunnel_connection_stat.client_id", sql);
    }

    [Fact]
    public async Task StartupCompatibilityAddsAndBackfillsPeerMeshAclDirection()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new TunnelDbContext(new DbContextOptionsBuilder<TunnelDbContext>()
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

    private static string BuildConnectionStatTenantBackfillSql(string providerName)
    {
        var method = typeof(DatabaseInitializer).GetMethod(
            "BuildConnectionStatTenantBackfillSql",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        return Assert.IsType<string>(method.Invoke(null, [providerName]));
    }
}
