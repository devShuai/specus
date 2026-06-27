using System.Reflection;
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

    private static string BuildConnectionStatTenantBackfillSql(string providerName)
    {
        var method = typeof(DatabaseInitializer).GetMethod(
            "BuildConnectionStatTenantBackfillSql",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        return Assert.IsType<string>(method.Invoke(null, [providerName]));
    }
}
