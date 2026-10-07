using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Specus.Server.Data;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

/// <summary>
/// The route lock that serializes share creations exists only on MySQL and PostgreSQL, which the
/// tests do not run. Offline contexts of every provider (nothing connects) pin the statement each
/// one sends, with the route table and id column as that provider's model maps and quotes them.
/// </summary>
public sealed class HttpShareRouteLockTests
{
    [Theory]
    [InlineData("postgres", "SELECT \"Id\" FROM http_route_mapping WHERE \"Id\" = {0} FOR UPDATE")]
    [InlineData("mysql", "SELECT `Id` FROM `http_route_mapping` WHERE `Id` = {0} FOR UPDATE")]
    public void MySqlAndPostgreSqlLockTheRouteRowForUpdate(string provider, string expected)
    {
        using var context = CreateContext(provider);

        Assert.Equal(expected, HttpShareService.RouteLockSql(context));
    }

    [Fact]
    public void SqliteTakesNoLock()
    {
        using var context = CreateContext("sqlite");

        Assert.Null(HttpShareService.RouteLockSql(context));
    }

    [Theory]
    [InlineData("/api/admin/http-routes/42/shares", true)]
    [InlineData("/api/admin/http-routes/42/shares/", true)]
    [InlineData("/api/admin/http-routes/42/shares/WlpaWlpaWlpaWlpa", true)]
    [InlineData("/api/admin/http-routes/42/shares/WlpaWlpaWlpaWlpa/revoke", true)]
    [InlineData("/api/admin/http-routes/42/access-audit", true)]
    [InlineData("/api/admin/http-access-audit", true)]
    [InlineData("/API/Admin/HTTP-Routes/42/Shares", true)]
    [InlineData("/api/admin/http-routes", false)]
    [InlineData("/api/admin/http-routes/42", false)]
    [InlineData("/api/admin/http-routes/42/connectivity-check", false)]
    [InlineData("/api/admin/http-routes/42/shares/WlpaWlpaWlpaWlpa/other", false)]
    [InlineData("/api/admin/http-routes//shares", false)]
    [InlineData("/api/public/http-shares/exchange", false)]
    [InlineData("/api/admin/clients", false)]
    public void ShareManagementPathsAreRecognized(string path, bool expected)
    {
        Assert.Equal(expected, HttpShareEndpoints.IsManagementPath(new PathString(path)));
    }

    private static SpecusDbContext CreateContext(string provider)
    {
        var builder = new DbContextOptionsBuilder<SpecusDbContext>();
        switch (provider)
        {
            case "sqlite":
                builder.UseSqlite("Data Source=:memory:", o => o.MigrationsAssembly("Specus.Server.Data"));
                break;
            case "postgres":
                builder.UseNpgsql("Host=localhost;Database=specus;Username=postgres;Password=postgres",
                    o => o.MigrationsAssembly("Specus.Server.Data.Postgres"));
                break;
            case "mysql":
                builder.UseMySQL("server=localhost;database=specus;user=root;password=root",
                    o => o.MigrationsAssembly("Specus.Server.Data.MySql"));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(provider), provider, "unknown provider");
        }
        return new SpecusDbContext(builder.Options);
    }
}
