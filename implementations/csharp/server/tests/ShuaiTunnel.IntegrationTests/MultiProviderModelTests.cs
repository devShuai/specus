using Microsoft.EntityFrameworkCore;
using ShuaiTunnel.Server.Data;

namespace ShuaiTunnel.IntegrationTests;

/// <summary>
/// Offline (no live database) validation that the shared <see cref="TunnelDbContext"/> model maps
/// cleanly onto every supported provider and that each provider's generated migrations still match
/// the model. Catches schema drift and provider-specific mapping breakage in CI without needing
/// Docker/Testcontainers.
/// </summary>
public sealed class MultiProviderModelTests
{
    private static readonly string[] ExpectedTables =
    {
        "tunnel_client_account",
        "tunnel_connection_record",
        "tunnel_mapping",
        "http_route_mapping",
        "client_download_link",
        "tunnel_management_user_email",
        "tunnel_management_registration_challenge",
        "peer_mesh_acl",
        "tunnel_traffic_usage",
        "tunnel_connection_stat",
    };

    public static TheoryData<string> Providers => new() { "sqlite", "postgres", "mysql" };

    [Theory]
    [MemberData(nameof(Providers))]
    public void GeneratesCreateScriptWithAllTables(string provider)
    {
        using var context = CreateContext(provider);

        var script = context.Database.GenerateCreateScript();

        Assert.False(string.IsNullOrWhiteSpace(script), $"empty DDL for provider '{provider}'");
        foreach (var table in ExpectedTables)
        {
            Assert.Contains(table, script, StringComparison.Ordinal);
        }
        Assert.Contains("direction", script, StringComparison.Ordinal);
        Assert.Contains("OUTBOUND", script, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public void HasNoPendingModelChanges(string provider)
    {
        using var context = CreateContext(provider);

        // Fails if OnModelCreating drifted from the committed migration snapshot for this provider —
        // i.e. someone changed the model but forgot to add a migration.
        Assert.False(context.Database.HasPendingModelChanges(),
            $"model differs from the committed migrations for provider '{provider}'");
    }

    private static TunnelDbContext CreateContext(string provider)
    {
        // Throwaway connection strings — GenerateCreateScript/HasPendingModelChanges never connect.
        var builder = new DbContextOptionsBuilder<TunnelDbContext>();
        switch (provider)
        {
            case "sqlite":
                builder.UseSqlite("Data Source=:memory:",
                    o => o.MigrationsAssembly("ShuaiTunnel.Server.Data"));
                break;
            case "postgres":
                builder.UseNpgsql("Host=localhost;Database=shuai_tunnel;Username=postgres;Password=postgres",
                    o => o.MigrationsAssembly("ShuaiTunnel.Server.Data.Postgres"));
                break;
            case "mysql":
                builder.UseMySQL("server=localhost;database=shuai_tunnel;user=root;password=root",
                    o => o.MigrationsAssembly("ShuaiTunnel.Server.Data.MySql"));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(provider), provider, "unknown provider");
        }

        return new TunnelDbContext(builder.Options);
    }
}
