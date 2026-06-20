using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace ShuaiTunnel.Server.Data.Postgres;

/// <summary>
/// Design-time factory so <c>dotnet ef</c> can scaffold/apply the PostgreSQL migration set without
/// booting the server. The connection string is throwaway — <c>migrations add</c> only needs the
/// provider to emit DDL, it never connects. Production options are wired through DI in
/// <c>Program.cs</c> (which sets the same <see cref="RelationalDbContextOptionsBuilderExtensions.MigrationsAssembly"/>).
/// </summary>
public sealed class PostgresDesignTimeDbContextFactory : IDesignTimeDbContextFactory<TunnelDbContext>
{
    public TunnelDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<TunnelDbContext>()
            .UseNpgsql(
                "Host=localhost;Database=shuai_tunnel;Username=postgres;Password=postgres",
                npgsql => npgsql.MigrationsAssembly(typeof(PostgresDesignTimeDbContextFactory).Assembly.GetName().Name))
            .Options;
        return new TunnelDbContext(options);
    }
}
