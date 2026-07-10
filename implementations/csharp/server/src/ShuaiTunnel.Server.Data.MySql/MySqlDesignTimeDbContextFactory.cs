using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace ShuaiTunnel.Server.Data.MySql;

/// <summary>
/// Design-time factory so <c>dotnet ef</c> can scaffold/apply the MySQL migration set without
/// booting the server. The connection string is throwaway — <c>migrations add</c> only needs the
/// provider to emit DDL, it never connects. Production options are wired through DI in
/// <c>Program.cs</c> (which sets the same migrations assembly). Uses Oracle's official
/// <c>MySql.EntityFrameworkCore</c> provider (the only one shipping an EF Core 10 build).
/// </summary>
public sealed class MySqlDesignTimeDbContextFactory : IDesignTimeDbContextFactory<TunnelDbContext>
{
    public TunnelDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<TunnelDbContext>()
            .UseMySQL(
                "server=localhost;database=design_time",
                mysql => mysql.MigrationsAssembly(typeof(MySqlDesignTimeDbContextFactory).Assembly.GetName().Name))
            .Options;
        return new TunnelDbContext(options);
    }
}
