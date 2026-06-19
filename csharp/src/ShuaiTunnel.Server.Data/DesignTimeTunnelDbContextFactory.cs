using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace ShuaiTunnel.Server.Data;

/// <summary>
/// Lets <c>dotnet ef</c> tooling instantiate <see cref="TunnelDbContext"/> without booting the
/// full server. The connection string here is throwaway — migrations are SQL-text-only and don't
/// touch the configured DB. Production wires real options through DI in <c>Program.cs</c>.
/// </summary>
public sealed class DesignTimeTunnelDbContextFactory : IDesignTimeDbContextFactory<TunnelDbContext>
{
    public TunnelDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<TunnelDbContext>()
            .UseSqlite("Data Source=:memory:")
            .Options;
        return new TunnelDbContext(options);
    }
}
