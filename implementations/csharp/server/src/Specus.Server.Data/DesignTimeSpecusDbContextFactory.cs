using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Specus.Server.Data;

/// <summary>
/// Lets <c>dotnet ef</c> tooling instantiate <see cref="SpecusDbContext"/> without booting the
/// full server. The connection string here is throwaway — migrations are SQL-text-only and don't
/// touch the configured DB. Production wires real options through DI in <c>Program.cs</c>.
/// </summary>
public sealed class DesignTimeSpecusDbContextFactory : IDesignTimeDbContextFactory<SpecusDbContext>
{
    public SpecusDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<SpecusDbContext>()
            .UseSqlite("Data Source=:memory:")
            .Options;
        return new SpecusDbContext(options);
    }
}
