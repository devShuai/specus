using Microsoft.EntityFrameworkCore;
using Specus.Server.Data;

namespace Specus.IntegrationTests;

public sealed class ManagementPasswordStorageTests
{
    [Fact]
    public async Task SqliteManagementPasswordHashesUpgradeWithoutTruncationOrUnsafeDowngrade()
    {
        await using var db = new SpecusDbContext(new DbContextOptionsBuilder<SpecusDbContext>().UseSqlite("Data Source=:memory:").Options);
        await db.Database.OpenConnectionAsync();
        await OwnerTransferWriterProof.VerifyPasswordHashUpgradeAsync(db);
    }
}
