using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Specus.Server.Data;

namespace Specus.IntegrationTests;

public sealed class TransferAttachmentExpiryTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task RealSqliteExpiresMultipleBatchesWithoutChangingLiveOrHistoricalRows(bool storageEnabled)
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new SpecusDbContext(new DbContextOptionsBuilder<SpecusDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync();
        await TransferAttachmentExpiryProof.VerifyBatchAsync(db, storageEnabled);
    }

    [Fact]
    public async Task ObjectDeleteFailureDoesNotClaimExpiryAndTheNextScanRetries()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new SpecusDbContext(new DbContextOptionsBuilder<SpecusDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync();
        await TransferAttachmentExpiryProof.VerifyDeleteFailureAsync(db);
    }
}
