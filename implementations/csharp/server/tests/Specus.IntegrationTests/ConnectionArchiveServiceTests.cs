using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;

namespace Specus.IntegrationTests;

public sealed class ConnectionArchiveServiceTests
{
    [Fact]
    public void CalculateCutoffUsesUtcDayBoundary()
    {
        var now = new DateTimeOffset(2026, 6, 25, 15, 30, 12, TimeSpan.FromHours(8));

        var cutoff = ConnectionArchiveService.CalculateCutoff(now, 60);

        Assert.Equal(new DateTimeOffset(2026, 4, 26, 0, 0, 0, TimeSpan.Zero), cutoff);
    }

    [Fact]
    public async Task ArchiveAsyncAggregatesOldDetailsByTenantClientAndMonth()
    {
        await using var fixture = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:ConnectionRecord:DetailRetentionDays"] = "60",
            ["Specus:ConnectionRecord:ArchiveIntervalMs"] = "3600000",
        });

        var cutoff = ConnectionArchiveService.CalculateCutoff(DateTimeOffset.UtcNow, 60);
        var old = cutoff.AddMonths(-1).AddHours(12);
        var fresh = cutoff.AddDays(10);
        const string tenantId = "archive-tenant";
        const string clientName = "archive-client";
        const long clientId = 998877;

        await using (var scope = fixture.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            db.ConnectionRecords.AddRange(
                new ConnectionRecord
                {
                    TenantId = tenantId,
                    ClientId = clientId,
                    ClientName = clientName,
                    ConnectedAt = old,
                    Success = true,
                },
                new ConnectionRecord
                {
                    TenantId = tenantId,
                    ClientId = clientId,
                    ClientName = clientName,
                    ConnectedAt = old.AddHours(1),
                    Success = false,
                },
                new ConnectionRecord
                {
                    TenantId = tenantId,
                    ClientId = clientId,
                    ClientName = clientName,
                    ConnectedAt = fresh,
                    Success = true,
                });
            await db.SaveChangesAsync();
        }

        var service = fixture.HostServices.GetRequiredService<ConnectionArchiveService>();
        var archived = await service.ArchiveAsync();

        Assert.Equal(2, archived);

        await using (var scope = fixture.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var remaining = await db.ConnectionRecords.AsNoTracking()
                .Where(r => r.TenantId == tenantId && r.ClientName == clientName)
                .ToListAsync();
            Assert.Single(remaining);
            Assert.Equal(fresh, remaining[0].ConnectedAt);

            var statMonth = old.ToUniversalTime().ToString("yyyy-MM", CultureInfo.InvariantCulture);
            var stat = await db.ConnectionStats.AsNoTracking()
                .SingleAsync(s =>
                    s.TenantId == tenantId
                    && s.ClientName == clientName
                    && s.StatMonth == statMonth);
            Assert.Equal(clientId, stat.ClientId);
            Assert.Equal(2, stat.TotalCount);
            Assert.Equal(1, stat.SuccessCount);
            Assert.Equal(1, stat.FailureCount);
        }
    }
}
