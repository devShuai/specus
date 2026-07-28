using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

public sealed class TrafficInspectionServiceTests
{
    [Fact]
    public async Task HttpDetailCaptureQueuesAndFlushesLikeJava()
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:Traffic:CaptureDetailEnabled"] = "true",
            ["Specus:Traffic:CaptureFlushIntervalMs"] = "3600000",
            ["Specus:Traffic:CaptureMaxPending"] = "100",
            ["Specus:Traffic:CaptureFlushBatchSize"] = "50",
        });

        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var account = await db.ClientAccounts.AsNoTracking()
                .SingleAsync(c => c.ClientName == DatabaseInitializer.DemoClientName);
            var now = DateTimeOffset.UtcNow;
            db.HttpRouteMappings.Add(new HttpRouteMapping
            {
                Id = ClientIdGenerator.NewId(),
                ClientId = account.Id,
                ClientName = account.ClientName,
                Route = "queued",
                TargetBaseUrl = "http://127.0.0.1:8080",
                Enabled = true,
                DetailCaptureEnabled = true,
                PathRewriteEnabled = false,
                CreatedAt = now,
                UpdatedAt = now,
            });
            await db.SaveChangesAsync();
        }

        var inspection = server.HostServices.GetRequiredService<TrafficInspectionService>();
        await inspection.RecordHttpExchangeAsync(new HttpExchangeCapture(
            DatabaseInitializer.DemoClientName,
            "queued",
            "GET",
            "/health",
            "ok=true",
            ["Accept: application/json"],
            null,
            200,
            ["Content-Type: application/json"],
            Encoding.UTF8.GetBytes("""{"ok":true}"""),
            DateTimeOffset.UtcNow.AddMilliseconds(-7),
            "127.0.0.1:61000",
            null),
            CancellationToken.None);

        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            Assert.Equal(0, await db.HttpTrafficExchanges.CountAsync(e => e.Route == "queued"));
        }

        await inspection.FlushAsync();

        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var row = await db.HttpTrafficExchanges.SingleAsync(e => e.Route == "queued");
            Assert.Equal(DatabaseInitializer.DemoClientName, row.ClientName);
            Assert.Equal("GET", row.Method);
            Assert.Equal("json", row.ResponseBodyType);
            Assert.Equal("""{"ok":true}""", row.ResponsePreviewText);
            Assert.True(row.ElapsedMs >= 0);
        }
    }
}
