using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.PeerMesh;

namespace Specus.IntegrationTests;

public sealed class RelayOwnershipRaceTests
{
    [Fact]
    public async Task ProbeDoesNotReadAnOldTrackedSessionAfterIndependentClose()
    {
        await using var server = await ClientOwnerTransferWriterTests.StartAsync();
        await using var first = server.HostServices.CreateAsyncScope();
        var db = first.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await SeedAsync(db, PeerMeshService.StatusActive);
        var relay = first.ServiceProvider.GetRequiredService<PeerMeshService>();
        Assert.True(await relay.AuthorizeRelayProbeAsync(89101, 1001, 1002, "probe-fixture", "check", CancellationToken.None));
        await using (var other = server.HostServices.CreateAsyncScope())
            await other.ServiceProvider.GetRequiredService<SpecusDbContext>().PeerMeshSessions.Where(s => s.Id == 89101)
                .ExecuteUpdateAsync(s => s.SetProperty(s => s.Status, PeerMeshService.StatusClosed));
        Assert.False(await relay.AuthorizeRelayProbeAsync(89101, 1001, 1002, "probe-fixture", "check", CancellationToken.None));
    }

    [Fact]
    public async Task DelayedActivationCannotResurrectAClosedSession()
    {
        var gate = new ActivationGate();
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?> { ["Specus:Auth:TenantId"] = "tenant-a", ["Specus:Database:SeedDemoClient"] = "false" },
            services => services.AddDbContext<SpecusDbContext>((_, options) => options.AddInterceptors(gate)));
        await using var first = server.HostServices.CreateAsyncScope();
        var db = first.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await SeedAsync(db, PeerMeshService.StatusNegotiating);
        gate.BeforeActivation = async () =>
        {
            await using var other = server.HostServices.CreateAsyncScope();
            await other.ServiceProvider.GetRequiredService<SpecusDbContext>().PeerMeshSessions.Where(s => s.Id == 89101)
                .ExecuteUpdateAsync(s => s.SetProperty(s => s.Status, PeerMeshService.StatusClosed));
        };
        var allowed = await first.ServiceProvider.GetRequiredService<PeerMeshService>().ValidateRelayFrameAsync(new PeerDataFrameHeader(89101, 1), 1001, 1002, CancellationToken.None);
        Assert.Equal(1, gate.Entered);
        Assert.False(allowed);
        Assert.Equal(PeerMeshService.StatusClosed, (await db.PeerMeshSessions.AsNoTracking().SingleAsync(s => s.Id == 89101)).Status);
    }

    private static async Task SeedAsync(SpecusDbContext db, string status)
    {
        await ClientOwnerTransferWriterTests.SeedAsync(db, "unique");
        db.PeerMeshSessions.Add(new PeerMeshSession { Id = 89101, TenantId = "tenant-a", SourceClientId = 1001, TargetClientId = 1002,
            SourceClientName = "laptop", TargetClientName = "offline", Status = status, ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            TokenHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("probe-fixture"))) });
        await db.SaveChangesAsync();
    }

    private sealed class ActivationGate : DbCommandInterceptor
    {
        internal Func<Task>? BeforeActivation;
        internal int Entered;
        public override async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<int> result, CancellationToken ct = default)
        {
            if (command.CommandText.StartsWith("UPDATE peer_mesh_session SET status=", StringComparison.Ordinal)
                && command.CommandText.Contains("last_keepalive_at", StringComparison.Ordinal) && BeforeActivation is { } callback)
            {
                BeforeActivation = null; Entered++;
                await callback();
            }
            return result;
        }
    }
}
