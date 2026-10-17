using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.PeerMesh;

namespace Specus.IntegrationTests;

public sealed class RelayOwnershipGenerationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InvalidationDuringSnapshotRechecksCurrentStateWithoutDroppingAuthorizedFrame(bool close)
    {
        var gate = new SnapshotGate();
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?> {
            ["Specus:Auth:TenantId"] = "tenant-a", ["Specus:Database:SeedDemoClient"] = "false" },
            services => services.AddDbContext<SpecusDbContext>((_, options) => options.AddInterceptors(gate)));
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await ClientOwnerTransferWriterTests.SeedAsync(db, "unique");
        await db.ClientAccounts.Where(c => c.Id == 1002).ExecuteUpdateAsync(s => s.SetProperty(c => c.Enabled, true));
        db.PeerMeshAcls.Add(new PeerMeshAcl { Id = 89603, TenantId = "tenant-a", SourceClientId = 1001, TargetClientId = 1002,
            SourceClientName = "laptop", TargetClientName = "offline", Allowed = true, Direction = PeerMeshService.DirectionOutbound });
        db.PeerMeshSessions.Add(new PeerMeshSession { Id = 89601, TenantId = "tenant-a", SourceClientId = 1001, TargetClientId = 1002,
            SourceClientName = "laptop", TargetClientName = "offline", Status = PeerMeshService.StatusActive,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1) });
        await db.SaveChangesAsync();
        var state = server.HostServices.GetRequiredService<PeerMeshServiceState>();
        gate.BeforeSnapshot = async () =>
        {
            state.InvalidateRelayAuthorizations();
            if (close)
            {
                await using var other = server.HostServices.CreateAsyncScope();
                await other.ServiceProvider.GetRequiredService<SpecusDbContext>().PeerMeshSessions.Where(s => s.Id == 89601)
                    .ExecuteUpdateAsync(s => s.SetProperty(s => s.Status, PeerMeshService.StatusClosed));
            }
        };
        var allowed = await scope.ServiceProvider.GetRequiredService<PeerMeshService>().AuthorizeRelayFrameAsync(
            new PeerDataFrameHeader(89601, 1), 1001, 1002, 17, CancellationToken.None);
        Assert.Equal(1, gate.Entered);
        Assert.Equal(!close, allowed);
        Assert.Equal(close ? 0 : 17, state.PendingRelayBytes.GetValueOrDefault(89601));
        Assert.Equal(close ? PeerMeshService.StatusClosed : PeerMeshService.StatusActive,
            (await db.PeerMeshSessions.AsNoTracking().SingleAsync(s => s.Id == 89601)).Status);
    }

    private sealed class SnapshotGate : DbCommandInterceptor
    {
        internal Func<Task>? BeforeSnapshot;
        internal int Entered;
        public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken ct = default)
        {
            if (command.CommandText.Contains("FROM \"peer_mesh_session\"", StringComparison.Ordinal)
                && BeforeSnapshot is { } callback)
            {
                BeforeSnapshot = null; Entered++; await callback();
            }
            return result;
        }
    }
}
