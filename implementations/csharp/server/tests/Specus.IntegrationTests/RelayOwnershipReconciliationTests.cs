using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.PeerMesh;

namespace Specus.IntegrationTests;

public sealed class RelayOwnershipReconciliationTests
{
    [Fact]
    public async Task IndependentScopeCloseInvalidatesAlreadyWarmedRelayAuthorization()
    {
        await using var server = await ClientOwnerTransferWriterTests.StartAsync();
        await using var first = server.HostServices.CreateAsyncScope();
        await using var second = server.HostServices.CreateAsyncScope();
        var db = first.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await ClientOwnerTransferWriterTests.SeedAsync(db, "unique");
        db.PeerMeshSessions.Add(new PeerMeshSession { Id = 89001, TenantId = "tenant-a", SourceClientId = 1001, TargetClientId = 1002,
            SourceClientName = "laptop", TargetClientName = "offline", Status = PeerMeshService.StatusActive,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1), StartedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow });
        await db.SaveChangesAsync();
        var service = first.ServiceProvider.GetRequiredService<PeerMeshService>();
        var header = new PeerDataFrameHeader(89001, 1);
        Assert.True(await service.ValidateRelayFrameAsync(header, 1001, 1002, CancellationToken.None));
        await second.ServiceProvider.GetRequiredService<PeerMeshService>().CloseOpenSessionsAsync(
            new ManagementContext("tenant-a", "admin", ManagementRole.Admin, true), CancellationToken.None);
        Assert.False(await service.ValidateRelayFrameAsync(header, 1001, 1002, CancellationToken.None));
    }
}
