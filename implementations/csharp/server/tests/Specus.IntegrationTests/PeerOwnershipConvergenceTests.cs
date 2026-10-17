using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.PeerMesh;

namespace Specus.IntegrationTests;

public sealed class PeerOwnershipConvergenceTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task PublicTransferSelectivelyClosesImplicitAccessAndReplaysPreclosedRows(bool explicitAcl, bool preclosed)
    {
        await using var server = await ClientOwnerTransferWriterTests.StartAsync();
        await using var first = server.HostServices.CreateAsyncScope();
        var db = first.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await ClientOwnerTransferWriterTests.SeedAsync(db, "unique");
        await db.ClientAccounts.Where(c => c.Id == 1002).ExecuteUpdateAsync(s => s.SetProperty(c => c.Enabled, true).SetProperty(c => c.OwnerUsername, "alice"));
        db.PeerMeshDevices.Add(new PeerMeshDevice { Id = 802, ClientId = 1002, TenantId = "tenant-a", ClientName = "offline", OwnerUsername = "alice", Enabled = true, VirtualIp = "10.66.0.12", Cidr = "10.66.0.0/16" });
        var now = DateTimeOffset.UtcNow;
        db.PeerMeshSessions.Add(new PeerMeshSession { Id = 89002, TenantId = "tenant-a", SourceClientId = 1001, TargetClientId = 1002,
            SourceClientName = "laptop", TargetClientName = "offline", Status = PeerMeshService.StatusActive, ExpiresAt = now.AddHours(1), StartedAt = now, UpdatedAt = now });
        if (explicitAcl) db.PeerMeshAcls.Add(new PeerMeshAcl { Id = 89003, TenantId = "tenant-a", SourceClientId = 1001, TargetClientId = 1002,
            SourceClientName = "laptop", TargetClientName = "offline", Allowed = true, Direction = PeerMeshService.DirectionOutbound });
        await db.SaveChangesAsync();
        var relay = first.ServiceProvider.GetRequiredService<PeerMeshService>();
        var header = new PeerDataFrameHeader(89002, 1);
        Assert.True(await relay.ValidateRelayFrameAsync(header, 1001, 1002, CancellationToken.None));
        if (preclosed) await db.PeerMeshSessions.Where(s => s.Id == 89002).ExecuteUpdateAsync(s => s.SetProperty(s => s.Status, PeerMeshService.StatusClosed).SetProperty(s => s.ClosedAt, now));
        using var http = await OwnerTransferPostContractTests.AdminAsync(server);
        var preview = (await http.GetFromJsonAsync<ClientOwnerTransferPreview>("/api/admin/clients/1001/owner-transfer"))!;
        using var response = await http.PostAsJsonAsync("/api/admin/clients/1001/owner-transfer", new { scope = "single", targetUsername = "bob", expectedRevision = preview.Revision });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await using var second = server.HostServices.CreateAsyncScope();
        await second.ServiceProvider.GetRequiredService<PeerMeshService>().ReconcileOwnershipAsync("tenant-a", new long[] { 1001 }, CancellationToken.None);
        var closed = preclosed || !explicitAcl;
        Assert.Equal(closed ? PeerMeshService.StatusClosed : PeerMeshService.StatusActive,
            (await db.PeerMeshSessions.AsNoTracking().SingleAsync(s => s.Id == 89002)).Status);
        Assert.Equal(!closed, await relay.ValidateRelayFrameAsync(header, 1001, 1002, CancellationToken.None));
        if (explicitAcl) Assert.True((await db.PeerMeshAcls.AsNoTracking().SingleAsync()).Allowed);
        Assert.Equal(2, await db.PeerMeshDevices.CountAsync());
        Assert.Equal("retained-password", (await db.ClientAccounts.AsNoTracking().SingleAsync(c => c.Id == 1001)).PasswordHash);
    }
}
