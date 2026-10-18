using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.PeerMesh;

namespace Specus.IntegrationTests;

public sealed class PeerInboundReportAuthorityTests
{
    private const long PeerSessionId = 991001;
    public static IEnumerable<object[]> InvalidReports()
    {
        foreach (var kind in new[] { "device", "path", "traffic", "close", "egress" })
        foreach (var mutation in new[] { "credential", "client", "identity", "channel", "expiry" })
            yield return [kind, mutation];
        yield return ["device", "missing-device"];
        yield return ["path", "access"];
        yield return ["traffic", "access"];
    }

    [Theory]
    [MemberData(nameof(InvalidReports))]
    public async Task OriginalControlReportCannotWriteAfterItsCurrentAuthorityIsRemoved(string kind, string mutation)
    {
        await using var fixture = await PeerCatalogDeliveryAuthorityTests.CatalogFixture.StartAsync();
        fixture.Pair.Stream.Release();
        await SeedAsync(fixture);
        await using (var change = fixture.Server.HostServices.CreateAsyncScope())
        {
            var db = change.ServiceProvider.GetRequiredService<SpecusDbContext>();
            switch (mutation)
            {
                case "credential": (await db.ClientCredentials.SingleAsync(c => c.Id == 502)).Enabled = false; break;
                case "client": (await db.ClientAccounts.SingleAsync(c => c.Id == 1002)).Enabled = false; break;
                case "identity": db.ClientIdentities.Remove(await db.ClientIdentities.SingleAsync(i => i.Id == 702)); break;
                case "channel": (await db.ClientSessions.SingleAsync(s => s.Id == fixture.Publisher.ClientSessionId)).ChannelId = "other-node-control"; break;
                case "expiry": (await db.ClientSessions.SingleAsync(s => s.Id == fixture.Publisher.ClientSessionId)).ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1); break;
                case "missing-device": db.PeerMeshDevices.Remove(await db.PeerMeshDevices.SingleAsync(d => d.ClientId == 1002)); break;
                case "access":
                    (await db.ClientAccounts.SingleAsync(c => c.Id == 1001)).OwnerUsername = "bob";
                    db.PeerMeshAcls.RemoveRange(await db.PeerMeshAcls.Where(a => a.TenantId == "default").ToListAsync()); break;
            }
            await db.SaveChangesAsync();
        }
        var before = await SnapshotAsync(fixture);
        var dispatcher = fixture.Server.HostServices.GetRequiredService<IControlChannelDispatcher>();
        var error = await Record.ExceptionAsync(() => dispatcher.DispatchAsync(fixture.Publisher, Request(kind)));
        Assert.True(error is null or ArgumentException or PeerSignalUndeliverableException, error?.ToString());
        Assert.Equal(before, await SnapshotAsync(fixture));
        Assert.False(fixture.Server.HostServices.GetRequiredService<PeerMeshServiceState>().EgressReportWindows.ContainsKey(fixture.Publisher.ClientSessionId!.Value));
    }

    [Theory]
    [InlineData("path")]
    [InlineData("traffic")]
    [InlineData("close")]
    public async Task TrackedPreCloseSnapshotCannotRewriteHistoricalPeerSession(string kind)
    {
        await using var fixture = await PeerCatalogDeliveryAuthorityTests.CatalogFixture.StartAsync();
        fixture.Pair.Stream.Release(); await SeedAsync(fixture);
        await using var scope = fixture.Server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        Assert.Equal(PeerMeshService.StatusActive, (await db.PeerMeshSessions.SingleAsync(s => s.Id == PeerSessionId)).Status);
        await using (var close = fixture.Server.HostServices.CreateAsyncScope())
        {
            var current = close.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var row = await current.PeerMeshSessions.SingleAsync(s => s.Id == PeerSessionId);
            row.Status = PeerMeshService.StatusClosed; row.ClosedAt = DateTimeOffset.UtcNow.AddHours(-1); row.UpdatedAt = row.ClosedAt.Value;
            row.DirectBytes = 71; row.RelayBytes = 89; await current.SaveChangesAsync();
        }
        var before = await SnapshotAsync(fixture);
        await scope.ServiceProvider.GetRequiredService<PeerMeshService>().HandleSignalAsync(Request(kind), fixture.Publisher.ClientName!,
            CancellationToken.None, fixture.Publisher.ClientSessionId, fixture.Publisher);
        Assert.Equal(before, await SnapshotAsync(fixture));
        Assert.Null(db.Database.CurrentTransaction);
    }

    internal static MessageRequestPacket Request(string kind)
    {
        var values = new Dictionary<string, object?> { ["type"] = kind + "-report" };
        switch (kind)
        {
            case "device": values["virtualDeviceError"] = "new-report"; values["natType"] = "RESTRICTED_CONE"; break;
            case "path": values["sessionId"] = PeerSessionId; values["status"] = "ACTIVE"; values["rttMillis"] = 17; break;
            case "traffic": values["sessionId"] = PeerSessionId; values["directBytes"] = 99; values["relayBytes"] = 17; break;
            case "close": values["type"] = "close"; values["sessionId"] = PeerSessionId; break;
            case "egress": values["revision"] = 1; values["activeFlows"] = 9; values["bytesIn"] = 77; break;
        }
        return new MessageRequestPacket { MessageType = MessageType.PeerControl, Message = JsonSerializer.Serialize(values) };
    }

    private static async Task SeedAsync(PeerCatalogDeliveryAuthorityTests.CatalogFixture fixture)
    {
        await using var scope = fixture.Server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var now = DateTimeOffset.UtcNow.AddMinutes(-1);
        (await db.ClientSessions.SingleAsync(s => s.Id == fixture.Publisher.ClientSessionId)).ClientEgressVersion = 1;
        db.PeerMeshSessions.Add(new PeerMeshSession { Id = PeerSessionId, TenantId = "default", SourceClientId = 1002,
            SourceClientName = "offline", TargetClientId = 1001, TargetClientName = "laptop", Status = PeerMeshService.StatusActive,
            PathType = PeerMeshService.PathDirect, TokenHash = "report-fixture-token", StartedAt = now, UpdatedAt = now, ExpiresAt = now.AddHours(1) });
        db.PeerMeshEgressActivities.Add(new PeerMeshEgressActivity { Id = 991002, TenantId = "default", EgressClientId = 1002,
            EgressClientName = "offline", SessionId = fixture.Publisher.ClientSessionId!.Value, Revision = 0, ActiveFlows = 1,
            BytesIn = 1, BytesOut = 2, RejectedFlows = "{}", CreatedAt = now, UpdatedAt = now, ReportedAt = now });
        await db.SaveChangesAsync();
    }

    private static async Task<string> SnapshotAsync(PeerCatalogDeliveryAuthorityTests.CatalogFixture fixture)
    {
        await using var scope = fixture.Server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        return JsonSerializer.Serialize(new
        {
            Device = await db.PeerMeshDevices.AsNoTracking().SingleOrDefaultAsync(d => d.ClientId == 1002),
            Session = await db.PeerMeshSessions.AsNoTracking().SingleAsync(s => s.Id == PeerSessionId),
            Activity = await db.PeerMeshEgressActivities.AsNoTracking().SingleAsync(a => a.EgressClientId == 1002),
        });
    }
}
