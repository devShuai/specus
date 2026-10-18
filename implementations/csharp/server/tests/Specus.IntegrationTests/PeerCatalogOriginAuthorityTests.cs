using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.PeerMesh;
using Specus.Server.Sessions;

namespace Specus.IntegrationTests;

public sealed class PeerCatalogOriginAuthorityTests
{
    internal static MessageRequestPacket Report() => new() { MessageType = MessageType.PeerControl,
        Message = "{\"type\":\"service-report\",\"enabled\":true,\"revision\":1,\"instanceId\":\"origin-fixture\",\"services\":[{\"serviceId\":\"catalog-service\"}]}" };

    [Theory]
    [InlineData("credential")]
    [InlineData("physical")]
    [InlineData("client")]
    public async Task PublisherInvalidatedDuringCatalogGateWaitCannotConsumeRevision(string mutation)
    {
        await using var fixture = await PeerCatalogDeliveryAuthorityTests.CatalogFixture.StartAsync();
        fixture.Pair.Stream.Release();
        await using var sourceScope = fixture.Server.HostServices.CreateAsyncScope();
        var db = sourceScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var source = await db.ClientAccounts.AsNoTracking().SingleAsync(a => a.Id == 1002);
        var state = fixture.Server.HostServices.GetRequiredService<PeerMeshServiceState>();
        var key = (TenantId: "default", ClientId: 1002L, SessionId: fixture.Publisher.ClientSessionId!.Value);
        var gate = state.ServiceCatalogMutationGates.GetOrAdd(key, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync();
        var report = JsonSerializer.Deserialize<PeerControlMessage>(Report().Message!)!;
        var pending = sourceScope.ServiceProvider.GetRequiredService<PeerMeshService>()
            .HandleServiceReportAsync(source, report, key.SessionId, CancellationToken.None);
        try
        {
            Assert.False(pending.IsCompleted);
            await using var change = fixture.Server.HostServices.CreateAsyncScope();
            var current = change.ServiceProvider.GetRequiredService<SpecusDbContext>();
            if (mutation == "credential") (await current.ClientCredentials.SingleAsync(c => c.Id == 502)).Enabled = false;
            else if (mutation == "client") (await current.ClientAccounts.SingleAsync(c => c.Id == 1002)).Enabled = false;
            else
            {
                var replacement = PeerCatalogDeliveryAuthorityTests.NewContext("new-origin", new PeerControlDeliveryAuthorityTests.RecordingWriter());
                (await current.ClientSessions.SingleAsync(s => s.Id == key.SessionId)).ChannelId = replacement.ChannelId;
                var store = change.ServiceProvider.GetRequiredService<ClientAuthSessionStore>();
                Assert.True(store.MarkOnline(store.FindById(key.SessionId)!, replacement.ChannelId, "127.0.0.1"));
                replacement.OnLoginSuccess(source.ClientName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), key.SessionId, tenantId: "default", clientId: 1002);
                fixture.Server.HostServices.GetRequiredService<SessionRegistry>().Replace(source.ClientName, replacement);
            }
            await current.SaveChangesAsync(); gate.Release();
            await Assert.ThrowsAsync<ArgumentException>(() => pending.WaitAsync(TimeSpan.FromSeconds(10)));
            Assert.False(state.ServiceCatalogs.ContainsKey(key));
            Assert.False(state.ServiceReportRevisions.ContainsKey(key));
            Assert.False(state.ServiceCatalogRevisions.ContainsKey(key));
            Assert.False(state.ServiceReportWindows.ContainsKey(key.SessionId));
            Assert.Empty(fixture.Pair.Stream.Wire());
        }
        finally { if (gate.CurrentCount == 0) gate.Release(); try { await pending; } catch (Exception) { } }
    }

    [Theory]
    [InlineData("missing-origin")]
    [InlineData("publisher-credential")]
    [InlineData("sharing")]
    [InlineData("definition-port")]
    [InlineData("receiver-credential")]
    public async Task LoginResyncUsesCurrentCatalogAuthorityInsteadOfSavedPublicFields(string mutation)
    {
        await using var fixture = await PeerCatalogDeliveryAuthorityTests.CatalogFixture.StartAsync();
        fixture.Pair.Stream.Release();
        await fixture.Server.HostServices.GetRequiredService<Specus.Server.ControlChannel.IControlChannelDispatcher>()
            .DispatchAsync(fixture.Publisher, Report());
        var prefix = fixture.Pair.Stream.Wire().Length;
        var state = fixture.Server.HostServices.GetRequiredService<PeerMeshServiceState>();
        var key = (TenantId: "default", ClientId: 1002L, SessionId: fixture.Publisher.ClientSessionId!.Value);
        await using var scope = fixture.Server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        switch (mutation)
        {
            case "missing-origin": state.ServiceCatalogs[key] = state.ServiceCatalogs[key] with { PublisherChannelId = null }; break;
            case "publisher-credential": (await db.ClientCredentials.SingleAsync(c => c.Id == 502)).Enabled = false; break;
            case "receiver-credential": (await db.ClientCredentials.SingleAsync(c => c.Id == 501)).Enabled = false; break;
            case "sharing": (await db.PeerMeshServiceSharings.SingleAsync()).Enabled = false; break;
            case "definition-port": (await db.PeerMeshSharedServices.SingleAsync(s => s.Id == 6501)).PublishedPort = 24003; break;
        }
        await db.SaveChangesAsync();
        var recipient = await db.ClientAccounts.AsNoTracking().SingleAsync(a => a.Id == 1001);
        var peer = scope.ServiceProvider.GetRequiredService<PeerMeshService>();
        var push = typeof(PeerMeshService).GetMethod("PushCurrentCatalogsAsync", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        await (Task)push.Invoke(peer, [recipient, CancellationToken.None])!;
        var bytes = fixture.Pair.Stream.Wire();
        if (mutation == "receiver-credential") { Assert.Equal(prefix, bytes.Length); return; }
        var packet = Assert.IsType<MessageResponsePacket>(PacketCodec.DecodeExact(bytes.AsSpan(prefix)));
        var catalog = JsonSerializer.Deserialize<PeerControlMessage>(packet.Message!)!;
        Assert.Equal(key.SessionId, catalog.PublisherSessionId);
        if (mutation == "definition-port") Assert.Equal(24003, Assert.Single(catalog.Services!).PublishedPort);
        else Assert.Empty(catalog.Services!);
    }
}
