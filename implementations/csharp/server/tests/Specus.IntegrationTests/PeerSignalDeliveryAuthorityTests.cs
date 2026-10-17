using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Management;
using Specus.Server.PeerMesh;
using Specus.Server.Sessions;
using Specus.Server.ControlChannel;

namespace Specus.IntegrationTests;

public sealed class PeerSignalDeliveryAuthorityTests
{
    [Theory]
    [InlineData(false, "other-credential")]
    [InlineData(false, "receiver-credential")]
    [InlineData(false, "source-physical")]
    [InlineData(false, "receiver-owner")]
    [InlineData(false, "receiver-owner-retained-acl")]
    [InlineData(false, "target-device")]
    [InlineData(false, "target-key")]
    [InlineData(true, "other-credential")]
    [InlineData(true, "receiver-credential")]
    [InlineData(true, "receiver-owner")]
    [InlineData(true, "receiver-owner-retained-acl")]
    [InlineData(true, "target-device")]
    [InlineData(true, "target-key")]
    public async Task SignalAndGrantRecheckOriginalPeersAtTheActualWireTurn(bool grantQueued, string mutation)
    {
        await using var fixture = await PeerCatalogDeliveryAuthorityTests.CatalogFixture.StartAsync();
        var registry = fixture.Server.HostServices.GetRequiredService<SessionRegistry>();
        var source = grantQueued ? registry.Find("laptop")! : fixture.Publisher;
        var target = grantQueued ? fixture.Publisher : registry.Find("laptop")!;
        long[] existing;
        await using (var read = fixture.Server.HostServices.CreateAsyncScope())
        {
            var db = read.ServiceProvider.GetRequiredService<SpecusDbContext>();
            // Distinguish implicit same-owner access from an explicit ACL retained by
            // the management-only transfer contract. Never silently revoke that ACL.
            if (mutation != "receiver-owner-retained-acl")
            {
                db.PeerMeshAcls.RemoveRange(await db.PeerMeshAcls.Where(a => a.TenantId == "default"
                    && ((a.SourceClientId == 1001 && a.TargetClientId == 1002)
                        || (a.SourceClientId == 1002 && a.TargetClientId == 1001))).ToListAsync());
                await db.SaveChangesAsync();
            }
            existing = await db.PeerMeshSessions.Select(s => s.Id).ToArrayAsync();
        }
        var firstPacket = new MessageResponsePacket { Message = "holds-peer-signal-writer" };
        var first = fixture.Pair.Connection.WriteAsync(firstPacket).AsTask();
        await fixture.Pair.Stream.HalfWritten.WaitAsync(TimeSpan.FromSeconds(10));
        fixture.Observer.OwnCall.Value = true;
        var pending = fixture.Server.HostServices.GetRequiredService<IControlChannelDispatcher>().DispatchAsync(source,
            new MessageRequestPacket { MessageType = MessageType.PeerControl, ToClientName = target.ClientName,
                Message = "{\"type\":\"candidates\",\"candidates\":[]}" });
        fixture.Observer.OwnCall.Value = false;
        try
        {
            await Task.WhenAny(pending, fixture.Observer.Entered.Task).WaitAsync(TimeSpan.FromSeconds(10));
            if (!fixture.Observer.Entered.Task.IsCompleted) { await pending; Assert.Fail("actual peer signal writer was not reached"); }
            Assert.False(pending.IsCompleted);
            await using (var change = fixture.Server.HostServices.CreateAsyncScope())
            {
                var db = change.ServiceProvider.GetRequiredService<SpecusDbContext>();
                switch (mutation)
                {
                    case "other-credential": (await db.ClientCredentials.SingleAsync(c => c.Id == 502)).Enabled = false; break;
                    case "receiver-credential": (await db.ClientCredentials.SingleAsync(c => c.Id == 501)).Enabled = false; break;
                    case "target-device": (await db.PeerMeshDevices.SingleAsync(d => d.ClientId == target.ClientId)).Enabled = false; break;
                    case "target-key":
                        var device = await db.PeerMeshDevices.SingleAsync(d => d.ClientId == target.ClientId);
                        device.PublicKey = "current-wire-key"; break;
                    case "receiver-owner":
                    case "receiver-owner-retained-acl":
                        var actor = await OwnerTransferWriterProof.ActorAsync(fixture.Server, change.ServiceProvider);
                        var preview = await change.ServiceProvider.GetRequiredService<ClientOwnerTransferService>().PreviewClientAsync(actor.Context, "1001", CancellationToken.None);
                        await change.ServiceProvider.GetRequiredService<ClientOwnerTransferWriter>().CommitAsync(actor,
                            ClientOwnerTransferPlan.PathScope.Single, "1001", OwnerTransferWriterProof.Body(ClientOwnerTransferPlan.PathScope.Single, "bob", preview.Revision!), CancellationToken.None);
                        break;
                    case "source-physical":
                        var replacement = PeerCatalogDeliveryAuthorityTests.NewContext("new-signal-source", new PeerControlDeliveryAuthorityTests.RecordingWriter());
                        (await db.ClientSessions.SingleAsync(s => s.Id == source.ClientSessionId)).ChannelId = replacement.ChannelId;
                        var store = change.ServiceProvider.GetRequiredService<ClientAuthSessionStore>();
                        Assert.True(store.MarkOnline(store.FindById(source.ClientSessionId)!, replacement.ChannelId, "127.0.0.1"));
                        replacement.OnLoginSuccess(source.ClientName!, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), source.ClientSessionId,
                            tenantId: "default", clientId: source.ClientId);
                        registry.Replace(source.ClientName!, replacement); break;
                }
                await db.SaveChangesAsync();
            }
            fixture.Pair.Stream.Release(); await first.WaitAsync(TimeSpan.FromSeconds(10)); await pending.WaitAsync(TimeSpan.FromSeconds(10));
            var prefix = PacketCodec.Encode(firstPacket).Length; var bytes = fixture.Pair.Stream.Wire();
            await using var verify = fixture.Server.HostServices.CreateAsyncScope();
            var session = await verify.ServiceProvider.GetRequiredService<SpecusDbContext>().PeerMeshSessions.AsNoTracking()
                .SingleAsync(s => !existing.Contains(s.Id));
            if (mutation is "target-key" or "receiver-owner-retained-acl")
            {
                var packet = Assert.IsType<MessageResponsePacket>(PacketCodec.DecodeExact(bytes.AsSpan(prefix)));
                var signal = JsonSerializer.Deserialize<PeerControlMessage>(packet.Message!)!;
                Assert.Equal(grantQueued ? "session-grant" : "candidates", signal.Type);
                if (mutation == "target-key") Assert.Equal("current-wire-key", signal.TargetPublicKey);
                Assert.Equal(session.Id, signal.SessionId);
                Assert.Equal(grantQueued ? "server" : source.ClientName, packet.ClientName);
                Assert.Equal(PeerMeshService.StatusNegotiating, session.Status);
            }
            else
            {
                Assert.Equal(prefix, bytes.Length);
                Assert.Equal(PeerMeshService.StatusClosed, session.Status);
                Assert.NotNull(session.ClosedAt);
                if (grantQueued) Assert.Empty(((PeerControlDeliveryAuthorityTests.RecordingWriter)fixture.Publisher.Writer).Messages);
            }
        }
        finally { fixture.Pair.Stream.Release(); try { await first; } catch (Exception) { } try { await pending; } catch (Exception) { } }
    }
}
