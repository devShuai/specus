using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.PeerMesh;
using Specus.Server.Sessions;

namespace Specus.IntegrationTests;

public sealed class PeerCatalogDeliveryAuthorityTests
{
    [Theory]
    [InlineData("definition-disabled")]
    [InlineData("definition-port")]
    [InlineData("sharing-disabled")]
    [InlineData("peer-disabled")]
    [InlineData("receiver-credential-disabled")]
    [InlineData("publisher-credential-disabled")]
    [InlineData("publisher-physical-replaced")]
    [InlineData("receiver-owner-transferred")]
    public async Task QueuedCatalogUsesCurrentPublisherReceiverAndServiceAuthority(string mutation)
    {
        await using var fixture = await CatalogFixture.StartAsync();
        using var background = fixture.Observer.PauseBackgroundWrites();
        var firstPacket = new MessageResponsePacket { Message = "hold-catalog-writer" };
        var first = fixture.Pair.Connection.WriteAsync(firstPacket).AsTask();
        await fixture.Pair.Stream.HalfWritten.WaitAsync(TimeSpan.FromSeconds(10));
        var request = new MessageRequestPacket { MessageType = MessageType.PeerControl, Message = JsonSerializer.Serialize(new
        { type = "service-report", enabled = true, revision = 1, instanceId = "catalog-fixture", services = new[] { new { serviceId = "catalog-service" } } }) };
        fixture.Observer.OwnCall.Value = true;
        var pending = fixture.Server.HostServices.GetRequiredService<IControlChannelDispatcher>().DispatchAsync(fixture.Publisher, request);
        fixture.Observer.OwnCall.Value = false;
        try
        {
            await Task.WhenAny(pending, fixture.Observer.Entered.Task).WaitAsync(TimeSpan.FromSeconds(10));
            if (!fixture.Observer.Entered.Task.IsCompleted) { await pending; Assert.Fail("actual catalog writer was never reached"); }
            await fixture.Observer.Entered.Task; Assert.False(pending.IsCompleted);
            var state = fixture.Server.HostServices.GetRequiredService<PeerMeshServiceState>();
            Assert.Single(state.ServiceCatalogs[("default", 1002, fixture.Publisher.ClientSessionId!.Value)].Services);
            await using (var change = fixture.Server.HostServices.CreateAsyncScope())
            {
                var db = change.ServiceProvider.GetRequiredService<SpecusDbContext>();
                switch (mutation)
                {
                    case "definition-disabled": (await db.PeerMeshSharedServices.SingleAsync(s => s.Id == 6501)).Enabled = false; break;
                    case "definition-port": (await db.PeerMeshSharedServices.SingleAsync(s => s.Id == 6501)).PublishedPort = 24002; break;
                    case "sharing-disabled": (await db.PeerMeshServiceSharings.SingleAsync()).Enabled = false; break;
                    case "peer-disabled": (await db.PeerMeshDevices.SingleAsync(d => d.ClientId == 1001)).Enabled = false; break;
                    case "receiver-credential-disabled": (await db.ClientCredentials.SingleAsync(c => c.Id == 501)).Enabled = false; break;
                    case "publisher-credential-disabled": (await db.ClientCredentials.SingleAsync(c => c.Id == 502)).Enabled = false; break;
                    case "publisher-physical-replaced":
                        var replacement = NewContext("replacement-publisher", new PeerControlDeliveryAuthorityTests.RecordingWriter());
                        var row = await db.ClientSessions.SingleAsync(s => s.Id == fixture.Publisher.ClientSessionId);
                        row.ChannelId = replacement.ChannelId;
                        var store = change.ServiceProvider.GetRequiredService<ClientAuthSessionStore>();
                        Assert.True(store.MarkOnline(store.FindById(row.Id)!, replacement.ChannelId, "127.0.0.1"));
                        replacement.OnLoginSuccess("offline", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), row.Id, tenantId: "default", clientId: 1002);
                        fixture.Server.HostServices.GetRequiredService<SessionRegistry>().Replace("offline", replacement);
                        break;
                    case "receiver-owner-transferred":
                        var actor = await OwnerTransferWriterProof.ActorAsync(fixture.Server, change.ServiceProvider);
                        var preview = await change.ServiceProvider.GetRequiredService<ClientOwnerTransferService>().PreviewClientAsync(actor.Context, "1001", CancellationToken.None);
                        await change.ServiceProvider.GetRequiredService<ClientOwnerTransferWriter>().CommitAsync(actor, ClientOwnerTransferPlan.PathScope.Single, "1001",
                            OwnerTransferWriterProof.Body(ClientOwnerTransferPlan.PathScope.Single, "bob", preview.Revision!), CancellationToken.None);
                        break;
                }
                await db.SaveChangesAsync();
            }
            fixture.Pair.Stream.Release(); await first.WaitAsync(TimeSpan.FromSeconds(10)); await pending.WaitAsync(TimeSpan.FromSeconds(10));
            var bytes = fixture.Pair.Stream.Wire(); var prefix = PacketCodec.Encode(firstPacket).Length;
            if (mutation == "receiver-credential-disabled") { Assert.Equal(prefix, bytes.Length); return; }
            var packet = Assert.IsType<MessageResponsePacket>(PacketCodec.DecodeExact(bytes.AsSpan(prefix)));
            var catalog = JsonSerializer.Deserialize<PeerControlMessage>(packet.Message!)!;
            Assert.Equal("service-catalog", catalog.Type); Assert.Equal(fixture.Publisher.ClientSessionId, catalog.PublisherSessionId);
            if (mutation == "definition-port") Assert.Equal(24002, Assert.Single(catalog.Services!).PublishedPort);
            else Assert.Empty(catalog.Services!);
            background.Dispose();
            if (mutation == "receiver-owner-transferred") await AssertOwnershipBackgroundAsync(fixture, bytes.Length);
        }
        finally { fixture.Pair.Stream.Release(); try { await first; } catch (Exception) { } try { await pending; } catch (Exception) { } }
    }

    internal static async Task AssertOwnershipBackgroundAsync(CatalogFixture fixture, int afterBytes)
    {
        // The ownership poller is an independent producer on this physical stream.
        // Verify it after the original queued-message assertions, not instead of them.
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var node = fixture.Server.HostServices.GetRequiredService<OwnerTransferNotifications>().NodeId;
        await using var scope = fixture.Server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var audit = await db.ClientOwnerTransferAudits.AsNoTracking().SingleAsync(timeout.Token);
        while (!await db.ClientOwnerTransferReceipts.AsNoTracking().AnyAsync(r => r.NodeId == node && r.EventId == audit.Id, timeout.Token))
            await Task.Delay(20, timeout.Token);
        Assert.Equal("bob", (await db.ClientAccounts.AsNoTracking().SingleAsync(a => a.Id == 1001, timeout.Token)).OwnerUsername);
        var bytes = fixture.Pair.Stream.Wire();
        var frames = new List<PeerControlMessage>();
        while (afterBytes < bytes.Length)
        {
            Assert.True(PacketCodec.TryDecode(bytes.AsSpan(afterBytes), out var packet, out var consumed));
            var message = Assert.IsType<MessageResponsePacket>(packet);
            Assert.Equal("server", message.ClientName);
            var control = JsonSerializer.Deserialize<PeerControlMessage>(message.Message!)!;
            Assert.Contains(control.Type, new[] { "close", "peer-config", "roster", "egress-config", "egress-catalog", "service-catalog" });
            frames.Add(control); afterBytes += consumed;
        }
        Assert.Contains(frames, frame => frame.Type == "peer-config" && frame.SourceClientId == 1001 && frame.TargetClientId == 1001);
        Assert.Contains(frames, frame => frame.Type == "roster");
    }

    internal static SpecusConnectionContext NewContext(string channel, IFrameWriter writer) => new(channel, "127.0.0.1", writer,
        CancellationToken.None, () => { }, new Specus.Server.Networking.ReadGate(CancellationToken.None),
        new Specus.Server.Networking.WriteBackpressureGate(65536, 1048576));

    internal sealed class CatalogFixture(PeerControlDeliveryAuthorityTests.RuntimeFixture receiver,
        PeerQueuedDeliveryTests.BoundWriter pair, SpecusConnectionContext publisher, ObservingWriter observer) : IAsyncDisposable
    {
        internal TestServerFixture Server => receiver.Server;
        internal PeerQueuedDeliveryTests.BoundWriter Pair { get; } = pair;
        internal SpecusConnectionContext Publisher { get; } = publisher;
        internal ObservingWriter Observer { get; } = observer;
        internal static async Task<CatalogFixture> StartAsync()
        {
            var receiver = await PeerControlDeliveryAuthorityTests.RuntimeFixture.StartAsync();
            try
            {
                await using (var seed = receiver.Server.HostServices.CreateAsyncScope())
                {
                    var db = seed.ServiceProvider.GetRequiredService<SpecusDbContext>();
                    var account = await db.ClientAccounts.SingleAsync(a => a.Id == 1002); account.Enabled = true; account.OwnerUsername = "alice";
                    (await db.ClientIdentities.SingleAsync(i => i.Id == 702)).CredentialId = 502;
                    db.ClientCredentials.Add(new ClientCredential { Id = 502, TenantId = "default", OwnerUsername = "alice", ApiKey = "catalog-publisher-api",
                        SecretHash = ClientStartupOwnershipTests.Hash("catalog-publisher-secret"), Enabled = true, MaxOnlineInstances = 7 });
                    db.PeerMeshDevices.Add(new PeerMeshDevice { Id = 8802, TenantId = "default", ClientId = 1002, ClientName = "offline", OwnerUsername = "alice",
                        Enabled = true, VirtualIp = "10.66.0.4", Cidr = "10.66.0.0/16" });
                    db.PeerMeshServiceSharings.Add(new PeerMeshServiceSharing { TenantId = "default", Enabled = true });
                    db.PeerMeshSharedServices.Add(new PeerMeshSharedService { Id = 6501, TenantId = "default", ClientId = 1002, ClientName = "offline",
                        ServiceId = "catalog-service", Name = "catalog-service", Enabled = true, Visibility = "OWNER", TargetPort = 8080, PublishedPort = 24001 });
                    await db.SaveChangesAsync();
                }
                using var http = receiver.Server.CreateClient();
                var request = ClientStartupOwnershipTests.Signed("catalog-publisher-api", "catalog-publisher-secret", Guid.NewGuid().ToString("N"), "retained-machine2", "retained-user");
                request.Environment!.ClientPeerServiceCapabilities.Version = 2;
                using var response = await http.PostAsJsonAsync("/api/client/auth/login", request); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                var login = await response.Content.ReadFromJsonAsync<ClientAuthLoginResponse>(); Assert.NotNull(login);
                var publisher = NewContext("catalog-publisher", new PeerControlDeliveryAuthorityTests.RecordingWriter());
                await using (var auth = receiver.Server.HostServices.CreateAsyncScope())
                    Assert.True((await auth.ServiceProvider.GetRequiredService<ClientAccountService>().AuthenticateAsync(new LoginRequestPacket
                        { ClientSessionId = login.ClientSessionId, AccessToken = login.AccessToken }, publisher.ChannelId, "127.0.0.1", CancellationToken.None)).Success);
                publisher.OnLoginSuccess(login.ClientName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), login.ClientSessionId, tenantId: "default", clientId: 1002);
                var registry = receiver.Server.HostServices.GetRequiredService<SessionRegistry>(); registry.Replace(login.ClientName, publisher);
                var pair = await PeerQueuedDeliveryTests.BoundWriter.OpenAsync(receiver);
                var observer = new ObservingWriter(pair.Connection); var physical = pair.Connection.Context;
                var alias = new SpecusConnectionContext(physical.ChannelId, physical.RemoteAddress, observer, physical.Lifetime, physical.CloseAsync,
                    physical.ReadGate, physical.WriteBackpressure);
                alias.OnLoginSuccess(receiver.Login.ClientName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), receiver.Login.ClientSessionId,
                    tenantId: "default", clientId: 1001);
                registry.Unbind(receiver.Login.ClientName, physical); registry.Replace(receiver.Login.ClientName, alias);
                return new CatalogFixture(receiver, pair, publisher, observer);
            }
            catch { await receiver.DisposeAsync(); throw; }
        }
        public async ValueTask DisposeAsync() { await Pair.DisposeAsync(); await receiver.DisposeAsync(); }
    }

    internal sealed class ObservingWriter(IFrameWriter inner) : IFrameWriter
    {
        internal AsyncLocal<bool> OwnCall { get; } = new();
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private TaskCompletionSource? _backgroundPause;
        internal IDisposable PauseBackgroundWrites()
        {
            var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            if (Interlocked.CompareExchange(ref _backgroundPause, gate, null) is not null)
                throw new InvalidOperationException("background writes already paused");
            return new BackgroundPause(this, gate);
        }
        private async ValueTask BeforeWriteAsync(CancellationToken ct)
        {
            if (OwnCall.Value) { Entered.TrySetResult(); return; }
            var gate = Volatile.Read(ref _backgroundPause);
            if (gate is not null) await gate.Task.WaitAsync(ct);
        }
        public async ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        { await BeforeWriteAsync(cancellationToken); await inner.WriteAsync(packet, cancellationToken); }
        public async ValueTask<bool> WritePreparedAsync(Func<CancellationToken, ValueTask<Packet?>> prepare, CancellationToken cancellationToken = default)
        { await BeforeWriteAsync(cancellationToken); return await inner.WritePreparedAsync(prepare, cancellationToken); }
        private sealed class BackgroundPause(ObservingWriter owner, TaskCompletionSource gate) : IDisposable
        {
            public void Dispose()
            {
                if (ReferenceEquals(Interlocked.CompareExchange(ref owner._backgroundPause, null, gate), gate))
                    gate.TrySetResult();
            }
        }
    }
}
