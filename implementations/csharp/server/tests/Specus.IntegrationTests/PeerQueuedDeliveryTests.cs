using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.PeerMesh;
using Specus.Server.Sessions;

namespace Specus.IntegrationTests;

public sealed class PeerQueuedDeliveryTests
{
    [Theory]
    [InlineData("config", "credential")]
    [InlineData("roster", "session")]
    [InlineData("egress", "channel")]
    public async Task QueuedPeerPushRechecksAuthorityAfterThePhysicalWriterBecomesAvailable(string kind, string mutation)
    {
        await using var fixture = await PeerControlDeliveryAuthorityTests.RuntimeFixture.StartAsync();
        await using var pair = await BoundWriter.OpenAsync(fixture);
        var firstPacket = new MessageResponsePacket { Message = "first-frame-holds-writer" };
        var first = pair.Connection.WriteAsync(firstPacket).AsTask();
        await pair.Stream.HalfWritten.WaitAsync(TimeSpan.FromSeconds(10));
        await using var scope = fixture.Server.HostServices.CreateAsyncScope();
        var push = PeerControlDeliveryAuthorityTests.PushAsync(scope.ServiceProvider.GetRequiredService<PeerMeshService>(), fixture.Account, kind);
        try
        {
            Assert.False(push.IsCompleted);
            await using var change = fixture.Server.HostServices.CreateAsyncScope();
            var db = change.ServiceProvider.GetRequiredService<SpecusDbContext>();
            if (mutation == "credential") (await db.ClientCredentials.SingleAsync()).Enabled = false;
            else
            {
                var session = await db.ClientSessions.SingleAsync(s => s.Id == fixture.Login.ClientSessionId);
                if (mutation == "session") session.ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1);
                else session.ChannelId = "another-physical-channel";
            }
            await db.SaveChangesAsync();
            pair.Stream.Release(); await first.WaitAsync(TimeSpan.FromSeconds(10)); await push.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(PacketCodec.Encode(firstPacket), pair.Stream.Wire());
            var received = new byte[PacketCodec.Encode(firstPacket).Length];
            await pair.Client.GetStream().ReadExactlyAsync(received, new CancellationTokenSource(TimeSpan.FromSeconds(10)).Token);
            Assert.Equal(PacketCodec.Encode(firstPacket), received);
        }
        finally { pair.Stream.Release(); try { await first; } catch (Exception) { } try { await push; } catch (Exception) { } }
    }

    [Fact]
    public async Task QueuedRosterIsBuiltFromTheOwnerCommittedWhileItWaited()
    {
        await using var fixture = await PeerControlDeliveryAuthorityTests.RuntimeFixture.StartAsync();
        await using var pair = await BoundWriter.OpenAsync(fixture);
        await using var scope = fixture.Server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider; var db = services.GetRequiredService<SpecusDbContext>();
        db.ClientAccounts.Add(new ClientAccount { Id = 3003, TenantId = "default", ClientName = "old-alice-peer", OwnerUsername = "alice", Enabled = true });
        db.PeerMeshDevices.Add(new PeerMeshDevice { Id = 3803, TenantId = "default", ClientId = 3003, ClientName = "old-alice-peer", OwnerUsername = "alice", Enabled = true, VirtualIp = "10.66.0.4", Cidr = "10.66.0.0/16" });
        await db.SaveChangesAsync();
        var firstPacket = new MessageResponsePacket { Message = "first-frame-holds-writer" };
        var first = pair.Connection.WriteAsync(firstPacket).AsTask(); await pair.Stream.HalfWritten.WaitAsync(TimeSpan.FromSeconds(10));
        var push = services.GetRequiredService<PeerMeshService>().PushRosterAsync(fixture.Account, CancellationToken.None);
        try
        {
            Assert.False(push.IsCompleted);
            await using var transfer = fixture.Server.HostServices.CreateAsyncScope();
            var actor = await OwnerTransferWriterProof.ActorAsync(fixture.Server, transfer.ServiceProvider);
            var preview = await transfer.ServiceProvider.GetRequiredService<ClientOwnerTransferService>().PreviewCredentialAsync(actor.Context, "501", CancellationToken.None);
            await transfer.ServiceProvider.GetRequiredService<ClientOwnerTransferWriter>().CommitAsync(actor, ClientOwnerTransferPlan.PathScope.CredentialGroup, "501",
                OwnerTransferWriterProof.Body(ClientOwnerTransferPlan.PathScope.CredentialGroup, "bob", preview.Revision!), CancellationToken.None);
            pair.Stream.Release(); await first.WaitAsync(TimeSpan.FromSeconds(10)); await push.WaitAsync(TimeSpan.FromSeconds(10));
            var bytes = pair.Stream.Wire(); var prefix = PacketCodec.Encode(firstPacket).Length;
            var packet = Assert.IsType<MessageResponsePacket>(PacketCodec.DecodeExact(bytes.AsSpan(prefix)));
            var roster = JsonSerializer.Deserialize<PeerControlMessage>(packet.Message!)!;
            Assert.Equal("roster", roster.Type); Assert.DoesNotContain(roster.Peers!, p => p.ClientId == 3003);
        }
        finally { pair.Stream.Release(); try { await first; } catch (Exception) { } try { await push; } catch (Exception) { } }
    }

    internal sealed class BoundWriter(SpecusConnection connection, TcpClient client, GatedNetworkStream stream) : IAsyncDisposable
    {
        internal SpecusConnection Connection { get; } = connection;
        internal TcpClient Client { get; } = client;
        internal GatedNetworkStream Stream { get; } = stream;
        internal static async Task<BoundWriter> OpenAsync(PeerControlDeliveryAuthorityTests.RuntimeFixture fixture)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            try
            {
                var client = new TcpClient(); await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint);
                var socket = await listener.AcceptSocketAsync();
                var stream = new GatedNetworkStream(new NetworkStream(socket, ownsSocket: false));
                var connection = new SpecusConnection(socket, stream, new NoDispatcher(), NullLogger.Instance, new NettyServerOptions(), CancellationToken.None);
                await using var scope = fixture.Server.HostServices.CreateAsyncScope();
                var result = await scope.ServiceProvider.GetRequiredService<ClientAccountService>().AuthenticateAsync(new LoginRequestPacket
                    { ClientSessionId = fixture.Login.ClientSessionId, AccessToken = fixture.Login.AccessToken }, connection.Context.ChannelId, "127.0.0.1", CancellationToken.None);
                Assert.True(result.Success, result.Reason);
                connection.Context.OnLoginSuccess(fixture.Login.ClientName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), fixture.Login.ClientSessionId,
                    tenantId: fixture.Login.TenantId, clientId: fixture.Login.ClientId);
                fixture.Server.HostServices.GetRequiredService<SessionRegistry>().Replace(fixture.Login.ClientName, connection.Context);
                return new BoundWriter(connection, client, stream);
            }
            finally { listener.Stop(); }
        }
        public async ValueTask DisposeAsync() { await Connection.DisposeAsync(); Client.Dispose(); }
    }

    private sealed class NoDispatcher : IControlChannelDispatcher
    {
        public Task OnConnectionOpenedAsync(SpecusConnectionContext context) => Task.CompletedTask;
        public Task DispatchAsync(SpecusConnectionContext context, Packet packet) => Task.CompletedTask;
        public Task OnConnectionClosedAsync(SpecusConnectionContext context) => Task.CompletedTask;
    }

    internal sealed class GatedNetworkStream(Stream inner) : Stream
    {
        private readonly MemoryStream _wire = new(); private readonly object _gate = new(); private int _writes;
        private readonly TaskCompletionSource _half = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task HalfWritten => _half.Task;
        internal void Release() => _release.TrySetResult();
        internal byte[] Wire() { lock (_gate) return _wire.ToArray(); }
        private async ValueTask AppendAsync(ReadOnlyMemory<byte> data, CancellationToken ct)
        { await inner.WriteAsync(data, ct); lock (_gate) _wire.Write(data.Span); }
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref _writes) != 1) { await AppendAsync(data, cancellationToken); return; }
            var half = data.Length / 2; await AppendAsync(data[..half], cancellationToken); _half.TrySetResult();
            await _release.Task.WaitAsync(cancellationToken); await AppendAsync(data[half..], cancellationToken);
        }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
        public override void Flush() => inner.Flush();
        public override bool CanRead => false; public override bool CanSeek => false; public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) { inner.Dispose(); _wire.Dispose(); } base.Dispose(disposing); }
    }
}
