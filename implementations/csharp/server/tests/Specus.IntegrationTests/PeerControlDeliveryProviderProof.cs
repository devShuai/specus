using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Management;
using Specus.Server.PeerMesh;
using Specus.Server.Sessions;

namespace Specus.IntegrationTests;

// Mandatory native DBs, real HMAC HTTP login and credential management API, production
// SpecusConnection with a gated real loopback TCP stream. Not separate OS process coverage.
internal static class PeerControlDeliveryProviderProof
{
    internal static async Task VerifyCatalogAsync(TestServerFixture server, bool verifySignals = false)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60)); var ct = timeout.Token;
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider; var db = services.GetRequiredService<SpecusDbContext>();
        await OwnerTransferWriterProof.SeedAsync(db, "default");
        const string secret = "native-catalog-fixture-secret";
        var receiverCredential = await db.ClientCredentials.SingleAsync(c => c.Id == 501, ct);
        receiverCredential.Enabled = true; receiverCredential.MaxOnlineInstances = 7; receiverCredential.SecretHash = Hash(secret);
        (await db.ClientSessions.SingleAsync(s => s.Id == 901, ct)).ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1);
        var publisher = await db.ClientAccounts.SingleAsync(a => a.Id == 1002, ct);
        publisher.Enabled = true; publisher.OwnerUsername = "alice";
        (await db.ClientIdentities.SingleAsync(i => i.Id == 702, ct)).CredentialId = 502;
        db.ClientCredentials.Add(new Specus.Server.Data.Entities.ClientCredential { Id = 502, TenantId = "default", OwnerUsername = "alice",
            ApiKey = "native-catalog-api", SecretHash = Hash(secret), Enabled = true, MaxOnlineInstances = 7 });
        db.PeerMeshDevices.Add(new Specus.Server.Data.Entities.PeerMeshDevice { Id = 802, TenantId = "default", ClientId = 1002,
            ClientName = publisher.ClientName, OwnerUsername = "alice", Enabled = true, VirtualIp = "10.66.0.4", Cidr = "10.66.0.0/16" });
        db.PeerMeshServiceSharings.Add(new Specus.Server.Data.Entities.PeerMeshServiceSharing { TenantId = "default", Enabled = true });
        db.PeerMeshSharedServices.Add(new Specus.Server.Data.Entities.PeerMeshSharedService { Id = 6501, TenantId = "default", ClientId = 1002,
            ClientName = publisher.ClientName, ServiceId = "catalog-service", Name = "catalog-service", Enabled = true,
            Visibility = "OWNER", TargetPort = 8080, PublishedPort = 24001 });
        await db.SaveChangesAsync(ct);
        using var http = server.CreateClient();
        async Task<ClientAuthLoginResponse> Login(string api, string machine)
        {
            using var response = await http.PostAsJsonAsync("/api/client/auth/login", Signed(api, secret, machine, "retained-user"), ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return (await response.Content.ReadFromJsonAsync<ClientAuthLoginResponse>(ct))!;
        }
        var recipientLogin = await Login(receiverCredential.ApiKey, "retained-machine1");
        var publisherLogin = await Login("native-catalog-api", "retained-machine2");
        var source = new SpecusConnectionContext("native-catalog-source", "127.0.0.1", new CatalogSink(), CancellationToken.None,
            () => { }, new Specus.Server.Networking.ReadGate(CancellationToken.None), new Specus.Server.Networking.WriteBackpressureGate(65536, 1048576));
        Assert.True((await services.GetRequiredService<ClientAccountService>().AuthenticateAsync(new LoginRequestPacket
            { ClientSessionId = publisherLogin.ClientSessionId, AccessToken = publisherLogin.AccessToken }, source.ChannelId, "127.0.0.1", ct)).Success);
        source.OnLoginSuccess(publisherLogin.ClientName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), publisherLogin.ClientSessionId,
            tenantId: "default", clientId: 1002);
        var registry = services.GetRequiredService<SessionRegistry>(); registry.Replace(publisherLogin.ClientName, source);
        await using var pair = await BoundWriter.OpenAsync(server, recipientLogin, ct);
        var observer = new CatalogObserver(pair.Connection); var physical = pair.Connection.Context;
        var alias = new SpecusConnectionContext(physical.ChannelId, physical.RemoteAddress, observer, physical.Lifetime,
            physical.CloseAsync, physical.ReadGate, physical.WriteBackpressure);
        alias.OnLoginSuccess(recipientLogin.ClientName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), recipientLogin.ClientSessionId,
            tenantId: "default", clientId: 1001);
        registry.Unbind(recipientLogin.ClientName, physical); registry.Replace(recipientLogin.ClientName, alias);
        var firstPacket = new MessageResponsePacket { Message = "holds-native-catalog-writer" };
        var first = pair.Connection.WriteAsync(firstPacket, ct).AsTask();
        await pair.Stream.HalfWritten.WaitAsync(TimeSpan.FromSeconds(10), ct);
        observer.OwnCall.Value = true;
        var pending = services.GetRequiredService<IControlChannelDispatcher>().DispatchAsync(source, new MessageRequestPacket
            { MessageType = Specus.Protocol.MessageType.PeerControl, ToClientName = verifySignals ? recipientLogin.ClientName : null,
                Message = verifySignals ? "{\"type\":\"candidates\",\"candidates\":[]}"
                    : "{\"type\":\"service-report\",\"enabled\":true,\"revision\":1,\"services\":[{\"serviceId\":\"catalog-service\"}]}" });
        observer.OwnCall.Value = false;
        try
        {
            await Task.WhenAny(pending, observer.Entered.Task).WaitAsync(TimeSpan.FromSeconds(10), ct);
            if (!observer.Entered.Task.IsCompleted) { await pending; Assert.Fail("native catalog did not reach actual wire queue"); }
            Assert.False(pending.IsCompleted);
            await using (var change = server.HostServices.CreateAsyncScope())
            {
                var current = change.ServiceProvider.GetRequiredService<SpecusDbContext>();
                if (verifySignals) (await current.ClientCredentials.SingleAsync(c => c.Id == 502, ct)).Enabled = false;
                else (await current.PeerMeshSharedServices.SingleAsync(s => s.Id == 6501, ct)).PublishedPort = 24002;
                await current.SaveChangesAsync(ct);
            }
            pair.Stream.Release(); await first.WaitAsync(ct); await pending.WaitAsync(ct);
            var prefix = PacketCodec.Encode(firstPacket).Length;
            if (verifySignals)
            {
                Assert.Equal(PacketCodec.Encode(firstPacket), pair.Stream.Wire());
                var session = await db.PeerMeshSessions.AsNoTracking().SingleAsync(s => s.SourceClientId == 1002 && s.TargetClientId == 1001, ct);
                Assert.Equal(PeerMeshService.StatusClosed, session.Status); Assert.NotNull(session.ClosedAt);
                var firstReceived = new byte[prefix]; await pair.Client.GetStream().ReadExactlyAsync(firstReceived, ct);
                Assert.Equal(PacketCodec.Encode(firstPacket), firstReceived);
                Assert.Null(db.Database.CurrentTransaction);
                foreach (var type in new[] { "session-grant", "peer-config", "roster", "service-catalog", "egress-config", "egress-catalog" })
                    await Assert.ThrowsAsync<ArgumentException>(() => services.GetRequiredService<IControlChannelDispatcher>().DispatchAsync(source,
                        new MessageRequestPacket { MessageType = Specus.Protocol.MessageType.PeerControl, ToClientName = recipientLogin.ClientName,
                            Message = JsonSerializer.Serialize(new { type, token = "forged" }) }));
                Assert.Equal(PacketCodec.Encode(firstPacket), pair.Stream.Wire());
                return;
            }
            var packet = Assert.IsType<MessageResponsePacket>(PacketCodec.DecodeExact(pair.Stream.Wire().AsSpan(prefix)));
            var catalog = JsonSerializer.Deserialize<PeerControlMessage>(packet.Message!)!;
            Assert.Equal(publisherLogin.ClientSessionId, catalog.PublisherSessionId);
            Assert.Equal(24002, Assert.Single(catalog.Services!).PublishedPort);
            var wire = pair.Stream.Wire(); var received = new byte[wire.Length];
            await pair.Client.GetStream().ReadExactlyAsync(received, ct); Assert.Equal(wire, received);
        }
        finally { pair.Stream.Release(); try { await first; } catch (Exception) { } try { await pending; } catch (Exception) { } }
        await using (var change = server.HostServices.CreateAsyncScope())
        {
            var current = change.ServiceProvider.GetRequiredService<SpecusDbContext>();
            (await current.ClientCredentials.SingleAsync(c => c.Id == 502, ct)).Enabled = false;
            await current.SaveChangesAsync(ct);
        }
        var peer = services.GetRequiredService<PeerMeshService>();
        var recipient = await db.ClientAccounts.AsNoTracking().SingleAsync(a => a.Id == 1001, ct);
        var before = pair.Stream.Wire().Length; await peer.PushOnLoginAsync(recipient, ct);
        var tail = pair.Stream.Wire().AsMemory(before);
        var sawWithdrawal = false;
        while (!tail.IsEmpty)
        {
            Assert.True(PacketCodec.TryDecode(tail.Span, out var decoded, out var length));
            var packet = Assert.IsType<MessageResponsePacket>(decoded);
            var message = JsonSerializer.Deserialize<PeerControlMessage>(packet.Message!)!;
            if (message.Type == "service-catalog" && message.PublisherSessionId == publisherLogin.ClientSessionId)
            { Assert.Empty(message.Services!); sawWithdrawal = true; }
            tail = tail[length..];
        }
        Assert.True(sawWithdrawal); Assert.Null(db.Database.CurrentTransaction);
    }

    private sealed class CatalogSink : IFrameWriter
    { public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default) => ValueTask.CompletedTask; }

    private sealed class CatalogObserver(IFrameWriter inner) : IFrameWriter
    {
        internal AsyncLocal<bool> OwnCall { get; } = new();
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        { if (OwnCall.Value) Entered.TrySetResult(); return inner.WriteAsync(packet, cancellationToken); }
        public ValueTask<bool> WritePreparedAsync(Func<CancellationToken, ValueTask<Packet?>> prepare, CancellationToken cancellationToken = default)
        { if (OwnCall.Value) Entered.TrySetResult(); return inner.WritePreparedAsync(prepare, cancellationToken); }
    }

    internal static async Task VerifyAsync(TestServerFixture server)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60)); var ct = timeout.Token;
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider; var db = services.GetRequiredService<SpecusDbContext>();
        await OwnerTransferWriterProof.SeedAsync(db, "default");
        var credential = await db.ClientCredentials.SingleAsync(ct);
        const string secret = "native-peer-delivery-fixture";
        credential.Enabled = true; credential.MaxOnlineInstances = 7; credential.SecretHash = Hash(secret);
        var historical = await db.ClientSessions.SingleAsync(s => s.Id == 901, ct);
        historical.ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1); historical.ClientEgressVersion = 1;
        await db.SaveChangesAsync(ct);
        var identity = await db.ClientIdentities.AsNoTracking().SingleAsync(i => i.Id == 701, ct);
        using var client = server.CreateClient();
        using var loginResponse = await client.PostAsJsonAsync("/api/client/auth/login", Signed(credential.ApiKey, secret, identity.MachineFingerprint, identity.OsUser), ct);
        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);
        var login = await loginResponse.Content.ReadFromJsonAsync<ClientAuthLoginResponse>(ct); Assert.NotNull(login);
        await using var pair = await BoundWriter.OpenAsync(server, login, ct);
        var account = await db.ClientAccounts.AsNoTracking().SingleAsync(a => a.Id == login.ClientId, ct);
        using var admin = server.CreateClient();
        var auth = services.GetRequiredService<IOptions<AuthOptions>>().Value;
        using var adminLogin = await admin.PostAsJsonAsync("/auth/login", new AdminLoginRequest(auth.Username, auth.Password, TenantId: auth.TenantId), ct);
        Assert.Equal(HttpStatusCode.OK, adminLogin.StatusCode);
        var token = (await adminLogin.Content.ReadFromJsonAsync<JsonElement>(ct)).GetProperty("accessToken").GetString();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var firstPacket = new MessageResponsePacket { Message = "holds-native-writer-" + new string('x', 4096) };
        var first = pair.Connection.WriteAsync(firstPacket, ct).AsTask();
        await pair.Stream.HalfWritten.WaitAsync(TimeSpan.FromSeconds(10), ct);
        var peer = services.GetRequiredService<PeerMeshService>();
        var push = peer.PushEgressAsync(account, ct);
        try
        {
            Assert.False(push.IsCompleted);
            using var disabled = await admin.PutAsJsonAsync("/api/admin/client-credentials/501", new { enabled = false }, ct);
            Assert.Equal(HttpStatusCode.OK, disabled.StatusCode);
            pair.Stream.Release(); await first.WaitAsync(ct); await push.WaitAsync(ct);
            Assert.Equal(PacketCodec.Encode(firstPacket), pair.Stream.Wire());
            var received = new byte[PacketCodec.Encode(firstPacket).Length];
            await pair.Client.GetStream().ReadExactlyAsync(received, ct);
            Assert.Equal(PacketCodec.Encode(firstPacket), received);
        }
        finally { pair.Stream.Release(); try { await first; } catch (Exception) { } try { await push; } catch (Exception) { } }
        using var enabled = await admin.PutAsJsonAsync("/api/admin/client-credentials/501", new { enabled = true }, ct);
        Assert.Equal(HttpStatusCode.OK, enabled.StatusCode);
        var prefix = pair.Stream.Wire().Length;
        await peer.PushRosterAsync(account, ct);
        var rosterPacket = Assert.IsType<MessageResponsePacket>(PacketCodec.DecodeExact(pair.Stream.Wire().AsSpan(prefix)));
        Assert.Equal("roster", JsonSerializer.Deserialize<PeerControlMessage>(rosterPacket.Message!)!.Type);
        // Another (expired) SQL session advertises v1, but this receiver's exact CS is v0.
        var current = await db.ClientSessions.SingleAsync(s => s.Id == login.ClientSessionId, ct);
        current.ClientEgressVersion = 0; await db.SaveChangesAsync(ct);
        var before = pair.Stream.Wire(); await peer.PushEgressAsync(account, ct); Assert.Equal(before, pair.Stream.Wire());
        current.ClientEgressVersion = 1; current.ChannelId = "replaced-native-physical-channel"; await db.SaveChangesAsync(ct);
        await peer.PushConfigAsync(account, ct); Assert.Equal(before, pair.Stream.Wire());
        Assert.Null(db.Database.CurrentTransaction);
    }

    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static ClientAuthLoginRequest Signed(string api, string secret, string machine, string user)
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture); var nonce = Guid.NewGuid().ToString("N");
        return new ClientAuthLoginRequest { ApiKey = api, Timestamp = timestamp, Nonce = nonce,
            Signature = Convert.ToHexStringLower(HMACSHA256.HashData(Convert.FromHexString(Hash(secret)), Encoding.UTF8.GetBytes(string.Join('\n', api, timestamp, nonce, machine, user)))),
            Environment = new ClientEnvironmentInfo { MachineFingerprint = machine, OsUser = user, Hostname = "native-peer-delivery",
                ClientEgressCapabilities = new ClientEgressCapabilities { Version = 1 }, ClientPeerServiceCapabilities = new ClientPeerServiceCapabilities { Version = 2 } } };
    }

    private sealed class BoundWriter(SpecusConnection connection, TcpClient client, GatedStream stream) : IAsyncDisposable
    {
        internal SpecusConnection Connection { get; } = connection; internal TcpClient Client { get; } = client; internal GatedStream Stream { get; } = stream;
        internal static async Task<BoundWriter> OpenAsync(TestServerFixture server, ClientAuthLoginResponse login, CancellationToken ct)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            try
            {
                var client = new TcpClient(); await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint, ct);
                var socket = await listener.AcceptSocketAsync(ct); var stream = new GatedStream(new NetworkStream(socket, ownsSocket: false));
                var connection = new SpecusConnection(socket, stream, new NoDispatcher(), NullLogger.Instance, new NettyServerOptions(), CancellationToken.None);
                await using var scope = server.HostServices.CreateAsyncScope();
                var result = await scope.ServiceProvider.GetRequiredService<ClientAccountService>().AuthenticateAsync(new LoginRequestPacket
                    { ClientSessionId = login.ClientSessionId, AccessToken = login.AccessToken }, connection.Context.ChannelId, "127.0.0.1", ct);
                Assert.True(result.Success, result.Reason);
                connection.Context.OnLoginSuccess(login.ClientName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), login.ClientSessionId, tenantId: login.TenantId, clientId: login.ClientId);
                server.HostServices.GetRequiredService<SessionRegistry>().Replace(login.ClientName, connection.Context);
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
    private sealed class GatedStream(Stream inner) : Stream
    {
        private readonly MemoryStream _wire = new(); private readonly object _gate = new(); private int _writes;
        private readonly TaskCompletionSource _half = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task HalfWritten => _half.Task; internal void Release() => _release.TrySetResult();
        internal byte[] Wire() { lock (_gate) return _wire.ToArray(); }
        private async ValueTask AppendAsync(ReadOnlyMemory<byte> bytes, CancellationToken ct) { await inner.WriteAsync(bytes, ct); lock (_gate) _wire.Write(bytes.Span); }
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref _writes) != 1) { await AppendAsync(bytes, cancellationToken); return; }
            var half = bytes.Length / 2; await AppendAsync(bytes[..half], cancellationToken); _half.TrySetResult();
            await _release.Task.WaitAsync(cancellationToken); await AppendAsync(bytes[half..], cancellationToken);
        }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken); public override void Flush() => inner.Flush();
        public override bool CanRead => false; public override bool CanSeek => false; public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException(); public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) { inner.Dispose(); _wire.Dispose(); } base.Dispose(disposing); }
    }
}
