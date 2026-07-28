using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.PeerMesh;
using Specus.Server.Sessions;

namespace Specus.IntegrationTests;

public sealed class StunTurnServerTests
{
    [Fact]
    public async Task AllocateRequiresAndAcceptsJavaCompatibleTurnCredentials()
    {
        using var fixture = StunTurnFixture.Create();
        using var primary = ListenUdp();
        using var source = ListenUdp();
        fixture.SetPrimary(primary);
        var tx = StunMessage.NewTransactionId();
        var unauthenticated = StunMessage.Of(StunMessage.AllocateRequest, tx,
            StunMessage.RequestedUdpTransportAttribute());

        await fixture.HandleAsync(unauthenticated.ToBytes(), Remote(source), primary);
        var challengeBytes = await ReadBytesAsync(source);
        var challenge = StunMessage.Parse(challengeBytes)!;
        Assert.Equal(StunMessage.AllocateError, challenge.Type);
        Assert.Equal(fixture.TurnCredentials.Realm, challenge.RealmValue());
        Assert.Equal(fixture.TurnCredentials.Nonce, challenge.NonceValue());

        var credential = fixture.TurnCredentials.Issue("test-client");
        var authenticated = StunMessage.Of(StunMessage.AllocateRequest, StunMessage.NewTransactionId(),
            StunMessage.RequestedUdpTransportAttribute(),
            StunMessage.Username(credential.Username),
            StunMessage.Realm(credential.Realm),
            StunMessage.Nonce(credential.Nonce));
        var key = fixture.TurnCredentials.LongTermKey(credential.Username, credential.Credential);
        await fixture.HandleAsync(authenticated.ToBytes(key), Remote(source), primary);
        var successBytes = await ReadBytesAsync(source);
        var success = StunMessage.Parse(successBytes)!;
        Assert.Equal(StunMessage.AllocateSuccess, success.Type);
        Assert.True(StunMessage.VerifyMessageIntegrity(successBytes, key));
    }

    [Fact]
    public void AllocateReplacesExpiredAllocationBeforeCleanup()
    {
        using var fixture = StunTurnFixture.Create();
        var remote = new IPEndPoint(IPAddress.Loopback, 50000);

        var first = fixture.Allocate(remote);
        var id = fixture.Id(first);
        fixture.SetExpiresAt(first, DateTimeOffset.UtcNow.AddSeconds(-1));

        var again = fixture.Allocate(remote);

        Assert.NotEqual(id, fixture.Id(again));
        Assert.False(fixture.ContainsAllocation(id));
        Assert.True(fixture.ContainsEndpoint(remote));
    }

    [Fact]
    public async Task RefreshExpiredAllocationReturnsErrorAndClosesAllocation()
    {
        using var fixture = StunTurnFixture.Create();
        using var primary = ListenUdp();
        using var source = ListenUdp();
        fixture.SetPrimary(primary);
        var allocation = fixture.Allocate(Remote(source));
        var id = fixture.Id(allocation);
        fixture.SetExpiresAt(allocation, DateTimeOffset.UtcNow.AddSeconds(-1));

        var tx = StunMessage.NewTransactionId();
        await fixture.RefreshAsync(StunMessage.Of(
            StunMessage.RefreshRequest,
            tx,
            StunMessage.Lifetime(60)), Remote(source));

        var response = await ReadStunAsync(source);
        Assert.Equal(StunMessage.RefreshError, response.Type);
        Assert.False(fixture.ContainsAllocation(id));
    }

    [Fact]
    public async Task CreatePermissionAndSendIndicationRejectOpaquePayload()
    {
        using var fixture = StunTurnFixture.Create();
        using var primary = ListenUdp();
        using var source = ListenUdp();
        using var peer = ListenUdp();
        fixture.SetPrimary(primary);
        fixture.Allocate(Remote(source));
        await fixture.CreatePermissionAsync(Remote(source), Remote(peer));
        await ReadStunAsync(source);

        await fixture.SendIndicationAsync(Remote(source), Remote(peer), "hello"u8.ToArray());

        Assert.Null(await TryReadBytesAsync(peer));
    }

    [Fact]
    public async Task SendIndicationWithoutPermissionDropsPayload()
    {
        using var fixture = StunTurnFixture.Create();
        using var primary = ListenUdp();
        using var source = ListenUdp();
        using var peer = ListenUdp();
        fixture.SetPrimary(primary);
        fixture.Allocate(Remote(source));

        await fixture.SendIndicationAsync(Remote(source), Remote(peer), "hello"u8.ToArray());

        Assert.Null(await TryReadBytesAsync(peer));
    }

    [Fact]
    public async Task RelayReceiveRejectsOpaquePayloadForPermittedPeer()
    {
        using var fixture = StunTurnFixture.Create();
        using var primary = ListenUdp();
        using var source = ListenUdp();
        using var peer = ListenUdp();
        fixture.SetPrimary(primary);
        var allocation = fixture.Allocate(Remote(source));
        await fixture.CreatePermissionAsync(Remote(source), Remote(peer));
        await ReadStunAsync(source);

        await peer.SendAsync("pong"u8.ToArray(), fixture.RelayLocalEndpoint(allocation));

        Assert.Null(await TryReadBytesAsync(source));
    }

    private static UdpClient ListenUdp() => new(new IPEndPoint(IPAddress.Loopback, 0));

    private static IPEndPoint Remote(UdpClient socket) => (IPEndPoint)socket.Client.LocalEndPoint!;

    private static async Task<StunMessage> ReadStunAsync(UdpClient socket)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var result = await socket.ReceiveAsync(cts.Token);
        return StunMessage.Parse(result.Buffer)
            ?? throw new InvalidOperationException("STUN packet expected");
    }

    private static async Task<byte[]> ReadBytesAsync(UdpClient socket) =>
        await TryReadBytesAsync(socket) ?? throw new InvalidOperationException("UDP payload expected");

    private static async Task<byte[]?> TryReadBytesAsync(UdpClient socket)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
        try
        {
            var result = await socket.ReceiveAsync(cts.Token);
            return result.Buffer;
        }
        catch (OperationCanceledException)
        {
            return null;
        }
    }

    private sealed class StunTurnFixture : IDisposable
    {
        private readonly ServiceProvider _provider;

        private StunTurnFixture(ServiceProvider provider, StunTurnServer server)
        {
            _provider = provider;
            Server = server;
        }

        private StunTurnServer Server { get; }

        private Type AllocationType => typeof(StunTurnServer).GetNestedType("Allocation", BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Allocation type not found");

        public static StunTurnFixture Create()
        {
            var services = new ServiceCollection();
            var peerOptions = Options.Create(new PeerMeshOptions
            {
                Enabled = true,
                StunTurnPort = 3478,
                AllocationTtlSeconds = 60,
            });
            services.AddSingleton<IOptions<PeerMeshOptions>>(peerOptions);
            services.AddSingleton(new SessionRegistry(NullLogger<SessionRegistry>.Instance));
            services.AddSingleton<ILogger<PeerMeshService>>(NullLogger<PeerMeshService>.Instance);
            services.AddScoped<PeerMeshService>();
            var provider = services.BuildServiceProvider();
            var server = new StunTurnServer(
                peerOptions,
                provider.GetRequiredService<IServiceScopeFactory>(),
                NullLogger<StunTurnServer>.Instance);
            return new StunTurnFixture(provider, server);
        }

        public object Allocate(IPEndPoint remote) => Invoke("Allocate", remote, CancellationToken.None)
            ?? throw new InvalidOperationException("Allocate returned null");

        public async Task RefreshAsync(StunMessage message, IPEndPoint remote) =>
            await InvokeTask("RefreshAsync", message, remote).ConfigureAwait(false);

        public async Task CreatePermissionAsync(IPEndPoint remote, IPEndPoint peer)
        {
            var tx = StunMessage.NewTransactionId();
            await InvokeTask("CreatePermissionAsync", StunMessage.Of(
                StunMessage.CreatePermissionRequest,
                tx,
                StunMessage.XorPeerAddress(peer, tx)), remote).ConfigureAwait(false);
        }

        public async Task SendIndicationAsync(IPEndPoint remote, IPEndPoint peer, byte[] payload)
        {
            var tx = StunMessage.NewTransactionId();
            await InvokeTask("SendIndicationAsync", StunMessage.Of(
                StunMessage.SendIndication,
                tx,
                StunMessage.XorPeerAddress(peer, tx),
                StunMessage.Data(payload)), remote, CancellationToken.None).ConfigureAwait(false);
        }

        public void SetPrimary(UdpClient socket) => typeof(StunTurnServer)
            .GetField("_primary", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(Server, socket);

        public bool ContainsAllocation(string id) =>
            (bool)Allocations.GetType().GetMethod("ContainsKey")!.Invoke(Allocations, [id])!;

        public bool ContainsEndpoint(IPEndPoint remote) =>
            (bool)AllocationByEndpoint.GetType().GetMethod("ContainsKey")!.Invoke(AllocationByEndpoint, [EndpointKey(remote)])!;

        public string Id(object allocation) => (string)AllocationType.GetProperty("Id")!.GetValue(allocation)!;

        public void SetExpiresAt(object allocation, DateTimeOffset expiresAt) =>
            AllocationType.GetProperty("ExpiresAt")!.SetValue(allocation, expiresAt);

        public IPEndPoint RelayLocalEndpoint(object allocation)
        {
            var relay = (UdpClient)AllocationType.GetProperty("Relay")!.GetValue(allocation)!;
            var endpoint = (IPEndPoint)relay.Client.LocalEndPoint!;
            return new IPEndPoint(IPAddress.Loopback, endpoint.Port);
        }

        public TurnCredentialService TurnCredentials => (TurnCredentialService)typeof(StunTurnServer)
            .GetField("_turnCredentials", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(Server)!;

        public async Task HandleAsync(byte[] payload, IPEndPoint remote, UdpClient socket) =>
            await InvokeTask("HandleAsync", payload, remote, socket, "primary", CancellationToken.None)
                .ConfigureAwait(false);

        private object Allocations => typeof(StunTurnServer)
            .GetField("_allocations", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(Server)!;

        private object AllocationByEndpoint => typeof(StunTurnServer)
            .GetField("_allocationByEndpoint", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(Server)!;

        private string EndpointKey(IPEndPoint remote) =>
            (string)typeof(StunTurnServer)
                .GetMethod("EndpointKey", BindingFlags.Static | BindingFlags.NonPublic)!
                .Invoke(null, [remote])!;

        private object? Invoke(string name, params object[] args) =>
            typeof(StunTurnServer).GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!
                .Invoke(Server, args);

        private async Task InvokeTask(string name, params object[] args)
        {
            var task = (Task)Invoke(name, args)!;
            await task.ConfigureAwait(false);
        }

        public void Dispose()
        {
            foreach (var value in (System.Collections.IEnumerable)Allocations)
            {
                var allocation = value.GetType().GetProperty("Value")!.GetValue(value)!;
                var relay = (UdpClient)AllocationType.GetProperty("Relay")!.GetValue(allocation)!;
                relay.Dispose();
            }
            _provider.Dispose();
        }
    }
}
