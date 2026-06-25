using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.PeerMesh;
using ShuaiTunnel.Server.Sessions;

namespace ShuaiTunnel.IntegrationTests;

public sealed class StunTurnServerTests
{
    [Fact]
    public void AllocateReusesExpiredAllocationBeforeCleanup()
    {
        using var fixture = StunTurnFixture.Create();
        var remote = new IPEndPoint(IPAddress.Parse("192.0.2.10"), 50000);

        var first = fixture.Allocate(remote);
        var id = fixture.Id(first);
        fixture.ReplaceAllocation(id, remote, DateTimeOffset.UtcNow.AddSeconds(-1));

        var again = fixture.Allocate(remote);

        Assert.Equal(id, fixture.Id(again));
        Assert.True(fixture.ExpiresAt(again) > DateTimeOffset.UtcNow);
    }

    [Fact]
    public void RefreshTextReusesExpiredAllocationBeforeCleanup()
    {
        using var fixture = StunTurnFixture.Create();
        var remote = new IPEndPoint(IPAddress.Parse("192.0.2.11"), 50001);

        var allocation = fixture.Allocate(remote);
        var id = fixture.Id(allocation);
        fixture.ReplaceAllocation(id, remote, DateTimeOffset.UtcNow.AddSeconds(-1));

        var response = fixture.RefreshText(id, remote);

        Assert.StartsWith($"REFRESHED {id} ", response, StringComparison.Ordinal);
        Assert.True(fixture.ExpiresAt(fixture.GetAllocation(id)) > DateTimeOffset.UtcNow);
    }

    [Fact]
    public void SourceAllocationAcceptsExpiredAllocationBeforeCleanup()
    {
        using var fixture = StunTurnFixture.Create();
        var remote = new IPEndPoint(IPAddress.Parse("192.0.2.12"), 50002);

        var allocation = fixture.Allocate(remote);
        var id = fixture.Id(allocation);
        fixture.ReplaceAllocation(id, remote, DateTimeOffset.UtcNow.AddSeconds(-1));

        var source = fixture.SourceAllocation(id, remote);

        Assert.NotNull(source);
        Assert.Equal(id, fixture.Id(source));
    }

    [Fact]
    public void CleanupExpiredAllocationsRemovesExpiredAllocation()
    {
        using var fixture = StunTurnFixture.Create();
        var remote = new IPEndPoint(IPAddress.Parse("192.0.2.13"), 50003);

        var allocation = fixture.Allocate(remote);
        var id = fixture.Id(allocation);
        fixture.ReplaceAllocation(id, remote, DateTimeOffset.UtcNow.AddSeconds(-1));

        fixture.CleanupExpiredAllocations();

        Assert.False(fixture.ContainsAllocation(id));
        Assert.False(fixture.ContainsEndpoint(remote));
    }

    [Fact]
    public async Task RelayDataRejectsMissingSourceAllocation()
    {
        using var fixture = StunTurnFixture.Create();
        using var primary = ListenUdp();
        using var sourceSocket = ListenUdp();
        fixture.SetPrimary(primary);

        await fixture.RelayDataAsync(fixture.RelayMessage(
            allocationId: "missing-source",
            toAllocationId: "missing-target",
            payloadBase64: Convert.ToBase64String(Encoding.UTF8.GetBytes("hello"))), Remote(sourceSocket));

        var response = await ReadRelayMessageAsync(sourceSocket);
        Assert.Equal("error", JsonString(response, "type"));
        Assert.Equal("allocation-not-found", JsonString(response, "error"));
    }

    [Fact]
    public async Task RelayDataRejectsMissingTargetAllocation()
    {
        using var fixture = StunTurnFixture.Create();
        using var primary = ListenUdp();
        using var sourceSocket = ListenUdp();
        fixture.SetPrimary(primary);
        var source = fixture.Allocate(Remote(sourceSocket));

        await fixture.RelayDataAsync(fixture.RelayMessage(
            allocationId: fixture.Id(source),
            toAllocationId: "missing-target",
            payloadBase64: Convert.ToBase64String(Encoding.UTF8.GetBytes("hello"))), Remote(sourceSocket));

        var response = await ReadRelayMessageAsync(sourceSocket);
        Assert.Equal("error", JsonString(response, "type"));
        Assert.Equal("target-allocation-not-found", JsonString(response, "error"));
    }

    [Fact]
    public async Task RelayDataRejectsInvalidPayload()
    {
        using var fixture = StunTurnFixture.Create();
        using var primary = ListenUdp();
        using var sourceSocket = ListenUdp();
        using var targetSocket = ListenUdp();
        fixture.SetPrimary(primary);
        var source = fixture.Allocate(Remote(sourceSocket));
        var target = fixture.Allocate(Remote(targetSocket));

        await fixture.RelayDataAsync(fixture.RelayMessage(
            allocationId: fixture.Id(source),
            toAllocationId: fixture.Id(target),
            payloadBase64: "not-base64%"), Remote(sourceSocket));

        var response = await ReadRelayMessageAsync(sourceSocket);
        Assert.Equal("error", JsonString(response, "type"));
        Assert.Equal("invalid-payload", JsonString(response, "error"));
    }

    [Fact]
    public async Task RelayDataRejectsDeniedPeerFrame()
    {
        using var fixture = StunTurnFixture.Create(withPeerMeshService: true);
        using var primary = ListenUdp();
        using var sourceSocket = ListenUdp();
        using var targetSocket = ListenUdp();
        fixture.SetPrimary(primary);
        var source = fixture.Allocate(Remote(sourceSocket));
        var target = fixture.Allocate(Remote(targetSocket));

        await fixture.RelayDataAsync(fixture.RelayMessage(
            allocationId: fixture.Id(source),
            toAllocationId: fixture.Id(target),
            payloadBase64: Convert.ToBase64String(TestPeerDataFrame(9901, 1, 2))), Remote(sourceSocket));

        var response = await ReadRelayMessageAsync(sourceSocket);
        Assert.Equal("error", JsonString(response, "type"));
        Assert.Equal("relay-session-denied", JsonString(response, "error"));
    }

    [Fact]
    public async Task RelayDataForwardsOpaquePayload()
    {
        using var fixture = StunTurnFixture.Create();
        using var primary = ListenUdp();
        using var sourceSocket = ListenUdp();
        using var targetSocket = ListenUdp();
        fixture.SetPrimary(primary);
        var source = fixture.Allocate(Remote(sourceSocket));
        var target = fixture.Allocate(Remote(targetSocket));
        var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes("hello"));

        await fixture.RelayDataAsync(fixture.RelayMessage(
            transactionId: "tx-1",
            allocationId: fixture.Id(source),
            toAllocationId: fixture.Id(target),
            payloadBase64: payload), Remote(sourceSocket));

        var response = await ReadRelayMessageAsync(targetSocket);
        Assert.Equal("data", JsonString(response, "type"));
        Assert.Equal("tx-1", JsonString(response, "transactionId"));
        Assert.Equal(fixture.Id(source), JsonString(response, "fromAllocationId"));
        Assert.Equal(fixture.Id(target), JsonString(response, "toAllocationId"));
        Assert.Equal(payload, JsonString(response, "payloadBase64"));
    }

    private static UdpClient ListenUdp() => new(new IPEndPoint(IPAddress.Loopback, 0));

    private static IPEndPoint Remote(UdpClient socket) => (IPEndPoint)socket.Client.LocalEndPoint!;

    private static async Task<JsonElement> ReadRelayMessageAsync(UdpClient socket)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var result = await socket.ReceiveAsync(cts.Token);
        using var document = JsonDocument.Parse(result.Buffer);
        return document.RootElement.Clone();
    }

    private static string? JsonString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) ? value.GetString() : null;

    private static byte[] TestPeerDataFrame(long sessionId, long fromClientId, long toClientId)
    {
        var frame = new byte[50];
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(0, 4), 0x53504d31);
        frame[4] = 1;
        frame[5] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(6, 8), (ulong)sessionId);
        BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(14, 8), (ulong)fromClientId);
        BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(22, 8), (ulong)toClientId);
        BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(30, 8), 1);
        return frame;
    }

    private sealed class StunTurnFixture : IDisposable
    {
        private readonly ServiceProvider _provider;
        private readonly SqliteConnection? _connection;

        private StunTurnFixture(ServiceProvider provider, StunTurnServer server, SqliteConnection? connection)
        {
            _provider = provider;
            _connection = connection;
            Server = server;
        }

        private StunTurnServer Server { get; }

        private Type AllocationType => typeof(StunTurnServer).GetNestedType("Allocation", BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Allocation type not found");

        private Type RelayMessageType => typeof(StunTurnServer).GetNestedType("PeerRelayMessage", BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("PeerRelayMessage type not found");

        public static StunTurnFixture Create(bool withPeerMeshService = false)
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
            SqliteConnection? connection = null;
            if (withPeerMeshService)
            {
                connection = new SqliteConnection("Data Source=:memory:");
                connection.Open();
                services.AddDbContext<TunnelDbContext>(options => options.UseSqlite(connection));
                services.AddScoped<PeerMeshService>();
            }
            var provider = services.BuildServiceProvider();
            if (withPeerMeshService)
            {
                using var scope = provider.CreateScope();
                scope.ServiceProvider.GetRequiredService<TunnelDbContext>().Database.EnsureCreated();
            }
            var server = new StunTurnServer(
                peerOptions,
                provider.GetRequiredService<IServiceScopeFactory>(),
                NullLogger<StunTurnServer>.Instance);
            return new StunTurnFixture(provider, server, connection);
        }

        public object Allocate(IPEndPoint remote) => Invoke("Allocate", remote)
            ?? throw new InvalidOperationException("Allocate returned null");

        public string RefreshText(string allocationId, IPEndPoint remote) =>
            (string)(Invoke("RefreshText", allocationId, remote)
                ?? throw new InvalidOperationException("RefreshText returned null"));

        public object RelayMessage(string? transactionId = null, string? allocationId = null,
            string? toAllocationId = null, string? payloadBase64 = null)
        {
            var message = Activator.CreateInstance(
                RelayMessageType,
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
                binder: null,
                args: [],
                culture: null)!;
            RelayMessageType.GetProperty("TransactionId")!.SetValue(message, transactionId);
            RelayMessageType.GetProperty("AllocationId")!.SetValue(message, allocationId);
            RelayMessageType.GetProperty("ToAllocationId")!.SetValue(message, toAllocationId);
            RelayMessageType.GetProperty("PayloadBase64")!.SetValue(message, payloadBase64);
            return message;
        }

        public async Task RelayDataAsync(object message, IPEndPoint remote)
        {
            var task = (Task)typeof(StunTurnServer)
                .GetMethod("RelayDataAsync", BindingFlags.Instance | BindingFlags.NonPublic)!
                .Invoke(Server, [message, remote, CancellationToken.None])!;
            await task.ConfigureAwait(false);
        }

        public object? SourceAllocation(string allocationId, IPEndPoint remote)
        {
            var message = Activator.CreateInstance(
                RelayMessageType,
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
                binder: null,
                args: [],
                culture: null)!;
            RelayMessageType.GetProperty("AllocationId")!.SetValue(message, allocationId);
            return Invoke("SourceAllocation", message, remote);
        }

        public void SetPrimary(UdpClient socket) => typeof(StunTurnServer)
            .GetField("_primary", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(Server, socket);

        public void CleanupExpiredAllocations() => Invoke("CleanupExpiredAllocations");

        public void ReplaceAllocation(string id, IPEndPoint remote, DateTimeOffset expiresAt)
        {
            var allocation = Activator.CreateInstance(
                AllocationType,
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
                binder: null,
                args: [id, remote, expiresAt],
                culture: null)!;
            Allocations.GetType().GetProperty("Item")!.SetValue(Allocations, allocation, [id]);
        }

        public object GetAllocation(string id) => Allocations.GetType().GetProperty("Item")!.GetValue(Allocations, [id])
            ?? throw new InvalidOperationException($"Allocation {id} not found");

        public bool ContainsAllocation(string id) =>
            (bool)Allocations.GetType().GetMethod("ContainsKey")!.Invoke(Allocations, [id])!;

        public bool ContainsEndpoint(IPEndPoint remote) =>
            (bool)AllocationByEndpoint.GetType().GetMethod("ContainsKey")!.Invoke(AllocationByEndpoint, [EndpointKey(remote)])!;

        public string Id(object allocation) => (string)AllocationType.GetProperty("Id")!.GetValue(allocation)!;

        public DateTimeOffset ExpiresAt(object allocation) =>
            (DateTimeOffset)AllocationType.GetProperty("ExpiresAt")!.GetValue(allocation)!;

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

        public void Dispose()
        {
            _provider.Dispose();
            _connection?.Dispose();
        }
    }
}
