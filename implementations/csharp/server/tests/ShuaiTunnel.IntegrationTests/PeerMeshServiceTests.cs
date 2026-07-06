using System.Reflection;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Protocol;
using ShuaiTunnel.Protocol.Packets;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.ControlChannel;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Data.Entities;
using ShuaiTunnel.Server.Management;
using ShuaiTunnel.Server.Networking;
using ShuaiTunnel.Server.PeerMesh;
using ShuaiTunnel.Server.Sessions;

namespace ShuaiTunnel.IntegrationTests;

public sealed class PeerMeshServiceTests
{
    [Fact]
    public async Task CandidatesSignalCreatesSessionGrantAndForwardsJavaShape()
    {
        await using var fixture = await PeerMeshFixture.CreateAsync();
        var source = fixture.AddClient(1001, "tenant-a", "alice", "alice-laptop");
        var target = fixture.AddClient(1002, "tenant-a", "alice", "alice-nas");
        fixture.AddDevice(source, "100.96.0.10", "source-key");
        fixture.AddDevice(target, "100.96.0.11", "target-key");
        await fixture.SaveChangesAsync();

        var sourceWriter = fixture.Bind(source);
        var targetWriter = fixture.Bind(target);
        var signal = JsonSerializer.Serialize(new PeerControlMessage
        {
            Type = "candidates",
            Candidates =
            [
                new PeerCandidate("host", "udp", "192.168.1.10", 53000, 0, null, null),
            ],
        });

        await fixture.Service.HandleSignalAsync(new MessageRequestPacket
        {
            ToClientName = target.ClientName,
            MessageType = MessageType.PeerControl,
            Message = signal,
        }, source.ClientName, CancellationToken.None);

        var grant = sourceWriter.SinglePeerMessage();
        Assert.Equal("session-grant", grant.Type);
        Assert.NotNull(grant.SessionId);
        Assert.False(string.IsNullOrWhiteSpace(grant.Token));
        Assert.False(string.IsNullOrWhiteSpace(grant.ExpiresAt));
        Assert.Equal(PeerMeshService.PathDirect, grant.PathType);
        Assert.Equal(PeerMeshService.StatusNegotiating, grant.Status);
        Assert.Equal(source.Id, grant.SourceClientId);
        Assert.Equal(source.ClientName, grant.SourceClientName);
        Assert.Equal("100.96.0.10", grant.SourceVirtualIp);
        Assert.Equal("source-key", grant.SourcePublicKey);
        Assert.Equal(target.Id, grant.TargetClientId);
        Assert.Equal(target.ClientName, grant.TargetClientName);
        Assert.Equal("100.96.0.11", grant.TargetVirtualIp);
        Assert.Equal("target-key", grant.TargetPublicKey);

        var forwarded = targetWriter.SinglePeerMessage();
        Assert.Equal("candidates", forwarded.Type);
        Assert.Equal(grant.SessionId, forwarded.SessionId);
        Assert.Equal(grant.Token, forwarded.Token);
        Assert.Equal(grant.ExpiresAt, forwarded.ExpiresAt);
        Assert.Equal(source.Id, forwarded.SourceClientId);
        Assert.Equal("100.96.0.10", forwarded.SourceVirtualIp);
        Assert.Equal(target.Id, forwarded.TargetClientId);
        Assert.Equal("100.96.0.11", forwarded.TargetVirtualIp);

        var stored = await fixture.Db.PeerMeshSessions.SingleAsync();
        Assert.Equal(grant.SessionId, stored.Id);
        Assert.Equal(source.Id, stored.SourceClientId);
        Assert.Equal(target.Id, stored.TargetClientId);
        Assert.Equal(PeerMeshService.PathDirect, stored.PathType);
        Assert.Equal(PeerMeshService.StatusNegotiating, stored.Status);
    }

    [Fact]
    public async Task DisablingDeviceClosesOpenSessionsAndNotifiesBothPeers()
    {
        await using var fixture = await PeerMeshFixture.CreateAsync();
        var source = fixture.AddClient(2001, "tenant-a", "alice", "alice-laptop");
        var target = fixture.AddClient(2002, "tenant-a", "alice", "alice-nas");
        fixture.AddDevice(source, "100.96.0.20", "source-key");
        fixture.AddDevice(target, "100.96.0.21", "target-key");
        var now = DateTimeOffset.UtcNow;
        fixture.Db.PeerMeshSessions.Add(new PeerMeshSession
        {
            Id = 9001,
            TenantId = "tenant-a",
            SourceClientId = source.Id,
            SourceClientName = source.ClientName,
            TargetClientId = target.Id,
            TargetClientName = target.ClientName,
            PathType = PeerMeshService.PathDirect,
            Status = PeerMeshService.StatusActive,
            StartedAt = now.AddMinutes(-1),
            UpdatedAt = now.AddMinutes(-1),
            ExpiresAt = now.AddHours(1),
        });
        await fixture.SaveChangesAsync();

        var sourceWriter = fixture.Bind(source);
        var targetWriter = fixture.Bind(target);

        await fixture.Service.UpdateDeviceAsync(
            new ManagementContext("tenant-a", "alice", ManagementRole.User, false),
            source.Id,
            new PeerMeshDeviceMutation(false),
            CancellationToken.None);

        var stored = await fixture.Db.PeerMeshSessions.SingleAsync();
        Assert.Equal(PeerMeshService.StatusClosed, stored.Status);
        Assert.NotNull(stored.ClosedAt);

        var sourceMessages = sourceWriter.PeerMessages();
        var targetMessages = targetWriter.PeerMessages();
        Assert.Contains(sourceMessages, m => m.Type == "peer-config");
        Assert.Contains(targetMessages, m => m.Type == "roster");
        Assert.Contains(sourceMessages, m => IsAdminClose(m, 9001));
        Assert.Contains(targetMessages, m => IsAdminClose(m, 9001));
    }

    [Fact]
    public async Task PathStatsAggregatesDirectRatioReportedSessionsAndNatTypes()
    {
        await using var fixture = await PeerMeshFixture.CreateAsync();
        var source = fixture.AddClient(2501, "tenant-a", "alice", "alice-laptop");
        var target = fixture.AddClient(2502, "tenant-a", "alice", "alice-nas");
        fixture.AddDevice(source, "100.96.0.30", "source-key");
        fixture.AddDevice(target, "100.96.0.31", "target-key");
        fixture.Db.PeerMeshDevices.Local.Single(d => d.ClientId == source.Id).NatType = "PORT_RESTRICTED_NAT";
        var now = DateTimeOffset.UtcNow;
        fixture.Db.PeerMeshSessions.AddRange(
            new PeerMeshSession
            {
                Id = 9201,
                TenantId = "tenant-a",
                SourceClientId = source.Id,
                SourceClientName = source.ClientName,
                TargetClientId = target.Id,
                TargetClientName = target.ClientName,
                PathType = PeerMeshService.PathDirect,
                Status = PeerMeshService.StatusActive,
                RttMillis = 10,
                DirectBytes = 100,
                RelayBytes = 5,
                StartedAt = now.AddMinutes(-2),
                UpdatedAt = now.AddMinutes(-2),
                ExpiresAt = now.AddHours(1),
            },
            new PeerMeshSession
            {
                Id = 9202,
                TenantId = "tenant-a",
                SourceClientId = target.Id,
                SourceClientName = target.ClientName,
                TargetClientId = source.Id,
                TargetClientName = source.ClientName,
                PathType = PeerMeshService.PathRelay,
                Status = PeerMeshService.StatusActive,
                RttMillis = 30,
                DirectBytes = 0,
                RelayBytes = 200,
                StartedAt = now.AddMinutes(-2),
                UpdatedAt = now.AddMinutes(-2),
                ExpiresAt = now.AddHours(1),
            },
            new PeerMeshSession
            {
                Id = 9203,
                TenantId = "tenant-a",
                SourceClientId = source.Id,
                SourceClientName = source.ClientName,
                TargetClientId = target.Id,
                TargetClientName = target.ClientName,
                PathType = PeerMeshService.PathDirect,
                Status = PeerMeshService.StatusNegotiating,
                StartedAt = now.AddMinutes(-2),
                UpdatedAt = now.AddMinutes(-2),
                ExpiresAt = now.AddHours(1),
            });
        await fixture.SaveChangesAsync();

        var stats = await fixture.Service.PathStatsAsync(
            new ManagementContext("tenant-a", "alice", ManagementRole.Admin, true),
            CancellationToken.None);

        Assert.Equal(3, stats.TotalSessions);
        Assert.Equal(2, stats.ReportedSessions);
        Assert.Equal(2, stats.ActiveSessions);
        Assert.Equal(1, stats.ActiveDirectSessions);
        Assert.Equal(1, stats.ActiveRelaySessions);
        Assert.Equal(0.5, stats.ActiveDirectRatio);
        var directActive = Assert.Single(stats.PathTypes,
            item => item.PathType == PeerMeshService.PathDirect && item.Status == PeerMeshService.StatusActive);
        Assert.Equal(1, directActive.Sessions);
        Assert.Equal(1, directActive.ReportedSessions);
        Assert.Equal(10d, directActive.AvgRttMillis);
        Assert.Equal(100, directActive.DirectBytes);
        Assert.Equal(5, directActive.RelayBytes);
        var directNegotiating = Assert.Single(stats.PathTypes,
            item => item.PathType == PeerMeshService.PathDirect
                && item.Status == PeerMeshService.StatusNegotiating);
        Assert.Equal(0, directNegotiating.ReportedSessions);
        Assert.Contains(stats.NatTypes, item => item.NatType == "PORT_RESTRICTED_NAT" && item.Devices == 1);
        Assert.Contains(stats.NatTypes, item => item.NatType == "UNKNOWN" && item.Devices == 1);
    }

    [Fact]
    public async Task RelayFrameRequiresActiveMatchingSessionAndAccountsBytes()
    {
        await using var fixture = await PeerMeshFixture.CreateAsync();
        var source = fixture.AddClient(3001, "tenant-a", "alice", "alice-laptop");
        var target = fixture.AddClient(3002, "tenant-a", "alice", "alice-nas");
        fixture.AddSession(9101, source, target, PeerMeshService.StatusActive, DateTimeOffset.UtcNow.AddHours(1));
        await fixture.SaveChangesAsync();

        var allowed = await AuthorizeRelayFrameAsync(fixture.Service, 9101, source.Id, target.Id, 7, 512);

        Assert.True(allowed);
        allowed = await AuthorizeRelayFrameAsync(fixture.Service, 9101, target.Id, source.Id, 8, 256);
        Assert.True(allowed);
        await fixture.Service.FlushRelayTrafficAsync(CancellationToken.None);

        var stored = await ReloadSessionAsync(fixture, 9101);
        Assert.Equal(768, stored.RelayBytes);
        Assert.Equal(0, stored.DirectBytes);
        Assert.NotNull(stored.LastTrafficAt);
        Assert.Equal(PeerMeshService.StatusActive, stored.Status);
        Assert.Null(stored.ClosedAt);
    }

    [Fact]
    public async Task RelayFrameRejectsWrongPeerPair()
    {
        await using var fixture = await PeerMeshFixture.CreateAsync();
        var source = fixture.AddClient(3101, "tenant-a", "alice", "alice-laptop");
        var target = fixture.AddClient(3102, "tenant-a", "alice", "alice-nas");
        fixture.AddSession(9102, source, target, PeerMeshService.StatusActive, DateTimeOffset.UtcNow.AddHours(1));
        await fixture.SaveChangesAsync();

        var allowed = await AuthorizeRelayFrameAsync(fixture.Service, 9102, source.Id, 9999, 7, 512);

        Assert.False(allowed);
        var stored = await ReloadSessionAsync(fixture, 9102);
        Assert.Equal(0, stored.RelayBytes);
        Assert.Null(stored.LastTrafficAt);
        Assert.Equal(PeerMeshService.StatusActive, stored.Status);
    }

    [Fact]
    public async Task RelayFrameRejectsExpiredSessionAndClosesIt()
    {
        await using var fixture = await PeerMeshFixture.CreateAsync();
        var source = fixture.AddClient(3201, "tenant-a", "alice", "alice-laptop");
        var target = fixture.AddClient(3202, "tenant-a", "alice", "alice-nas");
        fixture.AddSession(9103, source, target, PeerMeshService.StatusActive, DateTimeOffset.UtcNow.AddSeconds(-1));
        await fixture.SaveChangesAsync();

        var allowed = await AuthorizeRelayFrameAsync(fixture.Service, 9103, source.Id, target.Id, 7, 512);

        Assert.False(allowed);
        var stored = await ReloadSessionAsync(fixture, 9103);
        Assert.Equal(PeerMeshService.StatusClosed, stored.Status);
        Assert.NotNull(stored.ClosedAt);
        Assert.Equal(0, stored.RelayBytes);
        Assert.Null(stored.LastTrafficAt);
    }

    [Fact]
    public async Task RelayFrameRejectsNegotiatingSession()
    {
        await using var fixture = await PeerMeshFixture.CreateAsync();
        var source = fixture.AddClient(3301, "tenant-a", "alice", "alice-laptop");
        var target = fixture.AddClient(3302, "tenant-a", "alice", "alice-nas");
        fixture.AddSession(9104, source, target, PeerMeshService.StatusNegotiating, DateTimeOffset.UtcNow.AddHours(1));
        await fixture.SaveChangesAsync();

        var allowed = await AuthorizeRelayFrameAsync(fixture.Service, 9104, source.Id, target.Id, 7, 512);

        Assert.False(allowed);
        var stored = await ReloadSessionAsync(fixture, 9104);
        Assert.Equal(0, stored.RelayBytes);
        Assert.Null(stored.LastTrafficAt);
        Assert.Equal(PeerMeshService.StatusNegotiating, stored.Status);
    }

    private static async Task<bool> AuthorizeRelayFrameAsync(PeerMeshService service, long sessionId, long fromClientId,
        long toClientId, long sequence, long bytes)
    {
        var headerType = typeof(PeerMeshService).Assembly.GetType(
            "ShuaiTunnel.Server.PeerMesh.PeerDataFrameHeader", throwOnError: true)!;
        var header = Activator.CreateInstance(
            headerType,
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            args: [sessionId, fromClientId, toClientId, sequence],
            culture: null)!;
        var method = typeof(PeerMeshService).GetMethod(
            "AuthorizeRelayFrameAsync", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("AuthorizeRelayFrameAsync not found");
        var task = (Task<bool>)method.Invoke(service, [header, bytes, CancellationToken.None])!;
        return await task.ConfigureAwait(false);
    }

    private static async Task<PeerMeshSession> ReloadSessionAsync(PeerMeshFixture fixture, long id)
    {
        fixture.Db.ChangeTracker.Clear();
        return await fixture.Db.PeerMeshSessions.SingleAsync(s => s.Id == id);
    }

    private static bool IsAdminClose(PeerControlMessage message, long sessionId) =>
        message.Type == "close"
        && message.SessionId == sessionId
        && message.Status == PeerMeshService.StatusClosed
        && message.Reason == "admin-force-close";

    private sealed class PeerMeshFixture : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;

        private PeerMeshFixture(SqliteConnection connection, TunnelDbContext db, SessionRegistry registry,
            PeerMeshService service)
        {
            _connection = connection;
            Db = db;
            Registry = registry;
            Service = service;
        }

        public TunnelDbContext Db { get; }

        public SessionRegistry Registry { get; }

        public PeerMeshService Service { get; }

        public static async Task<PeerMeshFixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var options = new DbContextOptionsBuilder<TunnelDbContext>()
                .UseSqlite(connection)
                .Options;
            var db = new TunnelDbContext(options);
            await db.Database.EnsureCreatedAsync();
            var registry = new SessionRegistry(NullLogger<SessionRegistry>.Instance);
            var service = new PeerMeshService(db, registry, Options.Create(new PeerMeshOptions
            {
                Enabled = true,
                Cidr = "100.96.0.0/11",
                PublicAddress = "203.0.113.10",
                StunTurnPort = 3478,
                SessionTtlSeconds = 3600,
            }), NullLogger<PeerMeshService>.Instance);
            return new PeerMeshFixture(connection, db, registry, service);
        }

        public ClientAccount AddClient(long id, string tenantId, string owner, string clientName)
        {
            var now = DateTimeOffset.UtcNow;
            var account = new ClientAccount
            {
                Id = id,
                TenantId = tenantId,
                OwnerUsername = owner,
                ClientName = clientName,
                PasswordHash = "unused",
                Enabled = true,
                ConnectionRateLimitPerMinute = 60,
                CreatedAt = now,
                UpdatedAt = now,
            };
            Db.ClientAccounts.Add(account);
            return account;
        }

        public void AddDevice(ClientAccount account, string virtualIp, string publicKey)
        {
            var now = DateTimeOffset.UtcNow;
            Db.PeerMeshDevices.Add(new PeerMeshDevice
            {
                Id = account.Id + 10000,
                TenantId = account.TenantId,
                OwnerUsername = account.OwnerUsername ?? "admin",
                ClientId = account.Id,
                ClientName = account.ClientName,
                VirtualIp = virtualIp,
                Cidr = "100.96.0.0/11",
                PublicKey = publicKey,
                Enabled = true,
                CreatedAt = now,
                UpdatedAt = now,
            });
        }

        public void AddSession(long id, ClientAccount source, ClientAccount target, string status,
            DateTimeOffset expiresAt)
        {
            var now = DateTimeOffset.UtcNow.AddMinutes(-1);
            Db.PeerMeshSessions.Add(new PeerMeshSession
            {
                Id = id,
                TenantId = source.TenantId,
                SourceClientId = source.Id,
                SourceClientName = source.ClientName,
                TargetClientId = target.Id,
                TargetClientName = target.ClientName,
                PathType = PeerMeshService.PathDirect,
                Status = status,
                StartedAt = now,
                UpdatedAt = now,
                ExpiresAt = expiresAt,
            });
        }

        public CapturingFrameWriter Bind(ClientAccount account)
        {
            var writer = new CapturingFrameWriter();
            var context = new TunnelConnectionContext(
                $"channel-{account.Id}",
                "127.0.0.1:12345",
                writer,
                CancellationToken.None,
                static () => { },
                new ReadGate(CancellationToken.None),
                new WriteBackpressureGate(32 * 1024, 64 * 1024));
            context.OnLoginSuccess(account.ClientName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            Registry.Replace(account.ClientName, context);
            return writer;
        }

        public Task SaveChangesAsync() => Db.SaveChangesAsync();

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await _connection.DisposeAsync();
        }
    }

    private sealed class CapturingFrameWriter : IFrameWriter
    {
        private readonly List<Packet> _packets = [];

        public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        {
            _packets.Add(packet);
            return ValueTask.CompletedTask;
        }

        public PeerControlMessage SinglePeerMessage()
        {
            var messages = PeerMessages();
            Assert.Single(messages);
            return messages[0];
        }

        public List<PeerControlMessage> PeerMessages()
        {
            return _packets.Select(packet =>
            {
                var response = Assert.IsType<MessageResponsePacket>(packet);
                Assert.Equal(MessageType.PeerControl, response.MessageType);
                Assert.False(string.IsNullOrWhiteSpace(response.Message));
                return JsonSerializer.Deserialize<PeerControlMessage>(response.Message!)!;
            }).ToList();
        }
    }
}
