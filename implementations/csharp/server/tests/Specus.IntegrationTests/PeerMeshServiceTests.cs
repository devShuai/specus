using System.Reflection;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Networking;
using Specus.Server.PeerMesh;
using Specus.Server.Sessions;

namespace Specus.IntegrationTests;

public sealed class PeerMeshServiceTests
{
    [Fact]
    public async Task PublicStunConfigNormalizesJavaStyleHostsAndIpv6()
    {
        await using var fixture = await PeerMeshFixture.CreateAsync(
            "https://relay.example.com:8443/path",
            ["stun://stun.example.com:5349/path", "2001:db8::1"]);

        var config = fixture.Service.PublicStunConfig("ignored.example.com:8088");

        Assert.Equal("stun:relay.example.com:3478", config.SelfHostedStunServer);
        Assert.Contains("stun:stun.example.com:5349", config.StunServers);
        Assert.Contains("stun:[2001:db8::1]:3478", config.StunServers);
    }

    [Fact]
    public async Task RuntimeConfigUsesIndependentStandaloneStunEndpoint()
    {
        await using var fixture = await PeerMeshFixture.CreateAsync(
            publicAddress: "turn.example.com",
            standaloneStunAddress: "stun.example.com",
            standaloneStunPort: 5349);
        var account = fixture.AddClient(1001, "tenant-a", "alice", "alice-laptop");
        fixture.AddDevice(account, "100.96.0.10", "public-key");
        await fixture.SaveChangesAsync();

        var config = await fixture.Service.BuildRuntimeConfigAsync(account, CancellationToken.None);
        var publicStun = fixture.Service.PublicStunConfig("ignored.example.com");

        Assert.Equal("stun.example.com", config.StunHost);
        Assert.Equal(5349, config.StunPort);
        Assert.Equal("turn.example.com", config.TurnHost);
        Assert.Equal(3478, config.TurnPort);
        Assert.Equal("stun:stun.example.com:5349", publicStun.SelfHostedStunServer);
        Assert.Equal(3478, publicStun.StunTurnPort);
    }

    [Fact]
    public async Task PublicStunConfigSupportsIndependentDeploymentAndLegacyFallback()
    {
        await using var standalone = await PeerMeshFixture.CreateAsync(
            enabled: false,
            publicAddress: "turn.example.com",
            stunTurnPort: 4444,
            standaloneStunAddress: "stun.example.com",
            standaloneStunPort: 5349);

        var standaloneConfig = standalone.Service.PublicStunConfig("ignored.example.com");

        Assert.False(standaloneConfig.PeerMeshEnabled);
        Assert.Equal("stun:stun.example.com:5349", standaloneConfig.SelfHostedStunServer);
        Assert.Single(standaloneConfig.StunServers, standaloneConfig.SelfHostedStunServer);
        Assert.Equal(4444, standaloneConfig.StunTurnPort);

        await using var legacy = await PeerMeshFixture.CreateAsync(
            publicAddress: "relay.example.com",
            stunTurnPort: 4444,
            standaloneStunPort: 5349);

        var legacyConfig = legacy.Service.PublicStunConfig("ignored.example.com");

        Assert.Equal("stun:relay.example.com:4444", legacyConfig.SelfHostedStunServer);
        Assert.Equal(4444, legacyConfig.StunTurnPort);

        await using var partial = await PeerMeshFixture.CreateAsync(
            publicAddress: "relay.example.com",
            stunTurnPort: 4444,
            standaloneStunAddress: "stun.example.com",
            standaloneStunPort: 0);

        var partialConfig = partial.Service.PublicStunConfig("ignored.example.com");

        Assert.Equal("stun:relay.example.com:4444", partialConfig.SelfHostedStunServer);
    }

    [Fact]
    public async Task StandaloneAlternateStunIsPublishedForBrowserIce()
    {
        await using var fixture = await PeerMeshFixture.CreateAsync(
            enabled: false,
            standaloneStunAddress: "stun-primary.example.com",
            standaloneStunPort: 3478,
            standaloneStunAlternateAddress: "stun-alternate.example.com",
            standaloneStunAlternatePort: 3479);

        var stun = fixture.Service.PublicStunConfig("ignored.example.com");
        var ice = fixture.Service.PublicIceConfig("ignored.example.com");

        Assert.Equal(new[]
        {
            "stun:stun-primary.example.com:3478",
            "stun:stun-alternate.example.com:3479",
        }, stun.StunServers);
        Assert.Contains(ice.IceServers,
            server => server.Urls == "stun:stun-alternate.example.com:3479");
    }

    [Fact]
    public async Task DeviceReportPersistsNatBehaviorFields()
    {
        await using var fixture = await PeerMeshFixture.CreateAsync();
        var account = fixture.AddClient(1002, "tenant-a", "alice", "alice-phone");
        fixture.AddDevice(account, "100.96.0.11", "public-key");
        await fixture.SaveChangesAsync();

        await fixture.Service.HandleSignalAsync(new MessageRequestPacket
        {
            Message = JsonSerializer.Serialize(new PeerControlMessage
            {
                Type = "device-report",
                NatType = "PORT_RESTRICTED_NAT",
                NatMappingBehavior = "ENDPOINT_INDEPENDENT",
                NatFilteringBehavior = "ADDRESS_AND_PORT_DEPENDENT",
                NatBehaviorDiscovery = "RFC5780",
                LastEndpoint = "198.51.100.20:52000",
            }),
        }, account.ClientName, CancellationToken.None);

        fixture.Db.ChangeTracker.Clear();
        var stored = await fixture.Db.PeerMeshDevices.SingleAsync(d => d.ClientId == account.Id);
        var view = Assert.Single(await fixture.Service.ListDevicesAsync(
            new ManagementContext("tenant-a", "alice", ManagementRole.User, false),
            CancellationToken.None));
        Assert.Equal("ENDPOINT_INDEPENDENT", stored.NatMappingBehavior);
        Assert.Equal("ADDRESS_AND_PORT_DEPENDENT", stored.NatFilteringBehavior);
        Assert.Equal("RFC5780", stored.NatBehaviorDiscovery);
        Assert.Equal(stored.NatMappingBehavior, view.NatMappingBehavior);
        Assert.Equal(stored.NatFilteringBehavior, view.NatFilteringBehavior);
        Assert.Equal(stored.NatBehaviorDiscovery, view.NatBehaviorDiscovery);
    }

    [Fact]
    public async Task DirectionalAclAndExactTenantOwnerMatchingFollowJava()
    {
        await using var fixture = await PeerMeshFixture.CreateAsync();
        var source = fixture.AddClient(1101, "tenant-a", "Alice", "alice-laptop");
        var target = fixture.AddClient(1102, "tenant-a", "alice", "alice-nas");
        var normalizedTenantMismatch = fixture.AddClient(1103, "tenant-a ", "Alice", "other-tenant");
        fixture.AddDevice(source, "100.96.0.40", "source-key");
        fixture.AddDevice(target, "100.96.0.41", "target-key");
        fixture.AddDevice(normalizedTenantMismatch, "100.96.0.42", "other-key");
        await fixture.SaveChangesAsync();

        Assert.False(await fixture.Service.CanPeerAsync(source, target, CancellationToken.None));
        Assert.False(await fixture.Service.CanPeerAsync(source, normalizedTenantMismatch,
            CancellationToken.None));

        var admin = new ManagementContext("tenant-a", "admin", ManagementRole.Admin, false);
        var inbound = await fixture.Service.CreateAclAsync(admin,
            new PeerMeshAclMutation(source.Id, target.Id, true, "inbound"), CancellationToken.None);
        Assert.Equal(PeerMeshService.DirectionInbound, inbound.Direction);
        Assert.False(await fixture.Service.CanPeerAsync(source, target, CancellationToken.None));
        Assert.True(await fixture.Service.CanPeerAsync(target, source, CancellationToken.None));

        var outbound = await fixture.Service.CreateAclAsync(admin,
            new PeerMeshAclMutation(source.Id, target.Id, true, "OUTBOUND"), CancellationToken.None);
        Assert.Equal(PeerMeshService.DirectionOutbound, outbound.Direction);
        Assert.True(await fixture.Service.CanPeerAsync(source, target, CancellationToken.None));
        Assert.False(await fixture.Service.CanPeerAsync(target, source, CancellationToken.None));

        var both = await fixture.Service.CreateAclAsync(admin,
            new PeerMeshAclMutation(source.Id, target.Id, true, "BOTH"), CancellationToken.None);
        Assert.Equal(PeerMeshService.DirectionBoth, both.Direction);
        Assert.True(await fixture.Service.CanPeerAsync(source, target, CancellationToken.None));
        Assert.True(await fixture.Service.CanPeerAsync(target, source, CancellationToken.None));

        await Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.CreateAclAsync(admin,
            new PeerMeshAclMutation(source.Id, target.Id, true, "SIDEWAYS"), CancellationToken.None));
    }

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
    public async Task PushOnLoginRefreshesRosterForTenantPeers()
    {
        await using var fixture = await PeerMeshFixture.CreateAsync();
        var source = fixture.AddClient(2101, "tenant-a", "alice", "alice-laptop");
        var target = fixture.AddClient(2102, "tenant-a", "alice", "alice-nas");
        fixture.AddDevice(source, "100.96.0.22", "source-key");
        fixture.AddDevice(target, "100.96.0.23", "target-key");
        var now = DateTimeOffset.UtcNow;
        fixture.Db.ClientSessions.AddRange(
            new ClientSession
            {
                Id = 21021,
                TenantId = "tenant-a",
                ClientId = target.Id,
                ClientName = target.ClientName,
                Status = ClientAccountService.StatusNettyOnline,
                TokenHash = "older-capable-token",
                MachineFingerprint = "machine-a",
                OsUser = "alice",
                MessageReceiveCapable = true,
                HttpLoginAt = now.AddMinutes(-2),
                NettyConnectedAt = now.AddMinutes(-2),
                ExpiresAt = now.AddHours(1),
            },
            new ClientSession
            {
                Id = 21022,
                TenantId = "tenant-a",
                ClientId = target.Id,
                ClientName = target.ClientName,
                Status = ClientAccountService.StatusNettyOnline,
                TokenHash = "newer-incapable-token",
                MachineFingerprint = "machine-b",
                OsUser = "alice",
                HttpLoginAt = now.AddMinutes(-1),
                NettyConnectedAt = now.AddMinutes(-1),
                ExpiresAt = now.AddHours(1),
            });
        await fixture.SaveChangesAsync();

        var sourceWriter = fixture.Bind(source);
        var targetWriter = fixture.Bind(target);

        await fixture.Service.PushOnLoginAsync(source, CancellationToken.None);

        var sourceMessages = sourceWriter.PeerMessages();
        Assert.Contains(sourceMessages, message => message.Type == "peer-config"
            && message.SourceClientId == source.Id
            && message.TargetClientId == source.Id);
        Assert.Contains(sourceMessages, message => message.Type == "roster"
            && message.Peers is not null
            && message.Peers.Any(peer => peer.ClientId == target.Id
                && peer.Online
                && peer.MessageReceiveCapable));

        var targetRoster = Assert.Single(targetWriter.PeerMessages(), message => message.Type == "roster");
        Assert.Contains(targetRoster.Peers ?? [], peer => peer.ClientId == source.Id && peer.Online);
    }

    [Fact]
    public async Task PathStatsAggregatesDirectRatioReportedSessionsAndNatTypes()
    {
        await using var fixture = await PeerMeshFixture.CreateAsync();
        var source = fixture.AddClient(2501, "tenant-a", "alice", "alice-laptop");
        var target = fixture.AddClient(2502, "tenant-a", "alice", "alice-nas");
        fixture.AddDevice(source, "100.96.0.30", "source-key");
        fixture.AddDevice(target, "100.96.0.31", "target-key");
        var sourceDevice = fixture.Db.PeerMeshDevices.Local.Single(d => d.ClientId == source.Id);
        sourceDevice.NatType = "PORT_RESTRICTED_NAT";
        sourceDevice.NatMappingBehavior = "ENDPOINT_INDEPENDENT";
        sourceDevice.NatFilteringBehavior = "ADDRESS_AND_PORT_DEPENDENT";
        sourceDevice.NatBehaviorDiscovery = "RFC5780";
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
                RemoteEndpoint = "198.51.100.20:41000",
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
                RemoteEndpoint = "[2001:db8::20]:42000",
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
        Assert.Contains(stats.AddressFamilies, item => item.AddressFamily == "IPv4"
            && item.Status == PeerMeshService.StatusActive
            && item.PathType == PeerMeshService.PathDirect
            && item.Sessions == 1
            && item.ReportedSessions == 1);
        Assert.Contains(stats.AddressFamilies, item => item.AddressFamily == "IPv6"
            && item.Status == PeerMeshService.StatusActive
            && item.PathType == PeerMeshService.PathRelay
            && item.Sessions == 1
            && item.ReportedSessions == 1);
        Assert.Contains(stats.AddressFamilies, item => item.AddressFamily == "UNKNOWN"
            && item.Status == PeerMeshService.StatusNegotiating
            && item.PathType == PeerMeshService.PathDirect
            && item.Sessions == 1
            && item.ReportedSessions == 0);
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
        Assert.Equal(1, stats.NatBehaviorDevices);
        Assert.Equal(1, stats.NatBehaviorClassifiedDevices);
        Assert.Equal(1, stats.NatBehaviorSuccessRatio);
        Assert.Contains(
            stats.NatMappingBehaviors,
            item => item.Behavior == "ENDPOINT_INDEPENDENT" && item.Devices == 1);
        Assert.Contains(
            stats.NatFilteringBehaviors,
            item => item.Behavior == "ADDRESS_AND_PORT_DEPENDENT" && item.Devices == 1);
        Assert.Contains(
            stats.NatBehaviorDiscoveries,
            item => item.Behavior == "RFC5780" && item.Devices == 1);
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
    public async Task EffectivePathTypeUsesBusinessTrafficDominance()
    {
        await using var fixture = await PeerMeshFixture.CreateAsync();
        var source = fixture.AddClient(3401, "tenant-a", "alice", "alice-laptop");
        var target = fixture.AddClient(3402, "tenant-a", "alice", "alice-nas");
        fixture.AddSession(9401, source, target, PeerMeshService.StatusActive, DateTimeOffset.UtcNow.AddHours(1));
        await fixture.SaveChangesAsync();

        await fixture.Service.HandleSignalAsync(new MessageRequestPacket
        {
            MessageType = MessageType.PeerControl,
            Message = JsonSerializer.Serialize(new PeerControlMessage
            {
                Type = "traffic-report",
                SessionId = 9401,
                DirectBytes = 20_000,
                RelayBytes = 5_800_000,
            }),
        }, source.ClientName, CancellationToken.None);
        await fixture.Service.HandleSignalAsync(new MessageRequestPacket
        {
            MessageType = MessageType.PeerControl,
            Message = JsonSerializer.Serialize(new PeerControlMessage
            {
                Type = "path-report",
                SessionId = 9401,
                PathType = PeerMeshService.PathDirect,
                Status = PeerMeshService.StatusActive,
                RttMillis = 7,
            }),
        }, source.ClientName, CancellationToken.None);

        var stored = await ReloadSessionAsync(fixture, 9401);
        Assert.Equal(PeerMeshService.PathRelay, stored.PathType);

        var sessions = await fixture.Service.ListSessionsAsync(
            new ManagementContext("tenant-a", "alice", ManagementRole.Admin, true),
            10,
            CancellationToken.None);
        var view = Assert.Single(sessions);
        Assert.Equal(PeerMeshService.PathRelay, view.PathType);
        Assert.Equal(20_000, view.DirectBytes);
        Assert.Equal(5_800_000, view.RelayBytes);

        var stats = await fixture.Service.PathStatsAsync(
            new ManagementContext("tenant-a", "alice", ManagementRole.Admin, true),
            CancellationToken.None);
        Assert.Equal(1, stats.ActiveSessions);
        Assert.Equal(0, stats.ActiveDirectSessions);
        Assert.Equal(1, stats.ActiveRelaySessions);
        Assert.Equal(0d, stats.ActiveDirectRatio);
        var relayActive = Assert.Single(stats.PathTypes,
            item => item.PathType == PeerMeshService.PathRelay && item.Status == PeerMeshService.StatusActive);
        Assert.Equal(1, relayActive.Sessions);
        Assert.Equal(1, relayActive.ReportedSessions);
        Assert.Equal(20_000, relayActive.DirectBytes);
        Assert.Equal(5_800_000, relayActive.RelayBytes);
        Assert.DoesNotContain(stats.PathTypes,
            item => item.PathType == PeerMeshService.PathDirect && item.Status == PeerMeshService.StatusActive);
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
    public async Task RelayFrameActivatesNegotiatingSession()
    {
        // Probes are allowed while NEGOTIATING but business frames used to require ACTIVE, which
        // is only written by an asynchronous path-report. Clients flush queued data right after a
        // successful probe, so those frames raced ahead of the report and were dropped; peer app
        // messages have no retransmission, so this surfaced as "relay connected but file send fails".
        await using var fixture = await PeerMeshFixture.CreateAsync();
        var source = fixture.AddClient(3301, "tenant-a", "alice", "alice-laptop");
        var target = fixture.AddClient(3302, "tenant-a", "alice", "alice-nas");
        fixture.AddSession(9104, source, target, PeerMeshService.StatusNegotiating, DateTimeOffset.UtcNow.AddHours(1));
        await fixture.SaveChangesAsync();

        var allowed = await AuthorizeRelayFrameAsync(fixture.Service, 9104, source.Id, target.Id, 7, 512);

        Assert.True(allowed);
        var stored = await ReloadSessionAsync(fixture, 9104);
        Assert.Equal(PeerMeshService.StatusActive, stored.Status);
        Assert.Equal(PeerMeshService.PathRelay, stored.PathType);
    }

    [Fact]
    public async Task RelayFrameRejectsClosedSessionAndMismatchedPeers()
    {
        await using var fixture = await PeerMeshFixture.CreateAsync();
        var source = fixture.AddClient(3311, "tenant-a", "alice", "alice-laptop-2");
        var target = fixture.AddClient(3312, "tenant-a", "alice", "alice-nas-2");
        fixture.AddSession(9114, source, target, PeerMeshService.StatusClosed, DateTimeOffset.UtcNow.AddHours(1));
        fixture.AddSession(9115, source, target, PeerMeshService.StatusNegotiating, DateTimeOffset.UtcNow.AddHours(1));
        await fixture.SaveChangesAsync();

        Assert.False(await AuthorizeRelayFrameAsync(fixture.Service, 9114, source.Id, target.Id, 7, 512));
        Assert.False(await AuthorizeRelayFrameAsync(fixture.Service, 9115, source.Id, 999999, 7, 512));

        var stored = await ReloadSessionAsync(fixture, 9115);
        Assert.Equal(PeerMeshService.StatusNegotiating, stored.Status);
    }

    [Fact]
    public async Task RelayFrameAllowsUnidentifiedPeersWhenTurnAuthDisabled()
    {
        // With TURN auth disabled the allocation carries no clientId; the caller passes 0/0.
        // Rejecting that outright would make the relay unusable in that mode.
        await using var fixture = await PeerMeshFixture.CreateAsync();
        var source = fixture.AddClient(3321, "tenant-a", "alice", "alice-laptop-3");
        var target = fixture.AddClient(3322, "tenant-a", "alice", "alice-nas-3");
        fixture.AddSession(9124, source, target, PeerMeshService.StatusActive, DateTimeOffset.UtcNow.AddHours(1));
        await fixture.SaveChangesAsync();

        Assert.True(await AuthorizeRelayFrameAsync(fixture.Service, 9124, 0, 0, 7, 256));
    }

    [Fact]
    public void GeneralRelayDestinationPolicyRejectsNonPublicTargets()
    {
        // General relay destinations come straight from the browser, so anything pointing back
        // into the server's own network must be refused.
        Assert.True(StunTurnServer.IsRelayableDestination(Endpoint("203.0.113.10", 50000)));
        Assert.True(StunTurnServer.IsRelayableDestination(Endpoint("2001:db8::10", 50000)));

        Assert.False(StunTurnServer.IsRelayableDestination(Endpoint("127.0.0.1", 50000)));
        Assert.False(StunTurnServer.IsRelayableDestination(Endpoint("0.0.0.0", 50000)));
        Assert.False(StunTurnServer.IsRelayableDestination(Endpoint("192.168.1.10", 50000)));
        Assert.False(StunTurnServer.IsRelayableDestination(Endpoint("10.0.0.5", 50000)));
        Assert.False(StunTurnServer.IsRelayableDestination(Endpoint("169.254.1.10", 50000)));
        Assert.False(StunTurnServer.IsRelayableDestination(Endpoint("239.1.1.1", 50000)));
        Assert.False(StunTurnServer.IsRelayableDestination(Endpoint("fd00::1", 50000)));
        Assert.False(StunTurnServer.IsRelayableDestination(Endpoint("203.0.113.10", 0)));
        Assert.False(StunTurnServer.IsRelayableDestination(null));
        // 100.64.0.0/10 is RFC 6598 CGNAT and must be allowed: browser srflx addresses often fall
        // in it, and rejecting it would 403 CGNAT peers.
        Assert.True(StunTurnServer.IsRelayableDestination(Endpoint("100.64.0.2", 50000)));
        Assert.True(StunTurnServer.IsRelayableDestination(Endpoint("100.96.0.2", 50000)));
    }

    private static System.Net.IPEndPoint Endpoint(string host, int port) =>
        new(System.Net.IPAddress.Parse(host), port);

    private static async Task<bool> AuthorizeRelayFrameAsync(PeerMeshService service, long sessionId, long fromClientId,
        long toClientId, long sequence, long bytes)
    {
        var headerType = typeof(PeerMeshService).Assembly.GetType(
            "Specus.Server.PeerMesh.PeerDataFrameHeader", throwOnError: true)!;
        var header = Activator.CreateInstance(
            headerType,
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            args: [sessionId, sequence],
            culture: null)!;
        var method = typeof(PeerMeshService).GetMethod(
            "AuthorizeRelayFrameAsync", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("AuthorizeRelayFrameAsync not found");
        var task = (Task<bool>)method.Invoke(
            service, [header, fromClientId, toClientId, bytes, CancellationToken.None])!;
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

        private PeerMeshFixture(SqliteConnection connection, SpecusDbContext db, SessionRegistry registry,
            PeerMeshService service)
        {
            _connection = connection;
            Db = db;
            Registry = registry;
            Service = service;
        }

        public SpecusDbContext Db { get; }

        public SessionRegistry Registry { get; }

        public PeerMeshService Service { get; }

        public static async Task<PeerMeshFixture> CreateAsync(
            string publicAddress = "203.0.113.10",
            IReadOnlyList<string>? publicStunServers = null,
            string standaloneStunAddress = "",
            int standaloneStunPort = 3478,
            string standaloneStunAlternateAddress = "",
            int standaloneStunAlternatePort = 0,
            bool enabled = true,
            int stunTurnPort = 3478)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var options = new DbContextOptionsBuilder<SpecusDbContext>()
                .UseSqlite(connection)
                .Options;
            var db = new SpecusDbContext(options);
            await db.Database.EnsureCreatedAsync();
            var registry = new SessionRegistry(NullLogger<SessionRegistry>.Instance);
            var service = new PeerMeshService(db, registry, Options.Create(new PeerMeshOptions
            {
                Enabled = enabled,
                Cidr = "100.96.0.0/11",
                PublicAddress = publicAddress,
                StunTurnPort = stunTurnPort,
                StandaloneStunAddress = standaloneStunAddress,
                StandaloneStunPort = standaloneStunPort,
                StandaloneStunAlternateAddress = standaloneStunAlternateAddress,
                StandaloneStunAlternatePort = standaloneStunAlternatePort,
                PublicStunServers = publicStunServers?.ToList() ?? [],
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
            var context = new SpecusConnectionContext(
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
