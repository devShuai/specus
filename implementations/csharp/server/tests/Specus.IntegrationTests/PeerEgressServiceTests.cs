using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Specus.Protocol.Packets;
using Specus.Protocol.PeerEgress;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.PeerMesh;
using Specus.Server.Sessions;

namespace Specus.IntegrationTests;

/// <summary>
/// Server-side egress authorization. The judgment layer itself is covered by the shared vectors in
/// Specus.Protocol.Tests; what is tested here is what the server grants and what it pushes.
/// </summary>
public sealed class PeerEgressServiceTests
{
    private const long ConsumerId = 1001;
    private const long EgressId = 2002;
    private const long OutsiderId = 3003;

    /// <summary>
    /// The point of keeping egress policy separate from the mesh ACL: naming a device in the egress
    /// allowlist grants nothing unless the base ACL already allows the pair.
    /// </summary>
    [Fact]
    public async Task BaseMeshAccessIsRequiredOnTopOfTheEgressAllowlist()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        var consumer = fixture.AddClient(ConsumerId, "consumer-owner", "laptop");
        var egress = fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        await fixture.SaveChangesAsync();

        await fixture.UpsertAsync(EgressId, enabled: true, consumers: [ConsumerId]);

        // No ACL yet: the allowlist names the consumer but the mesh does not let the pair meet.
        var config = await fixture.Service.BuildEgressConfigAsync(egress, Capable(), default);
        Assert.NotNull(config);
        Assert.Empty(config.AllowedConsumerClientIds!);

        fixture.AllowPeering(consumer, egress);
        await fixture.SaveChangesAsync();

        config = await fixture.Service.BuildEgressConfigAsync(egress, Capable(), default);
        Assert.NotNull(config);
        Assert.Equal([ConsumerId], config.AllowedConsumerClientIds);
    }

    /// <summary>
    /// An empty allowlist grants nothing. This is the opposite of the shared-service default, where
    /// an empty list means "everyone the mesh ACL already allows".
    /// </summary>
    [Fact]
    public async Task AnEmptyConsumerAllowlistGrantsNothing()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        var consumer = fixture.AddClient(ConsumerId, "consumer-owner", "laptop");
        var egress = fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        fixture.AllowPeering(consumer, egress);
        await fixture.SaveChangesAsync();

        await fixture.UpsertAsync(EgressId, enabled: true, consumers: []);

        var config = await fixture.Service.BuildEgressConfigAsync(egress, Capable(), default);
        Assert.NotNull(config);
        Assert.True(config.Enabled);
        Assert.Empty(config.AllowedConsumerClientIds!);
    }

    [Fact]
    public async Task ADisabledPolicyPushesAnEmptyConfig()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        var consumer = fixture.AddClient(ConsumerId, "consumer-owner", "laptop");
        var egress = fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        fixture.AllowPeering(consumer, egress);
        await fixture.SaveChangesAsync();

        await fixture.UpsertAsync(EgressId, enabled: false, consumers: [ConsumerId],
            rules: [Rule("203.0.113.0/24", "tcp", 443)]);

        var config = await fixture.Service.BuildEgressConfigAsync(egress, Capable(), default);
        Assert.NotNull(config);
        Assert.False(config.Enabled);
        Assert.Empty(config.AllowedConsumerClientIds!);
        Assert.Empty(config.DestinationRules!);
        Assert.Null(config.Limits);
    }

    [Fact]
    public async Task ClientsThatCannotDoEgressAreNeverPushedAPolicy()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        var egress = fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        await fixture.SaveChangesAsync();
        await fixture.UpsertAsync(EgressId, enabled: true, consumers: [ConsumerId]);

        Assert.Null(await fixture.Service.BuildEgressConfigAsync(egress, null, default));
        Assert.Null(await fixture.Service.BuildEgressConfigAsync(egress, new ClientEgressCapabilities(), default));
        Assert.Null(await fixture.Service.BuildEgressCatalogAsync(egress, null, default));
    }

    [Fact]
    public async Task AnEnabledPolicyPushesRulesAndLimits()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        var consumer = fixture.AddClient(ConsumerId, "consumer-owner", "laptop");
        var egress = fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        fixture.AllowPeering(consumer, egress);
        await fixture.SaveChangesAsync();

        await fixture.UpsertAsync(EgressId, enabled: true, consumers: [ConsumerId],
            rules: [Rule("203.0.113.0/24", "tcp", 443)], maxConcurrentFlows: 128, maxFlowsPerConsumer: 32,
            idleTimeoutSeconds: 45);

        var config = await fixture.Service.BuildEgressConfigAsync(egress, Capable(), default);
        Assert.NotNull(config);
        Assert.Equal(PeerMeshService.TypeEgressConfig, config.Type);
        Assert.True(config.Enabled);
        Assert.Equal(PeerEgressAuthorization.ScopePublic, config.Scope);
        Assert.Equal([ConsumerId], config.AllowedConsumerClientIds);
        var rule = Assert.Single(config.DestinationRules!);
        Assert.Equal("203.0.113.0/24", rule.Cidr);
        Assert.Equal(["tcp"], rule.Protocols);
        Assert.NotNull(config.Limits);
        Assert.Equal(128, config.Limits.MaxConcurrentFlows);
        Assert.Equal(32, config.Limits.MaxFlowsPerConsumer);
        Assert.Equal(45, config.Limits.IdleTimeoutSeconds);
        Assert.NotNull(config.Revision);
    }

    /// <summary>
    /// A consumer learns which egress nodes exist, never what they are permitted to reach.
    /// </summary>
    [Fact]
    public async Task TheCatalogueCarriesNoDestinationAllowlist()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        var consumer = fixture.AddClient(ConsumerId, "consumer-owner", "laptop");
        var egress = fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        fixture.AllowPeering(consumer, egress);
        await fixture.SaveChangesAsync();

        await fixture.UpsertAsync(EgressId, enabled: true, consumers: [ConsumerId],
            rules: [Rule("203.0.113.0/24", "tcp", 443), Rule("198.51.100.0/24", "udp", 53)]);

        var catalog = await fixture.Service.BuildEgressCatalogAsync(consumer, Capable(), default);
        Assert.NotNull(catalog);
        Assert.Equal(PeerMeshService.TypeEgressCatalog, catalog.Type);
        var entry = Assert.Single(catalog.Egresses!);
        Assert.Equal(EgressId, entry.ClientId);
        Assert.Equal("office-gateway", entry.ClientName);
        Assert.True(entry.Online);
        Assert.Equal(PeerEgressAuthorization.ScopePublic, entry.Scope);
        // Protocols travel, addresses do not.
        Assert.Equal(["tcp", "udp"], entry.Protocols);
        Assert.False(entry.DomainTargetCapable);
        Assert.False(entry.Ipv6TargetCapable);
        Assert.Null(catalog.DestinationRules);
    }

    [Fact]
    public async Task AConsumerOutsideTheAllowlistDoesNotSeeTheEgress()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        var consumer = fixture.AddClient(ConsumerId, "consumer-owner", "laptop");
        var egress = fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        var outsider = fixture.AddClient(OutsiderId, "outsider-owner", "phone");
        fixture.AllowPeering(consumer, egress);
        fixture.AllowPeering(outsider, egress);
        await fixture.SaveChangesAsync();

        await fixture.UpsertAsync(EgressId, enabled: true, consumers: [ConsumerId]);

        var catalog = await fixture.Service.BuildEgressCatalogAsync(outsider, Capable(), default);
        Assert.NotNull(catalog);
        Assert.Empty(catalog.Egresses!);
    }

    [Fact]
    public void DestinationRulesRoundTripAndRejectOversizedInput()
    {
        var rules = new[] { Rule("203.0.113.0/24", "tcp", 443) };
        var encoded = PeerMeshService.EncodeEgressDestinationRules(rules);
        Assert.Contains("203.0.113.0/24", encoded, StringComparison.Ordinal);

        var tooMany = Enumerable.Range(0, PeerMeshService.MaxEgressDestinationRules + 1)
            .Select(index => Rule($"203.0.{index}.0/24", "tcp", 443))
            .ToArray();
        Assert.Throws<ArgumentException>(() => PeerMeshService.EncodeEgressDestinationRules(tooMany));

        var oversized = Enumerable.Range(0, PeerMeshService.MaxEgressDestinationRules)
            .Select(index => new PeerEgressDestinationRule
            {
                Cidr = $"203.0.{index}.0/24",
                Protocols = ["tcp", "udp"],
                PortRanges = Enumerable.Range(1, 20).Select(port => new[] { port, port + 100 }).ToArray(),
            })
            .ToArray();
        Assert.Throws<ArgumentException>(() => PeerMeshService.EncodeEgressDestinationRules(oversized));
    }

    /// <summary>An unreadable row must deny everything rather than fall back to something permissive.</summary>
    [Fact]
    public async Task UnreadableStoredRulesDenyEverything()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        Assert.Empty(fixture.Service.DecodeEgressDestinationRules("not json at all"));
        Assert.Empty(fixture.Service.DecodeEgressDestinationRules(""));
        Assert.Empty(fixture.Service.DecodeEgressDestinationRules(null));
    }

    [Fact]
    public async Task NonAdminCannotManageEgressPolicies()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        await fixture.SaveChangesAsync();

        var user = new ManagementContext("default", "someone", ManagementRole.User, false);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            fixture.Service.UpsertEgressPolicyAsync(user,
                new PeerEgressPolicyMutation(EgressClientId: EgressId, Enabled: true), default));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            fixture.Service.DeleteEgressPolicyAsync(user, 1, default));
    }

    [Fact]
    public async Task ManagementViewSeparatesConfiguredFromEffectiveConsumers()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        var consumer = fixture.AddClient(ConsumerId, "consumer-owner", "laptop");
        var egress = fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        fixture.AddClient(OutsiderId, "outsider-owner", "phone");
        fixture.AllowPeering(consumer, egress);
        await fixture.SaveChangesAsync();

        // The outsider is named but has no mesh ACL, so it is configured and not effective.
        await fixture.UpsertAsync(EgressId, enabled: true, consumers: [ConsumerId, OutsiderId]);

        var view = Assert.Single(await fixture.Service.ListEgressPoliciesAsync(fixture.Admin, default));
        Assert.Equal([ConsumerId, OutsiderId], view.AllowedConsumerClientIds.Order());
        Assert.Equal([ConsumerId], view.EffectiveConsumerClientIds);

        await fixture.Service.DeleteEgressPolicyAsync(fixture.Admin, view.Id, default);
        Assert.Empty(await fixture.Service.ListEgressPoliciesAsync(fixture.Admin, default));
    }

    /// <summary>
    /// The server binds the reporter from the authenticated control connection, so a report that
    /// carries routing or identity of its own is a protocol violation rather than something to
    /// sanitise and accept.
    /// </summary>
    [Fact]
    public void ReportEnvelopeRejectsClientControlledRoutingAndIdentity()
    {
        PeerMeshService.ValidateEgressReportEnvelope(new MessageRequestPacket
        {
            ToClientName = "",
            Message = "{\"type\":\"egress-report\",\"revision\":1,\"activeFlows\":3}",
        });
        Assert.Throws<ArgumentException>(() => PeerMeshService.ValidateEgressReportEnvelope(
            new MessageRequestPacket
            {
                ToClientName = "peer-b",
                Message = "{\"type\":\"egress-report\",\"revision\":1}",
            }));
        string[] fields =
        [
            "sourceClientId", "sourceClientName", "sourceVirtualIp", "sourcePublicKey", "sourceKeyEpoch",
            "targetClientId", "targetClientName", "targetVirtualIp", "targetPublicKey",
            "sessionId", "token",
        ];
        foreach (var field in fields)
        {
            // An explicit null is a violation too: the field has to be absent.
            Assert.Throws<ArgumentException>(() => PeerMeshService.ValidateEgressReportEnvelope(
                new MessageRequestPacket
                {
                    ToClientName = "",
                    Message = $"{{\"type\":\"egress-report\",\"{field}\":null}}",
                }));
        }
        Assert.Throws<ArgumentException>(() => PeerMeshService.ValidateEgressReportEnvelope(
            new MessageRequestPacket
            {
                ToClientName = "",
                Message = "{\"type\":\"egress-report\",\"padding\":\"" + new string('x', 9000) + "\"}",
            }));
    }

    /// <summary>
    /// Refusals are aggregated by result code. A client that invents keys must not be able to grow
    /// what the server stores.
    /// </summary>
    [Fact]
    public void RefusalCountersKeepOnlyCodesThisBuildDefines()
    {
        var encoded = PeerMeshService.EncodeRejectedFlows(new Dictionary<string, long>
        {
            [PeerEgressCodes.DestinationDenied] = 4,
            ["EGRESS_MADE_UP"] = 9,
            [PeerEgressCodes.PortDenied] = 1,
        });
        var decoded = PeerMeshService.DecodeRejectedFlows(encoded);
        Assert.Equal(4, decoded[PeerEgressCodes.DestinationDenied]);
        Assert.Equal(1, decoded[PeerEgressCodes.PortDenied]);
        Assert.DoesNotContain("EGRESS_MADE_UP", decoded.Keys);

        Assert.Equal("{}", PeerMeshService.EncodeRejectedFlows(
            new Dictionary<string, long> { ["EGRESS_MADE_UP"] = 9 }));
        Assert.Equal("{}", PeerMeshService.EncodeRejectedFlows(null));
        // A negative counter is a client bug or an attempt to skew the view.
        Assert.Equal("{}", PeerMeshService.EncodeRejectedFlows(
            new Dictionary<string, long> { [PeerEgressCodes.PortDenied] = -3 }));

        Assert.Empty(PeerMeshService.DecodeRejectedFlows("not json"));
        Assert.Empty(PeerMeshService.DecodeRejectedFlows(""));
        Assert.Empty(PeerMeshService.DecodeRejectedFlows(null));
    }

    /// <summary>The rate table is keyed by client-driven session ids, so it needs its own ceiling.</summary>
    [Fact]
    public async Task ReportRateLimitBoundsBothTheWindowAndTheTable()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        for (var i = 0; i < 20; i++)
        {
            fixture.Service.EnforceEgressReportRate(7001);
        }
        Assert.Throws<ArgumentException>(() => fixture.Service.EnforceEgressReportRate(7001));

        // One slot is already taken above; fill the remainder.
        for (var session = 2; session <= 4096; session++)
        {
            fixture.Service.EnforceEgressReportRate(100_000 + session);
        }
        Assert.Throws<ArgumentException>(() => fixture.Service.EnforceEgressReportRate(999_999));
    }

    [Fact]
    public async Task ReportBindsIdentityAndKeepsTheNewestSnapshot()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        var egress = fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        fixture.AddOnlineSession(egress, 4201, egressVersion: 1);
        await fixture.SaveChangesAsync();

        await fixture.Service.HandleEgressReportAsync(egress, new PeerControlMessage
        {
            Type = "egress-report",
            Revision = 12,
            ActiveFlows = 18,
            TotalFlows = 2140,
            BytesIn = 10_485_760,
            BytesOut = 2_097_152,
            RejectedFlows = new Dictionary<string, long> { [PeerEgressCodes.DestinationDenied] = 4 },
        }, 4201, default);

        var view = Assert.Single(await fixture.Service.ListEgressActivityAsync(fixture.Admin, default));
        Assert.Equal(EgressId, view.EgressClientId);
        Assert.Equal(18, view.ActiveFlows);
        Assert.Equal(2140, view.TotalFlows);
        Assert.Equal(4, view.RejectedFlows[PeerEgressCodes.DestinationDenied]);
        // No live control channel, so the device must read as offline rather than stay frozen at
        // whatever it last reported.
        Assert.False(view.Online);

        await fixture.Service.HandleEgressReportAsync(egress, new PeerControlMessage
        {
            Type = "egress-report",
            Revision = 5,
            ActiveFlows = 1,
        }, 4201, default);
        view = Assert.Single(await fixture.Service.ListEgressActivityAsync(fixture.Admin, default));
        Assert.Equal(18, view.ActiveFlows);
    }

    /// <summary>
    /// A session belonging to another device, or one that never announced the capability, cannot
    /// report.
    /// </summary>
    [Fact]
    public async Task ReportRejectsAnUnboundOrIncapableSession()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        var egress = fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        var other = fixture.AddClient(OutsiderId, "outsider-owner", "phone");
        fixture.AddOnlineSession(egress, 4301, egressVersion: 1);
        fixture.AddOnlineSession(other, 4302, egressVersion: 0);
        await fixture.SaveChangesAsync();

        await Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.HandleEgressReportAsync(
            other, new PeerControlMessage { Type = "egress-report" }, 4301, default));
        await Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.HandleEgressReportAsync(
            other, new PeerControlMessage { Type = "egress-report" }, 4302, default));
    }

    /// <summary>The tenant switch and the per-device flag are two gates; both must be on.</summary>
    [Fact]
    public async Task TenantSwitchGatesEveryPolicyWithoutErasingThem()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        var consumer = fixture.AddClient(ConsumerId, "consumer-owner", "laptop");
        var egress = fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        fixture.AllowPeering(consumer, egress);
        await fixture.SaveChangesAsync();
        await fixture.UpsertAsync(EgressId, enabled: true, consumers: [ConsumerId],
            rules: [Rule("203.0.113.0/24", "tcp", 443)]);

        var status = await fixture.Service.EgressSwitchStatusAsync(fixture.Admin, default);
        Assert.True(status.ConfiguredEnabled);
        Assert.True(status.EffectiveEnabled);
        Assert.Equal(1, status.EnabledPolicyCount);

        var config = await fixture.Service.BuildEgressConfigAsync(egress, Capable(), default);
        Assert.True(config!.Enabled);

        await fixture.Service.SetEgressSwitchAsync(fixture.Admin, false, default);
        config = await fixture.Service.BuildEgressConfigAsync(egress, Capable(), default);
        Assert.False(config!.Enabled);
        var catalog = await fixture.Service.BuildEgressCatalogAsync(consumer, Capable(), default);
        Assert.Empty(catalog!.Egresses!);

        // The policies survive the switch, so turning it back on restores what was configured
        // rather than making the operator rebuild it.
        status = await fixture.Service.EgressSwitchStatusAsync(fixture.Admin, default);
        Assert.Equal(1, status.EnabledPolicyCount);
        var view = Assert.Single(await fixture.Service.ListEgressPoliciesAsync(fixture.Admin, default));
        Assert.Single(view.AllowedConsumerClientIds);
    }

    /// <summary>Only admins may flip the tenant switch, same as every other egress mutation.</summary>
    [Fact]
    public async Task OnlyAdminsCanFlipTheTenantSwitch()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        var user = new ManagementContext("default", "someone", ManagementRole.User, false);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            fixture.Service.SetEgressSwitchAsync(user, true, default));
    }

    private static ClientEgressCapabilities Capable() => new()
    {
        Version = 1,
        ConsumerCapable = true,
        EgressCapable = true,
    };

    private static PeerEgressDestinationRule Rule(string cidr, string protocol, int port) => new()
    {
        Cidr = cidr,
        Protocols = [protocol],
        PortRanges = [[port, port]],
    };

    private sealed class EgressFixture : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;

        private EgressFixture(SqliteConnection connection, SpecusDbContext db, PeerMeshService service)
        {
            _connection = connection;
            Db = db;
            Service = service;
        }

        public SpecusDbContext Db { get; }

        public PeerMeshService Service { get; }

        public ManagementContext Admin { get; } = new("default", "admin", ManagementRole.Admin, true);

        public static async Task<EgressFixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new SpecusDbContext(new DbContextOptionsBuilder<SpecusDbContext>()
                .UseSqlite(connection)
                .Options);
            await db.Database.EnsureCreatedAsync();
            var service = new PeerMeshService(db,
                new SessionRegistry(NullLogger<SessionRegistry>.Instance),
                Options.Create(new PeerMeshOptions
                {
                    Enabled = true,
                    Cidr = "100.96.0.0/11",
                    PublicAddress = "203.0.113.10",
                    SessionTtlSeconds = 3600,
                }),
                NullLogger<PeerMeshService>.Instance,
                null,
                new PeerMeshServiceState());
            return new EgressFixture(connection, db, service);
        }

        public ClientAccount AddClient(long id, string owner, string clientName)
        {
            var now = DateTimeOffset.UtcNow;
            var account = new ClientAccount
            {
                Id = id,
                TenantId = "default",
                OwnerUsername = owner,
                ClientName = clientName,
                PasswordHash = "unused",
                Enabled = true,
                ConnectionRateLimitPerMinute = 60,
                CreatedAt = now,
                UpdatedAt = now,
            };
            Db.ClientAccounts.Add(account);
            Db.PeerMeshDevices.Add(new PeerMeshDevice
            {
                Id = id + 10000,
                TenantId = account.TenantId,
                OwnerUsername = owner,
                ClientId = id,
                ClientName = clientName,
                VirtualIp = $"100.96.0.{id % 250}",
                Cidr = "100.96.0.0/11",
                Enabled = true,
                CreatedAt = now,
                UpdatedAt = now,
            });
            return account;
        }

        /// <summary>An online control session, which is where the reporter identity is bound from.</summary>
        public void AddOnlineSession(ClientAccount account, long sessionId, int egressVersion)
        {
            var now = DateTimeOffset.UtcNow;
            Db.ClientSessions.Add(new ClientSession
            {
                Id = sessionId,
                TenantId = account.TenantId,
                ClientId = account.Id,
                ClientName = account.ClientName,
                TokenHash = $"egress-report-{sessionId}",
                Status = "NETTY_ONLINE",
                MachineFingerprint = "machine",
                OsUser = "user",
                ClientEgressVersion = egressVersion,
                HttpLoginAt = now,
                NettyConnectedAt = now,
                ExpiresAt = now.AddHours(1),
            });
        }

        public void AllowPeering(ClientAccount source, ClientAccount target)
        {
            var now = DateTimeOffset.UtcNow;
            Db.PeerMeshAcls.Add(new PeerMeshAcl
            {
                Id = (source.Id * 100) + target.Id,
                TenantId = source.TenantId,
                OwnerUsername = source.OwnerUsername ?? "admin",
                SourceClientId = source.Id,
                SourceClientName = source.ClientName,
                TargetClientId = target.Id,
                TargetClientName = target.ClientName,
                Allowed = true,
                Direction = PeerMeshService.DirectionBoth,
                CreatedAt = now,
                UpdatedAt = now,
            });
        }

        /// <summary>
        /// The tenant switch is off by default, so any fixture expecting a policy to take effect has
        /// to turn it on. That default is the point: egress is opt-in for the tenant as well as per
        /// device.
        /// </summary>
        public async Task UpsertAsync(long egressClientId, bool enabled, IReadOnlyList<long> consumers,
            IReadOnlyList<PeerEgressDestinationRule>? rules = null, int? maxConcurrentFlows = null,
            int? maxFlowsPerConsumer = null, int? idleTimeoutSeconds = null)
        {
            await Service.SetEgressSwitchAsync(Admin, true, default).ConfigureAwait(false);
            await Service.UpsertEgressPolicyAsync(Admin, new PeerEgressPolicyMutation(
                EgressClientId: egressClientId,
                Enabled: enabled,
                Scope: PeerEgressAuthorization.ScopePublic,
                AllowedConsumerClientIds: consumers,
                DestinationRules: rules ?? [],
                MaxConcurrentFlows: maxConcurrentFlows,
                MaxFlowsPerConsumer: maxFlowsPerConsumer,
                IdleTimeoutSeconds: idleTimeoutSeconds), default).ConfigureAwait(false);
        }

        public Task SaveChangesAsync() => Db.SaveChangesAsync();

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await _connection.DisposeAsync();
        }
    }
}
