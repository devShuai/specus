using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
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

        public Task UpsertAsync(long egressClientId, bool enabled, IReadOnlyList<long> consumers,
            IReadOnlyList<PeerEgressDestinationRule>? rules = null, int? maxConcurrentFlows = null,
            int? maxFlowsPerConsumer = null, int? idleTimeoutSeconds = null) =>
            Service.UpsertEgressPolicyAsync(Admin, new PeerEgressPolicyMutation(
                EgressClientId: egressClientId,
                Enabled: enabled,
                Scope: PeerEgressAuthorization.ScopePublic,
                AllowedConsumerClientIds: consumers,
                DestinationRules: rules ?? [],
                MaxConcurrentFlows: maxConcurrentFlows,
                MaxFlowsPerConsumer: maxFlowsPerConsumer,
                IdleTimeoutSeconds: idleTimeoutSeconds), default);

        public Task SaveChangesAsync() => Db.SaveChangesAsync();

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await _connection.DisposeAsync();
        }
    }
}
