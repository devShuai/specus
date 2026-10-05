using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
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

    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

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

    /// <summary>
    /// A consumer can only reject a domain rule aimed at an egress that cannot resolve names if the
    /// catalogue says which ones can. The answer comes from what each egress's online session
    /// announced; an egress with no online session is never advertised as capable, whatever it
    /// announced the last time it was connected.
    /// </summary>
    [Fact]
    public async Task TheCatalogueCarriesEachEgressAnnouncedDomainTargets()
    {
        const long PlainEgressId = 4004;
        const long OfflineEgressId = 5005;
        await using var fixture = await EgressFixture.CreateAsync();
        var consumer = fixture.AddClient(ConsumerId, "consumer-owner", "laptop");
        var resolving = fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        var plain = fixture.AddClient(PlainEgressId, "egress-owner", "plain-gateway");
        var offline = fixture.AddClient(OfflineEgressId, "egress-owner", "offline-gateway");
        foreach (var egress in new[] { resolving, plain, offline })
        {
            fixture.AllowPeering(consumer, egress);
        }
        fixture.AddOnlineSession(resolving, 4401, egressVersion: 1, domainTargets: true);
        fixture.AddOnlineSession(plain, 4402, egressVersion: 1, domainTargets: false);
        fixture.AddSession(offline, 4403, egressVersion: 1, domainTargets: true, status: "DISCONNECTED");
        await fixture.SaveChangesAsync();
        foreach (var egressId in new[] { EgressId, PlainEgressId, OfflineEgressId })
        {
            await fixture.UpsertAsync(egressId, enabled: true, consumers: [ConsumerId]);
        }

        var catalog = await fixture.Service.BuildEgressCatalogAsync(consumer, Capable(), default);

        Assert.NotNull(catalog);
        var entries = catalog.Egresses!.ToDictionary(entry => entry.ClientId);
        Assert.Equal(3, entries.Count);
        Assert.True(entries[EgressId].DomainTargetCapable);
        Assert.False(entries[PlainEgressId].DomainTargetCapable);
        Assert.False(entries[OfflineEgressId].DomainTargetCapable);
        // IPv6 targets are not announced by any client yet.
        Assert.All(entries.Values, entry => Assert.False(entry.Ipv6TargetCapable));
    }

    /// <summary>
    /// Only the newest online session speaks for the egress: one that reconnected with a build that
    /// cannot resolve names stops being advertised as able to, even while an older session row has
    /// not yet been marked disconnected.
    /// </summary>
    [Fact]
    public async Task TheNewestOnlineSessionDecidesDomainTargets()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        var consumer = fixture.AddClient(ConsumerId, "consumer-owner", "laptop");
        var egress = fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        fixture.AllowPeering(consumer, egress);
        var connected = DateTimeOffset.UtcNow;
        fixture.AddOnlineSession(egress, 4501, egressVersion: 1, domainTargets: true,
            connectedAt: connected.AddMinutes(-5));
        fixture.AddOnlineSession(egress, 4502, egressVersion: 1, domainTargets: false, connectedAt: connected);
        await fixture.SaveChangesAsync();
        await fixture.UpsertAsync(EgressId, enabled: true, consumers: [ConsumerId]);

        var catalog = await fixture.Service.BuildEgressCatalogAsync(consumer, Capable(), default);

        var entry = Assert.Single(catalog!.Egresses!);
        Assert.False(entry.DomainTargetCapable);
    }

    /// <summary>
    /// <c>egressVersion</c> is how a consumer tells an egress that cannot take a flow (an old
    /// client, 0) from one that can. It comes from what each egress's online session announced, and
    /// it is written even when 0, because a consumer reads an absent field as an old server instead.
    /// </summary>
    [Fact]
    public async Task TheCatalogueCarriesEachEgressAnnouncedVersion()
    {
        const long OldEgressId = 4004;
        const long OfflineEgressId = 5005;
        await using var fixture = await EgressFixture.CreateAsync();
        var consumer = fixture.AddClient(ConsumerId, "consumer-owner", "laptop");
        var current = fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        var old = fixture.AddClient(OldEgressId, "egress-owner", "old-gateway");
        var offline = fixture.AddClient(OfflineEgressId, "egress-owner", "offline-gateway");
        foreach (var egress in new[] { current, old, offline })
        {
            fixture.AllowPeering(consumer, egress);
        }
        fixture.AddOnlineSession(current, 4601, egressVersion: 1);
        // An old client is online but announced no clientEgressCapabilities.
        fixture.AddOnlineSession(old, 4602, egressVersion: 0);
        // It announced version 1, but that session has ended: nothing online can take the flow.
        fixture.AddSession(offline, 4603, egressVersion: 1, domainTargets: false, status: "DISCONNECTED");
        await fixture.SaveChangesAsync();
        foreach (var egressId in new[] { EgressId, OldEgressId, OfflineEgressId })
        {
            await fixture.UpsertAsync(egressId, enabled: true, consumers: [ConsumerId]);
        }

        var catalog = await fixture.Service.BuildEgressCatalogAsync(consumer, Capable(), default);

        Assert.NotNull(catalog);
        var entries = catalog.Egresses!.ToDictionary(entry => entry.ClientId);
        Assert.Equal(3, entries.Count);
        Assert.Equal(1, entries[EgressId].EgressVersion);
        Assert.Equal(0, entries[OldEgressId].EgressVersion);
        Assert.Equal(0, entries[OfflineEgressId].EgressVersion);

        // Serialised the way the server sends a control message.
        using var wire = JsonDocument.Parse(JsonSerializer.Serialize(catalog));
        var encoded = wire.RootElement.GetProperty("egresses").EnumerateArray().ToList();
        Assert.Equal(3, encoded.Count);
        Assert.All(encoded, entry =>
            Assert.True(entry.TryGetProperty("egressVersion", out _), entry.GetRawText()));
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

    public static TheoryData<string> AcceptedRuleCases => PeerEgressManagementVector.Names("accept");

    public static TheoryData<string> RefusedRuleCases => PeerEgressManagementVector.Names("reject");

    /// <summary>
    /// The shared vector: what a policy saved through the management API stores. The stored column
    /// is compared byte for byte with the reference, which is also the form the 4096-byte limit is
    /// measured on.
    /// </summary>
    [Theory]
    [MemberData(nameof(AcceptedRuleCases))]
    public async Task SavedDestinationRulesAreStoredAsTheSharedVectorSays(string name)
    {
        var vectorCase = PeerEgressManagementVector.Case("accept", name);
        await using var fixture = await EgressFixture.CreateAsync();
        fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        await fixture.SaveChangesAsync();

        var view = await fixture.Service.UpsertEgressPolicyAsync(fixture.Admin, new PeerEgressPolicyMutation(
            EgressClientId: EgressId,
            DestinationRules: VectorRules(vectorCase)), default);

        var expected = PeerEgressManagementVector.Compact(vectorCase.GetProperty("stored"));
        Assert.Equal(expected, JsonSerializer.Serialize(view.DestinationRules, WebJson));
        fixture.Db.ChangeTracker.Clear();
        var row = await fixture.Db.PeerMeshEgressPolicies.AsNoTracking().SingleAsync();
        Assert.Equal(expected, row.DestinationRules);
    }

    /// <summary>
    /// A refused case refuses the whole request: neither the update of an existing policy nor the
    /// creation of a new one saves anything, including the other fields that were valid, and
    /// nothing is left pending in the context for a later save to pick up.
    /// </summary>
    [Theory]
    [MemberData(nameof(RefusedRuleCases))]
    public async Task RefusedDestinationRulesSaveNothing(string name)
    {
        var vectorCase = PeerEgressManagementVector.Case("reject", name);
        await using var fixture = await EgressFixture.CreateAsync();
        fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        fixture.AddClient(OutsiderId, "outsider-owner", "phone");
        await fixture.SaveChangesAsync();
        await fixture.Service.UpsertEgressPolicyAsync(fixture.Admin, new PeerEgressPolicyMutation(
            EgressClientId: EgressId,
            Enabled: false,
            Scope: PeerEgressAuthorization.ScopeLan,
            DestinationRules: [Rule("192.168.1.0/24", "tcp", 22)]), default);
        fixture.Db.ChangeTracker.Clear();
        var before = await fixture.Db.PeerMeshEgressPolicies.AsNoTracking().SingleAsync();

        foreach (var egressClientId in new[] { EgressId, OutsiderId })
        {
            await Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.UpsertEgressPolicyAsync(
                fixture.Admin,
                new PeerEgressPolicyMutation(
                    EgressClientId: egressClientId,
                    Enabled: true,
                    Scope: PeerEgressAuthorization.ScopePublic,
                    AllowedConsumerClientIds: [ConsumerId],
                    DestinationRules: VectorRules(vectorCase),
                    MaxConcurrentFlows: 7),
                default));
        }

        Assert.False(fixture.Db.ChangeTracker.HasChanges());
        var after = Assert.Single(await fixture.Db.PeerMeshEgressPolicies.AsNoTracking().ToListAsync());
        Assert.Equal(before.Id, after.Id);
        Assert.False(after.Enabled);
        Assert.Equal(before.Scope, after.Scope);
        Assert.Equal(before.AllowedConsumerClientIds, after.AllowedConsumerClientIds);
        Assert.Equal(before.DestinationRules, after.DestinationRules);
        Assert.Equal(before.MaxConcurrentFlows, after.MaxConcurrentFlows);
        Assert.Equal(before.UpdatedAt, after.UpdatedAt);
    }

    public static TheoryData<string> AcceptedDomainRuleCases => PeerEgressDomainPolicyVector.Names("accept");

    public static TheoryData<string> RefusedDomainRuleCases => PeerEgressDomainPolicyVector.Names("reject");

    [Fact]
    public void DomainRuleLimitsMatchTheSharedVector()
    {
        var limits = PeerEgressDomainPolicyVector.Limits;
        Assert.Equal(PeerMeshService.MaxEgressDomainRules, limits.GetProperty("rules").GetInt32());
        Assert.Equal(PeerMeshService.MaxEgressPortRangesPerRule, limits.GetProperty("portRangesPerRule").GetInt32());
        Assert.Equal(PeerMeshService.MaxEgressDomainRulesBytes, limits.GetProperty("storedJsonBytes").GetInt32());
    }

    /// <summary>
    /// The shared domain-policy vector: what a policy saved through the management API stores. The
    /// stored column is compared byte for byte with the reference, the form the 4096-byte limit is
    /// measured on.
    /// </summary>
    [Theory]
    [MemberData(nameof(AcceptedDomainRuleCases))]
    public async Task SavedDomainRulesAreStoredAsTheSharedVectorSays(string name)
    {
        var vectorCase = PeerEgressDomainPolicyVector.Case("accept", name);
        await using var fixture = await EgressFixture.CreateAsync();
        fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        await fixture.SaveChangesAsync();

        var view = await fixture.Service.UpsertEgressPolicyAsync(fixture.Admin, new PeerEgressPolicyMutation(
            EgressClientId: EgressId,
            DomainRules: VectorDomainRules(vectorCase)), default);

        var expected = PeerEgressManagementVector.Compact(vectorCase.GetProperty("stored"));
        Assert.Equal(expected, JsonSerializer.Serialize(view.DomainRules, WebJson));
        fixture.Db.ChangeTracker.Clear();
        var row = await fixture.Db.PeerMeshEgressPolicies.AsNoTracking().SingleAsync();
        Assert.Equal(expected, row.DomainRules);
        Assert.Equal("[]", row.DestinationRules);
    }

    /// <summary>
    /// A refused domain rule list refuses the whole request: neither the update of an existing
    /// policy nor the creation of a new one saves anything.
    /// </summary>
    [Theory]
    [MemberData(nameof(RefusedDomainRuleCases))]
    public async Task RefusedDomainRulesSaveNothing(string name)
    {
        var vectorCase = PeerEgressDomainPolicyVector.Case("reject", name);
        await using var fixture = await EgressFixture.CreateAsync();
        fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        fixture.AddClient(OutsiderId, "outsider-owner", "phone");
        await fixture.SaveChangesAsync();
        await fixture.Service.UpsertEgressPolicyAsync(fixture.Admin, new PeerEgressPolicyMutation(
            EgressClientId: EgressId,
            Enabled: false,
            DomainRules: [DomainRule("example.com", "tcp", 443)]), default);
        fixture.Db.ChangeTracker.Clear();
        var before = await fixture.Db.PeerMeshEgressPolicies.AsNoTracking().SingleAsync();

        foreach (var egressClientId in new[] { EgressId, OutsiderId })
        {
            await Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.UpsertEgressPolicyAsync(
                fixture.Admin,
                new PeerEgressPolicyMutation(
                    EgressClientId: egressClientId,
                    Enabled: true,
                    DestinationRules: [Rule("203.0.113.0/24", "tcp", 443)],
                    DomainRules: VectorDomainRules(vectorCase)),
                default));
        }

        Assert.False(fixture.Db.ChangeTracker.HasChanges());
        var after = Assert.Single(await fixture.Db.PeerMeshEgressPolicies.AsNoTracking().ToListAsync());
        Assert.Equal(before.Id, after.Id);
        Assert.False(after.Enabled);
        Assert.Equal(before.DomainRules, after.DomainRules);
        Assert.Equal(before.DestinationRules, after.DestinationRules);
        Assert.Equal(before.UpdatedAt, after.UpdatedAt);
    }

    /// <summary>
    /// Omitted fields keep their stored value, domain rules included; a policy created without them
    /// stores and returns an empty list.
    /// </summary>
    [Fact]
    public async Task DomainRulesAreKeptWhenOmittedAndEmptyOnANewPolicy()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        await fixture.SaveChangesAsync();

        var created = await fixture.Service.UpsertEgressPolicyAsync(fixture.Admin,
            new PeerEgressPolicyMutation(EgressClientId: EgressId), default);
        Assert.Empty(created.DomainRules);
        Assert.Contains("\"domainRules\":[]", JsonSerializer.Serialize(created), StringComparison.Ordinal);
        fixture.Db.ChangeTracker.Clear();
        Assert.Equal("[]", (await fixture.Db.PeerMeshEgressPolicies.AsNoTracking().SingleAsync()).DomainRules);

        await fixture.Service.UpsertEgressPolicyAsync(fixture.Admin, new PeerEgressPolicyMutation(
            EgressClientId: EgressId,
            DomainRules: [new PeerEgressDomainRule { Match = " *.CDN.Example. ", Protocols = ["UDP"], PortRanges = [[443, 443]] }]),
            default);
        var kept = await fixture.Service.UpsertEgressPolicyAsync(fixture.Admin, new PeerEgressPolicyMutation(
            EgressClientId: EgressId, Scope: PeerEgressAuthorization.ScopeLan), default);
        var rule = Assert.Single(kept.DomainRules);
        Assert.Equal("*.cdn.example", rule.Match);
        Assert.Equal(["udp"], rule.Protocols);

        var cleared = await fixture.Service.UpsertEgressPolicyAsync(fixture.Admin, new PeerEgressPolicyMutation(
            EgressClientId: EgressId, DomainRules: []), default);
        Assert.Empty(cleared.DomainRules);
    }

    /// <summary>
    /// The egress-config an enabled egress receives carries the saved domain rules next to the
    /// destination rules, and an empty list when there are none, as serialised for the control
    /// channel. The disabling push keeps its shape, and the catalogue never carries them.
    /// </summary>
    [Fact]
    public async Task AnEnabledPolicyPushesItsDomainRules()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        var consumer = fixture.AddClient(ConsumerId, "consumer-owner", "laptop");
        var egress = fixture.AddClient(EgressId, "egress-owner", "office-gateway");
        fixture.AllowPeering(consumer, egress);
        await fixture.SaveChangesAsync();
        await fixture.UpsertAsync(EgressId, enabled: true, consumers: [ConsumerId],
            rules: [Rule("203.0.113.0/24", "tcp", 443)]);

        var config = await fixture.Service.BuildEgressConfigAsync(egress, Capable(), default);
        Assert.NotNull(config);
        Assert.NotNull(config.DomainRules);
        Assert.Empty(config.DomainRules);
        Assert.Contains("\"domainRules\":[]", JsonSerializer.Serialize(config), StringComparison.Ordinal);

        await fixture.Service.UpsertEgressPolicyAsync(fixture.Admin, new PeerEgressPolicyMutation(
            EgressClientId: EgressId,
            DomainRules: [DomainRule("example.com", "tcp", 443)]), default);
        config = await fixture.Service.BuildEgressConfigAsync(egress, Capable(), default);
        Assert.NotNull(config);
        var rule = Assert.Single(config.DomainRules!);
        Assert.Equal("example.com", rule.Match);
        Assert.Single(config.DestinationRules!);
        Assert.Contains(
            "\"domainRules\":[{\"match\":\"example.com\",\"protocols\":[\"tcp\"],\"portRanges\":[[443,443]]}]",
            JsonSerializer.Serialize(config), StringComparison.Ordinal);

        var catalog = await fixture.Service.BuildEgressCatalogAsync(consumer, Capable(), default);
        Assert.NotNull(catalog);
        Assert.DoesNotContain("domainRules", JsonSerializer.Serialize(catalog), StringComparison.Ordinal);

        await fixture.Service.UpsertEgressPolicyAsync(fixture.Admin,
            new PeerEgressPolicyMutation(EgressClientId: EgressId, Enabled: false), default);
        var disabled = await fixture.Service.BuildEgressConfigAsync(egress, Capable(), default);
        Assert.NotNull(disabled);
        Assert.False(disabled.Enabled);
        Assert.Null(disabled.DomainRules);
        Assert.DoesNotContain("domainRules", JsonSerializer.Serialize(disabled), StringComparison.Ordinal);
    }

    /// <summary>An unreadable stored list grants no name rather than failing the push.</summary>
    [Fact]
    public async Task UnreadableStoredDomainRulesGrantNothing()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        Assert.Empty(fixture.Service.DecodeEgressDomainRules("not json at all"));
        Assert.Empty(fixture.Service.DecodeEgressDomainRules(""));
        Assert.Empty(fixture.Service.DecodeEgressDomainRules(null));
    }

    /// <summary>
    /// A database from before domain rules: the migration adds the column with an empty list, so a
    /// policy saved before reads as granting no name.
    /// </summary>
    [Fact]
    public async Task TheMigrationGivesExistingPoliciesNoDomainRules()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new SpecusDbContext(new DbContextOptionsBuilder<SpecusDbContext>()
            .UseSqlite(connection)
            .Options);
        var migrator = db.GetService<IMigrator>();
        await migrator.MigrateAsync("20260929152403_AddClientEgressDomainTargets");
        await db.Database.ExecuteSqlRawAsync(
            "INSERT INTO peer_mesh_egress_policy (id, tenant_id, owner_username, egress_client_id, "
            + "egress_client_name, enabled, scope, allowed_consumer_client_ids, destination_rules, "
            + "max_concurrent_flows, max_flows_per_consumer, idle_timeout_seconds, created_at, updated_at) "
            + "VALUES (9001, 'default', 'admin', 2002, 'office-gateway', 1, 'PUBLIC', '', '[]', 256, 64, 60, "
            + "'2026-01-01T00:00:00.0000000+00:00', '2026-01-01T00:00:00.0000000+00:00')");

        await migrator.MigrateAsync();

        var policy = await db.PeerMeshEgressPolicies.AsNoTracking().SingleAsync();
        Assert.Equal("[]", policy.DomainRules);
    }

    /// <summary>
    /// A switch request without <c>enabled</c> used to be read as "off", turning a malformed body
    /// into the most disruptive change available. It is refused instead.
    /// </summary>
    [Fact]
    public async Task ASwitchRequestWithoutEnabledIsRefusedRatherThanReadAsOff()
    {
        await using var fixture = await EgressFixture.CreateAsync();
        await fixture.Service.SetEgressSwitchAsync(fixture.Admin, true, default);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            fixture.Service.SetEgressSwitchAsync(fixture.Admin, null, default));
        Assert.True((await fixture.Service.EgressSwitchStatusAsync(fixture.Admin, default)).ConfiguredEnabled);

        // Authorisation is still decided first, so a non-admin gets the same answer for any body.
        var user = new ManagementContext("default", "someone", ManagementRole.User, false);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            fixture.Service.SetEgressSwitchAsync(user, null, default));
    }

    /// <summary>Mapped to 404 by the management API, not to the 400 of an invalid field.</summary>
    [Fact]
    public async Task AnUnknownEgressDeviceOrPolicyIsNotFound()
    {
        await using var fixture = await EgressFixture.CreateAsync();

        await Assert.ThrowsAsync<ResourceNotFoundException>(() =>
            fixture.Service.UpsertEgressPolicyAsync(fixture.Admin,
                new PeerEgressPolicyMutation(EgressClientId: EgressId, Enabled: true), default));
        await Assert.ThrowsAsync<ResourceNotFoundException>(() =>
            fixture.Service.DeleteEgressPolicyAsync(fixture.Admin, 424242, default));
        Assert.Empty(await fixture.Db.PeerMeshEgressPolicies.AsNoTracking().ToListAsync());
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

    /// <summary>The vector's request rules, read the way the management endpoint binds its body.</summary>
    private static List<PeerEgressDestinationRule> VectorRules(JsonElement vectorCase) =>
        vectorCase.GetProperty("destinationRules").Deserialize<List<PeerEgressDestinationRule>>(WebJson)!;

    private static PeerEgressDomainRule DomainRule(string match, string protocol, int port) => new()
    {
        Match = match,
        Protocols = [protocol],
        PortRanges = [[port, port]],
    };

    /// <summary>The vector's request domain rules, read the way the management endpoint binds its body.</summary>
    private static List<PeerEgressDomainRule> VectorDomainRules(JsonElement vectorCase) =>
        vectorCase.GetProperty("domainRules").Deserialize<List<PeerEgressDomainRule>>(WebJson)!;

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

        /// <summary>
        /// An online control session, which is where the reporter identity and the announced
        /// capabilities are bound from.
        /// </summary>
        public void AddOnlineSession(ClientAccount account, long sessionId, int egressVersion,
            bool domainTargets = false, DateTimeOffset? connectedAt = null) =>
            AddSession(account, sessionId, egressVersion, domainTargets, "NETTY_ONLINE", connectedAt);

        public void AddSession(ClientAccount account, long sessionId, int egressVersion, bool domainTargets,
            string status, DateTimeOffset? connectedAt = null)
        {
            var now = connectedAt ?? DateTimeOffset.UtcNow;
            Db.ClientSessions.Add(new ClientSession
            {
                Id = sessionId,
                TenantId = account.TenantId,
                ClientId = account.Id,
                ClientName = account.ClientName,
                TokenHash = $"egress-report-{sessionId}",
                Status = status,
                MachineFingerprint = "machine",
                OsUser = "user",
                ClientEgressVersion = egressVersion,
                ClientEgressDomainTargets = domainTargets,
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
