using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Specus.Protocol.PeerEgress;
using Specus.Server.Authentication;
using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.Server.PeerMesh;

/// <summary>
/// Egress authorization: storage-backed policy, management mutations and the payloads pushed to
/// clients.
/// </summary>
/// <remarks>
/// Kept in its own file because it answers a different question from the mesh ACL: that one decides
/// whether two devices may see each other, this one decides whether one of them may be used as a
/// way out to the wider network. Effective permission is the intersection.
/// </remarks>
public sealed partial class PeerMeshService
{
    /// <summary>Caps a stored allowlist; enforced before persisting.</summary>
    internal const int MaxEgressDestinationRules = 64;

    /// <summary>Matches the column width in every schema dialect.</summary>
    internal const int MaxEgressDestinationRulesBytes = 4096;

    private static readonly JsonSerializerOptions EgressRuleJsonOptions = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// Reports whether a client can take part at all. Version 0 or absent means the server must not
    /// push egress-config or egress-catalog to it.
    /// </summary>
    public static bool EgressSupported(ClientEgressCapabilities? capabilities) =>
        capabilities is not null && capabilities.Version >= 1;

    /// <summary>
    /// Sends the current egress-config and egress-catalog to one device.
    /// </summary>
    /// <remarks>
    /// A client that announced no egress capability at login gets nothing, so a runtime that would
    /// not understand the payload never receives it.
    /// </remarks>
    public async Task PushEgressAsync(ClientAccount account, CancellationToken cancellationToken)
    {
        if (!Enabled)
        {
            return;
        }
        var session = _sessions.Find(account.ClientName);
        if (session is null)
        {
            return;
        }
        var version = await ClientEgressVersionAsync(account, cancellationToken).ConfigureAwait(false);
        if (version < 1)
        {
            return;
        }
        var capabilities = new ClientEgressCapabilities { Version = version };

        var config = await BuildEgressConfigAsync(account, capabilities, cancellationToken).ConfigureAwait(false);
        if (config is not null)
        {
            config.SourceClientId = account.Id;
            config.SourceClientName = account.ClientName;
            config.TargetClientId = account.Id;
            config.TargetClientName = account.ClientName;
            config.CreatedAtMillis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            await SendSignalAsync(session, "server", account.ClientName, config, cancellationToken)
                .ConfigureAwait(false);
        }

        var catalog = await BuildEgressCatalogAsync(account, capabilities, cancellationToken).ConfigureAwait(false);
        if (catalog is not null)
        {
            catalog.SourceClientId = account.Id;
            catalog.SourceClientName = account.ClientName;
            catalog.TargetClientId = account.Id;
            catalog.TargetClientName = account.ClientName;
            catalog.CreatedAtMillis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            await SendSignalAsync(session, "server", account.ClientName, catalog, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Refreshes every online device in the tenant after a policy change.
    /// </summary>
    /// <remarks>
    /// A policy change moves two things at once: what the egress node itself will accept, and which
    /// egresses its peers can see. Both sides are refreshed together so the catalogue never
    /// advertises an egress that has already stopped accepting the viewer.
    /// </remarks>
    public async Task PushTenantEgressAsync(string tenantId, CancellationToken cancellationToken)
    {
        var accounts = await _db.ClientAccounts.AsNoTracking()
            .Where(account => account.TenantId == tenantId)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        foreach (var account in accounts)
        {
            await PushEgressAsync(account, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The version the client announced on its live control-channel session, or 0 when it has none.
    /// </summary>
    /// <remarks>
    /// The maximum is projected as nullable rather than defaulted: EF cannot translate
    /// DefaultIfEmpty over a scalar projection, and Max over an empty set throws otherwise.
    /// </remarks>
    private async Task<int> ClientEgressVersionAsync(ClientAccount account, CancellationToken cancellationToken)
    {
        var version = await _db.ClientSessions.AsNoTracking()
            .Where(row => row.TenantId == account.TenantId
                && row.ClientId == account.Id
                && row.Status == "NETTY_ONLINE")
            .MaxAsync(row => (int?)row.ClientEgressVersion, cancellationToken)
            .ConfigureAwait(false);
        return version ?? 0;
    }

    /// <summary>Returns every policy in the tenant as a management view.</summary>
    public async Task<IReadOnlyList<PeerMeshEgressPolicyView>> ListEgressPoliciesAsync(ManagementContext context,
        CancellationToken cancellationToken)
    {
        var rows = await _db.PeerMeshEgressPolicies.AsNoTracking()
            .Where(row => row.TenantId == context.TenantId)
            .OrderBy(row => row.EgressClientName)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        var views = new List<PeerMeshEgressPolicyView>(rows.Count);
        foreach (var row in rows)
        {
            views.Add(await ToEgressViewAsync(row, cancellationToken).ConfigureAwait(false));
        }
        return views;
    }

    /// <summary>Creates or updates the policy for one egress device.</summary>
    public async Task<PeerMeshEgressPolicyView> UpsertEgressPolicyAsync(ManagementContext context,
        PeerEgressPolicyMutation mutation, CancellationToken cancellationToken)
    {
        RequireEgressAdmin(context);
        var egressClientId = mutation.EgressClientId
            ?? throw new ArgumentException("egressClientId is required");
        var egress = await FindEgressClientOrNullAsync(context.TenantId, egressClientId, cancellationToken)
                .ConfigureAwait(false)
            ?? throw new ArgumentException($"client not found: {egressClientId}");

        var policy = await _db.PeerMeshEgressPolicies
            .FirstOrDefaultAsync(row => row.TenantId == context.TenantId && row.EgressClientId == egress.Id,
                cancellationToken)
            .ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        var creating = policy is null;
        if (policy is null)
        {
            policy = new PeerMeshEgressPolicy
            {
                Id = ClientIdGenerator.NewId(),
                TenantId = context.TenantId,
                CreatedAt = now,
            };
            _db.PeerMeshEgressPolicies.Add(policy);
        }
        policy.OwnerUsername = context.Username;
        policy.EgressClientId = egress.Id;
        policy.EgressClientName = egress.ClientName;

        if (mutation.Enabled is not null)
        {
            policy.Enabled = mutation.Enabled.Value;
        }
        if (mutation.Scope is not null)
        {
            var scope = mutation.Scope.Trim().ToUpperInvariant();
            if (scope is not (PeerEgressAuthorization.ScopePublic or PeerEgressAuthorization.ScopeLan))
            {
                throw new ArgumentException($"invalid scope: {mutation.Scope}");
            }
            policy.Scope = scope;
        }
        if (mutation.AllowedConsumerClientIds is not null)
        {
            policy.AllowedConsumerClientIds = EncodeClientIds(mutation.AllowedConsumerClientIds);
        }
        if (mutation.DestinationRules is not null)
        {
            policy.DestinationRules = EncodeEgressDestinationRules(mutation.DestinationRules);
        }
        if (mutation.MaxConcurrentFlows is not null)
        {
            policy.MaxConcurrentFlows = RequirePositive(mutation.MaxConcurrentFlows.Value, "maxConcurrentFlows");
        }
        if (mutation.MaxFlowsPerConsumer is not null)
        {
            policy.MaxFlowsPerConsumer = RequirePositive(mutation.MaxFlowsPerConsumer.Value, "maxFlowsPerConsumer");
        }
        if (mutation.IdleTimeoutSeconds is not null)
        {
            policy.IdleTimeoutSeconds = RequirePositive(mutation.IdleTimeoutSeconds.Value, "idleTimeoutSeconds");
        }
        policy.UpdatedAt = now;

        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        Audit("egress-policy", context.TenantId, egress.Id, null, null, creating ? "created" : "updated");
        // Revoking or narrowing a grant has to take effect now, not at the peer next login.
        await PushTenantEgressAsync(context.TenantId, cancellationToken).ConfigureAwait(false);
        return await ToEgressViewAsync(policy, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Removes a policy. New flows stop being authorised immediately; flows already established
    /// under it are torn down when the egress node next applies a configuration push.
    /// </summary>
    public async Task DeleteEgressPolicyAsync(ManagementContext context, long id,
        CancellationToken cancellationToken)
    {
        RequireEgressAdmin(context);
        var policy = await _db.PeerMeshEgressPolicies
                .FirstOrDefaultAsync(row => row.TenantId == context.TenantId && row.Id == id, cancellationToken)
                .ConfigureAwait(false)
            ?? throw new ArgumentException($"egress policy not found: {id}");
        _db.PeerMeshEgressPolicies.Remove(policy);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        Audit("egress-policy", context.TenantId, policy.EgressClientId, null, null, "deleted");
        await PushTenantEgressAsync(context.TenantId, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Produces the egress-config pushed to an egress device.
    /// </summary>
    /// <returns>
    /// <c>null</c> when the client cannot take part, so callers never push a half-formed policy to
    /// a runtime that would not understand it.
    /// </returns>
    public async Task<PeerControlMessage?> BuildEgressConfigAsync(ClientAccount account,
        ClientEgressCapabilities? capabilities, CancellationToken cancellationToken)
    {
        if (!EgressSupported(capabilities))
        {
            return null;
        }
        var message = new PeerControlMessage
        {
            Type = TypeEgressConfig,
            Revision = _state.NextEgressRevision(),
        };
        var policy = await _db.PeerMeshEgressPolicies.AsNoTracking()
            .FirstOrDefaultAsync(row => row.TenantId == account.TenantId && row.EgressClientId == account.Id,
                cancellationToken)
            .ConfigureAwait(false);
        if (policy is not { Enabled: true } || !Enabled)
        {
            message.Enabled = false;
            message.AllowedConsumerClientIds = [];
            message.DestinationRules = [];
            return message;
        }
        message.Enabled = true;
        message.Scope = policy.Scope;
        message.AllowedConsumerClientIds =
            await AllowedEgressConsumerIdsAsync(account, policy, cancellationToken).ConfigureAwait(false);
        message.DestinationRules = DecodeEgressDestinationRules(policy.DestinationRules);
        message.Limits = new PeerEgressLimits
        {
            MaxConcurrentFlows = policy.MaxConcurrentFlows,
            MaxFlowsPerConsumer = policy.MaxFlowsPerConsumer,
            IdleTimeoutSeconds = policy.IdleTimeoutSeconds,
        };
        return message;
    }

    /// <summary>Produces the egress-catalog pushed to a consumer device.</summary>
    public async Task<PeerControlMessage?> BuildEgressCatalogAsync(ClientAccount account,
        ClientEgressCapabilities? capabilities, CancellationToken cancellationToken)
    {
        if (!EgressSupported(capabilities))
        {
            return null;
        }
        var entries = new List<PeerEgressCatalogEntry>();
        var message = new PeerControlMessage
        {
            Type = TypeEgressCatalog,
            Revision = _state.NextEgressRevision(),
            Egresses = entries,
        };
        if (!Enabled)
        {
            return message;
        }
        var policies = await _db.PeerMeshEgressPolicies.AsNoTracking()
            .Where(row => row.TenantId == account.TenantId && row.Enabled && row.EgressClientId != account.Id)
            .OrderBy(row => row.EgressClientName)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        foreach (var policy in policies)
        {
            var egress = await FindEgressClientOrNullAsync(account.TenantId, policy.EgressClientId, cancellationToken)
                .ConfigureAwait(false);
            if (egress is null || !await CanPeerAsync(account, egress, cancellationToken).ConfigureAwait(false))
            {
                continue;
            }
            var consumers = await AllowedEgressConsumerIdsAsync(egress, policy, cancellationToken)
                .ConfigureAwait(false);
            if (!consumers.Contains(account.Id))
            {
                continue;
            }
            var online = await _db.PeerMeshDevices.AsNoTracking()
                .AnyAsync(device => device.TenantId == account.TenantId
                    && device.ClientId == policy.EgressClientId && device.Enabled, cancellationToken)
                .ConfigureAwait(false);
            entries.Add(new PeerEgressCatalogEntry
            {
                ClientId = policy.EgressClientId,
                ClientName = policy.EgressClientName,
                Online = online,
                Scope = policy.Scope,
                Protocols = EgressProtocols(DecodeEgressDestinationRules(policy.DestinationRules)),
                // Both stay false until domain rules and an IPv6 data plane ship.
                DomainTargetCapable = false,
                Ipv6TargetCapable = false,
            });
        }
        return message;
    }

    /// <summary>
    /// Intersects the policy allowlist with the base Peer ACL.
    /// </summary>
    /// <remarks>
    /// Taking the intersection here, rather than only on the egress node, keeps the two failure
    /// modes aligned: a device that cannot see the egress in its catalogue also cannot reach it on
    /// the data plane.
    /// </remarks>
    private async Task<IReadOnlyList<long>> AllowedEgressConsumerIdsAsync(ClientAccount egress,
        PeerMeshEgressPolicy policy, CancellationToken cancellationToken)
    {
        if (!policy.Enabled)
        {
            return [];
        }
        var configured = DecodeClientIds(policy.AllowedConsumerClientIds);
        if (configured.Count == 0)
        {
            // An empty consumer allowlist grants nothing. Note this is the opposite of the shared
            // service default, where an empty list means "everyone the mesh ACL already allows".
            // Egress has to be chosen on both sides: reading a blank field as "anyone" would turn a
            // device into the whole tenant's way out.
            return [];
        }
        var candidates = await _db.ClientAccounts.AsNoTracking()
            .Where(row => row.TenantId == egress.TenantId && row.Id != egress.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        var allowed = new List<long>(configured.Count);
        foreach (var candidate in candidates)
        {
            if (!configured.Contains(candidate.Id) || allowed.Contains(candidate.Id))
            {
                continue;
            }
            if (await CanPeerAsync(candidate, egress, cancellationToken).ConfigureAwait(false))
            {
                allowed.Add(candidate.Id);
            }
        }
        return allowed;
    }

    private async Task<PeerMeshEgressPolicyView> ToEgressViewAsync(PeerMeshEgressPolicy policy,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<long> effective = [];
        var egress = await FindEgressClientOrNullAsync(policy.TenantId, policy.EgressClientId, cancellationToken)
            .ConfigureAwait(false);
        if (egress is not null)
        {
            effective = await AllowedEgressConsumerIdsAsync(egress, policy, cancellationToken)
                .ConfigureAwait(false);
        }
        return new PeerMeshEgressPolicyView(
            policy.Id,
            policy.EgressClientId,
            policy.EgressClientName,
            policy.Enabled,
            policy.Scope,
            DecodeClientIds(policy.AllowedConsumerClientIds),
            effective,
            DecodeEgressDestinationRules(policy.DestinationRules),
            policy.MaxConcurrentFlows,
            policy.MaxFlowsPerConsumer,
            policy.IdleTimeoutSeconds,
            policy.CreatedAt.ToString("O"),
            policy.UpdatedAt.ToString("O"));
    }

    private Task<ClientAccount?> FindEgressClientOrNullAsync(string tenantId, long clientId,
        CancellationToken cancellationToken) =>
        _db.ClientAccounts.AsNoTracking()
            .FirstOrDefaultAsync(row => row.TenantId == tenantId && row.Id == clientId, cancellationToken);

    /// <summary>Serialises an allowlist for storage.</summary>
    internal static string EncodeEgressDestinationRules(IReadOnlyList<PeerEgressDestinationRule> rules)
    {
        if (rules.Count == 0)
        {
            return "[]";
        }
        if (rules.Count > MaxEgressDestinationRules)
        {
            throw new ArgumentException($"too many destination rules: {rules.Count}");
        }
        var encoded = JsonSerializer.Serialize(rules, EgressRuleJsonOptions);
        if (encoded.Length > MaxEgressDestinationRulesBytes)
        {
            throw new ArgumentException("destination rules exceed the storage limit");
        }
        return encoded;
    }

    /// <summary>
    /// Reads a stored allowlist. A row that cannot be parsed denies everything rather than falling
    /// back to something permissive.
    /// </summary>
    internal IReadOnlyList<PeerEgressDestinationRule> DecodeEgressDestinationRules(string? raw)
    {
        var trimmed = raw?.Trim();
        if (string.IsNullOrEmpty(trimmed))
        {
            return [];
        }
        try
        {
            return JsonSerializer.Deserialize<List<PeerEgressDestinationRule>>(trimmed, EgressRuleJsonOptions)
                ?? [];
        }
        catch (JsonException)
        {
            _logger.LogWarning(
                "peer egress destination rules are unreadable; treating the policy as deny-all");
            return [];
        }
    }

    private static IReadOnlyList<string> EgressProtocols(IReadOnlyList<PeerEgressDestinationRule> rules)
    {
        var protocols = new List<string>(2);
        foreach (var protocol in rules.SelectMany(rule => rule.Protocols))
        {
            if (!protocols.Contains(protocol, StringComparer.Ordinal))
            {
                protocols.Add(protocol);
            }
        }
        return protocols;
    }

    private static void RequireEgressAdmin(ManagementContext context)
    {
        if (!context.IsAdmin)
        {
            throw new UnauthorizedAccessException("只有租户 ADMIN 可以管理出口授权");
        }
    }

    private static int RequirePositive(int value, string field) =>
        value > 0 ? value : throw new ArgumentException($"{field} must be positive");
}

/// <summary>
/// Mutation accepted by the management API; absent fields keep their stored value.
/// </summary>
public sealed record PeerEgressPolicyMutation(
    [property: JsonPropertyName("egressClientId")] long? EgressClientId = null,
    [property: JsonPropertyName("enabled")] bool? Enabled = null,
    [property: JsonPropertyName("scope")] string? Scope = null,
    [property: JsonPropertyName("allowedConsumerClientIds")] IReadOnlyList<long>? AllowedConsumerClientIds = null,
    [property: JsonPropertyName("destinationRules")] IReadOnlyList<PeerEgressDestinationRule>? DestinationRules = null,
    [property: JsonPropertyName("maxConcurrentFlows")] int? MaxConcurrentFlows = null,
    [property: JsonPropertyName("maxFlowsPerConsumer")] int? MaxFlowsPerConsumer = null,
    [property: JsonPropertyName("idleTimeoutSeconds")] int? IdleTimeoutSeconds = null);

/// <summary>
/// Management projection of an egress policy.
/// </summary>
/// <remarks>
/// <c>effectiveConsumerClientIds</c> is the configured allowlist already intersected with the base
/// Peer ACL, so an operator sees which devices the policy actually grants rather than which ones it
/// names.
/// </remarks>
public sealed record PeerMeshEgressPolicyView(
    [property: JsonPropertyName("id")] long Id,
    [property: JsonPropertyName("egressClientId")] long EgressClientId,
    [property: JsonPropertyName("egressClientName")] string EgressClientName,
    [property: JsonPropertyName("enabled")] bool Enabled,
    [property: JsonPropertyName("scope")] string Scope,
    [property: JsonPropertyName("allowedConsumerClientIds")] IReadOnlyList<long> AllowedConsumerClientIds,
    [property: JsonPropertyName("effectiveConsumerClientIds")] IReadOnlyList<long> EffectiveConsumerClientIds,
    [property: JsonPropertyName("destinationRules")] IReadOnlyList<PeerEgressDestinationRule> DestinationRules,
    [property: JsonPropertyName("maxConcurrentFlows")] int MaxConcurrentFlows,
    [property: JsonPropertyName("maxFlowsPerConsumer")] int MaxFlowsPerConsumer,
    [property: JsonPropertyName("idleTimeoutSeconds")] int IdleTimeoutSeconds,
    [property: JsonPropertyName("createdAt")] string CreatedAt,
    [property: JsonPropertyName("updatedAt")] string UpdatedAt);
