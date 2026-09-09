using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Specus.Protocol.PeerEgress;
using Specus.Server.Authentication;
using Specus.Protocol.Packets;
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

    /// <summary>Cap on one egress-report envelope; the report carries counters only.</summary>
    internal const int MaxEgressReportBytes = 8 * 1024;

    private const int EgressReportRateLimit = 20;
    private const int MaxEgressRateTableEntries = 4096;

    /// <summary>
    /// Rejects an egress-report envelope carrying routing or identity the server binds itself.
    /// </summary>
    /// <remarks>An explicit null counts as present: the field has to be absent.</remarks>
    internal static void ValidateEgressReportEnvelope(MessageRequestPacket request)
    {
        var message = request.Message ?? string.Empty;
        if (Encoding.UTF8.GetByteCount(message) > MaxEgressReportBytes)
        {
            throw new ArgumentException($"egress-report exceeds {MaxEgressReportBytes} bytes");
        }
        if (!string.IsNullOrWhiteSpace(request.ToClientName))
        {
            throw new ArgumentException("egress-report toClientName must be empty");
        }
        using var document = ParseReport(message);
        foreach (var field in new[]
                 {
                     "sourceClientId", "sourceClientName", "sourceVirtualIp", "sourcePublicKey",
                     "sourceKeyEpoch", "targetClientId", "targetClientName", "targetVirtualIp",
                     "targetPublicKey", "sessionId", "token",
                 })
        {
            if (document.RootElement.TryGetProperty(field, out _))
            {
                throw new ArgumentException($"egress-report {field} is server-bound");
            }
        }
    }

    private static JsonDocument ParseReport(string message)
    {
        try
        {
            var document = JsonDocument.Parse(message);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                document.Dispose();
                throw new ArgumentException("invalid egress-report");
            }
            return document;
        }
        catch (JsonException)
        {
            throw new ArgumentException("invalid egress-report");
        }
    }

    /// <summary>
    /// Bounds how often one control session may report. The table is keyed by client-driven session
    /// ids, so it carries a ceiling of its own.
    /// </summary>
    internal void EnforceEgressReportRate(long sessionId)
    {
        if (!_state.EgressReportWindows.ContainsKey(sessionId)
            && _state.EgressReportWindows.Count >= MaxEgressRateTableEntries)
        {
            throw new ArgumentException("egress-report rate limited");
        }
        var window = _state.EgressReportWindows.GetOrAdd(sessionId, static _ => new ConcurrentQueue<long>());
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var cutoff = now - 60_000;
        lock (window)
        {
            while (window.TryPeek(out var first) && first < cutoff)
            {
                window.TryDequeue(out _);
            }
            if (window.Count >= EgressReportRateLimit)
            {
                throw new ArgumentException("egress-report rate limited");
            }
            window.Enqueue(now);
        }
    }

    /// <summary>
    /// Records one egress-report.
    /// </summary>
    /// <remarks>
    /// The reporter identity and session come from the authenticated control connection, never from
    /// the message body. Counters are clamped to non-negative and refusal keys filtered to codes
    /// this build defines.
    /// </remarks>
    internal async Task HandleEgressReportAsync(ClientAccount source, PeerControlMessage report,
        long? reporterSessionId, CancellationToken cancellationToken)
    {
        var sessionId = reporterSessionId ?? 0;
        if (sessionId <= 0)
        {
            sessionId = await _db.ClientSessions.AsNoTracking()
                .Where(row => row.TenantId == source.TenantId && row.ClientId == source.Id
                    && row.Status == "NETTY_ONLINE")
                .Select(row => row.Id)
                .FirstOrDefaultAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        var session = sessionId <= 0
            ? null
            : await _db.ClientSessions.AsNoTracking()
                .FirstOrDefaultAsync(row => row.Id == sessionId, cancellationToken)
                .ConfigureAwait(false);
        if (session is null || session.ClientId != source.Id
            || !string.Equals(session.TenantId, source.TenantId, StringComparison.Ordinal)
            || session.Status != "NETTY_ONLINE")
        {
            throw new ArgumentException("egress session is not current");
        }
        if (session.ClientEgressVersion < 1)
        {
            throw new ArgumentException("client did not announce egress capability");
        }
        EnforceEgressReportRate(sessionId);

        var revision = report.Revision ?? 0;
        var activity = await _db.PeerMeshEgressActivities
            .FirstOrDefaultAsync(row => row.TenantId == source.TenantId && row.EgressClientId == source.Id,
                cancellationToken)
            .ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        if (activity is null)
        {
            activity = new PeerMeshEgressActivity
            {
                Id = ClientIdGenerator.NewId(),
                TenantId = source.TenantId,
                EgressClientId = source.Id,
                CreatedAt = now,
            };
            _db.PeerMeshEgressActivities.Add(activity);
        }
        else if (revision > 0 && revision < activity.Revision)
        {
            // Reports can overtake each other on reconnect; an older snapshot must not overwrite a
            // newer one.
            return;
        }
        activity.EgressClientName = source.ClientName;
        activity.SessionId = sessionId;
        activity.Revision = revision;
        activity.ActiveFlows = NonNegative(report.ActiveFlows);
        activity.TotalFlows = NonNegative(report.TotalFlows);
        activity.BytesIn = NonNegative(report.BytesIn);
        activity.BytesOut = NonNegative(report.BytesOut);
        activity.RejectedFlows = EncodeRejectedFlows(report.RejectedFlows);
        activity.ReportedAt = now;
        activity.UpdatedAt = now;
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Latest counters each egress device reported about itself.</summary>
    public async Task<IReadOnlyList<PeerMeshEgressActivityView>> ListEgressActivityAsync(
        ManagementContext context, CancellationToken cancellationToken)
    {
        var rows = await _db.PeerMeshEgressActivities.AsNoTracking()
            .Where(row => row.TenantId == context.TenantId)
            .OrderBy(row => row.EgressClientName)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return rows.Select(row => new PeerMeshEgressActivityView(
            row.EgressClientId,
            row.EgressClientName,
            // Resolved from the live control channel, so a node that stopped reporting shows as
            // offline instead of frozen at its last counters.
            _sessions.Find(row.EgressClientName) is not null,
            row.Revision,
            row.ActiveFlows,
            row.TotalFlows,
            DecodeRejectedFlows(row.RejectedFlows),
            row.BytesIn,
            row.BytesOut,
            row.ReportedAt.ToString("O"))).ToList();
    }

    private static long NonNegative(long? value) => value is null || value < 0 ? 0 : value.Value;

    /// <summary>
    /// Keeps only codes this build defines. Without the filter a client could grow the stored map
    /// with keys of its own invention.
    /// </summary>
    internal static string EncodeRejectedFlows(IReadOnlyDictionary<string, long>? reported)
    {
        if (reported is null || reported.Count == 0)
        {
            return "{}";
        }
        var filtered = new Dictionary<string, long>(reported.Count, StringComparer.Ordinal);
        foreach (var entry in reported)
        {
            if (!PeerEgressCodes.IsKnown(entry.Key) || entry.Value < 0)
            {
                continue;
            }
            filtered[entry.Key] = entry.Value;
        }
        if (filtered.Count == 0)
        {
            return "{}";
        }
        var encoded = JsonSerializer.Serialize(filtered, EgressRuleJsonOptions);
        // Cannot happen with known codes only; refusing beats storing a truncated map.
        return Encoding.UTF8.GetByteCount(encoded) > PeerMeshEgressActivity.MaxRejectedFlowsBytes
            ? "{}"
            : encoded;
    }

    /// <summary>
    /// Reads a stored refusal map. An unreadable row reports no refusals rather than breaking the
    /// management view.
    /// </summary>
    internal static IReadOnlyDictionary<string, long> DecodeRejectedFlows(string? raw)
    {
        var trimmed = raw?.Trim();
        if (string.IsNullOrEmpty(trimmed))
        {
            return new Dictionary<string, long>();
        }
        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, long>>(trimmed, EgressRuleJsonOptions)
                ?? new Dictionary<string, long>();
        }
        catch (JsonException)
        {
            return new Dictionary<string, long>();
        }
    }

    /// <summary>
    /// The tenant switch. Off by default: egress is opt-in for the tenant as well as per device.
    /// </summary>
    private async Task<bool> EgressEnabledForAsync(string tenantId, CancellationToken cancellationToken)
    {
        var row = await _db.PeerMeshEgressSwitches.AsNoTracking()
            .FirstOrDefaultAsync(x => x.TenantId == tenantId, cancellationToken)
            .ConfigureAwait(false);
        return row?.Enabled == true;
    }

    /// <summary>Tenant-wide egress switch, separate from the per-device flag on each policy.</summary>
    public async Task<PeerMeshEgressSwitchView> EgressSwitchStatusAsync(ManagementContext context,
        CancellationToken cancellationToken)
    {
        var row = await _db.PeerMeshEgressSwitches.AsNoTracking()
            .FirstOrDefaultAsync(x => x.TenantId == context.TenantId, cancellationToken)
            .ConfigureAwait(false);
        var enabledPolicies = await _db.PeerMeshEgressPolicies.AsNoTracking()
            .CountAsync(x => x.TenantId == context.TenantId && x.Enabled, cancellationToken)
            .ConfigureAwait(false);
        var configured = row?.Enabled == true;
        return new PeerMeshEgressSwitchView(
            Enabled,
            configured,
            Enabled && configured,
            PeerEgressProtocol.ProtocolVersion,
            enabledPolicies,
            row?.UpdatedAt.ToString("O"),
            row?.UpdatedBy);
    }

    /// <summary>
    /// Turns egress on or off for the whole tenant.
    /// </summary>
    /// <remarks>
    /// Switching off leaves every per-device policy intact, so turning it back on restores what was
    /// configured rather than making the operator rebuild it.
    /// </remarks>
    public async Task<PeerMeshEgressSwitchView> SetEgressSwitchAsync(ManagementContext context,
        bool enabled, CancellationToken cancellationToken)
    {
        RequireEgressAdmin(context);
        if (enabled && !Enabled)
        {
            throw new ArgumentException("部署端未启用 Peer Mesh，不能开启出口分流");
        }
        var row = await _db.PeerMeshEgressSwitches
            .FirstOrDefaultAsync(x => x.TenantId == context.TenantId, cancellationToken)
            .ConfigureAwait(false);
        if (row is null)
        {
            row = new PeerMeshEgressSwitch { TenantId = context.TenantId };
            _db.PeerMeshEgressSwitches.Add(row);
        }
        row.Enabled = enabled;
        row.UpdatedBy = context.Username;
        row.UpdatedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        // Turning the tenant off has to reach the peers now, like any other authorization change.
        await PushTenantEgressAsync(context.TenantId, cancellationToken).ConfigureAwait(false);
        return await EgressSwitchStatusAsync(context, cancellationToken).ConfigureAwait(false);
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
        if (policy is not { Enabled: true } || !Enabled
            || !await EgressEnabledForAsync(account.TenantId, cancellationToken).ConfigureAwait(false))
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
        if (!Enabled
            || !await EgressEnabledForAsync(account.TenantId, cancellationToken).ConfigureAwait(false))
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

/// <summary>
/// Management projection of one egress device latest self-report.
/// </summary>
/// <remarks>
/// <c>online</c> is resolved from the live control channel rather than from the report, so a node
/// that stopped reporting is shown as offline instead of frozen at its last counters.
/// </remarks>
public sealed record PeerMeshEgressActivityView(
    [property: JsonPropertyName("egressClientId")] long EgressClientId,
    [property: JsonPropertyName("egressClientName")] string EgressClientName,
    [property: JsonPropertyName("online")] bool Online,
    [property: JsonPropertyName("revision")] long Revision,
    [property: JsonPropertyName("activeFlows")] long ActiveFlows,
    [property: JsonPropertyName("totalFlows")] long TotalFlows,
    [property: JsonPropertyName("rejectedFlows")] IReadOnlyDictionary<string, long> RejectedFlows,
    [property: JsonPropertyName("bytesIn")] long BytesIn,
    [property: JsonPropertyName("bytesOut")] long BytesOut,
    [property: JsonPropertyName("reportedAt")] string ReportedAt);

/// <summary>
/// Management projection of the tenant-wide egress switch.
/// </summary>
/// <remarks>
/// The three flags are reported separately so an operator can tell why egress is off: the
/// deployment never enabled Peer Mesh, the tenant switch is down, or both are on and it is the
/// per-device policies that grant nothing.
/// </remarks>
public sealed record PeerMeshEgressSwitchView(
    [property: JsonPropertyName("deploymentEnabled")] bool DeploymentEnabled,
    [property: JsonPropertyName("configuredEnabled")] bool ConfiguredEnabled,
    [property: JsonPropertyName("effectiveEnabled")] bool EffectiveEnabled,
    [property: JsonPropertyName("protocolVersion")] int ProtocolVersion,
    [property: JsonPropertyName("enabledPolicyCount")] int EnabledPolicyCount,
    [property: JsonPropertyName("updatedAt")] string? UpdatedAt,
    [property: JsonPropertyName("updatedBy")] string? UpdatedBy);

/// <summary>Body of the switch PUT.</summary>
public sealed record PeerEgressSwitchMutation(
    [property: JsonPropertyName("enabled")] bool? Enabled = null);
