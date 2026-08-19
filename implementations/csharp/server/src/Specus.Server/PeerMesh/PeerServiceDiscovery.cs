using System.Collections.Concurrent;
using System.Net;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Specus.Server.Authentication;
using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.Server.PeerMesh;

public sealed partial class PeerMeshService
{
    private static readonly Regex ServiceIdPattern = new("^[A-Za-z0-9._-]{8,64}$", RegexOptions.Compiled);
    private static readonly Regex PathPattern = new("^/[A-Za-z0-9._~/-]*$", RegexOptions.Compiled);
    private static readonly string[] PeerServiceApps = ["http", "https", "ssh", "tcp", "udp"];
    private readonly ConcurrentDictionary<(string TenantId, long ClientId, long SessionId), CatalogSnapshot> _serviceCatalogs = new();
    private readonly ConcurrentQueue<PeerMeshAuditEvent> _audits = new();

    public async Task<PeerMeshServiceSharingView> SharingStatusAsync(ManagementContext context,
        CancellationToken cancellationToken)
    {
        var sharing = await _db.PeerMeshServiceSharings.AsNoTracking()
            .FirstOrDefaultAsync(row => row.TenantId == context.TenantId, cancellationToken)
            .ConfigureAwait(false);
        var count = await _db.PeerMeshSharedServices.CountAsync(
                row => row.TenantId == context.TenantId && row.Enabled, cancellationToken)
            .ConfigureAwait(false);
        return new PeerMeshServiceSharingView(
            Enabled,
            sharing?.Enabled == true,
            Enabled && sharing?.Enabled == true,
            PeerServiceDiscoveryVersion,
            PeerServiceApps,
            count,
            sharing?.UpdatedAt.ToString("O"),
            sharing?.UpdatedBy,
            sharing?.MdnsImportEnabled == true);
    }

    public async Task<PeerMeshServiceSharingView> SetSharingAsync(ManagementContext context, bool enabled,
        CancellationToken cancellationToken)
    {
        return await SetSharingAsync(context, new PeerMeshSharingMutation(enabled, null), cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<PeerMeshServiceSharingView> SetSharingAsync(ManagementContext context,
        PeerMeshSharingMutation mutation, CancellationToken cancellationToken)
    {
        RequireAdmin(context);
        if (mutation.Enabled is null && mutation.MdnsImportEnabled is null)
        {
            throw new ArgumentException("enabled or mdnsImportEnabled is required");
        }
        if (mutation.Enabled == true && !Enabled)
        {
            throw new ArgumentException("部署端未启用 Peer Mesh，不能开启服务共享");
        }
        var previous = await _db.PeerMeshServiceSharings
            .FirstOrDefaultAsync(row => row.TenantId == context.TenantId, cancellationToken)
            .ConfigureAwait(false);
        var wasEnabled = previous?.Enabled == true;
        if (previous is null)
        {
            previous = new PeerMeshServiceSharing { TenantId = context.TenantId };
            _db.PeerMeshServiceSharings.Add(previous);
        }
        if (mutation.Enabled is not null)
        {
            previous.Enabled = mutation.Enabled.Value;
        }
        if (mutation.MdnsImportEnabled is not null)
        {
            previous.MdnsImportEnabled = mutation.MdnsImportEnabled.Value;
        }
        previous.UpdatedBy = context.Username;
        previous.UpdatedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        Audit("sharing-toggle", context.TenantId, null, null, null, previous.Enabled ? "enabled" : "updated");
        if (wasEnabled && mutation.Enabled == false)
        {
            await WithdrawTenantAsync(context.TenantId, cancellationToken).ConfigureAwait(false);
        }
        await PushTenantConfigsAsync(context.TenantId, cancellationToken).ConfigureAwait(false);
        return await SharingStatusAsync(context, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<PeerMeshSharedServiceView>> ListSharedServicesAsync(ManagementContext context,
        CancellationToken cancellationToken)
    {
        var query = _db.PeerMeshSharedServices.AsNoTracking().Where(row => row.TenantId == context.TenantId);
        if (!context.IsAdmin)
        {
            var ids = await _db.ClientAccounts.AsNoTracking()
                .Where(account => account.TenantId == context.TenantId && account.OwnerUsername == context.Username)
                .Select(account => account.Id)
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false);
            query = query.Where(row => ids.Contains(row.ClientId));
        }
        var rows = await query.OrderBy(row => row.ClientName).ThenBy(row => row.Name)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        var views = new List<PeerMeshSharedServiceView>();
        foreach (var row in rows)
        {
            views.Add(await ToViewAsync(row, context.IsAdmin, cancellationToken).ConfigureAwait(false));
        }
        return views;
    }

    public async Task<PeerMeshSharedServiceView> CreateSharedServiceAsync(ManagementContext context,
        PeerMeshServiceMutation mutation, CancellationToken cancellationToken)
    {
        RequireAdmin(context);
        var account = await _db.ClientAccounts
                .FirstOrDefaultAsync(row => row.TenantId == context.TenantId && row.Id == mutation.ClientId,
                    cancellationToken)
                .ConfigureAwait(false)
            ?? throw new ArgumentException("client not found");
        var serviceId = string.IsNullOrWhiteSpace(mutation.ServiceId)
            ? Guid.NewGuid().ToString()
            : RequireServiceId(mutation.ServiceId);
        if (await _db.PeerMeshSharedServices.AnyAsync(row =>
                    row.TenantId == context.TenantId && row.ClientId == account.Id && row.ServiceId == serviceId,
                cancellationToken)
            .ConfigureAwait(false))
        {
            throw new ArgumentException("serviceId already exists on this client");
        }
        var now = DateTimeOffset.UtcNow;
        var row = new PeerMeshSharedService
        {
            Id = ClientIdGenerator.NewId(),
            TenantId = context.TenantId,
            ClientId = account.Id,
            ClientName = account.ClientName,
            ServiceId = serviceId,
            CreatedAt = now,
        };
        ApplyMutation(row, mutation, creating: true);
        await RejectPortConflictAsync(row, cancellationToken).ConfigureAwait(false);
        row.UpdatedAt = now;
        _db.PeerMeshSharedServices.Add(row);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return await ToViewAsync(row, true, cancellationToken).ConfigureAwait(false);
    }

    public async Task<PeerMeshSharedServiceView> UpdateSharedServiceAsync(ManagementContext context, long id,
        PeerMeshServiceMutation mutation, CancellationToken cancellationToken)
    {
        RequireAdmin(context);
        var row = await _db.PeerMeshSharedServices
                .FirstOrDefaultAsync(item => item.TenantId == context.TenantId && item.Id == id, cancellationToken)
                .ConfigureAwait(false)
            ?? throw new ArgumentException("service not found");
        var wasEnabled = row.Enabled;
        ApplyMutation(row, mutation, creating: false);
        await RejectPortConflictAsync(row, cancellationToken).ConfigureAwait(false);
        row.UpdatedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        if (wasEnabled && !row.Enabled)
        {
            await WithdrawClientAsync(row.TenantId, row.ClientId, cancellationToken).ConfigureAwait(false);
        }
        return await ToViewAsync(row, true, cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteSharedServiceAsync(ManagementContext context, long id, CancellationToken cancellationToken)
    {
        RequireAdmin(context);
        var row = await _db.PeerMeshSharedServices
                .FirstOrDefaultAsync(item => item.TenantId == context.TenantId && item.Id == id, cancellationToken)
                .ConfigureAwait(false)
            ?? throw new ArgumentException("service not found");
        _db.PeerMeshSharedServices.Remove(row);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await WithdrawClientAsync(row.TenantId, row.ClientId, cancellationToken).ConfigureAwait(false);
    }

    internal async Task HandleServiceReportAsync(ClientAccount source, PeerControlMessage report,
        long? publisherSessionId, CancellationToken cancellationToken)
    {
        var sessionId = publisherSessionId is > 0
            ? publisherSessionId.Value
            : throw new ArgumentException("publisher session is required");
        var revision = report.Revision ?? 0;
        if (revision < 1)
        {
            throw new ArgumentException("revision must be >= 1");
        }
        var key = (source.TenantId, source.Id, sessionId);
        if (_serviceCatalogs.TryGetValue(key, out var previous) && revision <= previous.Revision)
        {
            return;
        }
        if (report.Enabled != true || !await EffectiveSharingAsync(source, cancellationToken).ConfigureAwait(false))
        {
            await WithdrawSessionAsync(source, sessionId, cancellationToken).ConfigureAwait(false);
            return;
        }
        var roster = await AllowedRosterAsync(source, cancellationToken).ConfigureAwait(false);
        if (roster.All(item => !item.Online))
        {
            return;
        }
        var advertised = await AdvertisedFromReportAsync(source, report.Services, cancellationToken)
            .ConfigureAwait(false);
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);
        _serviceCatalogs[key] = new CatalogSnapshot(revision, report.InstanceId ?? "", DateTimeOffset.UtcNow,
            expiresAt, advertised, source.ClientName, CopyStats(report.Stats, advertised),
            SanitizeMdns(report.MdnsCandidates));
        Audit("service-report", source.TenantId, source.Id, sessionId, null, advertised.Count == 0 ? "empty" : "published");
        await FanoutAsync(source, sessionId, revision, advertised, expiresAt, cancellationToken).ConfigureAwait(false);
    }

    internal static IReadOnlyList<string> DecodeApplications(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return [];
        }
        return raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(item => item.ToLowerInvariant())
            .Where(item => PeerServiceApps.Contains(item))
            .Distinct()
            .ToArray();
    }

    internal static string EncodeApplications(IEnumerable<string>? apps) =>
        string.Join(',', DecodeApplications(string.Join(',', apps ?? [])));

    internal static int NormalizeDiscoveryVersion(int version) => version < 1 ? 0 : Math.Min(version, PeerServiceDiscoveryVersion);

    private async Task<IReadOnlyList<AdvertisedService>> AdvertisedFromReportAsync(ClientAccount source,
        IReadOnlyList<AdvertisedService>? reported, CancellationToken cancellationToken)
    {
        reported ??= [];
        if (reported.Count > 32)
        {
            throw new ArgumentException("at most 32 services per session");
        }
        var definitions = await _db.PeerMeshSharedServices.AsNoTracking()
            .Where(row => row.TenantId == source.TenantId && row.ClientId == source.Id && row.Enabled)
            .ToDictionaryAsync(row => row.ServiceId, cancellationToken)
            .ConfigureAwait(false);
        var advertised = new List<AdvertisedService>();
        var seen = new HashSet<string>();
        foreach (var item in reported)
        {
            var serviceId = RequireServiceId(item.ServiceId);
            if (!seen.Add(serviceId))
            {
                throw new ArgumentException("duplicate serviceId: " + serviceId);
            }
            if (!definitions.TryGetValue(serviceId, out var definition))
            {
                continue;
            }
            advertised.Add(FromDefinition(definition));
        }
        return advertised;
    }

    private async Task FanoutAsync(ClientAccount publisher, long publisherSessionId, long revision,
        IReadOnlyList<AdvertisedService> services, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        var recipients = await _db.ClientAccounts.AsNoTracking()
            .Where(account => account.TenantId == publisher.TenantId && account.Id != publisher.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        foreach (var recipient in recipients)
        {
            if (!await CanPeerAsync(publisher, recipient, cancellationToken).ConfigureAwait(false))
            {
                continue;
            }
            var session = _sessions.Find(recipient.ClientName);
            if (session is null)
            {
                continue;
            }
            var visible = new List<AdvertisedService>();
            foreach (var service in services)
            {
                if (await VisibleToAsync(publisher, recipient, service, cancellationToken).ConfigureAwait(false))
                {
                    visible.Add(service);
                }
            }
            await SendSignalAsync(session, "server", recipient.ClientName, new PeerControlMessage
            {
                Type = TypeServiceCatalog,
                PublisherClientId = publisher.Id,
                PublisherClientName = publisher.ClientName,
                PublisherSessionId = publisherSessionId,
                Revision = revision,
                ExpiresAt = expiresAt.ToString("O"),
                Services = visible,
                CreatedAtMillis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            }, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<bool> VisibleToAsync(ClientAccount publisher, ClientAccount recipient,
        AdvertisedService service, CancellationToken cancellationToken)
    {
        var definition = await _db.PeerMeshSharedServices.AsNoTracking()
            .FirstOrDefaultAsync(row => row.TenantId == publisher.TenantId && row.ClientId == publisher.Id
                && row.ServiceId == service.ServiceId, cancellationToken)
            .ConfigureAwait(false);
        if (definition is null || !definition.Enabled)
        {
            return false;
        }
        if (string.Equals(definition.Visibility, "OWNER", StringComparison.OrdinalIgnoreCase))
        {
            return string.Equals(publisher.OwnerUsername, recipient.OwnerUsername, StringComparison.Ordinal);
        }
        var allowed = DecodeClientIds(definition.AllowedClientIds);
        return allowed.Count == 0 || allowed.Contains(recipient.Id);
    }

    private async Task WithdrawSessionAsync(ClientAccount publisher, long sessionId,
        CancellationToken cancellationToken)
    {
        _serviceCatalogs.TryRemove((publisher.TenantId, publisher.Id, sessionId), out _);
        await FanoutAsync(publisher, sessionId, 0, [], DateTimeOffset.UtcNow, cancellationToken).ConfigureAwait(false);
    }

    private async Task WithdrawClientAsync(string tenantId, long clientId, CancellationToken cancellationToken)
    {
        var account = await _db.ClientAccounts.FirstOrDefaultAsync(
                row => row.TenantId == tenantId && row.Id == clientId, cancellationToken)
            .ConfigureAwait(false);
        if (account is null)
        {
            return;
        }
        foreach (var key in _serviceCatalogs.Keys.Where(item => item.TenantId == tenantId && item.ClientId == clientId).ToArray())
        {
            await WithdrawSessionAsync(account, key.SessionId, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task WithdrawTenantAsync(string tenantId, CancellationToken cancellationToken)
    {
        foreach (var key in _serviceCatalogs.Keys.Where(item => item.TenantId == tenantId).ToArray())
        {
            var account = await _db.ClientAccounts.FirstOrDefaultAsync(
                    row => row.TenantId == tenantId && row.Id == key.ClientId, cancellationToken)
                .ConfigureAwait(false);
            if (account is not null)
            {
                await WithdrawSessionAsync(account, key.SessionId, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task PushTenantConfigsAsync(string tenantId, CancellationToken cancellationToken)
    {
        var accounts = await _db.ClientAccounts.AsNoTracking()
            .Where(account => account.TenantId == tenantId)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        foreach (var account in accounts)
        {
            await PushConfigAsync(account, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<bool> EffectiveSharingAsync(ClientAccount account, CancellationToken cancellationToken)
    {
        if (!Enabled)
        {
            return false;
        }
        var sharing = await _db.PeerMeshServiceSharings.AsNoTracking()
            .FirstOrDefaultAsync(row => row.TenantId == account.TenantId, cancellationToken)
            .ConfigureAwait(false);
        if (sharing?.Enabled != true)
        {
            return false;
        }
        var device = await _db.PeerMeshDevices.AsNoTracking()
            .FirstOrDefaultAsync(row => row.TenantId == account.TenantId && row.ClientId == account.Id,
                cancellationToken)
            .ConfigureAwait(false);
        return device?.Enabled == true;
    }

    private async Task RejectPortConflictAsync(PeerMeshSharedService row, CancellationToken cancellationToken)
    {
        if (!row.Enabled)
        {
            return;
        }
        var conflict = await _db.PeerMeshSharedServices.AnyAsync(item =>
                item.TenantId == row.TenantId && item.ClientId == row.ClientId && item.Id != row.Id
                && item.Enabled && item.PublishedPort == row.PublishedPort, cancellationToken)
            .ConfigureAwait(false);
        if (conflict)
        {
            throw new ArgumentException("publishedPort already used by another enabled service");
        }
    }

    private async Task<PeerMeshSharedServiceView> ToViewAsync(PeerMeshSharedService row, bool includeTarget,
        CancellationToken cancellationToken)
    {
        var device = await _db.PeerMeshDevices.AsNoTracking()
            .FirstOrDefaultAsync(item => item.TenantId == row.TenantId && item.ClientId == row.ClientId,
                cancellationToken)
            .ConfigureAwait(false);
        string? publishedAddress = device is { VirtualIp: { Length: > 0 } ip }
            ? $"{ip}:{row.PublishedPort}"
            : null;
        var instances = new List<PeerMeshSharedServiceInstanceView>();
        foreach (var entry in _serviceCatalogs.Where(item =>
                     item.Key.TenantId == row.TenantId && item.Key.ClientId == row.ClientId))
        {
            var snapshot = entry.Value;
            var advertisedNow = snapshot.Services.Any(item => item.ServiceId == row.ServiceId);
            var stats = snapshot.Stats.FirstOrDefault(item => item.ServiceId == row.ServiceId);
            instances.Add(new PeerMeshSharedServiceInstanceView(
                entry.Key.SessionId,
                snapshot.InstanceId,
                advertisedNow,
                advertisedNow,
                snapshot.Revision,
                snapshot.GeneratedAt.ToString("O"),
                snapshot.ExpiresAt.ToString("O"),
                stats?.BytesIn ?? 0,
                stats?.BytesOut ?? 0,
                stats?.ActiveConnections ?? 0,
                stats?.TotalConnections ?? 0));
        }
        return new PeerMeshSharedServiceView(
            row.Id, row.ServiceId, row.ClientId, row.ClientName, row.Name, row.Description, row.Transport,
            row.Application, includeTarget ? row.TargetHost : null, includeTarget ? row.TargetPort : 0,
            row.PublishedPort, row.Path, row.Enabled, row.Visibility, DecodeClientIds(row.AllowedClientIds),
            publishedAddress, instances,
            row.CreatedAt.ToString("O"), row.UpdatedAt.ToString("O"));
    }

    public IReadOnlyList<PeerMeshAuditEvent> RecentAudits(ManagementContext context) =>
        _audits.Where(item => item.TenantId == context.TenantId).Take(50).ToArray();

    public async Task<PeerMeshImportResult> ImportCandidatesAsync(ManagementContext context, long clientId,
        CancellationToken cancellationToken) =>
        await ImportCandidatesAsync(context, clientId, "tcp-http", cancellationToken).ConfigureAwait(false);

    public async Task<PeerMeshImportResult> ImportCandidatesAsync(ManagementContext context, long clientId,
        string? source, CancellationToken cancellationToken)
    {
        RequireAdmin(context);
        var account = await _db.ClientAccounts
                .FirstOrDefaultAsync(row => row.TenantId == context.TenantId && row.Id == clientId, cancellationToken)
                .ConfigureAwait(false)
            ?? throw new ArgumentException("client not found");
        if (string.Equals(source, "mdns", StringComparison.OrdinalIgnoreCase))
        {
            return await ImportMdnsAsync(context, account, cancellationToken).ConfigureAwait(false);
        }
        var existing = await _db.PeerMeshSharedServices.AsNoTracking()
            .Where(row => row.TenantId == context.TenantId && row.ClientId == account.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        var used = existing.Select(row => $"{row.TargetHost}:{row.TargetPort}").ToHashSet(StringComparer.Ordinal);
        var created = new List<PeerMeshSharedServiceView>();
        var skipped = 0;
        var mappings = await _db.SpecusMappings.AsNoTracking()
            .Where(row => row.TenantId == context.TenantId && row.ClientId == account.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        foreach (var mapping in mappings)
        {
            if (await TryImportAsync(context, account, mapping.TargetAddress, mapping.TargetPort, mapping.ListenPort,
                    "tcp-" + mapping.ListenPort, "tcp", "", used, created, cancellationToken).ConfigureAwait(false))
            {
                continue;
            }
            skipped++;
        }
        var routes = await _db.HttpRouteMappings.AsNoTracking()
            .Where(row => row.TenantId == context.TenantId && row.ClientId == account.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        foreach (var route in routes)
        {
            if (!TryParseHttpCandidate(route.TargetBaseUrl, out var host, out var port, out var application, out var path)
                || !await TryImportAsync(context, account, host, port, port, route.Route, application, path, used,
                    created, cancellationToken).ConfigureAwait(false))
            {
                skipped++;
            }
        }
        return new PeerMeshImportResult(created.Count, skipped, created);
    }

    private async Task<bool> TryImportAsync(ManagementContext context, ClientAccount account, string host,
        int targetPort, int publishedPort, string name, string application, string path, HashSet<string> used,
        List<PeerMeshSharedServiceView> created, CancellationToken cancellationToken)
    {
        try
        {
            var targetHost = RequireTargetHost(host);
            var key = $"{targetHost}:{targetPort}";
            if (!used.Add(key))
            {
                return false;
            }
            created.Add(await CreateSharedServiceAsync(context, new PeerMeshServiceMutation(
                account.Id, null, name, "imported candidate", "tcp", application, targetHost, targetPort,
                publishedPort, path, false, "OWNER", null), cancellationToken).ConfigureAwait(false));
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryParseHttpCandidate(string? raw, out string host, out int port, out string application,
        out string path)
    {
        host = "";
        port = 80;
        application = "http";
        path = "/";
        if (string.IsNullOrWhiteSpace(raw) || !Uri.TryCreate(raw.Trim(), UriKind.Absolute, out var uri))
        {
            return false;
        }
        application = string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase) ? "https" : "http";
        host = uri.Host;
        port = uri.IsDefaultPort ? (application == "https" ? 443 : 80) : uri.Port;
        path = string.IsNullOrWhiteSpace(uri.AbsolutePath) ? "/" : uri.AbsolutePath;
        return !string.IsNullOrWhiteSpace(host);
    }

    private static IReadOnlyList<PeerServiceStats> CopyStats(IReadOnlyList<PeerServiceStats>? raw,
        IReadOnlyList<AdvertisedService> advertised)
    {
        var ids = advertised.Select(item => item.ServiceId).ToHashSet(StringComparer.Ordinal);
        return (raw ?? [])
            .Where(item => item is not null && ids.Contains(item.ServiceId))
            .Select(item => new PeerServiceStats
            {
                ServiceId = item.ServiceId,
                BytesIn = Math.Max(0, item.BytesIn),
                BytesOut = Math.Max(0, item.BytesOut),
                ActiveConnections = Math.Max(0, item.ActiveConnections),
                TotalConnections = Math.Max(0, item.TotalConnections),
            })
            .ToList();
    }

    private static void ApplyMutation(PeerMeshSharedService row, PeerMeshServiceMutation mutation, bool creating)
    {
        row.Name = RequireName(mutation.Name ?? (creating ? null : row.Name));
        row.Description = (mutation.Description ?? row.Description ?? "").Trim();
        if (row.Description.Length > 200)
        {
            throw new ArgumentException("description exceeds 200 characters");
        }
        row.Application = RequireApplication(mutation.Application ?? (creating ? null : row.Application));
        row.Transport = RequireTransportForApplication(mutation.Transport ?? row.Transport, row.Application);
        row.TargetHost = RequireTargetHost(mutation.TargetHost ?? (creating ? null : row.TargetHost));
        row.TargetPort = RequirePort(mutation.TargetPort ?? (creating ? null : row.TargetPort), "targetPort");
        row.PublishedPort = RequirePort(mutation.PublishedPort ?? (creating ? null : row.PublishedPort), "publishedPort");
        row.Path = RequirePath(mutation.Path ?? row.Path, row.Application);
        row.Visibility = string.Equals(mutation.Visibility, "ACL", StringComparison.OrdinalIgnoreCase) ? "ACL" : "OWNER";
        row.Enabled = mutation.Enabled ?? (creating ? false : row.Enabled);
        if (creating || mutation.AllowedClientIds is not null)
        {
            row.AllowedClientIds = EncodeClientIds(mutation.AllowedClientIds);
        }
    }

    private static AdvertisedService FromDefinition(PeerMeshSharedService row) => new()
    {
        ServiceId = row.ServiceId,
        Name = row.Name,
        Description = row.Description,
        Transport = row.Transport,
        Application = row.Application,
        PublishedPort = row.PublishedPort,
        Path = row.Path,
    };

    private static void RequireAdmin(ManagementContext context)
    {
        if (!context.IsAdmin)
        {
            throw new UnauthorizedAccessException("只有管理员可以修改 Peer 服务共享");
        }
    }

    private static string RequireServiceId(string? raw)
    {
        var value = raw?.Trim() ?? "";
        if (!ServiceIdPattern.IsMatch(value))
        {
            throw new ArgumentException("invalid serviceId");
        }
        return value;
    }

    private static string RequireName(string? raw)
    {
        var value = raw?.Trim() ?? "";
        if (value.Length is 0 or > 80)
        {
            throw new ArgumentException("name is required");
        }
        return value;
    }

    private static string RequireApplication(string? raw)
    {
        var value = raw?.Trim().ToLowerInvariant() ?? "";
        if (!PeerServiceApps.Contains(value))
        {
            throw new ArgumentException("unsupported application");
        }
        return value;
    }

    private static string RequireTransportForApplication(string? transport, string application)
    {
        var value = transport?.Trim().ToLowerInvariant() ?? "";
        if (value.Length == 0)
        {
            value = application == "udp" ? "udp" : "tcp";
        }
        if (value is not ("tcp" or "udp"))
        {
            throw new ArgumentException("transport must be tcp or udp");
        }
        if (application == "udp" && value != "udp")
        {
            throw new ArgumentException("udp application requires udp transport");
        }
        if (application != "udp" && value == "udp")
        {
            throw new ArgumentException("http/https/ssh/tcp applications require tcp transport");
        }
        return value;
    }

    private static string EncodeClientIds(IEnumerable<long>? ids)
    {
        var unique = (ids ?? []).Where(id => id > 0).Distinct().ToArray();
        if (unique.Length > 32)
        {
            throw new ArgumentException("at most 32 allowedClientIds");
        }
        return string.Join(',', unique);
    }

    private static IReadOnlyList<long> DecodeClientIds(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return [];
        }
        return raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(part => long.TryParse(part, out var id) ? id : 0)
            .Where(id => id > 0)
            .Distinct()
            .ToArray();
    }

    private static IReadOnlyList<PeerMdnsCandidate> SanitizeMdns(IReadOnlyList<PeerMdnsCandidate>? raw)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var outList = new List<PeerMdnsCandidate>();
        foreach (var item in raw ?? [])
        {
            if (outList.Count >= 32 || item is null)
            {
                continue;
            }
            try
            {
                var host = RequireTargetHost(item.TargetHost);
                var application = RequireApplication(item.Application);
                var transport = RequireTransportForApplication(item.Transport, application);
                var port = RequirePort(item.TargetPort, "targetPort");
                var key = $"{application}:{host}:{port}";
                if (!seen.Add(key))
                {
                    continue;
                }
                outList.Add(new PeerMdnsCandidate
                {
                    Name = RequireName(item.Name),
                    Transport = transport,
                    Application = application,
                    TargetHost = host,
                    TargetPort = port,
                });
            }
            catch
            {
                // skip invalid candidate
            }
        }
        return outList;
    }

    private void Audit(string action, string? tenantId, long? clientId, long? sessionId, string? serviceId,
        string reason)
    {
        _audits.Enqueue(new PeerMeshAuditEvent(DateTimeOffset.UtcNow.ToString("O"), action, tenantId, clientId,
            sessionId, serviceId, reason));
        while (_audits.Count > 80 && _audits.TryDequeue(out _))
        {
        }
    }

    private async Task<PeerMeshImportResult> ImportMdnsAsync(ManagementContext context, ClientAccount account,
        CancellationToken cancellationToken)
    {
        var sharing = await _db.PeerMeshServiceSharings.AsNoTracking()
            .FirstOrDefaultAsync(row => row.TenantId == context.TenantId, cancellationToken)
            .ConfigureAwait(false);
        if (sharing is not { Enabled: true, MdnsImportEnabled: true } || !Enabled)
        {
            throw new ArgumentException("mDNS 候选导入未开启");
        }
        var existing = await _db.PeerMeshSharedServices.AsNoTracking()
            .Where(row => row.TenantId == context.TenantId && row.ClientId == account.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        var used = existing.Select(row => $"{row.TargetHost}:{row.TargetPort}").ToHashSet(StringComparer.Ordinal);
        var created = new List<PeerMeshSharedServiceView>();
        var skipped = 0;
        var candidates = _serviceCatalogs
            .Where(item => item.Key.TenantId == account.TenantId && item.Key.ClientId == account.Id)
            .SelectMany(item => item.Value.Mdns)
            .ToList();
        foreach (var candidate in candidates)
        {
            try
            {
                var targetHost = RequireTargetHost(candidate.TargetHost);
                var key = $"{targetHost}:{candidate.TargetPort}";
                if (!used.Add(key))
                {
                    skipped++;
                    continue;
                }
                created.Add(await CreateSharedServiceAsync(context, new PeerMeshServiceMutation(
                    account.Id, null, candidate.Name, "imported candidate", candidate.Transport,
                    candidate.Application, targetHost, candidate.TargetPort, candidate.TargetPort, "", false, "OWNER",
                    null), cancellationToken).ConfigureAwait(false));
            }
            catch
            {
                skipped++;
            }
        }
        return new PeerMeshImportResult(created.Count, skipped, created);
    }

    private static int RequirePort(int? port, string field)
    {
        if (port is null or < 1 or > 65535)
        {
            throw new ArgumentException($"{field} must be 1..65535");
        }
        return port.Value;
    }

    private static string RequireTargetHost(string? raw)
    {
        var value = raw?.Trim() ?? "";
        var lower = value.ToLowerInvariant();
        if (value.Length == 0 || lower.Contains("://") || lower.IndexOfAny(['/', '@', '?', '#']) >= 0)
        {
            throw new ArgumentException("targetHost must be a local address, not a URL");
        }
        if (string.Equals(value, "localhost", StringComparison.OrdinalIgnoreCase)
            || value is "127.0.0.1" or "::1")
        {
            return value;
        }
        if (!IPAddress.TryParse(value, out var ip) || IPAddress.Any.Equals(ip) || ip.IsIPv6Multicast)
        {
            throw new ArgumentException("targetHost must be a unicast IP or localhost");
        }
        return value;
    }

    private static string RequirePath(string? raw, string application)
    {
        var value = raw?.Trim() ?? "";
        if (value.Length == 0)
        {
            return application is "http" or "https" ? "/" : "";
        }
        if (value.Contains("://", StringComparison.Ordinal) || value.Contains("..", StringComparison.Ordinal)
            || value.Contains('\\') || value.Contains(' '))
        {
            throw new ArgumentException("path must be a safe relative HTTP path");
        }
        if (!PathPattern.IsMatch(value))
        {
            throw new ArgumentException("path contains unsupported characters");
        }
        return value;
    }

    private sealed record CatalogSnapshot(long Revision, string InstanceId, DateTimeOffset GeneratedAt,
        DateTimeOffset ExpiresAt, IReadOnlyList<AdvertisedService> Services, string PublisherClientName,
        IReadOnlyList<PeerServiceStats> Stats, IReadOnlyList<PeerMdnsCandidate> Mdns);
}

public sealed record PeerMeshServiceSharingView(
    [property: JsonPropertyName("deploymentEnabled")] bool DeploymentEnabled,
    [property: JsonPropertyName("configuredEnabled")] bool ConfiguredEnabled,
    [property: JsonPropertyName("effectiveEnabled")] bool EffectiveEnabled,
    [property: JsonPropertyName("peerServiceDiscoveryVersion")] int PeerServiceDiscoveryVersion,
    [property: JsonPropertyName("supportedApplications")] IReadOnlyList<string> SupportedApplications,
    [property: JsonPropertyName("enabledServiceCount")] long EnabledServiceCount,
    [property: JsonPropertyName("updatedAt")] string? UpdatedAt,
    [property: JsonPropertyName("updatedBy")] string? UpdatedBy,
    [property: JsonPropertyName("mdnsImportEnabled")] bool MdnsImportEnabled);

public sealed record PeerMeshSharedServiceView(
    [property: JsonPropertyName("id")] long Id,
    [property: JsonPropertyName("serviceId")] string ServiceId,
    [property: JsonPropertyName("clientId")] long ClientId,
    [property: JsonPropertyName("clientName")] string ClientName,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("description")] string Description,
    [property: JsonPropertyName("transport")] string Transport,
    [property: JsonPropertyName("application")] string Application,
    [property: JsonPropertyName("targetHost")] string? TargetHost,
    [property: JsonPropertyName("targetPort")] int TargetPort,
    [property: JsonPropertyName("publishedPort")] int PublishedPort,
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("enabled")] bool Enabled,
    [property: JsonPropertyName("visibility")] string Visibility,
    [property: JsonPropertyName("allowedClientIds")] IReadOnlyList<long> AllowedClientIds,
    [property: JsonPropertyName("publishedAddress")] string? PublishedAddress,
    [property: JsonPropertyName("instances")] IReadOnlyList<PeerMeshSharedServiceInstanceView> Instances,
    [property: JsonPropertyName("createdAt")] string CreatedAt,
    [property: JsonPropertyName("updatedAt")] string UpdatedAt);

public sealed record PeerMeshSharedServiceInstanceView(
    [property: JsonPropertyName("publisherSessionId")] long PublisherSessionId,
    [property: JsonPropertyName("instanceId")] string InstanceId,
    [property: JsonPropertyName("online")] bool Online,
    [property: JsonPropertyName("advertised")] bool Advertised,
    [property: JsonPropertyName("revision")] long Revision,
    [property: JsonPropertyName("lastReportedAt")] string LastReportedAt,
    [property: JsonPropertyName("expiresAt")] string ExpiresAt,
    [property: JsonPropertyName("bytesIn")] long BytesIn,
    [property: JsonPropertyName("bytesOut")] long BytesOut,
    [property: JsonPropertyName("activeConnections")] int ActiveConnections,
    [property: JsonPropertyName("totalConnections")] long TotalConnections);

public sealed record PeerMeshImportResult(
    [property: JsonPropertyName("created")] int Created,
    [property: JsonPropertyName("skipped")] int Skipped,
    [property: JsonPropertyName("services")] IReadOnlyList<PeerMeshSharedServiceView> Services);

public sealed class PeerServiceStats
{
    [JsonPropertyName("serviceId")]
    public string ServiceId { get; set; } = "";

    [JsonPropertyName("bytesIn")]
    public long BytesIn { get; set; }

    [JsonPropertyName("bytesOut")]
    public long BytesOut { get; set; }

    [JsonPropertyName("activeConnections")]
    public int ActiveConnections { get; set; }

    [JsonPropertyName("totalConnections")]
    public long TotalConnections { get; set; }
}

public sealed record PeerMeshSharingMutation(
    [property: JsonPropertyName("enabled")] bool? Enabled,
    [property: JsonPropertyName("mdnsImportEnabled")] bool? MdnsImportEnabled = null);

public sealed record PeerMeshImportMutation(
    [property: JsonPropertyName("clientId")] long? ClientId,
    [property: JsonPropertyName("source")] string? Source = null);

public sealed record PeerMeshServiceMutation(
    [property: JsonPropertyName("clientId")] long? ClientId,
    [property: JsonPropertyName("serviceId")] string? ServiceId,
    [property: JsonPropertyName("name")] string? Name,
    [property: JsonPropertyName("description")] string? Description,
    [property: JsonPropertyName("transport")] string? Transport,
    [property: JsonPropertyName("application")] string? Application,
    [property: JsonPropertyName("targetHost")] string? TargetHost,
    [property: JsonPropertyName("targetPort")] int? TargetPort,
    [property: JsonPropertyName("publishedPort")] int? PublishedPort,
    [property: JsonPropertyName("path")] string? Path,
    [property: JsonPropertyName("enabled")] bool? Enabled,
    [property: JsonPropertyName("visibility")] string? Visibility,
    [property: JsonPropertyName("allowedClientIds")] IReadOnlyList<long>? AllowedClientIds = null);

public sealed record PeerMeshAuditEvent(
    [property: JsonPropertyName("at")] string At,
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("tenantId")] string? TenantId,
    [property: JsonPropertyName("clientId")] long? ClientId,
    [property: JsonPropertyName("sessionId")] long? SessionId,
    [property: JsonPropertyName("serviceId")] string? ServiceId,
    [property: JsonPropertyName("reason")] string Reason);

public sealed class PeerMdnsCandidate
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("transport")]
    public string Transport { get; set; } = "tcp";

    [JsonPropertyName("application")]
    public string Application { get; set; } = "tcp";

    [JsonPropertyName("targetHost")]
    public string TargetHost { get; set; } = "";

    [JsonPropertyName("targetPort")]
    public int TargetPort { get; set; }
}

public sealed class LocalPeerService
{
    [JsonPropertyName("serviceId")]
    public string ServiceId { get; set; } = "";

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("transport")]
    public string Transport { get; set; } = "tcp";

    [JsonPropertyName("application")]
    public string Application { get; set; } = "tcp";

    [JsonPropertyName("targetHost")]
    public string TargetHost { get; set; } = "";

    [JsonPropertyName("targetPort")]
    public int TargetPort { get; set; }

    [JsonPropertyName("publishedPort")]
    public int PublishedPort { get; set; }

    [JsonPropertyName("path")]
    public string? Path { get; set; }

    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    [JsonPropertyName("visibility")]
    public string Visibility { get; set; } = "OWNER";
}

public sealed class AdvertisedService
{
    [JsonPropertyName("serviceId")]
    public string ServiceId { get; set; } = "";

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("transport")]
    public string Transport { get; set; } = "tcp";

    [JsonPropertyName("application")]
    public string Application { get; set; } = "tcp";

    [JsonPropertyName("publishedPort")]
    public int PublishedPort { get; set; }

    [JsonPropertyName("path")]
    public string? Path { get; set; }
}

public sealed class ServiceSharingStatus
{
    [JsonPropertyName("deploymentEnabled")]
    public bool DeploymentEnabled { get; set; }

    [JsonPropertyName("configuredEnabled")]
    public bool ConfiguredEnabled { get; set; }

    [JsonPropertyName("effectiveEnabled")]
    public bool EffectiveEnabled { get; set; }

    [JsonPropertyName("mdnsImportEnabled")]
    public bool MdnsImportEnabled { get; set; }
}
