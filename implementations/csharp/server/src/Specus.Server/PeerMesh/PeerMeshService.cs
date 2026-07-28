using System.Net;
using System.Net.Sockets;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Sessions;

namespace Specus.Server.PeerMesh;

public sealed class PeerMeshService
{
    public const string PathDirect = "DIRECT";
    public const string PathRelay = "RELAY";
    public const string StatusNegotiating = "NEGOTIATING";
    public const string StatusActive = "ACTIVE";
    public const string StatusClosed = "CLOSED";
    public const string DirectionOutbound = "OUTBOUND";
    public const string DirectionInbound = "INBOUND";
    public const string DirectionBoth = "BOTH";

    private const string TypeCandidates = "candidates";
    private const string TypeSessionGrant = "session-grant";
    private const string TypeRoster = "roster";
    private const string TypeConfig = "peer-config";
    private const string TypePathReport = "path-report";
    private const string TypeTrafficReport = "traffic-report";
    private const string TypeDeviceReport = "device-report";
    private const string TypeClose = "close";
    private static readonly TimeSpan RelayAuthorizationCacheTtl = TimeSpan.FromSeconds(30);
    private readonly ConcurrentDictionary<long, RelayAuthorization> _relayAuthorizations = new();
    private readonly ConcurrentDictionary<long, long> _pendingRelayBytes = new();

    private readonly SpecusDbContext _db;
    private readonly SessionRegistry _sessions;
    private readonly PeerMeshOptions _options;
    private readonly TurnCredentialService _turnCredentials;
    private readonly ILogger<PeerMeshService> _logger;

    public PeerMeshService(SpecusDbContext db, SessionRegistry sessions, IOptions<PeerMeshOptions> options,
        ILogger<PeerMeshService> logger, TurnCredentialService? turnCredentials = null)
    {
        _db = db;
        _sessions = sessions;
        _options = options.Value;
        _turnCredentials = turnCredentials ?? new TurnCredentialService(options);
        _logger = logger;
    }

    public bool Enabled => _options.Enabled;

    internal async Task<bool> AuthorizeRelayFrameAsync(PeerDataFrameHeader header,
        long fromClientId, long toClientId, long bytes,
        CancellationToken cancellationToken)
    {
        if (!ValidRelayPeers(fromClientId, toClientId) || bytes <= 0)
        {
            return false;
        }
		return await AuthorizeRelayFrameCoreAsync(
            header, fromClientId, toClientId, bytes, true, cancellationToken).ConfigureAwait(false);
	}

	internal Task<bool> ValidateRelayFrameAsync(PeerDataFrameHeader header,
        long fromClientId, long toClientId, CancellationToken cancellationToken) =>
        ValidRelayPeers(fromClientId, toClientId)
            ? AuthorizeRelayFrameCoreAsync(header, fromClientId, toClientId, 0, false, cancellationToken)
            : Task.FromResult(false);

    /// <summary>
    /// Either both identities are known (TURN auth enabled) or both are zero (auth disabled and
    /// the caller cannot determine identity). A single zero is a caller bug.
    /// </summary>
    private static bool ValidRelayPeers(long fromClientId, long toClientId) =>
        (fromClientId > 0 && toClientId > 0) || (fromClientId == 0 && toClientId == 0);

    /// <summary>
    /// 0/0 means the caller could not determine the peer identities (TURN auth disabled), which
    /// degrades to "session exists and is not closed" instead of rejecting everything.
    /// </summary>
    private static bool MatchesSessionPeers(PeerMeshSession session, long fromClientId, long toClientId)
    {
        if (fromClientId <= 0 && toClientId <= 0)
        {
            return true;
        }
        var forward = fromClientId == session.SourceClientId && toClientId == session.TargetClientId;
        var reverse = fromClientId == session.TargetClientId && toClientId == session.SourceClientId;
        return forward || reverse;
    }

	private async Task<bool> AuthorizeRelayFrameCoreAsync(PeerDataFrameHeader header,
        long fromClientId, long toClientId, long bytes, bool account,
		CancellationToken cancellationToken)
	{
        var now = DateTimeOffset.UtcNow;
        if (AuthorizeRelayFrameCached(header, fromClientId, toClientId, bytes, now, account))
        {
            return true;
        }
        var session = await _db.PeerMeshSessions.FirstOrDefaultAsync(s => s.Id == header.SessionId,
                cancellationToken)
            .ConfigureAwait(false);
        if (session is null)
        {
            return false;
        }
        if (CloseIfExpired(session, now))
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return false;
        }
        if (string.Equals(session.Status, StatusClosed, StringComparison.Ordinal))
        {
            RemoveRelaySession(header.SessionId);
            return false;
        }
        if (!MatchesSessionPeers(session, fromClientId, toClientId))
        {
            RemoveRelaySession(header.SessionId);
            return false;
        }
        // The first authenticated relay business frame implicitly activates a NEGOTIATING
        // session. Probes are allowed while NEGOTIATING but business frames required ACTIVE,
        // which is only written by an asynchronous path-report; clients flush queued data right
        // after a successful probe, so those frames raced ahead of the report and were dropped.
        // Peer app messages have no retransmission, so this surfaced as "relay connected but
        // file send fails". Session identity is already verified here, so waiting for a status
        // report adds no security, only a race.
        if (!string.Equals(session.Status, StatusActive, StringComparison.Ordinal))
        {
            session.Status = StatusActive;
            session.PathType = PathRelay;
            session.UpdatedAt = now;
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        CacheRelayAuthorization(session, now);
		if (account)
		{
			AddPendingRelayBytes(header.SessionId, bytes);
		}
        return true;
    }

	internal async Task<bool> AuthorizeRelayProbeAsync(long sessionId, long fromClientId, long toClientId,
		string? token, string? type, CancellationToken cancellationToken)
	{
		if (sessionId <= 0 || fromClientId <= 0 || toClientId <= 0 || string.IsNullOrWhiteSpace(token)
			|| type is not ("check" or "check-response"))
		{
			return false;
		}
		var session = await _db.PeerMeshSessions.FirstOrDefaultAsync(item => item.Id == sessionId, cancellationToken)
			.ConfigureAwait(false);
		if (session is null)
		{
			return false;
		}
		var now = DateTimeOffset.UtcNow;
		if (CloseIfExpired(session, now))
		{
			await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
			return false;
		}
		var forward = fromClientId == session.SourceClientId && toClientId == session.TargetClientId;
		var reverse = fromClientId == session.TargetClientId && toClientId == session.SourceClientId;
		if ((!forward && !reverse) || string.Equals(session.Status, StatusClosed, StringComparison.Ordinal)
			|| string.IsNullOrWhiteSpace(session.TokenHash))
		{
			return false;
		}
		byte[] expected;
		try
		{
			expected = Convert.FromHexString(session.TokenHash);
		}
		catch (FormatException)
		{
			return false;
		}
		var actual = SHA256.HashData(Encoding.UTF8.GetBytes(token));
		return expected.Length == actual.Length && CryptographicOperations.FixedTimeEquals(expected, actual);
	}

    public async Task<PeerMeshConfig> BuildLoginConfigAsync(ClientAccount account, ClientEnvironmentInfo environment,
        string? requestServerName, CancellationToken cancellationToken)
    {
        PeerMeshDevice? device = null;
        if (Enabled)
        {
            device = await EnsureDeviceAsync(account, environment.PeerPublicKey, cancellationToken)
                .ConfigureAwait(false);
        }
        return BuildConfig(account, device, requestServerName);
    }

    public async Task<PeerMeshConfig> BuildRuntimeConfigAsync(ClientAccount account, CancellationToken cancellationToken)
    {
        PeerMeshDevice? device = null;
        if (Enabled)
        {
            device = await _db.PeerMeshDevices
                .FirstOrDefaultAsync(d => d.TenantId == account.TenantId && d.ClientId == account.Id,
                    cancellationToken)
                .ConfigureAwait(false)
                ?? await CreateDeviceAsync(account, cancellationToken).ConfigureAwait(false);
        }
        return BuildConfig(account, device, null);
    }

    public PublicStunConfig PublicStunConfig(string? requestHost)
    {
        var servers = new List<string>();
        var selfHosted = string.Empty;
        if (Enabled || HasStandaloneStun())
        {
            var host = ResolveStunHost(requestHost);
            var port = StunPort();
            if (!string.IsNullOrWhiteSpace(host) && port > 0)
            {
                selfHosted = $"stun:{BracketIpv6(host)}:{port}";
                servers.Add(selfHosted);
            }
        }
        foreach (var item in _options.PublicStunServers
                     .Where(value => !string.IsNullOrWhiteSpace(value))
                     .Select(NormalizeStunUrl)
                     .Where(value => !string.IsNullOrWhiteSpace(value)))
        {
            if (!servers.Contains(item, StringComparer.OrdinalIgnoreCase))
            {
                servers.Add(item);
            }
        }
        return new PublicStunConfig(Enabled, selfHosted, servers, _options.StunTurnPort);
    }

    public PublicIceConfig PublicIceConfig(string? requestHost)
    {
        var stun = PublicStunConfig(requestHost);
        var servers = stun.StunServers
            .Select(url => new IceServer(url, string.Empty, string.Empty))
            .ToList();
        if (Enabled)
        {
            var host = ResolvePeerHost(requestHost);
            if (!string.IsNullOrWhiteSpace(host) && _options.StunTurnPort > 0)
            {
                var credential = _turnCredentials.Issue("public-transfer");
                servers.Add(new IceServer(
                    $"turn:{BracketIpv6(host)}:{_options.StunTurnPort}?transport=udp",
                    credential.Username,
                    credential.Credential));
            }
        }
        return new PublicIceConfig(Enabled, servers, _turnCredentials.AuthRequired,
            _options.StunTurnPort);
    }

    public async Task HandleSignalAsync(MessageRequestPacket request, string sourceClientName,
        CancellationToken cancellationToken)
    {
        if (!Enabled)
        {
            throw new InvalidOperationException("peer mesh is disabled");
        }
        var source = await _db.ClientAccounts.FirstOrDefaultAsync(c => c.ClientName == sourceClientName,
                cancellationToken)
            .ConfigureAwait(false)
            ?? throw new ArgumentException($"source client not found: {sourceClientName}");
        if (string.IsNullOrWhiteSpace(request.Message))
        {
            throw new ArgumentException("invalid peer signal");
        }
        var signal = JsonSerializer.Deserialize<PeerControlMessage>(request.Message);
        if (signal is null || string.IsNullOrWhiteSpace(signal.Type))
        {
            throw new ArgumentException("invalid peer signal");
        }
        await FillSourceAsync(signal, source, cancellationToken).ConfigureAwait(false);

        switch (signal.Type)
        {
            case TypePathReport:
                await ReportPathAsync(source, signal, cancellationToken).ConfigureAwait(false);
                return;
            case TypeTrafficReport:
                await ReportTrafficAsync(source, signal, cancellationToken).ConfigureAwait(false);
                return;
            case TypeDeviceReport:
                await ReportDeviceAsync(source, signal, cancellationToken).ConfigureAwait(false);
                return;
            case TypeClose:
                await CloseSessionFromClientAsync(source, signal, cancellationToken).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(request.ToClientName))
                {
                    return;
                }
                break;
        }

        if (string.IsNullOrWhiteSpace(request.ToClientName))
        {
            throw new ArgumentException("toClientName is required");
        }
        var target = await _db.ClientAccounts.FirstOrDefaultAsync(c => c.ClientName == request.ToClientName,
                cancellationToken)
            .ConfigureAwait(false)
            ?? throw new ArgumentException($"target client not found: {request.ToClientName}");
        if (!await CanPeerAsync(source, target, cancellationToken).ConfigureAwait(false))
        {
            throw new UnauthorizedAccessException("peer access denied");
        }
        var targetSession = _sessions.Find(target.ClientName)
            ?? throw new InvalidOperationException($"target peer is offline: {target.ClientName}");
        await EnrichTargetAsync(signal, target, cancellationToken).ConfigureAwait(false);
        if (signal.SessionId is null && (signal.Type == TypeCandidates || signal.Type == "offer"))
        {
            var grant = await CreateSessionAsync(source, target, PathDirect, cancellationToken).ConfigureAwait(false);
            signal.SessionId = grant.Session.Id;
            signal.Token = grant.Token;
            signal.ExpiresAt = grant.Session.ExpiresAt;
            await SendSessionGrantAsync(source, target, grant, cancellationToken).ConfigureAwait(false);
        }
        await SendSignalAsync(targetSession, source.ClientName, target.ClientName, signal, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task PushConfigAsync(ClientAccount account, CancellationToken cancellationToken)
    {
        var session = _sessions.Find(account.ClientName);
        if (session is null)
        {
            return;
        }
        var config = await BuildRuntimeConfigAsync(account, cancellationToken).ConfigureAwait(false);
        await SendSignalAsync(session, "server", account.ClientName, new PeerControlMessage
        {
            Type = TypeConfig,
            SourceClientId = account.Id,
            SourceClientName = account.ClientName,
            TargetClientId = account.Id,
            TargetClientName = account.ClientName,
            PeerMesh = config,
            CreatedAtMillis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task PushRosterAsync(ClientAccount account, CancellationToken cancellationToken)
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
        var peers = await AllowedRosterAsync(account, cancellationToken).ConfigureAwait(false);
        await SendSignalAsync(session, "server", account.ClientName, new PeerControlMessage
        {
            Type = TypeRoster,
            SourceClientId = account.Id,
            SourceClientName = account.ClientName,
            Peers = peers,
            CreatedAtMillis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task PushOnLoginAsync(ClientAccount account, CancellationToken cancellationToken)
    {
        if (!Enabled)
        {
            return;
        }
        await PushConfigAsync(account, cancellationToken).ConfigureAwait(false);
        var targets = await RosterRefreshTargetsAsync(account, cancellationToken).ConfigureAwait(false);
        foreach (var target in targets)
        {
            await PushRosterAsync(target, cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task<IReadOnlyList<PeerMeshDeviceView>> ListDevicesAsync(ManagementContext context,
        CancellationToken cancellationToken)
    {
        var query = _db.PeerMeshDevices.AsNoTracking()
            .Where(d => d.TenantId == context.TenantId);
        if (!context.IsAdmin)
        {
            query = query.Where(d => d.OwnerUsername == context.Username);
        }
        var rows = await query.OrderBy(d => d.ClientName).ToListAsync(cancellationToken).ConfigureAwait(false);
        return rows.Select(DeviceView).ToList();
    }

    public async Task<PeerMeshDeviceView> UpdateDeviceAsync(ManagementContext context, long clientId,
        PeerMeshDeviceMutation request, CancellationToken cancellationToken)
    {
        var device = await FindAccessibleDeviceAsync(context, clientId, cancellationToken).ConfigureAwait(false);
        if (request.Enabled is not null)
        {
            device.Enabled = request.Enabled.Value;
        }
        device.UpdatedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        if (request.Enabled is not null)
        {
            await RefreshDeviceAsync(context, clientId, request.Enabled.Value, cancellationToken).ConfigureAwait(false);
        }
        return DeviceView(device);
    }

    public async Task<IReadOnlyList<PeerMeshAclView>> ListAclsAsync(ManagementContext context,
        CancellationToken cancellationToken)
    {
        var query = _db.PeerMeshAcls.AsNoTracking().Where(a => a.TenantId == context.TenantId);
        if (!context.IsAdmin)
        {
            query = query.Where(a => a.OwnerUsername == context.Username);
        }
        var rows = await query.OrderByDescending(a => a.Id).ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return rows.Select(AclView).ToList();
    }

    public async Task<PeerMeshAclView> CreateAclAsync(ManagementContext context, PeerMeshAclMutation request,
        CancellationToken cancellationToken)
    {
        if (request.SourceClientId is null or <= 0)
        {
            throw new ArgumentException("sourceClientId is required");
        }
        if (request.TargetClientId is null or <= 0)
        {
            throw new ArgumentException("targetClientId is required");
        }
        var source = await FindAccessibleClientAsync(context, request.SourceClientId.Value, cancellationToken)
            .ConfigureAwait(false);
        var target = await FindTenantClientAsync(context.TenantId, request.TargetClientId.Value, cancellationToken)
            .ConfigureAwait(false);
        if (source.Id == target.Id)
        {
            throw new ArgumentException("source and target cannot be the same client");
        }
        if (!context.IsAdmin && !string.Equals(NormalizeOwner(target.OwnerUsername), context.Username,
                StringComparison.Ordinal))
        {
            throw new ArgumentException("普通用户不能创建跨用户 peer ACL");
        }
        var acl = await _db.PeerMeshAcls.FirstOrDefaultAsync(a =>
                a.TenantId == context.TenantId
                && a.SourceClientId == source.Id
                && a.TargetClientId == target.Id, cancellationToken)
            .ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        if (acl is null)
        {
            acl = new PeerMeshAcl
            {
                Id = ClientIdGenerator.NewId(),
                TenantId = context.TenantId,
                CreatedAt = now,
            };
            _db.PeerMeshAcls.Add(acl);
        }
        acl.OwnerUsername = context.Username;
        acl.SourceClientId = source.Id;
        acl.SourceClientName = source.ClientName;
        acl.TargetClientId = target.Id;
        acl.TargetClientName = target.ClientName;
        acl.Allowed = request.Allowed ?? true;
        if (request.Direction is not null)
        {
            var direction = request.Direction.ToUpperInvariant();
            if (direction is not (DirectionOutbound or DirectionInbound or DirectionBoth))
            {
                throw new ArgumentException($"invalid direction: {request.Direction}");
            }
            acl.Direction = direction;
        }
        acl.UpdatedAt = now;
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return AclView(acl);
    }

    public async Task DeleteAclAsync(ManagementContext context, long id, CancellationToken cancellationToken)
    {
        var acl = await _db.PeerMeshAcls.FirstOrDefaultAsync(a => a.Id == id, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new ArgumentException("peer ACL not found");
        if (acl.TenantId != context.TenantId || (!context.IsAdmin && acl.OwnerUsername != context.Username))
        {
            throw new ArgumentException("peer ACL not found");
        }
        _db.PeerMeshAcls.Remove(acl);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<PeerMeshSessionView>> ListSessionsAsync(ManagementContext context, int? limit,
        CancellationToken cancellationToken)
    {
        await ExpireStaleSessionsAsync(cancellationToken).ConfigureAwait(false);
        var take = Math.Clamp(limit ?? 100, 1, 200);
        IQueryable<PeerMeshSession> query = _db.PeerMeshSessions.AsNoTracking()
            .Where(s => s.TenantId == context.TenantId);
        if (!context.IsAdmin)
        {
            var ids = await VisibleClientIdsAsync(context, cancellationToken).ConfigureAwait(false);
            query = query.Where(s => ids.Contains(s.SourceClientId) || ids.Contains(s.TargetClientId));
        }
        var rows = await query.OrderByDescending(s => s.UpdatedAt).Take(take)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return rows.Select(SessionView).ToList();
    }

    public async Task<PeerMeshSessionPage> ListSessionsPageAsync(ManagementContext context, int? page, int? size,
        bool openOnly, CancellationToken cancellationToken)
    {
        await ExpireStaleSessionsAsync(cancellationToken).ConfigureAwait(false);
        var normalizedPage = Math.Max(0, page ?? 0);
        var normalizedSize = Math.Clamp(size ?? 100, 1, 200);
        IQueryable<PeerMeshSession> query = _db.PeerMeshSessions.AsNoTracking()
            .Where(s => s.TenantId == context.TenantId);
        if (openOnly)
        {
            query = query.Where(s => s.Status != StatusClosed);
        }
        if (!context.IsAdmin)
        {
            var ids = await VisibleClientIdsAsync(context, cancellationToken).ConfigureAwait(false);
            query = query.Where(s => ids.Contains(s.SourceClientId) || ids.Contains(s.TargetClientId));
        }
        var total = await query.LongCountAsync(cancellationToken).ConfigureAwait(false);
        var rows = await query.OrderByDescending(s => s.UpdatedAt)
            .Skip(normalizedPage * normalizedSize)
            .Take(normalizedSize)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return new PeerMeshSessionPage(
            rows.Select(SessionView).ToList(),
            total,
            normalizedPage,
            normalizedSize,
            TotalPages(total, normalizedSize));
    }

    public async Task<PeerMeshPathStatsView> PathStatsAsync(ManagementContext context,
        CancellationToken cancellationToken)
    {
        await ExpireStaleSessionsAsync(cancellationToken).ConfigureAwait(false);
        List<long>? visibleIds = null;
        IQueryable<PeerMeshSession> sessionQuery = _db.PeerMeshSessions.AsNoTracking()
            .Where(s => s.TenantId == context.TenantId);
        if (!context.IsAdmin)
        {
            visibleIds = await VisibleClientIdsAsync(context, cancellationToken).ConfigureAwait(false);
            if (visibleIds.Count == 0)
            {
                sessionQuery = sessionQuery.Where(_ => false);
            }
            else
            {
                sessionQuery = sessionQuery.Where(s => visibleIds.Contains(s.SourceClientId)
                    || visibleIds.Contains(s.TargetClientId));
            }
        }
        var pathRows = await sessionQuery
            .GroupBy(s => new
            {
                PathType = s.RelayBytes > s.DirectBytes
                    ? PathRelay
                    : s.DirectBytes > s.RelayBytes
                        ? PathDirect
                        : s.PathType,
                s.Status,
            })
            .Select(g => new
            {
                g.Key.PathType,
                g.Key.Status,
                Sessions = g.LongCount(),
                ReportedSessions = g.LongCount(s => s.RttMillis != null),
                AvgRttMillis = g.Average(s => (double?)s.RttMillis),
                DirectBytes = g.Sum(s => s.DirectBytes),
                RelayBytes = g.Sum(s => s.RelayBytes)
            })
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        var addressFamilyRows = await sessionQuery
            .GroupBy(s => new
            {
                AddressFamily = string.IsNullOrEmpty(s.RemoteEndpoint)
                    ? "UNKNOWN"
                    : s.RemoteEndpoint.StartsWith("[")
                        ? "IPv6"
                        : "IPv4",
                PathType = s.RelayBytes > s.DirectBytes
                    ? PathRelay
                    : s.DirectBytes > s.RelayBytes
                        ? PathDirect
                        : s.PathType,
                s.Status,
            })
            .Select(g => new
            {
                g.Key.AddressFamily,
                g.Key.Status,
                g.Key.PathType,
                Sessions = g.LongCount(),
                ReportedSessions = g.LongCount(s => s.RttMillis != null),
            })
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        IQueryable<PeerMeshDevice> natQuery = _db.PeerMeshDevices.AsNoTracking()
            .Where(d => d.TenantId == context.TenantId);
        if (!context.IsAdmin)
        {
            natQuery = natQuery.Where(d => d.OwnerUsername == context.Username);
        }
        var natRows = await natQuery
            .GroupBy(d => d.NatType)
            .Select(g => new { NatType = g.Key, Devices = g.LongCount() })
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        var natBehaviorRows = await natQuery
            .GroupBy(d => new
            {
                Mapping = d.NatMappingBehavior,
                Filtering = d.NatFilteringBehavior,
                Discovery = d.NatBehaviorDiscovery,
            })
            .Select(g => new
            {
                g.Key.Mapping,
                g.Key.Filtering,
                g.Key.Discovery,
                Devices = g.LongCount(),
            })
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        long total = 0;
        long reported = 0;
        long active = 0;
        long activeDirect = 0;
        long activeRelay = 0;
        var pathTypes = new List<PeerMeshPathTypeStat>(pathRows.Count);
        foreach (var row in pathRows)
        {
            total += row.Sessions;
            reported += row.ReportedSessions;
            if (string.Equals(row.Status, StatusActive, StringComparison.Ordinal))
            {
                active += row.Sessions;
                if (string.Equals(row.PathType, PathDirect, StringComparison.Ordinal))
                {
                    activeDirect += row.Sessions;
                }
                else if (string.Equals(row.PathType, PathRelay, StringComparison.Ordinal))
                {
                    activeRelay += row.Sessions;
                }
            }
            pathTypes.Add(new PeerMeshPathTypeStat(row.PathType, row.Status, row.Sessions,
                row.ReportedSessions, row.AvgRttMillis, row.DirectBytes, row.RelayBytes));
        }
        var addressFamilies = addressFamilyRows.Select(row => new PeerMeshAddressFamilyStat(
            row.AddressFamily,
            row.Status,
            row.PathType,
            row.Sessions,
            row.ReportedSessions)).ToList();

        var natCounts = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var row in natRows)
        {
            var key = string.IsNullOrWhiteSpace(row.NatType) ? "UNKNOWN" : row.NatType!;
            natCounts.TryAdd(key, 0);
            natCounts[key] += row.Devices;
        }
        var natTypes = natCounts.Select(item => new PeerMeshNatTypeStat(item.Key, item.Value)).ToList();
        long natBehaviorDevices = 0;
        long natBehaviorClassifiedDevices = 0;
        var mappingCounts = new Dictionary<string, long>(StringComparer.Ordinal);
        var filteringCounts = new Dictionary<string, long>(StringComparer.Ordinal);
        var discoveryCounts = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var row in natBehaviorRows)
        {
            if (string.IsNullOrWhiteSpace(row.Mapping)
                && string.IsNullOrWhiteSpace(row.Filtering)
                && string.IsNullOrWhiteSpace(row.Discovery))
            {
                continue;
            }
            natBehaviorDevices += row.Devices;
            var mapping = NormalizeNatBehavior(row.Mapping);
            var filtering = NormalizeNatBehavior(row.Filtering);
            var discovery = NormalizeNatBehavior(row.Discovery);
            MergeNatBehavior(mappingCounts, mapping, row.Devices);
            MergeNatBehavior(filteringCounts, filtering, row.Devices);
            MergeNatBehavior(discoveryCounts, discovery, row.Devices);
            if (IsClassifiedNatBehavior(mapping) && IsClassifiedNatBehavior(filtering))
            {
                natBehaviorClassifiedDevices += row.Devices;
            }
        }
        double? ratio = active == 0 ? null : (double)activeDirect / active;
        return new PeerMeshPathStatsView(total, reported, active, activeDirect, activeRelay, ratio,
            pathTypes,
            addressFamilies,
            natTypes,
            natBehaviorDevices,
            natBehaviorClassifiedDevices,
            natBehaviorDevices == 0
                ? null
                : (double)natBehaviorClassifiedDevices / natBehaviorDevices,
            NatBehaviorStats(mappingCounts),
            NatBehaviorStats(filteringCounts),
            NatBehaviorStats(discoveryCounts));
    }

    private static void MergeNatBehavior(
        IDictionary<string, long> counts,
        string behavior,
        long devices)
    {
        counts.TryAdd(behavior, 0);
        counts[behavior] += devices;
    }

    private static IReadOnlyList<PeerMeshNatBehaviorStat> NatBehaviorStats(
        IEnumerable<KeyValuePair<string, long>> counts) =>
        counts.Select(item => new PeerMeshNatBehaviorStat(item.Key, item.Value)).ToList();

    private static string NormalizeNatBehavior(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "UNKNOWN" : value.Trim();

    private static bool IsClassifiedNatBehavior(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && !string.Equals(value, "UNKNOWN", StringComparison.OrdinalIgnoreCase)
        && !string.Equals(value, "UNSUPPORTED", StringComparison.OrdinalIgnoreCase);

    public async Task<PeerMeshSessionView> ForceCloseAsync(ManagementContext context, long sessionId,
        CancellationToken cancellationToken)
    {
        var session = await FindAccessibleSessionAsync(context, sessionId, cancellationToken).ConfigureAwait(false);
        MarkClosed(session, DateTimeOffset.UtcNow);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        var view = SessionView(session);
        await SendCloseAsync(view, cancellationToken).ConfigureAwait(false);
        return view;
    }

    public async Task<IReadOnlyList<PeerMeshSessionView>> CloseOpenSessionsAsync(ManagementContext context,
        CancellationToken cancellationToken)
    {
        IQueryable<PeerMeshSession> query = _db.PeerMeshSessions
            .Where(s => s.TenantId == context.TenantId && s.Status != StatusClosed);
        if (!context.IsAdmin)
        {
            var ids = await VisibleClientIdsAsync(context, cancellationToken).ConfigureAwait(false);
            query = query.Where(s => ids.Contains(s.SourceClientId) || ids.Contains(s.TargetClientId));
        }
        var sessions = await query.ToListAsync(cancellationToken).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        foreach (var session in sessions)
        {
            MarkClosed(session, now);
        }
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        var views = sessions.Select(SessionView).ToList();
        foreach (var view in views)
        {
            await SendCloseAsync(view, cancellationToken).ConfigureAwait(false);
        }
        return views;
    }

    private PeerMeshConfig BuildConfig(ClientAccount account, PeerMeshDevice? device, string? requestServerName)
    {
        var config = new PeerMeshConfig
        {
            Enabled = false,
            ClientId = account.Id,
            ClientName = account.ClientName,
            Cidr = _options.Cidr,
            SessionTtlSeconds = _options.SessionTtlSeconds,
        };
        if (!Enabled || device is null)
        {
            return config;
        }
        config.Enabled = device.Enabled;
        config.VirtualIp = device.VirtualIp;
        config.StunHost = ResolveStunHost(requestServerName);
        config.TurnHost = ResolvePeerHost(requestServerName);
        config.StunPort = StunPort();
        config.TurnPort = _options.StunTurnPort;
        config.PublicStunServers = _options.PublicStunServers
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(NormalizeStunUrl)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var turnCredential = _turnCredentials.Issue("pm-" + account.Id);
        config.IceUsername = turnCredential.Username;
        config.IceCredential = turnCredential.Credential;
        config.IceRealm = turnCredential.Realm;
        config.IceNonce = turnCredential.Nonce;
        config.ServerPublicKey = ServerPublicKey();
        config.ClientPublicKey = device.PublicKey;
        return config;
    }

    private async Task<PeerMeshDevice> EnsureDeviceAsync(ClientAccount account, string? peerPublicKey,
        CancellationToken cancellationToken)
    {
        var device = await _db.PeerMeshDevices.FirstOrDefaultAsync(
                d => d.TenantId == account.TenantId && d.ClientId == account.Id, cancellationToken)
            .ConfigureAwait(false)
            ?? await CreateDeviceAsync(account, cancellationToken).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        device.ClientName = account.ClientName;
        device.OwnerUsername = NormalizeOwner(account.OwnerUsername);
        if (!string.IsNullOrWhiteSpace(peerPublicKey))
        {
            device.PublicKey = Limit(peerPublicKey.Trim(), 256);
        }
        device.LastSeenAt = now;
        device.UpdatedAt = now;
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return device;
    }

    private async Task<PeerMeshDevice> CreateDeviceAsync(ClientAccount account, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var device = new PeerMeshDevice
        {
            Id = ClientIdGenerator.NewId(),
            TenantId = account.TenantId,
            OwnerUsername = NormalizeOwner(account.OwnerUsername),
            ClientId = account.Id,
            ClientName = account.ClientName,
            VirtualIp = await AllocateVirtualIpAsync(account, cancellationToken).ConfigureAwait(false),
            Cidr = _options.Cidr,
            Enabled = false,
            CreatedAt = now,
            UpdatedAt = now,
        };
        _db.PeerMeshDevices.Add(device);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return device;
    }

    private async Task<string> AllocateVirtualIpAsync(ClientAccount account, CancellationToken cancellationToken)
    {
        var parts = _options.Cidr.Split('/', 2);
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var baseAddress)
            || baseAddress.AddressFamily != AddressFamily.InterNetwork
            || !int.TryParse(parts[1], out var prefix) || prefix is < 0 or > 31)
        {
            throw new ArgumentException($"invalid peer mesh cidr: {_options.Cidr}");
        }
        var capacity = 1L << (32 - prefix);
        var usable = capacity - 2;
        var baseValue = Ipv4ToUInt32(baseAddress) & (uint.MaxValue << (32 - prefix));
        var seedBytes = SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{account.TenantId}:{account.OwnerUsername}:{account.Id}"));
        var seed = BitConverter.ToUInt32(seedBytes, 0) % (uint)usable;
        for (var i = 1L; i <= usable; i++)
        {
            var host = ((long)seed + i) % usable + 1;
            var ip = UInt32ToIpv4(baseValue + (uint)host);
            var exists = await _db.PeerMeshDevices.AsNoTracking()
                .AnyAsync(d => d.TenantId == account.TenantId && d.VirtualIp == ip, cancellationToken)
                .ConfigureAwait(false);
            if (!exists)
            {
                return ip;
            }
        }
        throw new InvalidOperationException($"peer mesh address pool exhausted: {_options.Cidr}");
    }

    private async Task FillSourceAsync(PeerControlMessage message, ClientAccount source,
        CancellationToken cancellationToken)
    {
        message.SourceClientId = source.Id;
        message.SourceClientName = source.ClientName;
        var device = await _db.PeerMeshDevices.AsNoTracking()
            .FirstOrDefaultAsync(d => d.TenantId == source.TenantId && d.ClientId == source.Id, cancellationToken)
            .ConfigureAwait(false);
        if (device is not null)
        {
            message.SourceVirtualIp = device.VirtualIp;
            message.SourcePublicKey = device.PublicKey;
        }
        if (message.CreatedAtMillis <= 0)
        {
            message.CreatedAtMillis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }
    }

    private async Task EnrichTargetAsync(PeerControlMessage message, ClientAccount target,
        CancellationToken cancellationToken)
    {
        message.TargetClientId = target.Id;
        message.TargetClientName = target.ClientName;
        var device = await _db.PeerMeshDevices.AsNoTracking()
            .FirstOrDefaultAsync(d => d.TenantId == target.TenantId && d.ClientId == target.Id, cancellationToken)
            .ConfigureAwait(false);
        if (device is not null)
        {
            message.TargetVirtualIp = device.VirtualIp;
            message.TargetPublicKey = device.PublicKey;
        }
    }

    public async Task<bool> CanPeerAsync(ClientAccount source, ClientAccount target, CancellationToken cancellationToken)
    {
        if (!string.Equals(source.TenantId, target.TenantId, StringComparison.Ordinal))
        {
            return false;
        }
        var sourceEnabled = await _db.PeerMeshDevices.AsNoTracking()
            .AnyAsync(d => d.TenantId == source.TenantId && d.ClientId == source.Id && d.Enabled, cancellationToken)
            .ConfigureAwait(false);
        var targetEnabled = await _db.PeerMeshDevices.AsNoTracking()
            .AnyAsync(d => d.TenantId == target.TenantId && d.ClientId == target.Id && d.Enabled, cancellationToken)
            .ConfigureAwait(false);
        if (!sourceEnabled || !targetEnabled)
        {
            return false;
        }
        if (string.Equals(NormalizeOwner(source.OwnerUsername), NormalizeOwner(target.OwnerUsername),
                StringComparison.Ordinal))
        {
            return true;
        }
        var forward = await _db.PeerMeshAcls.AsNoTracking().AnyAsync(a =>
                a.TenantId == source.TenantId
                && a.SourceClientId == source.Id
                && a.TargetClientId == target.Id
                && a.Allowed
                && (a.Direction == DirectionOutbound || a.Direction == DirectionBoth), cancellationToken)
            .ConfigureAwait(false);
        if (forward)
        {
            return true;
        }
        return await _db.PeerMeshAcls.AsNoTracking().AnyAsync(a =>
                a.TenantId == source.TenantId
                && a.SourceClientId == target.Id
                && a.TargetClientId == source.Id
                && a.Allowed
                && (a.Direction == DirectionInbound || a.Direction == DirectionBoth), cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<PeerSessionGrant> CreateSessionAsync(ClientAccount source, ClientAccount target,
        string pathType, CancellationToken cancellationToken)
    {
        if (!await CanPeerAsync(source, target, cancellationToken).ConfigureAwait(false))
        {
            throw new UnauthorizedAccessException("peer access denied");
        }
        var now = DateTimeOffset.UtcNow;
        var token = ShortToken(source.ClientName, target.ClientName, now.ToUnixTimeMilliseconds().ToString(), Guid.NewGuid().ToString("N"));
        var session = new PeerMeshSession
        {
            Id = ClientIdGenerator.NewId(),
            TenantId = source.TenantId,
            SourceClientId = source.Id,
            SourceClientName = source.ClientName,
            TargetClientId = target.Id,
            TargetClientName = target.ClientName,
            PathType = string.IsNullOrWhiteSpace(pathType) ? PathDirect : pathType,
            Status = StatusNegotiating,
            TokenHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant(),
            StartedAt = now,
            UpdatedAt = now,
            ExpiresAt = now.AddSeconds(_options.SessionTtlSeconds),
        };
        _db.PeerMeshSessions.Add(session);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return new PeerSessionGrant(SessionView(session), token);
    }

    private async Task ReportPathAsync(ClientAccount reporter, PeerControlMessage report,
        CancellationToken cancellationToken)
    {
        var session = await FindReportableSessionAsync(reporter, report.SessionId, cancellationToken)
            .ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        if (!CloseIfExpired(session, now))
        {
            if (!string.IsNullOrWhiteSpace(report.PathType))
            {
                session.PathType = session.DirectBytes <= 0 && session.RelayBytes <= 0
                    ? Limit(report.PathType, 40)!
                    : EffectivePathType(session);
            }
            session.Status = Limit(string.IsNullOrWhiteSpace(report.Status) ? StatusActive : report.Status, 40)!;
            session.RttMillis = report.RttMillis;
            session.LocalEndpoint = Limit(report.LocalEndpoint, 255);
            session.RemoteEndpoint = Limit(report.RemoteEndpoint, 255);
            session.UpdatedAt = now;
        }
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task ReportTrafficAsync(ClientAccount reporter, PeerControlMessage report,
        CancellationToken cancellationToken)
    {
        var session = await FindReportableSessionAsync(reporter, report.SessionId, cancellationToken)
            .ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        if (!CloseIfExpired(session, now))
        {
            ApplyTraffic(session, Math.Max(0, report.DirectBytes), Math.Max(0, report.RelayBytes), now);
        }
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task ReportDeviceAsync(ClientAccount reporter, PeerControlMessage report,
        CancellationToken cancellationToken)
    {
        var device = await _db.PeerMeshDevices.FirstOrDefaultAsync(
                d => d.TenantId == reporter.TenantId && d.ClientId == reporter.Id, cancellationToken)
            .ConfigureAwait(false)
            ?? await CreateDeviceAsync(reporter, cancellationToken).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        device.ClientName = reporter.ClientName;
        device.OwnerUsername = NormalizeOwner(reporter.OwnerUsername);
        if (report.VirtualDeviceMode is not null) device.VirtualDeviceMode = Limit(report.VirtualDeviceMode, 80);
        if (report.VirtualDeviceName is not null) device.VirtualDeviceName = Limit(report.VirtualDeviceName, 80);
        if (report.VirtualDeviceStatus is not null) device.VirtualDeviceStatus = Limit(report.VirtualDeviceStatus, 80);
        if (report.VirtualDeviceError is not null) device.VirtualDeviceError = Limit(report.VirtualDeviceError, 512);
        if (report.VirtualDeviceMode is not null || report.VirtualDeviceName is not null
            || report.VirtualDeviceStatus is not null || report.VirtualDeviceError is not null)
        {
            device.VirtualDeviceUpdatedAt = now;
        }
        if (report.NatType is not null) device.NatType = Limit(report.NatType, 80);
        if (report.NatMappingBehavior is not null)
            device.NatMappingBehavior = Limit(report.NatMappingBehavior, 80);
        if (report.NatFilteringBehavior is not null)
            device.NatFilteringBehavior = Limit(report.NatFilteringBehavior, 80);
        if (report.NatBehaviorDiscovery is not null)
            device.NatBehaviorDiscovery = Limit(report.NatBehaviorDiscovery, 40);
        if (report.LastEndpoint is not null) device.LastEndpoint = Limit(report.LastEndpoint, 255);
        device.LastSeenAt = now;
        device.UpdatedAt = now;
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task CloseSessionFromClientAsync(ClientAccount reporter, PeerControlMessage report,
        CancellationToken cancellationToken)
    {
        var session = await FindReportableSessionAsync(reporter, report.SessionId, cancellationToken)
            .ConfigureAwait(false);
        MarkClosed(session, DateTimeOffset.UtcNow);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task RefreshDeviceAsync(ManagementContext context, long clientId, bool enabled,
        CancellationToken cancellationToken)
    {
        var account = await FindAccessibleClientAsync(context, clientId, cancellationToken).ConfigureAwait(false);
        await PushConfigAsync(account, cancellationToken).ConfigureAwait(false);
        if (!enabled)
        {
            var sessions = await _db.PeerMeshSessions
                .Where(s => s.TenantId == context.TenantId && s.Status != StatusClosed
                    && (s.SourceClientId == clientId || s.TargetClientId == clientId))
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false);
            var now = DateTimeOffset.UtcNow;
            foreach (var session in sessions)
            {
                MarkClosed(session, now);
            }
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            foreach (var session in sessions.Select(SessionView))
            {
                await SendCloseAsync(session, cancellationToken).ConfigureAwait(false);
            }
        }
        var targets = await RosterRefreshTargetsAsync(account, cancellationToken).ConfigureAwait(false);
        foreach (var target in targets)
        {
            await PushRosterAsync(target, cancellationToken).ConfigureAwait(false);
        }
    }

    private Task<List<ClientAccount>> RosterRefreshTargetsAsync(ClientAccount account, CancellationToken cancellationToken) =>
        _db.ClientAccounts.AsNoTracking()
            .Where(c => c.TenantId == account.TenantId)
            .ToListAsync(cancellationToken);

    private async Task<IReadOnlyList<RosterItem>> AllowedRosterAsync(ClientAccount account,
        CancellationToken cancellationToken)
    {
        if (!Enabled)
        {
            return [];
        }
        var devices = await _db.PeerMeshDevices.AsNoTracking()
            .Where(d => d.TenantId == account.TenantId
                && d.OwnerUsername == NormalizeOwner(account.OwnerUsername)
                && d.Enabled)
            .ToDictionaryAsync(d => d.ClientId, cancellationToken)
            .ConfigureAwait(false);
        var acls = await _db.PeerMeshAcls.AsNoTracking()
            .Where(a => a.TenantId == account.TenantId && a.SourceClientId == account.Id && a.Allowed)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        foreach (var acl in acls)
        {
            var device = await _db.PeerMeshDevices.AsNoTracking()
                .FirstOrDefaultAsync(d => d.TenantId == account.TenantId && d.ClientId == acl.TargetClientId
                    && d.Enabled, cancellationToken)
                .ConfigureAwait(false);
            if (device is not null)
            {
                devices[device.ClientId] = device;
            }
        }
        devices.Remove(account.Id);
        var deviceIds = devices.Keys.ToArray();
        var messageSessions = deviceIds.Length == 0
            ? new Dictionary<long, ClientSession>()
            : (await _db.ClientSessions.AsNoTracking()
                .Where(session => session.TenantId == account.TenantId
                    && deviceIds.Contains(session.ClientId)
                    && session.Status == ClientAccountService.StatusNettyOnline)
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false))
                .GroupBy(session => session.ClientId)
                .ToDictionary(group => group.Key, group => group.Aggregate(MergeMessageCapabilities));
        return devices.Values.Select(device =>
        {
            var online = _sessions.Find(device.ClientName) is not null;
            messageSessions.TryGetValue(device.ClientId, out var capability);
            if (!online)
            {
                capability = null;
            }
            return new RosterItem(
                device.ClientId,
                device.ClientName,
                device.VirtualIp,
                device.PublicKey,
                online,
                capability?.MessageSendCapable ?? false,
                capability?.MessageReceiveCapable ?? false,
                capability?.MessageAttachmentsCapable ?? false,
                capability?.MessageMediaPreviewCapable ?? false,
                capability?.MessageMaxAttachmentBytes ?? 0L);
        }).ToList();
    }

    private static ClientSession MergeMessageCapabilities(ClientSession left, ClientSession right)
    {
        if (right.MessageReceiveCapable && !left.MessageReceiveCapable)
        {
            return right;
        }
        if (right.MessageSendCapable && !left.MessageSendCapable)
        {
            return right;
        }
        return right.MessageMaxAttachmentBytes > left.MessageMaxAttachmentBytes ? right : left;
    }

    private async Task SendSessionGrantAsync(ClientAccount source, ClientAccount target, PeerSessionGrant grant,
        CancellationToken cancellationToken)
    {
        var session = _sessions.Find(source.ClientName);
        if (session is null)
        {
            return;
        }
        var message = new PeerControlMessage
        {
            Type = TypeSessionGrant,
            SessionId = grant.Session.Id,
            SourceClientId = source.Id,
            SourceClientName = source.ClientName,
            TargetClientId = target.Id,
            TargetClientName = target.ClientName,
            Token = grant.Token,
            ExpiresAt = grant.Session.ExpiresAt,
            PathType = grant.Session.PathType,
            Status = grant.Session.Status,
            DataFrameVersion = 2,
            CreatedAtMillis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        };
        await FillSourceAsync(message, source, cancellationToken).ConfigureAwait(false);
        await EnrichTargetAsync(message, target, cancellationToken).ConfigureAwait(false);
        await SendSignalAsync(session, "server", source.ClientName, message, cancellationToken).ConfigureAwait(false);
    }

    private async Task SendCloseAsync(PeerMeshSessionView closed, CancellationToken cancellationToken)
    {
        var message = new PeerControlMessage
        {
            Type = TypeClose,
            SessionId = closed.Id,
            SourceClientId = closed.SourceClientId,
            SourceClientName = closed.SourceClientName,
            TargetClientId = closed.TargetClientId,
            TargetClientName = closed.TargetClientName,
            Status = closed.Status,
            Reason = "admin-force-close",
            CreatedAtMillis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        };
        foreach (var name in new[] { closed.SourceClientName, closed.TargetClientName })
        {
            var session = _sessions.Find(name);
            if (session is not null)
            {
                await SendSignalAsync(session, "server", name, message, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static ValueTask SendSignalAsync(SpecusConnectionContext session, string sourceClientName,
        string targetClientName, PeerControlMessage signal, CancellationToken cancellationToken)
    {
        return session.Writer.WriteAsync(new MessageResponsePacket
        {
            ClientName = sourceClientName,
            ToClientName = targetClientName,
            MessageType = MessageType.PeerControl,
            Message = JsonSerializer.Serialize(signal),
        }, cancellationToken);
    }

    private async Task<ClientAccount> FindAccessibleClientAsync(ManagementContext context, long clientId,
        CancellationToken cancellationToken)
    {
        var account = await _db.ClientAccounts.FirstOrDefaultAsync(c => c.Id == clientId, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new ArgumentException("client not found");
        if (!context.CanAccess(account))
        {
            throw new UnauthorizedAccessException("无权访问客户端");
        }
        return account;
    }

    private async Task<ClientAccount> FindTenantClientAsync(string tenantId, long clientId,
        CancellationToken cancellationToken)
    {
        return await _db.ClientAccounts.FirstOrDefaultAsync(c => c.Id == clientId && c.TenantId == tenantId,
                cancellationToken)
            .ConfigureAwait(false)
            ?? throw new ArgumentException("client not found");
    }

    private async Task<PeerMeshDevice> FindAccessibleDeviceAsync(ManagementContext context, long clientId,
        CancellationToken cancellationToken)
    {
        var device = await _db.PeerMeshDevices.FirstOrDefaultAsync(d => d.TenantId == context.TenantId
                && d.ClientId == clientId, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new ArgumentException("peer device not found");
        if (!context.IsAdmin && device.OwnerUsername != context.Username)
        {
            throw new UnauthorizedAccessException("无权访问客户端");
        }
        return device;
    }

    private async Task<PeerMeshSession> FindAccessibleSessionAsync(ManagementContext context, long sessionId,
        CancellationToken cancellationToken)
    {
        var session = await _db.PeerMeshSessions.FirstOrDefaultAsync(s => s.Id == sessionId,
                cancellationToken)
            .ConfigureAwait(false)
            ?? throw new ArgumentException("peer session not found");
        if (session.TenantId != context.TenantId)
        {
            throw new ArgumentException("peer session not found");
        }
        if (context.IsAdmin)
        {
            return session;
        }
        var ids = await VisibleClientIdsAsync(context, cancellationToken).ConfigureAwait(false);
        if (ids.Contains(session.SourceClientId) || ids.Contains(session.TargetClientId))
        {
            return session;
        }
        throw new ArgumentException("peer session not found");
    }

    private async Task<PeerMeshSession> FindReportableSessionAsync(ClientAccount reporter, long? sessionId,
        CancellationToken cancellationToken)
    {
        if (sessionId is null or <= 0)
        {
            throw new ArgumentException("sessionId is required");
        }
        var session = await _db.PeerMeshSessions.FirstOrDefaultAsync(s => s.Id == sessionId.Value,
                cancellationToken)
            .ConfigureAwait(false)
            ?? throw new ArgumentException("peer session not found");
        if (session.TenantId != reporter.TenantId
            || (session.SourceClientId != reporter.Id && session.TargetClientId != reporter.Id))
        {
            throw new ArgumentException("peer session report source mismatch");
        }
        return session;
    }

    private async Task<List<long>> VisibleClientIdsAsync(ManagementContext context, CancellationToken cancellationToken)
    {
        var query = _db.ClientAccounts.AsNoTracking().Where(c => c.TenantId == context.TenantId);
        if (!context.IsAdmin)
        {
            query = query.Where(c => c.OwnerUsername == context.Username);
        }
        return await query.Select(c => c.Id).ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task ExpireStaleSessionsAsync(CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var expired = await _db.PeerMeshSessions
            .Where(s => s.Status != StatusClosed && s.ExpiresAt <= now)
            .Take(500)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        foreach (var session in expired)
        {
            MarkClosed(session, now);
        }
        if (expired.Count > 0)
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task FlushRelayTrafficAsync(CancellationToken cancellationToken)
    {
        var pending = DrainPendingRelayBytes();
        if (pending.Count == 0)
        {
            return;
        }
        var now = DateTimeOffset.UtcNow;
        foreach (var (sessionId, bytes) in pending)
        {
            if (bytes <= 0)
            {
                continue;
            }
            var session = await _db.PeerMeshSessions.FirstOrDefaultAsync(s => s.Id == sessionId, cancellationToken)
                .ConfigureAwait(false);
            if (session is null)
            {
                RemoveRelaySession(sessionId);
                continue;
            }
            if (!CloseIfExpired(session, now))
            {
                ApplyTraffic(session, 0, bytes, now);
            }
        }
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    private bool CloseIfExpired(PeerMeshSession session, DateTimeOffset now)
    {
        if (session.Status == StatusClosed)
        {
            return true;
        }
        if (session.ExpiresAt > now)
        {
            return false;
        }
        MarkClosed(session, now);
        return true;
    }

    private void MarkClosed(PeerMeshSession session, DateTimeOffset now)
    {
        session.Status = StatusClosed;
        session.ClosedAt ??= now;
        session.UpdatedAt = now;
        RemoveRelaySession(session.Id);
    }

    private static void ApplyTraffic(PeerMeshSession session, long directBytes, long relayBytes, DateTimeOffset now)
    {
        if (directBytes <= 0 && relayBytes <= 0)
        {
            return;
        }
        session.DirectBytes = SaturatedAdd(session.DirectBytes, directBytes);
        session.RelayBytes = SaturatedAdd(session.RelayBytes, relayBytes);
        session.PathType = EffectivePathType(session);
        session.LastTrafficAt = now;
        session.UpdatedAt = now;
    }

    private bool AuthorizeRelayFrameCached(PeerDataFrameHeader header,
        long fromClientId, long toClientId, long bytes, DateTimeOffset now,
		bool account)
    {
        if (!_relayAuthorizations.TryGetValue(header.SessionId, out var authorization))
        {
            return false;
        }
        if (!authorization.ValidAt(now))
        {
            RemoveRelaySession(header.SessionId);
            return false;
        }
        // 0/0 means identity unknown (TURN auth disabled), consistent with the slow path.
        if (!authorization.Matches(fromClientId, toClientId))
        {
            return false;
        }
		if (account)
		{
			AddPendingRelayBytes(header.SessionId, bytes);
		}
        return true;
    }

    private void CacheRelayAuthorization(PeerMeshSession session, DateTimeOffset now)
    {
        _relayAuthorizations[session.Id] = new RelayAuthorization(
            session.SourceClientId,
            session.TargetClientId,
            string.Equals(session.Status, StatusActive, StringComparison.Ordinal),
            session.ExpiresAt,
            now.Add(RelayAuthorizationCacheTtl));
    }

    private void AddPendingRelayBytes(long sessionId, long bytes)
    {
        if (sessionId <= 0 || bytes <= 0)
        {
            return;
        }
        _pendingRelayBytes.AddOrUpdate(sessionId, bytes, (_, current) => SaturatedAdd(current, bytes));
    }

    private Dictionary<long, long> DrainPendingRelayBytes()
    {
        var snapshot = new Dictionary<long, long>();
        foreach (var (sessionId, _) in _pendingRelayBytes.ToArray())
        {
            if (_pendingRelayBytes.TryRemove(sessionId, out var bytes) && bytes > 0)
            {
                snapshot[sessionId] = bytes;
            }
        }
        return snapshot;
    }

    private void RemoveRelaySession(long sessionId)
    {
        if (sessionId <= 0)
        {
            return;
        }
        _relayAuthorizations.TryRemove(sessionId, out _);
        _pendingRelayBytes.TryRemove(sessionId, out _);
    }

    private PeerMeshDeviceView DeviceView(PeerMeshDevice device) => new(
        device.Id, device.ClientId, device.ClientName, device.OwnerUsername, device.Enabled,
        _sessions.Find(device.ClientName) is not null, device.VirtualIp, device.Cidr, device.PublicKey,
        device.NatType, device.NatMappingBehavior, device.NatFilteringBehavior,
        device.NatBehaviorDiscovery, device.LastEndpoint, device.VirtualDeviceMode, device.VirtualDeviceName,
        device.VirtualDeviceStatus, device.VirtualDeviceError, Iso(device.VirtualDeviceUpdatedAt),
        Iso(device.LastSeenAt), Iso(device.UpdatedAt)!);

    private static PeerMeshAclView AclView(PeerMeshAcl acl) => new(
        acl.Id, acl.SourceClientId, acl.SourceClientName, acl.TargetClientId, acl.TargetClientName,
        acl.Allowed, acl.Direction, Iso(acl.CreatedAt)!, Iso(acl.UpdatedAt)!);

    private static PeerMeshSessionView SessionView(PeerMeshSession session) => new(
        session.Id, session.SourceClientId, session.SourceClientName, session.TargetClientId,
        session.TargetClientName, EffectivePathType(session), session.Status, session.RttMillis,
        session.LocalEndpoint, session.RemoteEndpoint, session.DirectBytes, session.RelayBytes,
        Iso(session.LastTrafficAt), Iso(session.StartedAt)!, Iso(session.UpdatedAt)!,
        Iso(session.ExpiresAt)!, Iso(session.ClosedAt));

    private static string EffectivePathType(PeerMeshSession session)
    {
        if (session.RelayBytes > session.DirectBytes)
        {
            return PathRelay;
        }
        if (session.DirectBytes > session.RelayBytes)
        {
            return PathDirect;
        }
        return string.IsNullOrWhiteSpace(session.PathType) ? PathDirect : session.PathType;
    }

    private static int TotalPages(long total, int size) =>
        total <= 0 || size <= 0 ? 0 : (int)((total + size - 1) / size);

    private string ResolvePeerHost(string? requestServerName)
    {
        if (!string.IsNullOrWhiteSpace(_options.PublicAddress))
        {
            return NormalizeHost(_options.PublicAddress);
        }
        return NormalizeHost(requestServerName);
    }

    private string ResolveStunHost(string? requestServerName) =>
        HasStandaloneStun()
            ? NormalizeHost(_options.StandaloneStunAddress)
            : ResolvePeerHost(requestServerName);

    private int StunPort() =>
        HasStandaloneStun() ? _options.StandaloneStunPort : _options.StunTurnPort;

    private bool HasStandaloneStun() =>
        !string.IsNullOrWhiteSpace(_options.StandaloneStunAddress)
        && _options.StandaloneStunPort > 0;

    private static string NormalizeStunUrl(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }
        var normalized = value.Trim();
        if (normalized.StartsWith("stun://", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized["stun://".Length..];
        }
        else if (normalized.StartsWith("stun:", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized["stun:".Length..];
        }
        var host = NormalizeHost(normalized);
        return string.IsNullOrWhiteSpace(host)
            ? string.Empty
            : $"stun:{BracketIpv6(host)}:{ParsePort(normalized, 3478)}";
    }

    private static string NormalizeHost(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }
        var host = value.Trim();
        var scheme = host.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0)
        {
            host = host[(scheme + 3)..];
        }
        var slash = host.IndexOf('/', StringComparison.Ordinal);
        if (slash >= 0)
        {
            host = host[..slash];
        }
        if (host.StartsWith("[", StringComparison.Ordinal))
        {
            var close = host.IndexOf(']', StringComparison.Ordinal);
            return close > 0 ? host[1..close] : string.Empty;
        }
        var firstColon = host.IndexOf(':', StringComparison.Ordinal);
        var lastColon = host.LastIndexOf(':');
        if (firstColon > 0 && firstColon == lastColon)
        {
            host = host[..firstColon];
        }
        return host.Trim();
    }

    private static int ParsePort(string value, int fallback)
    {
        var normalized = value.Trim();
        var scheme = normalized.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0)
        {
            normalized = normalized[(scheme + 3)..];
        }
        var slash = normalized.IndexOf('/', StringComparison.Ordinal);
        if (slash >= 0)
        {
            normalized = normalized[..slash];
        }
        if (normalized.StartsWith("[", StringComparison.Ordinal))
        {
            var close = normalized.IndexOf(']', StringComparison.Ordinal);
            return close > 0 && close + 2 < normalized.Length && normalized[close + 1] == ':'
                ? ParsePortNumber(normalized[(close + 2)..], fallback)
                : fallback;
        }
        var firstColon = normalized.IndexOf(':', StringComparison.Ordinal);
        var lastColon = normalized.LastIndexOf(':');
        return firstColon > 0 && firstColon == lastColon && lastColon < normalized.Length - 1
            ? ParsePortNumber(normalized[(lastColon + 1)..], fallback)
            : fallback;
    }

    private static int ParsePortNumber(string value, int fallback) =>
        int.TryParse(value.Trim(), out var port) && port is > 0 and <= 65535 ? port : fallback;

    private static string BracketIpv6(string host) =>
        host.Contains(':', StringComparison.Ordinal) && !host.StartsWith("[", StringComparison.Ordinal)
            ? $"[{host}]"
            : host;

    private static string ShortToken(params string[] parts)
    {
        var random = RandomNumberGenerator.GetHexString(32).ToLowerInvariant();
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', parts))))
            .ToLowerInvariant();
        return $"{random}-{hash[..16]}";
    }

    private static string ServerPublicKey() =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("specus-peer-mesh-server")))
            .ToLowerInvariant();

    private static uint Ipv4ToUInt32(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    private static string UInt32ToIpv4(uint value) =>
        $"{(value >> 24) & 0xff}.{(value >> 16) & 0xff}.{(value >> 8) & 0xff}.{value & 0xff}";

    private static string NormalizeOwner(string? value) => string.IsNullOrWhiteSpace(value) ? "admin" : value.Trim();

    private static string? Limit(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];

    private static string? Iso(DateTimeOffset? value) => value?.UtcDateTime.ToString("O");

    private static long SaturatedAdd(long current, long delta)
    {
        if (delta <= 0)
        {
            return current;
        }
        return long.MaxValue - current < delta ? long.MaxValue : current + delta;
    }

    private sealed record RelayAuthorization(
        long SourceClientId,
        long TargetClientId,
        bool Active,
        DateTimeOffset SessionExpiresAt,
        DateTimeOffset CacheExpiresAt)
    {
        public bool ValidAt(DateTimeOffset now) =>
            Active && CacheExpiresAt > now && SessionExpiresAt > now;

        /// <summary>0/0 means identity unknown (TURN auth disabled), same as the slow path.</summary>
        public bool Matches(long fromClientId, long toClientId)
        {
            if (fromClientId <= 0 && toClientId <= 0)
            {
                return true;
            }
            var forward = fromClientId == SourceClientId && toClientId == TargetClientId;
            var reverse = fromClientId == TargetClientId && toClientId == SourceClientId;
            return forward || reverse;
        }
    }

    private sealed record PeerSessionGrant(PeerMeshSessionView Session, string Token);
}

public sealed record PublicStunConfig(
    bool PeerMeshEnabled,
    string SelfHostedStunServer,
    List<string> StunServers,
    int StunTurnPort);

public sealed record PublicIceConfig(
    bool PeerMeshEnabled,
    List<IceServer> IceServers,
    bool TurnAuthRequired,
    int StunTurnPort);

public sealed record IceServer(string Urls, string Username, string Credential);

public sealed record PeerMeshDeviceView(
    long Id,
    long ClientId,
    string ClientName,
    string OwnerUsername,
    bool Enabled,
    bool Online,
    string VirtualIp,
    string Cidr,
    string? PublicKey,
    string? NatType,
    string? NatMappingBehavior,
    string? NatFilteringBehavior,
    string? NatBehaviorDiscovery,
    string? LastEndpoint,
    string? VirtualDeviceMode,
    string? VirtualDeviceName,
    string? VirtualDeviceStatus,
    string? VirtualDeviceError,
    string? VirtualDeviceUpdatedAt,
    string? LastSeenAt,
    string UpdatedAt);

public sealed record PeerMeshAclView(
    long Id,
    long SourceClientId,
    string SourceClientName,
    long TargetClientId,
    string TargetClientName,
    bool Allowed,
    string Direction,
    string CreatedAt,
    string UpdatedAt);

public sealed record PeerMeshSessionView(
    long Id,
    long SourceClientId,
    string SourceClientName,
    long TargetClientId,
    string TargetClientName,
    string PathType,
    string Status,
    long? RttMillis,
    string? LocalEndpoint,
    string? RemoteEndpoint,
    long DirectBytes,
    long RelayBytes,
    string? LastTrafficAt,
    string StartedAt,
    string UpdatedAt,
    string ExpiresAt,
    string? ClosedAt);

public sealed record PeerMeshSessionPage(
    IReadOnlyList<PeerMeshSessionView> Items,
    long Total,
    int Page,
    int Size,
    int TotalPages);

public sealed record PeerMeshPathStatsView(
    long TotalSessions,
    long ReportedSessions,
    long ActiveSessions,
    long ActiveDirectSessions,
    long ActiveRelaySessions,
    double? ActiveDirectRatio,
    IReadOnlyList<PeerMeshPathTypeStat> PathTypes,
    IReadOnlyList<PeerMeshAddressFamilyStat> AddressFamilies,
    IReadOnlyList<PeerMeshNatTypeStat> NatTypes,
    long NatBehaviorDevices,
    long NatBehaviorClassifiedDevices,
    double? NatBehaviorSuccessRatio,
    IReadOnlyList<PeerMeshNatBehaviorStat> NatMappingBehaviors,
    IReadOnlyList<PeerMeshNatBehaviorStat> NatFilteringBehaviors,
    IReadOnlyList<PeerMeshNatBehaviorStat> NatBehaviorDiscoveries);

public sealed record PeerMeshPathTypeStat(
    string PathType,
    string Status,
    long Sessions,
    long ReportedSessions,
    double? AvgRttMillis,
    long DirectBytes,
    long RelayBytes);

public sealed record PeerMeshNatTypeStat(string NatType, long Devices);

public sealed record PeerMeshAddressFamilyStat(
    string AddressFamily,
    string Status,
    string PathType,
    long Sessions,
    long ReportedSessions);

public sealed record PeerMeshNatBehaviorStat(string Behavior, long Devices);

public sealed record PeerMeshDeviceMutation(bool? Enabled);

public sealed record PeerMeshAclMutation(long? SourceClientId, long? TargetClientId, bool? Allowed,
    string? Direction = null);

public sealed record RosterItem(
    [property: JsonPropertyName("clientId")] long ClientId,
    [property: JsonPropertyName("clientName")] string ClientName,
    [property: JsonPropertyName("virtualIp")] string VirtualIp,
    [property: JsonPropertyName("publicKey")] string? PublicKey,
    [property: JsonPropertyName("online")] bool Online,
    [property: JsonPropertyName("messageSendCapable")] bool MessageSendCapable,
    [property: JsonPropertyName("messageReceiveCapable")] bool MessageReceiveCapable,
    [property: JsonPropertyName("messageAttachmentsCapable")] bool MessageAttachmentsCapable,
    [property: JsonPropertyName("messageMediaPreviewCapable")] bool MessageMediaPreviewCapable,
    [property: JsonPropertyName("messageMaxAttachmentBytes")] long MessageMaxAttachmentBytes);

public sealed record PeerCandidate(
    [property: JsonPropertyName("type")] string? Type,
    [property: JsonPropertyName("transport")] string? Transport,
    [property: JsonPropertyName("address")] string? Address,
    [property: JsonPropertyName("port")] int Port,
    [property: JsonPropertyName("priority")] long Priority,
    [property: JsonPropertyName("foundation")] string? Foundation,
    [property: JsonPropertyName("relayId")] string? RelayId,
    [property: JsonPropertyName("addressFamily")] string? AddressFamily = null);

public sealed class PeerControlMessage
{
    [JsonPropertyName("type")]
    public string? Type { get; set; }

    [JsonPropertyName("sourceClientId")]
    public long SourceClientId { get; set; }

    [JsonPropertyName("sourceClientName")]
    public string? SourceClientName { get; set; }

    [JsonPropertyName("sourceVirtualIp")]
    public string? SourceVirtualIp { get; set; }

    [JsonPropertyName("sourcePublicKey")]
    public string? SourcePublicKey { get; set; }

    [JsonPropertyName("targetClientId")]
    public long TargetClientId { get; set; }

    [JsonPropertyName("targetClientName")]
    public string? TargetClientName { get; set; }

    [JsonPropertyName("targetVirtualIp")]
    public string? TargetVirtualIp { get; set; }

    [JsonPropertyName("targetPublicKey")]
    public string? TargetPublicKey { get; set; }

    [JsonPropertyName("sessionId")]
    public long? SessionId { get; set; }

    [JsonPropertyName("token")]
    public string? Token { get; set; }

    [JsonPropertyName("expiresAt")]
    public string? ExpiresAt { get; set; }

    [JsonPropertyName("pathType")]
    public string? PathType { get; set; }

    [JsonPropertyName("status")]
    public string? Status { get; set; }

    [JsonPropertyName("rttMillis")]
    public long? RttMillis { get; set; }

    [JsonPropertyName("localEndpoint")]
    public string? LocalEndpoint { get; set; }

    [JsonPropertyName("remoteEndpoint")]
    public string? RemoteEndpoint { get; set; }

    [JsonPropertyName("directBytes")]
    public long DirectBytes { get; set; }

    [JsonPropertyName("relayBytes")]
    public long RelayBytes { get; set; }

    [JsonPropertyName("natType")]
    public string? NatType { get; set; }

    [JsonPropertyName("natMappingBehavior")]
    public string? NatMappingBehavior { get; set; }

    [JsonPropertyName("natFilteringBehavior")]
    public string? NatFilteringBehavior { get; set; }

    [JsonPropertyName("natBehaviorDiscovery")]
    public string? NatBehaviorDiscovery { get; set; }

    [JsonPropertyName("lastEndpoint")]
    public string? LastEndpoint { get; set; }

    [JsonPropertyName("virtualDeviceMode")]
    public string? VirtualDeviceMode { get; set; }

    [JsonPropertyName("virtualDeviceName")]
    public string? VirtualDeviceName { get; set; }

    [JsonPropertyName("virtualDeviceStatus")]
    public string? VirtualDeviceStatus { get; set; }

    [JsonPropertyName("virtualDeviceError")]
    public string? VirtualDeviceError { get; set; }

    [JsonPropertyName("peerMesh")]
    public PeerMeshConfig? PeerMesh { get; set; }

    [JsonPropertyName("dataFrameVersion")]
    public int DataFrameVersion { get; set; } = 2;

    [JsonPropertyName("candidates")]
    public IReadOnlyList<PeerCandidate>? Candidates { get; set; }

    [JsonPropertyName("peers")]
    public IReadOnlyList<RosterItem>? Peers { get; set; }

    [JsonPropertyName("reason")]
    public string? Reason { get; set; }

    [JsonPropertyName("createdAtMillis")]
    public long CreatedAtMillis { get; set; }
}
