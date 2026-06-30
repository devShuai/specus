using Microsoft.EntityFrameworkCore;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Data.Entities;
using ShuaiTunnel.Server.Nat;
using ShuaiTunnel.Server.Sessions;

namespace ShuaiTunnel.Server.Management;

public sealed class ManagementQueryService
{
    private readonly TunnelDbContext _db;
    private readonly SessionRegistry _sessions;
    private readonly TrafficUsageService _traffic;
    private readonly TrafficInspectionService _inspection;
    private readonly RemotePortServerManager _remotePorts;
    private readonly ElasticsearchTrafficDetailClient _elasticsearchTraffic;

    public ManagementQueryService(TunnelDbContext db, SessionRegistry sessions,
        TrafficUsageService traffic, RemotePortServerManager remotePorts,
        ElasticsearchTrafficDetailClient elasticsearchTraffic,
        TrafficInspectionService inspection)
    {
        _db = db;
        _sessions = sessions;
        _traffic = traffic;
        _inspection = inspection;
        _remotePorts = remotePorts;
        _elasticsearchTraffic = elasticsearchTraffic;
    }

    public async Task<IReadOnlyList<ClientDownloadLinkView>> ListPublicClientDownloadsAsync(
        CancellationToken cancellationToken)
    {
        var rows = await _db.ClientDownloadLinks.AsNoTracking()
            .Where(link => link.Enabled)
            .OrderBy(link => link.Implementation)
            .ThenBy(link => link.DisplayOrder)
            .ThenBy(link => link.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return rows.Select(ToClientDownloadLinkView).ToList();
    }

    public async Task<IReadOnlyList<ClientAccountView>> ListClientsAsync(ManagementContext context,
        CancellationToken cancellationToken)
    {
        await _traffic.FlushAsync(cancellationToken).ConfigureAwait(false);

        var totals = await _db.TrafficUsages.AsNoTracking()
            .Where(t => t.TenantId == context.TenantId || t.TenantId == null || t.TenantId == string.Empty)
            .GroupBy(t => t.ClientId)
            .Select(g => new
            {
                ClientId = g.Key,
                Upload = g.Sum(t => t.UploadBytes),
                Download = g.Sum(t => t.DownloadBytes),
            })
            .ToDictionaryAsync(t => t.ClientId, cancellationToken)
            .ConfigureAwait(false);

        var accounts = await VisibleAccounts(context).AsNoTracking()
            .OrderByDescending(c => c.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return accounts.Select(account =>
        {
            totals.TryGetValue(account.Id, out var total);
            var session = _sessions.Find(account.ClientName);
            return new ClientAccountView(
                account.Id,
                account.ClientName,
                account.OwnerUsername,
                account.Enabled,
                account.ConnectionRateLimitPerMinute,
                session is not null,
                session?.LoginTimeMs,
                total?.Upload ?? 0,
                total?.Download ?? 0,
                account.CreatedAt.ToString("O"),
                account.UpdatedAt.ToString("O"));
        }).ToList();
    }

    public async Task<ClientDetailView> GetClientAsync(ManagementContext context, long id,
        CancellationToken cancellationToken)
    {
        await _traffic.FlushAsync(cancellationToken).ConfigureAwait(false);

        var account = await VisibleAccounts(context).AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == id, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"client not found: {id}");
        var totals = await _db.TrafficUsages.AsNoTracking()
            .Where(t => t.ClientId == id
                        && (t.TenantId == context.TenantId || t.TenantId == null || t.TenantId == string.Empty))
            .GroupBy(t => t.ClientId)
            .Select(g => new
            {
                Upload = g.Sum(t => t.UploadBytes),
                Download = g.Sum(t => t.DownloadBytes),
            })
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);
        var session = _sessions.Find(account.ClientName);
        var client = new ClientAccountView(
            account.Id,
            account.ClientName,
            account.OwnerUsername,
            account.Enabled,
            account.ConnectionRateLimitPerMinute,
            session is not null,
            session?.LoginTimeMs,
            totals?.Upload ?? 0,
            totals?.Download ?? 0,
            account.CreatedAt.ToString("O"),
            account.UpdatedAt.ToString("O"));
        var tunnels = await _db.TunnelMappings.AsNoTracking()
            .Where(t => t.ClientId == id)
            .OrderByDescending(t => t.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        var httpRoutes = await _db.HttpRouteMappings.AsNoTracking()
            .Where(r => r.ClientId == id)
            .OrderByDescending(r => r.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return new ClientDetailView(
            client,
            tunnels.Select(ToTunnelView).ToList(),
            httpRoutes.Select(ToHttpRouteView).ToList());
    }

    public async Task<OverviewResponse> GetOverviewAsync(ManagementContext context,
        CancellationToken cancellationToken)
    {
        var clients = await ListClientsAsync(context, cancellationToken).ConfigureAwait(false);
        var visibleIds = clients.Select(c => c.Id).ToArray();
        long successful = 0;
        long failed = 0;
        if (visibleIds.Length > 0)
        {
            successful = await _db.ConnectionRecords.AsNoTracking()
                .LongCountAsync(r => (r.TenantId == context.TenantId || r.TenantId == null || r.TenantId == string.Empty)
                                     && r.ClientId != null && visibleIds.Contains(r.ClientId.Value) && r.Success,
                    cancellationToken)
                .ConfigureAwait(false);
            failed = await _db.ConnectionRecords.AsNoTracking()
                .LongCountAsync(r => (r.TenantId == context.TenantId || r.TenantId == null || r.TenantId == string.Empty)
                                     && r.ClientId != null && visibleIds.Contains(r.ClientId.Value) && !r.Success,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        return new OverviewResponse(
            clients.Count,
            clients.Count(c => c.Online),
            successful,
            failed,
            clients.Sum(c => c.UploadBytes),
            clients.Sum(c => c.DownloadBytes),
            context.IsAdmin ? _remotePorts.ActiveExternalConnections : 0,
            context.IsAdmin ? _remotePorts.RejectedExternalConnections : 0);
    }

    public async Task<ConnectionPageResponse> ListConnectionsAsync(ManagementContext context, long? clientId, bool? success,
        string? from, string? to, int? page, int? size, CancellationToken cancellationToken)
    {
        var normalizedPage = Math.Max(0, page ?? 0);
        var normalizedSize = Math.Clamp(size ?? 100, 1, 500);
        var query = _db.ConnectionRecords.AsNoTracking()
            .Where(r => r.TenantId == context.TenantId || r.TenantId == null || r.TenantId == string.Empty);
        var visibleIds = await VisibleClientIdsAsync(context, cancellationToken).ConfigureAwait(false);
        if (clientId is not null)
        {
            EnsureVisibleClient(visibleIds, clientId.Value);
            query = query.Where(r => r.ClientId == clientId.Value);
        }
        else if (visibleIds.Count == 0)
        {
            return new ConnectionPageResponse([], 0, normalizedPage, normalizedSize, 0);
        }
        else
        {
            query = query.Where(r => r.ClientId != null && visibleIds.Contains(r.ClientId.Value));
        }
        if (success is not null)
        {
            query = query.Where(r => r.Success == success.Value);
        }
        if (!string.IsNullOrWhiteSpace(from))
        {
            var fromInstant = ParseDateTimeFilter(from, "from");
            query = query.Where(r => r.ConnectedAt >= fromInstant);
        }
        if (!string.IsNullOrWhiteSpace(to))
        {
            var toInstant = ParseDateTimeFilter(to, "to");
            query = query.Where(r => r.ConnectedAt <= toInstant);
        }

        var total = await query.LongCountAsync(cancellationToken).ConfigureAwait(false);
        var rows = await query.OrderByDescending(r => r.Id)
            .Skip(normalizedPage * normalizedSize)
            .Take(normalizedSize)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        var totalPages = total == 0 ? 0 : (int)Math.Ceiling(total / (double)normalizedSize);
        return new ConnectionPageResponse(
            rows.Select(ToConnectionView).ToList(),
            total,
            normalizedPage,
            normalizedSize,
            totalPages);
    }

    public async Task<IReadOnlyList<TrafficUsageView>> ListTrafficAsync(ManagementContext context,
        long? clientId, int? limit, bool flush,
        CancellationToken cancellationToken)
    {
        if (flush)
        {
            await _traffic.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        var normalizedLimit = Math.Clamp(limit ?? 100, 1, 500);
        var query = _db.TrafficUsages.AsNoTracking()
            .Where(t => t.TenantId == context.TenantId || t.TenantId == null || t.TenantId == string.Empty);
        var visibleIds = await VisibleClientIdsAsync(context, cancellationToken).ConfigureAwait(false);
        if (clientId is not null)
        {
            EnsureVisibleClient(visibleIds, clientId.Value);
            query = query.Where(t => t.ClientId == clientId.Value);
        }
        else if (visibleIds.Count == 0)
        {
            return [];
        }
        else
        {
            query = query.Where(t => visibleIds.Contains(t.ClientId));
        }

        var rows = await query.OrderByDescending(t => t.UsageDate)
            .ThenByDescending(t => t.Id)
            .Take(normalizedLimit)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return rows.Select(ToTrafficView).ToList();
    }

    public async Task<IReadOnlyList<ResourceTrafficUsageView>> ListResourceTrafficAsync(
        ManagementContext context, string? resourceType, long? clientId, int? limit,
        bool flush,
        CancellationToken cancellationToken)
    {
        if (flush)
        {
            await _traffic.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        var normalizedLimit = Math.Clamp(limit ?? 100, 1, 500);
        var visibleIds = await VisibleClientIdsAsync(context, cancellationToken).ConfigureAwait(false);
        var query = _db.ResourceTrafficUsages.AsNoTracking()
            .Where(row => row.TenantId == context.TenantId);
        if (clientId is not null)
        {
            EnsureVisibleClient(visibleIds, clientId.Value);
            query = query.Where(row => row.ClientId == clientId.Value);
        }
        else if (visibleIds.Count == 0)
        {
            return [];
        }
        else
        {
            query = query.Where(row => visibleIds.Contains(row.ClientId));
        }

        if (!string.IsNullOrWhiteSpace(resourceType))
        {
            var normalizedType = resourceType.Trim().ToUpperInvariant();
            query = query.Where(row => row.ResourceType == normalizedType);
        }

        var rows = await query.OrderByDescending(row => row.UsageDate)
            .ThenByDescending(row => row.Id)
            .Take(normalizedLimit)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return rows.Select(ToResourceTrafficView).ToList();
    }

    public async Task<TrafficDetailPage<HttpTrafficExchangeView>> ListHttpExchangesAsync(
        ManagementContext context, long? clientId, string? route, string? responseBodyType,
        string? field, string? q, int? page, int? size, bool flush, CancellationToken cancellationToken)
    {
        if (flush)
        {
            await _inspection.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        var normalizedPage = Math.Max(0, page ?? 0);
        var normalizedSize = Math.Clamp(size ?? 50, 1, 500);
        var visibleIds = await VisibleClientIdsAsync(context, cancellationToken).ConfigureAwait(false);
        var query = _db.HttpTrafficExchanges.AsNoTracking()
            .Where(e => e.TenantId == context.TenantId);
        if (clientId is not null)
        {
            EnsureVisibleClient(visibleIds, clientId.Value);
            query = query.Where(e => e.ClientId == clientId.Value);
        }
        else if (visibleIds.Count == 0)
        {
            return new TrafficDetailPage<HttpTrafficExchangeView>([], 0, normalizedPage, normalizedSize, 0);
        }
        else
        {
            query = query.Where(e => visibleIds.Contains(e.ClientId));
        }
        var normalizedRoute = string.IsNullOrWhiteSpace(route) ? null : route.Trim();
        var normalizedResponseBodyType = NormalizeResponseBodyType(responseBodyType);
        if (_elasticsearchTraffic.IsEnabled)
        {
            return await _elasticsearchTraffic.ListHttpAsync(context, visibleIds, clientId, normalizedRoute,
                    normalizedResponseBodyType, field, q, normalizedPage, normalizedSize, cancellationToken)
                .ConfigureAwait(false);
        }
        if (normalizedRoute is not null)
        {
            query = query.Where(e => e.Route == normalizedRoute);
        }
        if (normalizedResponseBodyType is not null)
        {
            query = ApplyResponseBodyTypeFilter(query, normalizedResponseBodyType);
        }
        query = ApplyHttpExchangeSearch(query, field, q);

        var total = await query.LongCountAsync(cancellationToken).ConfigureAwait(false);
        var rows = await query.OrderByDescending(e => e.Id)
            .Skip(normalizedPage * normalizedSize)
            .Take(normalizedSize)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return new TrafficDetailPage<HttpTrafficExchangeView>(
            rows.Select(ToHttpTrafficExchangeView).ToList(),
            total,
            normalizedPage,
            normalizedSize,
            TotalPages(total, normalizedSize));
    }

    public async Task<TrafficDetailPage<TcpTrafficFrameView>> ListTcpFramesAsync(
        ManagementContext context, long? clientId, int? listenPort, int? page, int? size,
        int? limit, bool flush, CancellationToken cancellationToken)
    {
        if (flush)
        {
            await _inspection.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        var normalizedPage = Math.Max(0, page ?? 0);
        var normalizedSize = Math.Clamp(size ?? limit ?? 50, 1, 500);
        var visibleIds = await VisibleClientIdsAsync(context, cancellationToken).ConfigureAwait(false);
        var query = _db.TcpTrafficFrames.AsNoTracking()
            .Where(f => f.TenantId == context.TenantId);
        if (clientId is not null)
        {
            EnsureVisibleClient(visibleIds, clientId.Value);
            query = query.Where(f => f.ClientId == clientId.Value);
        }
        else if (visibleIds.Count == 0)
        {
            return new TrafficDetailPage<TcpTrafficFrameView>([], 0, normalizedPage, normalizedSize, 0);
        }
        else
        {
            query = query.Where(f => visibleIds.Contains(f.ClientId));
        }
        if (_elasticsearchTraffic.IsEnabled)
        {
            return await _elasticsearchTraffic.ListTcpAsync(context, visibleIds, clientId, listenPort,
                    normalizedPage, normalizedSize, cancellationToken)
                .ConfigureAwait(false);
        }
        if (listenPort is not null)
        {
            query = query.Where(f => f.ListenPort == listenPort.Value);
        }

        var total = await query.LongCountAsync(cancellationToken).ConfigureAwait(false);
        var rows = await query.OrderByDescending(f => f.Id)
            .Skip(normalizedPage * normalizedSize)
            .Take(normalizedSize)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return new TrafficDetailPage<TcpTrafficFrameView>(
            rows.Select(f => ToTcpTrafficFrameView(f, includePayload: false)).ToList(),
            total,
            normalizedPage,
            normalizedSize,
            TotalPages(total, normalizedSize));
    }

    public async Task<TcpTrafficFrameView?> GetTcpFrameAsync(ManagementContext context, long id, bool flush,
        CancellationToken cancellationToken)
    {
        if (flush)
        {
            await _inspection.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        var visibleIds = await VisibleClientIdsAsync(context, cancellationToken).ConfigureAwait(false);
        if (_elasticsearchTraffic.IsEnabled)
        {
            return await _elasticsearchTraffic.GetTcpFrameAsync(context, visibleIds, id, cancellationToken)
                .ConfigureAwait(false);
        }
        var frame = await _db.TcpTrafficFrames.AsNoTracking()
            .FirstOrDefaultAsync(f => f.TenantId == context.TenantId
                                      && f.Id == id
                                      && visibleIds.Contains(f.ClientId), cancellationToken)
            .ConfigureAwait(false);
        return frame is null ? null : ToTcpTrafficFrameView(frame, includePayload: true);
    }

    public async Task<object> ListTcpStreamAsync(ManagementContext context, string channelId, int? limit, bool flush,
        CancellationToken cancellationToken)
    {
        if (flush)
        {
            await _inspection.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        if (string.IsNullOrWhiteSpace(channelId))
        {
            throw new ArgumentException("channelId 不能为空");
        }
        var normalizedLimit = Math.Clamp(limit ?? 500, 1, 1000);
        var visibleIds = await VisibleClientIdsAsync(context, cancellationToken).ConfigureAwait(false);
        if (_elasticsearchTraffic.IsEnabled)
        {
            var streamItems = await _elasticsearchTraffic.ListTcpStreamAsync(context, visibleIds, channelId,
                    normalizedLimit, cancellationToken)
                .ConfigureAwait(false);
            return new
            {
                channelId,
                items = streamItems,
                total = streamItems.Count,
                limit = normalizedLimit,
                truncated = streamItems.Count >= normalizedLimit,
            };
        }
        var rows = await _db.TcpTrafficFrames.AsNoTracking()
            .Where(f => f.TenantId == context.TenantId
                        && f.ChannelId == channelId
                        && visibleIds.Contains(f.ClientId))
            .OrderBy(f => f.Id)
            .Take(normalizedLimit)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        var items = rows.Select(f => ToTcpTrafficFrameView(f, includePayload: true)).ToList();
        return new
        {
            channelId,
            items,
            total = items.Count,
            limit = normalizedLimit,
            truncated = items.Count >= normalizedLimit,
        };
    }

    public async Task<IReadOnlyList<ConnectionStatView>> ListConnectionStatsAsync(ManagementContext context,
        string? clientName,
        int? limit, CancellationToken cancellationToken)
    {
        var normalizedLimit = Math.Clamp(limit ?? 100, 1, 500);
        var query = _db.ConnectionStats.AsNoTracking()
            .Where(s => s.TenantId == context.TenantId);
        IReadOnlyList<long> visibleIds = Array.Empty<long>();
        if (!context.IsAdmin)
        {
            visibleIds = await VisibleClientIdsAsync(context, cancellationToken).ConfigureAwait(false);
        }
        if (!context.IsAdmin)
        {
            if (visibleIds.Count == 0)
            {
                return [];
            }
            query = query.Where(s => s.ClientId != null && visibleIds.Contains(s.ClientId.Value));
        }
        if (!string.IsNullOrWhiteSpace(clientName))
        {
            var normalizedName = clientName.Trim();
            query = query.Where(s => s.ClientName == normalizedName);
        }

        var rows = await query.OrderByDescending(s => s.StatMonth)
            .ThenBy(s => s.ClientName)
            .Take(normalizedLimit)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return rows.Select(ToConnectionStatView).ToList();
    }

    private IQueryable<ClientAccount> VisibleAccounts(ManagementContext context)
    {
        var query = _db.ClientAccounts.Where(c => c.TenantId == context.TenantId);
        if (!context.IsAdmin)
        {
            query = query.Where(c => c.OwnerUsername == context.Username);
        }
        return query;
    }

    private async Task<IReadOnlyList<long>> VisibleClientIdsAsync(ManagementContext context,
        CancellationToken cancellationToken) =>
        await VisibleAccounts(context).AsNoTracking()
            .Select(c => c.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

    private async Task<IReadOnlyList<string>> VisibleClientNamesAsync(ManagementContext context,
        CancellationToken cancellationToken) =>
        await VisibleAccounts(context).AsNoTracking()
            .Select(c => c.ClientName)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

    private static void EnsureVisibleClient(IReadOnlyList<long> visibleIds, long clientId)
    {
        if (!visibleIds.Contains(clientId))
        {
            throw new UnauthorizedAccessException("无权访问客户端");
        }
    }

    private static DateTimeOffset ParseDateTimeFilter(string value, string field)
    {
        if (!DateTimeOffset.TryParse(value, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal, out var parsed))
        {
            throw new ArgumentException($"{field} is not a valid timestamp");
        }
        return parsed.ToUniversalTime();
    }

    private static ConnectionRecordView ToConnectionView(ConnectionRecord record)
    {
        var reason = DisconnectReasonExtensions.Parse(record.DisconnectReason);
        return new ConnectionRecordView(
            record.Id,
            record.ClientId,
            record.ClientName,
            record.ChannelId,
            record.RemoteAddress,
            record.ConnectedAt.ToString("O"),
            record.DisconnectedAt?.ToString("O"),
            record.Success,
            record.FailureReason,
            reason?.ToWireString(),
            reason is null ? null : ReasonText(reason.Value));
    }

    private static TrafficUsageView ToTrafficView(Data.Entities.TrafficUsage usage) => new(
        usage.Id,
        usage.ClientId,
        usage.ClientName,
        usage.UsageDate,
        usage.UploadBytes,
        usage.DownloadBytes,
        usage.UpdatedAt.ToString("O"));

    private static TunnelMappingView ToTunnelView(TunnelMapping mapping) => new(
        mapping.Id,
        mapping.ClientId,
        mapping.ClientName,
        mapping.ListenPort,
        mapping.TargetAddress,
        mapping.TargetPort,
        mapping.Enabled,
        mapping.DetailCaptureEnabled,
        mapping.CreatedAt.ToString("O"),
        mapping.UpdatedAt.ToString("O"));

    private static HttpRouteView ToHttpRouteView(HttpRouteMapping row) => new(
        row.Id,
        row.ClientId,
        row.ClientName,
        row.Route,
        row.TargetBaseUrl,
        row.Enabled,
        row.DetailCaptureEnabled,
        row.PathRewriteEnabled,
        row.CreatedAt.ToString("O"),
        row.UpdatedAt.ToString("O"));

    private static ResourceTrafficUsageView ToResourceTrafficView(ResourceTrafficUsage usage) => new(
        usage.Id,
        usage.ClientId,
        usage.ClientName,
        usage.ResourceType,
        usage.ResourceKey,
        usage.ResourceId,
        usage.ResourceName,
        usage.UsageDate,
        usage.UploadBytes,
        usage.DownloadBytes,
        usage.UpdatedAt.ToString("O"));

    private static ClientDownloadLinkView ToClientDownloadLinkView(ClientDownloadLink link) => new(
        link.Id,
        link.Implementation,
        link.Platform,
        link.Arch,
        link.DisplayName,
        link.DownloadUrl,
        link.Description,
        link.DisplayOrder,
        link.Enabled,
        link.CreatedAt.ToString("O"),
        link.UpdatedAt.ToString("O"));

    private static HttpTrafficExchangeView ToHttpTrafficExchangeView(HttpTrafficExchange exchange) => new(
        exchange.Id.ToString(System.Globalization.CultureInfo.InvariantCulture),
        exchange.ClientId,
        exchange.ClientName,
        exchange.Route,
        exchange.ResourceId,
        exchange.ResourceName,
        exchange.Method,
        exchange.RelativePath,
        exchange.RawQuery,
        exchange.StatusCode,
        exchange.Success,
        exchange.Error,
        exchange.RemoteAddress,
        exchange.RequestBytes,
        exchange.ResponseBytes,
        exchange.ElapsedMs,
        exchange.RequestContentType,
        exchange.ResponseContentType,
        NormalizeOrClassifyBodyType(exchange.ResponseBodyType, exchange.ResponseContentType, exchange.ResponseBytes),
        exchange.RequestHeaders,
        exchange.ResponseHeaders,
        exchange.RequestPreviewHex,
        exchange.RequestPreviewText,
        exchange.ResponsePreviewHex,
        exchange.ResponsePreviewText,
        exchange.RequestTruncated,
        exchange.ResponseTruncated,
        exchange.CapturedAt.ToString("O"));

    private static TcpTrafficFrameView ToTcpTrafficFrameView(TcpTrafficFrame frame, bool includePayload) => new(
        frame.Id.ToString(System.Globalization.CultureInfo.InvariantCulture),
        frame.ClientId,
        frame.ClientName,
        frame.ListenPort,
        frame.ResourceId,
        frame.ResourceName,
        frame.ChannelId,
        frame.Direction,
        frame.RemoteAddress,
        frame.SourceAddress,
        frame.SourcePort,
        frame.DestinationAddress,
        frame.DestinationPort,
        frame.StreamOffset,
        frame.StreamEndOffset,
        frame.FrameIndex,
        frame.PayloadBytes,
        includePayload && frame.PayloadData.Length > 0 ? Convert.ToBase64String(frame.PayloadData) : null,
        frame.PayloadPreviewHex,
        frame.PayloadPreviewText,
        frame.Truncated,
        frame.FrameTime.ToString("O"));

    private static ConnectionStatView ToConnectionStatView(ConnectionStat stat) => new(
        stat.Id,
        stat.ClientId,
        stat.ClientName,
        stat.StatMonth,
        stat.TotalCount,
        stat.SuccessCount,
        stat.FailureCount,
        stat.UpdatedAt.ToString("O"));

    private static IQueryable<HttpTrafficExchange> ApplyHttpExchangeSearch(
        IQueryable<HttpTrafficExchange> query, string? field, string? q)
    {
        if (string.IsNullOrWhiteSpace(q))
        {
            return query;
        }
        var normalizedField = NormalizeHttpSearchField(field);
        foreach (var token in q.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            query = ApplyHttpExchangeSearchToken(query, normalizedField, token);
        }
        return query;
    }

    private static string? NormalizeResponseBodyType(string? value)
    {
        var normalized = (value ?? string.Empty).Trim().ToLowerInvariant();
        return normalized is "empty" or "json" or "html" or "xml" or "image" or "video" or "audio"
            or "form" or "script" or "text" or "binary"
            ? normalized
            : null;
    }

    private static string NormalizeOrClassifyBodyType(string? bodyType, string? contentType, long responseBytes)
    {
        var normalized = NormalizeResponseBodyType(bodyType);
        return normalized ?? ClassifyBodyType(contentType, responseBytes);
    }

    private static string ClassifyBodyType(string? contentType, long responseBytes)
    {
        if (responseBytes <= 0)
        {
            return "empty";
        }
        var media = (contentType ?? string.Empty).Split(';', 2)[0].Trim().ToLowerInvariant();
        if (media == "application/json" || media.EndsWith("+json", StringComparison.Ordinal)) return "json";
        if (media == "text/html") return "html";
        if (media is "application/xml" or "text/xml" || media.EndsWith("+xml", StringComparison.Ordinal)) return "xml";
        if (media.StartsWith("image/", StringComparison.Ordinal)) return "image";
        if (media.StartsWith("video/", StringComparison.Ordinal)) return "video";
        if (media.StartsWith("audio/", StringComparison.Ordinal)) return "audio";
        if (media is "application/x-www-form-urlencoded" or "multipart/form-data") return "form";
        if (media.Contains("javascript", StringComparison.Ordinal) || media.Contains("ecmascript", StringComparison.Ordinal)) return "script";
        if (media.StartsWith("text/", StringComparison.Ordinal)) return "text";
        return "binary";
    }

    private static IQueryable<HttpTrafficExchange> ApplyResponseBodyTypeFilter(
        IQueryable<HttpTrafficExchange> query, string bodyType) => bodyType switch
        {
            "empty" => query.Where(e => e.ResponseBodyType.ToLower() == "empty" || e.ResponseBytes == 0),
            "json" => query.Where(e =>
                e.ResponseBodyType.ToLower() == "json"
                || (e.ResponseContentType != null && (e.ResponseContentType.ToLower().Contains("application/json")
                    || e.ResponseContentType.ToLower().Contains("+json")))),
            "html" => query.Where(e =>
                e.ResponseBodyType.ToLower() == "html"
                || (e.ResponseContentType != null && e.ResponseContentType.ToLower().Contains("text/html"))),
            "xml" => query.Where(e =>
                e.ResponseBodyType.ToLower() == "xml"
                || (e.ResponseContentType != null && (e.ResponseContentType.ToLower().Contains("application/xml")
                    || e.ResponseContentType.ToLower().Contains("text/xml")
                    || e.ResponseContentType.ToLower().Contains("+xml")))),
            "image" => query.Where(e =>
                e.ResponseBodyType.ToLower() == "image"
                || (e.ResponseContentType != null && e.ResponseContentType.ToLower().StartsWith("image/"))),
            "video" => query.Where(e =>
                e.ResponseBodyType.ToLower() == "video"
                || (e.ResponseContentType != null && e.ResponseContentType.ToLower().StartsWith("video/"))),
            "audio" => query.Where(e =>
                e.ResponseBodyType.ToLower() == "audio"
                || (e.ResponseContentType != null && e.ResponseContentType.ToLower().StartsWith("audio/"))),
            "form" => query.Where(e =>
                e.ResponseBodyType.ToLower() == "form"
                || (e.ResponseContentType != null && (e.ResponseContentType.ToLower().Contains("application/x-www-form-urlencoded")
                    || e.ResponseContentType.ToLower().Contains("multipart/form-data")))),
            "script" => query.Where(e =>
                e.ResponseBodyType.ToLower() == "script"
                || (e.ResponseContentType != null && (e.ResponseContentType.ToLower().Contains("javascript")
                    || e.ResponseContentType.ToLower().Contains("ecmascript")))),
            "text" => query.Where(e =>
                e.ResponseBodyType.ToLower() == "text"
                || (e.ResponseContentType != null && e.ResponseContentType.ToLower().StartsWith("text/"))),
            "binary" => query.Where(e =>
                e.ResponseBodyType.ToLower() == "binary"
                || (e.ResponseContentType != null && (e.ResponseContentType.ToLower().Contains("application/octet-stream")
                    || e.ResponseContentType.ToLower().Contains("application/pdf")
                    || e.ResponseContentType.ToLower().Contains("application/zip")
                    || e.ResponseContentType.ToLower().Contains("application/x-")
                    || e.ResponseContentType.ToLower().Contains("application/vnd.")))),
            _ => query,
        };

    private static string NormalizeHttpSearchField(string? field) =>
        (field ?? string.Empty).Trim().ToLowerInvariant().Replace("_", string.Empty).Replace("-", string.Empty);

    private static IQueryable<HttpTrafficExchange> ApplyHttpExchangeSearchToken(
        IQueryable<HttpTrafficExchange> query, string field, string token)
    {
        var lower = token.ToLowerInvariant();
        var hasNumber = long.TryParse(token, out var number);
        return field switch
        {
            "method" => query.Where(e => e.Method.ToLower() == lower),
            "id" when hasNumber => query.Where(e => e.Id == number),
            "id" => query.Where(_ => false),
            "status" or "statuscode" when hasNumber => query.Where(e => e.StatusCode == number),
            "status" or "statuscode" => query.Where(_ => false),
            "route" => query.Where(e => e.Route.ToLower().Contains(lower)),
            "path" or "relativepath" => query.Where(e =>
                e.RelativePath.ToLower().Contains(lower)
                || (e.RawQuery != null && e.RawQuery.ToLower().Contains(lower))),
            "query" or "rawquery" =>
                query.Where(e => e.RawQuery != null && e.RawQuery.ToLower().Contains(lower)),
            "client" or "clientid" or "clientname" => query.Where(e =>
                e.ClientName.ToLower().Contains(lower) || (hasNumber && e.ClientId == number)),
            "resource" or "resourceid" or "resourcename" => query.Where(e =>
                (e.ResourceName != null && e.ResourceName.ToLower().Contains(lower))
                || (hasNumber && e.ResourceId == number)),
            "remote" or "remoteaddress" =>
                query.Where(e => e.RemoteAddress != null && e.RemoteAddress.ToLower().Contains(lower)),
            "contenttype" => query.Where(e =>
                (e.RequestContentType != null && e.RequestContentType.ToLower().Contains(lower))
                || (e.ResponseContentType != null && e.ResponseContentType.ToLower().Contains(lower))
                || e.ResponseBodyType.ToLower() == lower),
            "error" => query.Where(e => e.Error != null && e.Error.ToLower().Contains(lower)),
            "responsebodytype" or "responsedatatype" =>
                query.Where(e => e.ResponseBodyType.ToLower() == lower),
            "requestheaders" =>
                query.Where(e => e.RequestHeaders != null && e.RequestHeaders.ToLower().Contains(lower)),
            "responseheaders" =>
                query.Where(e => e.ResponseHeaders != null && e.ResponseHeaders.ToLower().Contains(lower)),
            "headers" => query.Where(e =>
                (e.RequestHeaders != null && e.RequestHeaders.ToLower().Contains(lower))
                || (e.ResponseHeaders != null && e.ResponseHeaders.ToLower().Contains(lower))),
            "requestbody" =>
                query.Where(e => e.RequestPreviewText != null && e.RequestPreviewText.ToLower().Contains(lower)),
            "responsebody" =>
                query.Where(e => e.ResponsePreviewText != null && e.ResponsePreviewText.ToLower().Contains(lower)),
            "body" => query.Where(e =>
                (e.RequestPreviewText != null && e.RequestPreviewText.ToLower().Contains(lower))
                || (e.ResponsePreviewText != null && e.ResponsePreviewText.ToLower().Contains(lower))),
            "all" => query.Where(e =>
                e.ClientName.ToLower().Contains(lower)
                || e.Route.ToLower().Contains(lower)
                || (e.ResourceName != null && e.ResourceName.ToLower().Contains(lower))
                || e.Method.ToLower().Contains(lower)
                || e.RelativePath.ToLower().Contains(lower)
                || (e.RawQuery != null && e.RawQuery.ToLower().Contains(lower))
                || (e.Error != null && e.Error.ToLower().Contains(lower))
                || (e.RemoteAddress != null && e.RemoteAddress.ToLower().Contains(lower))
                || (e.RequestContentType != null && e.RequestContentType.ToLower().Contains(lower))
                || (e.ResponseContentType != null && e.ResponseContentType.ToLower().Contains(lower))
                || e.ResponseBodyType.ToLower().Contains(lower)
                || (e.RequestHeaders != null && e.RequestHeaders.ToLower().Contains(lower))
                || (e.ResponseHeaders != null && e.ResponseHeaders.ToLower().Contains(lower))
                || (e.RequestPreviewText != null && e.RequestPreviewText.ToLower().Contains(lower))
                || (e.ResponsePreviewText != null && e.ResponsePreviewText.ToLower().Contains(lower))
                || (hasNumber && (e.Id == number || e.ClientId == number || e.StatusCode == number || e.ResourceId == number))),
            _ => query.Where(e =>
                e.ClientName.ToLower().Contains(lower)
                || e.Route.ToLower().Contains(lower)
                || (e.ResourceName != null && e.ResourceName.ToLower().Contains(lower))
                || e.Method.ToLower().Contains(lower)
                || e.RelativePath.ToLower().Contains(lower)
                || (e.RawQuery != null && e.RawQuery.ToLower().Contains(lower))
                || (e.Error != null && e.Error.ToLower().Contains(lower))
                || (e.RemoteAddress != null && e.RemoteAddress.ToLower().Contains(lower))
                || (e.RequestContentType != null && e.RequestContentType.ToLower().Contains(lower))
                || (e.ResponseContentType != null && e.ResponseContentType.ToLower().Contains(lower))
                || e.ResponseBodyType.ToLower().Contains(lower)
                || (hasNumber && (e.Id == number || e.ClientId == number || e.StatusCode == number || e.ResourceId == number))),
        };
    }

    private static int TotalPages(long total, int size) =>
        size <= 0 || total == 0 ? 0 : (int)Math.Ceiling(total / (double)size);

    private static string ReasonText(DisconnectReason reason) => reason switch
    {
        DisconnectReason.LoginFailure => "登录失败",
        DisconnectReason.ClientClosed => "客户端正常断开",
        DisconnectReason.IoError => "传输异常",
        DisconnectReason.IdleTimeout => "读空闲超时(60s)",
        DisconnectReason.HeartbeatWriteFailed => "心跳发送失败",
        DisconnectReason.ProtocolViolation => "协议违规",
        DisconnectReason.RegisterFailed => "注册失败",
        DisconnectReason.ReplacedByNewLogin => "被新登录替换",
        DisconnectReason.AdminDisabled => "管理员停用账号",
        DisconnectReason.AdminRenamed => "管理员修改账号名",
        DisconnectReason.AdminDeleted => "管理员删除账号",
        DisconnectReason.ServerBusy => "服务端繁忙拒绝",
        DisconnectReason.ServerShutdown => "服务端优雅停机",
        DisconnectReason.ServerRestarted => "服务端重启时清理",
        DisconnectReason.Unknown => "未知",
        _ => "未知",
    };
}
