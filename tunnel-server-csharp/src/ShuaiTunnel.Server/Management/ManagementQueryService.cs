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
    private readonly RemotePortServerManager _remotePorts;

    public ManagementQueryService(TunnelDbContext db, SessionRegistry sessions,
        TrafficUsageService traffic, RemotePortServerManager remotePorts)
    {
        _db = db;
        _sessions = sessions;
        _traffic = traffic;
        _remotePorts = remotePorts;
    }

    public async Task<IReadOnlyList<ClientAccountView>> ListClientsAsync(CancellationToken cancellationToken)
    {
        await _traffic.FlushAsync(cancellationToken).ConfigureAwait(false);

        var totals = await _db.TrafficUsages.AsNoTracking()
            .GroupBy(t => t.ClientId)
            .Select(g => new
            {
                ClientId = g.Key,
                Upload = g.Sum(t => t.UploadBytes),
                Download = g.Sum(t => t.DownloadBytes),
            })
            .ToDictionaryAsync(t => t.ClientId, cancellationToken)
            .ConfigureAwait(false);

        var accounts = await _db.ClientAccounts.AsNoTracking()
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

    public async Task<OverviewResponse> GetOverviewAsync(CancellationToken cancellationToken)
    {
        var clients = await ListClientsAsync(cancellationToken).ConfigureAwait(false);
        var successful = await _db.ConnectionRecords.AsNoTracking()
            .LongCountAsync(r => r.Success, cancellationToken)
            .ConfigureAwait(false);
        var failed = await _db.ConnectionRecords.AsNoTracking()
            .LongCountAsync(r => !r.Success, cancellationToken)
            .ConfigureAwait(false);

        return new OverviewResponse(
            clients.Count,
            clients.Count(c => c.Online),
            successful,
            failed,
            clients.Sum(c => c.UploadBytes),
            clients.Sum(c => c.DownloadBytes),
            _remotePorts.ActiveExternalConnections,
            _remotePorts.RejectedExternalConnections);
    }

    public async Task<ConnectionPageResponse> ListConnectionsAsync(long? clientId, bool? success,
        string? from, string? to, int? page, int? size, CancellationToken cancellationToken)
    {
        var normalizedPage = Math.Max(0, page ?? 0);
        var normalizedSize = Math.Clamp(size ?? 100, 1, 500);
        var query = _db.ConnectionRecords.AsNoTracking();
        if (clientId is not null)
        {
            query = query.Where(r => r.ClientId == clientId.Value);
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

    public async Task<IReadOnlyList<TrafficUsageView>> ListTrafficAsync(long? clientId, int? limit,
        CancellationToken cancellationToken)
    {
        await _traffic.FlushAsync(cancellationToken).ConfigureAwait(false);
        var normalizedLimit = Math.Clamp(limit ?? 100, 1, 500);
        var query = _db.TrafficUsages.AsNoTracking();
        if (clientId is not null)
        {
            query = query.Where(t => t.ClientId == clientId.Value);
        }

        var rows = await query.OrderByDescending(t => t.UsageDate)
            .ThenByDescending(t => t.Id)
            .Take(normalizedLimit)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return rows.Select(ToTrafficView).ToList();
    }

    public async Task<IReadOnlyList<ConnectionStatView>> ListConnectionStatsAsync(string? clientName,
        int? limit, CancellationToken cancellationToken)
    {
        var normalizedLimit = Math.Clamp(limit ?? 100, 1, 500);
        var query = _db.ConnectionStats.AsNoTracking();
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

    private static ConnectionStatView ToConnectionStatView(ConnectionStat stat) => new(
        stat.Id,
        stat.ClientId,
        stat.ClientName,
        stat.StatMonth,
        stat.TotalCount,
        stat.SuccessCount,
        stat.FailureCount,
        stat.UpdatedAt.ToString("O"));

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
