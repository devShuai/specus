using Microsoft.EntityFrameworkCore;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Data.Entities;
using ShuaiTunnel.Server.Management;
using ShuaiTunnel.Server.WebSockets;

namespace ShuaiTunnel.Server.Authentication;

/// <summary>
/// Persists the audit row for a control-channel login. Phase 2 only writes the
/// <see cref="RecordConnectionAsync"/> + <see cref="RecordDisconnectAsync"/> half; the
/// startup/shutdown sweepers and WebSocket broadcast hooks land in Phase 4.
/// </summary>
public sealed class ConnectionRecordService
{
    private readonly TunnelDbContext _db;
    private readonly ConnectionEventsHub _events;

    public ConnectionRecordService(TunnelDbContext db, ConnectionEventsHub events)
    {
        _db = db;
        _events = events;
    }

    /// <summary>
    /// Always writes a row — successes get <see cref="ConnectionRecord.DisconnectedAt"/> = null
    /// (closed later via <see cref="RecordDisconnectAsync"/>); failures get both timestamps and
    /// a stamped reason of <c>LOGIN_FAILURE</c>.
    /// </summary>
    public async Task<long> RecordConnectionAsync(AuthenticationResult result, string clientName,
        string channelId, string? remoteAddress, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var record = new ConnectionRecord
        {
            TenantId = result.Account?.TenantId ?? "default",
            ClientId = result.Account?.Id,
            ClientName = clientName,
            ChannelId = channelId,
            RemoteAddress = remoteAddress,
            ConnectedAt = now,
            DisconnectedAt = result.Success ? null : now,
            Success = result.Success,
            FailureReason = result.Reason,
            DisconnectReason = result.Success ? null : DisconnectReason.LoginFailure.ToWireString(),
        };
        _db.ConnectionRecords.Add(record);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await _events.BroadcastAsync(new ConnectionEvent(record.TenantId, "created", ToView(record))).ConfigureAwait(false);
        return record.Id;
    }

    public async Task RecordDisconnectAsync(long connectionRecordId, DisconnectReason reason,
        CancellationToken cancellationToken)
    {
        if (connectionRecordId <= 0)
        {
            return;
        }
        var record = await _db.ConnectionRecords
            .FirstOrDefaultAsync(r => r.Id == connectionRecordId, cancellationToken)
            .ConfigureAwait(false);
        if (record is null)
        {
            return;
        }
        var dirty = false;
        if (record.DisconnectedAt is null)
        {
            record.DisconnectedAt = DateTimeOffset.UtcNow;
            dirty = true;
        }
        if (record.DisconnectReason is null)
        {
            record.DisconnectReason = reason.ToWireString();
            dirty = true;
        }
        if (dirty)
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            await _events.BroadcastAsync(new ConnectionEvent(record.TenantId, "updated", ToView(record))).ConfigureAwait(false);
        }
    }

    private static ConnectionRecordView ToView(ConnectionRecord record)
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
