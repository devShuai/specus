using Microsoft.EntityFrameworkCore;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Data.Entities;

namespace ShuaiTunnel.Server.Authentication;

/// <summary>
/// Persists the audit row for a control-channel login. Phase 2 only writes the
/// <see cref="RecordConnectionAsync"/> + <see cref="RecordDisconnectAsync"/> half; the
/// startup/shutdown sweepers and WebSocket broadcast hooks land in Phase 4.
/// </summary>
public sealed class ConnectionRecordService
{
    private readonly TunnelDbContext _db;

    public ConnectionRecordService(TunnelDbContext db)
    {
        _db = db;
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
        }
    }
}
