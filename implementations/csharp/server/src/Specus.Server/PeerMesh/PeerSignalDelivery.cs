using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.Data.Entities;
using Specus.Server.Persistence;

namespace Specus.Server.PeerMesh;

public sealed partial class PeerMeshService
{
    private async Task<bool> SendPreparedPeerExchangeAsync(PeerReceiver source, PeerReceiver target,
        PeerControlMessage original, bool grant, CancellationToken ct)
    {
        var receiver = grant ? source : target;
        return await receiver.Transport.Writer.WritePreparedAsync(async token =>
        {
            var currentSource = await ReadPeerReceiverAsync(source, token).ConfigureAwait(false);
            var currentTarget = await ReadPeerReceiverAsync(target, token).ConfigureAwait(false);
            if (currentSource is null || currentTarget is null
                || !await CanPeerAsync(currentSource.Account, currentTarget.Account, token).ConfigureAwait(false)) return null;
            var signal = JsonSerializer.Deserialize<PeerControlMessage>(JsonSerializer.Serialize(original))!;
            if (!await PeerSignalSessionIsCurrentAsync(signal, currentSource.Account, currentTarget.Account, token).ConfigureAwait(false)) return null;
            await FillSourceAsync(signal, currentSource.Account, token).ConfigureAwait(false);
            await EnrichTargetAsync(signal, currentTarget.Account, token).ConfigureAwait(false);
            var latestSource = await ReadPeerReceiverAsync(source, token).ConfigureAwait(false);
            var latestTarget = await ReadPeerReceiverAsync(target, token).ConfigureAwait(false);
            if (latestSource is null || latestTarget is null
                || latestSource.Account.OwnerUsername != currentSource.Account.OwnerUsername
                || latestTarget.Account.OwnerUsername != currentTarget.Account.OwnerUsername
                || latestSource.Account.UpdatedAt != currentSource.Account.UpdatedAt
                || latestTarget.Account.UpdatedAt != currentTarget.Account.UpdatedAt
                || !await CanPeerAsync(latestSource.Account, latestTarget.Account, token).ConfigureAwait(false)
                || !await PeerSignalSessionIsCurrentAsync(signal, latestSource.Account, latestTarget.Account, token).ConfigureAwait(false)) return null;
            // All SQL transactions have ended before any socket bytes can be emitted.
            return new MessageResponsePacket { ClientName = grant ? "server" : latestSource.Account.ClientName,
                ToClientName = grant ? latestSource.Account.ClientName : latestTarget.Account.ClientName,
                MessageType = MessageType.PeerControl, Message = JsonSerializer.Serialize(signal) };
        }, ct).ConfigureAwait(false);
    }

    private async Task<bool> PeerSignalSessionIsCurrentAsync(PeerControlMessage signal, ClientAccount source,
        ClientAccount target, CancellationToken ct)
    {
        if (signal.SessionId is null) return true;
        var session = await _db.PeerMeshSessions.AsNoTracking().SingleOrDefaultAsync(s => s.Id == signal.SessionId, ct).ConfigureAwait(false);
        if (session is null || session.TenantId != source.TenantId || target.TenantId != source.TenantId
            || !MatchesSessionPeers(session, source.Id, target.Id)
            || (signal.Type != TypeClose && (session.Status == StatusClosed || session.ExpiresAt <= DateTimeOffset.UtcNow))) return false;
        if (!string.IsNullOrEmpty(signal.Token))
        {
            byte[] expected;
            try { expected = Convert.FromHexString(session.TokenHash ?? ""); }
            catch (FormatException) { return false; }
            var actual = SHA256.HashData(Encoding.UTF8.GetBytes(signal.Token));
            if (expected.Length != actual.Length || !CryptographicOperations.FixedTimeEquals(expected, actual)) return false;
        }
        signal.ExpiresAt = session.ExpiresAt.ToString("O");
        if (signal.Type is TypeSessionGrant or TypeClose) signal.Status = session.Status;
        if (signal.Type == TypeSessionGrant) signal.PathType = session.PathType;
        return true;
    }

    private async Task CloseUndeliveredGrantAsync(long id, string tenant, CancellationToken ct)
    {
        await using var transaction = await ClientOwnershipWrite.BeginAsync(_db, ct).ConfigureAwait(false);
        await ClientOwnershipWrite.LockAsync<PeerMeshSession>(_db, id, tenant, ct).ConfigureAwait(false);
        var current = await _db.PeerMeshSessions.AsNoTracking().SingleOrDefaultAsync(s => s.Id == id, ct).ConfigureAwait(false);
        if (current is not null && current.TenantId == tenant && current.Status != StatusClosed)
        {
            // Refresh the already-tracked issuance row instead of overwriting a concurrent
            // close/deletion or traffic report with the old pre-queue snapshot.
            var tracked = _db.PeerMeshSessions.Local.SingleOrDefault(s => s.Id == id);
            if (tracked is null) { _db.Attach(current); tracked = current; }
            else { _db.Entry(tracked).CurrentValues.SetValues(current); _db.Entry(tracked).OriginalValues.SetValues(current); }
            MarkClosed(tracked, DateTimeOffset.UtcNow);
            await _db.SaveChangesAsync(ct).ConfigureAwait(false);
        }
        await transaction.CommitAsync(ct).ConfigureAwait(false);
    }
}
