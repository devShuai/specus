using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.ControlChannel;
using Specus.Server.Data.Entities;
using Specus.Server.Persistence;

namespace Specus.Server.PeerMesh;

public sealed partial class PeerMeshService
{
    private sealed record PeerReceiver(SpecusConnectionContext Transport, ClientAuthSession Binding,
        string Tenant, long ClientId, long SessionId, string Name, string Channel);
    private sealed record CurrentPeerReceiver(ClientAccount Account, ClientSession Session);

    // Capture the original physical receiver before an asynchronous queue wait. A delayed
    // callback must not look up a newer connection by a mutable/reused display name.
    private PeerReceiver? CapturePeerReceiver(ClientAccount account)
    {
        var transport = _sessions.Find(account.ClientName);
        if (transport?.ClientSessionId is not > 0 || transport.ClientId != account.Id || transport.TenantId != account.TenantId) return null;
        var binding = _clientAuthSessions?.FindById(transport.ClientSessionId);
        if (binding is null || binding.ClientId != account.Id || binding.TenantId != account.TenantId) return null;
        return new PeerReceiver(transport, binding, account.TenantId, account.Id, binding.Id, account.ClientName, transport.ChannelId);
    }

    private bool PeerReceiverIsCurrent(PeerReceiver receiver) => !receiver.Binding.Revoked
        && receiver.Binding.Status == ClientAuthSessionStatus.NettyOnline && receiver.Binding.ChannelId == receiver.Channel
        && receiver.Binding.ExpiresAt > DateTimeOffset.UtcNow
        && ReferenceEquals(_sessions.Find(receiver.Name), receiver.Transport)
        && !receiver.Transport.Lifetime.IsCancellationRequested && receiver.Transport.ReadDisconnectReason() is null
        && receiver.Transport.ConnectionRole == ConnectionRole.Control
        && receiver.Transport.ClientId == receiver.ClientId && receiver.Transport.ClientSessionId == receiver.SessionId
        && receiver.Transport.ClientName == receiver.Name && receiver.Transport.TenantId == receiver.Tenant;

    private async Task<CurrentPeerReceiver?> ReadPeerReceiverAsync(PeerReceiver receiver, CancellationToken ct)
    {
        if (!PeerReceiverIsCurrent(receiver)) return null;
        if (_db.ChangeTracker.HasChanges()) throw new InvalidOperationException("peer control delivery requires a clean pending-write scope");
        await using var transaction = await ClientOwnershipWrite.BeginAsync(_db, ct).ConfigureAwait(false);
        var current = await LockAndReadPeerReceiverAsync(receiver, ct).ConfigureAwait(false);
        if (current is null) return null;
        await transaction.CommitAsync(ct).ConfigureAwait(false);
        await transaction.DisposeAsync().ConfigureAwait(false);
        return current;
    }

    private async Task<CurrentPeerReceiver?> LockAndReadPeerReceiverAsync(PeerReceiver receiver, CancellationToken ct,
        IEnumerable<long>? peerClientIds = null)
    {
        if (_db.Database.CurrentTransaction is null) throw new InvalidOperationException("peer authority requires a caller-owned SQL transaction");
        if (!PeerReceiverIsCurrent(receiver)) return null;
        var binding = receiver.Binding;
        await ClientOwnershipWrite.LockAsync<ClientCredential>(_db, binding.CredentialId, receiver.Tenant, ct).ConfigureAwait(false);
        foreach (var id in (peerClientIds ?? []).Append(receiver.ClientId).Distinct().Order())
            await ClientOwnershipWrite.LockAsync<ClientAccount>(_db, id, receiver.Tenant, ct).ConfigureAwait(false);
        await ClientOwnershipWrite.LockAsync<ClientIdentity>(_db, binding.IdentityId, receiver.Tenant, ct).ConfigureAwait(false);
        await ClientOwnershipWrite.LockAsync<ClientSession>(_db, receiver.SessionId, receiver.Tenant, ct).ConfigureAwait(false);
        var credential = await _db.ClientCredentials.AsNoTracking().SingleOrDefaultAsync(c => c.Id == binding.CredentialId, ct).ConfigureAwait(false);
        var account = await _db.ClientAccounts.AsNoTracking().SingleOrDefaultAsync(c => c.Id == receiver.ClientId, ct).ConfigureAwait(false);
        var identity = await _db.ClientIdentities.AsNoTracking().SingleOrDefaultAsync(i => i.Id == binding.IdentityId, ct).ConfigureAwait(false);
        var session = await _db.ClientSessions.AsNoTracking().SingleOrDefaultAsync(s => s.Id == receiver.SessionId, ct).ConfigureAwait(false);
        if (credential is not { Enabled: true } || account is not { Enabled: true } || identity is null || session is null
            || credential.TenantId != receiver.Tenant || account.TenantId != receiver.Tenant || identity.TenantId != receiver.Tenant || session.TenantId != receiver.Tenant
            || account.ClientName != receiver.Name || identity.ClientId != receiver.ClientId || identity.CredentialId != binding.CredentialId
            || identity.MachineFingerprint != binding.MachineFingerprint || identity.OsUser != binding.OsUser
            || session.ClientId != receiver.ClientId || session.IdentityId != binding.IdentityId || session.CredentialId != binding.CredentialId
            || session.TokenHash != binding.TokenHash || session.ExpiresAt != binding.ExpiresAt || session.ExpiresAt <= DateTimeOffset.UtcNow
            || session.MachineFingerprint != binding.MachineFingerprint || session.OsUser != binding.OsUser
            || session.Status != ClientAccountService.StatusNettyOnline || session.ChannelId != receiver.Channel || !PeerReceiverIsCurrent(receiver)) return null;
        return new CurrentPeerReceiver(account, session);
    }

    private async Task<PeerMeshConfig> BuildRuntimeConfigForReceiverAsync(ClientAccount account, int version, CancellationToken ct)
    {
        var device = Enabled ? await _db.PeerMeshDevices.AsNoTracking().SingleOrDefaultAsync(d => d.ClientId == account.Id && d.TenantId == account.TenantId, ct).ConfigureAwait(false) : null;
        if (device is not null && device.TenantId != account.TenantId) device = null;
        // Device creation belongs to coordinated HTTP startup, not a late runtime push.
        return await BuildConfigAsync(account, device, null, version, ct).ConfigureAwait(false);
    }

    private async Task SendPreparedPeerPushAsync(PeerReceiver receiver,
        Func<CurrentPeerReceiver, CancellationToken, Task<PeerControlMessage?>> build, CancellationToken ct)
    {
        await receiver.Transport.Writer.WritePreparedAsync(async token =>
        {
            var current = await ReadPeerReceiverAsync(receiver, token).ConfigureAwait(false);
            if (current is null) return null;
            var signal = await build(current, token).ConfigureAwait(false);
            if (signal is null) return null;
            var latest = await ReadPeerReceiverAsync(receiver, token).ConfigureAwait(false);
            if (latest is null || latest.Account.OwnerUsername != current.Account.OwnerUsername
                || latest.Account.UpdatedAt != current.Account.UpdatedAt
                || latest.Session.ClientEgressVersion != current.Session.ClientEgressVersion
                || latest.Session.PeerServiceDiscoveryVersion != current.Session.PeerServiceDiscoveryVersion) return null;
            return new MessageResponsePacket { ClientName = "server", ToClientName = latest.Account.ClientName,
                MessageType = MessageType.PeerControl, Message = JsonSerializer.Serialize(signal) };
        }, ct).ConfigureAwait(false);
    }
}
