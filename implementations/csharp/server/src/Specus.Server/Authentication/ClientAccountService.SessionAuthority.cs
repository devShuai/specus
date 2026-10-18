using Microsoft.EntityFrameworkCore;
using Specus.Protocol.Packets;
using Specus.Server.Data.Entities;
using Specus.Server.Persistence;

namespace Specus.Server.Authentication;

public sealed partial class ClientAccountService
{
    private async Task<AuthenticationResult> AuthenticateCurrentSessionAsync(ClientAuthSession cached,
        LoginRequestPacket packet, string channelId, string? remoteAddress, bool dataConnection, CancellationToken ct)
    {
        if (_db.ChangeTracker.HasChanges())
            throw new InvalidOperationException("client session authentication requires a clean pending-write scope");
        await using var transaction = await ClientOwnershipWrite.BeginAsync(_db, ct).ConfigureAwait(false);
        // Same order as startup, ownership transfer and ordinary client deletion. The
        // credential lock also serializes online quota admission across server processes.
        await ClientOwnershipWrite.LockAsync<ClientCredential>(_db, cached.CredentialId, cached.TenantId, ct).ConfigureAwait(false);
        await ClientOwnershipWrite.LockAsync<ClientAccount>(_db, cached.ClientId, cached.TenantId, ct).ConfigureAwait(false);
        await ClientOwnershipWrite.LockAsync<ClientIdentity>(_db, cached.IdentityId, cached.TenantId, ct).ConfigureAwait(false);
        await ClientOwnershipWrite.LockAsync<ClientSession>(_db, cached.Id, cached.TenantId, ct).ConfigureAwait(false);
        var credential = await _db.ClientCredentials.AsNoTracking().SingleOrDefaultAsync(c => c.Id == cached.CredentialId, ct).ConfigureAwait(false);
        var account = await _db.ClientAccounts.AsNoTracking().SingleOrDefaultAsync(c => c.Id == cached.ClientId, ct).ConfigureAwait(false);
        var identity = await _db.ClientIdentities.AsNoTracking().SingleOrDefaultAsync(i => i.Id == cached.IdentityId, ct).ConfigureAwait(false);
        var session = await _db.ClientSessions.AsNoTracking().SingleOrDefaultAsync(s => s.Id == cached.Id, ct).ConfigureAwait(false);
        if (credential is null || account is null || identity is null || session is null
            || credential.TenantId != cached.TenantId || account.TenantId != cached.TenantId || identity.TenantId != cached.TenantId || session.TenantId != cached.TenantId
            || identity.CredentialId != credential.Id || identity.ClientId != account.Id
            || session.CredentialId != credential.Id || session.ClientId != account.Id || session.IdentityId != identity.Id
            || session.TokenHash != cached.TokenHash || session.ExpiresAt != cached.ExpiresAt || session.ExpiresAt <= DateTimeOffset.UtcNow
            || identity.MachineFingerprint != cached.MachineFingerprint || identity.OsUser != cached.OsUser
            || session.MachineFingerprint != cached.MachineFingerprint || session.OsUser != cached.OsUser
            || cached.Revoked || session.Status is not (StatusHttpAuthenticated or StatusNettyOnline or StatusDisconnected))
            return AuthenticationResult.Fail(null, "客户端访问令牌或身份已失效", cached.TenantId);
        if (!account.Enabled || !credential.Enabled)
            return AuthenticationResult.Fail(account, "客户端已停用");
        if (dataConnection && (cached.Status != ClientAuthSessionStatus.NettyOnline || session.Status != StatusNettyOnline
                               || session.ChannelId != cached.ChannelId))
            return AuthenticationResult.Fail(account, "数据连接要求控制连接先登录");
        if (!dataConnection && await ExceedsRateLimitAsync(account.Id, account.ConnectionRateLimitPerMinute, ct).ConfigureAwait(false))
            return AuthenticationResult.Fail(account, "连接频率超过限制");
        if (!dataConnection)
        {
            var now = DateTimeOffset.UtcNow;
            var online = await _db.ClientSessions.AsNoTracking().Where(s => s.CredentialId == credential.Id
                && s.TenantId == cached.TenantId && s.Id != cached.Id && s.Status == StatusNettyOnline && s.ExpiresAt > now).ToListAsync(ct).ConfigureAwait(false);
            // Native database collations may not be ordinal; never merge tenants or
            // immutable canonical machine/user bindings based on that collation alone.
            online = online.Where(s => s.TenantId == cached.TenantId && s.Status == StatusNettyOnline && s.ExpiresAt > now).ToList();
            if (online.Count(s => s.MachineFingerprint == cached.MachineFingerprint && s.OsUser == cached.OsUser) >= PerMachineUserMaxInstances)
                return AuthenticationResult.Fail(account, "同一台机器和用户已经有在线实例");
            if (online.Count >= credential.MaxOnlineInstances)
                return AuthenticationResult.Fail(account, "在线实例数已达上限");
            var tracked = _db.ChangeTracker.Entries<ClientSession>().SingleOrDefault(e => e.Entity.Id == session.Id);
            if (tracked is null) _db.Attach(session);
            else
            {
                tracked.CurrentValues.SetValues(session); tracked.OriginalValues.SetValues(session); tracked.State = EntityState.Unchanged;
                session = tracked.Entity;
            }
            session.Status = StatusNettyOnline; session.ChannelId = channelId; session.RemoteAddress = remoteAddress;
            session.NettyConnectedAt = now; session.DisconnectedAt = null;
            await _db.SaveChangesAsync(ct).ConfigureAwait(false);
        }
        await transaction.CommitAsync(ct).ConfigureAwait(false);
        await transaction.DisposeAsync().ConfigureAwait(false);
        if (!dataConnection && !_sessionStore.MarkOnline(cached, channelId, remoteAddress))
            return AuthenticationResult.Fail(null, "客户端已删除，请重新认证", cached.TenantId);
        packet.ClientName = account.ClientName; packet.ClientSessionId = cached.Id;
        return AuthenticationResult.Pass(account);
    }
}
