using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Specus.Protocol.Packets;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Data.Conversion;
using Specus.Server.Persistence;
using Specus.Protocol.PeerEgress;
using Specus.Server.PeerMesh;

namespace Specus.Server.Authentication;

/// <summary>
/// HMAC login verification + per-client connection rate limiting. Mirrors the small slice of
/// <c>ClientAccountService.authenticate</c> we need at this phase: account lookup → enabled
/// check → rate limit → signature verification.
///
/// <para>The Java implementation's CRUD surface (create/update/delete client) lands in
/// Phase 4 alongside the management REST endpoints.</para>
/// </summary>
public sealed partial class ClientAccountService
{
    public const string StatusHttpAuthenticated = "HTTP_AUTHENTICATED";
    public const string StatusNettyOnline = "NETTY_ONLINE";
    public const string StatusDisconnected = "DISCONNECTED";
    private const string DefaultTenantId = "default";

    private readonly SpecusDbContext _db;
    private readonly ClientAuthSessionStore _sessionStore;
    private readonly NettyServerOptions _netty;
    private readonly ClientAuthOptions _clientAuth;
    private readonly SpecusOptions _specus;
    private readonly TlsOptions _tls;
    private readonly PeerMeshService _peerMesh;

    public ClientAccountService(SpecusDbContext db, ClientAuthSessionStore sessionStore,
        IOptions<NettyServerOptions> netty, IOptions<ClientAuthOptions> clientAuth, IOptions<SpecusOptions> specus,
        IOptions<TlsOptions> tls, PeerMeshService peerMesh)
    {
        _db = db;
        _sessionStore = sessionStore;
        _netty = netty.Value;
        _clientAuth = clientAuth.Value;
        _specus = specus.Value;
        _tls = tls.Value;
        _peerMesh = peerMesh;
    }

    public async Task<ClientAuthLoginResponse> LoginAsync(
        ClientAuthLoginRequest request, string? requestServerName, CancellationToken cancellationToken)
    {
        if (_db.ChangeTracker.HasChanges())
            throw new InvalidOperationException("client startup requires a clean pending-write scope");
        var environment = RequireEnvironment(request.Environment);
        var authenticated = await AuthenticateCredentialAsync(request, cancellationToken).ConfigureAwait(false);
        if (!authenticated.Enabled)
        {
            throw new ArgumentException("客户端凭证已停用");
        }

        // Authentication and nonce consumption precede this boundary. Re-read the locked
        // credential: a transfer may already have changed its owner, but not its access key.
        await using var transaction = await ClientOwnershipWrite.BeginAsync(_db, cancellationToken).ConfigureAwait(false);
        var (credential, account, identity) = await ResolveClientStartupOnAsync(authenticated, environment, cancellationToken).ConfigureAwait(false);
        // Native collations may reuse an identity for a case variant. Runtime keys must bind
        // the resolved canonical identity, not the spelling of the authenticated request.
        environment.MachineFingerprint = identity.MachineFingerprint;
        environment.OsUser = identity.OsUser;
        var mappings = await _db.SpecusMappings.AsNoTracking().Where(m => m.ClientId == account.Id && m.Enabled)
            .OrderBy(m => m.Id).Select(m => new SpecusEndpoint { Port = m.ListenPort, SpecusAddress = m.TargetAddress, SpecusPort = m.TargetPort })
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        var routes = await _db.HttpRouteMappings.AsNoTracking().Where(r => r.ClientId == account.Id && r.Enabled)
            .OrderBy(r => r.Id).Select(r => new HttpRouteEndpoint { Route = r.Route, TargetBaseUrl = r.TargetBaseUrl })
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        var peer = await _peerMesh.BuildLoginConfigAsync(account, environment, requestServerName, cancellationToken).ConfigureAwait(false);
        var nettyHost = ResolveNettyHost(requestServerName);
        var nettyTls = _tls.ResolveMode() != TlsMode.Disabled || _tls.TerminatedUpstream;

        await CloseStaleHttpAuthenticatedSessionsAsync(credential, environment, cancellationToken)
            .ConfigureAwait(false);
        var ttlSeconds = _clientAuth.TokenTtlSeconds <= 0 ? 8 * 60 * 60 : _clientAuth.TokenTtlSeconds;
        var session = _sessionStore.Prepare(credential, identity, account, TimeSpan.FromSeconds(ttlSeconds), environment);
        _db.ClientSessions.Add(ToSessionEntity(session, environment));
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        var persisted = await _db.ClientSessions.AsNoTracking().SingleOrDefaultAsync(s => s.Id == session.Id, cancellationToken).ConfigureAwait(false);
        if (persisted is null || persisted.TokenHash != session.TokenHash || persisted.TenantId != session.TenantId
            || persisted.CredentialId != session.CredentialId || persisted.IdentityId != session.IdentityId
            || persisted.ClientId != session.ClientId || persisted.ClientName != session.ClientName
            || persisted.Status != StatusHttpAuthenticated || persisted.ExpiresAt != session.ExpiresAt
            || persisted.MachineFingerprint != session.MachineFingerprint || persisted.OsUser != session.OsUser)
            throw new InvalidOperationException("client startup session persistence postcondition failed");
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        _sessionStore.Publish(session);
        return new ClientAuthLoginResponse
        {
            TenantId = credential.TenantId,
            ClientId = account.Id,
            ClientName = account.ClientName,
            ClientSessionId = session.Id,
            AccessToken = session.AccessToken,
            TokenTtlSeconds = ttlSeconds,
            NettyHost = nettyHost,
            NettyPort = _netty.Port,
            NettyTls = nettyTls,
            MaxOnlineInstances = credential.MaxOnlineInstances,
            SpecusConfigList = mappings,
            HttpSpecusConfigList = routes,
            PeerMesh = peer,
        };
    }

    public async Task<AuthenticationResult> AuthenticateAsync(
        LoginRequestPacket packet, string channelId, string? remoteAddress, CancellationToken cancellationToken)
        => await AuthenticateCoreAsync(packet, channelId, remoteAddress, dataConnection: false, cancellationToken)
            .ConfigureAwait(false);

    internal long? AuthenticatedClientId(LoginRequestPacket packet) =>
        _sessionStore.Find(packet.ClientSessionId, packet.AccessToken)?.ClientId;

    internal long? SessionClientId(long? sessionId) => _sessionStore.FindById(sessionId)?.ClientId;

    internal bool HasNewerControl(long? sessionId, string channelId) =>
        _sessionStore.FindById(sessionId) is { Status: ClientAuthSessionStatus.NettyOnline } current
        && current.ChannelId != channelId;

    public async Task<AuthenticationResult> AuthenticateDataAsync(
        LoginRequestPacket packet, string channelId, string? remoteAddress, CancellationToken cancellationToken)
        => await AuthenticateCoreAsync(packet, channelId, remoteAddress, dataConnection: true, cancellationToken)
            .ConfigureAwait(false);

    private async Task<AuthenticationResult> AuthenticateCoreAsync(
        LoginRequestPacket packet, string channelId, string? remoteAddress,
        bool dataConnection, CancellationToken cancellationToken)
    {
        var session = _sessionStore.Find(packet.ClientSessionId, packet.AccessToken);
        if (session is null)
        {
            var auditTenantId = await ResolveAuditTenantAsync(packet.ClientSessionId, cancellationToken)
                .ConfigureAwait(false);
            return AuthenticationResult.Fail(null, "客户端访问令牌无效", auditTenantId);
        }
        if (session.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            _sessionStore.MarkDisconnected(session.Id);
            await MarkSessionDisconnectedAsync(session.Id, cancellationToken).ConfigureAwait(false);
            return AuthenticationResult.Fail(null, "客户端访问令牌已过期", session.TenantId);
        }

        var account = await _db.ClientAccounts
            .FirstOrDefaultAsync(a => a.Id == session.ClientId && a.TenantId == session.TenantId,
                cancellationToken)
            .ConfigureAwait(false);
        var credential = await _db.ClientCredentials
            .FirstOrDefaultAsync(c => c.Id == session.CredentialId && c.TenantId == session.TenantId,
                cancellationToken)
            .ConfigureAwait(false);

        if (account is null || credential is null)
        {
            return AuthenticationResult.Fail(null, "客户端不存在", session.TenantId);
        }
        if (!account.Enabled || !credential.Enabled)
        {
            return AuthenticationResult.Fail(account, "客户端已停用");
        }
        if (dataConnection && session.Status != ClientAuthSessionStatus.NettyOnline)
        {
            return AuthenticationResult.Fail(account, "数据连接要求控制连接先登录");
        }
        if (!dataConnection && await ExceedsRateLimitAsync(
                account.Id, account.ConnectionRateLimitPerMinute, cancellationToken).ConfigureAwait(false))
        {
            return AuthenticationResult.Fail(account, "连接频率超过限制");
        }
        if (!dataConnection && _sessionStore.CountOnlineByMachineUser(
                session.CredentialId, session.MachineFingerprint, session.OsUser, session.Id) >= PerMachineUserMaxInstances)
        {
            return AuthenticationResult.Fail(account, "同一台机器和用户已经有在线实例");
        }
        if (!dataConnection
            && _sessionStore.CountOnlineByCredential(session.CredentialId, session.Id) >= credential.MaxOnlineInstances)
        {
            return AuthenticationResult.Fail(account, "在线实例数已达上限");
        }

        packet.ClientName = account.ClientName;
        packet.ClientSessionId = session.Id;
        if (!dataConnection)
        {
            await MarkSessionOnlineAsync(session, channelId, remoteAddress, cancellationToken)
                .ConfigureAwait(false);
            _sessionStore.MarkOnline(session, channelId, remoteAddress);
        }
        return AuthenticationResult.Pass(account);
    }

    private async Task<string> ResolveAuditTenantAsync(long? sessionId,
        CancellationToken cancellationToken)
    {
        if (sessionId is null or <= 0)
        {
            return DefaultTenantId;
        }
        var inMemory = _sessionStore.FindById(sessionId);
        if (inMemory is not null)
        {
            return NormalizeTenant(inMemory.TenantId);
        }
        var persistedTenant = await _db.ClientSessions.AsNoTracking()
            .Where(row => row.Id == sessionId.Value)
            .Select(row => row.TenantId)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);
        return NormalizeTenant(persistedTenant);
    }

    private static string NormalizeTenant(string? tenantId) =>
        string.IsNullOrWhiteSpace(tenantId) ? DefaultTenantId : tenantId.Trim();

    private int PerMachineUserMaxInstances => _clientAuth.PerMachineUserMaxInstances <= 0
        ? 1
        : _clientAuth.PerMachineUserMaxInstances;

    private async Task<bool> ExceedsRateLimitAsync(long clientId, int limit, CancellationToken ct)
    {
        if (limit <= 0)
        {
            return false;
        }
        var since = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(1);
        var count = await _db.ConnectionRecords
            .Where(r => r.ClientId == clientId && r.ConnectedAt >= since)
            .CountAsync(ct)
            .ConfigureAwait(false);
        return count >= limit;
    }

    public async Task<bool> MarkNettyDisconnectedAsync(long? sessionId, string channelId,
        CancellationToken cancellationToken)
    {
        if (sessionId is null or <= 0)
        {
            return false;
        }
        var now = DateTimeOffset.UtcNow;
        // One native conditional write, not a query followed by an unconditional tracked Save.
        // EF maps/quotes the provider's actual column names (including PostgreSQL's Id).
        var changed = await _db.ClientSessions
            .Where(s => s.Id == sessionId.Value && s.ChannelId == channelId && s.Status == StatusNettyOnline)
            .ExecuteUpdateAsync(setters => setters.SetProperty(s => s.Status, StatusDisconnected)
                .SetProperty(s => s.DisconnectedAt, now), cancellationToken).ConfigureAwait(false);
        _sessionStore.MarkDisconnected(sessionId, channelId);
        return changed != 0;
    }

    private async Task<ClientCredential> AuthenticateCredentialAsync(
        ClientAuthLoginRequest request, CancellationToken cancellationToken)
    {
        var apiKey = RequireText(request.ApiKey, "apiKey");
        var credential = await _db.ClientCredentials
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.ApiKey == apiKey, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new ArgumentException("客户端凭证不存在");
        if (!HasValidApiKeySignature(request, credential.SecretHash))
        {
            throw new ArgumentException("客户端签名无效或已过期");
        }
        await ConsumeNonceAsync(apiKey, request.Nonce!, cancellationToken).ConfigureAwait(false);
        return credential;
    }

    private async Task ConsumeNonceAsync(string apiKey, string nonce,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        // Portable single-table DELETE: Oracle EF's alias form is rejected by MariaDB 11.4.
        await _db.Database.ExecuteSqlInterpolatedAsync($"DELETE FROM specus_client_auth_nonce WHERE expires_at <= {IsoDateTimeOffsetConverter.Format(now)}",
            cancellationToken).ConfigureAwait(false);
        var row = new ClientAuthNonce
        {
            ApiKeyHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(apiKey)))
                .ToLowerInvariant(),
            NonceHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(nonce)))
                .ToLowerInvariant(),
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(2),
        };
        _db.ClientAuthNonces.Add(row);
        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateException)
        {
            _db.Entry(row).State = EntityState.Detached;
            var duplicate = await _db.ClientAuthNonces.AsNoTracking()
                .AnyAsync(item => item.ApiKeyHash == row.ApiKeyHash
                    && item.NonceHash == row.NonceHash, cancellationToken)
                .ConfigureAwait(false);
            if (duplicate)
            {
                throw new ArgumentException("客户端 nonce 已使用");
            }
            throw;
        }
    }

    private static bool HasValidApiKeySignature(ClientAuthLoginRequest request, string secretHashHex)
    {
        if (request.Environment is null
            || string.IsNullOrWhiteSpace(request.Timestamp)
            || string.IsNullOrWhiteSpace(request.Nonce)
            || string.IsNullOrWhiteSpace(request.Signature))
        {
            return false;
        }
        if (!long.TryParse(request.Timestamp, System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture, out var ts))
        {
            return false;
        }
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (Math.Abs(ts - nowMs) > 60_000L)
        {
            return false;
        }

        byte[] key;
        try
        {
            key = Convert.FromHexString(secretHashHex);
        }
        catch (FormatException)
        {
            return false;
        }
        if (key.Length != 32)
        {
            return false;
        }

        var message = string.Join('\n',
            request.ApiKey ?? "",
            request.Timestamp ?? "",
            request.Nonce ?? "",
            request.Environment.MachineFingerprint ?? "",
            request.Environment.OsUser ?? "");
        var expected = Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(message)))
            .ToLowerInvariant();
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expected),
            Encoding.ASCII.GetBytes(request.Signature));
    }

    private async Task<string> GenerateClientNameAsync(ClientCredential credential,
        ClientEnvironmentInfo environment, CancellationToken cancellationToken)
    {
        var host = Slug(environment.Hostname, "client");
        var user = Slug(environment.OsUser, "user");
        var suffixInput = $"{credential.Id}\n{environment.MachineFingerprint}\n{environment.OsUser}";
        var suffix = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(suffixInput)))
            .ToLowerInvariant()[..8];
        var baseName = Limit($"{host}-{user}-{suffix}", 120)!;
        var candidate = baseName;
        var i = 2;
        while (await _db.ClientAccounts.AsNoTracking()
                   .AnyAsync(a => a.ClientName == candidate, cancellationToken)
                   .ConfigureAwait(false))
        {
            var extra = "-" + i++;
            candidate = Limit(baseName, 120 - extra.Length) + extra;
        }
        return candidate;
    }

    private async Task CloseStaleHttpAuthenticatedSessionsAsync(ClientCredential credential,
        ClientEnvironmentInfo environment, CancellationToken cancellationToken)
    {
        // Conditional native update: a CONTROL that already became online must not be
        // overwritten by an earlier HTTP-only session snapshot.
        var now = IsoDateTimeOffsetConverter.Format(DateTimeOffset.UtcNow);
        await _db.Database.ExecuteSqlInterpolatedAsync($"""
            UPDATE specus_client_session SET status={StatusDisconnected}, disconnected_at={now}
            WHERE tenant_id={credential.TenantId} AND credential_id={credential.Id}
              AND machine_fingerprint={environment.MachineFingerprint} AND os_user={environment.OsUser}
              AND status={StatusHttpAuthenticated}
            """, cancellationToken).ConfigureAwait(false);
    }

    private static ClientSession ToSessionEntity(ClientAuthSession session, ClientEnvironmentInfo environment)
    {
        var localAddresses = environment.LocalAddresses ?? new List<string>();
        return new ClientSession
        {
            Id = session.Id,
            TenantId = session.TenantId,
            CredentialId = session.CredentialId,
            IdentityId = session.IdentityId,
            ClientId = session.ClientId,
            ClientName = session.ClientName,
            TokenHash = session.TokenHash,
            Status = StatusHttpAuthenticated,
            MachineFingerprint = session.MachineFingerprint,
            OsUser = session.OsUser,
            Hostname = Limit(environment.Hostname, 160),
            OsName = Limit(environment.OsName, 120),
            OsVersion = Limit(environment.OsVersion, 80),
            OsArch = Limit(environment.OsArch, 60),
            ClientVersion = Limit(environment.ClientVersion, 80),
            JavaVersion = Limit(environment.JavaVersion, 80),
            LocalAddresses = Limit(string.Join(",", localAddresses.Where(a => a is not null)), 2000),
            MessageSendCapable = environment.ClientMessageCapabilities.SendMessages,
            MessageReceiveCapable = environment.ClientMessageCapabilities.ReceiveMessages,
            MessageAttachmentsCapable = environment.ClientMessageCapabilities.Attachments,
            MessageMediaPreviewCapable = environment.ClientMessageCapabilities.MediaPreview,
            MessageMaxAttachmentBytes = Math.Max(0L, environment.ClientMessageCapabilities.MaxAttachmentBytes),
            PeerServiceDiscoveryVersion = PeerMeshService.NormalizeDiscoveryVersion(
                environment.ClientPeerServiceCapabilities.Version),
            PeerServiceApplications = PeerMeshService.EncodeApplications(
                environment.ClientPeerServiceCapabilities.Applications),
            ClientEgressVersion = PeerEgressProtocol.NormalizeVersion(
                environment.ClientEgressCapabilities.Version),
            // A client that cannot take part in egress at all is never advertised as resolving
            // names, whatever else it sent alongside version 0.
            ClientEgressDomainTargets = PeerEgressProtocol.NormalizeVersion(
                    environment.ClientEgressCapabilities.Version) >= 1
                && environment.ClientEgressCapabilities.DomainTargetCapable,
            HttpLoginAt = DateTimeOffset.UtcNow,
            ExpiresAt = session.ExpiresAt,
        };
    }

    private async Task MarkSessionOnlineAsync(ClientAuthSession session, string channelId, string? remoteAddress,
        CancellationToken cancellationToken)
    {
        var row = await _db.ClientSessions.FirstOrDefaultAsync(s => s.Id == session.Id, cancellationToken)
            .ConfigureAwait(false);
        if (row is null)
        {
            return;
        }
        row.Status = StatusNettyOnline;
        row.NettyConnectedAt = DateTimeOffset.UtcNow;
        row.DisconnectedAt = null;
        row.ChannelId = channelId;
        row.RemoteAddress = remoteAddress;
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task MarkSessionDisconnectedAsync(long sessionId, CancellationToken cancellationToken)
    {
        var row = await _db.ClientSessions.FirstOrDefaultAsync(s => s.Id == sessionId, cancellationToken)
            .ConfigureAwait(false);
        if (row is null)
        {
            return;
        }
        row.Status = StatusDisconnected;
        row.DisconnectedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    private static ClientEnvironmentInfo RequireEnvironment(ClientEnvironmentInfo? environment)
    {
        if (environment is null)
        {
            throw new ArgumentException("environment 不能为空");
        }
        if (string.IsNullOrWhiteSpace(environment.MachineFingerprint))
        {
            throw new ArgumentException("machineFingerprint 不能为空");
        }
        if (string.IsNullOrWhiteSpace(environment.OsUser))
        {
            throw new ArgumentException("osUser 不能为空");
        }
        environment.MachineFingerprint = Limit(environment.MachineFingerprint.Trim(), 160);
        environment.OsUser = Limit(environment.OsUser.Trim(), 120);
        environment.Hostname = Limit(
            string.IsNullOrWhiteSpace(environment.Hostname) ? "unknown-host" : environment.Hostname.Trim(), 160);
        environment.ClientMessageCapabilities ??= new ClientMessageCapabilities();
        return environment;
    }

    private string ResolveNettyHost(string? requestServerName)
    {
        if (!string.IsNullOrWhiteSpace(_specus.PublicAddress))
        {
            return _specus.PublicAddress.Trim();
        }
        return string.IsNullOrWhiteSpace(requestServerName) ? "127.0.0.1" : requestServerName.Trim();
    }

    private static string RequireText(string? value, string field)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{field} cannot be blank");
        }
        return value.Trim();
    }

    private static string Slug(string? value, string fallback)
    {
        var normalized = string.IsNullOrWhiteSpace(value)
            ? fallback
            : value.Trim().ToLowerInvariant();
        normalized = Regex.Replace(normalized, "[^a-z0-9._-]+", "-");
        normalized = Regex.Replace(normalized, "^-+|-+$", "");
        return string.IsNullOrWhiteSpace(normalized) ? fallback : Limit(normalized, 50)!;
    }

    private static string? Limit(string? value, int maxLength)
    {
        if (value is null || value.Length <= maxLength)
        {
            return value;
        }
        return value[..maxLength];
    }
}
