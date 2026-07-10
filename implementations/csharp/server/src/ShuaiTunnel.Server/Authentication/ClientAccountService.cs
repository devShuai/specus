using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Protocol.Packets;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Data.Entities;
using ShuaiTunnel.Server.PeerMesh;

namespace ShuaiTunnel.Server.Authentication;

/// <summary>
/// HMAC login verification + per-client connection rate limiting. Mirrors the small slice of
/// <c>ClientAccountService.authenticate</c> we need at this phase: account lookup → enabled
/// check → rate limit → signature verification.
///
/// <para>The Java implementation's CRUD surface (create/update/delete client) lands in
/// Phase 4 alongside the management REST endpoints.</para>
/// </summary>
public sealed class ClientAccountService
{
    public const string StatusHttpAuthenticated = "HTTP_AUTHENTICATED";
    public const string StatusNettyOnline = "NETTY_ONLINE";
    public const string StatusDisconnected = "DISCONNECTED";
    private const string DefaultTenantId = "default";

    private readonly TunnelDbContext _db;
    private readonly ClientAuthSessionStore _sessionStore;
    private readonly NettyServerOptions _netty;
    private readonly ClientAuthOptions _clientAuth;
    private readonly TunnelOptions _tunnel;
    private readonly PeerMeshService _peerMesh;

    public ClientAccountService(TunnelDbContext db, ClientAuthSessionStore sessionStore,
        IOptions<NettyServerOptions> netty, IOptions<ClientAuthOptions> clientAuth, IOptions<TunnelOptions> tunnel,
        PeerMeshService peerMesh)
    {
        _db = db;
        _sessionStore = sessionStore;
        _netty = netty.Value;
        _clientAuth = clientAuth.Value;
        _tunnel = tunnel.Value;
        _peerMesh = peerMesh;
    }

    public async Task<ClientAuthLoginResponse> LoginAsync(
        ClientAuthLoginRequest request, string? requestServerName, CancellationToken cancellationToken)
    {
        var environment = RequireEnvironment(request.Environment);
        var credential = await AuthenticateCredentialAsync(request, cancellationToken).ConfigureAwait(false);
        if (!credential.Enabled)
        {
            throw new ArgumentException("客户端凭证已停用");
        }

        var identity = await FindOrCreateIdentityAsync(credential, environment, cancellationToken)
            .ConfigureAwait(false);
        var account = await _db.ClientAccounts
            .FirstOrDefaultAsync(a => a.Id == identity.ClientId && a.TenantId == credential.TenantId,
                cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException($"client account missing: {identity.ClientId}");
        if (!account.Enabled)
        {
            throw new ArgumentException("客户端已停用");
        }

        await CloseStaleHttpAuthenticatedSessionsAsync(credential, environment, cancellationToken)
            .ConfigureAwait(false);
        var ttlSeconds = _clientAuth.TokenTtlSeconds <= 0 ? 8 * 60 * 60 : _clientAuth.TokenTtlSeconds;
        var session = _sessionStore.Create(credential, identity, account, TimeSpan.FromSeconds(ttlSeconds), environment);
        _db.ClientSessions.Add(ToSessionEntity(session, environment));
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return new ClientAuthLoginResponse
        {
            TenantId = credential.TenantId,
            ClientId = account.Id,
            ClientName = account.ClientName,
            ClientSessionId = session.Id,
            AccessToken = session.AccessToken,
            TokenTtlSeconds = ttlSeconds,
            NettyHost = ResolveNettyHost(requestServerName),
            NettyPort = _netty.Port,
            MaxOnlineInstances = credential.MaxOnlineInstances,
            TunnelConfigList = await _db.TunnelMappings
                .AsNoTracking()
                .Where(m => m.ClientId == account.Id && m.Enabled)
                .OrderBy(m => m.Id)
                .Select(m => new TunnelEndpoint
                {
                    Port = m.ListenPort,
                    TunnelAddress = m.TargetAddress,
                    TunnelPort = m.TargetPort,
                })
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false),
            HttpTunnelConfigList = await _db.HttpRouteMappings
                .AsNoTracking()
                .Where(r => r.ClientId == account.Id && r.Enabled)
                .OrderBy(r => r.Id)
                .Select(r => new HttpRouteEndpoint
                {
                    Route = r.Route,
                    TargetBaseUrl = r.TargetBaseUrl,
                })
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false),
            PeerMesh = await _peerMesh.BuildLoginConfigAsync(account, environment, requestServerName,
                    cancellationToken)
                .ConfigureAwait(false),
        };
    }

    public async Task<AuthenticationResult> AuthenticateAsync(
        LoginRequestPacket packet, string channelId, string? remoteAddress, CancellationToken cancellationToken)
    {
        var session = _sessionStore.Find(packet.ClientSessionId, packet.AccessToken);
        if (session is null)
        {
            return AuthenticationResult.Fail(null, "客户端访问令牌无效");
        }
        if (session.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            _sessionStore.MarkDisconnected(session.Id);
            await MarkSessionDisconnectedAsync(session.Id, cancellationToken).ConfigureAwait(false);
            return AuthenticationResult.Fail(null, "客户端访问令牌已过期");
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
            return AuthenticationResult.Fail(null, "客户端不存在");
        }
        if (!account.Enabled || !credential.Enabled)
        {
            return AuthenticationResult.Fail(account, "客户端已停用");
        }
        if (await ExceedsRateLimitAsync(account.Id, account.ConnectionRateLimitPerMinute, cancellationToken).ConfigureAwait(false))
        {
            return AuthenticationResult.Fail(account, "连接频率超过限制");
        }
        if (_sessionStore.CountOnlineByMachineUser(
                session.CredentialId, session.MachineFingerprint, session.OsUser) >= PerMachineUserMaxInstances)
        {
            return AuthenticationResult.Fail(account, "同一台机器和用户已经有在线实例");
        }
        if (_sessionStore.CountOnlineByCredential(session.CredentialId) >= credential.MaxOnlineInstances)
        {
            return AuthenticationResult.Fail(account, "在线实例数已达上限");
        }

        packet.ClientName = account.ClientName;
        packet.ClientSessionId = session.Id;
        _sessionStore.MarkOnline(session, channelId, remoteAddress);
        await MarkSessionOnlineAsync(session, channelId, remoteAddress, cancellationToken)
            .ConfigureAwait(false);
        return AuthenticationResult.Pass(account);
    }

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

    public void MarkNettyDisconnected(long? sessionId)
    {
        _sessionStore.MarkDisconnected(sessionId);
        if (sessionId is null or <= 0)
        {
            return;
        }

        var row = _db.ClientSessions.FirstOrDefault(s => s.Id == sessionId.Value);
        if (row is null || row.Status != StatusNettyOnline)
        {
            return;
        }
        row.Status = StatusDisconnected;
        row.DisconnectedAt = DateTimeOffset.UtcNow;
        _db.SaveChanges();
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
        return credential;
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

    private async Task<ClientIdentity> FindOrCreateIdentityAsync(
        ClientCredential credential, ClientEnvironmentInfo environment, CancellationToken cancellationToken)
    {
        var identity = await _db.ClientIdentities
            .FirstOrDefaultAsync(i => i.CredentialId == credential.Id
                && i.MachineFingerprint == environment.MachineFingerprint
                && i.OsUser == environment.OsUser, cancellationToken)
            .ConfigureAwait(false);
        if (identity is not null)
        {
            identity.Hostname = Limit(environment.Hostname, 160);
            identity.LastSeenAt = DateTimeOffset.UtcNow;
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return identity;
        }

        var now = DateTimeOffset.UtcNow;
        var account = new ClientAccount
        {
            Id = ClientIdGenerator.NewId(),
            TenantId = credential.TenantId,
            OwnerUsername = credential.OwnerUsername,
            ClientName = await GenerateClientNameAsync(credential, environment, cancellationToken)
                .ConfigureAwait(false),
            PasswordHash = PasswordHasher.Hash(Guid.NewGuid().ToString("N")),
            Enabled = true,
            ConnectionRateLimitPerMinute = 30,
            CreatedAt = now,
            UpdatedAt = now,
        };
        _db.ClientAccounts.Add(account);

        identity = new ClientIdentity
        {
            Id = ClientIdGenerator.NewId(),
            TenantId = credential.TenantId,
            CredentialId = credential.Id,
            ClientId = account.Id,
            ClientName = account.ClientName,
            MachineFingerprint = environment.MachineFingerprint!,
            OsUser = environment.OsUser!,
            Hostname = Limit(environment.Hostname, 160),
            FirstSeenAt = now,
            LastSeenAt = now,
        };
        _db.ClientIdentities.Add(identity);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return identity;
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
        var rows = await _db.ClientSessions
            .Where(s => s.CredentialId == credential.Id
                && s.MachineFingerprint == environment.MachineFingerprint
                && s.OsUser == environment.OsUser
                && s.Status == StatusHttpAuthenticated)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        if (rows.Count == 0)
        {
            return;
        }
        var now = DateTimeOffset.UtcNow;
        foreach (var row in rows)
        {
            row.Status = StatusDisconnected;
            row.DisconnectedAt = now;
        }
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
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
        if (!string.IsNullOrWhiteSpace(_tunnel.PublicAddress))
        {
            return _tunnel.PublicAddress.Trim();
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
