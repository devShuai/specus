using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Protocol.Packets;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Data.Entities;

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
    private readonly TunnelDbContext _db;
    private readonly ClientAuthSessionStore _sessionStore;
    private readonly NettyServerOptions _netty;
    private readonly AuthOptions _auth;
    private readonly TunnelOptions _tunnel;

    public ClientAccountService(TunnelDbContext db, ClientAuthSessionStore sessionStore,
        IOptions<NettyServerOptions> netty, IOptions<AuthOptions> auth, IOptions<TunnelOptions> tunnel)
    {
        _db = db;
        _sessionStore = sessionStore;
        _netty = netty.Value;
        _auth = auth.Value;
        _tunnel = tunnel.Value;
    }

    public async Task<ClientAuthLoginResponse> LoginAsync(
        ClientAuthLoginRequest request, string? requestServerName, CancellationToken cancellationToken)
    {
        var environment = RequireEnvironment(request.Environment);
        var account = await AuthenticateStartupCredentialAsync(request, cancellationToken).ConfigureAwait(false);
        if (!account.Enabled)
        {
            throw new ArgumentException("客户端已停用");
        }

        var ttlSeconds = Math.Max(60, _auth.TokenTtlSeconds);
        var session = _sessionStore.Create(account, TimeSpan.FromSeconds(ttlSeconds), environment);
        return new ClientAuthLoginResponse
        {
            TenantId = "default",
            ClientId = account.Id,
            ClientName = account.ClientName,
            ClientSessionId = session.Id,
            AccessToken = session.AccessToken,
            TokenTtlSeconds = ttlSeconds,
            NettyHost = ResolveNettyHost(requestServerName),
            NettyPort = _netty.Port,
            MaxOnlineInstances = 2,
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
            return AuthenticationResult.Fail(null, "客户端访问令牌已过期");
        }

        var account = await _db.ClientAccounts
            .FirstOrDefaultAsync(a => a.Id == session.ClientId, cancellationToken)
            .ConfigureAwait(false);

        if (account is null)
        {
            return AuthenticationResult.Fail(null, "客户端不存在");
        }
        if (!account.Enabled)
        {
            return AuthenticationResult.Fail(account, "客户端已停用");
        }
        if (await ExceedsRateLimitAsync(account.Id, account.ConnectionRateLimitPerMinute, cancellationToken).ConfigureAwait(false))
        {
            return AuthenticationResult.Fail(account, "连接频率超过限制");
        }

        packet.ClientName = account.ClientName;
        _sessionStore.MarkOnline(session, channelId, remoteAddress);
        return AuthenticationResult.Pass(account);
    }

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

    public void MarkNettyDisconnected(long? sessionId) => _sessionStore.MarkDisconnected(sessionId);

    private async Task<ClientAccount> AuthenticateStartupCredentialAsync(
        ClientAuthLoginRequest request, CancellationToken cancellationToken)
    {
        var authType = string.IsNullOrWhiteSpace(request.AuthType) ? "apiKey" : request.AuthType.Trim();
        if (authType.Equals("password", StringComparison.OrdinalIgnoreCase))
        {
            var username = RequireText(request.Username, "username");
            var password = RequireText(request.Password, "password");
            var account = await _db.ClientAccounts
                .AsNoTracking()
                .FirstOrDefaultAsync(a => a.ClientName == username, cancellationToken)
                .ConfigureAwait(false)
                ?? throw new ArgumentException("客户端凭证不存在");
            if (!PasswordHasher.Matches(password, account.PasswordHash))
            {
                throw new ArgumentException("客户端凭证无效");
            }
            return account;
        }

        var apiKey = RequireText(request.ApiKey, "apiKey");
        var apiSecret = RequireText(request.Secret, "secret");
        var apiAccount = await _db.ClientAccounts
            .AsNoTracking()
            .FirstOrDefaultAsync(a => a.ClientName == apiKey, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new ArgumentException("客户端凭证不存在");
        if (!PasswordHasher.Matches(apiSecret, apiAccount.PasswordHash)
            && !HasValidApiKeySignature(request, apiAccount.PasswordHash))
        {
            throw new ArgumentException("客户端凭证无效");
        }
        return apiAccount;
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
            Encoding.ASCII.GetBytes(request.Signature.ToLowerInvariant()));
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
}
