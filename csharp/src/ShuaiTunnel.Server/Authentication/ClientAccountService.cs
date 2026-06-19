using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using ShuaiTunnel.Protocol.Packets;
using ShuaiTunnel.Protocol.Security;
using ShuaiTunnel.Server.Data;

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

    public ClientAccountService(TunnelDbContext db)
    {
        _db = db;
    }

    public async Task<AuthenticationResult> AuthenticateAsync(LoginRequestPacket packet, CancellationToken cancellationToken)
    {
        if (packet.ClientName is null)
        {
            return AuthenticationResult.Fail(null, "缺少 clientName");
        }

        var account = await _db.ClientAccounts
            .AsNoTracking()
            .FirstOrDefaultAsync(a => a.ClientName == packet.ClientName, cancellationToken)
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
        if (!HasValidSignature(packet, account.PasswordHash))
        {
            return AuthenticationResult.Fail(account, "签名无效或已过期");
        }

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

    /// <summary>
    /// Verifies the login HMAC. Mirrors the Java recipe verbatim:
    /// <code>
    /// key = decodeHex(account.password_hash)              // 32 bytes
    /// msg = clientName \n timestamp \n nonce              // \n = U+000A
    /// expected = HMAC-SHA256(key, utf8(msg))
    /// </code>
    /// Plus the timestamp window: |ts - now| ≤ 30 000 ms (yes, milliseconds).
    /// </summary>
    private static bool HasValidSignature(LoginRequestPacket packet, string passwordHashHex)
    {
        if (string.IsNullOrEmpty(packet.ClientName)
            || string.IsNullOrEmpty(packet.Timestamp)
            || string.IsNullOrEmpty(packet.Nonce)
            || packet.CheckSign is null)
        {
            return false;
        }
        if (packet.CheckSign.Length != HmacSigner.SignatureLength)
        {
            return false;
        }
        if (!long.TryParse(packet.Timestamp, System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture, out var ts))
        {
            return false;
        }
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (Math.Abs(ts - nowMs) > 30_000L)
        {
            return false;
        }

        byte[] key;
        try
        {
            key = Convert.FromHexString(passwordHashHex);
        }
        catch (FormatException)
        {
            // Stored hash is corrupt — fail closed.
            return false;
        }
        if (key.Length != 32)
        {
            return false;
        }

        var msg = $"{packet.ClientName}\n{packet.Timestamp}\n{packet.Nonce}";
        var expected = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(msg));
        return CryptographicOperations.FixedTimeEquals(expected, packet.CheckSign);
    }
}
