using ShuaiTunnel.Server.Data.Entities;

namespace ShuaiTunnel.Server.Authentication;

/// <summary>
/// JS-safe random ID generator — matches Java's <c>ClientIdGenerator</c>. We pick from
/// <c>[1, 2^53-1]</c> so the SPA can round-trip the value as a JS Number without losing
/// precision.
/// </summary>
public static class ClientIdGenerator
{
    private const long MaxJsSafeInteger = 9_007_199_254_740_991L;

    public static long NewId()
    {
        // Random.Shared is thread-safe per docs and produces non-cryptographic but
        // collision-rare 53-bit values. Using crypto RNG isn't necessary here — the IDs are
        // identifiers, not secrets, and the namespace is large enough that a birthday
        // collision in practice would mean millions of accounts.
        return System.Random.Shared.NextInt64(1L, MaxJsSafeInteger + 1);
    }
}

/// <summary>
/// What <see cref="ClientAccountService.AuthenticateAsync"/> returns. Encodes both the success
/// path (account present) and the rich set of failure modes the audit row needs to record.
/// </summary>
public sealed record AuthenticationResult(bool Success, ClientAccount? Account, string? Reason)
{
    public static AuthenticationResult Pass(ClientAccount account) => new(true, account, null);
    public static AuthenticationResult Fail(ClientAccount? account, string reason) => new(false, account, reason);
}
