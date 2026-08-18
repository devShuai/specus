using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;

namespace Specus.Server.Security;

/// <summary>
/// Bounds login attempts per source IP and per target account using fixed windows. It is
/// independent of the captcha, so deployments running without Turnstile still limit credential
/// stuffing. Both dimensions share one rejection message so responses never reveal whether an
/// account exists.
/// </summary>
public sealed class LoginRateLimiter
{
    /// <summary>Bounds the counter tables so abnormal traffic cannot exhaust memory.</summary>
    private const int MaxTrackedKeys = 100_000;

    public const string RateLimitedMessage = "登录尝试过于频繁,请稍后再试";

    private readonly IOptions<AuthOptions> _options;
    private readonly ILogger<LoginRateLimiter> _logger;
    private readonly object _sync = new();
    private readonly Dictionary<string, Window> _ips = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Window> _accounts = new(StringComparer.Ordinal);

    public LoginRateLimiter(IOptions<AuthOptions> options, ILogger<LoginRateLimiter> logger)
    {
        _options = options;
        _logger = logger;
    }

    /// <summary>
    /// Records one attempt and reports whether it may proceed. When the result is false the caller
    /// must answer 429 with the returned Retry-After seconds.
    /// </summary>
    public bool TryAcquire(string? clientIp, string? username, out long retryAfterSeconds)
    {
        retryAfterSeconds = 0;
        var options = _options.Value;
        if (!options.LoginRateLimitEnabled)
        {
            return true;
        }
        var window = Math.Max(1L, options.LoginRateLimitWindowSeconds);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        lock (_sync)
        {
            Purge(_ips, now, window);
            Purge(_accounts, now, window);
            // Count both dimensions before deciding so an exceeded dimension cannot mask the other.
            var ipWindow = Record(_ips, IpKey(clientIp), now, window);
            var accountWindow = Record(_accounts, AccountKey(username), now, window);

            var ipExceeded = ipWindow.Count > Math.Max(1, options.LoginRateLimitPerIp);
            var accountExceeded = accountWindow.Count > Math.Max(1, options.LoginRateLimitPerAccount);
            if (!ipExceeded && !accountExceeded)
            {
                return true;
            }
            var blocking = ipExceeded ? ipWindow : accountWindow;
            retryAfterSeconds = Math.Max(1L, window - Math.Max(0L, now - blocking.StartUnix));
            _logger.LogWarning(
                "[login-rate-limit] rejected login attempt: ip={Ip}, dimension={Dimension}, retryAfter={RetryAfter}s",
                IpKey(clientIp), ipExceeded ? "ip" : "account", retryAfterSeconds);
            return false;
        }
    }

    /// <summary>
    /// Clears the account budget after a successful login. The source IP budget is kept so cracking
    /// one account does not unlock the whole source.
    /// </summary>
    public void RecordSuccess(string? username)
    {
        if (!_options.Value.LoginRateLimitEnabled)
        {
            return;
        }
        lock (_sync)
        {
            _accounts.Remove(AccountKey(username));
        }
    }

    private static Window Record(Dictionary<string, Window> windows, string key, long now, long window)
    {
        if (!windows.TryGetValue(key, out var existing))
        {
            if (windows.Count >= MaxTrackedKeys)
            {
                // Table is full and this is a new source: treat as exceeded rather than growing.
                return new Window(now) { Count = int.MaxValue };
            }
            var created = new Window(now) { Count = 1 };
            windows[key] = created;
            return created;
        }
        if (now - existing.StartUnix >= window)
        {
            var reset = new Window(now) { Count = 1 };
            windows[key] = reset;
            return reset;
        }
        existing.Count += 1;
        return existing;
    }

    private static void Purge(Dictionary<string, Window> windows, long now, long window)
    {
        foreach (var key in windows.Where(entry => now - entry.Value.StartUnix >= window)
                     .Select(entry => entry.Key).ToList())
        {
            windows.Remove(key);
        }
    }

    private static string IpKey(string? clientIp) =>
        string.IsNullOrWhiteSpace(clientIp) ? "unknown" : clientIp.Trim();

    private static string AccountKey(string? username) =>
        string.IsNullOrWhiteSpace(username) ? "unknown" : username.Trim().ToLowerInvariant();

    private sealed class Window
    {
        public Window(long startUnix) => StartUnix = startUnix;

        public long StartUnix { get; }
        public int Count { get; set; }
    }
}
