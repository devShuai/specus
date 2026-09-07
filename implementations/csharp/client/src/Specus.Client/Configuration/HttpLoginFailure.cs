using System.Net;

namespace Specus.Client.Configuration;

public sealed class HttpLoginFailure(string message, bool retryable, int exitCode = 1, TimeSpan? retryAfter = null)
    : InvalidOperationException(message)
{
    public bool Retryable { get; } = retryable;
    public int ExitCode { get; } = exitCode;
    public TimeSpan RetryAfter { get; } = retryAfter ?? TimeSpan.Zero;
    public static HttpLoginFailure FromResponse(HttpResponseMessage response)
    {
        int status = (int)response.StatusCode;
        bool retry = status is 408 or 425 or 429 || status is >= 500 and <= 599;
        bool auth = status is 400 or 401 or 403 or 409;
        var advice = auth ? "Check apiKey/secret, system clock, account permissions and gateway access rules."
            : retry ? "Check network/server availability." : "Check serverBaseUrl and server/client compatibility.";
        var wait = response.Headers.RetryAfter?.Delta ?? (response.Headers.RetryAfter?.Date - DateTimeOffset.UtcNow) ?? TimeSpan.Zero;
        wait = TimeSpan.FromSeconds(Math.Clamp(wait.TotalSeconds, 0, 3600));
        return new($"HTTP login failed (HTTP {status}). {advice}", retry, auth ? 3 : 1, wait);
    }
}
