using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;

namespace ShuaiTunnel.Server.Security;

public interface ITurnstileVerifier
{
    bool Enabled { get; }
    bool Configured { get; }
    string SiteKey { get; }
    Task VerifyAsync(string? responseToken, string expectedAction,
        CancellationToken cancellationToken = default);
}

public sealed class TurnstileVerifier : ITurnstileVerifier
{
    public const string LoginAction = "login";
    public const string RegisterAction = "register";

    private readonly AuthOptions _options;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<TurnstileVerifier> _logger;

    public TurnstileVerifier(IOptions<AuthOptions> options, IHttpClientFactory httpClientFactory,
        ILogger<TurnstileVerifier> logger)
    {
        _options = options.Value;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public bool Enabled => _options.TurnstileEnabled;

    public bool Configured => !Enabled
        || (!string.IsNullOrWhiteSpace(_options.TurnstileSiteKey)
            && !string.IsNullOrWhiteSpace(_options.TurnstileSecretKey)
            && VerifyUri() is not null
            && AllowedHostnames().Count > 0);

    public string SiteKey => _options.TurnstileSiteKey;

    public async Task VerifyAsync(string? responseToken, string expectedAction,
        CancellationToken cancellationToken = default)
    {
        if (!Enabled)
        {
            return;
        }
        if (!Configured)
        {
            throw new AuthenticationDependencyUnavailableException("Turnstile 未正确配置");
        }
        if (string.IsNullOrWhiteSpace(responseToken))
        {
            throw Rejected();
        }

        var verifyUri = VerifyUri()
            ?? throw new AuthenticationDependencyUnavailableException("Turnstile 验证地址无效");
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["secret"] = _options.TurnstileSecretKey.Trim(),
            ["response"] = responseToken.Trim(),
        });

        try
        {
            var client = _httpClientFactory.CreateClient(nameof(TurnstileVerifier));
            using var response = await client.PostAsync(verifyUri, content, cancellationToken)
                .ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Turnstile siteverify returned HTTP {StatusCode}",
                    (int)response.StatusCode);
                throw Unavailable();
            }

            var result = await response.Content.ReadFromJsonAsync<TurnstileSiteVerifyResponse>(
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (result is null)
            {
                throw Unavailable();
            }
            var hostname = NormalizeHostname(result?.Hostname);
            var accepted = result?.Success == true
                && string.Equals(expectedAction, result.Action, StringComparison.Ordinal)
                && AllowedHostnames().Contains(hostname);
            if (!accepted)
            {
                _logger.LogInformation(
                    "Turnstile rejected action={ExpectedAction} actualAction={ActualAction} hostname={Hostname} errors={Errors}",
                    expectedAction, result?.Action ?? string.Empty, hostname,
                    string.Join(',', result?.ErrorCodes ?? []));
                throw Rejected();
            }
        }
        catch (ArgumentException)
        {
            throw;
        }
        catch (AuthenticationDependencyUnavailableException)
        {
            throw;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            _logger.LogWarning(ex, "Turnstile verification request failed");
            throw Unavailable();
        }
    }

    private Uri? VerifyUri() =>
        Uri.TryCreate(_options.TurnstileVerifyUrl?.Trim(), UriKind.Absolute, out var uri)
        && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
            ? uri
            : null;

    private HashSet<string> AllowedHostnames() => _options.TurnstileAllowedHostnames
        .Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(NormalizeHostname)
        .Where(value => value.Length > 0)
        .ToHashSet(StringComparer.Ordinal);

    private static string NormalizeHostname(string? hostname) =>
        (hostname ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();

    private static ArgumentException Rejected() => new("人机验证失败，请重试");

    private static AuthenticationDependencyUnavailableException Unavailable() =>
        new("人机验证服务暂不可用");

    private sealed record TurnstileSiteVerifyResponse(
        [property: JsonPropertyName("success")] bool Success,
        [property: JsonPropertyName("action")] string? Action,
        [property: JsonPropertyName("hostname")] string? Hostname,
        [property: JsonPropertyName("error-codes")] IReadOnlyList<string>? ErrorCodes);
}

public sealed class AuthenticationDependencyUnavailableException(string message) : Exception(message);
