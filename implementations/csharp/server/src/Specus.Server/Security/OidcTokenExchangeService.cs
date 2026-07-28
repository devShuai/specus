using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;

namespace Specus.Server.Security;

public sealed class OidcTokenExchangeService
{
    private readonly OidcOptions _options;
    private readonly IOidcTokenEndpointClient _client;
    private readonly ILogger<OidcTokenExchangeService> _logger;

    public OidcTokenExchangeService(IOptions<OidcOptions> options,
        IOidcTokenEndpointClient client,
        ILogger<OidcTokenExchangeService> logger)
    {
        _options = options.Value;
        _client = client;
        _logger = logger;
    }

    public async Task<IResult> ExchangeAsync(OidcTokenExchangeRequest? request,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(_options.ClientId))
        {
            return Results.Json(new { error = "OIDC 未配置（缺少 client-id）" },
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        if (request is null
            || string.IsNullOrWhiteSpace(request.Code)
            || string.IsNullOrWhiteSpace(request.CodeVerifier))
        {
            return Results.Json(new { error = "缺少 code 或 code_verifier" },
                statusCode: StatusCodes.Status400BadRequest);
        }

        var form = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "authorization_code",
            ["code"] = request.Code,
            ["redirect_uri"] = _options.RedirectUri,
            ["code_verifier"] = request.CodeVerifier,
        };

        string? basicAuthorization = null;
        if (string.IsNullOrWhiteSpace(_options.ClientSecret))
        {
            form["client_id"] = _options.ClientId;
        }
        else
        {
            var raw = $"{_options.ClientId}:{_options.ClientSecret}";
            basicAuthorization = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(raw));
        }

        try
        {
            var endpoint = new Uri(_options.TokenEndpoint, UriKind.Absolute);
            var response = await _client.ExchangeAsync(
                new OidcTokenEndpointRequest(endpoint, form, basicAuthorization),
                cancellationToken).ConfigureAwait(false);

            using var body = JsonDocument.Parse(response.Body);
            if ((int)response.StatusCode / 100 != 2)
            {
                var error = ReadString(body.RootElement, "error") ?? "token_exchange_failed";
                var description = ReadString(body.RootElement, "error_description") ?? string.Empty;
                _logger.LogWarning("[oidc] token exchange failed status={StatusCode} error={Error}",
                    (int)response.StatusCode, error);
                return Results.Json(new { error, error_description = description },
                    statusCode: StatusCodes.Status502BadGateway);
            }

            return Results.Ok(new
            {
                accessToken = ReadString(body.RootElement, "access_token"),
                idToken = ReadString(body.RootElement, "id_token"),
                tokenType = ReadString(body.RootElement, "token_type") ?? "Bearer",
                expiresIn = ReadInt64(body.RootElement, "expires_in"),
            });
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "[oidc] token exchange returned unparseable body");
            return Results.Json(new { error = "OIDC 令牌响应无法解析" },
                statusCode: StatusCodes.Status502BadGateway);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or UriFormatException
            or InvalidOperationException)
        {
            _logger.LogWarning(ex, "[oidc] token exchange error");
            return Results.Json(new { error = "无法连接 OIDC 令牌端点" },
                statusCode: StatusCodes.Status502BadGateway);
        }
    }

    private static string? ReadString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;

    private static long ReadInt64(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) && property.TryGetInt64(out var value)
            ? value
            : 0;
}

public sealed record OidcTokenExchangeRequest(string Code, string CodeVerifier);

public sealed record OidcTokenEndpointRequest(Uri TokenEndpoint,
    IReadOnlyDictionary<string, string> Form,
    string? BasicAuthorization);

public sealed record OidcTokenEndpointResponse(HttpStatusCode StatusCode, string Body);

public interface IOidcTokenEndpointClient
{
    Task<OidcTokenEndpointResponse> ExchangeAsync(OidcTokenEndpointRequest request,
        CancellationToken cancellationToken = default);
}

public sealed class HttpOidcTokenEndpointClient : IOidcTokenEndpointClient
{
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(15),
    };

    public async Task<OidcTokenEndpointResponse> ExchangeAsync(OidcTokenEndpointRequest request,
        CancellationToken cancellationToken = default)
    {
        using var message = new HttpRequestMessage(HttpMethod.Post, request.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(request.Form),
        };
        message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (!string.IsNullOrWhiteSpace(request.BasicAuthorization))
        {
            message.Headers.TryAddWithoutValidation("Authorization", request.BasicAuthorization);
        }

        using var response = await HttpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return new OidcTokenEndpointResponse(response.StatusCode, body);
    }
}
