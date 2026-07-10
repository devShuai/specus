using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;

namespace ShuaiTunnel.Server.Management;

public interface IObjectStorageService
{
    bool Enabled { get; }
    void ValidateObjectKey(string objectKey);
    PresignedObjectUrl PresignUpload(string objectKey, string contentType, TimeSpan ttl);
    PresignedObjectUrl PresignDownload(string objectKey, TimeSpan ttl);
    Task<ObjectStat> StatAsync(string objectKey, CancellationToken cancellationToken);
    Task DeleteAsync(string objectKey, CancellationToken cancellationToken);
}

public sealed record PresignedObjectUrl(string Url, IReadOnlyDictionary<string, string> Headers,
    string ExpiresAt);
public sealed record ObjectStat(bool Exists, long ContentLength);

/// <summary>Aliyun OSS v1 query signing, matching the Java attachment implementation.</summary>
public sealed class AliyunOssObjectStorageService : IObjectStorageService
{
    private readonly ObjectStorageOptions _options;
    private readonly HttpClient _http;

    public AliyunOssObjectStorageService(IOptions<ObjectStorageOptions> options,
        IHttpClientFactory httpClientFactory)
    {
        _options = options.Value;
        _http = httpClientFactory.CreateClient(nameof(AliyunOssObjectStorageService));
        _http.Timeout = TimeSpan.FromSeconds(20);
    }

    public bool Enabled => string.Equals(_options.Provider, "aliyun-oss",
        StringComparison.OrdinalIgnoreCase)
        && !string.IsNullOrWhiteSpace(_options.Endpoint)
        && !string.IsNullOrWhiteSpace(_options.Bucket)
        && !string.IsNullOrWhiteSpace(_options.AccessKeyId)
        && !string.IsNullOrWhiteSpace(_options.AccessKeySecret);

    /// <summary>Java's JDK HttpClient does not follow redirects unless explicitly enabled.</summary>
    internal static HttpMessageHandler CreateNoRedirectHandler() => new HttpClientHandler
    {
        AllowAutoRedirect = false,
    };

    public void ValidateObjectKey(string objectKey)
    {
        if (string.IsNullOrWhiteSpace(objectKey))
        {
            throw new ArgumentException("objectKey cannot be blank");
        }
        var normalized = objectKey.Trim();
        if (normalized.StartsWith('/') || normalized.Contains('\\') || normalized.Contains("..",
                StringComparison.Ordinal) || normalized.Contains("//", StringComparison.Ordinal)
            || normalized.Any(ch => ch < 32))
        {
            throw new ArgumentException("objectKey is invalid");
        }
        var prefix = NormalizedPrefix();
        if (prefix.Length > 0 && !normalized.StartsWith(prefix + '/', StringComparison.Ordinal))
        {
            throw new ArgumentException("objectKey is outside the configured prefix");
        }
    }

    public PresignedObjectUrl PresignUpload(string objectKey, string contentType, TimeSpan ttl)
    {
        EnsureEnabled();
        ValidateObjectKey(objectKey);
        var safeContentType = string.IsNullOrWhiteSpace(contentType)
            ? "application/octet-stream"
            : contentType.Trim();
        var expires = DateTimeOffset.UtcNow.Add(ttl).ToUnixTimeSeconds();
        var signature = Signature("PUT", safeContentType, expires, objectKey);
        return new PresignedObjectUrl(SignedUrl(objectKey, expires, signature),
            new Dictionary<string, string> { ["Content-Type"] = safeContentType },
            DateTimeOffset.FromUnixTimeSeconds(expires).ToString("O"));
    }

    public PresignedObjectUrl PresignDownload(string objectKey, TimeSpan ttl)
    {
        EnsureEnabled();
        ValidateObjectKey(objectKey);
        var expires = DateTimeOffset.UtcNow.Add(ttl).ToUnixTimeSeconds();
        var signature = Signature("GET", string.Empty, expires, objectKey);
        return new PresignedObjectUrl(SignedUrl(objectKey, expires, signature),
            new Dictionary<string, string>(),
            DateTimeOffset.FromUnixTimeSeconds(expires).ToString("O"));
    }

    public async Task<ObjectStat> StatAsync(string objectKey, CancellationToken cancellationToken)
    {
        EnsureEnabled();
        ValidateObjectKey(objectKey);
        using var request = AuthorizedRequest(HttpMethod.Head, objectKey);
        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsTransportFailure(ex, cancellationToken))
        {
            throw new InvalidOperationException("failed to stat object", ex);
        }
        using (response)
        {
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                return new ObjectStat(false, -1);
            }
            // Match Java literally: every response below 400 (including redirects) is a
            // completed HEAD. Redirect following is disabled so the signed OSS request is never
            // replayed to an untrusted Location.
            if ((int)response.StatusCode >= 400)
            {
                throw new InvalidOperationException($"failed to stat object: HTTP {(int)response.StatusCode}");
            }
            return new ObjectStat(true, response.Content.Headers.ContentLength ?? -1L);
        }
    }

    public async Task DeleteAsync(string objectKey, CancellationToken cancellationToken)
    {
        EnsureEnabled();
        ValidateObjectKey(objectKey);
        using var request = AuthorizedRequest(HttpMethod.Delete, objectKey);
        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsTransportFailure(ex, cancellationToken))
        {
            throw new InvalidOperationException("failed to delete object", ex);
        }
        using (response)
        {
            if ((int)response.StatusCode >= 400 && response.StatusCode != HttpStatusCode.NotFound)
            {
                throw new InvalidOperationException($"failed to delete object: HTTP {(int)response.StatusCode}");
            }
        }
    }

    internal string NormalizedPrefix() => (_options.ObjectPrefix ?? string.Empty).Trim().Trim('/');

    private HttpRequestMessage AuthorizedRequest(HttpMethod method, string objectKey)
    {
        var now = DateTimeOffset.UtcNow.ToString("r", CultureInfo.InvariantCulture);
        var signature = HmacSha1($"{method.Method.ToUpperInvariant()}\n\n\n{now}\n{CanonicalResource(objectKey)}");
        var request = new HttpRequestMessage(method, ObjectUrl(objectKey));
        request.Headers.TryAddWithoutValidation("Date", now);
        request.Headers.TryAddWithoutValidation("Authorization",
            $"OSS {_options.AccessKeyId}:{signature}");
        return request;
    }

    private string Signature(string method, string contentType, long expires, string objectKey) =>
        HmacSha1($"{method.ToUpperInvariant()}\n\n{contentType}\n{expires}\n{CanonicalResource(objectKey)}");

    private string HmacSha1(string value)
    {
        using var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(_options.AccessKeySecret));
        return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(value)));
    }

    private string SignedUrl(string objectKey, long expires, string signature) =>
        ObjectUrl(objectKey) + "?OSSAccessKeyId=" + Encode(_options.AccessKeyId)
        + "&Expires=" + expires.ToString(CultureInfo.InvariantCulture)
        + "&Signature=" + Encode(signature);

    private string ObjectUrl(string objectKey)
    {
        var endpoint = _options.Endpoint.Trim();
        if (!endpoint.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            && !endpoint.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            endpoint = "https://" + endpoint;
        }
        var endpointUri = new Uri(endpoint.TrimEnd('/'));
        var port = endpointUri.IsDefaultPort ? string.Empty : ":" + endpointUri.Port;
        return $"{endpointUri.Scheme}://{_options.Bucket}.{endpointUri.Host}{port}/{EncodePath(objectKey)}";
    }

    private string CanonicalResource(string objectKey) => $"/{_options.Bucket}/{objectKey}";
    private static string EncodePath(string value) => string.Join('/', value.Split('/').Select(Encode));
    private static string Encode(string value) => Uri.EscapeDataString(value).Replace("%7E", "~",
        StringComparison.OrdinalIgnoreCase);

    private void EnsureEnabled()
    {
        if (!Enabled)
        {
            throw new InvalidOperationException("object storage is not configured");
        }
    }

    private static bool IsTransportFailure(Exception exception, CancellationToken cancellationToken) =>
        exception is HttpRequestException or IOException
        || exception is OperationCanceledException && !cancellationToken.IsCancellationRequested;
}
