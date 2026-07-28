using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;

namespace Specus.Server.Management;

public interface IObjectStorageService
{
    bool Enabled { get; }
    void ValidateObjectKey(string objectKey);
    PresignedObjectUrl PresignUpload(string objectKey, string contentType, TimeSpan ttl);
    PresignedObjectUrl PresignDownload(string objectKey, TimeSpan ttl);
    PresignedObjectUrl PresignDownload(string objectKey, TimeSpan ttl, string? downloadGrantId) =>
        PresignDownload(objectKey, ttl);
    Task<bool> VerifyUploadCallbackAsync(string requestTarget, byte[] body,
        string? authorization, string? publicKeyUrl, CancellationToken cancellationToken) =>
        Task.FromResult(false);
    Task<ObjectStat> StatAsync(string objectKey, CancellationToken cancellationToken);
    Task DeleteAsync(string objectKey, CancellationToken cancellationToken);
}

public sealed record PresignedObjectUrl(string Url, IReadOnlyDictionary<string, string> Headers,
    string ExpiresAt);
public sealed record ObjectStat(bool Exists, long ContentLength);

/// <summary>Aliyun OSS V4 signing for direct client upload and download.</summary>
public sealed class AliyunOssObjectStorageService : IObjectStorageService
{
    private const string Algorithm = "OSS4-HMAC-SHA256";
    private const string Terminator = "aliyun_v4_request";
    private const string UnsignedPayload = "UNSIGNED-PAYLOAD";
    private const long MaxPresignTtlSeconds = 7L * 24 * 60 * 60;

    private readonly ObjectStorageOptions _options;
    private readonly HttpClient _http;
    private readonly TimeProvider _timeProvider;
    private readonly ConcurrentDictionary<string, RSAParameters> _callbackPublicKeys = new();

    public AliyunOssObjectStorageService(IOptions<ObjectStorageOptions> options,
        IHttpClientFactory httpClientFactory)
        : this(options.Value, httpClientFactory.CreateClient(nameof(AliyunOssObjectStorageService)),
            TimeProvider.System)
    {
        _http.Timeout = TimeSpan.FromSeconds(20);
    }

    internal AliyunOssObjectStorageService(ObjectStorageOptions options, HttpClient http,
        TimeProvider timeProvider)
    {
        _options = options;
        _http = http;
        _timeProvider = timeProvider;
    }

    public bool Enabled => string.Equals(_options.Provider, "aliyun-oss",
        StringComparison.OrdinalIgnoreCase)
        && !string.IsNullOrWhiteSpace(_options.Endpoint)
        && !string.IsNullOrWhiteSpace(_options.Bucket)
        && !string.IsNullOrWhiteSpace(_options.AccessKeyId)
        && !string.IsNullOrWhiteSpace(_options.AccessKeySecret);

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
        return Presign("PUT", objectKey, ttl, safeContentType, null);
    }

    public PresignedObjectUrl PresignDownload(string objectKey, TimeSpan ttl) =>
        PresignDownload(objectKey, ttl, null);

    public PresignedObjectUrl PresignDownload(string objectKey, TimeSpan ttl,
        string? downloadGrantId)
    {
        EnsureEnabled();
        ValidateObjectKey(objectKey);
        return Presign("GET", objectKey, ttl, null, downloadGrantId);
    }

    public async Task<bool> VerifyUploadCallbackAsync(string requestTarget, byte[] body,
        string? authorization, string? publicKeyUrl, CancellationToken cancellationToken)
    {
        if (!Enabled || string.IsNullOrWhiteSpace(_options.UploadCallbackUrl)
            || string.IsNullOrWhiteSpace(requestTarget) || body.Length > 64 * 1024
            || string.IsNullOrWhiteSpace(authorization) || string.IsNullOrWhiteSpace(publicKeyUrl))
        {
            return false;
        }
        try
        {
            var parameters = await CallbackPublicKeyAsync(publicKeyUrl, cancellationToken)
                .ConfigureAwait(false);
            var signatureValue = authorization.Trim();
            if (signatureValue.StartsWith("OSS ", StringComparison.OrdinalIgnoreCase))
            {
                signatureValue = signatureValue[4..].Trim();
            }
            using var rsa = RSA.Create();
            rsa.ImportParameters(parameters);
            return rsa.VerifyData(Encoding.UTF8.GetBytes(CallbackStringToVerify(requestTarget, body)),
                Convert.FromBase64String(signatureValue), HashAlgorithmName.MD5,
                RSASignaturePadding.Pkcs1);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException
                                   or HttpRequestException or IOException
                                   or InvalidOperationException or OperationCanceledException)
        {
            return false;
        }
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

    private PresignedObjectUrl Presign(string method, string objectKey, TimeSpan ttl,
        string? contentType, string? downloadGrantId)
    {
        var now = _timeProvider.GetUtcNow();
        var ttlSeconds = NormalizePresignTtl(ttl);
        var expiresAt = now.AddSeconds(ttlSeconds);
        var date = now.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        var timestamp = now.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        var region = ResolvedRegion();
        var scope = $"{date}/{region}/oss/{Terminator}";
        var query = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["x-oss-additional-headers"] = "host",
            ["x-oss-credential"] = $"{_options.AccessKeyId.Trim()}/{scope}",
            ["x-oss-date"] = timestamp,
            ["x-oss-expires"] = ttlSeconds.ToString(CultureInfo.InvariantCulture),
            ["x-oss-signature-version"] = Algorithm,
        };
        if (!string.IsNullOrWhiteSpace(downloadGrantId))
        {
            query["x-st-grant"] = downloadGrantId.Trim();
        }
        var headers = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["host"] = ObjectHost(),
        };
        var responseHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(contentType))
        {
            headers["content-type"] = contentType;
            responseHeaders["Content-Type"] = contentType;
        }
        if (string.Equals(method, "PUT", StringComparison.OrdinalIgnoreCase))
        {
            var callback = UploadCallbackHeader();
            if (callback.Length > 0)
            {
                headers["x-oss-callback"] = callback;
                responseHeaders["x-oss-callback"] = callback;
            }
        }
        var canonical = CanonicalRequest(method, objectKey, query, headers, "host",
            UnsignedPayload);
        query["x-oss-signature"] = Signature(now, canonical, region);
        return new PresignedObjectUrl(ObjectUrl(objectKey) + "?" + CanonicalQuery(query),
            responseHeaders, expiresAt.ToString("O", CultureInfo.InvariantCulture));
    }

    private HttpRequestMessage AuthorizedRequest(HttpMethod method, string objectKey)
    {
        var now = _timeProvider.GetUtcNow();
        var date = now.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        var timestamp = now.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        var region = ResolvedRegion();
        var headers = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["host"] = ObjectHost(),
            ["x-oss-content-sha256"] = UnsignedPayload,
            ["x-oss-date"] = timestamp,
        };
        var canonical = CanonicalRequest(method.Method, objectKey, null, headers, "host",
            UnsignedPayload);
        var authorization = $"{Algorithm} Credential={_options.AccessKeyId.Trim()}/" +
            $"{date}/{region}/oss/{Terminator}, AdditionalHeaders=host, " +
            $"Signature={Signature(now, canonical, region)}";
        var request = new HttpRequestMessage(method, ObjectUrl(objectKey));
        request.Headers.TryAddWithoutValidation("x-oss-content-sha256", UnsignedPayload);
        request.Headers.TryAddWithoutValidation("x-oss-date", timestamp);
        request.Headers.TryAddWithoutValidation("Authorization", authorization);
        return request;
    }

    private string CanonicalRequest(string method, string objectKey,
        IReadOnlyDictionary<string, string>? query, IReadOnlyDictionary<string, string> headers,
        string additionalHeaders, string payloadHash) =>
        $"{method.ToUpperInvariant()}\n{CanonicalResource(objectKey)}\n{CanonicalQuery(query)}\n" +
        $"{CanonicalHeaders(headers)}\n{additionalHeaders}\n{payloadHash}";

    private string Signature(DateTimeOffset now, string canonicalRequest, string region)
    {
        var date = now.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        var scope = $"{date}/{region}/oss/{Terminator}";
        var stringToSign = $"{Algorithm}\n" +
            $"{now.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture)}\n" +
            $"{scope}\n{Sha256Hex(canonicalRequest)}";
        var dateKey = HmacSha256(Encoding.UTF8.GetBytes("aliyun_v4" + _options.AccessKeySecret), date);
        var regionKey = HmacSha256(dateKey, region);
        var serviceKey = HmacSha256(regionKey, "oss");
        var signingKey = HmacSha256(serviceKey, Terminator);
        return Convert.ToHexStringLower(HmacSha256(signingKey, stringToSign));
    }

    private static byte[] HmacSha256(byte[] key, string value) =>
        HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value));

    private static string Sha256Hex(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string CanonicalHeaders(IReadOnlyDictionary<string, string> headers)
    {
        var result = new StringBuilder();
        foreach (var entry in headers.OrderBy(entry => entry.Key, StringComparer.Ordinal))
        {
            result.Append(entry.Key.ToLowerInvariant()).Append(':').Append(entry.Value.Trim())
                .Append('\n');
        }
        return result.ToString();
    }

    private static string CanonicalQuery(IReadOnlyDictionary<string, string>? query)
    {
        if (query is null || query.Count == 0)
        {
            return string.Empty;
        }
        return string.Join('&', query
            .Select(entry => (Key: UriEncode(entry.Key, true), Value: UriEncode(entry.Value, true)))
            .OrderBy(entry => entry.Key, StringComparer.Ordinal)
            .ThenBy(entry => entry.Value, StringComparer.Ordinal)
            .Select(entry => $"{entry.Key}={entry.Value}"));
    }

    private static long NormalizePresignTtl(TimeSpan ttl) =>
        Math.Clamp((long)ttl.TotalSeconds, 1L, MaxPresignTtlSeconds);

    private string UploadCallbackHeader()
    {
        if (string.IsNullOrWhiteSpace(_options.UploadCallbackUrl))
        {
            return string.Empty;
        }
        if (!Uri.TryCreate(_options.UploadCallbackUrl.Trim(), UriKind.Absolute, out var callbackUrl)
            || callbackUrl.Scheme is not ("http" or "https")
            || string.IsNullOrWhiteSpace(callbackUrl.Host)
            || !string.IsNullOrEmpty(callbackUrl.UserInfo)
            || !string.IsNullOrEmpty(callbackUrl.Fragment))
        {
            throw new InvalidOperationException("object storage upload callback URL is invalid");
        }
        var callback = new Dictionary<string, object>
        {
            ["callbackUrl"] = callbackUrl.AbsoluteUri,
            ["callbackBody"] = "{\"bucket\":${bucket},\"object\":${object},\"size\":${size}," +
                "\"mimeType\":${mimeType},\"etag\":${etag}}",
            ["callbackBodyType"] = "application/json",
        };
        if (callbackUrl.Scheme == Uri.UriSchemeHttps)
        {
            callback["callbackSNI"] = true;
        }
        return Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(callback));
    }

    private async Task<RSAParameters> CallbackPublicKeyAsync(string encodedUrl,
        CancellationToken cancellationToken)
    {
        var decodedUrl = Encoding.UTF8.GetString(Convert.FromBase64String(encodedUrl.Trim()));
        if (!Uri.TryCreate(decodedUrl.Trim(), UriKind.Absolute, out var supplied)
            || !string.Equals(supplied.Host, "gosspublic.alicdn.com", StringComparison.OrdinalIgnoreCase)
            || supplied.Scheme is not ("http" or "https") || !supplied.IsDefaultPort
            || !string.IsNullOrEmpty(supplied.UserInfo) || !string.IsNullOrEmpty(supplied.Fragment)
            || !string.IsNullOrEmpty(supplied.Query)
            || !supplied.AbsolutePath.StartsWith("/callback_pub_key", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("OSS callback public key URL is invalid");
        }
        var secureUrl = new UriBuilder(supplied)
        {
            Scheme = Uri.UriSchemeHttps,
            Port = -1,
            Query = string.Empty,
            Fragment = string.Empty,
        }.Uri.AbsoluteUri;
        if (_callbackPublicKeys.TryGetValue(secureUrl, out var cached))
        {
            return cached;
        }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        using var response = await _http.GetAsync(secureUrl, HttpCompletionOption.ResponseHeadersRead,
            timeout.Token).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new InvalidOperationException(
                $"failed to load OSS callback public key: HTTP {(int)response.StatusCode}");
        }
        await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token)
            .ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = new byte[4096];
        while (output.Length <= 64 * 1024)
        {
            var read = await stream.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            output.Write(buffer, 0, read);
        }
        if (output.Length > 64 * 1024)
        {
            throw new InvalidOperationException("OSS callback public key response is too large");
        }
        using var rsa = RSA.Create();
        rsa.ImportFromPem(Encoding.UTF8.GetString(output.ToArray()));
        var parsed = rsa.ExportParameters(false);
        return _callbackPublicKeys.GetOrAdd(secureUrl, parsed);
    }

    private static string CallbackStringToVerify(string requestTarget, byte[] body)
    {
        var queryIndex = requestTarget.IndexOf('?');
        var rawPath = queryIndex < 0 ? requestTarget : requestTarget[..queryIndex];
        var rawQuery = queryIndex < 0 ? string.Empty : requestTarget[queryIndex..];
        return Uri.UnescapeDataString(rawPath) + rawQuery + "\n" + Encoding.UTF8.GetString(body);
    }

    private string ResolvedRegion()
    {
        if (!string.IsNullOrWhiteSpace(_options.Region))
        {
            return _options.Region.Trim();
        }
        var host = EndpointUri().Host.ToLowerInvariant();
        if (host.StartsWith("oss-", StringComparison.Ordinal))
        {
            var candidate = host.Split('.', 2)[0][4..];
            if (candidate.EndsWith("-internal", StringComparison.Ordinal))
            {
                candidate = candidate[..^"-internal".Length];
            }
            if (candidate.Length > 0 && !string.Equals(candidate, "accelerate",
                    StringComparison.Ordinal))
            {
                return candidate;
            }
        }
        throw new InvalidOperationException("object storage region is required for OSS V4 signing");
    }

    private Uri EndpointUri()
    {
        var endpoint = _options.Endpoint.Trim();
        if (!endpoint.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            && !endpoint.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            endpoint = "https://" + endpoint;
        }
        if (!Uri.TryCreate(endpoint.TrimEnd('/'), UriKind.Absolute, out var uri)
            || string.IsNullOrWhiteSpace(uri.Host))
        {
            throw new InvalidOperationException("object storage endpoint is invalid");
        }
        return uri;
    }

    private string ObjectHost()
    {
        var endpoint = EndpointUri();
        var port = endpoint.IsDefaultPort ? string.Empty : ":" + endpoint.Port;
        return $"{_options.Bucket.Trim()}.{endpoint.Host}{port}";
    }

    private string ObjectUrl(string objectKey)
    {
        var endpoint = EndpointUri();
        return $"{endpoint.Scheme}://{ObjectHost()}/{UriEncode(objectKey, false)}";
    }

    private string CanonicalResource(string objectKey) =>
        UriEncode($"/{_options.Bucket.Trim()}/{objectKey}", false);

    private static string UriEncode(string value, bool encodeSlash)
    {
        const string hex = "0123456789ABCDEF";
        var result = new StringBuilder();
        foreach (var current in Encoding.UTF8.GetBytes(value))
        {
            var unreserved = current is >= (byte)'A' and <= (byte)'Z'
                or >= (byte)'a' and <= (byte)'z'
                or >= (byte)'0' and <= (byte)'9'
                or (byte)'-' or (byte)'_' or (byte)'.' or (byte)'~';
            if (unreserved || !encodeSlash && current == (byte)'/')
            {
                result.Append((char)current);
            }
            else
            {
                result.Append('%').Append(hex[current >> 4]).Append(hex[current & 0x0f]);
            }
        }
        return result.ToString();
    }

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
