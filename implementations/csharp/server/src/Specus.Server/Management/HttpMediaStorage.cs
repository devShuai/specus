using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;

namespace Specus.Server.Management;

public interface IHttpMediaStorage
{
    bool Ready { get; }
    Task InitializeAsync(CancellationToken cancellationToken);
    Task<MediaMultipartUpload> BeginMultipartAsync(string objectKey, string? contentType,
        string? contentEncoding, CancellationToken cancellationToken);
    Task<MediaCompletedPart> UploadPartAsync(MediaMultipartUpload upload, int partNumber,
        ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken);
    Task<string> CompleteMultipartAsync(MediaMultipartUpload upload,
        IReadOnlyList<MediaCompletedPart> parts, CancellationToken cancellationToken);
    Task AbortMultipartAsync(MediaMultipartUpload upload, CancellationToken cancellationToken);
    Task<Stream> OpenReadAsync(string objectKey, long? start, long? end,
        CancellationToken cancellationToken);
    Task<byte[]> ReadAllAsync(string objectKey, long maxBytes, CancellationToken cancellationToken);
    Task DeleteAsync(string objectKey, CancellationToken cancellationToken);
}

public sealed record MediaMultipartUpload(string ObjectKey, string UploadId);
public sealed record MediaCompletedPart(int PartNumber, string Etag);

/// <summary>
/// Minimal AWS Signature V4 S3 client for RustFS/MinIO-compatible media storage. Keeping this
/// separate from attachment OSS signing avoids silently treating Aliyun OSS credentials as S3.
/// </summary>
public sealed class RustFsMediaStorage : IHttpMediaStorage
{
    private static readonly byte[] EmptyHash = SHA256.HashData([]);
    private readonly MediaCaptureOptions _options;
    private readonly HttpClient _http;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<RustFsMediaStorage> _logger;
    private volatile bool _ready;

    public RustFsMediaStorage(IOptions<MediaCaptureOptions> options, IHttpClientFactory factory,
        ILogger<RustFsMediaStorage> logger)
        : this(options.Value, factory.CreateClient(nameof(RustFsMediaStorage)),
            TimeProvider.System, logger)
    {
    }

    internal RustFsMediaStorage(MediaCaptureOptions options, HttpClient http,
        TimeProvider timeProvider, ILogger<RustFsMediaStorage> logger)
    {
        _options = options;
        _http = http;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    public bool Ready => _ready && _options.IsReady;

    internal static HttpMessageHandler CreateNoRedirectHandler() => new HttpClientHandler
    {
        AllowAutoRedirect = false,
    };

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        _ready = false;
        if (!_options.IsReady)
        {
            _logger.LogInformation("HTTP media capture is disabled or its RustFS configuration is incomplete");
            return;
        }
        try
        {
            using var head = await SendAsync(HttpMethod.Head, null, null, null, null,
                cancellationToken).ConfigureAwait(false);
            if (head.StatusCode == HttpStatusCode.NotFound && _options.CreateBucketIfMissing)
            {
                using var create = await SendAsync(HttpMethod.Put, null, null, null, null,
                    cancellationToken).ConfigureAwait(false);
                await EnsureSuccessAsync(create, "create media bucket", cancellationToken)
                    .ConfigureAwait(false);
            }
            else
            {
                await EnsureSuccessAsync(head, "verify media bucket", cancellationToken)
                    .ConfigureAwait(false);
            }
            _ready = true;
            _logger.LogInformation("HTTP media capture RustFS bucket {Bucket} is ready", _options.Bucket);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException
                                   or InvalidOperationException or OperationCanceledException)
        {
            if (ex is OperationCanceledException && cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            _logger.LogCritical(ex,
                "HTTP media capture is fully configured but RustFS initialization failed; refusing to start");
            throw new InvalidOperationException("HTTP media capture RustFS initialization failed", ex);
        }
    }

    public async Task<MediaMultipartUpload> BeginMultipartAsync(string objectKey, string? contentType,
        string? contentEncoding, CancellationToken cancellationToken)
    {
        EnsureReady();
        ValidateObjectKey(objectKey);
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(contentType))
        {
            headers["content-type"] = contentType.Trim();
        }
        if (!string.IsNullOrWhiteSpace(contentEncoding))
        {
            headers["content-encoding"] = contentEncoding.Trim();
        }
        using var response = await SendAsync(HttpMethod.Post, objectKey,
            new Dictionary<string, string?> { ["uploads"] = null }, [], headers,
            cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, "begin media multipart upload", cancellationToken)
            .ConfigureAwait(false);
        var xml = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var uploadId = XDocument.Parse(xml).Descendants()
            .FirstOrDefault(node => node.Name.LocalName == "UploadId")?.Value;
        if (string.IsNullOrWhiteSpace(uploadId))
        {
            throw new InvalidOperationException("RustFS multipart response did not contain UploadId");
        }
        return new MediaMultipartUpload(objectKey, uploadId);
    }

    public async Task<MediaCompletedPart> UploadPartAsync(MediaMultipartUpload upload, int partNumber,
        ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken)
    {
        EnsureReady();
        if (partNumber <= 0 || bytes.IsEmpty)
        {
            throw new ArgumentException("media multipart part is invalid");
        }
        using var response = await SendAsync(HttpMethod.Put, upload.ObjectKey,
            new Dictionary<string, string?>
            {
                ["partNumber"] = partNumber.ToString(CultureInfo.InvariantCulture),
                ["uploadId"] = upload.UploadId,
            }, bytes.ToArray(), null, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, "upload media part", cancellationToken).ConfigureAwait(false);
        var etag = response.Headers.ETag?.Tag;
        if (etag is null && response.Headers.TryGetValues("ETag", out var values))
        {
            etag = values.FirstOrDefault();
        }
        if (string.IsNullOrWhiteSpace(etag))
        {
            throw new InvalidOperationException("RustFS upload part response did not contain ETag");
        }
        return new MediaCompletedPart(partNumber, etag);
    }

    public async Task<string> CompleteMultipartAsync(MediaMultipartUpload upload,
        IReadOnlyList<MediaCompletedPart> parts, CancellationToken cancellationToken)
    {
        EnsureReady();
        if (parts.Count == 0)
        {
            throw new ArgumentException("media multipart upload has no parts");
        }
        var document = new XDocument(new XElement("CompleteMultipartUpload",
            parts.OrderBy(part => part.PartNumber).Select(part => new XElement("Part",
                new XElement("PartNumber", part.PartNumber), new XElement("ETag", part.Etag)))));
        var body = Encoding.UTF8.GetBytes(document.ToString(SaveOptions.DisableFormatting));
        using var response = await SendAsync(HttpMethod.Post, upload.ObjectKey,
            new Dictionary<string, string?> { ["uploadId"] = upload.UploadId }, body,
            new Dictionary<string, string> { ["content-type"] = "application/xml" },
            cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, "complete media multipart upload", cancellationToken)
            .ConfigureAwait(false);
        var xml = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(xml))
        {
            throw new InvalidOperationException("RustFS complete multipart response was empty");
        }
        var result = XDocument.Parse(xml);
        if (result.Root?.Name.LocalName == "Error")
        {
            var code = result.Descendants().FirstOrDefault(node => node.Name.LocalName == "Code")?.Value;
            var message = result.Descendants().FirstOrDefault(node => node.Name.LocalName == "Message")?.Value;
            throw new InvalidOperationException(
                $"RustFS rejected complete multipart upload: {code} {message}".TrimEnd());
        }
        var etag = result.Descendants().FirstOrDefault(node => node.Name.LocalName == "ETag")?.Value;
        if (string.IsNullOrWhiteSpace(etag))
        {
            throw new InvalidOperationException("RustFS complete multipart response did not contain ETag");
        }
        return etag;
    }

    public async Task AbortMultipartAsync(MediaMultipartUpload upload, CancellationToken cancellationToken)
    {
        if (!Ready)
        {
            return;
        }
        using var response = await SendAsync(HttpMethod.Delete, upload.ObjectKey,
            new Dictionary<string, string?> { ["uploadId"] = upload.UploadId }, null, null,
            cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.NotFound)
        {
            await EnsureSuccessAsync(response, "abort media multipart upload", cancellationToken)
                .ConfigureAwait(false);
        }
    }

    public async Task<Stream> OpenReadAsync(string objectKey, long? start, long? end,
        CancellationToken cancellationToken)
    {
        EnsureReady();
        Dictionary<string, string>? headers = null;
        if (start is not null)
        {
            headers = new Dictionary<string, string>
            {
                ["range"] = $"bytes={start.Value}-{(end is null ? string.Empty : end.Value.ToString(CultureInfo.InvariantCulture))}",
            };
        }
        var response = await SendAsync(HttpMethod.Get, objectKey, null, null, headers,
            cancellationToken, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
        try
        {
            await EnsureSuccessAsync(response, "read media object", cancellationToken)
                .ConfigureAwait(false);
            if (start is not null)
            {
                var contentRange = response.Content.Headers.ContentRange;
                if (response.StatusCode != HttpStatusCode.PartialContent
                    || contentRange is null
                    || !string.Equals(contentRange.Unit, "bytes", StringComparison.OrdinalIgnoreCase)
                    || contentRange.From != start
                    || end is not null && contentRange.To != end)
                {
                    throw new InvalidOperationException(
                        "RustFS returned an invalid response for a ranged media read");
                }
            }
            var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            return new ResponseBoundStream(stream, response);
        }
        catch
        {
            response.Dispose();
            throw;
        }
    }

    public async Task<byte[]> ReadAllAsync(string objectKey, long maxBytes,
        CancellationToken cancellationToken)
    {
        if (maxBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBytes));
        }
        using var head = await SendAsync(HttpMethod.Head, objectKey, null, null, null,
            cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(head, "stat media object", cancellationToken).ConfigureAwait(false);
        if (head.Content.Headers.ContentLength is { } length && length > maxBytes)
        {
            throw new InvalidOperationException("media manifest exceeds configured size limit");
        }
        await using var input = await OpenReadAsync(objectKey, null, null, cancellationToken)
            .ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return output.ToArray();
            }
            if (output.Length + read > maxBytes)
            {
                throw new InvalidOperationException("media manifest exceeds configured size limit");
            }
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task DeleteAsync(string objectKey, CancellationToken cancellationToken)
    {
        EnsureReady();
        using var response = await SendAsync(HttpMethod.Delete, objectKey, null, null, null,
            cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.NotFound)
        {
            await EnsureSuccessAsync(response, "delete media object", cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string? objectKey,
        IReadOnlyDictionary<string, string?>? query, byte[]? body,
        IReadOnlyDictionary<string, string>? extraHeaders, CancellationToken cancellationToken,
        HttpCompletionOption completion = HttpCompletionOption.ResponseContentRead)
    {
        if (objectKey is not null)
        {
            ValidateObjectKey(objectKey);
        }
        var now = _timeProvider.GetUtcNow();
        var date = now.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        var timestamp = now.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        var region = string.IsNullOrWhiteSpace(_options.Region) ? "us-east-1" : _options.Region.Trim();
        var (uri, canonicalPath) = ObjectUri(objectKey, query);
        var payloadHash = Convert.ToHexStringLower(body is null ? EmptyHash : SHA256.HashData(body));
        var headers = new SortedDictionary<string, string>(StringComparer.Ordinal)
        {
            ["host"] = uri.IsDefaultPort ? uri.Host : uri.Authority,
            ["x-amz-content-sha256"] = payloadHash,
            ["x-amz-date"] = timestamp,
        };
        foreach (var (name, value) in extraHeaders ?? new Dictionary<string, string>())
        {
            headers[name.Trim().ToLowerInvariant()] = NormalizeHeader(value);
        }
        var signedHeaders = string.Join(';', headers.Keys);
        var canonicalHeaders = string.Concat(headers.Select(entry => $"{entry.Key}:{entry.Value}\n"));
        var canonicalRequest = $"{method.Method}\n{canonicalPath}\n{CanonicalQuery(query)}\n" +
                               $"{canonicalHeaders}\n{signedHeaders}\n{payloadHash}";
        var scope = $"{date}/{region}/s3/aws4_request";
        var stringToSign = $"AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n" +
                           Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalRequest)));
        var dateKey = Hmac(Encoding.UTF8.GetBytes("AWS4" + _options.AccessKeySecret), date);
        var regionKey = Hmac(dateKey, region);
        var serviceKey = Hmac(regionKey, "s3");
        var signingKey = Hmac(serviceKey, "aws4_request");
        var signature = Convert.ToHexStringLower(Hmac(signingKey, stringToSign));

        var request = new HttpRequestMessage(method, uri);
        if (body is not null)
        {
            request.Content = new ByteArrayContent(body);
        }
        foreach (var (name, value) in extraHeaders ?? new Dictionary<string, string>())
        {
            if (!request.Headers.TryAddWithoutValidation(name, value))
            {
                request.Content ??= new ByteArrayContent([]);
                request.Content.Headers.TryAddWithoutValidation(name, value);
            }
        }
        request.Headers.TryAddWithoutValidation("x-amz-content-sha256", payloadHash);
        request.Headers.TryAddWithoutValidation("x-amz-date", timestamp);
        request.Headers.TryAddWithoutValidation("Authorization",
            $"AWS4-HMAC-SHA256 Credential={_options.AccessKeyId.Trim()}/{scope}, " +
            $"SignedHeaders={signedHeaders}, Signature={signature}");
        try
        {
            return await _http.SendAsync(request, completion, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            request.Dispose();
        }
    }

    private (Uri Uri, string CanonicalPath) ObjectUri(string? objectKey,
        IReadOnlyDictionary<string, string?>? query)
    {
        if (!Uri.TryCreate(_options.Endpoint.Trim(), UriKind.Absolute, out var endpoint)
            || endpoint.Scheme is not ("http" or "https")
            || string.IsNullOrWhiteSpace(endpoint.Host) || !string.IsNullOrEmpty(endpoint.UserInfo)
            || !string.IsNullOrEmpty(endpoint.Query) || !string.IsNullOrEmpty(endpoint.Fragment))
        {
            throw new InvalidOperationException("media capture endpoint is invalid");
        }
        var endpointPath = endpoint.AbsolutePath.TrimEnd('/');
        var keyPath = objectKey is null ? string.Empty : "/" + EncodePath(objectKey);
        UriBuilder builder;
        string path;
        if (_options.PathStyle)
        {
            path = endpointPath + "/" + AwsEncode(_options.Bucket.Trim()) + keyPath;
            builder = new UriBuilder(endpoint) { Path = path };
        }
        else
        {
            path = endpointPath + (keyPath.Length == 0 ? "/" : keyPath);
            builder = new UriBuilder(endpoint)
            {
                Host = _options.Bucket.Trim() + "." + endpoint.Host,
                Path = path,
            };
        }
        builder.Query = CanonicalQuery(query);
        return (builder.Uri, path.Length == 0 ? "/" : path);
    }

    private static string CanonicalQuery(IReadOnlyDictionary<string, string?>? query) => query is null
        ? string.Empty
        : string.Join('&', query.Select(entry => (Key: AwsEncode(entry.Key),
                Value: entry.Value is null ? string.Empty : AwsEncode(entry.Value)))
            .OrderBy(entry => entry.Key, StringComparer.Ordinal)
            .ThenBy(entry => entry.Value, StringComparer.Ordinal)
            .Select(entry => $"{entry.Key}={entry.Value}"));

    private static string EncodePath(string value) => string.Join('/',
        value.Split('/').Select(AwsEncode));

    private static string AwsEncode(string value) => Uri.EscapeDataString(value)
        .Replace("%7E", "~", StringComparison.OrdinalIgnoreCase);

    private static byte[] Hmac(byte[] key, string value) =>
        HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value));

    private static string NormalizeHeader(string value) =>
        string.Join(' ', value.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    private static async Task EnsureSuccessAsync(HttpResponseMessage response, string operation,
        CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }
        var detail = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (detail.Length > 1024)
        {
            detail = detail[..1024];
        }
        throw new InvalidOperationException(
            $"failed to {operation}: HTTP {(int)response.StatusCode} {detail}".TrimEnd());
    }

    private void ValidateObjectKey(string objectKey)
    {
        if (string.IsNullOrWhiteSpace(objectKey) || objectKey.StartsWith('/')
            || objectKey.Contains('\\') || objectKey.Contains("..", StringComparison.Ordinal)
            || objectKey.Contains("//", StringComparison.Ordinal) || objectKey.Any(ch => ch < 32))
        {
            throw new ArgumentException("media object key is invalid", nameof(objectKey));
        }
        var prefix = (_options.ObjectPrefix ?? string.Empty).Trim().Trim('/');
        if (prefix.Length > 0 && !objectKey.StartsWith(prefix + "/", StringComparison.Ordinal))
        {
            throw new ArgumentException("media object key is outside the configured prefix", nameof(objectKey));
        }
    }

    private void EnsureReady()
    {
        if (!Ready)
        {
            throw new InvalidOperationException("HTTP media capture storage is disabled or unavailable");
        }
    }

    private sealed class ResponseBoundStream(Stream inner, HttpResponseMessage response) : Stream
    {
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override ValueTask<int> ReadAsync(Memory<byte> buffer,
            CancellationToken cancellationToken = default) => inner.ReadAsync(buffer, cancellationToken);
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
                response.Dispose();
            }
            base.Dispose(disposing);
        }
        public override async ValueTask DisposeAsync()
        {
            await inner.DisposeAsync().ConfigureAwait(false);
            response.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}

public sealed class HttpMediaStorageInitializer(IHttpMediaStorage storage) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken) => storage.InitializeAsync(cancellationToken);
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
