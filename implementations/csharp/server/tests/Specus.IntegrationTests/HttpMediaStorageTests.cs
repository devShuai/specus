using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Server.Configuration;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

public sealed class HttpMediaStorageTests
{
    private static readonly DateTimeOffset FixedNow =
        new(2026, 8, 4, 12, 34, 56, TimeSpan.Zero);

    [Fact]
    public async Task IncompleteConfigurationSafelyDisablesWithoutSendingARequest()
    {
        var handler = new RecordingHandler(_ => throw new InvalidOperationException("must not send"));
        var storage = CreateStorage(new MediaCaptureOptions { Enabled = true }, handler);

        await storage.InitializeAsync(CancellationToken.None);

        Assert.False(storage.Ready);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task FullyConfiguredUnavailableBucketFailsStartup()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.Forbidden)
        {
            Content = new StringContent("denied"),
        });
        var storage = CreateStorage(ReadyOptions(), handler);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            storage.InitializeAsync(CancellationToken.None));

        Assert.Contains("initialization failed", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(storage.Ready);
    }

    [Fact]
    public async Task MultipartAndRangeRequestsPreserveCanonicalPathQueryAndEtag()
    {
        var handler = new RecordingHandler(request =>
        {
            if (request.Method == HttpMethod.Head)
            {
                return new HttpResponseMessage(HttpStatusCode.OK);
            }
            if (request.Method == HttpMethod.Post && request.RequestUri!.Query == "?uploads=")
            {
                return Xml(HttpStatusCode.OK,
                    "<InitiateMultipartUploadResult><UploadId>u +/?</UploadId></InitiateMultipartUploadResult>");
            }
            if (request.Method == HttpMethod.Put)
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Headers.ETag = new EntityTagHeaderValue("\"part-etag\"");
                return response;
            }
            if (request.Method == HttpMethod.Post)
            {
                return Xml(HttpStatusCode.OK,
                    "<CompleteMultipartUploadResult><ETag>\"object-etag\"</ETag></CompleteMultipartUploadResult>");
            }
            if (request.Method == HttpMethod.Get)
            {
                var response = new HttpResponseMessage(HttpStatusCode.PartialContent)
                {
                    Content = new ByteArrayContent([2, 3, 4]),
                };
                response.Content.Headers.ContentRange = new ContentRangeHeaderValue(2, 4, 10);
                return response;
            }
            throw new InvalidOperationException("unexpected request");
        });
        var storage = CreateStorage(ReadyOptions(), handler);
        await storage.InitializeAsync(CancellationToken.None);
        const string key = "specus/http-media/a b/中文/%done.mp4";

        var upload = await storage.BeginMultipartAsync(key, "video/mp4", "gzip",
            CancellationToken.None);
        var part = await storage.UploadPartAsync(upload, 1, new byte[] { 1, 2, 3 },
            CancellationToken.None);
        var etag = await storage.CompleteMultipartAsync(upload, [part], CancellationToken.None);
        await using var stream = await storage.OpenReadAsync(key, 2, 4, CancellationToken.None);
        using var output = new MemoryStream();
        await stream.CopyToAsync(output);

        Assert.Equal("u +/?", upload.UploadId);
        Assert.Equal("\"part-etag\"", part.Etag);
        Assert.Equal("\"object-etag\"", etag);
        Assert.Equal(new byte[] { 2, 3, 4 }, output.ToArray());

        var begin = handler.Requests[1];
        Assert.Equal(
            "http://localhost:9000/root/media/specus/http-media/a%20b/%E4%B8%AD%E6%96%87/%25done.mp4?uploads=",
            begin.Uri.AbsoluteUri);
        Assert.Contains("SignedHeaders=content-encoding;content-type;host;x-amz-content-sha256;x-amz-date",
            begin.Authorization, StringComparison.Ordinal);
        Assert.Equal("video/mp4", begin.ContentType);
        Assert.Equal("gzip", begin.ContentEncoding);

        var uploadPart = handler.Requests[2];
        Assert.Equal("?partNumber=1&uploadId=u%20%2B%2F%3F", uploadPart.Uri.Query);
        Assert.Equal(new byte[] { 1, 2, 3 }, uploadPart.Body);
        var read = handler.Requests[4];
        Assert.Equal("bytes=2-4", read.Range);
    }

    [Fact]
    public async Task RangeReadRejectsStorageThatIgnoresRange()
    {
        var handler = new RecordingHandler(request => request.Method == HttpMethod.Head
            ? new HttpResponseMessage(HttpStatusCode.OK)
            : new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(Enumerable.Range(0, 10)
                    .Select(value => (byte)value).ToArray()),
            });
        var storage = CreateStorage(ReadyOptions(), handler);
        await storage.InitializeAsync(CancellationToken.None);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            storage.OpenReadAsync("specus/http-media/file.mp4", 2, 4,
                CancellationToken.None));

        Assert.Contains("ranged media read", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RangeReadRejectsMismatchedContentRange()
    {
        var handler = new RecordingHandler(request =>
        {
            if (request.Method == HttpMethod.Head)
            {
                return new HttpResponseMessage(HttpStatusCode.OK);
            }
            var response = new HttpResponseMessage(HttpStatusCode.PartialContent)
            {
                Content = new ByteArrayContent([3, 4, 5]),
            };
            response.Content.Headers.ContentRange = new ContentRangeHeaderValue(3, 5, 10);
            return response;
        });
        var storage = CreateStorage(ReadyOptions(), handler);
        await storage.InitializeAsync(CancellationToken.None);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            storage.OpenReadAsync("specus/http-media/file.mp4", 2, 4,
                CancellationToken.None));

        Assert.Contains("ranged media read", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CompleteMultipartRejectsHttp200ErrorDocument()
    {
        var storage = CompleteResponseStorage(
            "<Error><Code>InvalidPart</Code><Message>part mismatch</Message></Error>");
        await storage.Storage.InitializeAsync(CancellationToken.None);
        var upload = await storage.Storage.BeginMultipartAsync("specus/http-media/file.mp4",
            "video/mp4", null, CancellationToken.None);
        var part = await storage.Storage.UploadPartAsync(upload, 1, new byte[] { 1 },
            CancellationToken.None);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            storage.Storage.CompleteMultipartAsync(upload, [part], CancellationToken.None));

        Assert.Contains("InvalidPart", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CompleteMultipartRejectsSuccessDocumentWithoutEtag()
    {
        var storage = CompleteResponseStorage("<CompleteMultipartUploadResult />");
        await storage.Storage.InitializeAsync(CancellationToken.None);
        var upload = await storage.Storage.BeginMultipartAsync("specus/http-media/file.mp4",
            "video/mp4", null, CancellationToken.None);
        var part = await storage.Storage.UploadPartAsync(upload, 1, new byte[] { 1 },
            CancellationToken.None);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            storage.Storage.CompleteMultipartAsync(upload, [part], CancellationToken.None));

        Assert.Contains("ETag", error.Message, StringComparison.Ordinal);
    }

    private static (RustFsMediaStorage Storage, RecordingHandler Handler) CompleteResponseStorage(
        string completionXml)
    {
        var handler = new RecordingHandler(request =>
        {
            if (request.Method == HttpMethod.Head)
            {
                return new HttpResponseMessage(HttpStatusCode.OK);
            }
            if (request.Method == HttpMethod.Post && request.RequestUri!.Query == "?uploads=")
            {
                return Xml(HttpStatusCode.OK,
                    "<InitiateMultipartUploadResult><UploadId>upload</UploadId></InitiateMultipartUploadResult>");
            }
            if (request.Method == HttpMethod.Put)
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Headers.ETag = new EntityTagHeaderValue("\"part\"");
                return response;
            }
            return Xml(HttpStatusCode.OK, completionXml);
        });
        return (CreateStorage(ReadyOptions(), handler), handler);
    }

    private static RustFsMediaStorage CreateStorage(MediaCaptureOptions options,
        HttpMessageHandler handler) => new(options, new HttpClient(handler),
        new FixedTimeProvider(FixedNow), NullLogger<RustFsMediaStorage>.Instance);

    private static MediaCaptureOptions ReadyOptions() => new()
    {
        Enabled = true,
        Endpoint = "http://localhost:9000/root",
        Region = "us-east-1",
        Bucket = "media",
        AccessKeyId = "key",
        AccessKeySecret = "secret",
        ObjectPrefix = "specus/http-media",
        PathStyle = true,
    };

    private static HttpResponseMessage Xml(HttpStatusCode status, string xml) => new(status)
    {
        Content = new StringContent(xml, Encoding.UTF8, "application/xml"),
    };

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class RecordingHandler(
        Func<HttpRequestMessage, HttpResponseMessage> responseFactory) : HttpMessageHandler
    {
        public List<RecordedRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var body = request.Content is null
                ? Array.Empty<byte>()
                : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            var authorization = request.Headers.TryGetValues("Authorization", out var values)
                ? values.Single() : string.Empty;
            Requests.Add(new RecordedRequest(request.Method, request.RequestUri!,
                authorization,
                request.Headers.Range?.ToString(), request.Content?.Headers.ContentType?.ToString(),
                request.Content?.Headers.ContentEncoding.FirstOrDefault(), body));
            return responseFactory(request);
        }
    }

    private sealed record RecordedRequest(HttpMethod Method, Uri Uri, string Authorization,
        string? Range, string? ContentType, string? ContentEncoding, byte[] Body);
}
