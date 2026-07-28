using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

public sealed class ObjectStorageServiceTests
{
    [Fact]
    public void PresignedDownloadUsesV4AndSignsGrantMarker()
    {
        using var client = new HttpClient(new RecordingHandler(
            new HttpResponseMessage(HttpStatusCode.OK)));
        var storage = new AliyunOssObjectStorageService(new ObjectStorageOptions
        {
            Provider = "aliyun-oss",
            Endpoint = "https://oss-cn-hangzhou.aliyuncs.com",
            Bucket = "examplebucket",
            AccessKeyId = "test-access-key",
            AccessKeySecret = "test-secret-key",
            ObjectPrefix = "prefix",
        }, client, new FixedTimeProvider(DateTimeOffset.Parse("2024-12-03T03:44:20Z")));

        var result = storage.PresignDownload("prefix/example.txt", TimeSpan.FromSeconds(600),
            "grant-123");

        Assert.Contains("x-oss-signature-version=OSS4-HMAC-SHA256", result.Url,
            StringComparison.Ordinal);
        Assert.Contains("x-oss-credential=test-access-key%2F20241203%2Fcn-hangzhou%2Foss%2Faliyun_v4_request",
            result.Url, StringComparison.Ordinal);
        Assert.Contains("x-oss-date=20241203T034420Z", result.Url, StringComparison.Ordinal);
        Assert.Contains("x-oss-expires=600", result.Url, StringComparison.Ordinal);
        Assert.Contains("x-st-grant=grant-123", result.Url, StringComparison.Ordinal);
        Assert.Contains("x-oss-signature=c2fae9c2ac1a8e6ec5d0ef73e0ac015f40deaf92c3ec5626139a7cacb71225ac",
            result.Url, StringComparison.Ordinal);
        Assert.DoesNotContain("OSSAccessKeyId=", result.Url, StringComparison.Ordinal);
    }

    [Fact]
    public void PresignedUploadIncludesSignedOssCallbackHeader()
    {
        using var client = new HttpClient(new RecordingHandler(
            new HttpResponseMessage(HttpStatusCode.OK)));
        var storage = new AliyunOssObjectStorageService(new ObjectStorageOptions
        {
            Provider = "aliyun-oss",
            Endpoint = "https://oss-cn-hangzhou.aliyuncs.com",
            Bucket = "examplebucket",
            AccessKeyId = "test-access-key",
            AccessKeySecret = "test-secret-key",
            ObjectPrefix = "prefix",
            UploadCallbackUrl = "https://specus.example/api/public/transfer/oss-callback",
        }, client, TimeProvider.System);

        var result = storage.PresignUpload("prefix/example.txt", "text/plain",
            TimeSpan.FromMinutes(10));

        var encoded = result.Headers["x-oss-callback"];
        using var callback = JsonDocument.Parse(Convert.FromBase64String(encoded));
        Assert.Equal("https://specus.example/api/public/transfer/oss-callback",
            callback.RootElement.GetProperty("callbackUrl").GetString());
        Assert.Equal("application/json",
            callback.RootElement.GetProperty("callbackBodyType").GetString());
        Assert.True(callback.RootElement.GetProperty("callbackSNI").GetBoolean());
        Assert.Contains("${object}", callback.RootElement.GetProperty("callbackBody").GetString(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task OssUploadCallbackVerificationUsesPinnedAliyunPublicKeyHost()
    {
        using var key = RSA.Create(2048);
        var publicKey = key.ExportSubjectPublicKeyInfoPem();
        var handler = new RecordingHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(publicKey, Encoding.ASCII, "application/x-pem-file"),
        });
        using var client = new HttpClient(handler);
        var storage = new AliyunOssObjectStorageService(new ObjectStorageOptions
        {
            Provider = "aliyun-oss",
            Endpoint = "https://oss-cn-hangzhou.aliyuncs.com",
            Bucket = "examplebucket",
            AccessKeyId = "test-access-key",
            AccessKeySecret = "test-secret-key",
            ObjectPrefix = "prefix",
            UploadCallbackUrl = "https://specus.example/api/public/transfer/oss-callback",
        }, client, TimeProvider.System);
        const string target = "/api/public/transfer/oss-callback";
        var body = Encoding.UTF8.GetBytes("{\"bucket\":\"examplebucket\"}");
        var signature = Convert.ToBase64String(key.SignData(
            Encoding.UTF8.GetBytes(target + "\n" + Encoding.UTF8.GetString(body)),
            HashAlgorithmName.MD5, RSASignaturePadding.Pkcs1));
        var publicKeyUrl = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            "http://gosspublic.alicdn.com/callback_pub_key_v1.pem"));

        Assert.True(await storage.VerifyUploadCallbackAsync(target, body, signature, publicKeyUrl,
            CancellationToken.None));
        Assert.False(await storage.VerifyUploadCallbackAsync(target, body, signature + "invalid",
            publicKeyUrl, CancellationToken.None));
        Assert.Equal(1, handler.RequestCount);
    }

    [Fact]
    public void OssHttpClientHandlerDisablesAutomaticRedirects()
    {
        using var handler = Assert.IsType<HttpClientHandler>(
            AliyunOssObjectStorageService.CreateNoRedirectHandler());

        Assert.False(handler.AllowAutoRedirect);
    }

    [Fact]
    public async Task HeadRedirectIsAcceptedAsJavaStatusBelow400WithoutReplay()
    {
        var handler = new RecordingHandler(new HttpResponseMessage(HttpStatusCode.Found)
        {
            Headers = { Location = new Uri("https://redirect-target.example/object") },
            Content = new ByteArrayContent([]),
        });
        handler.Response.Content.Headers.ContentLength = 17;
        using var client = new HttpClient(handler);
        var storage = CreateStorage(client);

        var stat = await storage.StatAsync("attachments/test.bin", CancellationToken.None);

        Assert.True(stat.Exists);
        Assert.Equal(17, stat.ContentLength);
        Assert.Equal(1, handler.RequestCount);
        Assert.Equal(HttpMethod.Head, handler.LastMethod);
    }

    [Fact]
    public async Task DeleteRedirectIsAcceptedAsJavaStatusBelow400WithoutReplay()
    {
        var handler = new RecordingHandler(new HttpResponseMessage(HttpStatusCode.TemporaryRedirect)
        {
            Headers = { Location = new Uri("https://redirect-target.example/object") },
        });
        using var client = new HttpClient(handler);
        var storage = CreateStorage(client);

        await storage.DeleteAsync("attachments/test.bin", CancellationToken.None);

        Assert.Equal(1, handler.RequestCount);
        Assert.Equal(HttpMethod.Delete, handler.LastMethod);
    }

    [Fact]
    public async Task HeadNetworkFailureBecomesConflictClassInvalidOperation()
    {
        using var client = new HttpClient(new ThrowingHandler(
            new HttpRequestException("simulated network failure")));
        var storage = CreateStorage(client);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            storage.StatAsync("attachments/test.bin", CancellationToken.None));

        Assert.Equal("failed to stat object", error.Message);
        Assert.IsAssignableFrom<HttpRequestException>(error.InnerException);
    }

    [Fact]
    public async Task DeleteIoFailureBecomesConflictClassInvalidOperation()
    {
        using var client = new HttpClient(new ThrowingHandler(
            new IOException("simulated IO failure")));
        var storage = CreateStorage(client);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            storage.DeleteAsync("attachments/test.bin", CancellationToken.None));

        Assert.Equal("failed to delete object", error.Message);
        Assert.NotNull(error.InnerException);
    }

    [Fact]
    public async Task HeadFailureDuringPublicCompleteReturns409Conflict()
    {
        var storage = new EndpointStorage
        {
            StatException = new InvalidOperationException("failed to stat object"),
        };
        await using var fixture = await StartEndpointFixtureAsync(storage, maxAttachmentBytes: 100);
        using var client = fixture.CreateClient();
        await AuthenticateAsync(client);
        var attachmentId = await PresignPublicUploadAsync(client);

        using var response = await client.PostAsJsonAsync(
            $"/api/public/transfer/attachments/{attachmentId}/complete",
            new { roomToken = "secret" });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task DeleteFailureDuringOversizeCompleteReturns409Conflict()
    {
        var storage = new EndpointStorage
        {
            Stat = new ObjectStat(true, 101),
            DeleteException = new InvalidOperationException("failed to delete object"),
        };
        await using var fixture = await StartEndpointFixtureAsync(storage, maxAttachmentBytes: 100);
        using var client = fixture.CreateClient();
        await AuthenticateAsync(client);
        var attachmentId = await PresignPublicUploadAsync(client);

        using var response = await client.PostAsJsonAsync(
            $"/api/public/transfer/attachments/{attachmentId}/complete",
            new { roomToken = "secret" });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task UnknownOneTimeDownloadGrantIsAnonymousAndGone()
    {
        var storage = new EndpointStorage();
        await using var fixture = await StartEndpointFixtureAsync(storage, maxAttachmentBytes: 100);
        using var client = fixture.CreateClient();

        using var response = await client.GetAsync(
            "/api/public/transfer/downloads/not-a-real-token");

        Assert.Equal(HttpStatusCode.Gone, response.StatusCode);
    }

    [Fact]
    public async Task OneTimeDownloadGrantRejectsHeadWithoutConsumingIt()
    {
        var storage = new EndpointStorage();
        await using var fixture = await StartEndpointFixtureAsync(storage, maxAttachmentBytes: 100);
        using var client = fixture.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Head,
            "/api/public/transfer/downloads/not-a-real-token");

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        Assert.Contains("GET", response.Content.Headers.Allow);
    }

    [Fact]
    public async Task OssUploadCallbackIsAnonymousButRejectsInvalidSignature()
    {
        var storage = new EndpointStorage();
        await using var fixture = await StartEndpointFixtureAsync(storage, maxAttachmentBytes: 100);
        using var client = fixture.CreateClient();

        using var response = await client.PostAsJsonAsync(
            "/api/public/transfer/oss-callback", new { });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    private static Task<TestServerFixture> StartEndpointFixtureAsync(EndpointStorage storage,
        long maxAttachmentBytes) => TestServerFixture.StartAsync(
        new Dictionary<string, string?>
        {
            ["Specus:ObjectStorage:MaxAttachmentBytes"] = maxAttachmentBytes.ToString(),
        },
        services =>
        {
            services.RemoveAll<IObjectStorageService>();
            services.AddSingleton<IObjectStorageService>(storage);
        });

    private static async Task<long> PresignPublicUploadAsync(HttpClient client)
    {
        using var response = await client.PostAsJsonAsync(
            "/api/public/transfer/attachments/presign-upload",
            new
            {
                fileName = "test.bin",
                mimeType = "application/octet-stream",
                sizeBytes = 1,
                roomId = "room",
                roomToken = "secret",
            });
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("attachmentId").GetInt64();
    }

    private static async Task AuthenticateAsync(HttpClient client)
    {
        using var response = await client.PostAsJsonAsync("/auth/login", new
        {
            username = "admin",
            password = "admin",
        });
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        client.DefaultRequestHeaders.Authorization = new(
            "Bearer", json.RootElement.GetProperty("accessToken").GetString());
    }

    private static AliyunOssObjectStorageService CreateStorage(HttpClient client) => new(
        Options.Create(new ObjectStorageOptions
        {
            Provider = "aliyun-oss",
            Endpoint = "https://oss.example.com",
            Region = "cn-hangzhou",
            Bucket = "bucket",
            AccessKeyId = "access-key",
            AccessKeySecret = "access-secret",
            ObjectPrefix = "attachments",
        }),
        new SingleClientFactory(client));

    private sealed class FixedTimeProvider(DateTimeOffset value) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => value;
    }

    private sealed class SingleClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }

    private sealed class ThrowingHandler(Exception exception) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken) => Task.FromException<HttpResponseMessage>(exception);
    }

    private sealed class RecordingHandler(HttpResponseMessage response) : HttpMessageHandler
    {
        public HttpResponseMessage Response { get; } = response;
        public int RequestCount { get; private set; }
        public HttpMethod? LastMethod { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestCount++;
            LastMethod = request.Method;
            return Task.FromResult(Response);
        }
    }

    private sealed class EndpointStorage : IObjectStorageService
    {
        public bool Enabled => true;
        public ObjectStat Stat { get; set; } = new(true, 1);
        public Exception? StatException { get; set; }
        public Exception? DeleteException { get; set; }

        public void ValidateObjectKey(string objectKey)
        {
        }

        public PresignedObjectUrl PresignUpload(string objectKey, string contentType, TimeSpan ttl) =>
            new("https://storage.example/upload", new Dictionary<string, string>(),
                DateTimeOffset.UtcNow.Add(ttl).ToString("O"));

        public PresignedObjectUrl PresignDownload(string objectKey, TimeSpan ttl) =>
            new("https://storage.example/download", new Dictionary<string, string>(),
                DateTimeOffset.UtcNow.Add(ttl).ToString("O"));

        public Task<ObjectStat> StatAsync(string objectKey, CancellationToken cancellationToken) =>
            StatException is null ? Task.FromResult(Stat) : Task.FromException<ObjectStat>(StatException);

        public Task DeleteAsync(string objectKey, CancellationToken cancellationToken) =>
            DeleteException is null ? Task.CompletedTask : Task.FromException(DeleteException);
    }
}
