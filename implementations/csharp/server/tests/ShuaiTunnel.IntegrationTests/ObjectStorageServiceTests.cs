using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Management;

namespace ShuaiTunnel.IntegrationTests;

public sealed class ObjectStorageServiceTests
{
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

    private static Task<TestServerFixture> StartEndpointFixtureAsync(EndpointStorage storage,
        long maxAttachmentBytes) => TestServerFixture.StartAsync(
        new Dictionary<string, string?>
        {
            ["Tunnel:ObjectStorage:MaxAttachmentBytes"] = maxAttachmentBytes.ToString(),
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
            Bucket = "bucket",
            AccessKeyId = "access-key",
            AccessKeySecret = "access-secret",
            ObjectPrefix = "attachments",
        }),
        new SingleClientFactory(client));

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
