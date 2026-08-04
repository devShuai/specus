using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

public sealed class HttpMediaIntegrationTests : IAsyncLifetime
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly FakeMediaStorage _storage = new();
    private readonly MutableTimeProvider _time = new(DateTimeOffset.UtcNow);
    private TestServerFixture? _server;

    public async Task InitializeAsync()
    {
        _server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:MediaCapture:PlaybackTicketTtlSeconds"] = "60",
        }, services =>
        {
            services.RemoveAll<IHttpMediaStorage>();
            services.AddSingleton<IHttpMediaStorage>(_storage);
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(_time);
        });
    }

    public async Task DisposeAsync()
    {
        if (_server is not null)
        {
            await _server.DisposeAsync();
        }
    }

    [Fact]
    public async Task PublicPlaybackTicketSupportsRangeAndGetHeadParity()
    {
        var capture = await SeedCaptureAsync("/movie.mp4", HttpMediaManifestSupport.Progressive,
            Enumerable.Range(0, 10).Select(value => (byte)value).ToArray());
        using var client = await AuthenticatedClientAsync();
        var ticket = await CreateTicketAsync(client, capture.Id);
        client.DefaultRequestHeaders.Authorization = null;

        using var get = new HttpRequestMessage(HttpMethod.Get, ticket.PlayUrl);
        get.Headers.Range = new RangeHeaderValue(2, 5);
        using var getResponse = await client.SendAsync(get);
        Assert.Equal(HttpStatusCode.PartialContent, getResponse.StatusCode);
        Assert.Equal(new byte[] { 2, 3, 4, 5 }, await getResponse.Content.ReadAsByteArrayAsync());
        Assert.Equal("bytes 2-5/10", getResponse.Content.Headers.ContentRange?.ToString());
        Assert.Equal(4, getResponse.Content.Headers.ContentLength);

        using var head = new HttpRequestMessage(HttpMethod.Head, ticket.PlayUrl);
        head.Headers.Range = new RangeHeaderValue(2, 5);
        using var headResponse = await client.SendAsync(head);
        Assert.Equal(HttpStatusCode.PartialContent, headResponse.StatusCode);
        Assert.Empty(await headResponse.Content.ReadAsByteArrayAsync());
        Assert.Equal(4, headResponse.Content.Headers.ContentLength);
        Assert.Equal("bytes 2-5/10", headResponse.Content.Headers.ContentRange?.ToString());
    }

    [Fact]
    public async Task InvalidAndExpiredTicketsReturnBoundedGetAndHeadErrors()
    {
        using var client = _server!.CreateClient();
        using var invalidGet = await client.GetAsync("/api/public/media-playback/invalid/play");
        Assert.Equal(HttpStatusCode.NotFound, invalidGet.StatusCode);
        var invalidBody = await invalidGet.Content.ReadAsByteArrayAsync();
        Assert.NotEmpty(invalidBody);
        Assert.Equal(invalidBody.Length, invalidGet.Content.Headers.ContentLength);

        using var invalidHead = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head,
            "/api/public/media-playback/invalid/play"));
        Assert.Equal(HttpStatusCode.NotFound, invalidHead.StatusCode);
        Assert.Empty(await invalidHead.Content.ReadAsByteArrayAsync());
        Assert.True(invalidHead.Content.Headers.ContentLength > 0);

        var capture = await SeedCaptureAsync("/expires.mp4", HttpMediaManifestSupport.Progressive,
            [1, 2, 3]);
        using var authenticated = await AuthenticatedClientAsync();
        var ticket = await CreateTicketAsync(authenticated, capture.Id);
        _time.Advance(TimeSpan.FromSeconds(61));
        authenticated.DefaultRequestHeaders.Authorization = null;

        using var expired = await authenticated.GetAsync(ticket.PlayUrl);
        Assert.Equal(HttpStatusCode.NotFound, expired.StatusCode);
        Assert.Contains("已过期", await expired.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ManifestAndAssetExposeSameHeadersForGetAndHead()
    {
        var manifest = await SeedCaptureAsync("/live/master.m3u8",
            HttpMediaManifestSupport.HlsManifest,
            Encoding.UTF8.GetBytes("#EXTM3U\n#EXTINF:4,\nseg-1.ts\n#EXT-X-ENDLIST\n"));
        await SeedCaptureAsync("/live/seg-1.ts", HttpMediaManifestSupport.MediaSegment,
            [7, 8, 9]);
        using var client = await AuthenticatedClientAsync();
        var ticket = await CreateTicketAsync(client, manifest.Id);
        client.DefaultRequestHeaders.Authorization = null;

        using var manifestGet = await client.GetAsync(ticket.ManifestUrl);
        manifestGet.EnsureSuccessStatusCode();
        var manifestText = await manifestGet.Content.ReadAsStringAsync();
        Assert.Contains($"/api/public/media-playback/{ticket.Ticket}/asset?url=%2Flive%2Fseg-1.ts",
            manifestText, StringComparison.OrdinalIgnoreCase);
        using var manifestHead = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head,
            ticket.ManifestUrl));
        Assert.Equal(HttpStatusCode.OK, manifestHead.StatusCode);
        Assert.Empty(await manifestHead.Content.ReadAsByteArrayAsync());
        Assert.Equal(manifestGet.Content.Headers.ContentLength,
            manifestHead.Content.Headers.ContentLength);
        Assert.Equal(manifestGet.Content.Headers.ContentType?.MediaType,
            manifestHead.Content.Headers.ContentType?.MediaType);

        var assetUrl = $"/api/public/media-playback/{ticket.Ticket}/asset?url=%2Flive%2Fseg-1.ts";
        using var assetGet = await client.GetAsync(assetUrl);
        Assert.Equal(HttpStatusCode.OK, assetGet.StatusCode);
        Assert.Equal(new byte[] { 7, 8, 9 }, await assetGet.Content.ReadAsByteArrayAsync());
        using var assetHead = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, assetUrl));
        Assert.Equal(HttpStatusCode.OK, assetHead.StatusCode);
        Assert.Empty(await assetHead.Content.ReadAsByteArrayAsync());
        Assert.Equal(3, assetHead.Content.Headers.ContentLength);
    }

    [Fact]
    public async Task AdminManifestMapsMissingTo404AndIncompleteTo409()
    {
        using var client = await AuthenticatedClientAsync();
        using var missing = await client.GetAsync(
            "/api/admin/traffic/media-captures/9223372036854775806/manifest");
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);

        var capture = await SeedCaptureAsync("/pending.m3u8", HttpMediaManifestSupport.HlsManifest,
            Encoding.UTF8.GetBytes("#EXTM3U\n"), HttpMediaCaptureService.StateCapturing);
        using var pending = await client.GetAsync(
            $"/api/admin/traffic/media-captures/{capture.Id}/manifest");
        Assert.Equal(HttpStatusCode.Conflict, pending.StatusCode);
    }

    [Fact]
    public async Task AdminPlaybackTicketForMissingCaptureRemains404()
    {
        using var client = await AuthenticatedClientAsync();

        using var response = await client.PostAsync(
            "/api/admin/traffic/media-captures/9223372036854775806/playback-ticket", null);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.NotEqual("null", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task CaptureCompletionDoesNotWaitForSlowRustFsFinalize()
    {
        await using var scope = _server!.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var account = await db.ClientAccounts.SingleAsync(row =>
            row.ClientName == DatabaseInitializer.DemoClientName);
        var now = DateTimeOffset.UtcNow;
        db.HttpRouteMappings.Add(new HttpRouteMapping
        {
            Id = ClientIdGenerator.NewId(),
            ClientId = account.Id,
            ClientName = account.ClientName,
            Route = "media-finalize",
            TargetBaseUrl = "http://127.0.0.1:1",
            Enabled = true,
            MediaCaptureEnabled = true,
            CreatedAt = now,
            UpdatedAt = now,
        });
        await db.SaveChangesAsync();
        _storage.BlockCompletion();
        var service = scope.ServiceProvider.GetRequiredService<HttpMediaCaptureService>();
        var session = await service.OpenAsync(account.ClientName, "media-finalize", "GET",
            "/slow.mp4", 200, ["Content-Type:video/mp4", "Content-Length:3"],
            CancellationToken.None);
        await session.AppendAsync(new byte[] { 1, 2, 3 }, CancellationToken.None);

        var elapsed = Stopwatch.StartNew();
        await session.CompleteAsync(CancellationToken.None);
        elapsed.Stop();

        Assert.True(elapsed.Elapsed < TimeSpan.FromSeconds(1), elapsed.Elapsed.ToString());
        await _storage.CompletionStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        _storage.ReleaseCompletion();
        await WaitForCaptureStateAsync(HttpMediaCaptureService.StateComplete);
    }

    private async Task<HttpMediaCapture> SeedCaptureAsync(string sourceUrl, string mediaKind,
        byte[] bytes, string state = HttpMediaCaptureService.StateComplete)
    {
        await using var scope = _server!.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var account = await db.ClientAccounts.AsNoTracking().SingleAsync(row =>
            row.ClientName == DatabaseInitializer.DemoClientName);
        var now = DateTimeOffset.UtcNow;
        var objectKey = "specus/http-media/tests/" + Guid.NewGuid().ToString("N");
        var capture = new HttpMediaCapture
        {
            TenantId = account.TenantId,
            ClientId = account.Id,
            ClientName = account.ClientName,
            Route = "media-test",
            SourceUrl = sourceUrl,
            ResourceKey = Guid.NewGuid().ToString("N"),
            Method = "GET",
            StatusCode = 200,
            ContentType = mediaKind == HttpMediaManifestSupport.HlsManifest
                ? "application/vnd.apple.mpegurl" : "video/mp4",
            MediaKind = mediaKind,
            ContentRangeStart = 0,
            ContentRangeEnd = bytes.Length - 1,
            TotalBytes = bytes.Length,
            CapturedBytes = bytes.Length,
            ObjectKey = objectKey,
            ObjectEtag = "\"test\"",
            State = state,
            CapturedAt = now,
            CompletedAt = state == HttpMediaCaptureService.StateComplete ? now : null,
            ExpiresAt = now.AddHours(1),
        };
        db.HttpMediaCaptures.Add(capture);
        await db.SaveChangesAsync();
        _storage.Objects[objectKey] = bytes;
        return capture;
    }

    private async Task WaitForCaptureStateAsync(string state)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
        while (DateTimeOffset.UtcNow < deadline)
        {
            await using var scope = _server!.HostServices.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            if (await db.HttpMediaCaptures.AsNoTracking().AnyAsync(row => row.State == state
                                                                         && row.Route == "media-finalize"))
            {
                return;
            }
            await Task.Delay(20);
        }
        throw new TimeoutException("media capture did not complete");
    }

    private async Task<HttpClient> AuthenticatedClientAsync()
    {
        var client = _server!.CreateClient();
        var response = await client.PostAsJsonAsync("/auth/login", new
        {
            username = "admin",
            password = "admin",
        });
        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<TokenBody>(JsonOptions);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            token!.AccessToken);
        return client;
    }

    private static async Task<HttpMediaPlaybackTicketView> CreateTicketAsync(HttpClient client,
        long captureId)
    {
        using var response = await client.PostAsync(
            $"/api/admin/traffic/media-captures/{captureId}/playback-ticket", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<HttpMediaPlaybackTicketView>(JsonOptions))!;
    }

    private sealed record TokenBody(string AccessToken);

    private sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private long _utcTicks = now.UtcTicks;
        public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref _utcTicks), TimeSpan.Zero);
        public void Advance(TimeSpan value) => Interlocked.Add(ref _utcTicks, value.Ticks);
    }

    private sealed class FakeMediaStorage : IHttpMediaStorage
    {
        private readonly ConcurrentDictionary<string, SortedDictionary<int, byte[]>> _parts = new();
        private TaskCompletionSource _completionGate = CompletedGate();
        public TaskCompletionSource CompletionStarted { get; private set; } = NewGate();
        public ConcurrentDictionary<string, byte[]> Objects { get; } = new();
        public bool Ready { get; private set; } = true;

        public Task InitializeAsync(CancellationToken cancellationToken)
        {
            Ready = true;
            return Task.CompletedTask;
        }

        public Task<MediaMultipartUpload> BeginMultipartAsync(string objectKey, string? contentType,
            string? contentEncoding, CancellationToken cancellationToken)
        {
            var id = Guid.NewGuid().ToString("N");
            _parts[id] = new SortedDictionary<int, byte[]>();
            return Task.FromResult(new MediaMultipartUpload(objectKey, id));
        }

        public Task<MediaCompletedPart> UploadPartAsync(MediaMultipartUpload upload, int partNumber,
            ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken)
        {
            lock (_parts[upload.UploadId])
            {
                _parts[upload.UploadId][partNumber] = bytes.ToArray();
            }
            return Task.FromResult(new MediaCompletedPart(partNumber, $"\"part-{partNumber}\""));
        }

        public async Task<string> CompleteMultipartAsync(MediaMultipartUpload upload,
            IReadOnlyList<MediaCompletedPart> parts, CancellationToken cancellationToken)
        {
            CompletionStarted.TrySetResult();
            await _completionGate.Task.WaitAsync(cancellationToken);
            byte[] bytes;
            lock (_parts[upload.UploadId])
            {
                bytes = _parts[upload.UploadId].OrderBy(entry => entry.Key)
                    .SelectMany(entry => entry.Value).ToArray();
            }
            Objects[upload.ObjectKey] = bytes;
            return "\"complete\"";
        }

        public Task AbortMultipartAsync(MediaMultipartUpload upload,
            CancellationToken cancellationToken)
        {
            _parts.TryRemove(upload.UploadId, out _);
            return Task.CompletedTask;
        }

        public Task<Stream> OpenReadAsync(string objectKey, long? start, long? end,
            CancellationToken cancellationToken)
        {
            var bytes = Objects[objectKey];
            var offset = checked((int)(start ?? 0));
            var length = checked((int)((end ?? bytes.Length - 1) - offset + 1));
            return Task.FromResult<Stream>(new MemoryStream(bytes, offset, length,
                writable: false, publiclyVisible: false));
        }

        public Task<byte[]> ReadAllAsync(string objectKey, long maxBytes,
            CancellationToken cancellationToken)
        {
            var bytes = Objects[objectKey];
            if (bytes.Length > maxBytes)
            {
                throw new InvalidOperationException("too large");
            }
            return Task.FromResult(bytes);
        }

        public Task DeleteAsync(string objectKey, CancellationToken cancellationToken)
        {
            Objects.TryRemove(objectKey, out _);
            return Task.CompletedTask;
        }

        public void BlockCompletion()
        {
            CompletionStarted = NewGate();
            _completionGate = NewGate();
        }

        public void ReleaseCompletion() => _completionGate.TrySetResult();

        private static TaskCompletionSource NewGate() =>
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        private static TaskCompletionSource CompletedGate()
        {
            var gate = NewGate();
            gate.SetResult();
            return gate;
        }
    }
}
