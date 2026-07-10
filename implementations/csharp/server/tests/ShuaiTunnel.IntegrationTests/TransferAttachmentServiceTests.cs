using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Management;

namespace ShuaiTunnel.IntegrationTests;

public sealed class TransferAttachmentServiceTests
{
    [Fact]
    public void PublicPresignLimiterPurgesExpiredIpWindowsEveryTenMinutes()
    {
        var limiter = new PublicTransferRateLimiter(Options.Create(new PublicTransferOptions
        {
            PresignRateLimitPerIp = 2,
            PresignRateLimitWindowSeconds = 1,
        }));

        limiter.CheckPresignUpload("203.0.113.10");
        Assert.Equal(1, limiter.TrackedSourceCount);
        limiter.PurgeExpired(DateTimeOffset.UtcNow.AddSeconds(2));

        Assert.Equal(0, limiter.TrackedSourceCount);
        Assert.Equal(TimeSpan.FromMinutes(10), PublicTransferRateLimiterCleanupService.CleanupInterval);
    }

    [Fact]
    public async Task PublicAttachmentRequiresRoomTokenAndUsesActualUploadedSize()
    {
        await using var fixture = await AttachmentFixture.CreateAsync(maxBytes: 1024);
        var upload = await fixture.Service.CreatePublicUploadAsync(new PresignUploadRequest(
            "../photo.png", "image/png", 10, new string('a', 64), "room-a", "secret", null),
            CancellationToken.None);
        Assert.Equal("photo.png", upload.Attachment.FileName);
        Assert.Equal(TransferAttachmentService.StatusPending, upload.Attachment.Status);

        await Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.CompletePublicAsync(
            upload.AttachmentId, new CompleteAttachmentRequest("wrong"), CancellationToken.None));

        fixture.Storage.Stat = new ObjectStat(true, 42);
        var completed = await fixture.Service.CompletePublicAsync(upload.AttachmentId,
            new CompleteAttachmentRequest("secret"), CancellationToken.None);
        Assert.Equal(42, completed.SizeBytes);
        Assert.Equal(TransferAttachmentService.StatusUploaded, completed.Status);

        var download = await fixture.Service.CreatePublicDownloadAsync(upload.AttachmentId,
            new PresignDownloadRequest("secret"), CancellationToken.None);
        Assert.Equal("https://storage.test/download", download.DownloadUrl);
    }

    [Fact]
    public async Task CompleteDeletesObjectWhenActualSizeExceedsLimit()
    {
        await using var fixture = await AttachmentFixture.CreateAsync(maxBytes: 100);
        var upload = await fixture.Service.CreatePublicUploadAsync(new PresignUploadRequest(
            "big.bin", null, 10, null, "room", "secret", null), CancellationToken.None);
        fixture.Storage.Stat = new ObjectStat(true, 101);

        await Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.CompletePublicAsync(
            upload.AttachmentId, new CompleteAttachmentRequest("secret"), CancellationToken.None));
        Assert.Equal(upload.ObjectKey, Assert.Single(fixture.Storage.DeletedKeys));
    }

    [Fact]
    public async Task FileNameUsesJavaAsciiAlnumSanitization()
    {
        await using var fixture = await AttachmentFixture.CreateAsync(maxBytes: 100);

        var upload = await fixture.Service.CreatePublicUploadAsync(new PresignUploadRequest(
            "中文图.png", "image/png", 10, null, "room", "secret", null), CancellationToken.None);

        Assert.Equal("_.png", upload.Attachment.FileName);
        Assert.EndsWith("/_.png", upload.ObjectKey, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("mixed/path\\photo😀  中文.png", "photo_.png")]
    [InlineData("😀😀.txt", "_.txt")]
    [InlineData("folder/", "attachment")]
    [InlineData("folder\\", "attachment")]
    [InlineData("folder/...", "attachment")]
    [InlineData("archive..tar...gz", "archive.tar.gz")]
    [InlineData(".env", ".env")]
    [InlineData("file.", "file.")]
    [InlineData("   ", "_")]
    [InlineData("  photo .png  ", "_photo_.png_")]
    public async Task FileNameNormalizationMatchesProtocol(string input, string expected)
    {
        await using var fixture = await AttachmentFixture.CreateAsync(maxBytes: 100);

        var upload = await fixture.Service.CreatePublicUploadAsync(new PresignUploadRequest(
            input, null, 10, null, "room", "secret", null), CancellationToken.None);

        Assert.Equal(expected, upload.Attachment.FileName);
        Assert.EndsWith('/' + expected, upload.ObjectKey, StringComparison.Ordinal);
        Assert.DoesNotContain("..", upload.ObjectKey, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FileNameTruncationPreservesOnlyAnExtensionThatFits()
    {
        await using var fixture = await AttachmentFixture.CreateAsync(maxBytes: 100);
        var shortExtension = "." + new string('b', 178);
        var cases = new Dictionary<string, string>
        {
            [new string('a', 200) + ".txt"] = new string('a', 176) + ".txt",
            ["abcdefghij" + shortExtension] = "a" + shortExtension,
            ["a." + new string('b', 180)] = "a." + new string('b', 178),
            [new string('x', 181)] = new string('x', 180),
        };

        foreach (var (input, expected) in cases)
        {
            var upload = await fixture.Service.CreatePublicUploadAsync(new PresignUploadRequest(
                input, null, 10, null, "room", "secret", null), CancellationToken.None);
            Assert.Equal(expected, upload.Attachment.FileName);
            Assert.Equal(180, upload.Attachment.FileName.Length);
        }
    }

    [Fact]
    public async Task ZeroPresignTtlIsPassedThroughLikeJava()
    {
        await using (var uploadFixture = await AttachmentFixture.CreateAsync(
                         maxBytes: 100, uploadTtlSeconds: 0))
        {
            _ = await uploadFixture.Service.CreatePublicUploadAsync(new PresignUploadRequest(
                "zero-upload.bin", null, 10, null, "room", "secret", null), CancellationToken.None);
            Assert.Equal(TimeSpan.Zero, uploadFixture.Storage.LastUploadTtl);
        }

        await using var downloadFixture = await AttachmentFixture.CreateAsync(
            maxBytes: 100, downloadTtlSeconds: 0);
        var upload = await downloadFixture.Service.CreatePublicUploadAsync(new PresignUploadRequest(
            "zero-download.bin", null, 10, null, "room", "secret", null), CancellationToken.None);
        _ = await downloadFixture.Service.CompletePublicAsync(upload.AttachmentId,
            new CompleteAttachmentRequest("secret"), CancellationToken.None);
        _ = await downloadFixture.Service.CreatePublicDownloadAsync(upload.AttachmentId,
            new PresignDownloadRequest("secret"), CancellationToken.None);
        Assert.Equal(TimeSpan.Zero, downloadFixture.Storage.LastDownloadTtl);
    }

    private sealed class AttachmentFixture : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;

        private AttachmentFixture(SqliteConnection connection, TunnelDbContext db,
            FakeObjectStorage storage, TransferAttachmentService service)
        {
            _connection = connection;
            Db = db;
            Storage = storage;
            Service = service;
        }

        public TunnelDbContext Db { get; }
        public FakeObjectStorage Storage { get; }
        public TransferAttachmentService Service { get; }

        public static async Task<AttachmentFixture> CreateAsync(long maxBytes,
            long uploadTtlSeconds = 900, long downloadTtlSeconds = 600)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new TunnelDbContext(new DbContextOptionsBuilder<TunnelDbContext>()
                .UseSqlite(connection)
                .Options);
            await db.Database.EnsureCreatedAsync();
            var storage = new FakeObjectStorage();
            var objectOptions = Options.Create(new ObjectStorageOptions
            {
                Provider = "aliyun-oss",
                Endpoint = "storage.test",
                Bucket = "bucket",
                AccessKeyId = "key",
                AccessKeySecret = "secret",
                MaxAttachmentBytes = maxBytes,
                UploadUrlTtlSeconds = uploadTtlSeconds,
                DownloadUrlTtlSeconds = downloadTtlSeconds,
            });
            var service = new TransferAttachmentService(db, storage, objectOptions,
                Options.Create(new PublicTransferOptions()));
            return new AttachmentFixture(connection, db, storage, service);
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await _connection.DisposeAsync();
        }
    }

    private sealed class FakeObjectStorage : IObjectStorageService
    {
        public bool Enabled => true;
        public ObjectStat Stat { get; set; } = new(true, 10);
        public List<string> DeletedKeys { get; } = [];
        public TimeSpan? LastUploadTtl { get; private set; }
        public TimeSpan? LastDownloadTtl { get; private set; }

        public void ValidateObjectKey(string objectKey)
        {
            Assert.DoesNotContain("..", objectKey, StringComparison.Ordinal);
        }

        public PresignedObjectUrl PresignUpload(string objectKey, string contentType, TimeSpan ttl)
        {
            LastUploadTtl = ttl;
            return new("https://storage.test/upload", new Dictionary<string, string>
            {
                ["Content-Type"] = contentType,
            }, DateTimeOffset.UtcNow.Add(ttl).ToString("O"));
        }

        public PresignedObjectUrl PresignDownload(string objectKey, TimeSpan ttl)
        {
            LastDownloadTtl = ttl;
            return new("https://storage.test/download", new Dictionary<string, string>(),
                DateTimeOffset.UtcNow.Add(ttl).ToString("O"));
        }

        public Task<ObjectStat> StatAsync(string objectKey, CancellationToken cancellationToken) =>
            Task.FromResult(Stat);

        public Task DeleteAsync(string objectKey, CancellationToken cancellationToken)
        {
            DeletedKeys.Add(objectKey);
            return Task.CompletedTask;
        }
    }
}
