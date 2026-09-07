using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Text;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Security;

namespace Specus.IntegrationTests;

public sealed class TransferAttachmentServiceTests
{
    private static readonly ManagementContext Account = new("default", "alice", ManagementRole.User, false);

    [Fact]
    public async Task CapabilitiesAreReadOnlyAndIsolateAccountAndExpiry()
    {
        await using var fixture = await AttachmentFixture.CreateAsync(maxBytes: 100, storageQuotaBytes: 20, monthlyDownloadQuotaBytes: 10);
        var now = DateTimeOffset.UtcNow;
        var rows = new[] {
            ("default", "alice", "PENDING", 10L, false), ("default", "alice", "UPLOADED", 20L, false),
            ("default", "alice", "PENDING", 100L, true), ("default", "alice", "UPLOADED", 100L, true),
            ("other", "alice", "PENDING", 100L, false), ("default", "bob", "UPLOADED", 100L, false),
        };
        for (var i = 0; i < rows.Length; i++)
        {
            var (tenant, user, status, size, expired) = rows[i];
            fixture.Db.TransferAttachments.Add(new TransferAttachment { Id = i + 1, TenantId = tenant, OwnerUsername = user,
                Scope = TransferAttachmentService.ScopeAdminClientMessage, ObjectKey = $"test-{i}", FileName = "test.bin",
                Status = status, SizeBytes = size, CreatedAt = now, UpdatedAt = now,
                UploadExpiresAt = now.AddHours(expired ? -1 : 1), ExpiresAt = now.AddHours(expired ? -1 : 1) });
        }
        var usageRows = new[] { ("default", "alice", now, 14L), ("other", "alice", now, 100L),
            ("default", "bob", now, 100L), ("default", "alice", now.AddMonths(-1), 100L) };
        for (var i = 0; i < usageRows.Length; i++)
        {
            var (tenant, user, at, size) = usageRows[i];
            fixture.Db.TransferAttachmentDownloadUsages.Add(new TransferAttachmentDownloadUsage { Id = i + 1, TenantId = tenant,
                Username = user, SizeBytes = size, AttachmentId = 1, CreatedAt = at, UsageMonth = at.ToString("yyyy-MM", System.Globalization.CultureInfo.InvariantCulture) });
        }
        await fixture.Db.SaveChangesAsync();
        for (var i = 0; i < 2; i++)
        {
            var v = await fixture.Service.CapabilitiesAsync(Account, CancellationToken.None);
            Assert.True(v.StorageEnabled); Assert.Equal(30, v.StorageUsedBytes); Assert.Equal(0, v.StorageRemainingBytes);
            Assert.Equal(14, v.MonthlyDownloadUsedBytes); Assert.Equal(0, v.MonthlyDownloadRemainingBytes);
            Assert.Equal(100, v.MaxAttachmentBytes); Assert.True(v.DownloadGrantSingleUse);
            Assert.Equal(v.CheckedAt.ToString("yyyy-MM", System.Globalization.CultureInfo.InvariantCulture), v.DownloadUsageMonth);
            Assert.Equal(new DateTimeOffset(v.CheckedAt.Year, v.CheckedAt.Month, 1, 0, 0, 0, TimeSpan.Zero).AddMonths(1), v.DownloadResetsAt);
        }
        Assert.Equal(6, await fixture.Db.TransferAttachments.CountAsync());
        Assert.Equal(4, await fixture.Db.TransferAttachmentDownloadUsages.CountAsync());
        Assert.Empty(fixture.Db.TransferAttachmentDownloadGrants);
        Assert.Null(fixture.Storage.LastUploadTtl); Assert.Null(fixture.Storage.LastDownloadTtl);
        Assert.Equal(0, fixture.Storage.StatCalls); Assert.Empty(fixture.Storage.DeletedKeys);
        var other = await fixture.Service.CapabilitiesAsync(new ManagementContext("other", "alice", ManagementRole.User, false), CancellationToken.None);
        Assert.Equal(100, other.StorageUsedBytes);
    }

    [Fact]
    public async Task CapabilitiesUseEnforcementDefaultsAndReportDisabledStorage()
    {
        await using var fixture = await AttachmentFixture.CreateAsync(maxBytes: 0, storageQuotaBytes: 0, monthlyDownloadQuotaBytes: -1);
        fixture.Storage.Enabled = false;
        var v = await fixture.Service.CapabilitiesAsync(Account, CancellationToken.None);
        Assert.False(v.StorageEnabled); Assert.Equal(1024L * 1024 * 1024, v.StorageQuotaBytes);
        Assert.Equal(v.StorageQuotaBytes, v.MonthlyDownloadQuotaBytes); Assert.Equal(0, v.MaxAttachmentBytes);
        Assert.Null(fixture.Storage.LastUploadTtl); Assert.Equal(0, fixture.Storage.StatCalls);
        await fixture.Db.DisposeAsync();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => fixture.Service.CapabilitiesAsync(Account, CancellationToken.None));
    }

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
        var upload = await fixture.Service.CreatePublicUploadAsync(Account, new PresignUploadRequest(
            "../photo.png", "image/png", 10, new string('a', 64), "room-a", "secret", null),
            CancellationToken.None);
        Assert.Equal("photo.png", upload.Attachment.FileName);
        Assert.Equal(TransferAttachmentService.StatusPending, upload.Attachment.Status);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => fixture.Service.CompletePublicAsync(
            Account, upload.AttachmentId, new CompleteAttachmentRequest("wrong"), CancellationToken.None));

        fixture.Storage.Stat = new ObjectStat(true, 42);
        var completed = await fixture.Service.CompletePublicAsync(Account, upload.AttachmentId,
            new CompleteAttachmentRequest("secret"), CancellationToken.None);
        Assert.Equal(42, completed.SizeBytes);
        Assert.Equal(TransferAttachmentService.StatusUploaded, completed.Status);

        var download = await fixture.Service.CreatePublicDownloadAsync(Account, upload.AttachmentId,
            new PresignDownloadRequest("secret"), CancellationToken.None);
        Assert.StartsWith("/api/public/transfer/downloads/", download.DownloadUrl,
            StringComparison.Ordinal);
        var token = download.DownloadUrl["/api/public/transfer/downloads/".Length..];
        Assert.Equal("https://storage.test/download", await fixture.Service
            .ConsumeDownloadGrantAsync(token, CancellationToken.None));
        Assert.Null(await fixture.Service.ConsumeDownloadGrantAsync(token, CancellationToken.None));
    }

    [Fact]
    public async Task PublicAttachmentAcceptsRoomInvitesAndEnforcesViewerReadOnlyRole()
    {
        await using var fixture = await AttachmentFixture.CreateAsync(maxBytes: 1024);
        const string roomId = "shared-room";
        const string ownerToken = "shared-owner-secret";
        var editor = await fixture.Rooms.CreateAccessTokenAsync(new CreateAccessTokenRequest(
            roomId, ownerToken, "owner-peer", "EDITOR", "Editor", null),
            CancellationToken.None);
        var viewer = await fixture.Rooms.CreateAccessTokenAsync(new CreateAccessTokenRequest(
            roomId, ownerToken, "owner-peer", "VIEWER", "Viewer", null),
            CancellationToken.None);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            fixture.Service.CreatePublicUploadAsync(Account, new PresignUploadRequest(
                "viewer.bin", null, 10, null, roomId, viewer.Token, null),
                CancellationToken.None));

        var upload = await fixture.Service.CreatePublicUploadAsync(Account,
            new PresignUploadRequest("editor.bin", null, 10, null, roomId, editor.Token, null),
            CancellationToken.None);
        var stored = await fixture.Db.TransferAttachments.AsNoTracking()
            .SingleAsync(row => row.Id == upload.AttachmentId);
        Assert.NotNull(stored.PublicTransferRoomId);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            fixture.Service.CompletePublicAsync(Account, upload.AttachmentId,
                new CompleteAttachmentRequest(viewer.Token), CancellationToken.None));
        fixture.Storage.Stat = new ObjectStat(true, 10);
        _ = await fixture.Service.CompletePublicAsync(Account, upload.AttachmentId,
            new CompleteAttachmentRequest(editor.Token), CancellationToken.None);

        var download = await fixture.Service.CreatePublicDownloadAsync(Account,
            upload.AttachmentId, new PresignDownloadRequest(viewer.Token), CancellationToken.None);
        Assert.StartsWith("/api/public/transfer/downloads/", download.DownloadUrl,
            StringComparison.Ordinal);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            fixture.Service.CreatePublicDownloadAsync(Account, upload.AttachmentId,
                new PresignDownloadRequest("different-owner-token"), CancellationToken.None));
    }

    [Fact]
    public async Task CompleteDeletesObjectWhenActualSizeExceedsLimit()
    {
        await using var fixture = await AttachmentFixture.CreateAsync(maxBytes: 100);
        var upload = await fixture.Service.CreatePublicUploadAsync(Account, new PresignUploadRequest(
            "big.bin", null, 10, null, "room", "secret", null), CancellationToken.None);
        fixture.Storage.Stat = new ObjectStat(true, 101);

        await Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.CompletePublicAsync(
            Account, upload.AttachmentId, new CompleteAttachmentRequest("secret"), CancellationToken.None));
        Assert.Equal(upload.ObjectKey, Assert.Single(fixture.Storage.DeletedKeys));
    }

    [Fact]
    public async Task StorageQuotaIsScopedToAuthenticatedAccount()
    {
        await using var fixture = await AttachmentFixture.CreateAsync(maxBytes: 100,
            storageQuotaBytes: 10);
        _ = await fixture.Service.CreatePublicUploadAsync(Account, new PresignUploadRequest(
            "first.bin", null, 5, null, "room", "secret", null), CancellationToken.None);

        var error = await Assert.ThrowsAsync<RateLimitedException>(() =>
            fixture.Service.CreatePublicUploadAsync(Account, new PresignUploadRequest(
                "second.bin", null, 6, null, "room", "secret", null), CancellationToken.None));
        Assert.Contains("存储额度不足", error.Message, StringComparison.Ordinal);

        var bob = Account with { Username = "bob" };
        _ = await fixture.Service.CreatePublicUploadAsync(bob, new PresignUploadRequest(
            "second.bin", null, 6, null, "other-room", "other-secret", null), CancellationToken.None);
    }

    [Fact]
    public async Task DownloadQuotaIsChargedWhenOneTimeLinkIsConsumed()
    {
        await using var fixture = await AttachmentFixture.CreateAsync(maxBytes: 100,
            storageQuotaBytes: 100, monthlyDownloadQuotaBytes: 10);
        var upload = await fixture.Service.CreatePublicUploadAsync(Account, new PresignUploadRequest(
            "file.bin", null, 6, null, "room", "secret", null), CancellationToken.None);
        fixture.Storage.Stat = new ObjectStat(true, 6);
        _ = await fixture.Service.CompletePublicAsync(Account, upload.AttachmentId,
            new CompleteAttachmentRequest("secret"), CancellationToken.None);
        var firstDownload = await fixture.Service.CreatePublicDownloadAsync(Account, upload.AttachmentId,
            new PresignDownloadRequest("secret"), CancellationToken.None);
        Assert.Empty(fixture.Db.TransferAttachmentDownloadUsages);
        var token = firstDownload.DownloadUrl["/api/public/transfer/downloads/".Length..];
        _ = await fixture.Service.ConsumeDownloadGrantAsync(token, CancellationToken.None);

        var error = await Assert.ThrowsAsync<RateLimitedException>(() =>
            fixture.Service.CreatePublicDownloadAsync(Account, upload.AttachmentId,
                new PresignDownloadRequest("secret"), CancellationToken.None));
        Assert.Contains("下载流量额度不足", error.Message, StringComparison.Ordinal);
        Assert.Single(fixture.Db.TransferAttachmentDownloadUsages);
    }

    [Fact]
    public async Task VerifiedOssCallbackCompletesUploadAndClientCompleteIsIdempotent()
    {
        await using var fixture = await AttachmentFixture.CreateAsync(maxBytes: 100);
        var upload = await fixture.Service.CreatePublicUploadAsync(Account, new PresignUploadRequest(
            "callback.bin", null, 10, null, "room", "secret", null), CancellationToken.None);
        fixture.Storage.CallbackValid = true;
        var body = Encoding.UTF8.GetBytes($$"""
            {"bucket":"bucket","object":"{{upload.ObjectKey}}","size":42,"mimeType":"application/octet-stream","etag":"etag"}
            """);

        var callbackResult = await fixture.Service.CompleteUploadCallbackAsync(
            "/api/public/transfer/oss-callback", body, "signature", "public-key-url",
            CancellationToken.None);
        var clientResult = await fixture.Service.CompletePublicAsync(Account, upload.AttachmentId,
            new CompleteAttachmentRequest("secret"), CancellationToken.None);

        Assert.Equal(TransferAttachmentService.StatusUploaded, callbackResult.Status);
        Assert.Equal(42, callbackResult.SizeBytes);
        Assert.Equal(42, clientResult.SizeBytes);
        Assert.Equal(0, fixture.Storage.StatCalls);
    }

    [Fact]
    public async Task FileNameUsesJavaAsciiAlnumSanitization()
    {
        await using var fixture = await AttachmentFixture.CreateAsync(maxBytes: 100);

        var upload = await fixture.Service.CreatePublicUploadAsync(Account, new PresignUploadRequest(
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

        var upload = await fixture.Service.CreatePublicUploadAsync(Account, new PresignUploadRequest(
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
            var upload = await fixture.Service.CreatePublicUploadAsync(Account, new PresignUploadRequest(
                input, null, 10, null, "room", "secret", null), CancellationToken.None);
            Assert.Equal(expected, upload.Attachment.FileName);
            Assert.Equal(180, upload.Attachment.FileName.Length);
        }
    }

    [Fact]
    public async Task ZeroGrantTtlClampsAndDirectUrlUsesDedicatedTtl()
    {
        await using (var uploadFixture = await AttachmentFixture.CreateAsync(
                         maxBytes: 100, uploadTtlSeconds: 0))
        {
            _ = await uploadFixture.Service.CreatePublicUploadAsync(Account, new PresignUploadRequest(
                "zero-upload.bin", null, 10, null, "room", "secret", null), CancellationToken.None);
            Assert.Equal(TimeSpan.Zero, uploadFixture.Storage.LastUploadTtl);
        }

        await using var downloadFixture = await AttachmentFixture.CreateAsync(
            maxBytes: 100, downloadTtlSeconds: 0);
        var upload = await downloadFixture.Service.CreatePublicUploadAsync(Account, new PresignUploadRequest(
            "zero-download.bin", null, 10, null, "room", "secret", null), CancellationToken.None);
        _ = await downloadFixture.Service.CompletePublicAsync(Account, upload.AttachmentId,
            new CompleteAttachmentRequest("secret"), CancellationToken.None);
        var before = DateTimeOffset.UtcNow;
        var download = await downloadFixture.Service.CreatePublicDownloadAsync(Account, upload.AttachmentId,
            new PresignDownloadRequest("secret"), CancellationToken.None);
        var expiresAt = DateTimeOffset.Parse(download.ExpiresAt);
        Assert.InRange(expiresAt, before, before.AddSeconds(2));
        var token = download.DownloadUrl["/api/public/transfer/downloads/".Length..];
        _ = await downloadFixture.Service.ConsumeDownloadGrantAsync(token, CancellationToken.None);
        Assert.Equal(TimeSpan.FromSeconds(30), downloadFixture.Storage.LastDownloadTtl);
    }

    private sealed class AttachmentFixture : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;

        private AttachmentFixture(SqliteConnection connection, SpecusDbContext db,
            FakeObjectStorage storage, PublicTransferRoomService rooms,
            TransferAttachmentService service)
        {
            _connection = connection;
            Db = db;
            Storage = storage;
            Rooms = rooms;
            Service = service;
        }

        public SpecusDbContext Db { get; }
        public FakeObjectStorage Storage { get; }
        public PublicTransferRoomService Rooms { get; }
        public TransferAttachmentService Service { get; }

        public static async Task<AttachmentFixture> CreateAsync(long maxBytes,
            long uploadTtlSeconds = 900, long downloadTtlSeconds = 600,
            long storageQuotaBytes = 1024L * 1024 * 1024,
            long monthlyDownloadQuotaBytes = 1024L * 1024 * 1024)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new SpecusDbContext(new DbContextOptionsBuilder<SpecusDbContext>()
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
                PerUserStorageQuotaBytes = storageQuotaBytes,
                PerUserMonthlyDownloadQuotaBytes = monthlyDownloadQuotaBytes,
                UploadUrlTtlSeconds = uploadTtlSeconds,
                DownloadUrlTtlSeconds = downloadTtlSeconds,
                DownloadObjectUrlTtlSeconds = 30,
            });
            var publicOptions = Options.Create(new PublicTransferOptions());
            var rooms = new PublicTransferRoomService(db, publicOptions,
                new LocalTokenService(Options.Create(new AuthOptions
                {
                    JwtSecret = "attachment-test-secret",
                })));
            var service = new TransferAttachmentService(db, storage, objectOptions,
                publicOptions, rooms);
            return new AttachmentFixture(connection, db, storage, rooms, service);
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await _connection.DisposeAsync();
        }
    }

    private sealed class FakeObjectStorage : IObjectStorageService
    {
        public bool Enabled { get; set; } = true;
        public ObjectStat Stat { get; set; } = new(true, 10);
        public List<string> DeletedKeys { get; } = [];
        public TimeSpan? LastUploadTtl { get; private set; }
        public TimeSpan? LastDownloadTtl { get; private set; }
        public bool CallbackValid { get; set; }
        public int StatCalls { get; private set; }

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
            Task.FromResult(RecordStatCall());

        public Task<bool> VerifyUploadCallbackAsync(string requestTarget, byte[] body,
            string? authorization, string? publicKeyUrl, CancellationToken cancellationToken) =>
            Task.FromResult(CallbackValid);

        private ObjectStat RecordStatCall()
        {
            StatCalls++;
            return Stat;
        }

        public Task DeleteAsync(string objectKey, CancellationToken cancellationToken)
        {
            DeletedKeys.Add(objectKey);
            return Task.CompletedTask;
        }
    }
}
