using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Security;

namespace Specus.IntegrationTests;

// SQL is real (SQLite or a required native provider). Only external object storage
// is recorded locally: this verifies orchestration, not an actual cloud deletion.
internal static class TransferAttachmentExpiryProof
{
    internal static async Task VerifyBatchAsync(SpecusDbContext db, bool storageEnabled)
    {
        // In native WebApplicationFactory hosts this also fences the periodic GC
        // from racing the intentionally expired seed rows. No network I/O occurs.
        await using var transaction = await db.Database.BeginTransactionAsync();
        var storage = new RecordedStorage { Enabled = storageEnabled };
        var service = Service(db, storage);
        var now = DateTimeOffset.UtcNow;
        for (var i = 1; i <= 205; i++)
        {
            var row = Attachment(i, now, expired: true);
            row.TenantId = i % 2 == 0 ? "default" : "expiry-other-tenant";
            row.Status = i % 2 == 0 ? TransferAttachmentService.StatusPending : TransferAttachmentService.StatusUploaded;
            // Persist offsets too: SQL comparison must follow UTC instants.
            row.ExpiresAt = row.ExpiresAt.ToOffset(TimeSpan.FromHours(i % 2 == 0 ? 8 : -7));
            db.TransferAttachments.Add(row);
        }
        var live = Attachment(301, now, expired: false);
        var already = Attachment(302, now, expired: true); already.Status = TransferAttachmentService.StatusExpired;
        db.TransferAttachments.AddRange(live, already);
        db.TransferAttachmentDownloadGrants.AddRange(
            Grant(401, 1, now, expired: true), Grant(402, 2, now, expired: true, consumed: true),
            Grant(403, 301, now, expired: false), Grant(404, 301, now, expired: false, consumed: true));
        db.TransferAttachmentDownloadUsages.Add(new TransferAttachmentDownloadUsage { Id = 501, TenantId = "default",
            Username = "expiry-fixture", AttachmentId = 1, CreatedAt = now.AddDays(-30), UsageMonth = "2026-01", SizeBytes = 17 });
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
        var liveBefore = await db.TransferAttachments.AsNoTracking().SingleAsync(a => a.Id == 301);
        var alreadyBefore = await db.TransferAttachments.AsNoTracking().SingleAsync(a => a.Id == 302);
        var grantsBefore = await db.TransferAttachmentDownloadGrants.AsNoTracking().Where(g => g.Id >= 403).OrderBy(g => g.Id).ToListAsync();

        await service.ExpireOldAsync(CancellationToken.None);
        db.ChangeTracker.Clear();
        Assert.Equal(207, await db.TransferAttachments.CountAsync());
        Assert.Equal(206, await db.TransferAttachments.CountAsync(a => a.Status == TransferAttachmentService.StatusExpired));
        Assert.Equal(storageEnabled ? 205 : 0, storage.DeletedKeys.Count);
        Assert.Equal(storage.DeletedKeys.Count, storage.DeletedKeys.Distinct().Count());
        Assert.DoesNotContain("expiry-proof-301", storage.DeletedKeys);
        Assert.DoesNotContain("expiry-proof-302", storage.DeletedKeys);
        var expired = await db.TransferAttachments.AsNoTracking().Where(a => a.Id <= 205).ToListAsync();
        Assert.All(expired, a => Assert.True(a.UpdatedAt >= now));
        Assert.Equal(Json(liveBefore), Json(await db.TransferAttachments.AsNoTracking().SingleAsync(a => a.Id == 301)));
        Assert.Equal(Json(alreadyBefore), Json(await db.TransferAttachments.AsNoTracking().SingleAsync(a => a.Id == 302)));
        Assert.Equal(Json(grantsBefore), Json(await db.TransferAttachmentDownloadGrants.AsNoTracking().OrderBy(g => g.Id).ToListAsync()));
        Assert.Equal(17, (await db.TransferAttachmentDownloadUsages.AsNoTracking().SingleAsync()).SizeBytes);
        var after = Json(await db.TransferAttachments.AsNoTracking().OrderBy(a => a.Id).ToListAsync());
        await service.ExpireOldAsync(CancellationToken.None);
        db.ChangeTracker.Clear();
        Assert.Equal(after, Json(await db.TransferAttachments.AsNoTracking().OrderBy(a => a.Id).ToListAsync()));
        Assert.Equal(storageEnabled ? 205 : 0, storage.DeletedKeys.Count);
        await transaction.CommitAsync();
    }

    internal static async Task VerifyDeleteFailureAsync(SpecusDbContext db)
    {
        var now = DateTimeOffset.UtcNow;
        db.TransferAttachments.Add(Attachment(601, now, expired: true));
        await db.SaveChangesAsync(); db.ChangeTracker.Clear();
        var before = Json(await db.TransferAttachments.AsNoTracking().SingleAsync());
        var storage = new RecordedStorage { FailNextDelete = true };
        var service = Service(db, storage);
        var error = await Assert.ThrowsAsync<IOException>(() => service.ExpireOldAsync(CancellationToken.None));
        Assert.Equal("deliberate expiry storage failure", error.Message);
        db.ChangeTracker.Clear();
        Assert.Equal(before, Json(await db.TransferAttachments.AsNoTracking().SingleAsync()));
        Assert.Empty(storage.DeletedKeys);
        await service.ExpireOldAsync(CancellationToken.None);
        db.ChangeTracker.Clear();
        Assert.Equal(TransferAttachmentService.StatusExpired, (await db.TransferAttachments.AsNoTracking().SingleAsync()).Status);
        Assert.Equal(new[] { "expiry-proof-601" }, storage.DeletedKeys);
        Assert.Equal(2, storage.DeleteAttempts);
    }

    private static TransferAttachment Attachment(long id, DateTimeOffset now, bool expired) => new()
    {
        Id = id, TenantId = "default", OwnerUsername = "expiry-fixture", Scope = TransferAttachmentService.ScopeAdminClientMessage,
        ObjectKey = "expiry-proof-" + id, FileName = "fixture.bin", MimeType = "application/octet-stream", SizeBytes = 17,
        Status = TransferAttachmentService.StatusUploaded, CreatedAt = now.AddDays(-2), UpdatedAt = now.AddDays(-2),
        UploadExpiresAt = now.AddDays(-1), ExpiresAt = now.AddHours(expired ? -1 : 1),
    };
    private static TransferAttachmentDownloadGrant Grant(long id, long attachment, DateTimeOffset now, bool expired, bool consumed = false) => new()
    {
        Id = id, AttachmentId = attachment, TenantId = "default", Username = "expiry-fixture", TokenHash = "expiry-proof-grant-" + id,
        CreatedAt = now.AddDays(-1), ExpiresAt = now.AddHours(expired ? -1 : 1), ConsumedAt = consumed ? now.AddHours(-2) : null,
    };
    private static string Json<T>(T value) => System.Text.Json.JsonSerializer.Serialize(value);
    private static TransferAttachmentService Service(SpecusDbContext db, IObjectStorageService storage)
    {
        var options = Options.Create(new PublicTransferOptions());
        var rooms = new PublicTransferRoomService(db, options, new LocalTokenService(Options.Create(new AuthOptions
            { JwtSecret = "expiry-fixture-signing-key-not-production" })));
        return new TransferAttachmentService(db, storage, Options.Create(new ObjectStorageOptions()), options, rooms);
    }
    private sealed class RecordedStorage : IObjectStorageService
    {
        public bool Enabled { get; set; } = true;
        internal bool FailNextDelete;
        internal int DeleteAttempts;
        internal List<string> DeletedKeys { get; } = [];
        public void ValidateObjectKey(string key) => throw new NotSupportedException();
        public PresignedObjectUrl PresignUpload(string key, string type, TimeSpan ttl) => throw new NotSupportedException();
        public PresignedObjectUrl PresignDownload(string key, TimeSpan ttl) => throw new NotSupportedException();
        public Task<ObjectStat> StatAsync(string key, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string key, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); DeleteAttempts++;
            if (FailNextDelete) { FailNextDelete = false; throw new IOException("deliberate expiry storage failure"); }
            DeletedKeys.Add(key); return Task.CompletedTask;
        }
    }
}
