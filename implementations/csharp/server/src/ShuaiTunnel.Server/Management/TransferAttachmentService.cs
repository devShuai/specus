using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Authentication;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Data.Entities;

namespace ShuaiTunnel.Server.Management;

public sealed class RateLimitedException(string message) : Exception(message);

public sealed class PublicTransferRateLimiter
{
    private const int MaxTrackedSources = 100_000;
    private readonly ConcurrentDictionary<string, Window> _windows = new(StringComparer.Ordinal);
    private readonly PublicTransferOptions _options;

    public PublicTransferRateLimiter(IOptions<PublicTransferOptions> options) => _options = options.Value;

    public void CheckPresignUpload(string? clientIp)
    {
        var key = string.IsNullOrWhiteSpace(clientIp) ? "unknown" : clientIp.Trim();
        var now = DateTimeOffset.UtcNow;
        var duration = TimeSpan.FromSeconds(Math.Max(1L, _options.PresignRateLimitWindowSeconds));
        if (_windows.Count >= MaxTrackedSources && !_windows.ContainsKey(key))
        {
            throw new RateLimitedException("请求过于频繁,请稍后再试");
        }
        var window = _windows.AddOrUpdate(key, _ => new Window(now, 1), (_, current) =>
        {
            lock (current)
            {
                if (now - current.StartedAt >= duration)
                {
                    return new Window(now, 1);
                }
                current.Count++;
                return current;
            }
        });
        if (window.Count > Math.Max(1, _options.PresignRateLimitPerIp))
        {
            throw new RateLimitedException("请求过于频繁,请稍后再试");
        }
    }

    internal int TrackedSourceCount => _windows.Count;

    internal void PurgeExpired(DateTimeOffset? currentTime = null)
    {
        var now = currentTime ?? DateTimeOffset.UtcNow;
        var duration = TimeSpan.FromSeconds(Math.Max(1L, _options.PresignRateLimitWindowSeconds));
        foreach (var entry in _windows)
        {
            if (now - entry.Value.StartedAt >= duration)
            {
                _windows.TryRemove(entry.Key, out _);
            }
        }
    }

    private sealed class Window(DateTimeOffset startedAt, int count)
    {
        public DateTimeOffset StartedAt { get; } = startedAt;
        public int Count { get; set; } = count;
    }
}

public sealed class PublicTransferRateLimiterCleanupService : BackgroundService
{
    internal static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(10);
    private readonly PublicTransferRateLimiter _rateLimiter;

    public PublicTransferRateLimiterCleanupService(PublicTransferRateLimiter rateLimiter)
    {
        _rateLimiter = rateLimiter;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(CleanupInterval, stoppingToken).ConfigureAwait(false);
                _rateLimiter.PurgeExpired();
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal host shutdown.
        }
    }
}

public sealed class TransferAttachmentService
{
    public const string ScopePublicTransfer = "PUBLIC_TRANSFER";
    public const string ScopeAdminClientMessage = "ADMIN_CLIENT_MESSAGE";
    public const string StatusPending = "PENDING";
    public const string StatusUploaded = "UPLOADED";
    public const string StatusExpired = "EXPIRED";
    private const long DefaultPerUserQuotaBytes = 1024L * 1024 * 1024;

    private static readonly Regex Sha256Pattern = new("^[a-fA-F0-9]{64}$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly SemaphoreSlim[] QuotaLocks = Enumerable.Range(0, 64)
        .Select(_ => new SemaphoreSlim(1, 1))
        .ToArray();

    private readonly TunnelDbContext _db;
    private readonly IObjectStorageService _storage;
    private readonly ObjectStorageOptions _options;
    private readonly PublicTransferOptions _publicOptions;

    public TransferAttachmentService(TunnelDbContext db, IObjectStorageService storage,
        IOptions<ObjectStorageOptions> options, IOptions<PublicTransferOptions> publicOptions)
    {
        _db = db;
        _storage = storage;
        _options = options.Value;
        _publicOptions = publicOptions.Value;
    }

    public async Task<PresignUploadResponse> CreatePublicUploadAsync(ManagementContext context,
        PresignUploadRequest request, CancellationToken cancellationToken)
    {
        var roomTokenHash = RoomTokenHash(RequireText(request.RoomToken, "roomToken"));
        var pending = await _db.TransferAttachments.AsNoTracking()
            .CountAsync(attachment => attachment.Scope == ScopePublicTransfer
                && attachment.RoomTokenHash == roomTokenHash
                && attachment.Status == StatusPending, cancellationToken)
            .ConfigureAwait(false);
        if (pending >= Math.Max(1, _publicOptions.MaxPendingUploadsPerRoom))
        {
            throw new RateLimitedException("当前房间待上传文件过多,请稍后再试");
        }
        var quotaLock = QuotaLock(context.TenantId, context.Username);
        await quotaLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await CreateUploadAsync(ScopePublicTransfer, context.TenantId,
                NormalizeRoomId(request.RoomId), roomTokenHash, context.Username, null, request,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            quotaLock.Release();
        }
    }

    public async Task<PresignUploadResponse> CreateAdminUploadAsync(ManagementContext context,
        PresignUploadRequest request, CancellationToken cancellationToken)
    {
        if (request.TargetClientId is not { } targetClientId)
        {
            throw new ArgumentException("targetClientId is required");
        }
        await RequireClientAccessAsync(context, targetClientId, cancellationToken).ConfigureAwait(false);
        var quotaLock = QuotaLock(context.TenantId, context.Username);
        await quotaLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await CreateUploadAsync(ScopeAdminClientMessage, context.TenantId, null, null,
                context.Username, targetClientId, request, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            quotaLock.Release();
        }
    }

    public async Task<TransferAttachmentView> CompletePublicAsync(ManagementContext context,
        long attachmentId, CompleteAttachmentRequest request, CancellationToken cancellationToken)
    {
        var attachment = await FindAsync(attachmentId, ScopePublicTransfer, null, cancellationToken)
            .ConfigureAwait(false);
        RequireMatchingRoomToken(attachment, request.RoomToken);
        if (string.IsNullOrWhiteSpace(attachment.TenantId))
        {
            attachment.TenantId = context.TenantId;
        }
        if (string.IsNullOrWhiteSpace(attachment.OwnerUsername))
        {
            attachment.OwnerUsername = context.Username;
        }
        return await CompleteAsync(attachment, cancellationToken).ConfigureAwait(false);
    }

    public async Task<TransferAttachmentView> CompleteAdminAsync(ManagementContext context,
        long attachmentId, CancellationToken cancellationToken)
    {
        var attachment = await FindAsync(attachmentId, ScopeAdminClientMessage, context.TenantId,
            cancellationToken).ConfigureAwait(false);
        await RequireClientAccessAsync(context, attachment.TargetClientId, cancellationToken)
            .ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(attachment.TenantId))
        {
            attachment.TenantId = context.TenantId;
        }
        if (string.IsNullOrWhiteSpace(attachment.OwnerUsername))
        {
            attachment.OwnerUsername = context.Username;
        }
        return await CompleteAsync(attachment, cancellationToken).ConfigureAwait(false);
    }

    public async Task<PresignDownloadResponse> CreatePublicDownloadAsync(ManagementContext context,
        long attachmentId, PresignDownloadRequest request, CancellationToken cancellationToken)
    {
        var attachment = await FindAsync(attachmentId, ScopePublicTransfer, null, cancellationToken)
            .ConfigureAwait(false);
        RequireMatchingRoomToken(attachment, request.RoomToken);
        return await CreateDownloadAsync(context, attachment, cancellationToken).ConfigureAwait(false);
    }

    public async Task<PresignDownloadResponse> CreateAdminDownloadAsync(ManagementContext context,
        long attachmentId, CancellationToken cancellationToken)
    {
        var attachment = await FindAsync(attachmentId, ScopeAdminClientMessage, context.TenantId,
            cancellationToken).ConfigureAwait(false);
        await RequireClientAccessAsync(context, attachment.TargetClientId, cancellationToken)
            .ConfigureAwait(false);
        return await CreateDownloadAsync(context, attachment, cancellationToken).ConfigureAwait(false);
    }

    public async Task ExpireOldAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var now = DateTimeOffset.UtcNow;
            var expired = await _db.TransferAttachments
                .Where(attachment => attachment.ExpiresAt < now && attachment.Status != StatusExpired)
                .OrderBy(attachment => attachment.ExpiresAt)
                .Take(100)
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false);
            if (expired.Count == 0)
            {
                return;
            }
            foreach (var attachment in expired)
            {
                if (_storage.Enabled)
                {
                    await _storage.DeleteAsync(attachment.ObjectKey, cancellationToken).ConfigureAwait(false);
                }
                attachment.Status = StatusExpired;
                attachment.UpdatedAt = now;
            }
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<PresignUploadResponse> CreateUploadAsync(string scope, string? tenantId,
        string? roomId, string? roomTokenHash, string? ownerUsername, long? targetClientId,
        PresignUploadRequest request, CancellationToken cancellationToken)
    {
        if (!_storage.Enabled)
        {
            throw new InvalidOperationException("object storage is not configured");
        }
        var fileName = NormalizeFileName(request.FileName);
        var mimeType = NormalizeMimeType(request.MimeType);
        var sizeBytes = NormalizeSize(request.SizeBytes);
        await EnsureStorageQuotaAsync(tenantId, ownerUsername, sizeBytes, long.MinValue,
            cancellationToken).ConfigureAwait(false);
        var sha256 = NormalizeSha256(request.Sha256);
        var now = DateTimeOffset.UtcNow;
        var uploadExpiresAt = now.AddSeconds(_options.UploadUrlTtlSeconds);
        var expiresAt = now.AddHours(Math.Max(1L, _options.RetentionHours));
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var id = ClientIdGenerator.NewId();
            if (await _db.TransferAttachments.AsNoTracking().AnyAsync(row => row.Id == id,
                    cancellationToken).ConfigureAwait(false))
            {
                continue;
            }
            var attachment = new TransferAttachment
            {
                Id = id,
                TenantId = tenantId,
                Scope = scope,
                RoomId = roomId,
                RoomTokenHash = roomTokenHash,
                OwnerUsername = ownerUsername,
                TargetClientId = targetClientId,
                FileName = fileName,
                MimeType = mimeType,
                SizeBytes = sizeBytes,
                Sha256 = sha256,
                Status = StatusPending,
                CreatedAt = now,
                UpdatedAt = now,
                UploadExpiresAt = uploadExpiresAt,
                ExpiresAt = expiresAt,
            };
            attachment.ObjectKey = ObjectKey(scope, id, fileName, now);
            _storage.ValidateObjectKey(attachment.ObjectKey);
            var upload = _storage.PresignUpload(attachment.ObjectKey, mimeType,
                TimeSpan.FromSeconds(_options.UploadUrlTtlSeconds));
            _db.TransferAttachments.Add(attachment);
            try
            {
                await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                return new PresignUploadResponse(id, id.ToString(CultureInfo.InvariantCulture),
                    attachment.ObjectKey, upload.Url, upload.Headers, upload.ExpiresAt,
                    ToView(attachment));
            }
            catch (DbUpdateException) when (attempt < 7)
            {
                _db.Entry(attachment).State = EntityState.Detached;
            }
        }
        throw new InvalidOperationException("failed to allocate attachment id");
    }

    private async Task<TransferAttachmentView> CompleteAsync(TransferAttachment attachment,
        CancellationToken cancellationToken)
    {
        var tenantId = RequireAccountText(attachment.TenantId, "tenantId");
        var ownerUsername = RequireAccountText(attachment.OwnerUsername, "ownerUsername");
        var quotaLock = QuotaLock(tenantId, ownerUsername);
        await quotaLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await CompleteWithinQuotaAsync(attachment, tenantId, ownerUsername,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            quotaLock.Release();
        }
    }

    private async Task<TransferAttachmentView> CompleteWithinQuotaAsync(TransferAttachment attachment,
        string tenantId, string ownerUsername, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        if (attachment.Status != StatusPending)
        {
            throw new InvalidOperationException("attachment is not pending");
        }
        if (attachment.UploadExpiresAt < now)
        {
            throw new InvalidOperationException("attachment upload URL is expired");
        }
        if (_storage.Enabled)
        {
            var stat = await _storage.StatAsync(attachment.ObjectKey, cancellationToken).ConfigureAwait(false);
            if (!stat.Exists)
            {
                throw new InvalidOperationException("attachment object was not uploaded");
            }
            if (stat.ContentLength > _options.MaxAttachmentBytes)
            {
                await _storage.DeleteAsync(attachment.ObjectKey, cancellationToken).ConfigureAwait(false);
                throw new ArgumentException("attachment is too large");
            }
            if (stat.ContentLength >= 0)
            {
                attachment.SizeBytes = stat.ContentLength;
            }
        }
        try
        {
            await EnsureStorageQuotaAsync(tenantId, ownerUsername, attachment.SizeBytes,
                attachment.Id, cancellationToken).ConfigureAwait(false);
        }
        catch (RateLimitedException)
        {
            if (_storage.Enabled)
            {
                await _storage.DeleteAsync(attachment.ObjectKey, cancellationToken).ConfigureAwait(false);
            }
            throw;
        }
        attachment.Status = StatusUploaded;
        attachment.UploadedAt = now;
        attachment.UpdatedAt = now;
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return ToView(attachment);
    }

    private async Task<PresignDownloadResponse> CreateDownloadAsync(ManagementContext context,
        TransferAttachment attachment, CancellationToken cancellationToken)
    {
        if (attachment.Status != StatusUploaded)
        {
            throw new InvalidOperationException("attachment is not uploaded");
        }
        if (attachment.ExpiresAt < DateTimeOffset.UtcNow)
        {
            throw new InvalidOperationException("attachment is expired");
        }
        var tenantId = RequireAccountText(context.TenantId, "tenantId");
        var username = RequireAccountText(context.Username, "username");
        var quotaLock = QuotaLock(tenantId, username);
        await quotaLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var usageMonth = DateTimeOffset.UtcNow.ToString("yyyy-MM", CultureInfo.InvariantCulture);
            var usedBytes = await _db.TransferAttachmentDownloadUsages.AsNoTracking()
                .Where(usage => usage.TenantId == tenantId && usage.Username == username
                    && usage.UsageMonth == usageMonth)
                .SumAsync(usage => (long?)usage.SizeBytes, cancellationToken)
                .ConfigureAwait(false) ?? 0L;
            EnsureWithinQuota(usedBytes, attachment.SizeBytes,
                _options.PerUserMonthlyDownloadQuotaBytes,
                "本月 OSS 下载流量额度不足");

            var download = _storage.PresignDownload(attachment.ObjectKey,
                TimeSpan.FromSeconds(_options.DownloadUrlTtlSeconds));
            await RecordDownloadUsageAsync(tenantId, username, usageMonth, attachment,
                cancellationToken).ConfigureAwait(false);
            return new PresignDownloadResponse(attachment.Id,
                attachment.Id.ToString(CultureInfo.InvariantCulture), download.Url, download.Headers,
                download.ExpiresAt, ToView(attachment));
        }
        finally
        {
            quotaLock.Release();
        }
    }

    private async Task EnsureStorageQuotaAsync(string? tenantId, string? ownerUsername,
        long requestedBytes, long excludedAttachmentId, CancellationToken cancellationToken)
    {
        var normalizedTenant = RequireAccountText(tenantId, "tenantId");
        var normalizedOwner = RequireAccountText(ownerUsername, "ownerUsername");
        var now = DateTimeOffset.UtcNow;
        var usedBytes = await _db.TransferAttachments.AsNoTracking()
            .Where(attachment => attachment.TenantId == normalizedTenant
                && attachment.OwnerUsername == normalizedOwner
                && attachment.Id != excludedAttachmentId
                && ((attachment.Status == StatusPending && attachment.UploadExpiresAt > now)
                    || (attachment.Status == StatusUploaded && attachment.ExpiresAt > now)))
            .SumAsync(attachment => (long?)attachment.SizeBytes, cancellationToken)
            .ConfigureAwait(false) ?? 0L;
        EnsureWithinQuota(usedBytes, requestedBytes, _options.PerUserStorageQuotaBytes,
            "OSS 存储额度不足");
    }

    private static void EnsureWithinQuota(long usedBytes, long requestedBytes, long limitBytes,
        string message)
    {
        var normalizedLimit = limitBytes > 0L ? limitBytes : DefaultPerUserQuotaBytes;
        if (requestedBytes < 0L || usedBytes > normalizedLimit - requestedBytes)
        {
            throw new RateLimitedException(message);
        }
    }

    private async Task RecordDownloadUsageAsync(string tenantId, string username, string usageMonth,
        TransferAttachment attachment, CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var usage = new TransferAttachmentDownloadUsage
            {
                Id = ClientIdGenerator.NewId(),
                TenantId = tenantId,
                Username = username,
                AttachmentId = attachment.Id,
                SizeBytes = attachment.SizeBytes,
                UsageMonth = usageMonth,
                CreatedAt = DateTimeOffset.UtcNow,
            };
            _db.TransferAttachmentDownloadUsages.Add(usage);
            try
            {
                await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                return;
            }
            catch (DbUpdateException) when (attempt < 7)
            {
                _db.Entry(usage).State = EntityState.Detached;
            }
        }
        throw new InvalidOperationException("failed to record download usage");
    }

    private static SemaphoreSlim QuotaLock(string? tenantId, string? username)
    {
        var hash = HashCode.Combine(tenantId?.Trim(), username?.Trim());
        var index = (int)(Math.Abs((long)hash) % QuotaLocks.Length);
        return QuotaLocks[index];
    }

    private static string RequireAccountText(string? value, string field) =>
        !string.IsNullOrWhiteSpace(value)
            ? value.Trim()
            : throw new InvalidOperationException(field + " is missing from authenticated account");

    private async Task<TransferAttachment> FindAsync(long attachmentId, string scope,
        string? tenantId, CancellationToken cancellationToken)
    {
        var query = _db.TransferAttachments.Where(row => row.Id == attachmentId && row.Scope == scope);
        if (tenantId is not null)
        {
            query = query.Where(row => row.TenantId == tenantId);
        }
        return await query.FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new ArgumentException($"attachment not found: {attachmentId}");
    }

    private async Task RequireClientAccessAsync(ManagementContext context, long? clientId,
        CancellationToken cancellationToken)
    {
        if (clientId is null)
        {
            throw new ArgumentException("target client is not accessible");
        }
        var client = await _db.ClientAccounts.AsNoTracking()
            .FirstOrDefaultAsync(row => row.Id == clientId.Value, cancellationToken)
            .ConfigureAwait(false);
        if (client is null || !context.CanAccess(client))
        {
            throw new ArgumentException("target client is not accessible");
        }
    }

    private static void RequireMatchingRoomToken(TransferAttachment attachment, string? roomToken)
    {
        var actual = RoomTokenHash(RequireText(roomToken, "roomToken"));
        var expected = attachment.RoomTokenHash ?? string.Empty;
        var actualBytes = Encoding.ASCII.GetBytes(actual);
        var expectedBytes = Encoding.ASCII.GetBytes(expected);
        if (actualBytes.Length != expectedBytes.Length
            || !CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes))
        {
            throw new ArgumentException("roomToken is invalid");
        }
    }

    private string ObjectKey(string scope, long attachmentId, string fileName, DateTimeOffset now)
    {
        var prefix = (_options.ObjectPrefix ?? string.Empty).Trim().Trim('/');
        var scopeSegment = scope.ToLowerInvariant().Replace('_', '-');
        var basePath = prefix.Length == 0 ? string.Empty : prefix + '/';
        return $"{basePath}{scopeSegment}/{now:yyyyMMdd}/{attachmentId}/{fileName}";
    }

    private long NormalizeSize(long? sizeBytes)
    {
        if (sizeBytes is null or <= 0)
        {
            throw new ArgumentException("sizeBytes must be positive");
        }
        if (sizeBytes > _options.MaxAttachmentBytes)
        {
            throw new ArgumentException("attachment is too large");
        }
        return sizeBytes.Value;
    }

    private static string NormalizeFileName(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw new ArgumentException("fileName cannot be blank");
        }

        var slash = Math.Max(value.LastIndexOf('/'), value.LastIndexOf('\\'));
        var segment = value[(slash + 1)..];
        var normalized = new StringBuilder(segment.Length);
        var previousWasInvalid = false;
        var previousWasDot = false;
        foreach (var rune in segment.EnumerateRunes())
        {
            var codePoint = rune.Value;
            var asciiAlphaNumeric = codePoint is >= 'A' and <= 'Z'
                or >= 'a' and <= 'z'
                or >= '0' and <= '9';
            var allowed = asciiAlphaNumeric || codePoint is '.' or '_' or '-';
            if (!allowed)
            {
                if (!previousWasInvalid)
                {
                    normalized.Append('_');
                }
                previousWasInvalid = true;
                previousWasDot = false;
                continue;
            }
            previousWasInvalid = false;
            if (codePoint == '.')
            {
                if (!previousWasDot)
                {
                    normalized.Append('.');
                }
                previousWasDot = true;
            }
            else
            {
                normalized.Append(rune);
                previousWasDot = false;
            }
        }

        var result = normalized.ToString();
        if (result is "" or ".")
        {
            return "attachment";
        }
        if (result.Length <= 180)
        {
            return result;
        }

        var dot = result.LastIndexOf('.');
        if (dot > 0 && dot < result.Length - 1)
        {
            var extension = result[dot..];
            if (extension.Length < 180)
            {
                return result[..(180 - extension.Length)] + extension;
            }
        }
        return result[..180];
    }

    private static string NormalizeMimeType(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "application/octet-stream";
        }
        var normalized = value.Trim();
        if (normalized.Length > 120 || normalized.Contains('\r') || normalized.Contains('\n'))
        {
            throw new ArgumentException("mimeType is invalid");
        }
        return normalized;
    }

    private static string? NormalizeSha256(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }
        var normalized = value.Trim().ToLowerInvariant();
        return Sha256Pattern.IsMatch(normalized)
            ? normalized
            : throw new ArgumentException("sha256 is invalid");
    }

    private static string NormalizeRoomId(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "default";
        }
        var normalized = value.Trim();
        if (normalized.Length > 120 || normalized.Contains('\r') || normalized.Contains('\n'))
        {
            throw new ArgumentException("roomId is invalid");
        }
        return normalized;
    }

    private static string RequireText(string? value, string field) => !string.IsNullOrWhiteSpace(value)
        ? value.Trim()
        : throw new ArgumentException(field + " cannot be blank");

    private static string RoomTokenHash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static TransferAttachmentView ToView(TransferAttachment attachment) => new(
        attachment.Id,
        attachment.Id.ToString(CultureInfo.InvariantCulture),
        attachment.FileName,
        attachment.MimeType,
        attachment.SizeBytes,
        attachment.Sha256,
        attachment.Status,
        attachment.ExpiresAt.ToString("O"));
}

public sealed class TransferAttachmentExpirationService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ObjectStorageOptions _options;
    private readonly ILogger<TransferAttachmentExpirationService> _logger;

    public TransferAttachmentExpirationService(IServiceScopeFactory scopeFactory,
        IOptions<ObjectStorageOptions> options, ILogger<TransferAttachmentExpirationService> logger)
    {
        _scopeFactory = scopeFactory;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var scope = _scopeFactory.CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<TransferAttachmentService>()
                    .ExpireOldAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "attachment expiration scan failed");
            }
            await Task.Delay(TimeSpan.FromMilliseconds(Math.Max(1_000L,
                _options.ExpirationScanIntervalMs)), stoppingToken).ConfigureAwait(false);
        }
    }
}

public sealed record PresignUploadRequest(string? FileName, string? MimeType, long? SizeBytes,
    string? Sha256, string? RoomId, string? RoomToken, long? TargetClientId);
public sealed record CompleteAttachmentRequest(string? RoomToken);
public sealed record PresignDownloadRequest(string? RoomToken);
public sealed record TransferAttachmentView(long AttachmentId, string ObjectId, string FileName,
    string MimeType, long SizeBytes, string? Sha256, string Status, string ExpiresAt);
public sealed record PresignUploadResponse(long AttachmentId, string ObjectId, string ObjectKey,
    string UploadUrl, IReadOnlyDictionary<string, string> UploadHeaders, string ExpiresAt,
    TransferAttachmentView Attachment);
public sealed record PresignDownloadResponse(long AttachmentId, string ObjectId, string DownloadUrl,
    IReadOnlyDictionary<string, string> DownloadHeaders, string ExpiresAt,
    TransferAttachmentView Attachment);
