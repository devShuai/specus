using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;

namespace Specus.Server.Management;

public interface IHttpMediaCaptureSession
{
    bool Active { get; }
    bool Externalized { get; }
    ValueTask AppendAsync(ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken);
    Task CompleteAsync(CancellationToken cancellationToken);
    Task FailAsync(string? reason, CancellationToken cancellationToken);
}

public sealed class HttpMediaCaptureService
{
    public const string StateStarting = "STARTING";
    public const string StateCapturing = "CAPTURING";
    public const string StateComplete = "COMPLETE";
    public const string StateIncomplete = "INCOMPLETE";
    public const string StateFailed = "FAILED";

    private static readonly Regex SensitiveQueryParameter = new(
        "([?&](?:api_?key|access_token|auth_token|token|x-emby-token)=)[^&#]*",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly IHttpMediaCaptureSession Noop = new NoopCaptureSession(false);
    private static readonly IHttpMediaCaptureSession ExternalizedNoop = new NoopCaptureSession(true);

    private readonly SpecusDbContext _db;
    private readonly IHttpMediaStorage _storage;
    private readonly HttpMediaUploadScheduler _scheduler;
    private readonly MediaCaptureOptions _options;
    private readonly ILogger<HttpMediaCaptureService> _logger;
    private readonly IServiceScopeFactory _scopeFactory;

    public HttpMediaCaptureService(SpecusDbContext db, IHttpMediaStorage storage,
        HttpMediaUploadScheduler scheduler, IOptions<MediaCaptureOptions> options,
        ILogger<HttpMediaCaptureService> logger, IServiceScopeFactory scopeFactory)
    {
        _db = db;
        _storage = storage;
        _scheduler = scheduler;
        _options = options.Value;
        _logger = logger;
        _scopeFactory = scopeFactory;
    }

    public async Task<IHttpMediaCaptureSession> OpenAsync(string clientName, string route,
        string method, string sourceUrl, int statusCode, IReadOnlyList<string> responseHeaders,
        CancellationToken cancellationToken)
    {
        if (!_storage.Ready || method.Equals("HEAD", StringComparison.OrdinalIgnoreCase))
        {
            return Noop;
        }
        var normalizedSourceUrl = HttpMediaManifestSupport.NormalizeSourceUrl(sourceUrl);
        var contentType = HeaderValue(responseHeaders, "content-type");
        var contentEncoding = HeaderValue(responseHeaders, "content-encoding");
        var contentRangeValue = HeaderValue(responseHeaders, "content-range");
        var kind = HttpMediaManifestSupport.Classify(normalizedSourceUrl, contentType,
            statusCode, contentRangeValue);
        if (kind is null)
        {
            return Noop;
        }

        var account = await _db.ClientAccounts.AsNoTracking()
            .FirstOrDefaultAsync(row => row.ClientName == clientName, cancellationToken)
            .ConfigureAwait(false);
        if (account is null)
        {
            return Noop;
        }
        var mapping = await _db.HttpRouteMappings.AsNoTracking()
            .FirstOrDefaultAsync(row => row.ClientId == account.Id && row.Route == route,
                cancellationToken).ConfigureAwait(false);
        if (mapping is null || !mapping.MediaCaptureEnabled)
        {
            return Noop;
        }

        var now = DateTimeOffset.UtcNow;
        var entityTag = HeaderValue(responseHeaders, "etag");
        var lastModified = HeaderValue(responseHeaders, "last-modified");
        var parsedRange = HttpMediaManifestSupport.ParseContentRange(contentRangeValue);
        var contentLength = NonNegativeLong(HeaderValue(responseHeaders, "content-length"));
        long? rangeStart;
        long? rangeEnd;
        long? totalBytes;
        long expectedResponseBytes;
        if (parsedRange is null)
        {
            rangeStart = 0;
            rangeEnd = contentLength is null ? null : contentLength - 1;
            totalBytes = contentLength;
            expectedResponseBytes = contentLength ?? -1;
        }
        else
        {
            rangeStart = parsedRange.Start;
            rangeEnd = parsedRange.End;
            totalBytes = parsedRange.Total;
            expectedResponseBytes = parsedRange.End - parsedRange.Start + 1;
        }

        var normalizedMethod = Cap(string.IsNullOrWhiteSpace(method)
            ? "GET" : method.Trim().ToUpperInvariant(), 16)!;
        var storedEncoding = Cap(contentEncoding, 128);
        var resourceKey = ResourceKey(account.TenantId, account.Id, route, normalizedSourceUrl,
            entityTag, lastModified);
        var deduplicationKey = DeduplicationKey(resourceKey, normalizedMethod, kind, rangeStart,
            rangeEnd, totalBytes, storedEncoding);
        if (deduplicationKey is not null && await HasReusableCaptureAsync(account.TenantId,
                deduplicationKey, resourceKey, kind, rangeStart, rangeEnd, totalBytes,
                expectedResponseBytes, storedEncoding, now, cancellationToken).ConfigureAwait(false))
        {
            return ExternalizedNoop;
        }

        var capture = new HttpMediaCapture
        {
            TenantId = account.TenantId,
            ClientId = account.Id,
            ClientName = account.ClientName,
            Route = route,
            ResourceId = mapping.Id,
            SourceUrl = normalizedSourceUrl,
            ResourceKey = resourceKey,
            DeduplicationKey = deduplicationKey,
            Method = normalizedMethod,
            StatusCode = statusCode,
            ContentType = Cap(contentType, 255),
            ContentEncoding = storedEncoding,
            MediaKind = kind,
            EntityTag = Cap(entityTag, 512),
            LastModified = Cap(lastModified, 128),
            ContentRangeStart = rangeStart,
            ContentRangeEnd = rangeEnd,
            TotalBytes = totalBytes,
            SegmentSequence = HttpMediaManifestSupport.InferSequence(normalizedSourceUrl),
            InitializationSegment = HttpMediaManifestSupport.IsInitializationSegment(normalizedSourceUrl),
            ObjectKey = ObjectKey(account.TenantId, route, normalizedSourceUrl),
            State = StateStarting,
            ResponseHeaders = string.Join('\n', responseHeaders),
            CapturedAt = now,
            ExpiresAt = now.AddSeconds(Math.Max(60, _options.RetentionSeconds)),
        };
        _db.HttpMediaCaptures.Add(capture);
        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateException) when (deduplicationKey is not null)
        {
            _db.Entry(capture).State = EntityState.Detached;
            var concurrent = await _db.HttpMediaCaptures.AsNoTracking()
                .FirstOrDefaultAsync(row => row.TenantId == account.TenantId
                                            && row.DeduplicationKey == deduplicationKey,
                    cancellationToken).ConfigureAwait(false);
            if (concurrent is not null && IsReusable(concurrent, rangeStart, rangeEnd,
                    expectedResponseBytes, DateTimeOffset.UtcNow))
            {
                return ExternalizedNoop;
            }
            throw;
        }

        try
        {
            var upload = await _storage.BeginMultipartAsync(capture.ObjectKey, capture.ContentType,
                capture.ContentEncoding, cancellationToken).ConfigureAwait(false);
            capture.UploadId = upload.UploadId;
            capture.State = StateCapturing;
            _db.HttpMediaCaptures.Update(capture);
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return new ActiveCaptureSession(this, capture.Id, upload, kind, expectedResponseBytes);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException
                                   or InvalidOperationException or OperationCanceledException)
        {
            await MarkFailedAsync(capture.Id, ex, CancellationToken.None).ConfigureAwait(false);
            _logger.LogWarning(ex,
                "Failed to begin media capture for client {ClientName}, route {Route}, source {SourceUrl}",
                clientName, route, normalizedSourceUrl);
            return Noop;
        }
    }

    public async Task<HttpMediaCapturePage> ListAsync(ManagementContext context, long? clientId,
        string? route, int page, int size, CancellationToken cancellationToken)
    {
        page = Math.Max(0, page);
        size = Math.Clamp(size, 1, 200);
        var normalizedRoute = string.IsNullOrWhiteSpace(route) ? null : route.Trim();
        IQueryable<HttpMediaCapture> query = _db.HttpMediaCaptures.AsNoTracking()
            .Where(row => row.TenantId == context.TenantId);
        if (!context.IsAdmin)
        {
            var visibleIds = _db.ClientAccounts.AsNoTracking()
                .Where(row => row.TenantId == context.TenantId
                              && row.OwnerUsername == context.Username)
                .Select(row => row.Id);
            query = query.Where(row => visibleIds.Contains(row.ClientId));
        }
        if (clientId is not null)
        {
            query = query.Where(row => row.ClientId == clientId.Value);
        }
        if (normalizedRoute is not null)
        {
            query = query.Where(row => row.Route == normalizedRoute);
        }
        var total = await query.LongCountAsync(cancellationToken).ConfigureAwait(false);
        var rows = await query.OrderByDescending(row => row.Id).Skip(page * size).Take(size)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        var views = new List<HttpMediaCaptureView>(rows.Count);
        foreach (var row in rows)
        {
            views.Add(await ToViewAsync(row, cancellationToken).ConfigureAwait(false));
        }
        return new HttpMediaCapturePage(views, total, page, size,
            total == 0 ? 0 : checked((int)((total + size - 1) / size)));
    }

    public async Task<HttpMediaCapture> RequireAccessibleAsync(ManagementContext context, long id,
        CancellationToken cancellationToken)
    {
        var capture = await _db.HttpMediaCaptures.AsNoTracking()
            .FirstOrDefaultAsync(row => row.Id == id && row.TenantId == context.TenantId,
                cancellationToken).ConfigureAwait(false)
            ?? throw new ArgumentException("媒体采集记录不存在");
        if (!context.IsAdmin)
        {
            var owned = await _db.ClientAccounts.AsNoTracking().AnyAsync(row =>
                row.Id == capture.ClientId && row.TenantId == context.TenantId
                                           && row.OwnerUsername == context.Username,
                cancellationToken).ConfigureAwait(false);
            if (!owned)
            {
                throw new ArgumentException("媒体采集记录不存在");
            }
        }
        return capture;
    }

    public async Task<HttpMediaCapture> FindByTicketAsync(long id, string tenantId,
        CancellationToken cancellationToken) =>
        await _db.HttpMediaCaptures.AsNoTracking()
            .FirstOrDefaultAsync(row => row.Id == id && row.TenantId == tenantId, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException("媒体采集记录不存在");

    public async Task<HttpMediaCapture> LatestForSourceAsync(HttpMediaCapture anchor,
        string sourceUrl, CancellationToken cancellationToken)
    {
        var normalized = HttpMediaManifestSupport.NormalizeSourceUrl(sourceUrl);
        return await _db.HttpMediaCaptures.AsNoTracking()
            .Where(row => row.TenantId == anchor.TenantId && row.ClientId == anchor.ClientId
                          && row.Route == anchor.Route && row.SourceUrl == normalized
                          && row.State == StateComplete)
            .OrderByDescending(row => row.Id).FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException("对应媒体分段尚未采集完成");
    }

    public async Task<HttpMediaCapture> LatestManifestAsync(HttpMediaCapture anchor,
        CancellationToken cancellationToken) => await _db.HttpMediaCaptures.AsNoTracking()
        .Where(row => row.TenantId == anchor.TenantId && row.ClientId == anchor.ClientId
                      && row.Route == anchor.Route && row.SourceUrl == anchor.SourceUrl
                      && row.State == StateComplete
                      && (row.MediaKind == HttpMediaManifestSupport.HlsManifest
                          || row.MediaKind == HttpMediaManifestSupport.DashManifest))
        .OrderByDescending(row => row.Id).FirstOrDefaultAsync(cancellationToken)
        .ConfigureAwait(false) ?? anchor;

    public async Task<string> RewrittenManifestAsync(HttpMediaCapture anchor, string assetBasePath,
        CancellationToken cancellationToken)
    {
        var latest = await LatestManifestAsync(anchor, cancellationToken).ConfigureAwait(false);
        if (latest.State != StateComplete || !HttpMediaManifestSupport.IsManifest(latest.MediaKind))
        {
            throw new InvalidOperationException("媒体清单尚未采集完成");
        }
        var bytes = await _storage.ReadAllAsync(latest.ObjectKey, _options.ManifestMaxBytes,
            cancellationToken).ConfigureAwait(false);
        var text = HttpMediaBodyCodec.ToText(bytes, latest.ContentEncoding);
        return HttpMediaManifestSupport.Rewrite(latest.MediaKind, latest.SourceUrl, text,
            assetBasePath);
    }

    public Task<List<HttpMediaCapture>> CompleteResourceCapturesAsync(HttpMediaCapture anchor,
        CancellationToken cancellationToken) => _db.HttpMediaCaptures.AsNoTracking()
        .Where(row => row.TenantId == anchor.TenantId && row.ResourceKey == anchor.ResourceKey
                      && row.State == StateComplete)
        .OrderByDescending(row => row.Id).ToListAsync(cancellationToken);

    public async Task CleanupExpiredAsync(CancellationToken cancellationToken)
    {
        if (!_options.Enabled)
        {
            return;
        }
        var now = DateTimeOffset.UtcNow;
        var states = new[] { StateStarting, StateCapturing, StateComplete, StateIncomplete, StateFailed };
        var captures = await _db.HttpMediaCaptures.Where(row => states.Contains(row.State)
                                                               && row.ExpiresAt < now)
            .OrderBy(row => row.Id).Take(200).ToListAsync(cancellationToken).ConfigureAwait(false);
        foreach (var capture in captures)
        {
            try
            {
                if (ExtendNonLiveRetention(capture, now))
                {
                    await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                    continue;
                }
                if (capture.State is StateStarting or StateCapturing
                    && !string.IsNullOrWhiteSpace(capture.UploadId) && _storage.Ready)
                {
                    await _storage.AbortMultipartAsync(
                        new MediaMultipartUpload(capture.ObjectKey, capture.UploadId), cancellationToken)
                        .ConfigureAwait(false);
                }
                else if (capture.State is StateComplete or StateIncomplete && _storage.Ready)
                {
                    await _storage.DeleteAsync(capture.ObjectKey, cancellationToken).ConfigureAwait(false);
                }
                await _db.HttpMediaReferences.Where(row => row.TenantId == capture.TenantId
                                                            && row.ManifestCaptureId == capture.Id)
                    .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
                _db.HttpMediaCaptures.Remove(capture);
                await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidOperationException
                                       or DbUpdateException)
            {
                _logger.LogWarning(ex, "Failed to clean expired media capture {CaptureId}", capture.Id);
                _db.ChangeTracker.Clear();
            }
        }
    }

    private async Task<HttpMediaCaptureView> ToViewAsync(HttpMediaCapture row,
        CancellationToken cancellationToken)
    {
        var playback = await PlaybackStatusAsync(row, cancellationToken).ConfigureAwait(false);
        return new HttpMediaCaptureView(row.Id, row.ClientId, row.ClientName, row.Route,
            row.ResourceId, RedactSourceUrl(row.SourceUrl), row.Method, row.StatusCode,
            row.ContentType, row.MediaKind, row.EntityTag, row.ContentRangeStart,
            row.ContentRangeEnd, row.TotalBytes, row.CapturedBytes, row.SegmentSequence,
            row.InitializationSegment, row.LiveStream, row.State, row.FailureReason,
            playback.Playable, playback.OfflineReady, playback.Message,
            row.CapturedAt.ToString("O"), row.CompletedAt?.ToString("O"), row.ExpiresAt.ToString("O"));
    }

    private async Task<PlaybackStatus> PlaybackStatusAsync(HttpMediaCapture row,
        CancellationToken cancellationToken)
    {
        if (row.State != StateComplete)
        {
            return new PlaybackStatus(false, false, "媒体采集尚未完成");
        }
        if (row.MediaKind == HttpMediaManifestSupport.MediaSegment || row.InitializationSegment)
        {
            return new PlaybackStatus(false, true, "媒体分段由 HLS/DASH 清单播放器按需加载");
        }
        if (HttpMediaManifestSupport.IsManifest(row.MediaKind))
        {
            return row.CapturedBytes > 0
                ? new PlaybackStatus(true, false, "仅播放已缓存的媒体分段")
                : new PlaybackStatus(false, false, "媒体清单正文为空");
        }
        var coverage = HttpMediaPlaybackService.EvaluateCoverage(
            await CompleteResourceCapturesAsync(row, cancellationToken).ConfigureAwait(false));
        if (coverage.Playable)
        {
            return new PlaybackStatus(true, true, null);
        }
        return row.CapturedBytes > 0
            ? new PlaybackStatus(true, false, coverage.Reason + "；仅可播放已缓存区间")
            : new PlaybackStatus(false, false, coverage.Reason);
    }

    private bool ExtendNonLiveRetention(HttpMediaCapture capture, DateTimeOffset now)
    {
        if (capture.LiveStream || capture.State is not (StateComplete or StateIncomplete))
        {
            return false;
        }
        var configuredExpiry = capture.CapturedAt.AddSeconds(Math.Max(60, _options.RetentionSeconds));
        if (configuredExpiry <= now || configuredExpiry <= capture.ExpiresAt)
        {
            return false;
        }
        capture.ExpiresAt = configuredExpiry;
        return true;
    }

    private async Task<bool> HasReusableCaptureAsync(string tenantId, string deduplicationKey,
        string resourceKey, string mediaKind, long? rangeStart, long? rangeEnd, long? totalBytes,
        long expectedBytes, string? contentEncoding, DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var keyed = await _db.HttpMediaCaptures.FirstOrDefaultAsync(row =>
            row.TenantId == tenantId && row.DeduplicationKey == deduplicationKey,
            cancellationToken).ConfigureAwait(false);
        if (keyed is not null)
        {
            if (IsReusable(keyed, rangeStart, rangeEnd, expectedBytes, now))
            {
                return true;
            }
            keyed.DeduplicationKey = null;
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        return await _db.HttpMediaCaptures.AsNoTracking().AnyAsync(row =>
            row.TenantId == tenantId && row.ResourceKey == resourceKey
                                       && row.MediaKind == mediaKind
                                       && row.ContentRangeStart == rangeStart
                                       && row.ContentRangeEnd == rangeEnd
                                       && row.TotalBytes == totalBytes
                                       && row.CapturedBytes == expectedBytes
                                       && row.ContentEncoding == contentEncoding
                                       && row.State == StateComplete && row.ExpiresAt > now,
            cancellationToken).ConfigureAwait(false);
    }

    private static bool IsReusable(HttpMediaCapture capture, long? rangeStart, long? rangeEnd,
        long expectedBytes, DateTimeOffset now) => capture.State is StateStarting or StateCapturing
        || capture.State == StateComplete && capture.CapturedBytes == expectedBytes
        && capture.ContentRangeStart == rangeStart && capture.ContentRangeEnd == rangeEnd
        && capture.ExpiresAt > now;

    private async Task MarkCompleteAsync(long captureId, string? etag, long capturedBytes,
        long expectedBytes, byte[]? manifestBytes, bool acceptPartial, string? completionReason,
        CancellationToken cancellationToken)
    {
        var capture = await _db.HttpMediaCaptures.FirstOrDefaultAsync(row => row.Id == captureId,
            cancellationToken).ConfigureAwait(false);
        if (capture is null)
        {
            return;
        }
        var now = DateTimeOffset.UtcNow;
        var retainedPartial = acceptPartial && capturedBytes > 0 && expectedBytes >= 0
                              && expectedBytes != capturedBytes;
        var complete = retainedPartial || expectedBytes < 0 || expectedBytes == capturedBytes;
        capture.State = complete ? StateComplete : StateIncomplete;
        if (!complete || retainedPartial)
        {
            capture.DeduplicationKey = null;
        }
        capture.FailureReason = complete ? null
            : $"响应正文长度不完整，预期 {expectedBytes} 字节，实际 {capturedBytes} 字节";
        capture.ObjectEtag = Cap(etag, 512);
        capture.UploadId = null;
        capture.CapturedBytes = capturedBytes;
        if (retainedPartial || capture.ContentRangeEnd is null && capturedBytes > 0)
        {
            capture.ContentRangeEnd = (capture.ContentRangeStart ?? 0) + capturedBytes - 1;
        }
        if (capture.TotalBytes is null && capture.ContentRangeStart == 0 && complete)
        {
            capture.TotalBytes = capturedBytes;
        }
        capture.CompletedAt = now;
        if (complete && manifestBytes is not null && HttpMediaManifestSupport.IsManifest(capture.MediaKind))
        {
            var text = HttpMediaBodyCodec.ToText(manifestBytes, capture.ContentEncoding);
            var parsed = HttpMediaManifestSupport.Parse(capture.MediaKind, capture.SourceUrl, text);
            capture.LiveStream = parsed.Live;
            if (parsed.Live)
            {
                capture.ExpiresAt = now.AddSeconds(Math.Max(60, _options.LiveWindowSeconds));
                await MarkLiveWindowAsync(capture, parsed, now, cancellationToken).ConfigureAwait(false);
            }
            await SaveManifestReferencesAsync(capture, parsed, now, cancellationToken)
                .ConfigureAwait(false);
        }
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        _logger.LogDebug("Completed media capture {CaptureId} as {State}, {Bytes} bytes ({Reason})",
            captureId, capture.State, capturedBytes, completionReason);
    }

    private async Task MarkLiveWindowAsync(HttpMediaCapture manifest,
        HttpMediaManifestSupport.ParsedManifest parsed, DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var expiresAt = now.AddSeconds(Math.Max(60, _options.LiveWindowSeconds));
        var recentCutoff = now.AddSeconds(-Math.Max(60, _options.LiveWindowSeconds));
        var sourceUrls = parsed.References
            .Where(reference => reference.RelationType is "SEGMENT" or "INITIALIZATION")
            .Select(reference => reference.ResolvedSourceUrl).Distinct().ToList();
        var related = await _db.HttpMediaCaptures.Where(row =>
                row.TenantId == manifest.TenantId && row.ClientId == manifest.ClientId
                && row.Route == manifest.Route && row.State == StateComplete
                && (sourceUrls.Contains(row.SourceUrl)
                    || row.MediaKind == HttpMediaManifestSupport.MediaSegment
                    && row.CapturedAt > recentCutoff))
            .OrderByDescending(row => row.Id).Take(1000).ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        foreach (var capture in related)
        {
            capture.LiveStream = true;
            capture.ExpiresAt = expiresAt;
        }
    }

    private async Task SaveManifestReferencesAsync(HttpMediaCapture capture,
        HttpMediaManifestSupport.ParsedManifest parsed, DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await _db.HttpMediaReferences.Where(row => row.TenantId == capture.TenantId
                                                    && row.ManifestCaptureId == capture.Id)
            .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        _db.HttpMediaReferences.AddRange(parsed.References.Select(reference => new HttpMediaReference
        {
            TenantId = capture.TenantId,
            ManifestCaptureId = capture.Id,
            RelationType = Cap(reference.RelationType, 24)!,
            SequenceIndex = reference.Sequence,
            OriginalUri = Cap(reference.OriginalUri, 2048)!,
            ResolvedSourceUrl = Cap(reference.ResolvedSourceUrl, 3072)!,
            CreatedAt = now,
        }));
    }

    private async Task MarkFailedAsync(long captureId, Exception error,
        CancellationToken cancellationToken)
    {
        var capture = await _db.HttpMediaCaptures.FirstOrDefaultAsync(row => row.Id == captureId,
            cancellationToken).ConfigureAwait(false);
        if (capture is null)
        {
            return;
        }
        capture.State = StateFailed;
        capture.DeduplicationKey = null;
        capture.FailureReason = Cap(RootMessage(error), 2048);
        capture.CompletedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    private static string RedactSourceUrl(string sourceUrl) =>
        SensitiveQueryParameter.Replace(sourceUrl, "$1***");

    private string ObjectKey(string tenantId, string route, string sourceUrl)
    {
        var prefix = (_options.ObjectPrefix ?? string.Empty).Trim().Trim('/');
        var date = DateTimeOffset.UtcNow.ToString("yyyy/MM/dd");
        var path = $"{SafeSegment(tenantId)}/{date}/{SafeSegment(route)}/" +
                   Guid.NewGuid().ToString("N") + Extension(sourceUrl);
        return prefix.Length == 0 ? path : prefix + "/" + path;
    }

    private static string ResourceKey(string tenantId, long clientId, string route,
        string sourceUrl, string? entityTag, string? lastModified)
    {
        var version = !string.IsNullOrWhiteSpace(entityTag) ? entityTag
            : !string.IsNullOrWhiteSpace(lastModified) ? lastModified : string.Empty;
        return Sha256($"{tenantId}\n{clientId}\n{route}\n{sourceUrl}\n{version}");
    }

    private static string? DeduplicationKey(string resourceKey, string method, string kind,
        long? rangeStart, long? rangeEnd, long? totalBytes, string? contentEncoding)
    {
        if (HttpMediaManifestSupport.IsManifest(kind) || rangeStart is null || rangeEnd is null
            || rangeEnd < rangeStart)
        {
            return null;
        }
        return Sha256($"{resourceKey}\n{method}\n{kind}\n{rangeStart}\n{rangeEnd}\n" +
                      $"{totalBytes?.ToString() ?? string.Empty}\n{contentEncoding?.ToLowerInvariant() ?? string.Empty}");
    }

    private static string Sha256(string value) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string Extension(string sourceUrl)
    {
        var path = sourceUrl.Split('?', 2)[0];
        var slash = path.LastIndexOf('/');
        var dot = path.LastIndexOf('.');
        if (dot <= slash || path.Length - dot > 12)
        {
            return ".bin";
        }
        var extension = path[dot..].ToLowerInvariant();
        return Regex.IsMatch(extension, "^\\.[a-z0-9]{1,10}$") ? extension : ".bin";
    }

    private static string SafeSegment(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "default";
        }
        var normalized = Regex.Replace(value.Trim(), "[^A-Za-z0-9._-]", "_");
        return normalized.Length <= 80 ? normalized : normalized[..80];
    }

    private static string? HeaderValue(IEnumerable<string> headers, string name)
    {
        foreach (var header in headers)
        {
            var separator = header.IndexOf(':');
            if (separator > 0 && name.Equals(header[..separator].Trim(),
                    StringComparison.OrdinalIgnoreCase))
            {
                return header[(separator + 1)..].Trim();
            }
        }
        return null;
    }

    private static long? NonNegativeLong(string? value) =>
        long.TryParse(value?.Trim(), out var parsed) && parsed >= 0 ? parsed : null;

    private static string? Cap(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];

    private static string RootMessage(Exception error)
    {
        var current = error;
        while (current.InnerException is Exception inner)
        {
            current = inner;
        }
        return string.IsNullOrWhiteSpace(current.Message) ? current.GetType().Name : current.Message;
    }

    private sealed record PlaybackStatus(bool Playable, bool OfflineReady, string? Message);

    private sealed class NoopCaptureSession(bool externalized) : IHttpMediaCaptureSession
    {
        public bool Active => false;
        public bool Externalized => externalized;
        public ValueTask AppendAsync(ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken) =>
            ValueTask.CompletedTask;
        public Task CompleteAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task FailAsync(string? reason, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class ActiveCaptureSession : IHttpMediaCaptureSession
    {
        private readonly HttpMediaCaptureService _owner;
        private readonly long _captureId;
        private readonly MediaMultipartUpload _upload;
        private readonly long _expectedBytes;
        private readonly bool _partialUsable;
        private readonly int _partSize;
        private readonly SemaphoreSlim _inflight;
        private readonly List<Task<MediaCompletedPart>> _parts = [];
        private MemoryStream? _partBuffer;
        private MemoryStream? _manifestBuffer;
        private int _nextPart = 1;
        private long _capturedBytes;
        private int _terminal;

        public ActiveCaptureSession(HttpMediaCaptureService owner, long captureId,
            MediaMultipartUpload upload, string kind, long expectedBytes)
        {
            _owner = owner;
            _captureId = captureId;
            _upload = upload;
            _expectedBytes = expectedBytes;
            _partialUsable = !HttpMediaManifestSupport.IsManifest(kind);
            _partSize = checked((int)Math.Min(owner._options.NormalizedPartSizeBytes,
                512L * 1024 * 1024));
            _inflight = new SemaphoreSlim(owner._options.NormalizedMaxInflightParts);
            _partBuffer = new MemoryStream(_partSize);
            _manifestBuffer = HttpMediaManifestSupport.IsManifest(kind) ? new MemoryStream() : null;
        }

        public bool Active => Volatile.Read(ref _terminal) == 0;
        public bool Externalized => true;

        public async ValueTask AppendAsync(ReadOnlyMemory<byte> bytes,
            CancellationToken cancellationToken)
        {
            if (!Active || bytes.IsEmpty || _partBuffer is null)
            {
                return;
            }
            if (_manifestBuffer is not null)
            {
                if (_owner._options.ManifestMaxBytes > 0
                    && _manifestBuffer.Length + bytes.Length <= _owner._options.ManifestMaxBytes)
                {
                    await _manifestBuffer.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    await _manifestBuffer.DisposeAsync().ConfigureAwait(false);
                    _manifestBuffer = null;
                }
            }
            var offset = 0;
            while (offset < bytes.Length)
            {
                var length = Math.Min(bytes.Length - offset,
                    _partSize - checked((int)_partBuffer.Length));
                await _partBuffer.WriteAsync(bytes.Slice(offset, length), cancellationToken)
                    .ConfigureAwait(false);
                _capturedBytes += length;
                offset += length;
                if (_partBuffer.Length == _partSize)
                {
                    var part = _partBuffer.ToArray();
                    await _partBuffer.DisposeAsync().ConfigureAwait(false);
                    _partBuffer = new MemoryStream(_partSize);
                    await SubmitPartAsync(part, cancellationToken).ConfigureAwait(false);
                }
            }
        }

        public Task CompleteAsync(CancellationToken cancellationToken) =>
            FinishAsync(false, null, cancellationToken);

        public Task FailAsync(string? reason, CancellationToken cancellationToken) =>
            _partialUsable && _capturedBytes > 0
                ? FinishAsync(true, reason, cancellationToken)
                : AbortAsync(new InvalidOperationException(string.IsNullOrWhiteSpace(reason)
                    ? "媒体响应中断" : reason), cancellationToken);

        private async Task FinishAsync(bool acceptPartial, string? reason,
            CancellationToken cancellationToken)
        {
            if (Interlocked.Exchange(ref _terminal, 1) != 0)
            {
                return;
            }
            try
            {
                if (_partBuffer is { Length: > 0 })
                {
                    await SubmitPartAsync(_partBuffer.ToArray(), cancellationToken).ConfigureAwait(false);
                }
                if (_partBuffer is not null)
                {
                    await _partBuffer.DisposeAsync().ConfigureAwait(false);
                    _partBuffer = null;
                }
                var manifestBytes = _manifestBuffer?.ToArray();
                if (_manifestBuffer is not null)
                {
                    await _manifestBuffer.DisposeAsync().ConfigureAwait(false);
                    _manifestBuffer = null;
                }
                _owner._scheduler.Track(FinalizeAsync(_parts.ToArray(), manifestBytes,
                    acceptPartial, reason));
            }
            catch (Exception ex)
            {
                _owner._scheduler.Track(AbortAfterTerminalAsync(ex));
            }
        }

        private Task AbortAsync(Exception error, CancellationToken cancellationToken)
        {
            if (Interlocked.Exchange(ref _terminal, 1) != 0)
            {
                return Task.CompletedTask;
            }
            _owner._scheduler.Track(AbortAfterTerminalAsync(error));
            return Task.CompletedTask;
        }

        private async Task FinalizeAsync(IReadOnlyList<Task<MediaCompletedPart>> parts,
            byte[]? manifestBytes, bool acceptPartial, string? reason)
        {
            if (parts.Count == 0)
            {
                await AbortAfterTerminalAsync(new InvalidOperationException("媒体响应正文为空"))
                    .ConfigureAwait(false);
                return;
            }
            try
            {
                var completed = await Task.WhenAll(parts).ConfigureAwait(false);
                var etag = await _owner._storage.CompleteMultipartAsync(_upload,
                    completed.OrderBy(part => part.PartNumber).ToList(), CancellationToken.None)
                    .ConfigureAwait(false);
                await using var scope = _owner._scopeFactory.CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<HttpMediaCaptureService>()
                    .MarkCompleteAsync(_captureId, etag, _capturedBytes, _expectedBytes,
                        manifestBytes, acceptPartial, reason, CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await AbortAfterTerminalAsync(ex).ConfigureAwait(false);
            }
        }

        private async Task AbortAfterTerminalAsync(Exception error)
        {
            try
            {
                await Task.WhenAll(_parts).ConfigureAwait(false);
            }
            catch (Exception uploadError)
            {
                error = uploadError;
            }
            try
            {
                await _owner._storage.AbortMultipartAsync(_upload, CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (Exception abortError)
            {
                error = new AggregateException(error, abortError);
            }
            await using (var scope = _owner._scopeFactory.CreateAsyncScope())
            {
                await scope.ServiceProvider.GetRequiredService<HttpMediaCaptureService>()
                    .MarkFailedAsync(_captureId, error, CancellationToken.None).ConfigureAwait(false);
            }
            _owner._logger.LogWarning(error, "Media multipart upload failed for capture {CaptureId}",
                _captureId);
        }

        private async Task SubmitPartAsync(byte[] bytes, CancellationToken cancellationToken)
        {
            if (bytes.Length == 0)
            {
                return;
            }
            await _inflight.WaitAsync(cancellationToken).ConfigureAwait(false);
            var partNumber = _nextPart++;
            async Task<MediaCompletedPart> UploadAsync()
            {
                try
                {
                    return await _owner._scheduler.RunAsync(() => _owner._storage.UploadPartAsync(
                        _upload, partNumber, bytes, CancellationToken.None)).ConfigureAwait(false);
                }
                finally
                {
                    _inflight.Release();
                }
            }
            _parts.Add(UploadAsync());
        }
    }
}

public sealed class HttpMediaCaptureCleanupService(IServiceScopeFactory scopeFactory,
    IOptions<MediaCaptureOptions> options, ILogger<HttpMediaCaptureCleanupService> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var delay = TimeSpan.FromMilliseconds(Math.Max(1_000, options.Value.CleanupIntervalMs));
        using var timer = new PeriodicTimer(delay);
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<HttpMediaCaptureService>()
                    .CleanupExpiredAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "HTTP media capture cleanup failed");
            }
        }
    }
}
