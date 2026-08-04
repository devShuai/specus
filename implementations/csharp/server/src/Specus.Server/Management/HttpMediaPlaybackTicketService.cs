using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Data.Entities;

namespace Specus.Server.Management;

public sealed class HttpMediaPlaybackTicketService : BackgroundService
{
    private readonly ConcurrentDictionary<string, Ticket> _tickets = new(StringComparer.Ordinal);
    private readonly MediaCaptureOptions _options;
    private readonly TimeProvider _timeProvider;

    public HttpMediaPlaybackTicketService(IOptions<MediaCaptureOptions> options,
        TimeProvider timeProvider)
        : this(options.Value, timeProvider)
    {
    }

    internal HttpMediaPlaybackTicketService(MediaCaptureOptions options, TimeProvider timeProvider)
    {
        _options = options;
        _timeProvider = timeProvider;
    }

    public async Task<HttpMediaPlaybackTicketView> CreateAsync(HttpMediaCapture capture,
        HttpMediaPlaybackService playbackService, bool backfillMissing,
        CancellationToken cancellationToken)
    {
        if (capture.State != HttpMediaCaptureService.StateComplete)
        {
            throw new InvalidOperationException("媒体采集尚未完成");
        }
        if (capture.MediaKind == HttpMediaManifestSupport.MediaSegment
            || capture.InitializationSegment)
        {
            throw new InvalidOperationException("媒体分段不能独立创建播放会话");
        }
        HttpMediaPlaybackService.PlaybackCacheLayout? layout = null;
        if (!HttpMediaManifestSupport.IsManifest(capture.MediaKind))
        {
            var availability = await playbackService.AvailabilityAsync(capture, cancellationToken)
                .ConfigureAwait(false);
            if (!availability.Playable && capture.CapturedBytes <= 0)
            {
                throw new InvalidOperationException(availability.Reason);
            }
            layout = await playbackService.CacheLayoutAsync(capture, cancellationToken)
                .ConfigureAwait(false);
        }
        var token = Base64Url(RandomNumberGenerator.GetBytes(32));
        var expiresAt = _timeProvider.GetUtcNow()
            .AddSeconds(Math.Max(60, _options.PlaybackTicketTtlSeconds));
        _tickets[token] = new Ticket(capture.Id, capture.TenantId, expiresAt, backfillMissing);
        var basePath = "/api/public/media-playback/" + token;
        var totalBytes = layout?.TotalBytes ?? 0;
        long? initialStart = null;
        long? initialEnd = null;
        if (layout is not null && capture.CapturedBytes > 0 && totalBytes > 0)
        {
            var start = capture.ContentRangeStart ?? 0;
            var end = capture.ContentRangeEnd ?? start + capture.CapturedBytes - 1;
            initialStart = Math.Max(0, Math.Min(start, totalBytes - 1));
            initialEnd = Math.Max(initialStart.Value, Math.Min(end, totalBytes - 1));
        }
        return new HttpMediaPlaybackTicketView(token, capture.MediaKind,
            basePath + "/play", basePath + "/manifest", totalBytes, initialStart, initialEnd,
            layout?.CachedRanges ?? [], backfillMissing, expiresAt.ToString("O"));
    }

    public ResolvedTicket Resolve(string token)
    {
        Ticket? ticket = null;
        if (string.IsNullOrWhiteSpace(token) || !_tickets.TryGetValue(token, out ticket)
            || ticket.ExpiresAt < _timeProvider.GetUtcNow())
        {
            if (ticket is not null)
            {
                _tickets.TryRemove(new KeyValuePair<string, Ticket>(token, ticket));
            }
            throw new ArgumentException("媒体播放票据无效或已过期");
        }
        return new ResolvedTicket(token, ticket.CaptureId, ticket.TenantId, ticket.ExpiresAt,
            ticket.BackfillMissing);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            var now = _timeProvider.GetUtcNow();
            foreach (var entry in _tickets)
            {
                if (entry.Value.ExpiresAt < now)
                {
                    _tickets.TryRemove(entry);
                }
            }
        }
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes)
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed record Ticket(long CaptureId, string TenantId, DateTimeOffset ExpiresAt,
        bool BackfillMissing);

    public sealed record ResolvedTicket(string Token, long CaptureId, string TenantId,
        DateTimeOffset ExpiresAt, bool BackfillMissing)
    {
        public string AssetBasePath => "/api/public/media-playback/" + Token + "/asset";
    }
}
