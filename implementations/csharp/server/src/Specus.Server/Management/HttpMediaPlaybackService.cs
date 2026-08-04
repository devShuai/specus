using Specus.Server.Data.Entities;

namespace Specus.Server.Management;

public sealed class HttpMediaPlaybackService(HttpMediaCaptureService captureService,
    IHttpMediaStorage storage)
{
    public async Task<PlaybackPlan> PlanAsync(HttpMediaCapture anchor, string? rangeHeader,
        CancellationToken cancellationToken)
    {
        if (anchor.State != HttpMediaCaptureService.StateComplete)
        {
            throw new InvalidOperationException("媒体采集尚未完成");
        }
        var captures = Usable(await captureService.CompleteResourceCapturesAsync(anchor,
            cancellationToken).ConfigureAwait(false));
        if (captures.Count == 0)
        {
            throw new InvalidOperationException("媒体采集没有可回放的数据");
        }
        var totalBytes = TotalBytes(captures);
        var rangeRequested = !string.IsNullOrWhiteSpace(rangeHeader);
        var coverage = EvaluateCoverage(captures);
        var requested = !rangeRequested && !coverage.Playable
            ? InitialSparseRange(anchor, captures, totalBytes)
            : ParseRange(rangeHeader, totalBytes);
        var availableEnd = ContiguousAvailableEnd(captures, requested.Start, requested.End,
            totalBytes);
        var slices = Slices(captures, requested.Start, availableEnd, totalBytes);
        return new PlaybackPlan(anchor,
            string.IsNullOrWhiteSpace(anchor.ContentType) ? "application/octet-stream" : anchor.ContentType,
            anchor.ContentEncoding,
            string.IsNullOrWhiteSpace(anchor.EntityTag) ? anchor.ObjectEtag : anchor.EntityTag,
            totalBytes, requested.Start, availableEnd,
            rangeRequested || requested.Start > 0 || availableEnd < totalBytes - 1, slices);
    }

    public async Task<PlaybackCacheLayout> CacheLayoutAsync(HttpMediaCapture anchor,
        CancellationToken cancellationToken)
    {
        if (anchor.State != HttpMediaCaptureService.StateComplete)
        {
            throw new InvalidOperationException("媒体采集尚未完成");
        }
        var captures = Usable(await captureService.CompleteResourceCapturesAsync(anchor,
            cancellationToken).ConfigureAwait(false));
        var totalBytes = TotalBytes(captures);
        return new PlaybackCacheLayout(totalBytes, MergeAvailableRanges(captures, totalBytes));
    }

    public async Task<PlaybackAvailability> AvailabilityAsync(HttpMediaCapture anchor,
        CancellationToken cancellationToken)
    {
        if (anchor.State != HttpMediaCaptureService.StateComplete)
        {
            return new PlaybackAvailability(false, 0, "媒体采集尚未完成");
        }
        return EvaluateCoverage(await captureService.CompleteResourceCapturesAsync(anchor,
            cancellationToken).ConfigureAwait(false));
    }

    internal static PlaybackAvailability EvaluateCoverage(IReadOnlyList<HttpMediaCapture> captures)
    {
        var usable = Usable(captures);
        if (usable.Count == 0)
        {
            return new PlaybackAvailability(false, 0, "媒体采集没有可回放的数据");
        }
        var totalBytes = TotalBytes(usable);
        if (totalBytes <= 0)
        {
            return new PlaybackAvailability(false, 0, "媒体总长度未知");
        }
        long cursor = 0;
        while (cursor < totalBytes)
        {
            long selectedEnd = -1;
            foreach (var capture in usable)
            {
                var captureStart = NormalizedStart(capture);
                var captureEnd = NormalizedEnd(capture);
                if (captureStart <= cursor && captureEnd >= cursor && captureEnd > selectedEnd)
                {
                    selectedEnd = captureEnd;
                }
            }
            if (selectedEnd < cursor)
            {
                return new PlaybackAvailability(false, totalBytes, $"采集数据不完整，缺少字节 {cursor}");
            }
            if (selectedEnd >= totalBytes - 1)
            {
                return new PlaybackAvailability(true, totalBytes, null);
            }
            cursor = selectedEnd + 1;
        }
        return new PlaybackAvailability(true, totalBytes, null);
    }

    public async Task StreamAsync(PlaybackPlan plan, Stream output,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[64 * 1024];
        foreach (var slice in plan.Slices)
        {
            var remaining = slice.ObjectEnd - slice.ObjectStart + 1;
            await using var input = await storage.OpenReadAsync(slice.Capture.ObjectKey,
                slice.ObjectStart, slice.ObjectEnd, cancellationToken).ConfigureAwait(false);
            while (remaining > 0)
            {
                var read = await input.ReadAsync(buffer.AsMemory(0,
                    checked((int)Math.Min(buffer.Length, remaining))), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    throw new IOException($"RustFS 对象提前结束: {slice.Capture.ObjectKey}");
                }
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                    .ConfigureAwait(false);
                remaining -= read;
            }
        }
    }

    private static long ContiguousAvailableEnd(IReadOnlyList<HttpMediaCapture> captures,
        long start, long requestedEnd, long totalBytes)
    {
        var cursor = start;
        var availableEnd = start - 1;
        while (cursor <= requestedEnd)
        {
            long selectedEnd = -1;
            foreach (var capture in captures)
            {
                var captureStart = NormalizedStart(capture);
                var captureEnd = NormalizedEnd(capture);
                if (captureStart <= cursor && captureEnd >= cursor && captureEnd > selectedEnd)
                {
                    selectedEnd = captureEnd;
                }
            }
            if (selectedEnd < cursor)
            {
                if (availableEnd < start)
                {
                    throw new MediaRangeException($"请求位置尚未缓存，缺少字节 {cursor}", totalBytes);
                }
                break;
            }
            availableEnd = Math.Min(requestedEnd, selectedEnd);
            cursor = availableEnd + 1;
        }
        return availableEnd;
    }

    private static RequestedRange InitialSparseRange(HttpMediaCapture anchor,
        IReadOnlyList<HttpMediaCapture> captures, long totalBytes)
    {
        if (totalBytes <= 0)
        {
            throw new MediaRangeException("媒体总长度未知", totalBytes);
        }
        var anchorStart = NormalizedStart(anchor);
        var anchorEnd = NormalizedEnd(anchor);
        if (anchorStart >= 0 && anchorStart < totalBytes && anchorEnd >= anchorStart
            && captures.Any(capture => NormalizedStart(capture) <= anchorStart
                                       && NormalizedEnd(capture) >= anchorStart))
        {
            return new RequestedRange(anchorStart, Math.Min(anchorEnd, totalBytes - 1));
        }
        var first = MergeAvailableRanges(captures, totalBytes).FirstOrDefault()
                    ?? throw new MediaRangeException("媒体采集没有可回放的数据", totalBytes);
        return new RequestedRange(first.Start, first.End);
    }

    private static List<PlaybackSlice> Slices(IReadOnlyList<HttpMediaCapture> captures,
        long start, long end, long totalBytes)
    {
        var result = new List<PlaybackSlice>();
        var cursor = start;
        while (cursor <= end)
        {
            HttpMediaCapture? selected = null;
            long selectedEnd = -1;
            foreach (var capture in captures)
            {
                var captureStart = NormalizedStart(capture);
                var captureEnd = NormalizedEnd(capture);
                if (captureStart <= cursor && captureEnd >= cursor && captureEnd > selectedEnd)
                {
                    selected = capture;
                    selectedEnd = captureEnd;
                }
            }
            if (selected is null)
            {
                throw new MediaRangeException($"采集数据存在空洞，缺少字节 {cursor}", totalBytes);
            }
            var logicalEnd = Math.Min(end, selectedEnd);
            var selectedStart = NormalizedStart(selected);
            result.Add(new PlaybackSlice(selected, cursor, logicalEnd, cursor - selectedStart,
                logicalEnd - selectedStart));
            cursor = logicalEnd + 1;
        }
        return result;
    }

    private static RequestedRange ParseRange(string? rangeHeader, long totalBytes)
    {
        if (totalBytes <= 0)
        {
            throw new MediaRangeException("媒体总长度未知", totalBytes);
        }
        if (string.IsNullOrWhiteSpace(rangeHeader))
        {
            return new RequestedRange(0, totalBytes - 1);
        }
        var normalized = rangeHeader.Trim().ToLowerInvariant();
        if (!normalized.StartsWith("bytes=", StringComparison.Ordinal) || normalized.Contains(','))
        {
            throw new MediaRangeException("仅支持单一 bytes Range", totalBytes);
        }
        var value = normalized["bytes=".Length..].Trim();
        var separator = value.IndexOf('-');
        if (separator < 0)
        {
            throw new MediaRangeException("Range 格式无效", totalBytes);
        }
        var startText = value[..separator].Trim();
        var endText = value[(separator + 1)..].Trim();
        long start;
        long end = 0;
        if (startText.Length == 0)
        {
            if (!long.TryParse(endText, out var suffixLength) || suffixLength <= 0)
            {
                throw new MediaRangeException("Range 后缀长度无效", totalBytes);
            }
            start = Math.Max(0, totalBytes - suffixLength);
            end = totalBytes - 1;
        }
        else if (!long.TryParse(startText, out start)
                 || endText.Length > 0 && !long.TryParse(endText, out end))
        {
            throw new MediaRangeException("Range 格式无效", totalBytes);
        }
        else
        {
            end = endText.Length == 0 ? totalBytes - 1 : end;
        }
        if (start < 0 || start >= totalBytes || end < start)
        {
            throw new MediaRangeException("Range 超出媒体范围", totalBytes);
        }
        return new RequestedRange(start, Math.Min(end, totalBytes - 1));
    }

    private static List<HttpMediaCapture> Usable(IEnumerable<HttpMediaCapture> captures) =>
        captures.Where(capture => capture.CapturedBytes > 0
                                  && NormalizedEnd(capture) >= NormalizedStart(capture))
            .OrderByDescending(capture => capture.Id).ToList();

    private static long TotalBytes(IEnumerable<HttpMediaCapture> captures)
    {
        var rows = captures.ToList();
        var total = rows.Where(capture => capture.TotalBytes > 0)
            .Select(capture => capture.TotalBytes!.Value).DefaultIfEmpty().Max();
        return total > 0 ? total : rows.Select(capture => NormalizedEnd(capture) + 1)
            .DefaultIfEmpty().Max();
    }

    private static List<PlaybackByteRange> MergeAvailableRanges(
        IReadOnlyList<HttpMediaCapture> captures, long totalBytes)
    {
        if (totalBytes <= 0)
        {
            return [];
        }
        var sorted = captures.Select(capture => new PlaybackByteRange(
                Math.Max(0, NormalizedStart(capture)), Math.Min(totalBytes - 1, NormalizedEnd(capture))))
            .Where(range => range.End >= range.Start).OrderBy(range => range.Start)
            .ThenBy(range => range.End).ToList();
        if (sorted.Count == 0)
        {
            return [];
        }
        var merged = new List<PlaybackByteRange>();
        var current = sorted[0];
        foreach (var next in sorted.Skip(1))
        {
            if (next.Start <= current.End + 1)
            {
                current = new PlaybackByteRange(current.Start, Math.Max(current.End, next.End));
            }
            else
            {
                merged.Add(current);
                current = next;
            }
        }
        merged.Add(current);
        return merged;
    }

    private static long NormalizedStart(HttpMediaCapture capture) => capture.ContentRangeStart ?? 0;
    private static long NormalizedEnd(HttpMediaCapture capture) => capture.ContentRangeEnd
        ?? NormalizedStart(capture) + capture.CapturedBytes - 1;

    public sealed record PlaybackPlan(HttpMediaCapture Anchor, string ContentType,
        string? ContentEncoding, string? Etag, long TotalBytes, long Start, long End, bool Partial,
        IReadOnlyList<PlaybackSlice> Slices)
    {
        public long ContentLength => End - Start + 1;
    }

    public sealed record PlaybackSlice(HttpMediaCapture Capture, long LogicalStart, long LogicalEnd,
        long ObjectStart, long ObjectEnd);
    public sealed record PlaybackAvailability(bool Playable, long TotalBytes, string? Reason);
    public sealed record PlaybackCacheLayout(long TotalBytes, IReadOnlyList<PlaybackByteRange> CachedRanges);
    private sealed record RequestedRange(long Start, long End);

    public sealed class MediaRangeException(string message, long totalBytes = 0)
        : ArgumentException(message)
    {
        public long TotalBytes { get; } = totalBytes;
    }
}
