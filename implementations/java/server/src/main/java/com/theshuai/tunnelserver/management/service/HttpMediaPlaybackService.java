package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.HttpMediaCapture;
import com.theshuai.tunnelserver.management.security.ManagementContext;
import com.theshuai.tunnelserver.management.storage.media.RustFsMediaStorage;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

import org.springframework.stereotype.Service;

@Service
public class HttpMediaPlaybackService {
    private final HttpMediaCaptureService captureService;
    private final RustFsMediaStorage storage;

    public HttpMediaPlaybackService(HttpMediaCaptureService captureService,
                                    RustFsMediaStorage storage) {
        this.captureService = captureService;
        this.storage = storage;
    }

    public PlaybackPlan plan(ManagementContext context, long captureId, String rangeHeader) {
        HttpMediaCapture anchor = captureService.requireAccessible(context, captureId);
        return plan(anchor, rangeHeader);
    }

    public PlaybackPlan plan(HttpMediaCapture anchor, String rangeHeader) {
        if (!HttpMediaCaptureService.STATE_COMPLETE.equals(anchor.getState())) {
            throw new IllegalStateException("媒体采集尚未完成");
        }
        List<HttpMediaCapture> captures = usableCaptures(
                captureService.completeResourceCaptures(anchor));
        if (captures.isEmpty()) {
            throw new IllegalStateException("媒体采集没有可回放的数据");
        }

        long totalBytes = totalBytes(captures);
        boolean rangeRequested = rangeHeader != null && !rangeHeader.isBlank();
        if (!rangeRequested && !evaluateCoverage(captures).playable()) {
            throw new MediaRangeException(
                    "媒体仅缓存部分区间，请使用 bytes Range 请求", totalBytes);
        }
        RequestedRange requested = parseRange(rangeHeader, totalBytes);
        long availableEnd = contiguousAvailableEnd(
                captures, requested.start(), requested.end(), totalBytes);
        List<PlaybackSlice> slices = slices(
                captures, requested.start(), availableEnd, totalBytes);
        String contentType = firstText(anchor.getContentType(), "application/octet-stream");
        String contentEncoding = anchor.getContentEncoding();
        String etag = firstText(anchor.getEntityTag(), anchor.getObjectEtag());
        return new PlaybackPlan(
                anchor,
                contentType,
                contentEncoding,
                etag,
                totalBytes,
                requested.start(),
                availableEnd,
                rangeRequested,
                slices);
    }

    public PlaybackAvailability availability(HttpMediaCapture anchor) {
        if (!HttpMediaCaptureService.STATE_COMPLETE.equals(anchor.getState())) {
            return new PlaybackAvailability(false, 0, "媒体采集尚未完成");
        }
        return evaluateCoverage(captureService.completeResourceCaptures(anchor));
    }

    static PlaybackAvailability evaluateCoverage(List<HttpMediaCapture> captures) {
        List<HttpMediaCapture> usable = usableCaptures(captures);
        if (usable.isEmpty()) {
            return new PlaybackAvailability(false, 0, "媒体采集没有可回放的数据");
        }
        long totalBytes = totalBytes(usable);
        if (totalBytes <= 0) {
            return new PlaybackAvailability(false, 0, "媒体总长度未知");
        }
        long cursor = 0;
        while (cursor < totalBytes) {
            long selectedEnd = -1;
            for (HttpMediaCapture capture : usable) {
                long captureStart = normalizedStart(capture);
                long captureEnd = normalizedEnd(capture);
                if (captureStart <= cursor && captureEnd >= cursor && captureEnd > selectedEnd) {
                    selectedEnd = captureEnd;
                }
            }
            if (selectedEnd < cursor) {
                return new PlaybackAvailability(
                        false, totalBytes, "采集数据不完整，缺少字节 " + cursor);
            }
            if (selectedEnd >= totalBytes - 1) {
                return new PlaybackAvailability(true, totalBytes, null);
            }
            cursor = selectedEnd + 1;
        }
        return new PlaybackAvailability(true, totalBytes, null);
    }

    private long contiguousAvailableEnd(List<HttpMediaCapture> captures,
                                        long start,
                                        long requestedEnd,
                                        long totalBytes) {
        long cursor = start;
        long availableEnd = start - 1;
        while (cursor <= requestedEnd) {
            long selectedEnd = -1;
            for (HttpMediaCapture capture : captures) {
                long captureStart = normalizedStart(capture);
                long captureEnd = normalizedEnd(capture);
                if (captureStart <= cursor && captureEnd >= cursor && captureEnd > selectedEnd) {
                    selectedEnd = captureEnd;
                }
            }
            if (selectedEnd < cursor) {
                if (availableEnd < start) {
                    throw new MediaRangeException(
                            "请求位置尚未缓存，缺少字节 " + cursor, totalBytes);
                }
                break;
            }
            availableEnd = Math.min(requestedEnd, selectedEnd);
            cursor = availableEnd + 1;
        }
        return availableEnd;
    }

    public void stream(PlaybackPlan plan, OutputStream output) throws IOException {
        byte[] buffer = new byte[64 * 1024];
        for (PlaybackSlice slice : plan.slices()) {
            long remaining = slice.objectEnd() - slice.objectStart() + 1;
            try (ResponseInputStream<GetObjectResponse> input = storage.open(
                    slice.capture().getObjectKey(), slice.objectStart(), slice.objectEnd())) {
                while (remaining > 0) {
                    int read = input.read(buffer, 0, (int) Math.min(buffer.length, remaining));
                    if (read < 0) {
                        throw new IOException("RustFS 对象提前结束: " + slice.capture().getObjectKey());
                    }
                    output.write(buffer, 0, read);
                    remaining -= read;
                }
            }
        }
    }

    private List<PlaybackSlice> slices(List<HttpMediaCapture> captures,
                                       long start,
                                       long end,
                                       long totalBytes) {
        List<PlaybackSlice> result = new ArrayList<>();
        long cursor = start;
        while (cursor <= end) {
            HttpMediaCapture selected = null;
            long selectedEnd = -1;
            for (HttpMediaCapture capture : captures) {
                long captureStart = normalizedStart(capture);
                long captureEnd = normalizedEnd(capture);
                if (captureStart <= cursor && captureEnd >= cursor && captureEnd > selectedEnd) {
                    selected = capture;
                    selectedEnd = captureEnd;
                }
            }
            if (selected == null) {
                throw new MediaRangeException(
                        "采集数据存在空洞，缺少字节 " + cursor, totalBytes);
            }
            long logicalEnd = Math.min(end, selectedEnd);
            long captureStart = normalizedStart(selected);
            result.add(new PlaybackSlice(
                    selected,
                    cursor,
                    logicalEnd,
                    cursor - captureStart,
                    logicalEnd - captureStart));
            cursor = logicalEnd + 1;
        }
        return result;
    }

    private RequestedRange parseRange(String rangeHeader, long totalBytes) {
        if (totalBytes <= 0) {
            throw new MediaRangeException("媒体总长度未知", totalBytes);
        }
        if (rangeHeader == null || rangeHeader.isBlank()) {
            return new RequestedRange(0, totalBytes - 1);
        }
        String normalized = rangeHeader.trim().toLowerCase(Locale.ROOT);
        if (!normalized.startsWith("bytes=") || normalized.indexOf(',') >= 0) {
            throw new MediaRangeException("仅支持单一 bytes Range", totalBytes);
        }
        String value = normalized.substring("bytes=".length()).trim();
        int separator = value.indexOf('-');
        if (separator < 0) {
            throw new MediaRangeException("Range 格式无效", totalBytes);
        }
        String startText = value.substring(0, separator).trim();
        String endText = value.substring(separator + 1).trim();
        try {
            long start;
            long end;
            if (startText.isEmpty()) {
                long suffixLength = Long.parseLong(endText);
                if (suffixLength <= 0) {
                    throw new MediaRangeException("Range 后缀长度无效", totalBytes);
                }
                start = Math.max(0, totalBytes - suffixLength);
                end = totalBytes - 1;
            } else {
                start = Long.parseLong(startText);
                end = endText.isEmpty() ? totalBytes - 1 : Long.parseLong(endText);
            }
            if (start < 0 || start >= totalBytes || end < start) {
                throw new MediaRangeException("Range 超出媒体范围", totalBytes);
            }
            return new RequestedRange(start, Math.min(end, totalBytes - 1));
        } catch (NumberFormatException exception) {
            throw new MediaRangeException("Range 格式无效", totalBytes);
        }
    }

    private static List<HttpMediaCapture> usableCaptures(List<HttpMediaCapture> captures) {
        return captures.stream()
                .filter(HttpMediaPlaybackService::hasUsableRange)
                .sorted(Comparator.comparing(HttpMediaCapture::getId).reversed())
                .toList();
    }

    private static long totalBytes(List<HttpMediaCapture> captures) {
        long total = captures.stream()
                .map(HttpMediaCapture::getTotalBytes)
                .filter(value -> value != null && value > 0)
                .mapToLong(Long::longValue)
                .max()
                .orElse(0);
        if (total > 0) {
            return total;
        }
        return captures.stream().mapToLong(capture -> normalizedEnd(capture) + 1).max().orElse(0);
    }

    private static boolean hasUsableRange(HttpMediaCapture capture) {
        return capture.getCapturedBytes() > 0 && normalizedEnd(capture) >= normalizedStart(capture);
    }

    private static long normalizedStart(HttpMediaCapture capture) {
        return capture.getContentRangeStart() == null ? 0 : capture.getContentRangeStart();
    }

    private static long normalizedEnd(HttpMediaCapture capture) {
        if (capture.getContentRangeEnd() != null) {
            return capture.getContentRangeEnd();
        }
        return normalizedStart(capture) + capture.getCapturedBytes() - 1;
    }

    private String firstText(String first, String second) {
        return first == null || first.isBlank() ? second : first;
    }

    public record PlaybackPlan(
            HttpMediaCapture anchor,
            String contentType,
            String contentEncoding,
            String etag,
            long totalBytes,
            long start,
            long end,
            boolean partial,
            List<PlaybackSlice> slices
    ) {
        public long contentLength() {
            return end - start + 1;
        }
    }

    public record PlaybackSlice(
            HttpMediaCapture capture,
            long logicalStart,
            long logicalEnd,
            long objectStart,
            long objectEnd
    ) {
    }

    public record PlaybackAvailability(
            boolean playable,
            long totalBytes,
            String reason
    ) {
    }

    private record RequestedRange(long start, long end) {
    }

    public static final class MediaRangeException extends IllegalArgumentException {
        private final long totalBytes;

        public MediaRangeException(String message) {
            this(message, 0);
        }

        public MediaRangeException(String message, long totalBytes) {
            super(message);
            this.totalBytes = totalBytes;
        }

        public long totalBytes() {
            return totalBytes;
        }
    }
}
