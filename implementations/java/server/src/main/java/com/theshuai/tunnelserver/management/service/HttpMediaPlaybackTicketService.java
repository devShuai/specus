package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.config.MediaCaptureProperties;
import com.theshuai.tunnelserver.management.model.HttpMediaCapture;
import com.theshuai.tunnelserver.management.repository.HttpMediaCaptureRepository;
import com.theshuai.tunnelserver.management.security.ManagementContext;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class HttpMediaPlaybackTicketService {
    private final HttpMediaCaptureService captureService;
    private final HttpMediaPlaybackService playbackService;
    private final HttpMediaCaptureRepository captureRepository;
    private final MediaCaptureProperties properties;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Ticket> tickets = new ConcurrentHashMap<>();

    public HttpMediaPlaybackTicketService(HttpMediaCaptureService captureService,
                                          HttpMediaPlaybackService playbackService,
                                          HttpMediaCaptureRepository captureRepository,
                                          MediaCaptureProperties properties) {
        this.captureService = captureService;
        this.playbackService = playbackService;
        this.captureRepository = captureRepository;
        this.properties = properties;
    }

    public PlaybackTicketView create(ManagementContext context, long captureId) {
        return create(context, captureId, false);
    }

    public PlaybackTicketView create(ManagementContext context,
                                     long captureId,
                                     boolean backfillMissing) {
        HttpMediaCapture capture = captureService.requireAccessible(context, captureId);
        if (!HttpMediaCaptureService.STATE_COMPLETE.equals(capture.getState())) {
            throw new IllegalStateException("媒体采集尚未完成");
        }
        if (HttpMediaManifestSupport.MEDIA_SEGMENT.equals(capture.getMediaKind())
                || capture.isInitializationSegment()) {
            throw new IllegalStateException("媒体分段不能独立创建播放会话");
        }
        HttpMediaPlaybackService.PlaybackCacheLayout cacheLayout = null;
        if (!isManifest(capture)) {
            HttpMediaPlaybackService.PlaybackAvailability availability =
                    playbackService.availability(capture);
            if (!availability.playable() && capture.getCapturedBytes() <= 0) {
                throw new IllegalStateException(availability.reason());
            }
            cacheLayout = playbackService.cacheLayout(capture);
        }
        byte[] tokenBytes = new byte[32];
        random.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        Instant expiresAt = Instant.now().plusSeconds(
                Math.max(60, properties.getPlaybackTicketTtlSeconds()));
        tickets.put(token, new Ticket(
                capture.getId(), capture.getTenantId(), expiresAt, backfillMissing));
        String base = "/api/public/media-playback/" + token;
        long totalBytes = cacheLayout == null ? 0 : cacheLayout.totalBytes();
        Long initialRangeStart = null;
        Long initialRangeEnd = null;
        if (cacheLayout != null && capture.getCapturedBytes() > 0 && totalBytes > 0) {
            long start = capture.getContentRangeStart() == null
                    ? 0 : capture.getContentRangeStart();
            long end = capture.getContentRangeEnd() == null
                    ? start + capture.getCapturedBytes() - 1
                    : capture.getContentRangeEnd();
            initialRangeStart = Math.max(0, Math.min(start, totalBytes - 1));
            initialRangeEnd = Math.max(
                    initialRangeStart,
                    Math.min(end, totalBytes - 1));
        }
        return new PlaybackTicketView(
                token,
                capture.getMediaKind(),
                base + "/play",
                base + "/manifest",
                totalBytes,
                initialRangeStart,
                initialRangeEnd,
                cacheLayout == null ? List.of() : cacheLayout.cachedRanges(),
                backfillMissing,
                expiresAt.toString());
    }

    public ResolvedTicket resolve(String token) {
        Ticket ticket = tickets.get(token);
        if (ticket == null || ticket.expiresAt().isBefore(Instant.now())) {
            if (ticket != null) {
                tickets.remove(token, ticket);
            }
            throw new IllegalArgumentException("媒体播放票据无效或已过期");
        }
        HttpMediaCapture capture = captureRepository
                .findByIdAndTenantId(ticket.captureId(), ticket.tenantId())
                .orElseThrow(() -> new IllegalArgumentException("媒体采集记录不存在"));
        return new ResolvedTicket(
                token, capture, ticket.expiresAt(), ticket.backfillMissing());
    }

    @Scheduled(fixedDelay = 60_000L)
    public void cleanup() {
        Instant now = Instant.now();
        tickets.entrySet().removeIf(entry -> entry.getValue().expiresAt().isBefore(now));
    }

    private record Ticket(
            long captureId,
            String tenantId,
            Instant expiresAt,
            boolean backfillMissing
    ) {
    }

    public record ResolvedTicket(
            String token,
            HttpMediaCapture capture,
            Instant expiresAt,
            boolean backfillMissing
    ) {
        public String assetBasePath() {
            return "/api/public/media-playback/" + token + "/asset";
        }
    }

    public record PlaybackTicketView(
            String ticket,
            String mediaKind,
            String playUrl,
            String manifestUrl,
            long totalBytes,
            Long initialRangeStart,
            Long initialRangeEnd,
            List<HttpMediaPlaybackService.PlaybackByteRange> cachedRanges,
            boolean backfillMissing,
            String expiresAt
    ) {
    }

    private boolean isManifest(HttpMediaCapture capture) {
        return HttpMediaManifestSupport.HLS_MANIFEST.equals(capture.getMediaKind())
                || HttpMediaManifestSupport.DASH_MANIFEST.equals(capture.getMediaKind());
    }
}
