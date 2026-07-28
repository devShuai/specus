package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.MediaCaptureProperties;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.HttpBodyDataCodec;
import com.theshuai.specusserver.management.model.HttpMediaCapture;
import com.theshuai.specusserver.management.model.HttpMediaCaptureView;
import com.theshuai.specusserver.management.model.HttpMediaReference;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.HttpMediaCaptureRepository;
import com.theshuai.specusserver.management.repository.HttpMediaReferenceRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.storage.media.RustFsMediaStorage;
import com.theshuai.specusserver.management.storage.media.RustFsMediaStorage.MultipartUpload;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.s3.model.CompletedPart;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

@Service
@Slf4j
public class HttpMediaCaptureService {
    public static final String STATE_STARTING = "STARTING";
    public static final String STATE_CAPTURING = "CAPTURING";
    public static final String STATE_COMPLETE = "COMPLETE";
    public static final String STATE_INCOMPLETE = "INCOMPLETE";
    public static final String STATE_FAILED = "FAILED";
    private static final Pattern SENSITIVE_QUERY_PARAMETER = Pattern.compile(
            "(?i)([?&](?:api_?key|access_token|auth_token|token|x-emby-token)=)[^&#]*");

    private final MediaCaptureProperties properties;
    private final RustFsMediaStorage storage;
    private final ClientAccountService clientAccountService;
    private final ClientAccountRepository clientAccountRepository;
    private final HttpRouteMappingRepository routeRepository;
    private final HttpMediaCaptureRepository captureRepository;
    private final HttpMediaReferenceRepository referenceRepository;
    private final ThreadPoolExecutor uploadExecutor;

    public HttpMediaCaptureService(MediaCaptureProperties properties,
                                   RustFsMediaStorage storage,
                                   ClientAccountService clientAccountService,
                                   ClientAccountRepository clientAccountRepository,
                                   HttpRouteMappingRepository routeRepository,
                                   HttpMediaCaptureRepository captureRepository,
                                   HttpMediaReferenceRepository referenceRepository) {
        this.properties = properties;
        this.storage = storage;
        this.clientAccountService = clientAccountService;
        this.clientAccountRepository = clientAccountRepository;
        this.routeRepository = routeRepository;
        this.captureRepository = captureRepository;
        this.referenceRepository = referenceRepository;
        int threads = properties.normalizedUploadThreads();
        int queueCapacity = Math.max(threads, threads * properties.normalizedMaxInflightParts() * 4);
        this.uploadExecutor = new ThreadPoolExecutor(
                threads,
                threads,
                30,
                TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(queueCapacity),
                new MediaThreadFactory(),
                new ThreadPoolExecutor.CallerRunsPolicy());
        this.uploadExecutor.allowCoreThreadTimeOut(true);
    }

    public CaptureSession open(String clientName,
                               String route,
                               String method,
                               String sourceUrl,
                               int statusCode,
                               List<String> responseHeaders) {
        if (!storage.isReady() || "HEAD".equalsIgnoreCase(method)) {
            return CaptureSession.noop();
        }
        String normalizedSourceUrl = HttpMediaManifestSupport.normalizeSourceUrl(sourceUrl);
        String contentType = headerValue(responseHeaders, "content-type");
        String contentEncoding = headerValue(responseHeaders, "content-encoding");
        String contentRangeValue = headerValue(responseHeaders, "content-range");
        String kind = HttpMediaManifestSupport.classify(
                normalizedSourceUrl, contentType, statusCode, contentRangeValue);
        if (kind == null) {
            return CaptureSession.noop();
        }

        ClientAccount account = clientAccountService.findClientByName(clientName).orElse(null);
        if (account == null) {
            return CaptureSession.noop();
        }
        HttpRouteMapping mapping = routeRepository
                .findByTenantIdAndClientIdAndRoute(account.getTenantId(), account.getId(), route)
                .orElse(null);
        if (mapping == null || !Boolean.TRUE.equals(mapping.getMediaCaptureEnabled())) {
            return CaptureSession.noop();
        }

        Instant now = Instant.now();
        String entityTag = headerValue(responseHeaders, "etag");
        String lastModified = headerValue(responseHeaders, "last-modified");
        HttpMediaManifestSupport.ContentRange contentRange =
                HttpMediaManifestSupport.parseContentRange(contentRangeValue);
        Long contentLength = positiveLong(headerValue(responseHeaders, "content-length"));
        Long rangeStart;
        Long rangeEnd;
        Long totalBytes;
        long expectedResponseBytes;
        if (contentRange == null) {
            rangeStart = 0L;
            rangeEnd = contentLength == null ? null : contentLength - 1;
            totalBytes = contentLength;
            expectedResponseBytes = contentLength == null ? -1 : contentLength;
        } else {
            rangeStart = contentRange.start();
            rangeEnd = contentRange.end();
            totalBytes = contentRange.total();
            expectedResponseBytes = contentRange.end() - contentRange.start() + 1;
        }

        String normalizedMethod = normalizeMethod(method);
        String storedContentEncoding = cap(contentEncoding, 128);
        String resourceKey = resourceKey(
                account.getTenantId(), account.getId(), route, normalizedSourceUrl, entityTag, lastModified);
        String deduplicationKey = deduplicationKey(
                resourceKey,
                normalizedMethod,
                kind,
                rangeStart,
                rangeEnd,
                totalBytes,
                storedContentEncoding);
        if (deduplicationKey != null && hasReusableCapture(
                account.getTenantId(),
                deduplicationKey,
                resourceKey,
                kind,
                rangeStart,
                rangeEnd,
                totalBytes,
                expectedResponseBytes,
                storedContentEncoding,
                now)) {
            log.debug("[media-capture] skipped duplicate client={} route={} range={}-{} source={}",
                    clientName, route, rangeStart, rangeEnd, normalizedSourceUrl);
            return CaptureSession.externalizedNoop();
        }

        HttpMediaCapture capture = new HttpMediaCapture();
        capture.setTenantId(account.getTenantId());
        capture.setClientId(account.getId());
        capture.setClientName(account.getClientName());
        capture.setRoute(route);
        capture.setResourceId(mapping.getId());
        capture.setSourceUrl(normalizedSourceUrl);
        capture.setResourceKey(resourceKey);
        capture.setDeduplicationKey(deduplicationKey);
        capture.setMethod(normalizedMethod);
        capture.setStatusCode(statusCode);
        capture.setContentType(cap(contentType, 255));
        capture.setContentEncoding(storedContentEncoding);
        capture.setMediaKind(kind);
        capture.setEntityTag(cap(entityTag, 512));
        capture.setLastModified(cap(lastModified, 128));
        capture.setContentRangeStart(rangeStart);
        capture.setContentRangeEnd(rangeEnd);
        capture.setTotalBytes(totalBytes);
        capture.setCapturedBytes(0);
        capture.setSegmentSequence(HttpMediaManifestSupport.inferSequence(normalizedSourceUrl));
        capture.setInitializationSegment(HttpMediaManifestSupport.isInitializationSegment(normalizedSourceUrl));
        capture.setLiveStream(false);
        capture.setObjectKey(objectKey(account.getTenantId(), route, normalizedSourceUrl));
        capture.setState(STATE_STARTING);
        capture.setResponseHeaders(joinHeaders(responseHeaders));
        capture.setCapturedAt(now.toString());
        capture.setExpiresAt(now.plusSeconds(Math.max(60, properties.getRetentionSeconds())).toString());
        HttpMediaCapture saved;
        try {
            saved = captureRepository.saveAndFlush(capture);
        } catch (DataIntegrityViolationException exception) {
            HttpMediaCapture concurrent = deduplicationKey == null ? null
                    : captureRepository.findByTenantIdAndDeduplicationKey(
                            account.getTenantId(), deduplicationKey).orElse(null);
            if (concurrent != null
                    && isReusableCapture(
                            concurrent, rangeStart, rangeEnd, expectedResponseBytes, Instant.now())) {
                log.debug("[media-capture] concurrent duplicate skipped client={} route={} range={}-{} source={}",
                        clientName, route, rangeStart, rangeEnd, normalizedSourceUrl);
                return CaptureSession.externalizedNoop();
            }
            throw exception;
        }

        try {
            MultipartUpload upload = storage.beginMultipart(
                    saved.getObjectKey(), saved.getContentType(), saved.getContentEncoding());
            saved.setUploadId(upload.uploadId());
            saved.setState(STATE_CAPTURING);
            captureRepository.saveAndFlush(saved);
            return new ActiveCapture(saved.getId(), upload, kind, expectedResponseBytes);
        } catch (RuntimeException exception) {
            markFailed(saved.getId(), exception);
            log.warn("[media-capture] failed to begin RustFS upload client={} route={} source={}",
                    clientName, route, normalizedSourceUrl, exception);
            return CaptureSession.noop();
        }
    }

    public Page<HttpMediaCaptureView> list(ManagementContext context,
                                           Long clientId,
                                           String route,
                                           Pageable pageable) {
        String normalizedRoute = route == null || route.isBlank() ? null : route.trim();
        if (context.isAdmin()) {
            if (clientId != null && normalizedRoute != null) {
                return captureRepository.findByTenantIdAndClientIdAndRouteOrderByIdDesc(
                        context.tenant().tenantId(), clientId, normalizedRoute, pageable).map(this::toView);
            }
            if (clientId != null) {
                return captureRepository.findByTenantIdAndClientIdOrderByIdDesc(
                        context.tenant().tenantId(), clientId, pageable).map(this::toView);
            }
            if (normalizedRoute != null) {
                return captureRepository.findByTenantIdAndRouteOrderByIdDesc(
                        context.tenant().tenantId(), normalizedRoute, pageable).map(this::toView);
            }
            return captureRepository.findByTenantIdOrderByIdDesc(
                    context.tenant().tenantId(), pageable).map(this::toView);
        }

        List<Long> visibleClientIds = visibleClientIds(context);
        if (visibleClientIds.isEmpty() || (clientId != null && !visibleClientIds.contains(clientId))) {
            return Page.empty(pageable);
        }
        if (clientId != null && normalizedRoute != null) {
            return captureRepository.findByTenantIdAndClientIdAndRouteOrderByIdDesc(
                    context.tenant().tenantId(), clientId, normalizedRoute, pageable).map(this::toView);
        }
        if (clientId != null) {
            return captureRepository.findByTenantIdAndClientIdOrderByIdDesc(
                    context.tenant().tenantId(), clientId, pageable).map(this::toView);
        }
        if (normalizedRoute != null) {
            return captureRepository.findByTenantIdAndClientIdInAndRouteOrderByIdDesc(
                    context.tenant().tenantId(), visibleClientIds, normalizedRoute, pageable).map(this::toView);
        }
        return captureRepository.findByTenantIdAndClientIdInOrderByIdDesc(
                context.tenant().tenantId(), visibleClientIds, pageable).map(this::toView);
    }

    public HttpMediaCapture requireAccessible(ManagementContext context, long id) {
        HttpMediaCapture capture = captureRepository.findByIdAndTenantId(id, context.tenant().tenantId())
                .orElseThrow(() -> new IllegalArgumentException("媒体采集记录不存在"));
        if (!context.isAdmin() && clientAccountRepository.findByIdAndTenantIdAndOwnerUsername(
                capture.getClientId(), context.tenant().tenantId(), context.username()).isEmpty()) {
            throw new IllegalArgumentException("媒体采集记录不存在");
        }
        return capture;
    }

    public HttpMediaCapture latestForSource(HttpMediaCapture anchor, String sourceUrl) {
        String normalized = HttpMediaManifestSupport.normalizeSourceUrl(sourceUrl);
        return captureRepository
                .findByTenantIdAndClientIdAndRouteAndSourceUrlAndStateOrderByIdDesc(
                        anchor.getTenantId(), anchor.getClientId(), anchor.getRoute(), normalized, STATE_COMPLETE)
                .stream()
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("对应媒体分段尚未采集完成"));
    }

    public HttpMediaCapture latestManifest(HttpMediaCapture anchor) {
        return captureRepository
                .findByTenantIdAndClientIdAndRouteAndSourceUrlAndStateOrderByIdDesc(
                        anchor.getTenantId(), anchor.getClientId(), anchor.getRoute(),
                        anchor.getSourceUrl(), STATE_COMPLETE)
                .stream()
                .filter(row -> isManifest(row.getMediaKind()))
                .findFirst()
                .orElse(anchor);
    }

    public String rewrittenManifest(HttpMediaCapture anchor, String assetBasePath) {
        HttpMediaCapture latest = latestManifest(anchor);
        if (!STATE_COMPLETE.equals(latest.getState()) || !isManifest(latest.getMediaKind())) {
            throw new IllegalStateException("媒体清单尚未采集完成");
        }
        byte[] bytes = storage.readAll(latest.getObjectKey(), properties.getManifestMaxBytes());
        String text = HttpBodyDataCodec.toDisplayText(
                bytes, latest.getContentType(), latest.getResponseHeaders(), "");
        return HttpMediaManifestSupport.rewrite(
                latest.getMediaKind(), latest.getSourceUrl(), text, assetBasePath);
    }

    public List<HttpMediaCapture> completeResourceCaptures(HttpMediaCapture anchor) {
        return captureRepository.findByTenantIdAndResourceKeyAndStateOrderByIdDesc(
                anchor.getTenantId(), anchor.getResourceKey(), STATE_COMPLETE);
    }

    public RustFsMediaStorage storage() {
        return storage;
    }

    @Scheduled(fixedDelayString = "${specus.media-capture.cleanup-interval-ms:60000}")
    public void cleanupExpired() {
        if (!properties.isEnabled()) {
            return;
        }
        Instant now = Instant.now();
        List<HttpMediaCapture> expired = captureRepository
                .findTop200ByStateInAndExpiresAtBeforeOrderByIdAsc(
                        List.of(STATE_STARTING, STATE_CAPTURING, STATE_COMPLETE, STATE_INCOMPLETE, STATE_FAILED),
                        now.toString());
        int extended = 0;
        int deleted = 0;
        for (HttpMediaCapture capture : expired) {
            try {
                if (extendNonLiveRetention(capture, now)) {
                    extended++;
                    continue;
                }
                if ((STATE_STARTING.equals(capture.getState()) || STATE_CAPTURING.equals(capture.getState()))
                        && hasText(capture.getUploadId()) && storage.isReady()) {
                    storage.abortMultipart(new MultipartUpload(capture.getObjectKey(), capture.getUploadId()));
                } else if ((STATE_COMPLETE.equals(capture.getState()) || STATE_INCOMPLETE.equals(capture.getState()))
                        && storage.isReady()) {
                    storage.delete(capture.getObjectKey());
                }
                referenceRepository.deleteByTenantIdAndManifestCaptureId(
                        capture.getTenantId(), capture.getId());
                captureRepository.delete(capture);
                deleted++;
            } catch (RuntimeException exception) {
                log.warn("[media-capture] failed to clean expired capture id={} key={}",
                        capture.getId(), capture.getObjectKey(), exception);
            }
        }
        if (extended > 0 || deleted > 0) {
            log.info("[media-capture] retention cleanup extended={} deleted={}", extended, deleted);
        }
    }

    private boolean extendNonLiveRetention(HttpMediaCapture capture, Instant now) {
        if (capture.isLiveStream()
                || (!STATE_COMPLETE.equals(capture.getState())
                && !STATE_INCOMPLETE.equals(capture.getState()))) {
            return false;
        }
        try {
            Instant configuredExpiry = Instant.parse(capture.getCapturedAt())
                    .plusSeconds(Math.max(60, properties.getRetentionSeconds()));
            Instant storedExpiry = Instant.parse(capture.getExpiresAt());
            if (!configuredExpiry.isAfter(now) || !configuredExpiry.isAfter(storedExpiry)) {
                return false;
            }
            capture.setExpiresAt(configuredExpiry.toString());
            captureRepository.save(capture);
            return true;
        } catch (RuntimeException invalidTimestamp) {
            log.warn("[media-capture] invalid retention timestamp id={} capturedAt={} expiresAt={}",
                    capture.getId(), capture.getCapturedAt(), capture.getExpiresAt());
            return false;
        }
    }

    @PreDestroy
    public void shutdown() {
        uploadExecutor.shutdown();
        try {
            if (!uploadExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
                uploadExecutor.shutdownNow();
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            uploadExecutor.shutdownNow();
        }
    }

    private void markComplete(long captureId,
                              String objectEtag,
                              long capturedBytes,
                              long expectedResponseBytes,
                              byte[] manifestBytes,
                              boolean acceptPartial,
                              String completionReason) {
        HttpMediaCapture capture = captureRepository.findById(captureId).orElse(null);
        if (capture == null) {
            return;
        }
        Instant now = Instant.now();
        boolean retainedPartial = acceptPartial
                && capturedBytes > 0
                && expectedResponseBytes >= 0
                && expectedResponseBytes != capturedBytes;
        boolean complete = retainedPartial
                || expectedResponseBytes < 0
                || expectedResponseBytes == capturedBytes;
        capture.setState(complete ? STATE_COMPLETE : STATE_INCOMPLETE);
        if (!complete || retainedPartial) {
            capture.setDeduplicationKey(null);
        }
        capture.setFailureReason(complete ? null
                : "响应正文长度不完整，预期 " + expectedResponseBytes + " 字节，实际 " + capturedBytes + " 字节");
        capture.setObjectEtag(cap(objectEtag, 512));
        capture.setUploadId(null);
        capture.setCapturedBytes(capturedBytes);
        if (retainedPartial) {
            capture.setContentRangeEnd(capture.getContentRangeStart() + capturedBytes - 1);
        } else if (capture.getContentRangeEnd() == null && capturedBytes > 0) {
            capture.setContentRangeEnd(capture.getContentRangeStart() + capturedBytes - 1);
        }
        if (capture.getTotalBytes() == null && capture.getContentRangeStart() == 0 && complete) {
            capture.setTotalBytes(capturedBytes);
        }
        capture.setCompletedAt(now.toString());

        if (complete && manifestBytes != null && isManifest(capture.getMediaKind())) {
            String text = HttpBodyDataCodec.toDisplayText(
                    manifestBytes, capture.getContentType(), capture.getResponseHeaders(), "");
            HttpMediaManifestSupport.ParsedManifest parsed = HttpMediaManifestSupport.parse(
                    capture.getMediaKind(), capture.getSourceUrl(), text);
            capture.setLiveStream(parsed.live());
            if (parsed.live()) {
                capture.setExpiresAt(now.plusSeconds(Math.max(60, properties.getLiveWindowSeconds())).toString());
                markLiveWindow(capture, parsed, now);
            }
            saveManifestReferences(capture, parsed);
        }
        captureRepository.save(capture);
        log.debug("[media-capture] completed id={} state={} bytes={} retainedPartial={} reason={} key={}",
                captureId, capture.getState(), capturedBytes, retainedPartial,
                completionReason, capture.getObjectKey());
    }

    private void markLiveWindow(HttpMediaCapture manifest,
                                HttpMediaManifestSupport.ParsedManifest parsed,
                                Instant now) {
        String expiresAt = now.plusSeconds(Math.max(60, properties.getLiveWindowSeconds())).toString();
        Instant recentCutoff = now.minusSeconds(Math.max(60, properties.getLiveWindowSeconds()));
        Map<Long, HttpMediaCapture> related = new java.util.LinkedHashMap<>();
        for (HttpMediaManifestSupport.ManifestReference reference : parsed.references()) {
            if (!"SEGMENT".equals(reference.relationType())
                    && !"INITIALIZATION".equals(reference.relationType())) {
                continue;
            }
            captureRepository
                    .findByTenantIdAndClientIdAndRouteAndSourceUrlAndStateOrderByIdDesc(
                            manifest.getTenantId(),
                            manifest.getClientId(),
                            manifest.getRoute(),
                            reference.resolvedSourceUrl(),
                            STATE_COMPLETE)
                    .forEach(row -> related.put(row.getId(), row));
        }
        // DASH SegmentTemplate references may not resolve to a concrete URL until the player
        // substitutes $Number$/$Time$. Include recent route segments so they also roll forward.
        captureRepository
                .findTop1000ByTenantIdAndClientIdAndRouteAndMediaKindAndStateOrderByIdDesc(
                        manifest.getTenantId(),
                        manifest.getClientId(),
                        manifest.getRoute(),
                        HttpMediaManifestSupport.MEDIA_SEGMENT,
                        STATE_COMPLETE)
                .stream()
                .filter(row -> capturedAfter(row, recentCutoff))
                .forEach(row -> related.put(row.getId(), row));
        for (HttpMediaCapture capture : related.values()) {
            capture.setLiveStream(true);
            capture.setExpiresAt(expiresAt);
        }
        if (!related.isEmpty()) {
            captureRepository.saveAll(related.values());
        }
    }

    private boolean capturedAfter(HttpMediaCapture capture, Instant cutoff) {
        try {
            return Instant.parse(capture.getCapturedAt()).isAfter(cutoff);
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    private void saveManifestReferences(HttpMediaCapture capture,
                                        HttpMediaManifestSupport.ParsedManifest parsed) {
        referenceRepository.deleteByTenantIdAndManifestCaptureId(capture.getTenantId(), capture.getId());
        if (parsed.references().isEmpty()) {
            return;
        }
        String now = Instant.now().toString();
        List<HttpMediaReference> rows = new ArrayList<>(parsed.references().size());
        for (HttpMediaManifestSupport.ManifestReference reference : parsed.references()) {
            HttpMediaReference row = new HttpMediaReference();
            row.setTenantId(capture.getTenantId());
            row.setManifestCaptureId(capture.getId());
            row.setRelationType(reference.relationType());
            row.setSequenceIndex(reference.sequence());
            row.setOriginalUri(cap(reference.originalUri(), 2048));
            row.setResolvedSourceUrl(cap(reference.resolvedSourceUrl(), 3072));
            row.setCreatedAt(now);
            rows.add(row);
        }
        referenceRepository.saveAll(rows);
    }

    private void markFailed(long captureId, Throwable error) {
        HttpMediaCapture capture = captureRepository.findById(captureId).orElse(null);
        if (capture == null) {
            return;
        }
        capture.setState(STATE_FAILED);
        capture.setDeduplicationKey(null);
        capture.setFailureReason(cap(rootMessage(error), 2048));
        capture.setCompletedAt(Instant.now().toString());
        captureRepository.save(capture);
    }

    private HttpMediaCaptureView toView(HttpMediaCapture row) {
        PlaybackStatus playback = playbackStatus(row);
        return new HttpMediaCaptureView(
                row.getId(),
                row.getClientId(),
                row.getClientName(),
                row.getRoute(),
                row.getResourceId(),
                redactSourceUrl(row.getSourceUrl()),
                row.getMethod(),
                row.getStatusCode(),
                row.getContentType(),
                row.getMediaKind(),
                row.getEntityTag(),
                row.getContentRangeStart(),
                row.getContentRangeEnd(),
                row.getTotalBytes(),
                row.getCapturedBytes(),
                row.getSegmentSequence(),
                row.isInitializationSegment(),
                row.isLiveStream(),
                row.getState(),
                row.getFailureReason(),
                playback.playable(),
                playback.offlineReady(),
                playback.message(),
                row.getCapturedAt(),
                row.getCompletedAt(),
                row.getExpiresAt());
    }

    private PlaybackStatus playbackStatus(HttpMediaCapture row) {
        if (!STATE_COMPLETE.equals(row.getState())) {
            return new PlaybackStatus(false, false, "媒体采集尚未完成");
        }
        if (HttpMediaManifestSupport.MEDIA_SEGMENT.equals(row.getMediaKind())
                || row.isInitializationSegment()) {
            return new PlaybackStatus(
                    false, true, "媒体分段由 HLS/DASH 清单播放器按需加载");
        }
        if (isManifest(row.getMediaKind())) {
            boolean playable = row.getCapturedBytes() > 0;
            return new PlaybackStatus(
                    playable,
                    false,
                    playable ? "仅播放已缓存的媒体分段" : "媒体清单正文为空");
        }
        HttpMediaPlaybackService.PlaybackAvailability coverage =
                HttpMediaPlaybackService.evaluateCoverage(completeResourceCaptures(row));
        if (coverage.playable()) {
            return new PlaybackStatus(true, true, null);
        }
        if (row.getCapturedBytes() > 0) {
            return new PlaybackStatus(
                    true,
                    false,
                    coverage.reason() + "；仅可播放已缓存区间");
        }
        return new PlaybackStatus(false, false, coverage.reason());
    }

    static String redactSourceUrl(String sourceUrl) {
        if (sourceUrl == null || sourceUrl.isBlank()) {
            return sourceUrl;
        }
        return SENSITIVE_QUERY_PARAMETER.matcher(sourceUrl).replaceAll("$1***");
    }

    private List<Long> visibleClientIds(ManagementContext context) {
        return clientAccountRepository
                .findByTenantIdAndOwnerUsernameOrderByIdDesc(
                        context.tenant().tenantId(), context.username())
                .stream()
                .map(ClientAccount::getId)
                .toList();
    }

    private String objectKey(String tenantId, String route, String sourceUrl) {
        String prefix = properties.getObjectPrefix() == null
                ? "" : properties.getObjectPrefix().trim().replaceAll("^/+|/+$", "");
        String extension = extension(sourceUrl);
        String date = LocalDate.now(ZoneOffset.UTC).toString().replace("-", "/");
        return (prefix.isEmpty() ? "" : prefix + "/")
                + safeSegment(tenantId) + "/" + date + "/" + safeSegment(route) + "/"
                + UUID.randomUUID().toString().replace("-", "") + extension;
    }

    private String resourceKey(String tenantId,
                               long clientId,
                               String route,
                               String sourceUrl,
                               String entityTag,
                               String lastModified) {
        String version = hasText(entityTag) ? entityTag : hasText(lastModified) ? lastModified : "";
        String value = tenantId + '\n' + clientId + '\n' + route + '\n' + sourceUrl + '\n' + version;
        return sha256(value);
    }

    private String deduplicationKey(String resourceKey,
                                    String method,
                                    String kind,
                                    Long rangeStart,
                                    Long rangeEnd,
                                    Long totalBytes,
                                    String contentEncoding) {
        if (isManifest(kind)
                || rangeStart == null
                || rangeEnd == null
                || rangeEnd < rangeStart) {
            return null;
        }
        String value = resourceKey
                + '\n' + method
                + '\n' + kind
                + '\n' + rangeStart
                + '\n' + rangeEnd
                + '\n' + (totalBytes == null ? "" : totalBytes)
                + '\n' + (contentEncoding == null ? "" : contentEncoding.toLowerCase(Locale.ROOT));
        return sha256(value);
    }

    private String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private boolean hasReusableCapture(String tenantId,
                                       String deduplicationKey,
                                       String resourceKey,
                                       String mediaKind,
                                       Long rangeStart,
                                       Long rangeEnd,
                                       Long totalBytes,
                                       long expectedResponseBytes,
                                       String contentEncoding,
                                       Instant now) {
        HttpMediaCapture keyed = captureRepository
                .findByTenantIdAndDeduplicationKey(tenantId, deduplicationKey)
                .orElse(null);
        if (keyed != null) {
            if (isReusableCapture(keyed, rangeStart, rangeEnd, expectedResponseBytes, now)) {
                return true;
            }
            keyed.setDeduplicationKey(null);
            captureRepository.saveAndFlush(keyed);
        }

        return captureRepository
                .findFirstByTenantIdAndResourceKeyAndMediaKindAndContentRangeStartAndContentRangeEndAndTotalBytesAndCapturedBytesAndContentEncodingAndStateAndExpiresAtAfterOrderByIdDesc(
                        tenantId,
                        resourceKey,
                        mediaKind,
                        rangeStart,
                        rangeEnd,
                        totalBytes,
                        expectedResponseBytes,
                        contentEncoding,
                        STATE_COMPLETE,
                        now.toString())
                .isPresent();
    }

    private boolean isReusableCapture(HttpMediaCapture capture,
                                      Long rangeStart,
                                      Long rangeEnd,
                                      long expectedResponseBytes,
                                      Instant now) {
        if (STATE_STARTING.equals(capture.getState()) || STATE_CAPTURING.equals(capture.getState())) {
            return true;
        }
        if (!STATE_COMPLETE.equals(capture.getState())
                || capture.getCapturedBytes() != expectedResponseBytes
                || !java.util.Objects.equals(capture.getContentRangeStart(), rangeStart)
                || !java.util.Objects.equals(capture.getContentRangeEnd(), rangeEnd)) {
            return false;
        }
        try {
            return Instant.parse(capture.getExpiresAt()).isAfter(now);
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    private String extension(String sourceUrl) {
        String path = sourceUrl == null ? "" : sourceUrl.split("\\?", 2)[0];
        int slash = path.lastIndexOf('/');
        int dot = path.lastIndexOf('.');
        if (dot <= slash || path.length() - dot > 12) {
            return ".bin";
        }
        String extension = path.substring(dot).toLowerCase(Locale.ROOT);
        return extension.matches("\\.[a-z0-9]{1,10}") ? extension : ".bin";
    }

    private String safeSegment(String value) {
        if (value == null || value.isBlank()) {
            return "default";
        }
        String normalized = value.trim().replaceAll("[^A-Za-z0-9._-]", "_");
        return normalized.length() <= 80 ? normalized : normalized.substring(0, 80);
    }

    private String headerValue(List<String> headers, String name) {
        if (headers == null) {
            return null;
        }
        for (String header : headers) {
            if (header == null) {
                continue;
            }
            int separator = header.indexOf(':');
            if (separator > 0 && name.equalsIgnoreCase(header.substring(0, separator).trim())) {
                return header.substring(separator + 1).trim();
            }
        }
        return null;
    }

    private Long positiveLong(String value) {
        if (!hasText(value)) {
            return null;
        }
        try {
            long parsed = Long.parseLong(value.trim());
            return parsed >= 0 ? parsed : null;
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private String joinHeaders(List<String> headers) {
        return headers == null ? "" : String.join("\n", headers);
    }

    private String normalizeMethod(String method) {
        String normalized = method == null ? "GET" : method.trim().toUpperCase(Locale.ROOT);
        return cap(normalized, 16);
    }

    private String rootMessage(Throwable error) {
        Throwable current = error;
        while (current != null && current.getCause() != null) {
            current = current.getCause();
        }
        if (current == null) {
            return "媒体采集失败";
        }
        return current.getMessage() == null ? current.getClass().getSimpleName() : current.getMessage();
    }

    private boolean isManifest(String kind) {
        return HttpMediaManifestSupport.HLS_MANIFEST.equals(kind)
                || HttpMediaManifestSupport.DASH_MANIFEST.equals(kind);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String cap(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }

    public interface CaptureSession {
        void append(byte[] bytes);

        void complete();

        void fail(String reason);

        boolean active();

        default boolean externalized() {
            return active();
        }

        static CaptureSession noop() {
            return NoopCapture.INSTANCE;
        }

        static CaptureSession externalizedNoop() {
            return ExternalizedNoopCapture.INSTANCE;
        }
    }

    private enum NoopCapture implements CaptureSession {
        INSTANCE;

        @Override
        public void append(byte[] bytes) {
        }

        @Override
        public void complete() {
        }

        @Override
        public void fail(String reason) {
        }

        @Override
        public boolean active() {
            return false;
        }
    }

    private enum ExternalizedNoopCapture implements CaptureSession {
        INSTANCE;

        @Override
        public void append(byte[] bytes) {
        }

        @Override
        public void complete() {
        }

        @Override
        public void fail(String reason) {
        }

        @Override
        public boolean active() {
            return false;
        }

        @Override
        public boolean externalized() {
            return true;
        }
    }

    private final class ActiveCapture implements CaptureSession {
        private final long captureId;
        private final MultipartUpload upload;
        private final long expectedResponseBytes;
        private final boolean partialResponseUsable;
        private final int partSize;
        private final Semaphore inflight;
        private final List<CompletableFuture<CompletedPart>> parts = new ArrayList<>();
        private final AtomicBoolean terminal = new AtomicBoolean();
        private final AtomicReference<Throwable> asynchronousFailure = new AtomicReference<>();
        private ByteArrayOutputStream partBuffer;
        private ByteArrayOutputStream manifestBuffer;
        private int nextPartNumber = 1;
        private long capturedBytes;

        private ActiveCapture(long captureId,
                              MultipartUpload upload,
                              String kind,
                              long expectedResponseBytes) {
            this.captureId = captureId;
            this.upload = upload;
            this.expectedResponseBytes = expectedResponseBytes;
            this.partialResponseUsable = !isManifest(kind);
            long configuredPartSize = Math.min(
                    properties.normalizedPartSizeBytes(), 512L * 1024L * 1024L);
            this.partSize = Math.toIntExact(configuredPartSize);
            this.inflight = new Semaphore(properties.normalizedMaxInflightParts());
            this.partBuffer = new ByteArrayOutputStream(partSize);
            this.manifestBuffer = isManifest(kind) ? new ByteArrayOutputStream() : null;
        }

        @Override
        public void append(byte[] bytes) {
            if (terminal.get() || bytes == null || bytes.length == 0) {
                return;
            }
            Throwable uploadFailure = asynchronousFailure.get();
            if (uploadFailure != null) {
                abortForFailure(uploadFailure);
                return;
            }
            try {
                if (manifestBuffer != null) {
                    long nextSize = (long) manifestBuffer.size() + bytes.length;
                    if (properties.getManifestMaxBytes() > 0
                            && nextSize <= properties.getManifestMaxBytes()) {
                        manifestBuffer.writeBytes(bytes);
                    } else {
                        manifestBuffer = null;
                    }
                }
                int offset = 0;
                while (offset < bytes.length) {
                    int length = Math.min(bytes.length - offset, partSize - partBuffer.size());
                    partBuffer.write(bytes, offset, length);
                    capturedBytes += length;
                    offset += length;
                    if (partBuffer.size() == partSize) {
                        submitPart(partBuffer.toByteArray());
                        partBuffer = new ByteArrayOutputStream(partSize);
                    }
                }
            } catch (RuntimeException exception) {
                abortForFailure(exception);
            }
        }

        @Override
        public void complete() {
            finish(false, null);
        }

        @Override
        public void fail(String reason) {
            if (partialResponseUsable && capturedBytes > 0) {
                finish(true, reason);
                return;
            }
            abortForFailure(new IllegalStateException(
                    reason == null || reason.isBlank() ? "媒体响应中断" : reason));
        }

        private void finish(boolean acceptPartial, String completionReason) {
            if (!terminal.compareAndSet(false, true)) {
                return;
            }
            try {
                if (partBuffer.size() > 0) {
                    submitPart(partBuffer.toByteArray());
                }
                partBuffer = null;
                if (parts.isEmpty()) {
                    storage.abortMultipart(upload);
                    markFailed(captureId, new IllegalStateException("媒体响应正文为空"));
                    return;
                }
                byte[] manifestBytes = manifestBuffer == null ? null : manifestBuffer.toByteArray();
                CompletableFuture<?>[] pending = parts.toArray(CompletableFuture[]::new);
                CompletableFuture.allOf(pending).whenCompleteAsync((ignored, error) -> {
                    Throwable failed = error == null ? asynchronousFailure.get() : error;
                    if (failed != null) {
                        abortAndFail(failed);
                        return;
                    }
                    try {
                        List<CompletedPart> completed = parts.stream()
                                .map(CompletableFuture::join)
                                .sorted(Comparator.comparingInt(CompletedPart::partNumber))
                                .toList();
                        String etag = storage.completeMultipart(upload, completed);
                        markComplete(
                                captureId,
                                etag,
                                capturedBytes,
                                expectedResponseBytes,
                                manifestBytes,
                                acceptPartial,
                                completionReason);
                    } catch (RuntimeException exception) {
                        abortAndFail(exception);
                    }
                }, uploadExecutor);
            } catch (RuntimeException exception) {
                abortAndFail(exception);
            }
        }

        private void abortForFailure(Throwable failure) {
            if (!terminal.compareAndSet(false, true)) {
                return;
            }
            CompletableFuture<?>[] pending = parts.toArray(CompletableFuture[]::new);
            CompletableFuture.allOf(pending).whenCompleteAsync(
                    (ignored, error) -> abortAndFail(error == null ? failure : error),
                    uploadExecutor);
        }

        @Override
        public boolean active() {
            return !terminal.get();
        }

        private void submitPart(byte[] bytes) {
            if (bytes.length == 0) {
                return;
            }
            try {
                inflight.acquire();
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("等待 RustFS 上传被中断", exception);
            }
            int partNumber = nextPartNumber++;
            CompletableFuture<CompletedPart> future = CompletableFuture
                    .supplyAsync(() -> storage.uploadPart(upload, partNumber, bytes), uploadExecutor)
                    .whenComplete((part, error) -> {
                        if (error != null) {
                            asynchronousFailure.compareAndSet(null, error);
                        }
                        inflight.release();
                    });
            parts.add(future);
        }

        private void abortAndFail(Throwable error) {
            try {
                storage.abortMultipart(upload);
            } catch (RuntimeException abortError) {
                error.addSuppressed(abortError);
            }
            markFailed(captureId, error);
            log.warn("[media-capture] RustFS multipart failed id={} key={}",
                    captureId, upload.objectKey(), error);
        }
    }

    private static final class MediaThreadFactory implements ThreadFactory {
        private final AtomicInteger sequence = new AtomicInteger();

        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable,
                    "http-media-upload-" + sequence.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        }
    }

    private record PlaybackStatus(
            boolean playable,
            boolean offlineReady,
            String message
    ) {
    }
}
